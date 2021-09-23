/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include "string_ex.h"
#include "dhcp_server.h"
#include "address_utils.h"
#include "dhcp_config.h"
#include "dhcp_option.h"
#include "dhcp_logger.h"
#include "system_func_mock.h"
#include "dhcp_message_sim.h"
#include "securec.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::Wifi;

#undef LOG_TAG
#define LOG_TAG "DhcpServerTest"

static const int SERVER_RUNING_TIME = 10;   //the value is in units of seconds.
class DhcpServerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}

    int InitServerConfig(DhcpConfig *config);
    int FreeServerConfig(DhcpConfig *config);

    int InitDhcpClient();
    void ServerRun(void);
    bool StartServerTest();
    bool StopServerTest();

private:
    DhcpServerContext *m_pServerCtx = NULL;
    DhcpConfig m_serverConfg;
    thread testSrvTh;

    DhcpClientContext *m_pMockClient = NULL;
    DhcpClientConfig m_clientConfg;
};

int DhcpServerTest::InitServerConfig(DhcpConfig *config)
{
    if (!config) {
        return RET_FAILED;
    }
    const char* testIfaceName = "wlan0";
    uint32_t serverId = ParseIpAddr("192.168.188.254");
    uint32_t netmask = ParseIpAddr("255.255.255.0");
    uint32_t beginIp = ParseIpAddr("192.168.188.100");
    uint32_t endIp = ParseIpAddr("192.168.188.150");
    if (serverId == 0 || netmask == 0 || beginIp == 0 || endIp == 0) {
        printf("failed to parse address.\n");
        return RET_FAILED;
    }
    if (memset_s(config, sizeof(DhcpConfig), 0, sizeof(DhcpConfig)) != EOK) {
        return RET_FAILED;
    }
    if (memset_s(config->ifname, sizeof(config->ifname), '\0', sizeof(config->ifname)) != EOK) {
        return RET_FAILED;
    }
    if (strncpy_s(config->ifname, sizeof(config->ifname), testIfaceName, sizeof(config->ifname)) != EOK) {
        return RET_FAILED;
    }
    config->serverId = serverId;
    config->netmask = netmask;
    config->pool.beginAddress = beginIp;
    config->pool.endAddress = endIp;
    if (InitOptionList(&config->options) != RET_SUCCESS) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

void DhcpServerTest::ServerRun(void)
{
    LOGD("begin test start dhcp server.");
    SystemFuncMock::GetInstance().SetMockFlag(true);
    EXPECT_CALL(SystemFuncMock::GetInstance(), socket(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(SystemFuncMock::GetInstance(), setsockopt(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), select(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), recvfrom(_, _, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), bind(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), close(_)).WillRepeatedly(Return(0));
    m_pServerCtx = InitializeServer(&m_serverConfg);
    if (!m_pServerCtx) {
        LOGE("failed to initialized dhcp server context.");
    }
    if (m_pServerCtx && StartDhcpServer(m_pServerCtx) != RET_SUCCESS) {
        printf("failed to start dhcp server. \n");
    }
    SystemFuncMock::GetInstance().SetMockFlag(false);
}
bool DhcpServerTest::StartServerTest()
{
    SystemFuncMock::GetInstance().SetMockFlag(true);
    EXPECT_CALL(SystemFuncMock::GetInstance(), close(_)).WillRepeatedly(Return(0));
    bool retval = true;
    if (InitServerConfig(&m_serverConfg) != RET_SUCCESS) {
        LOGD("failed to initialized dhcp server config.");
        retval = false;
    }
    testSrvTh = std::thread(std::bind(&DhcpServerTest::ServerRun, this));
    testSrvTh.detach();
    sleep(SERVER_RUNING_TIME);
    if (retval && StopServerTest() != RET_SUCCESS) {
        retval = false;
    }
    sleep(6);
    if (m_pServerCtx) {
        FreeServerContex(m_pServerCtx);
        m_pServerCtx = NULL;
    }
    SystemFuncMock::GetInstance().SetMockFlag(false);
    return retval;
}

bool DhcpServerTest::StopServerTest()
{
    printf("begin stop dhcp server. \n");
    if (!m_pServerCtx) {
        return false;
    }
    if (StopDhcpServer(m_pServerCtx) != RET_SUCCESS) {
        return false;
    }
    return true;
}

int DhcpServerTest::InitDhcpClient()
{
    LOGD("init mock dhcp client.");
    const char* testIfname = "wlan0";
    uint8_t testMac[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};

    if (memset_s(&m_clientConfg, sizeof(DhcpClientConfig), 0, sizeof(DhcpClientConfig)) != EOK) {
        return RET_FAILED;
    }
    if (!FillHwAddr(m_clientConfg.chaddr, DHCP_HWADDR_LENGTH, testMac, MAC_ADDR_LENGTH)) {
        return RET_FAILED;
    }
    if (memset_s(m_clientConfg.ifname, IFACE_NAME_SIZE, '\0', IFACE_NAME_SIZE) != EOK) {
        return RET_FAILED;
    }
    if (memcpy_s(m_clientConfg.ifname, IFACE_NAME_SIZE, testIfname, strlen(testIfname)) != EOK) {
        return RET_FAILED;
    }
    m_pMockClient = InitialDhcpClient(&m_clientConfg);

    if (!m_pMockClient) {
        return RET_FAILED;
    }
    return DhcpDiscover(m_pMockClient);
}

int DhcpServerTest::FreeServerConfig(DhcpConfig *config)
{
    if (!config) {
        return RET_FAILED;
    }
    FreeOptionList(&config->options);
    return RET_SUCCESS;
}

HWTEST_F(DhcpServerTest, InitializeServerTest, TestSize.Level1)
{
    SystemFuncMock::GetInstance().SetMockFlag(true);
    EXPECT_CALL(SystemFuncMock::GetInstance(), socket(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(SystemFuncMock::GetInstance(), setsockopt(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), select(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), recvfrom(_, _, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), bind(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), close(_)).WillRepeatedly(Return(0));

    DhcpConfig config;
    PDhcpServerContext ctx = InitializeServer(&config);
    EXPECT_TRUE(ctx == NULL);
    EXPECT_EQ(RET_SUCCESS, InitServerConfig(&config));
    ctx = InitializeServer(&config);
    ASSERT_TRUE(ctx != NULL);
    EXPECT_EQ(RET_SUCCESS, FreeServerConfig(&config));
    EXPECT_EQ(RET_SUCCESS, FreeServerContex(ctx));
    SystemFuncMock::GetInstance().SetMockFlag(false);
}