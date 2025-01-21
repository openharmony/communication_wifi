/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <net/if_arp.h>
#include <gtest/gtest.h>
#include "mock_wifi_settings.h"
#include "multi_gateway.h"
#include "log.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int32_t NUM_TEN = 10;
    static std::string g_errLog;
    voidGatewayCallback(const LogType type, const LogLevel level, const unsigned int domain,
                          const char *tag, const char *msg)
    {
        g_errLog = msg;
    }
class MultiGatewayTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        LOG_SetCallback(MultiGatewayCallback);
    }
    virtual void TearDown() {}
};

HWTEST_F(MultiGatewayTest, GetGatewayAddr_test, TestSize.Level1)
{
    MultiGateway::GetInstance().GetGatewayAddr(0);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(MultiGatewayTest, IsMultiGateway_test, TestSize.Level1)
{
    EXPECT_TRUE(MultiGateway::GetInstance().IsMultiGateway());
}

HWTEST_F(MultiGatewayTest, GetNextGatewayMac_test, TestSize.Level1)
{
    std::string mac = "";
    MultiGateway::GetInstance().GetNextGatewayMac(mac);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(MultiGatewayTest, SetStaticArp_test, TestSize.Level1)
{
    std::string iface = "";
    std::string ipAddr = "";
    std::string macAddr = "";
    EXPECT_TRUE(MultiGateway::GetInstance().SetStaticArp(iface, ipAddr, macAddr) == -1);
    iface = "wlan0";
    EXPECT_TRUE(MultiGateway::GetInstance().SetStaticArp(iface, ipAddr, macAddr) == -1);
    ipAddr = "12.12.12.12";
    EXPECT_TRUE(MultiGateway::GetInstance().SetStaticArp(iface, ipAddr, macAddr) == -1);
    macAddr = "00:00:11:11:11:11";
    MultiGateway::GetInstance().SetStaticArp(iface, ipAddr, macAddr);
}

HWTEST_F(MultiGatewayTest, DelStaticArp_test, TestSize.Level1)
{
    std::string iface = "";
    std::string ipAddr = "";
    EXPECT_TRUE(MultiGateway::GetInstance().DelStaticArp(iface, ipAddr) == -1);
    iface = "wlan0";
    EXPECT_TRUE(MultiGateway::GetInstance().DelStaticArp(iface, ipAddr) == -1);
    ipAddr = "12.12.12.12";
    MultiGateway::GetInstance().DelStaticArp(iface, ipAddr);
}

HWTEST_F(MultiGatewayTest, DoArpItem_test, TestSize.Level1)
{
    int32_t cmd = 1;
    struct arpreq *req = nullptr;
    EXPECT_TRUE(MultiGateway::GetInstance().DoArpItem(cmd, req) == -1);
}

HWTEST_F(MultiGatewayTest, GetMacAddr_test, TestSize.Level1)
{
    char *buff = nullptr;
    const char *macAddr = nullptr;
    EXPECT_TRUE(MultiGateway::GetInstance().GetMacAddr(buff, macAddr) == -1);
    char buff1[NUM_TEN] = {0};
    EXPECT_TRUE(MultiGateway::GetInstance().GetMacAddr(buff1, macAddr) == -1);
    const char *macAddr1 = "11:22:33:44:55:66";
    EXPECT_TRUE(MultiGateway::GetInstance().GetMacAddr(buff1, macAddr1) == 0);
}
}
}