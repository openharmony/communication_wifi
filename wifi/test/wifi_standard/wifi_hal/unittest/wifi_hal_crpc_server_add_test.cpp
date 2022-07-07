/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "wifi_hal_crpc_server_add_test.h"
#include "wifi_log.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_crpc_p2p.h"
#include "mock_wpa_ctrl.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
static std::string g_rpcSockPath = "./unix_sock_test.sock";
RpcServer *WifiHalCRpcServerAddTest::mServer = nullptr;
Context *WifiHalCRpcServerAddTest::mContext = nullptr;

void WifiHalCRpcServerAddTest::SetUpTestCase()
{
    if (access(g_rpcSockPath.c_str(), 0) == 0) {
        unlink(g_rpcSockPath.c_str());
    }
    mServer = CreateRpcServer(g_rpcSockPath.c_str());
    mContext = CreateContext(CONTEXT_BUFFER_MIN_SIZE);
    if (mServer == nullptr || mContext == nullptr) {
        printf("Init rpc server failed or create context failed!");
        exit(-1);
    }
    InitCallbackMsg();
    SetRpcServerInited(mServer);
    MockInitGlobalCmd();
    MockInitP2pSupportedCmd();
}

void WifiHalCRpcServerAddTest::TearDownTestCase()
{
    if (mServer != nullptr) {
        ReleaseRpcServer(mServer);
        mServer = nullptr;
    }
    SetRpcServerInited(NULL);
    ReleaseCallbackMsg();
    if (mContext != nullptr) {
        ReleaseContext(mContext);
        mContext = nullptr;
    }
}

void WifiHalCRpcServerAddTest::SetUp()
{
    if (mContext != nullptr) {
        mContext->wBegin = mContext->wEnd = 0;
    }
}

void WifiHalCRpcServerAddTest::TearDown()
{
    if (mContext != nullptr) {
        mContext->wBegin = mContext->wEnd = 0;
    }
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pStartTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pStart(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pStart(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pStopTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pStop(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pStop(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetRandomMacTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetRandomMac(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetRandomMac\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetRandomMac\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetRandomMac(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetRandomMac\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetRandomMac\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetRandomMac(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetDeviceNameTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetDeviceName(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetDeviceName\tp2p_device_name";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetDeviceName\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetDeviceName(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetDeviceName\tp2p_device_name\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetDeviceName\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetDeviceName(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetSsidPostfixNameTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetSsidPostfixName(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetSsidPostfixName\tp2p_postfix_name";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetSsidPostfixName\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetSsidPostfixName(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetSsidPostfixName\tp2p_postfix_name\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetSsidPostfixName\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetSsidPostfixName(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetWpsDeviceTypeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetWpsDeviceType(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetWpsDeviceType\tp2p_device_type";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetWpsDeviceType\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetWpsDeviceType(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetWpsDeviceType\tp2p_device_type\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetWpsDeviceType\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetWpsDeviceType(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetWpsConfigMethodsTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetWpsConfigMethods(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetWpsConfigMethods\tp2p_config_methods";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetWpsConfigMethods\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetWpsConfigMethods(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetWpsConfigMethods\tp2p_config_methods\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetWpsConfigMethods\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetWpsConfigMethods(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pGetDeviceAddressTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pGetDeviceAddress(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pGetDeviceAddress\t17";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pGetDeviceAddress\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pGetDeviceAddress(mServer, mContext) < 0);
    char buff1[] = "N\tP2pGetDeviceAddress\t17\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pGetDeviceAddress\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pGetDeviceAddress(mServer, mContext) == 0);
    char buff2[] = "N\tP2pGetDeviceAddress\t-1\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tP2pGetDeviceAddress\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcP2pGetDeviceAddress(mServer, mContext) < 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pFlushTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pFlush(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pFlush(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pFlushServiceTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pFlushService(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pFlushService(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSaveConfigTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSaveConfig(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pSaveConfig(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetupWpsPbcTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetupWpsPbc(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetupWpsPbc\tp2p-dev-wlan0\t00:00:00:00:00:00";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetupWpsPbc\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetupWpsPbc(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetupWpsPbc\tp2p-dev-wlan0\t00:00:00:00:00:00\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetupWpsPbc\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetupWpsPbc(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetupWpsPinTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetupWpsPin(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetupWpsPiN\tp2p-dev-wlan0\t00:00:00:00:00:00\t123456789\t8\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetupWpsPiN\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetupWpsPin(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetupWpsPiN\tp2p-dev-wlan0\t00:00:00:00:00:00\t12345678\t8\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetupWpsPiN\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetupWpsPin(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pRemoveNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pRemoveNetwork(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pRemoveNetwork\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pRemoveNetwork\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pRemoveNetwork(mServer, mContext) < 0);
    char buff1[] = "N\tP2pRemoveNetwork\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pRemoveNetwork\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pRemoveNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pListNetworksTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pListNetworks(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pListNetworks(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetGroupMaxIdleTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetGroupMaxIdle(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetGroupMaxIdle\tp2p-dev-wlan0\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetGroupMaxIdle\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetGroupMaxIdle(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetGroupMaxIdle\tp2p-dev-wlan0\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetGroupMaxIdle\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetGroupMaxIdle(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetPowerSaveTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetPowerSave(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetPowerSave\tp2p-dev-wlan0\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetPowerSave\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetPowerSave(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetPowerSave\tp2p-dev-wlan0\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetPowerSave\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetPowerSave(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetWfdEnableTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetWfdEnable(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetWfdEnable\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetWfdEnable\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetWfdEnable(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetWfdEnable\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetWfdEnable\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetWfdEnable(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetWfdDeviceConfigTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetWfdDeviceConfig(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetWfdDeviceConfig\tp2p_device_config";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetWfdDeviceConfig\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetWfdDeviceConfig(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetWfdDeviceConfig\tp2p_device_config\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetWfdDeviceConfig\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetWfdDeviceConfig(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pStartFindTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pStartFind(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pStartFind\t120";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pStartFind\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pStartFind(mServer, mContext) < 0);
    char buff1[] = "N\tP2pStartFind\t120\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pStartFind\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pStartFind(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pStopFindTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pStopFind(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pStopFind(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetExtListenTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetExtListen(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetExtListeN\t0\t0\t0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetExtListeN\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetExtListen(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetExtListeN\t0\t0\t0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetExtListeN\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetExtListen(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetListenChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetListenChannel(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetListenChannel\t0\t0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetListenChannel\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetListenChannel(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetListenChannel\t0\t0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetListenChannel\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetListenChannel(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pConnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pConnect(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pConnect\t0\t0\t0\t0\t00:00:00:00:00:00\t12345678";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pConnect\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pConnect(mServer, mContext) < 0);
    char buff1[] = "N\tP2pConnect\t0\t0\t0\t0\t00:00:00:00:00:00\t12345678\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pConnect\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pConnect(mServer, mContext) == 0);
    char buff2[] = "N\tP2pConnect\t0\t1\t0\t0\t00:00:00:00:00:00\tpiN\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tP2pConnect\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcP2pConnect(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pCancelConnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pCancelConnect(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcP2pCancelConnect(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pProvisionDiscoveryTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pProvisionDiscovery(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pProvisionDiscovery\t00:00:00:00:00:00\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pProvisionDiscovery\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pProvisionDiscovery(mServer, mContext) < 0);
    char buff1[] = "N\tP2pProvisionDiscovery\t00:00:00:00:00:00\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pProvisionDiscovery\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pProvisionDiscovery(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pAddGroupTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pAddGroup(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pAddGroup\t0\t1\t0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pAddGroup\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pAddGroup(mServer, mContext) < 0);
    char buff1[] = "N\tP2pAddGroup\t0\t1\t0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pAddGroup\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pAddGroup(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pRemoveGroupTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pRemoveGroup(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pRemoveGroup\tp2p-dev-wlan0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pRemoveGroup\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pRemoveGroup(mServer, mContext) < 0);
    char buff1[] = "N\tP2pRemoveGroup\tp2p-dev-wlan0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pRemoveGroup\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pRemoveGroup(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pInviteTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pInvite(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pInvite\t0\tp2p-dev-wlan0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pInvite\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pInvite(mServer, mContext) < 0);
    char buff1[] = "N\tP2pInvite\t0\tp2p-dev-wlan0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pInvite\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pInvite(mServer, mContext) < 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pReinvokeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pReinvoke(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pReinvoke\t0\t00:00:00:00:00:00";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pReinvoke\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pReinvoke(mServer, mContext) < 0);
    char buff1[] = "N\tP2pReinvoke\t0\t00:00:00:00:00:00\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pReinvoke\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pReinvoke(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pGetGroupCapabilityTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pGetGroupCapability(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pGetGroupCapability\t00:00:00:00:00:00";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pGetGroupCapability\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pGetGroupCapability(mServer, mContext) < 0);
    char buff1[] = "N\tP2pGetGroupCapability\t00:00:00:00:00:00\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pGetGroupCapability\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pGetGroupCapability(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pAddServiceTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pAddService(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pAddService\tx\t0\tservice_name";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pAddService\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pAddService(mServer, mContext) < 0);
    char buff1[] = "N\tP2pAddService\t0\t0\tservice_name";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pAddService\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pAddService(mServer, mContext) < 0);
    char buff2[] = "N\tP2pAddService\t0\t0\tservice_name\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tP2pAddService\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcP2pAddService(mServer, mContext) == 0);
    char buff3[] = "N\tP2pAddService\t1\tquery_message\tresp_message";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tP2pAddService\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcP2pAddService(mServer, mContext) < 0);
    char buff4[] = "N\tP2pAddService\t1\tquery_message\tresp_message\t";
    mContext->oneProcess = buff4;
    mContext->nPos = strlen("N\tP2pAddService\t");
    mContext->nSize = strlen(buff4);
    EXPECT_TRUE(RpcP2pAddService(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pRemoveServiceTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pRemoveService(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pRemoveService\tx\t0\tservice_name";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pRemoveService\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pRemoveService(mServer, mContext) < 0);
    char buff1[] = "N\tP2pRemoveService\t0\t0\tservice_name";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pRemoveService\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pRemoveService(mServer, mContext) < 0);
    char buff2[] = "N\tP2pRemoveService\t0\t0\tservice_name\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tP2pRemoveService\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcP2pRemoveService(mServer, mContext) == 0);
    char buff3[] = "N\tP2pRemoveService\t1\tquery_message";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tP2pRemoveService\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcP2pRemoveService(mServer, mContext) < 0);
    char buff4[] = "N\tP2pRemoveService\t1\tquery_message\t";
    mContext->oneProcess = buff4;
    mContext->nPos = strlen("N\tP2pRemoveService\t");
    mContext->nSize = strlen(buff4);
    EXPECT_TRUE(RpcP2pRemoveService(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pReqServiceDiscoveryTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pReqServiceDiscovery(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pReqServiceDiscovery\t00:00:00:00:00:00\tdiscover message";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pReqServiceDiscovery\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pReqServiceDiscovery(mServer, mContext) < 0);
    char buff1[] = "N\tP2pReqServiceDiscovery\t00:00:00:00:00:00\tdiscover message\t32\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pReqServiceDiscovery\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pReqServiceDiscovery(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pCancelServiceDiscoveryTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pCancelServiceDiscovery(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pCancelServiceDiscovery\tdiscover message";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pCancelServiceDiscovery\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pCancelServiceDiscovery(mServer, mContext) < 0);
    char buff1[] = "N\tP2pCancelServiceDiscovery\tdiscover message\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pCancelServiceDiscovery\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pCancelServiceDiscovery(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetMiracastTypeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetMiracastType(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetMiracastType\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetMiracastType\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetMiracastType(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetMiracastType\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetMiracastType\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetMiracastType(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pRespServerDiscoveryTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pRespServerDiscovery(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pRespServerDiscovery\t0\t0\t00:00:00:00:00:00\ttlvs message";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pRespServerDiscovery\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pRespServerDiscovery(mServer, mContext) < 0);
    char buff1[] = "N\tP2pRespServerDiscovery\t0\t0\t00:00:00:00:00:00\ttlvs message\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pRespServerDiscovery\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pRespServerDiscovery(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetServDiscExternalTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetServDiscExternal(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetServDiscExternal\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetServDiscExternal\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetServDiscExternal(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetServDiscExternal\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetServDiscExternal\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetServDiscExternal(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerAddTest, RpcP2pSetPersistentReconnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcP2pSetPersistentReconnect(nullptr, nullptr) < 0);
    char buff[] = "N\tP2pSetPersistentReconnect\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tP2pSetPersistentReconnect\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcP2pSetPersistentReconnect(mServer, mContext) < 0);
    char buff1[] = "N\tP2pSetPersistentReconnect\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tP2pSetPersistentReconnect\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcP2pSetPersistentReconnect(mServer, mContext) == 0);
}
}  // namespace Wifi
}  // namespace OHOS