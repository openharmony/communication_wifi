/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "kits/c/wifi_p2p.h"
#include "kits/c/wifi_hid2d.h"
#include "securec.h"
#include "wifi_logger.h"

using ::testing::Return;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiCP2PStubTest");

namespace OHOS {
namespace Wifi {
int g_networkid = 15;
int g_config = 5;
P2pState g_moded = P2pState::P2P_STATE_CLOSING;
class WifiP2pTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};
void P2pCallback(P2pState state)
{}

void P2pPersistentCallback(void)
{}

void P2pConnectionCallback(const WifiP2pLinkedInfo info)
{}

void P2pPeersCallback(WifiP2pDevice* devices, int len)
{}

void WifiCfgChangCallback(CfgType, char* data, int dataLen)
{}

HWTEST_F(WifiP2pTest, EnableP2pTest, TestSize.Level1)
{
    EnableP2p();
}

HWTEST_F(WifiP2pTest, DisableP2pTest, TestSize.Level1)
{
    DisableP2p();
}

HWTEST_F(WifiP2pTest, GetP2pEnableStatusTests, TestSize.Level1)
{
    P2pState* state = &g_moded;
    GetP2pEnableStatus(state);
}

HWTEST_F(WifiP2pTest, DiscoverDevicesTest, TestSize.Level1)
{
    DiscoverDevices();
}

HWTEST_F(WifiP2pTest, StopDiscoverDevicesTest, TestSize.Level1)
{
    StopDiscoverDevices();
}

HWTEST_F(WifiP2pTest, DiscoverServicesTest, TestSize.Level1)
{
    DiscoverServices();
}

HWTEST_F(WifiP2pTest, StopDiscoverServicesTest, TestSize.Level1)
{
    StopDiscoverServices();
}

HWTEST_F(WifiP2pTest, StartP2pListenTest, TestSize.Level1)
{
    int period = 0;
    int interval = 0;
    StartP2pListen(period, interval);
}

HWTEST_F(WifiP2pTest, StopP2pListenTests, TestSize.Level1)
{
    StopP2pListen();
}

HWTEST_F(WifiP2pTest, CreateGroupTests, TestSize.Level1)
{
    WifiP2pConfig config;
    config.netId = g_networkid;
    CreateGroup(&config);
}

HWTEST_F(WifiP2pTest, RemoveGroupTests, TestSize.Level1)
{
    RemoveGroup();
}

HWTEST_F(WifiP2pTest, DeleteGroupTests, TestSize.Level1)
{
    WifiP2pGroupInfo group;
    group.networkId = g_networkid;
    DeleteGroup(&group);
}

HWTEST_F(WifiP2pTest, P2pConnectTests, TestSize.Level1)
{
    WifiP2pConfig config;
    config.netId = g_networkid;
    P2pConnect(&config);
}

HWTEST_F(WifiP2pTest, P2pCancelConnectTests, TestSize.Level1)
{
    P2pCancelConnect();
}

HWTEST_F(WifiP2pTest, GetCurrentGroupTests, TestSize.Level1)
{
    WifiP2pGroupInfo groupInfo;
    groupInfo.networkId = g_networkid;
    GetCurrentGroup(&groupInfo);
}

HWTEST_F(WifiP2pTest, GetP2pConnectedStatusTests, TestSize.Level1)
{
    int* status = &g_networkid;
    GetP2pConnectedStatus(status);
}

HWTEST_F(WifiP2pTest, QueryP2pDevicesTests, TestSize.Level1)
{
    WifiP2pDevice clientDevices;
    clientDevices.groupCapabilitys = g_networkid;
    int size = 0;
    int* retSize = &g_config;
    EXPECT_EQ(QueryP2pDevices(&clientDevices, size, retSize), ERROR_WIFI_UNKNOWN);
}

HWTEST_F(WifiP2pTest, QueryP2pLocalDeviceTests, TestSize.Level1)
{
    WIFI_LOGI("QueryP2pLocalDeviceTests enter");
    WifiP2pDevice deviceInfo;
    deviceInfo.supportWpsConfigMethods = 1;
    deviceInfo.deviceCapabilitys = 1;
    deviceInfo.groupCapabilitys = 1;
    if (strcpy_s(deviceInfo.deviceName, sizeof(deviceInfo.deviceName), "device") != EOK) {
        WIFI_LOGE("QueryP2pLocalDeviceTests strcpy_s deviceName Fail!");
        return;
    }

    if (strcpy_s(deviceInfo.primaryDeviceType, sizeof(deviceInfo.primaryDeviceType), "10-0050F204-1") != EOK) {
        WIFI_LOGE("QueryP2pLocalDeviceTests strcpy_s primaryDeviceType Fail!");
        return;
    }

    if (strcpy_s(deviceInfo.secondaryDeviceType, sizeof(deviceInfo.secondaryDeviceType), "10-0050F204-2") != EOK) {
        WIFI_LOGE("QueryP2pLocalDeviceTests strcpy_s secondaryDeviceType Fail!");
        return;
    }
    QueryP2pLocalDevice(&deviceInfo);
}

HWTEST_F(WifiP2pTest, QueryP2pGroupsTests, TestSize.Level1)
{
    WifiP2pGroupInfo groupInfo;
    groupInfo.networkId = g_networkid;
    int size = 0;
    EXPECT_EQ(QueryP2pGroups(&groupInfo, size), ERROR_WIFI_UNKNOWN);
}

HWTEST_F(WifiP2pTest, RegisterP2pStateChangedCallbackTest, TestSize.Level1)
{
    EXPECT_EQ(RegisterP2pStateChangedCallback(P2pCallback), WIFI_SUCCESS);
}

HWTEST_F(WifiP2pTest, RegisterP2pPersistentGroupsChangedCallbackTest, TestSize.Level1)
{
    EXPECT_EQ(RegisterP2pPersistentGroupsChangedCallback(P2pPersistentCallback), WIFI_SUCCESS);
}

HWTEST_F(WifiP2pTest, RegisterP2pConnectionChangedCallbackTest, TestSize.Level1)
{
    EXPECT_EQ(RegisterP2pConnectionChangedCallback(P2pConnectionCallback), WIFI_SUCCESS);
}

HWTEST_F(WifiP2pTest, RegisterP2pPeersChangedCallbackTest, TestSize.Level1)
{
    EXPECT_EQ(RegisterP2pPeersChangedCallback(P2pPeersCallback), WIFI_SUCCESS);
}

HWTEST_F(WifiP2pTest, RegisterCfgChangCallbackTest, TestSize.Level1)
{
    EXPECT_EQ(RegisterCfgChangCallback(WifiCfgChangCallback), WIFI_SUCCESS);
}

HWTEST_F(WifiP2pTest, UnregisterCfgChangCallbackTest, TestSize.Level1)
{
    EXPECT_EQ(UnregisterCfgChangCallback(), WIFI_SUCCESS);
}
}
}
