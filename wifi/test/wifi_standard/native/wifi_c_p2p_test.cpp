/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "../../../interfaces/kits/c/wifi_p2p.h"
#include "../../../interfaces/kits/c/wifi_hid2d.h"



using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class wifiP2p_Test : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown(){}
};
HWTEST_F(wifiHid2d_Test, EnableP2pTest, TestSize.Level1)
{
    EnableP2p();
}

HWTEST_F(wifiHid2d_Test, DisableP2pTest, TestSize.Level1)
{
    DisableP2p();
}

HWTEST_F(wifiHid2d_Test, GetP2pEnableStatusTests, TestSize.Level1)
{
    P2pState* state = P2pState::P2P_STATE_IDLE;
    GetP2pEnableStatus(state);
}

HWTEST_F(wifiHid2d_Test, DiscoverDevicesTest, TestSize.Level1)
{
    DiscoverDevices();
}

HWTEST_F(wifiHid2d_Test, StopDiscoverDevicesTest, TestSize.Level1)
{
    StopDiscoverDevices();
}

HWTEST_F(wifiHid2d_Test, DiscoverServicesTest, TestSize.Level1)
{
    DiscoverServices();
}

HWTEST_F(wifiHid2d_Test, StopDiscoverServicesTest, TestSize.Level1)
{
    StopDiscoverServices();
}

HWTEST_F(wifiHid2d_Test, StartP2pListenTest, TestSize.Level1)
{
    int period;
    int interval;
    StartP2pListen(period, interval);
}

HWTEST_F(wifiHid2d_Test, StopP2pListenTests, TestSize.Level1)
{
    StopP2pListen();
}

HWTEST_F(wifiHid2d_Test, CreateGroupTests, TestSize.Level1)
{
    WifiP2pConfig* config;
    CreateGroup(config);
}

HWTEST_F(wifiHid2d_Test, RemoveGroupTests, TestSize.Level1)
{
    RemoveGroup();
}

HWTEST_F(wifiHid2d_Test, DeleteGroupTests, TestSize.Level1)
{
    WifiP2pGroupInfo* group;
    DeleteGroup(group);
}

HWTEST_F(wifiHid2d_Test, P2pConnectTests, TestSize.Level1)
{
    WifiP2pConfig* config;
    P2pConnect(config);
}

HWTEST_F(wifiHid2d_Test, P2pCancelConnectTests, TestSize.Level1)
{
    P2pCancelConnect();
}

HWTEST_F(wifiHid2d_Test, GetCurrentGroupTests, TestSize.Level1)
{
    WifiP2pGroupInfo* groupInfo;
    GetCurrentGroup(groupInfo);
}

HWTEST_F(wifiHid2d_Test, GetP2pConnectedStatusTests, TestSize.Level1)
{
    int* status;
    GetP2pConnectedStatus(status);
}

HWTEST_F(wifiHid2d_Test, QueryP2pLocalDeviceTests, TestSize.Level1)
{
    WifiP2pDevice* deviceInfo;
    QueryP2pLocalDevice();
}

HWTEST_F(wifiHid2d_Test, QueryP2pDevicesTests, TestSize.Level1)
{
    WifiP2pDevice* clientDevices;
    int size;
    int* retSize;
    QueryP2pDevices(clientDevices, size, retSize);
}

HWTEST_F(wifiHid2d_Test, QueryP2pGroupsTests, TestSize.Level1)
{
    WifiP2pGroupInfo* groupInfo;
    int size;
    QueryP2pGroups(groupInfo, size);
}

HWTEST_F(wifiHid2d_Test, RegisterP2pStateChangedCallbackTest, TestSize.Level1)
{
    P2pStateChangedCallback callback;
    RegisterP2pStateChangedCallback(callback);
}

HWTEST_F(wifiHid2d_Test, RegisterP2pPersistentGroupsChangedCallbackTest, TestSize.Level1)
{
    P2pPersistentGroupsChangedCallback callback;
    RegisterP2pPersistentGroupsChangedCallback(callback);
}

HWTEST_F(wifiHid2d_Test, RegisterP2pConnectionChangedCallbackTest, TestSize.Level1)
{
    P2pConnectionChangedCallback callback;
    RegisterP2pConnectionChangedCallback(callback);
}

HWTEST_F(wifiHid2d_Test, RegisterP2pPeersChangedCallbackTest, TestSize.Level1)
{
    P2pPeersChangedCallback callback;
    RegisterP2pPeersChangedCallback(callback);
}

HWTEST_F(wifiHid2d_Test, RegisterP2pPersistentGroupsChangedCallbackTest, TestSize.Level1)
{
    WifiCfgChangCallback callback;
    RegisterCfgChangCallback(callback);
}

HWTEST_F(wifiHid2d_Test, OnP2pStateChangedTest, TestSize.Level1)
{
    int state;
    OnP2pStateChanged(state);
}

HWTEST_F(wifiHid2d_Test, OnP2pPersistentGroupsChangedTest, TestSize.Level1)
{
    OnP2pPersistentGroupsChanged();
}

HWTEST_F(wifiHid2d_Test, OnP2pThisDeviceChangedTest, TestSize.Level1)
{
    OnP2pThisDeviceChanged();
}

HWTEST_F(wifiHid2d_Test, OnP2pPeersChangedTest, TestSize.Level1)
{
    std::vector<OHOS::Wifi::WifiP2pDevice> devices;
    OnP2pPeersChanged(devices);
}

HWTEST_F(wifiHid2d_Test, OnP2pPeersChangedTest, TestSize.Level1)
{
    OnP2pPeersChanged();
}
}
}
