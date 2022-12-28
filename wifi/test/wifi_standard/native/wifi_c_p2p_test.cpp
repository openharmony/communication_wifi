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
#include "../../../interfaces/kits/c/wifi_p2p.h"
#include "../../../interfaces/kits/c/wifi_hid2d.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int NetWorkId = 15;
constexpr int Config = 5;
constexpr int Band = 5;
class WifiP2pTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
public:
    void P2pCallback(P2pState state)
    {}

    void P2pPersistentCallback(void)
    {}

    void P2pConnectionCallback(const WifiP2pLinkedInfo info)
    {}

    void P2pPeersCallback(WifiP2pDevice* devices, int len)
    {}
};
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
    P2pState* state = P2pState::P2P_STATE_CLOSING;
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
    WifiP2pConfig* config = nullptr;
    config->netId = NetWorkId;
    CreateGroup(config);
}

HWTEST_F(WifiP2pTest, RemoveGroupTests, TestSize.Level1)
{
    RemoveGroup();
}

HWTEST_F(WifiP2pTest, DeleteGroupTests, TestSize.Level1)
{
    WifiP2pGroupInfo* group;
    group->networkId = NetWorkId;
    DeleteGroup(group);
}

HWTEST_F(WifiP2pTest, P2pConnectTests, TestSize.Level1)
{
    WifiP2pConfig* config;
    config->netId = NetWorkId;
    P2pConnect(config);
}

HWTEST_F(WifiP2pTest, P2pCancelConnectTests, TestSize.Level1)
{
    P2pCancelConnect();
}

HWTEST_F(WifiP2pTest, GetCurrentGroupTests, TestSize.Level1)
{
    WifiP2pGroupInfo* groupInfo;
    groupInfo->networkId = NetWorkId;
    groupInfo->interface = Band;
    GetCurrentGroup(groupInfo);
}

HWTEST_F(WifiP2pTest, GetP2pConnectedStatusTests, TestSize.Level1)
{
    int* status;
    status = NetWorkId;
    GetP2pConnectedStatus(status);
}

HWTEST_F(WifiP2pTest, QueryP2pDevicesTests, TestSize.Level1)
{
    WifiP2pDevice* clientDevices;
    clientDevices->groupCapabilitys = NetWorkId;
    int size = 0;
    int* retSize = Config;
    QueryP2pDevices(clientDevices, size, retSize);
}

HWTEST_F(WifiP2pTest, QueryP2pGroupsTests, TestSize.Level1)
{
    WifiP2pGroupInfo* groupInfo;
    groupInfo->networkId = NetWorkId;
    int size = 0;
    QueryP2pGroups(groupInfo, size);
}

HWTEST_F(WifiP2pTest, RegisterP2pStateChangedCallbackTest, TestSize.Level1)
{

    RegisterP2pStateChangedCallback(P2pCallback);
}

HWTEST_F(WifiP2pTest, RegisterP2pPersistentGroupsChangedCallbackTest, TestSize.Level1)
{
    RegisterP2pPersistentGroupsChangedCallback(P2pPersistentCallback);
}

HWTEST_F(WifiP2pTest, RegisterP2pConnectionChangedCallbackTest, TestSize.Level1)
{
    RegisterP2pConnectionChangedCallback(P2pConnectionCallback);
}

HWTEST_F(WifiP2pTest, RegisterP2pPeersChangedCallbackTest, TestSize.Level1)
{
    P2pPeersChangedCallback callback = nullptr;
    RegisterP2pPeersChangedCallback(callback);
}

HWTEST_F(WifiP2pTest, RegisterCfgChangCallbackTest, TestSize.Level1)
{
    RegisterCfgChangCallback(P2pPeersCallback);
}
}
}
