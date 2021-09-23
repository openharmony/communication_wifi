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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_p2p_pendant.h"
#include "mock_wifi_p2p_hal_interface.h"
#include "p2p_group_operating_state.h"
#include "mock_p2p_monitor.h"
#include "mock_wifi_settings.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class P2pGroupOperatingStateTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pMockP2pPendant.reset(new MockP2pPendant());
        pP2pGroupOperatingState.reset(
            new P2pGroupOperatingState(pMockP2pPendant->GetP2pStateMachine(), groupManager, deviceManager));
        pP2pGroupOperatingState->Init();
    }
    virtual void TearDown()
    {
        pP2pGroupOperatingState.reset();
        EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RegisterP2pCallback(_));
        pMockP2pPendant.reset();
    }

public:
    void AddGroupManager()
    {
        pP2pGroupOperatingState->groupManager.ClearAll();
        WifiP2pGroupInfo group;
        group.SetP2pGroupStatus(P2pGroupStatus::GS_STARTED);
        group.SetNetworkId(1);
        group.SetIsPersistent(true);
        pP2pGroupOperatingState->groupManager.AddGroup(group);
        pP2pGroupOperatingState->groupManager.SetCurrentGroup(group);
    }
    std::unique_ptr<P2pGroupOperatingState> pP2pGroupOperatingState;
    std::unique_ptr<MockP2pPendant> pMockP2pPendant;
    WifiP2pGroupManager groupManager;
    WifiP2pDeviceManager deviceManager;
};

HWTEST_F(P2pGroupOperatingStateTest, GoInState, TestSize.Level1)
{
    pP2pGroupOperatingState->GoInState();
}

HWTEST_F(P2pGroupOperatingStateTest, GoOutState, TestSize.Level1)
{
    pP2pGroupOperatingState->GoOutState();
}

HWTEST_F(P2pGroupOperatingStateTest, ExecuteStateMsg1, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_FORM_GROUP));
    WifiP2pConfig config;
    config.SetNetId(0);
    msg.SetMessageObj(config);
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupAdd(_, _, _)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));

    config.SetNetId(-2);
    msg.SetMessageObj(config);
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupAdd(_, _, _)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));

    config.SetNetId(-1);
    msg.SetMessageObj(config);
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupAdd(_, _, _)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));

    config.SetNetId(-5);
    msg.SetMessageObj(config);
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pGroupOperatingStateTest, ExecuteStateMsg2, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_STARTED));
    WifiP2pGroupInfo group;
    group.SetIsPersistent(true);
    msg.SetMessageObj(group);
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
    group.SetIsPersistent(false);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));

    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CREATE_GROUP_TIMED_OUT));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));

    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pGroupOperatingStateTest, ExecuteStateMsg3, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));

    AddGroupManager();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupRemove(_))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
    AddGroupManager();
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pGroupOperatingStateTest, ExecuteStateMsg4, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP));
    AddGroupManager();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RemoveNetwork(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupRemove(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WifiP2pGroupInfo group;
    group.SetNetworkId(1);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pGroupOperatingStateTest, ExecuteStateMsg5, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP));
    AddGroupManager();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RemoveNetwork(_))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupRemove(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WifiP2pGroupInfo group;
    group.SetNetworkId(1);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pGroupOperatingStateTest, ExecuteStateMsg6, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DISCONNECT));
    EXPECT_FALSE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP));
    AddGroupManager();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RemoveNetwork(_))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WifiP2pGroupInfo group;
    group.SetNetworkId(2);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
    EXPECT_FALSE(pP2pGroupOperatingState->ExecuteStateMsg(nullptr));
}

HWTEST_F(P2pGroupOperatingStateTest, ProcessGroupRemovedEvt, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_REMOVED));
    AddGroupManager();
    EXPECT_TRUE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
    EXPECT_FALSE(pP2pGroupOperatingState->ExecuteStateMsg(nullptr));

    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_PBC_REQ));
    EXPECT_FALSE(pP2pGroupOperatingState->ExecuteStateMsg(&msg));
}
}  // namespace Wifi
}  // namespace OHOS