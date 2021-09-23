
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
#include "p2p_idle_state.h"
#include "mock_p2p_monitor.h"
#include "mock_wifi_settings.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class P2pIdleStateTest : public testing::Test {
    const int TEST_CONFIG_METHOD1 = 8;
    const int TEST_CONFIG_METHOD2 = 128;
    const int TEST_CONFIG_METHOD3 = 256;

public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pMockP2pPendant.reset(new MockP2pPendant());
        pP2pIdleState.reset(new P2pIdleState(pMockP2pPendant->GetP2pStateMachine(), groupManager, deviceManager));
        pP2pIdleState->Init();
    }
    virtual void TearDown()
    {
        EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RegisterP2pCallback(_));
        pP2pIdleState.reset();
        pMockP2pPendant.reset();
    }

public:
    void AddGroupManager() const
    {
        pP2pIdleState->groupManager.ClearAll();
        WifiP2pGroupInfo group;
        group.SetP2pGroupStatus(P2pGroupStatus::GS_STARTED);
        group.SetNetworkId(1);
        WifiP2pDevice device;
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        group.SetOwner(device);
        pP2pIdleState->groupManager.AddGroup(group);
        pP2pIdleState->groupManager.SetCurrentGroup(group);
    }
    void AddDeviceManager() const
    {
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetWpsConfigMethod(P2pIdleStateTest::TEST_CONFIG_METHOD2);
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_GROUP_OWNER));
        device.SetPrimaryDeviceType("10-0050F204-5");
        pMockP2pPendant->AddDevice(device);
    }
    void AddDeviceManager1() const
    {
        pP2pIdleState->deviceManager.ClearAll();
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetWpsConfigMethod(P2pIdleStateTest::TEST_CONFIG_METHOD2);
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_GROUP_OWNER));
        device.SetPrimaryDeviceType("10-0050F204-5");
        pP2pIdleState->deviceManager.AddDevice(device);
    }
    void AddDeviceManager2() const
    {
        pP2pIdleState->deviceManager.ClearAll();
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetWpsConfigMethod(P2pIdleStateTest::TEST_CONFIG_METHOD1);
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_GROUP_OWNER));
        device.SetPrimaryDeviceType("10-0050F204-5");
        pP2pIdleState->deviceManager.AddDevice(device);
    }
    void AddDeviceManager3() const
    {
        pP2pIdleState->deviceManager.ClearAll();
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetWpsConfigMethod(P2pIdleStateTest::TEST_CONFIG_METHOD3);
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_GROUP_OWNER));
        device.SetPrimaryDeviceType("10-0050F204-5");
        pP2pIdleState->deviceManager.AddDevice(device);
    }
    std::unique_ptr<P2pIdleState> pP2pIdleState;
    std::unique_ptr<MockP2pPendant> pMockP2pPendant;
    WifiP2pGroupManager groupManager;
    WifiP2pDeviceManager deviceManager;
};

HWTEST_F(P2pIdleStateTest, GoInState, TestSize.Level1)
{
    pP2pIdleState->GoInState();
}

HWTEST_F(P2pIdleStateTest, GoOutState, TestSize.Level1)
{
    pP2pIdleState->GoOutState();
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg1, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_STOP_DEVICE_DISCOVERS));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pStopFind()).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pFlush()).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pStopFind())
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg2, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_CONNECT));
    WifiP2pConfig config;
    msg.SetMessageObj(config);
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    AddDeviceManager();
    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    msg.SetMessageObj(config);
    EXPECT_CALL(pMockP2pPendant->GetP2pStateMachine(), IsConfigUnusable(_)).WillOnce(Return(P2pConfigErrCode::SUCCESS));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pStopFind()).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_CONNECT));
    WifiP2pConfig config;
    AddDeviceManager();
    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    msg.SetMessageObj(config);
    EXPECT_CALL(pMockP2pPendant->GetP2pStateMachine(), IsConfigUnusable(_)).WillOnce(Return(P2pConfigErrCode::SUCCESS));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pStopFind()).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg3, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_ENTER_PIN));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_SHOW_PIN));
    WifiP2pTempDiscEvent provDisc;
    msg.SetMessageObj(provDisc);
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg4, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DISCONNECT));
    EXPECT_FALSE(pP2pIdleState->ExecuteStateMsg(&msg));

    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_INVITATION_RECEIVED));
    WifiP2pGroupInfo group;
    WifiP2pDevice device;

    group.SetNetworkId(-1);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    group.SetNetworkId(1);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    AddGroupManager();
    device.SetDeviceAddress("");
    group.SetOwner(device);
    msg.SetMessageObj(group);
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    AddDeviceManager1();
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    AddDeviceManager2();
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));

    AddDeviceManager3();
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg5, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_GO_NEG_REQUEST));
    WifiP2pConfig conf;
    msg.SetMessageObj(conf);
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ExecuteStateMsg6, TestSize.Level1)
{
    InternalMessage msg;
    WifiP2pGroupInfo group;
    group.SetIsPersistent(true);
    msg.SetMessageObj(group);
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_STARTED));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_REMOVED));
    EXPECT_FALSE(pP2pIdleState->ExecuteStateMsg(&msg));
    EXPECT_FALSE(pP2pIdleState->ExecuteStateMsg(nullptr));
}

HWTEST_F(P2pIdleStateTest, ProcessCmdDeleteGroup, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ProcessCmdRemoveGroup, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}

HWTEST_F(P2pIdleStateTest, ProcessCmdCreateGroup, TestSize.Level1)
{
    InternalMessage msg;
    msg.SetMessageName(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_FORM_GROUP));
    EXPECT_TRUE(pP2pIdleState->ExecuteStateMsg(&msg));
}
}  // namespace Wifi
}  // namespace OHOS