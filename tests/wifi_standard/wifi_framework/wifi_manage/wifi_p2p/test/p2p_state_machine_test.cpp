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

#include "p2p_state_machine.h"
#include "mock_p2p_pendant.h"
#include "wifi_p2p_msg.h"
#include "mock_p2p_monitor.h"
#include "mock_authorizing_negotiation_request_state.h"
#include "mock_group_formed_state.h"
#include "mock_group_negotiation_state.h"
#include "mock_invitation_recelved_state.h"
#include "mock_invitation_request_state.h"
#include "mock_p2p_default_state.h"
#include "mock_p2p_disabled_state.h"
#include "mock_p2p_disabling_state.h"
#include "mock_p2p_enabled_state.h"
#include "mock_p2p_enabling_state.h"
#include "mock_p2p_group_formation_state.h"
#include "mock_p2p_group_join_state.h"
#include "mock_p2p_group_operating_state.h"
#include "mock_p2p_idle_state.h"
#include "mock_p2p_inviting_state.h"
#include "mock_p2p_state_machine.h"
#include "mock_provision_discovery_state.h"
#include "mock_wifi_p2p_hal_interface.h"
#include "mock_wifi_settings.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::ext::TestSize;

DEFINE_WIFILOG_P2P_LABEL("p2pStateMachineTest");
namespace OHOS {
namespace Wifi {
class P2pStateMachineTest : public testing::Test {
public:
    ~P2pStateMachineTest()
    {}
    P2pStateMachineTest() : pMockP2pPendant(nullptr), groupManager(), deviceManager(), svrManager()
    {}
    static void SetUpTestCase(){}
    static void TearDownTestCase(){}
    virtual void SetUp()
    {
        WifiP2PHalInterface::GetInstance();
        pMockP2pPendant = new MockP2pPendant();
        pMockAuthorizingNegotiationRequestState = &pMockP2pPendant->GetMockAuthorizingNegotiationRequestState();
        pMockGroupFormedState = &pMockP2pPendant->GetMockGroupFormedState();
        pMockGroupNegotiationState = &pMockP2pPendant->GetMockGroupNegotiationState();
        pMockInvitationReceivedState = &pMockP2pPendant->GetMockInvitationReceivedState();
        pMockInvitationRequestState = &pMockP2pPendant->GetMockInvitationRequestState();
        pMockP2pDefaultState = &pMockP2pPendant->GetMockP2pDefaultState();
        pMockP2pDisabledState = &pMockP2pPendant->GetMockP2pDisabledState();
        pMockP2pDisablingState = &pMockP2pPendant->GetMockP2pDisablingState();
        pMockP2pEnabledState = &pMockP2pPendant->GetMockP2pEnabledState();
        pMockP2pEnablingState = &pMockP2pPendant->GetMockP2pEnablingState();
        pMockP2pGroupFormationState = &pMockP2pPendant->GetMockP2pGroupFormationState();
        pMockP2pGroupJoinState = &pMockP2pPendant->GetMockP2pGroupJoinState();
        pMockP2pGroupOperatingState = &pMockP2pPendant->GetMockP2pGroupOperatingState();
        pMockP2pIdleState = &pMockP2pPendant->GetMockP2pIdleState();
        pMockP2pInvitingState = &pMockP2pPendant->GetMockP2pInvitingState();
        pMockProvisionDiscoveryState = &pMockP2pPendant->GetMockProvisionDiscoveryState();
        pMockP2pMonitor = &pMockP2pPendant->GetMockP2pMonitor();
        pP2pStateMachine.reset(new P2pStateMachine(*pMockP2pMonitor,
            groupManager,
            deviceManager,
            svrManager,
            *pMockAuthorizingNegotiationRequestState,
            *pMockGroupFormedState,
            *pMockGroupNegotiationState,
            *pMockInvitationReceivedState,
            *pMockInvitationRequestState,
            *pMockP2pDefaultState,
            *pMockP2pDisabledState,
            *pMockP2pDisablingState,
            *pMockP2pEnabledState,
            *pMockP2pEnablingState,
            *pMockP2pGroupFormationState,
            *pMockP2pGroupJoinState,
            *pMockP2pGroupOperatingState,
            *pMockP2pIdleState,
            *pMockP2pInvitingState,
            *pMockProvisionDiscoveryState));
        pP2pStateMachine->groupManager.Initialize();
    }
    virtual void TearDown()
    {
        EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RegisterP2pCallback(_));
        pP2pStateMachine.reset();
        delete pMockP2pPendant;
        pMockAuthorizingNegotiationRequestState = nullptr;
        pMockGroupFormedState = nullptr;
        pMockGroupNegotiationState = nullptr;
        pMockInvitationReceivedState = nullptr;
        pMockInvitationRequestState = nullptr;
        pMockP2pDefaultState = nullptr;
        pMockP2pDisabledState = nullptr;
        pMockP2pDisablingState = nullptr;
        pMockP2pEnabledState = nullptr;
        pMockP2pEnablingState = nullptr;
        pMockP2pGroupFormationState = nullptr;
        pMockP2pGroupJoinState = nullptr;
        pMockP2pGroupOperatingState = nullptr;
        pMockP2pIdleState = nullptr;
        pMockP2pInvitingState = nullptr;
        pMockProvisionDiscoveryState = nullptr;
        pMockP2pMonitor = nullptr;
    }

public:
    std::unique_ptr<P2pStateMachine> pP2pStateMachine;
    MockP2pPendant *pMockP2pPendant;
    WifiP2pGroupManager groupManager;
    WifiP2pDeviceManager deviceManager;
    WifiP2pServiceManager svrManager;

    MockAuthorizingNegotiationRequestState *pMockAuthorizingNegotiationRequestState;
    MockGroupFormedState *pMockGroupFormedState;
    MockGroupNegotiationState *pMockGroupNegotiationState;
    MockInvitationReceivedState *pMockInvitationReceivedState;
    MockInvitationRequestState *pMockInvitationRequestState;
    MockP2pDefaultState *pMockP2pDefaultState;
    MockP2pDisabledState *pMockP2pDisabledState;
    MockP2pDisablingState *pMockP2pDisablingState;
    MockP2pEnabledState *pMockP2pEnabledState;
    MockP2pEnablingState *pMockP2pEnablingState;
    MockP2pGroupFormationState *pMockP2pGroupFormationState;
    MockP2pGroupJoinState *pMockP2pGroupJoinState;
    MockP2pGroupOperatingState *pMockP2pGroupOperatingState;
    MockP2pIdleState *pMockP2pIdleState;
    MockP2pInvitingState *pMockP2pInvitingState;
    MockProvisionDiscoveryState *pMockProvisionDiscoveryState;
    MockP2pMonitor *pMockP2pMonitor;

public:
    void Addsvr()
    {
        pP2pStateMachine->serviceManager.SetQueryId("queryId");
    }
    void AddDeviceManager()
    {
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_GROUP_OWNER));
        device.SetPrimaryDeviceType("10-0050F204-5");
        pP2pStateMachine->deviceManager.AddDevice(device);
    }
    void AddDeviceManagerLimit()
    {
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_GROUP_LIMIT));
        device.SetPrimaryDeviceType("10-0050F204-5");
        pP2pStateMachine->deviceManager.AddDevice(device);
    }
    void AddDeviceManagerInViteable()
    {
        WifiP2pDevice device;
        device.SetDeviceName("device");
        device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        device.SetGroupCapabilitys(static_cast<int>(P2pGroupCapability::PGC_PERSISTENT_RECONN));
        device.SetPrimaryDeviceType("10-0050F204-5");
        device.SetDeviceCapabilitys(static_cast<int>(P2pDeviceCapability::PDC_INVITATION_PROCEDURE));
        pP2pStateMachine->deviceManager.AddDevice(device);
    }
    void AddGroupManager()
    {
        WifiP2pGroupInfo groupInfo;
        groupInfo.SetNetworkId(0);
        groupInfo.SetGroupName("AAA");
        groupInfo.SetIsGroupOwner(true);
        WifiP2pDevice owner;
        owner.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        groupInfo.SetOwner(owner);
        pP2pStateMachine->groupManager.AddGroup(groupInfo);
    }
    void AddGroupManager2()
    {
        WifiP2pGroupInfo groupInfo;
        groupInfo.SetNetworkId(-1);
        groupInfo.SetGroupName("AAA");
        groupInfo.SetIsGroupOwner(true);
        WifiP2pDevice owner;
        owner.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
        groupInfo.SetOwner(owner);
        pP2pStateMachine->groupManager.AddGroup(groupInfo);
    }
    void WarpHandlerDiscoverPeers()
    {
        pP2pStateMachine->HandlerDiscoverPeers();
    }
    void WarpRegisterEventHandler()
    {
        pP2pStateMachine->RegisterEventHandler();
    }

    void WarpUpdateThisDevice()
    {
        pP2pStateMachine->UpdateOwnDevice(P2pDeviceStatus::PDS_CONNECTED);
    }
    void WarpUpdatePersistentGroups()
    {
        pP2pStateMachine->UpdatePersistentGroups();
    }

    bool WarpReinvokePersistentGroup(WifiP2pConfig &config) const
    {
        return pP2pStateMachine->ReawakenPersistentGroup(config);
    }
    void WarpFetchNewerDeviceInfo(const std::string &deviceAddr) const
    {
        pP2pStateMachine->FetchNewerDeviceInfo(deviceAddr);
    }
    void WarpDealGroupCreationFailed()
    {
        pP2pStateMachine->DealGroupCreationFailed();
    }
    void WarpRemoveGroupByNetworkId(int networkId) const
    {
        pP2pStateMachine->RemoveGroupByNetworkId(networkId);
    }
    void WarpSetWifiP2pInfoOnGroupFormed(const std::string &groupOwnerAddress)
    {
        pP2pStateMachine->SetWifiP2pInfoWhenGroupFormed(groupOwnerAddress);
    }
    void WarpInitializeThisDevice()
    {
        pP2pStateMachine->InitializeThisDevice();
    }
    bool WarpIsUsableNetworkName(std::string nwName)
    {
        return pP2pStateMachine->IsUsableNetworkName(nwName);
    }
    P2pConfigErrCode WarpIsConfigUnusable(const WifiP2pConfig &config)
    {
        return pP2pStateMachine->IsConfigUnusable(config);
    }
    bool WarpIsConfigUsableAsGroup(WifiP2pConfig config)
    {
        return pP2pStateMachine->IsConfigUsableAsGroup(config);
    }
    void WarpCleanSupplicantServiceReq()
    {
        pP2pStateMachine->CancelSupplicantSrvDiscReq();
    }

    void WarpBroadcastP2pStatusChanged(P2pState state) const
    {
        pP2pStateMachine->BroadcastP2pStatusChanged(state);
    }
    void WarpBroadcastP2pPeersChanged() const
    {
        pP2pStateMachine->BroadcastP2pPeersChanged();
    }
    void WarpBroadcastP2pServicesChanged() const
    {
        pP2pStateMachine->BroadcastP2pServicesChanged();
    }
    void WarpBroadcastP2pConnectionChanged() const
    {
        pP2pStateMachine->BroadcastP2pConnectionChanged();
    }
    void WarpBroadcastThisDeviceChanaged(const WifiP2pDevice &device) const
    {
        pP2pStateMachine->BroadcastThisDeviceChanaged(device);
    }
    void WarpBroadcastP2pDiscoveryChanged(bool isActive) const
    {
        pP2pStateMachine->BroadcastP2pDiscoveryChanged(isActive);
    }
    void WarpBroadcastPersistentGroupsChanged() const
    {
        pP2pStateMachine->BroadcastPersistentGroupsChanged();
    }
    void WarpBroadcastActionResult(P2pActionCallback action, ErrCode result) const
    {
        pP2pStateMachine->BroadcastActionResult(action, result);
    }

    void WarpNotifyInvitationSent(const std::string &pin, const std::string &peerAddress) const
    {
        pP2pStateMachine->NotifyUserInvitationSentMessage(pin, peerAddress);
    }
    void WarpNotifyP2pProvDiscShowPinRequest(const std::string &pin, const std::string &peerAddress)
    {
        pP2pStateMachine->NotifyUserProvDiscShowPinRequestMessage(pin, peerAddress);
    }
    void WarpP2pConnectWithPinDisplay(const WifiP2pConfig &config) const
    {
        pP2pStateMachine->P2pConnectByShowingPin(config);
    }
    void WarpNotifyInvitationReceived()
    {
        pP2pStateMachine->NotifyUserInvitationReceivedMessage();
    }
    void WarpNotifyInvitationReceived2()
    {
        WpsInfo info;
        info.SetWpsMethod(WpsMethod::WPS_METHOD_KEYPAD);
        pP2pStateMachine->savedP2pConfig.SetWpsInfo(info);
        pP2pStateMachine->NotifyUserInvitationReceivedMessage();
    }
    void WarpNotifyInvitationReceived3()
    {
        WpsInfo info;
        info.SetWpsMethod(WpsMethod::WPS_METHOD_DISPLAY);
        pP2pStateMachine->savedP2pConfig.SetWpsInfo(info);
        pP2pStateMachine->NotifyUserInvitationReceivedMessage();
    }

    void WarpClearWifiP2pInfo()
    {
        pP2pStateMachine->ClearWifiP2pInfo();
    }
};

void ButtonTest(AlertDialog &dialog, std::any ctx)
{
    printf("button callback, input = %s\n", dialog.GetInputBox("input pin").c_str());
}

HWTEST_F(P2pStateMachineTest, RegisterP2pServiceCallbacks_SUCCESS, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
}

HWTEST_F(P2pStateMachineTest, HandlerDiscoverPeers, TestSize.Level1)
{
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pFind(DISC_TIMEOUT_S))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    WarpHandlerDiscoverPeers();
}

HWTEST_F(P2pStateMachineTest, HandlerDiscoverPeers2, TestSize.Level1)
{
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), P2pFind(DISC_TIMEOUT_S))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WarpHandlerDiscoverPeers();
}

HWTEST_F(P2pStateMachineTest, RegisterEventHandler, TestSize.Level1)
{
    EXPECT_CALL(*pMockP2pMonitor, RegisterIfaceHandler(_, _));
    WarpRegisterEventHandler();
}

HWTEST_F(P2pStateMachineTest, UpdateOwnDevice, TestSize.Level1)
{
    WarpUpdateThisDevice();
}

HWTEST_F(P2pStateMachineTest, UpdatePersistentGroups_SUCCESS, TestSize.Level1)
{
    std::map<int, WifiP2pGroupInfo> mapGroups;
    WifiP2pGroupInfo p2pGroupInfo;
    WifiP2pDevice device;
    device.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    p2pGroupInfo.SetOwner(device);
    mapGroups[100] = p2pGroupInfo;
    deviceManager.AddDevice(device);
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_))
        .WillOnce(DoAll(SetArgReferee<0>(mapGroups), Return(WifiErrorNo::WIFI_IDL_OPT_OK)));
    WarpUpdatePersistentGroups();
}

HWTEST_F(P2pStateMachineTest, UpdatePersistentGroups_FAILED, TestSize.Level1)
{
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WarpUpdatePersistentGroups();
}

HWTEST_F(P2pStateMachineTest, P2pConnectWithPinDisplay_SUCCESS, TestSize.Level1)
{
    WifiP2pConfig conf;
    WarpP2pConnectWithPinDisplay(conf);

    conf.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    WarpP2pConnectWithPinDisplay(conf);

    AddDeviceManager();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), Connect(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>("11"), Return(WifiErrorNo::WIFI_IDL_OPT_FAILED)));
    WarpP2pConnectWithPinDisplay(conf);
}

HWTEST_F(P2pStateMachineTest, DealGroupCreationFailed, TestSize.Level1)
{
    WarpDealGroupCreationFailed();
}

HWTEST_F(P2pStateMachineTest, RemoveGroupByNetworkId, TestSize.Level1)
{
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RemoveNetwork(Eq(1)))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WarpRemoveGroupByNetworkId(1);
}

HWTEST_F(P2pStateMachineTest, SetWifiP2pInfoWhenGroupFormed, TestSize.Level1)
{
    WarpSetWifiP2pInfoOnGroupFormed("AA:BB:CC:DD:EE:FF");
}

HWTEST_F(P2pStateMachineTest, InitializeThisDevice1, TestSize.Level1)
{
    P2pVendorConfig vendorconfig, a;
    vendorconfig.SetDeviceName("DeviceName");
    vendorconfig.SetPrimaryDeviceType("DeviceType");
    vendorconfig.SetRandomMacSupport(true);
    WarpInitializeThisDevice();
}

HWTEST_F(P2pStateMachineTest, InitializeThisDevice2, TestSize.Level1)
{
    P2pVendorConfig vendorconfig;
    vendorconfig.SetDeviceName("");
    vendorconfig.SetPrimaryDeviceType("DeviceType");
    vendorconfig.SetRandomMacSupport(true);
    WarpInitializeThisDevice();
}

HWTEST_F(P2pStateMachineTest, IsUsableNetworkName, TestSize.Level1)
{
    EXPECT_FALSE(WarpIsUsableNetworkName(""));
    EXPECT_TRUE(WarpIsUsableNetworkName("12345678910"));
    EXPECT_FALSE(WarpIsUsableNetworkName("1"));
}

HWTEST_F(P2pStateMachineTest, IsConfigUnusable, TestSize.Level1)
{
    WifiP2pConfig config;
    config.SetDeviceAddress("");
    EXPECT_TRUE(WarpIsConfigUnusable(config) == P2pConfigErrCode::MAC_EMPTY);
    AddDeviceManager();
    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    EXPECT_FALSE(WarpIsConfigUnusable(config) == P2pConfigErrCode::SUCCESS);
    config.SetDeviceAddress("aa:cc:bb:dd:ee:ff");
    EXPECT_TRUE(WarpIsConfigUnusable(config) == P2pConfigErrCode::MAC_NOT_FOUND);
    config.SetDeviceAddress("aa:cc::bb:dd:ee:ff");
    EXPECT_TRUE(WarpIsConfigUnusable(config) == P2pConfigErrCode::ERR_MAC_FORMAT);
}

HWTEST_F(P2pStateMachineTest, IsConfigUsableAsGroup, TestSize.Level1)
{
    WifiP2pConfig config;
    config.SetDeviceAddress("");
    EXPECT_FALSE(WarpIsConfigUsableAsGroup(config));
    config.SetDeviceAddress("1");
    EXPECT_FALSE(WarpIsConfigUsableAsGroup(config));
    config.SetNetworkName("12345678910");
    config.SetPassphrase("12345678910");
    EXPECT_TRUE(WarpIsConfigUsableAsGroup(config));
}

HWTEST_F(P2pStateMachineTest, CancelSupplicantSrvDiscReq, TestSize.Level1)
{
    WarpCleanSupplicantServiceReq();
    Addsvr();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), CancelReqServiceDiscovery(testing::StrEq("queryId")))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    WarpCleanSupplicantServiceReq();
    Addsvr();
    WarpCleanSupplicantServiceReq();
}

HWTEST_F(P2pStateMachineTest, BroadcastP2pStatusChanged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pStateChangedEvent = [](P2pState state) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastP2pStatusChanged(P2pState::P2P_STATE_STARTED);
}

HWTEST_F(P2pStateMachineTest, BroadcastP2pPeersChanged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pPeersChangedEvent = [](const std::vector<WifiP2pDevice> &) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastP2pPeersChanged();
}

HWTEST_F(P2pStateMachineTest, BroadcastP2pServicesChanged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pServicesChangedEvent = [](const std::vector<WifiP2pServiceInfo> &) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastP2pServicesChanged();
}

HWTEST_F(P2pStateMachineTest, BroadcastP2pConnectionChanged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pConnectionChangedEvent = [](const WifiP2pInfo &) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastP2pConnectionChanged();
}

HWTEST_F(P2pStateMachineTest, BroadcastThisDeviceChanaged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pThisDeviceChangedEvent = [](const WifiP2pDevice &) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WifiP2pDevice device;
    WarpBroadcastThisDeviceChanaged(device);
}

HWTEST_F(P2pStateMachineTest, BroadcastP2pDiscoveryChanged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pDiscoveryChangedEvent = [](bool) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastP2pDiscoveryChanged(true);
}

HWTEST_F(P2pStateMachineTest, BroadcastPersistentGroupsChanged, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pGroupsChangedEvent = []() { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastPersistentGroupsChanged();
}

HWTEST_F(P2pStateMachineTest, BroadcastActionResult, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    callback.OnP2pActionResultEvent = [](P2pActionCallback, ErrCode) { WIFI_LOGI("lamda"); };
    pP2pStateMachine->RegisterP2pServiceCallbacks(callback);
    WarpBroadcastActionResult(P2pActionCallback::PutLocalP2pService, ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(P2pStateMachineTest, NotifyUserProvDiscShowPinRequestMessage, TestSize.Level1)
{
    std::string pin;
    const std::string peerAddress;
    WarpNotifyP2pProvDiscShowPinRequest(pin, peerAddress);
}

HWTEST_F(P2pStateMachineTest, NotifyUserInvitationSentMessage, TestSize.Level1)
{
    std::string pin;
    const std::string peerAddress;
    WarpNotifyInvitationSent(pin, peerAddress);
}

HWTEST_F(P2pStateMachineTest, NotifyInvitationReceived1, TestSize.Level1)
{
    WarpNotifyInvitationReceived();
}

HWTEST_F(P2pStateMachineTest, NotifyInvitationReceived2, TestSize.Level1)
{
    WarpNotifyInvitationReceived2();
}

HWTEST_F(P2pStateMachineTest, NotifyInvitationReceived3, TestSize.Level1)
{
    WarpNotifyInvitationReceived3();
}

HWTEST_F(P2pStateMachineTest, ClearWifiP2pInfo, TestSize.Level1)
{
    WarpClearWifiP2pInfo();
}

HWTEST_F(P2pStateMachineTest, ReinvokePersistentGroup1, TestSize.Level1)
{
    WifiP2pConfig config;
    EXPECT_FALSE(WarpReinvokePersistentGroup(config));

    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    config.SetNetworkName("AAA");
    AddGroupManager();
    AddDeviceManager();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), GroupAdd(_, _, _))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(WarpReinvokePersistentGroup(config));
    EXPECT_FALSE(WarpReinvokePersistentGroup(config));
}

HWTEST_F(P2pStateMachineTest, ReinvokePersistentGroup2, TestSize.Level1)
{
    WifiP2pConfig config;
    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    config.SetNetworkName("AAA");
    AddGroupManager();
    AddDeviceManagerLimit();
    EXPECT_FALSE(WarpReinvokePersistentGroup(config));
}

HWTEST_F(P2pStateMachineTest, ReinvokePersistentGroup3, TestSize.Level1)
{
    WifiP2pConfig config;
    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    config.SetNetworkName("AAA");
    config.SetNetId(2);
    AddGroupManager();
    AddDeviceManagerInViteable();
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), Reinvoke(_, _))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_CALL(WifiP2PHalInterface::GetInstance(), ListNetworks(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(WarpReinvokePersistentGroup(config));
    EXPECT_FALSE(WarpReinvokePersistentGroup(config));
}

HWTEST_F(P2pStateMachineTest, ReinvokePersistentGroup4, TestSize.Level1)
{
    WifiP2pConfig config;
    config.SetDeviceAddress("AA:BB:CC:DD:EE:FF");
    config.SetNetworkName("AAA");
    config.SetNetId(3);
    AddGroupManager2();
    AddDeviceManagerInViteable();
    EXPECT_FALSE(WarpReinvokePersistentGroup(config));
}
}  // namespace Wifi
}  // namespace OHOS