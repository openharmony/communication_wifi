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
#include "group_negotiation_state.h"
#include "mac_address.h"
#include "wifi_p2p_hal_interface.h"
#include "p2p_state_machine.h"
#include "wifi_logger.h"
#include "p2p_define.h"
#include "wifi_hisysevent.h"
#include "wifi_config_center.h"
#include "p2p_chr_reporter.h"

DEFINE_WIFILOG_P2P_LABEL("GroupNegotiationState");

namespace OHOS {
namespace Wifi {
GroupNegotiationState::GroupNegotiationState(
    P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr, WifiP2pDeviceManager &deviceMgr)
    : State("GroupNegotiationState"), mProcessFunMap(), p2pStateMachine(stateMachine), groupManager(groupMgr), deviceManager(deviceMgr)
{}
void GroupNegotiationState::GoInState()
{
    Init();
    WIFI_LOGI("             GoInState");
}

void GroupNegotiationState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
}

void GroupNegotiationState::Init()
{
    mProcessFunMap.insert(std::make_pair(
        P2P_STATE_MACHINE_CMD::P2P_EVENT_GO_NEG_SUCCESS, &GroupNegotiationState::ProcessNegotSucessEvt));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_FORMATION_SUCCESS,
        &GroupNegotiationState::ProcessGroupFormationSuccessEvt));
    mProcessFunMap.insert(
        std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_STARTED, &GroupNegotiationState::ProcessGroupStartedEvt));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_FORMATION_FAILURE,
        &GroupNegotiationState::ProcessGroupFormationFailEvt));
    mProcessFunMap.insert(std::make_pair(
        P2P_STATE_MACHINE_CMD::P2P_EVENT_GO_NEG_FAILURE, &GroupNegotiationState::ProcessNegotFailEvt));
    mProcessFunMap.insert(std::make_pair(
        P2P_STATE_MACHINE_CMD::P2P_EVENT_INVITATION_RESULT, &GroupNegotiationState::ProcessInvitationResultEvt));
    mProcessFunMap.insert(
        std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_REMOVED, &GroupNegotiationState::ProcessGroupRemovedEvt));
    mProcessFunMap.insert(
        std::make_pair(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP, &GroupNegotiationState::ProcessCmdRemoveGroup));
}

bool GroupNegotiationState::ProcessNegotSucessEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("Negotiation success: %{public}d", msg->GetMessageName());
    return EXECUTED;
}

bool GroupNegotiationState::ProcessGroupFormationSuccessEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("Group formation success: %{public}d", msg->GetMessageName());
    return EXECUTED;
}

bool GroupNegotiationState::ProcessGroupStartedEvt(InternalMessagePtr msg) const
{
    WifiP2pGroupInfo group;
    if (!msg->GetMessageObj(group)) {
        WIFI_LOGE("Failed to obtain the group information.");
        return EXECUTED;
    }
    WifiP2pLinkedInfo p2pInfo;
    WifiConfigCenter::GetInstance().GetP2pInfo(p2pInfo);
    p2pInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    WifiConfigCenter::GetInstance().SaveP2pInfo(p2pInfo);
    groupManager.SaveP2pInfo(p2pInfo);
    group.SetP2pGroupStatus(P2pGroupStatus::GS_STARTED);
    group.SetCreatorUid(WifiConfigCenter::GetInstance().GetP2pCreatorUid());
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(-1);
    groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, group);

    if (groupManager.GetCurrentGroup().IsGroupOwner() &&
        MacAddress::IsValidMac(groupManager.GetCurrentGroup().GetOwner().GetDeviceAddress().c_str())) {
        deviceManager.GetThisDevice().SetP2pDeviceStatus(P2pDeviceStatus::PDS_CONNECTED);
        group.SetOwner(deviceManager.GetThisDevice());
        groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, group);
    }

    if (groupManager.GetCurrentGroup().IsPersistent()) {
        p2pStateMachine.UpdateGroupManager();
        const WifiP2pDevice &owner = groupManager.GetCurrentGroup().GetOwner();
        WifiP2pGroupInfo copy = groupManager.GetCurrentGroup();
        copy.SetNetworkId(groupManager.GetGroupNetworkId(owner, groupManager.GetCurrentGroup().GetGroupName()));
        groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, copy);
        groupManager.AddOrUpdateGroup(groupManager.GetCurrentGroup());
        p2pStateMachine.UpdatePersistentGroups();
    } else {
        WifiP2pGroupInfo copy = groupManager.GetCurrentGroup();
        copy.SetNetworkId(TEMPORARY_NET_ID);
        groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, copy);
    }

    DoDhcpInGroupStart();
    SharedLinkManager::IncreaseSharedLink();
    if (WifiP2PHalInterface::GetInstance().SetP2pPowerSave(group.GetInterface(), true) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("SetP2pPowerSave() failed!");
    }
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
    return EXECUTED;
}

void GroupNegotiationState::DoDhcpInGroupStart(void) const
{
    if (groupManager.GetCurrentGroup().IsGroupOwner()) {
        if (!p2pStateMachine.StartDhcpServer()) {
            WIFI_LOGE("failed to startup Dhcp server.");
            p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP));
        }
        if (WifiErrorNo::WIFI_HAL_OPT_OK !=
            WifiP2PHalInterface::GetInstance().SetP2pGroupIdle(groupManager.GetCurrentGroup().GetInterface(), 0)) {
            WIFI_LOGE("failed to set GO Idle time.");
        }
    } else {
        if (WifiErrorNo::WIFI_HAL_OPT_OK !=
            WifiP2PHalInterface::GetInstance().SetP2pGroupIdle(groupManager.GetCurrentGroup().GetInterface(), 0)) {
            WIFI_LOGE("failed to set GC Idle time.");
        }

        /* GC start DHCP Client. */
        if (p2pStateMachine.GetIsNeedDhcp() == DHCPTYPE::NO_DHCP) {
            p2pStateMachine.BroadcastP2pConnectionChanged();
        } else {
            p2pStateMachine.StartDhcpClientInterface();
        }
        const WifiP2pDevice &owner = groupManager.GetCurrentGroup().GetOwner();
        WifiP2pDevice device = deviceManager.GetDevices(owner.GetDeviceAddress());
        if (device.IsValid()) {
            device.SetRandomDeviceAddress(owner.GetRandomDeviceAddress());
            device.SetP2pDeviceStatus(P2pDeviceStatus::PDS_CONNECTED);
            WifiP2pGroupInfo copy = groupManager.GetCurrentGroup();
            copy.SetOwner(device);
            groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, copy);
            WIFI_LOGI("ProcessGroupStartedEvt %{private}s %{private}s",
                device.GetDeviceAddress().c_str(), device.GetRandomDeviceAddress().c_str());
            deviceManager.UpdateDeviceStatus(owner.GetDeviceAddress(), P2pDeviceStatus::PDS_CONNECTED);

            p2pStateMachine.BroadcastP2pPeersChanged();
        } else {
            WIFI_LOGE("fail:No GO device information is found.");
        }
    }
}

bool GroupNegotiationState::ProcessGroupFormationFailEvt(InternalMessagePtr msg) const
{
    int status = msg->GetParam1();
    WIFI_LOGW("Group formation failure. Error code: %{public}d", status);
    return EXECUTED;
}

bool GroupNegotiationState::ProcessNegotFailEvt(InternalMessagePtr msg) const
{
    int status = msg->GetParam1();
    WIFI_LOGE("Negotiation failure. Error code: %{public}d", status);
    p2pStateMachine.DealGroupCreationFailed();
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool GroupNegotiationState::ProcessInvitationResultEvt(InternalMessagePtr msg) const
{
    P2pStatus status = static_cast<P2pStatus>(msg->GetParam1());
    WIFI_LOGI("Invitation result is %{public}d", msg->GetParam1());
    if (status == P2pStatus::SUCCESS) {
        WIFI_LOGI("Invitation is succeeded.");
        return EXECUTED;
    }

    if (status == P2pStatus::UNKNOWN_P2P_GROUP) {
        int networkId = p2pStateMachine.savedP2pConfig.GetNetId();
        if (networkId >= 0) {
            groupManager.RemoveClientFromGroup(networkId, p2pStateMachine.savedP2pConfig.GetDeviceAddress());
        }
        p2pStateMachine.savedP2pConfig.SetNetId(-1);
        p2pStateMachine.P2pConnectByShowingPin(p2pStateMachine.savedP2pConfig);
    } else if (status == P2pStatus::INFORMATION_IS_CURRENTLY_UNAVAILABLE) {
        p2pStateMachine.savedP2pConfig.SetNetId(-1);
        p2pStateMachine.P2pConnectByShowingPin(p2pStateMachine.savedP2pConfig);
    } else if (status == P2pStatus::NO_COMMON_CHANNELS) {
        WIFI_LOGE("fail:There is no common channel.");
    } else {
        P2pChrReporter::GetInstance().ReportErrCodeBeforeGroupFormationSucc(P2P_INVITATION, msg->GetParam1(),
            P2P_CHR_DEFAULT_REASON_CODE);
        p2pStateMachine.DealGroupCreationFailed();
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    }
    return EXECUTED;
}
bool GroupNegotiationState::ProcessGroupRemovedEvt(InternalMessagePtr msg) const
{
    /**
     * The group has been removed. The possible cause is that an exception occurs during the connection.
     */
    WIFI_LOGI("Recv event: %{public}d. The group has been removed.", msg->GetMessageName());
    p2pStateMachine.DealGroupCreationFailed();
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool GroupNegotiationState::ProcessCmdRemoveGroup(InternalMessagePtr msg) const
{
    std::string ifName = p2pStateMachine.p2pDevIface;
    if (ifName.empty()) {
        WIFI_LOGE("invalid ifname on ProcessCmdRemoveGroup");
        return EXECUTED;
    }
    p2pStateMachine.p2pDevIface = "";
    WifiErrorNo ret = WifiP2PHalInterface::GetInstance().GroupRemove(ifName);
    if (ret) {
        WIFI_LOGE("P2P group (%{public}s) removal failed.", ifName.c_str());
        p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_DISCONNECTED);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::RemoveGroup, WIFI_OPT_FAILED);
    } else {
        WIFI_LOGI("The P2P group (%{public}s) is successfully removed.", ifName.c_str());
        p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_DISCONNECTED);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::RemoveGroup, WIFI_OPT_SUCCESS);
        ret = WifiP2PHalInterface::GetInstance().P2pFlush();
        if (ret != WifiErrorNo::WIFI_HAL_OPT_OK) {
            WIFI_LOGE("call P2pFlush() failed, ErrCode: %{public}d", static_cast<int>(ret));
        }
    }
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool GroupNegotiationState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("fatal error!");
        return NOT_EXECUTED;
    }
    int msgName = msg->GetMessageName();
    auto iter = mProcessFunMap.find(static_cast<P2P_STATE_MACHINE_CMD>(msgName));
    if (iter == mProcessFunMap.end()) {
        return NOT_EXECUTED;
    }
    if ((this->*(iter->second))(msg)) {
        return EXECUTED;
    } else {
        return NOT_EXECUTED;
    }
}
}  // namespace Wifi
}  // namespace OHOS
