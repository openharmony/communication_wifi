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

#include "p2p_group_operating_state.h"
#include <dlfcn.h>
#include "wifi_p2p_hal_interface.h"
#include "p2p_state_machine.h"
#include "wifi_logger.h"
#include "if_config.h"
#include "wifi_config_center.h"
#include "wifi_hisysevent.h"
#include "wifi_net_agent.h"
#include "p2p_chr_reporter.h"
#include "wifi_global_func.h"

DEFINE_WIFILOG_P2P_LABEL("P2pGroupOperatingState");

#define P2P_ENHANCE_MASK 0x08000000
#define BAND_MASK 5
#define P2P_IP_ADDR_PREFIX_LEN 24

namespace OHOS {
namespace Wifi {
P2pGroupOperatingState::P2pGroupOperatingState(P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr,
    WifiP2pDeviceManager &deviceMgr)
    : State("P2pGroupOperatingState"),
      mProcessFunMap(),
      p2pStateMachine(stateMachine),
      groupManager(groupMgr),
      deviceManager(deviceMgr)
{}

void P2pGroupOperatingState::GoInState()
{
    WIFI_LOGI("             GoInState");
    WifiConfigCenter::GetInstance().SetExplicitGroup(false);
    Init();
}

void P2pGroupOperatingState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
    WifiConfigCenter::GetInstance().SetExplicitGroup(false);
}

void P2pGroupOperatingState::Init()
{
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_FORM_GROUP,
        [this](const InternalMessagePtr msg) { return this->ProcessCmdCreateGroup(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_FORM_RPT_GROUP,
        [this](const InternalMessagePtr msg) { return this->ProcessCmdCreateRptGroup(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_STARTED,
        [this](const InternalMessagePtr msg) { return this->ProcessGroupStartedEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CREATE_GROUP_TIMED_OUT,
        [this](const InternalMessagePtr msg) { return this->ProcessCreateGroupTimeOut(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_REMOVED,
        [this](const InternalMessagePtr msg) { return this->ProcessGroupRemovedEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE,
        [this](const InternalMessagePtr msg) { return this->ProcessCmdDisable(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP,
        [this](const InternalMessagePtr msg) { return this->ProcessCmdRemoveGroup(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP,
        [this](const InternalMessagePtr msg) { return this->ProcessCmdDeleteGroup(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_HID2D_CREATE_GROUP,
        [this](const InternalMessagePtr msg) { return this->ProcessCmdHid2dCreateGroup(msg); }));
}

bool P2pGroupOperatingState::ProcessCmdCreateRptGroup(const InternalMessagePtr msg) const
{
    WifiErrorNo ret = WIFI_HAL_OPT_FAILED;
    WifiP2pConfigInternal config;
    if (!msg->GetMessageObj(config)) {
        WIFI_LOGE("failed to get config.");
        return false;
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState == CONNECTED && !config.GetPassphrase().empty() && !config.GetGroupName().empty() &&
        config.GetPassphrase().length() >= MIN_PSK_LEN && config.GetPassphrase().length() <= MAX_PSK_LEN) {
        bool sameFreq = (linkedInfo.band == static_cast<int>(BandType::BAND_5GHZ) &&
                         config.GetGoBand() == GroupOwnerBand::GO_BAND_5GHZ) ||
                        (linkedInfo.band == static_cast<int>(BandType::BAND_2GHZ) &&
                         config.GetGoBand() == GroupOwnerBand::GO_BAND_2GHZ);
        int freq = sameFreq ? linkedInfo.frequency : p2pStateMachine.GetAvailableFreqByBand(config.GetGoBand());
        WIFI_LOGI("Create rpt group.");
        WifiConfigCenter::GetInstance().SetExplicitGroup(true);
        if (p2pStateMachine.DealCreateRptGroupWithConfig(config, freq)) {
            ret = WIFI_HAL_OPT_OK;
        }
    } else {
        WIFI_LOGE("Invalid parameter.");
    }
    if (WifiErrorNo::WIFI_HAL_OPT_FAILED == ret) {
        WIFI_LOGE("p2p configure to CreateGroup failed.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::CreateGroup, WIFI_OPT_FAILED);
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    } else {
        WIFI_LOGI("p2p configure to CreateGroup successful.");
        p2pStateMachine.MessageExecutedLater(
            static_cast<int>(P2P_STATE_MACHINE_CMD::CREATE_GROUP_TIMED_OUT), CREATE_GROUP_TIMEOUT);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::CreateGroup, WIFI_OPT_SUCCESS);
    }
    return EXECUTED;
}

WifiErrorNo P2pGroupOperatingState::CreateGroupByConfig(int netId,
    const WifiP2pConfigInternal &config, int freq) const
{
    WifiErrorNo ret = WIFI_HAL_OPT_FAILED;
    bool isPersistent = (netId == PERSISTENT_NET_ID) ? true : false;
    if (isPersistent && p2pStateMachine.DealCreateNewGroupWithConfig(config, freq)) {
        ret = WIFI_HAL_OPT_OK;
    } else if (!isPersistent && p2pStateMachine.CreateTempGroupWithConfig(config, freq)) {
        ret = WIFI_HAL_OPT_OK;
    }
    return ret;
}

int P2pGroupOperatingState::GetGroupFreq(WifiP2pConfigInternal &config) const
{
    if (IsValid24GHz(config.GetFreq()) || IsValid5GHz(config.GetFreq())) {
        return config.GetFreq();
    } else {
        return p2pStateMachine.GetAvailableFreqByBand(config.GetGoBand());
    }
}

bool P2pGroupOperatingState::ProcessCmdCreateGroup(const InternalMessagePtr msg) const
{
    WifiErrorNo ret = WIFI_HAL_OPT_FAILED;
    const int minValidNetworkid = 0;
    WifiP2pConfigInternal config;
    SharedLinkManager::SetGroupUid(msg->GetParam1());
    msg->GetMessageObj(config);
    int freq = GetGroupFreq(config);
    int netId = config.GetNetId();
    if (netId >= minValidNetworkid) {
        // Restart the group using an existing network ID.
        WIFI_LOGE("Restart the group using an existing network ID.");
        if ((!config.GetPassphrase().empty() && config.GetPassphrase().length() >= MIN_PSK_LEN &&
            config.GetPassphrase().length() <= MAX_PSK_LEN) ||
            config.GetPassphrase().empty()) {
            if (!p2pStateMachine.SetGroupConfig(config, false)) {
                WIFI_LOGW("Some configuration settings failed!");
            }
            ret = WifiP2PHalInterface::GetInstance().GroupAdd(true, netId, freq);
            p2pStateMachine.UpdateGroupManager();
            p2pStateMachine.UpdatePersistentGroups();
        }
    } else if (netId == PERSISTENT_NET_ID || netId == TEMPORARY_NET_ID) {
        // Create a new persistence group.
        WIFI_LOGE("Create a new %{public}s group.", (netId == PERSISTENT_NET_ID) ? "persistence" : "temporary");
        if (config.GetPassphrase().empty() && config.GetGroupName().empty()) {
            WifiConfigCenter::GetInstance().SetExplicitGroup(true);
            ret = WifiP2PHalInterface::GetInstance().GroupAdd((netId == PERSISTENT_NET_ID) ? true : false, netId, freq);
            p2pStateMachine.UpdateGroupManager();
            p2pStateMachine.UpdatePersistentGroups();
        } else if (!config.GetPassphrase().empty() && !config.GetGroupName().empty() &&
            config.GetPassphrase().length() >= MIN_PSK_LEN && config.GetPassphrase().length() <= MAX_PSK_LEN) {
            WifiConfigCenter::GetInstance().SetExplicitGroup(true);
            ret = CreateGroupByConfig(netId, config, freq);
        }
    } else {
        WIFI_LOGE("Invalid parameter.");
    }
    if (WifiErrorNo::WIFI_HAL_OPT_FAILED == ret) {
        WIFI_LOGE("p2p configure to CreateGroup failed.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::CreateGroup, WIFI_OPT_FAILED);
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    } else {
        WIFI_LOGI("p2p configure to CreateGroup successful.");
        p2pStateMachine.MessageExecutedLater(
            static_cast<int>(P2P_STATE_MACHINE_CMD::CREATE_GROUP_TIMED_OUT), CREATE_GROUP_TIMEOUT);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::CreateGroup, WIFI_OPT_SUCCESS);
    }
    return EXECUTED;
}

bool P2pGroupOperatingState::ProcessGroupStartedEvt(const InternalMessagePtr msg) const
{
    p2pStateMachine.StopTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::CREATE_GROUP_TIMED_OUT));
    WifiP2pGroupInfo group;
    msg->GetMessageObj(group);
    WIFI_LOGI("P2P_EVENT_GROUP_STARTED create group interface name : %{private}s, network name : %{private}s, owner "
              "address : %{private}s",
        group.GetInterface().c_str(), group.GetGroupName().c_str(), group.GetOwner().GetDeviceAddress().c_str());
    if (group.IsPersistent()) {
        /**
         * Update groups.
         */
        p2pStateMachine.UpdateGroupManager();
        group.SetNetworkId(groupManager.GetGroupNetworkId(group.GetOwner(), group.GetGroupName()));
        WIFI_LOGI("the group network id is %{public}d set id is %{public}d",
            group.GetNetworkId(), groupManager.GetGroupNetworkId(group.GetOwner(), group.GetGroupName()));
        p2pStateMachine.UpdatePersistentGroups();
    } else {
        group.SetNetworkId(TEMPORARY_NET_ID);
        WIFI_LOGI("This is a temporary group.");
    }

    std::string goAddr = group.GetOwner().GetDeviceAddress();
    if (group.IsGroupOwner()) { /* append setting the device name if this is GO */
        WifiP2pDevice thisDevice = deviceManager.GetThisDevice();
        WifiP2pDevice tempDevice = thisDevice;
        tempDevice.SetP2pDeviceStatus(P2pDeviceStatus::PDS_CONNECTED);
        tempDevice.SetDeviceAddress(goAddr);
        group.SetOwner(tempDevice);
        group.SetExplicitGroup(WifiConfigCenter::GetInstance().IsExplicitGroup());
    } else {
        WifiP2pDevice dev = deviceManager.GetDevices(goAddr);
        dev.SetP2pDeviceStatus(P2pDeviceStatus::PDS_CONNECTED);
        if (dev.IsValid()) {
            group.SetOwner(dev);
        }
    }
    group.SetCreatorUid(WifiConfigCenter::GetInstance().GetP2pCreatorUid());
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(-1);
    group.SetP2pGroupStatus(P2pGroupStatus::GS_STARTED);
    p2pStateMachine.groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, group);

    if (groupManager.GetCurrentGroup().IsGroupOwner()) {
        if (!p2pStateMachine.StartDhcpServer()) {
            WIFI_LOGE("failed to startup Dhcp server.");
            p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP));
        }
    } else {
        p2pStateMachine.StartDhcpClientInterface();
    }
    SharedLinkManager::IncreaseSharedLink();
    p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_CONNECTED);
    if (WifiP2PHalInterface::GetInstance().SetP2pPowerSave(group.GetInterface(), true) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("SetP2pPowerSave() failed!");
    }
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
    return EXECUTED;
}

bool P2pGroupOperatingState::ProcessCreateGroupTimeOut(const InternalMessagePtr msg) const
{
    WIFI_LOGI("recv event: %{public}d", msg->GetMessageName());
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool P2pGroupOperatingState::ProcessGroupRemovedEvt(const InternalMessagePtr msg) const
{
    WIFI_LOGI("recv group remove event: %{public}d", msg->GetMessageName());
    if (groupManager.GetCurrentGroup().IsPersistent()) {
        groupManager.StashGroups();
        WifiP2pGroupInfo copy = groupManager.GetCurrentGroup();
        copy.SetP2pGroupStatus(P2pGroupStatus::GS_CREATED);
        copy.SetGoIpAddress(std::string(""));
        groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, copy);
        groupManager.StashGroups();
    }
    if (groupManager.GetCurrentGroup().GetInterface() == p2pStateMachine.p2pDevIface) {
        p2pStateMachine.p2pDevIface = "";
    }
    SharedLinkManager::ClearSharedLinkCount();
    p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_DISCONNECTED);
    IpPool::ReleaseIpPool();
    IfConfig::GetInstance().FlushIpAddr(groupManager.GetCurrentGroup().GetInterface(), IpType::IPTYPE_IPV4);
    if (groupManager.GetCurrentGroup().IsGroupOwner()) {
        if (!p2pStateMachine.StopDhcpServer()) {
            WIFI_LOGW("failed to stop Dhcp server.");
        }
    } else {
        p2pStateMachine.StopP2pDhcpClient();
        WriteWifiP2pStateHiSysEvent(groupManager.GetCurrentGroup().GetInterface(), P2P_GC, P2P_OFF);
    }
    WifiErrorNo ret = WifiP2PHalInterface::GetInstance().P2pFlush();
    if (ret != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("call P2pFlush() failed, ErrCode: %{public}d", static_cast<int>(ret));
    }
    WifiP2pGroupInfo invalidGroup;
    groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, invalidGroup);
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool P2pGroupOperatingState::ProcessCmdDisable(const InternalMessagePtr msg) const
{
    /**
     * Before disabling P2P, you need to remove the group.
     */
    p2pStateMachine.DelayMessage(msg);
    return ProcessCmdRemoveGroup(msg);
}

bool P2pGroupOperatingState::ProcessCmdRemoveGroup(const InternalMessagePtr msg) const
{
    /**
     * Removes a current setup group.
     */
    WIFI_LOGI("recv CMD: %{public}d", msg->GetMessageName());
    WifiP2pGroupInfo group = groupManager.GetCurrentGroup();
    auto dhcpFunc = [=]() {
        if (!groupManager.GetCurrentGroup().IsGroupOwner()) {
            p2pStateMachine.StopP2pDhcpClient();
        } else {
            if (!p2pStateMachine.StopDhcpServer()) {
                WIFI_LOGW("failed to stop Dhcp server.");
            }
        }
    };
    if (group.GetP2pGroupStatus() == P2pGroupStatus::GS_STARTED) {
        /**
         * Only started groups can be removed.
         */
        WIFI_LOGI("now remove : %{private}s.", group.GetInterface().c_str());
        if (p2pStateMachine.p2pDevIface == group.GetInterface()) {
            p2pStateMachine.p2pDevIface = "";
        }
        WifiNetAgent::GetInstance().DelInterfaceAddress(group.GetInterface(),
            group.IsGroupOwner() ? group.GetGoIpAddress() : group.GetGcIpAddress(), P2P_IP_ADDR_PREFIX_LEN);
        if (WifiP2PHalInterface::GetInstance().GroupRemove(group.GetInterface())) {
            WIFI_LOGE("P2P group removal failed.");
            dhcpFunc();
            WifiP2pGroupInfo invalidGroup;
            groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, invalidGroup);
            p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_DISCONNECTED);
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
            p2pStateMachine.BroadcastActionResult(P2pActionCallback::RemoveGroup, WIFI_OPT_FAILED);
            WriteP2pAbDisConnectHiSysEvent(static_cast<int>(P2P_ERROR_CODE::P2P_GROUP_REMOVE_ERROR),
                static_cast<int>(P2P_ERROR_RES::P2P_GROUP_REMOVE_FAILURE));
        } else {
            p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_DISCONNECTED);
            WIFI_LOGI("The P2P group is successfully removed.");
            p2pStateMachine.BroadcastActionResult(P2pActionCallback::RemoveGroup, WIFI_OPT_SUCCESS);
            WifiErrorNo ret = WifiP2PHalInterface::GetInstance().P2pFlush();
            if (ret != WifiErrorNo::WIFI_HAL_OPT_OK) {
                WIFI_LOGE("call P2pFlush() failed, ErrCode: %{public}d", static_cast<int>(ret));
            }
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupRemoveState);
        }
    } else {
        WIFI_LOGE("Error:No group can be removed.");
        p2pStateMachine.ChangeConnectedStatus(P2pConnectedState::P2P_DISCONNECTED);
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    }
    return EXECUTED;
}

bool P2pGroupOperatingState::ProcessCmdDeleteGroup(const InternalMessagePtr msg) const
{
    /**
     * Delete a group from the group list.
     */
    WIFI_LOGI("Delete a group from the group list.");
    WifiErrorNo ret;
    WifiP2pGroupInfo group;
    WifiP2pGroupInfo currentGroup = groupManager.GetCurrentGroup();
    msg->GetMessageObj(group);
    int networkId = group.GetNetworkId();
    /**
     * If the current group is to be deleted, remove the current group first.
     */
    if (currentGroup.GetP2pGroupStatus() == P2pGroupStatus::GS_STARTED) {
        if (group.GetNetworkId() == currentGroup.GetNetworkId() || group.GetNetworkId() == -1) {
            ProcessCmdRemoveGroup(msg);
        } else {
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
        }
    } else {
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    }

    ret = WifiP2PHalInterface::GetInstance().RemoveNetwork(networkId);
    groupManager.RemoveGroup(group);
    if (ret) {
        WIFI_LOGE("P2P group deletion failed.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DeleteGroup, WIFI_OPT_FAILED);
    } else {
        WIFI_LOGI("The P2P group is deleted successfully.");
        p2pStateMachine.UpdateGroupManager();
        p2pStateMachine.UpdatePersistentGroups();
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DeleteGroup, WIFI_OPT_SUCCESS);
    }
    return EXECUTED;
}

bool P2pGroupOperatingState::ProcessCmdHid2dCreateGroup(const InternalMessagePtr msg) const
{
    WifiErrorNo ret = WIFI_HAL_OPT_FAILED;
    int freq = 0;
    int freqEnhance = 0;
    bool isFreqEnhance = false;
    std::pair<int, FreqType> info;
    msg->GetMessageObj(info);
    freq = info.first;
    isFreqEnhance = (info.second == FreqType::FREQUENCY_160M);
    WIFI_LOGI("Create a hid2d group, frequency: %{public}d, isFreqEnhance: %{public}d.", freq, isFreqEnhance);
    do {
        if (enhanceService_ == nullptr) {
            WIFI_LOGE("p2p enhanceService_ is nullptr");
            break;
        }
        freqEnhance = enhanceService_->FreqEnhance(freq, isFreqEnhance);
        if (!(static_cast<unsigned int>(freqEnhance) & (static_cast<unsigned int>(P2P_ENHANCE_MASK))) &&
            (static_cast<unsigned int>(freqEnhance) % static_cast<unsigned int>(BAND_MASK != 0))) {
            WIFI_LOGE("FreqEnhance Error :freq = %d, freqEnhance = %d.", freq, freqEnhance);
        } else {
            freq = freqEnhance;
        }
    } while (0);
    bool isEnableWifiAx = (info.second == FreqType::FREQUENCY_80M_11AX);
    if (isEnableWifiAx) {
        ret = WifiP2PHalInterface::GetInstance().GroupAdd(false, AX_NET_ID, freq);
    } else {
        ret = WifiP2PHalInterface::GetInstance().GroupAdd(false, AX_NET_ID, freq);
    }
    if (WifiErrorNo::WIFI_HAL_OPT_FAILED == ret) {
        WIFI_LOGE("p2p configure to CreateGroup failed.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::CreateHid2dGroup, WIFI_OPT_FAILED);
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    } else {
        SharedLinkManager::SetGroupUid(msg->GetParam1());
        WIFI_LOGI("p2p configure hid2d group successful.");
        p2pStateMachine.MessageExecutedLater(
            static_cast<int>(P2P_STATE_MACHINE_CMD::CREATE_GROUP_TIMED_OUT), CREATE_GROUP_TIMEOUT);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::CreateHid2dGroup, WIFI_OPT_SUCCESS);
    }
    P2pChrReporter::GetInstance().SetWpsSuccess(true);
    return EXECUTED;
}

bool P2pGroupOperatingState::ExecuteStateMsg(InternalMessagePtr msg)
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
    if ((iter->second)(msg)) {
        return EXECUTED;
    } else {
        return NOT_EXECUTED;
    }
}

void P2pGroupOperatingState::SetEnhanceService(IEnhanceService* enhanceService)
{
    enhanceService_ = enhanceService;
}

}  // namespace Wifi
}  // namespace OHOS
