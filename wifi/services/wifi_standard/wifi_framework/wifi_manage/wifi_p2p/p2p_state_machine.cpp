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

#include "p2p_state_machine.h"
#include <cerrno>
#include <ifaddrs.h>
#include <net/if.h>
#include <string>
#include <functional>
#include <map>
#include "dhcpd_interface.h"
#include "ip_tools.h"
#include "ipv4_address.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_net_agent.h"
#include "wifi_p2p_dns_sd_service_info.h"
#include "wifi_p2p_dns_sd_service_response.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_p2p_upnp_service_response.h"
#include "wifi_settings.h"
#include "wifi_hisysevent.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_P2P_LABEL("P2pStateMachine");
#define P2P_PREFIX_LEN 4
namespace OHOS {
namespace Wifi {
const std::string DEFAULT_P2P_IPADDR = "192.168.49.1";
std::mutex P2pStateMachine::m_gcJoinmutex;

DHCPTYPE P2pStateMachine::m_isNeedDhcp = DHCPTYPE::DHCP_P2P;
P2pStateMachine::P2pStateMachine(P2pMonitor &monitor, WifiP2pGroupManager &groupMgr,
    WifiP2pDeviceManager &setDeviceMgr,
    WifiP2pServiceManager &setSvrMgr, AuthorizingNegotiationRequestState &authorizingNegotiationRequestState,
    GroupFormedState &groupFormedState, GroupNegotiationState &groupNegotiationState,
    InvitationReceivedState &invltationRecelvedState, InvitationRequestState &invitationRequestState,
    P2pDefaultState &defaultState, P2pDisabledState &disabledState, P2pDisablingState &disablingState,
    P2pEnabledState &enabledState, P2pEnablingState &enablingState,
    P2pGroupFormationState &groupFormationState, P2pGroupJoinState &groupJoinState,
    P2pGroupOperatingState &groupOperatingState, P2pIdleState &idleState, P2pInvitingState &invitingState,
    ProvisionDiscoveryState &provisionDiscoveryState)
    : StateMachine("P2pStateMachine"),
      p2pServiceCallbacks(), p2pIface(), savedP2pConfig(),
      p2pMonitor(monitor),
      groupManager(groupMgr),
      deviceManager(setDeviceMgr),
      serviceManager(setSvrMgr),
      p2pAuthorizingNegotiationRequestState(authorizingNegotiationRequestState),
      p2pGroupFormedState(groupFormedState),
      p2pGroupNegotiationState(groupNegotiationState),
      p2pInvitationReceivedState(invltationRecelvedState),
      p2pInvitationRequestState(invitationRequestState),
      p2pDefaultState(defaultState),
      p2pDisabledState(disabledState),
      p2pDisablingState(disablingState),
      p2pEnabledState(enabledState),
      p2pEnablingState(enablingState),
      p2pGroupFormationState(groupFormationState),
      p2pGroupJoinState(groupJoinState),
      p2pGroupOperatingState(groupOperatingState),
      p2pIdleState(idleState),
      p2pInvitingState(invitingState),
      p2pProvisionDiscoveryState(provisionDiscoveryState),
      p2pDevIface()
{
    Initialize();
}

P2pStateMachine::~P2pStateMachine()
{
    StopHandlerThread();
    groupManager.StashGroups();
    StopDhcpClient(groupManager.GetCurrentGroup().GetInterface().c_str(), false);
    StopDhcpServer();
    if (pDhcpResultNotify != nullptr) {
        delete pDhcpResultNotify;
        pDhcpResultNotify = nullptr;
    }
    AbstractUI::GetInstance().UnInit();
}

void P2pStateMachine::Initialize()
{
    if (!InitialStateMachine("P2pStateMachine")) {
        WIFI_LOGE("P2P StateMachine Initialize failed.");
        return;
    }

    groupManager.Initialize();

    /**
     * Initialize the UI server in advance.
     */
    AbstractUI::GetInstance();
    StatePlus(&p2pDefaultState, nullptr);
    StatePlus(&p2pDisabledState, &p2pDefaultState);
    StatePlus(&p2pDisablingState, &p2pDefaultState);
    StatePlus(&p2pEnablingState, &p2pDefaultState);
    StatePlus(&p2pEnabledState, &p2pDefaultState);
    StatePlus(&p2pIdleState, &p2pEnabledState);
    StatePlus(&p2pGroupJoinState, &p2pEnabledState);
    StatePlus(&p2pGroupOperatingState, &p2pEnabledState);
    StatePlus(&p2pInvitingState, &p2pEnabledState);
    StatePlus(&p2pInvitationRequestState, &p2pInvitingState);
    StatePlus(&p2pInvitationReceivedState, &p2pInvitingState);

    StatePlus(&p2pGroupFormationState, &p2pEnabledState);
    StatePlus(&p2pGroupNegotiationState, &p2pGroupFormationState);
    StatePlus(&p2pAuthorizingNegotiationRequestState, &p2pGroupFormationState);
    StatePlus(&p2pProvisionDiscoveryState, &p2pGroupFormationState);
    StatePlus(&p2pGroupFormedState, &p2pGroupFormationState);

    SetFirstState(&p2pDisabledState);
    StartStateMachine();
    pDhcpResultNotify = new (std::nothrow)DhcpResultNotify();
    if (pDhcpResultNotify == nullptr) {
        WIFI_LOGW("pDhcpResultNotify Initialize failed.");
    }
    return;
}

void P2pStateMachine::RegisterEventHandler()
{
    using namespace std::placeholders;
    using type = void (StateMachine::*)(int, int, int, const std::any &);

    auto handler = std::bind(static_cast<type>(&StateMachine::SendMessage), this, _1, _2, _3, _4);

    p2pMonitor.RegisterIfaceHandler(
        p2pIface, [=](P2P_STATE_MACHINE_CMD msgName, int param1, int param2, const std::any &messageObj) {
            handler(static_cast<int>(msgName), param1, param2, messageObj);
        });
}

void P2pStateMachine::UpdateOwnDevice(P2pDeviceStatus status)
{
    deviceManager.GetThisDevice().SetP2pDeviceStatus(status);
    BroadcastThisDeviceChanaged(deviceManager.GetThisDevice());
}

void P2pStateMachine::InitializeThisDevice()
{
    std::string deviceName;
    constexpr size_t randomLen = 4;
    P2pVendorConfig p2pVendorCfg;
    int ret = WifiSettings::GetInstance().GetP2pVendorConfig(p2pVendorCfg);
    if (ret < 0) {
        WIFI_LOGW("Failed to obtain P2pVendorConfig information.");
    }
    WIFI_LOGI("%{public}s: random mac is %{public}s", __func__, p2pVendorCfg.GetRandomMacSupport() ? "true" : "false");
    if (p2pVendorCfg.GetDeviceName().empty()) {
        deviceName = std::string("OHOS_") + GetRandomStr(randomLen);
        p2pVendorCfg.SetDeviceName(deviceName);
        ret = WifiSettings::GetInstance().SetP2pVendorConfig(p2pVendorCfg);
        if (ret < 0) {
            WIFI_LOGW("Failed to Set P2pVendorConfig information.");
        }
    } else {
        deviceName = p2pVendorCfg.GetDeviceName();
    }
    deviceManager.GetThisDevice().SetDeviceName(deviceName);
    deviceManager.GetThisDevice().SetPrimaryDeviceType(p2pVendorCfg.GetPrimaryDeviceType());
    deviceManager.GetThisDevice().SetSecondaryDeviceType(p2pVendorCfg.GetSecondaryDeviceType());
}

void P2pStateMachine::UpdateGroupManager() const
{
    std::map<int, WifiP2pGroupInfo> wpaGroups;
    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().ListNetworks(wpaGroups);
    if (retCode == WifiErrorNo::WIFI_IDL_OPT_FAILED) {
        WIFI_LOGE("Failed to get listNetworks");
        return;
    }
    for (auto wpaGroup = wpaGroups.begin(); wpaGroup != wpaGroups.end(); ++wpaGroup) {
        groupManager.UpdateWpaGroup(wpaGroup->second);
    }
    groupManager.UpdateGroupsNetwork(wpaGroups);
}

void P2pStateMachine::UpdatePersistentGroups() const
{
    WIFI_LOGI("UpdatePersistentGroups");
    std::vector<WifiP2pGroupInfo> groups;
    groups = groupManager.GetGroups();
    WifiSettings::GetInstance().SetWifiP2pGroupInfo(groups);
    WifiSettings::GetInstance().SyncWifiP2pGroupInfoConfig();
    BroadcastPersistentGroupsChanged();
}

bool P2pStateMachine::ReawakenPersistentGroup(WifiP2pConfigInternal &config) const
{
    const WifiP2pDevice device = FetchNewerDeviceInfo(config.GetDeviceAddress());
    if (!device.IsValid()) {
        WIFI_LOGE("Invalid device.");
        return false;
    }

    bool isJoin = device.IsGroupOwner();
    std::string groupName = config.GetGroupName();

    if (isJoin && !device.IsGroupLimit()) {
        if (groupName.empty()) {
            groupName = device.GetNetworkName();
        }
        int networkId = groupManager.GetGroupNetworkId(device, groupName);
        if (networkId >= 0) {
            /**
             * If GO is running on the peer device and the GO has been connected,
             * you can directly connect to the peer device through p2p_group_add.
             */
            if (WifiErrorNo::WIFI_IDL_OPT_OK != WifiP2PHalInterface::GetInstance().GroupAdd(true, networkId, 0)) {
                return false;
            }
            return true;
        }
    }

    if (!isJoin && device.IsDeviceLimit()) {
        return false;
    }

    if (!isJoin && device.Isinviteable()) {
        /**
         * If the peer device is in idle state and the local device is in idle state,
         * try to connect to the peer device in revoke mode.
         */
        int networkId = -1;
        /* Prepare to reinvoke as GC. */
        if (config.GetNetId() >= 0) {
            if (config.GetDeviceAddress() == groupManager.GetGroupOwnerAddr(config.GetNetId())) {
                networkId = config.GetNetId();
            }
        } else {
            networkId = groupManager.GetGroupNetworkId(device);
        }
        if (networkId < 0) {
            /**
             * Prepare to reinvoke as GO.
             * Mean that the group is not found when the peer device roles as GO,
             * try to find the group that this device roles as GO and the peer device roles as GC.
             */
            networkId = groupManager.GetNetworkIdFromClients(device);
        }

        if (networkId >= 0) {
            /**
             * If a persistent group that has been connected to the peer device exists,
             * the reinvoke process is triggered.
             */
            if (WifiErrorNo::WIFI_IDL_OPT_OK !=
                WifiP2PHalInterface::GetInstance().Reinvoke(networkId, device.GetDeviceAddress())) {
                WIFI_LOGE("Failed to reinvoke.");
                UpdateGroupManager();
                UpdatePersistentGroups();
                return false;
            } else {
                config.SetNetId(networkId);
                return true;
            }
        }
    }

    return false;
}

WifiP2pDevice P2pStateMachine::FetchNewerDeviceInfo(const std::string &deviceAddr) const
{
    WifiP2pDevice device;
    device.SetDeviceAddress(deviceAddr);
    if (deviceAddr.empty()) {
        WIFI_LOGE("Invalid device address.");
        return device;
    }
    WifiP2pDevice newDevice = deviceManager.GetDevices(deviceAddr);
    if (WifiP2PHalInterface::GetInstance().GetP2pPeer(deviceAddr, device) ==
        WifiErrorNo::WIFI_IDL_OPT_OK) {
        int groupCap = device.GetGroupCapabilitys();
        deviceManager.UpdateDeviceGroupCap(deviceAddr, groupCap);
        newDevice.SetGroupCapabilitys(groupCap);
        newDevice.SetNetworkName(device.GetNetworkName());
    }
    return newDevice;
}

void P2pStateMachine::DealGroupCreationFailed()
{
    WifiP2pLinkedInfo info;
    info.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    WifiSettings::GetInstance().SaveP2pInfo(info);
    WifiSettings::GetInstance().ClearLocalHid2dInfo();
    groupManager.SaveP2pInfo(info);
    BroadcastP2pConnectionChanged();

    if (!savedP2pConfig.GetDeviceAddress().empty() && deviceManager.RemoveDevice(savedP2pConfig.GetDeviceAddress())) {
        BroadcastP2pPeersChanged();
    }
    WifiErrorNo ret = WifiP2PHalInterface::GetInstance().P2pFlush();
    if (ret != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGE("call P2pFlush() failed, ErrCode: %{public}d", static_cast<int>(ret));
    }
    SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DEVICE_DISCOVERS));
}

void P2pStateMachine::RemoveGroupByNetworkId(int networkId) const
{
    if (WifiP2PHalInterface::GetInstance().RemoveNetwork(networkId) != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGE("failed to remove networkId, networkId is %{public}d.", networkId);
    }
    UpdateGroupManager();
    UpdatePersistentGroups();
    BroadcastPersistentGroupsChanged();
}

void P2pStateMachine::SetWifiP2pInfoWhenGroupFormed(const std::string &groupOwnerAddress)
{
    WifiP2pLinkedInfo p2pInfo;
    WifiSettings::GetInstance().GetP2pInfo(p2pInfo);
    p2pInfo.SetIsGroupOwner(groupManager.GetCurrentGroup().IsGroupOwner());
    p2pInfo.SetIsGroupOwnerAddress(groupOwnerAddress);
    WifiSettings::GetInstance().SaveP2pInfo(p2pInfo);
    groupManager.SaveP2pInfo(p2pInfo);
}

ErrCode P2pStateMachine::AddClientInfo(std::vector<GcInfo> &gcInfos)
{
    std::lock_guard<std::mutex> lock(m_gcJoinmutex);
    WifiP2pGroupInfo groupInfo = groupManager.GetCurrentGroup();
    if (!groupInfo.IsGroupOwner()) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    std::vector<OHOS::Wifi::WifiP2pDevice> deviceList;
    if (deviceManager.GetDevicesList(deviceList) <= 0) {
        WIFI_LOGE("deviceList.size <=0 ");
        return WIFI_OPT_FAILED;
    }
    WifiP2pDevice curDev;
    GcInfo curGc;
    bool isFound = false;
    for (auto iterClientList : curClientList) {
        for (auto iterDeviceList : deviceList) {
            if (iterDeviceList.GetDeviceAddress() == iterClientList) {
                curDev = iterDeviceList;
                auto p2pDeviceMac = curDev.GetDeviceAddress();
                auto p2pGroupMac = curDev.GetGroupAddress();
                curGc = MatchDevInGcInfos(p2pDeviceMac, p2pGroupMac, gcInfos);
                isFound = !(curGc.ip.empty());
                break;
            }
        }
        if (isFound) {
            break;
        }
    }
    if (!isFound) {
        return ErrCode::WIFI_OPT_FAILED;
    } else {
        auto iter = std::find(curClientList.begin(), curClientList.end(), curDev.GetDeviceAddress().c_str());
        curClientList.erase(iter);
    }
    WifiP2pLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetP2pInfo(linkedInfo);
    linkedInfo.ClearClientInfo();
    linkedInfo.AddClientInfoList(curGc.mac, curGc.ip, curDev.GetDeviceName());

    if (WifiSettings::GetInstance().SaveP2pInfo(linkedInfo) == 0) {
        groupManager.SaveP2pInfo(linkedInfo);
        BroadcastP2pGcJoinGroup(curGc);
        return ErrCode::WIFI_OPT_SUCCESS;
    }
    return ErrCode::WIFI_OPT_FAILED;
}

GcInfo P2pStateMachine::MatchDevInGcInfos(const std::string &deviceAddr,
    const std::string &groupAddr, std::vector<GcInfo> &gcInfos)
{
    WIFI_LOGD("P2pStateMachine::MatchDevInGcInfos: devAddr = %s, groupAddr = %s",
        MacAnonymize(deviceAddr).c_str(), MacAnonymize(groupAddr).c_str());
    GcInfo info;
    for (auto gcInfo : gcInfos) {
        if ((gcInfo.mac == deviceAddr) || (gcInfo.mac == groupAddr)) {
            WIFI_LOGD("find curDev Ip:%s", gcInfo.ip.c_str());
            info = gcInfo;
            break;
        }
    }
    return info;
}

ErrCode P2pStateMachine::RemoveClientInfo(std::string mac)
{
    WIFI_LOGD("P2pStateMachine::RemoveClientInfo: mac = %s",
        MacAnonymize(mac).c_str());
    WifiP2pLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetP2pInfo(linkedInfo);
    linkedInfo.RemoveClientInfo(mac);
    if (WifiSettings::GetInstance().SaveP2pInfo(linkedInfo) == 0) {
        groupManager.SaveP2pInfo(linkedInfo);
        return ErrCode::WIFI_OPT_SUCCESS;
    }
    return ErrCode::WIFI_OPT_FAILED;
}

void P2pStateMachine::BroadcastP2pStatusChanged(P2pState state) const
{
    WifiSettings::GetInstance().SetP2pState(static_cast<int>(state));
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pStateChangedEvent != nullptr) {
            callBackItem.second.OnP2pStateChangedEvent(state);
        }
    }
}

void P2pStateMachine::BroadcastP2pPeersChanged() const
{
    std::vector<WifiP2pDevice> peers;
    deviceManager.GetDevicesList(peers);
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pPeersChangedEvent != nullptr) {
            callBackItem.second.OnP2pPeersChangedEvent(peers);
        }
    }
}

void P2pStateMachine::BroadcastP2pServicesChanged() const
{
    std::vector<WifiP2pServiceInfo> svrInfoList;
    serviceManager.GetDeviceServices(svrInfoList);
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pServicesChangedEvent != nullptr) {
            callBackItem.second.OnP2pServicesChangedEvent(svrInfoList);
        }
    }
}

void P2pStateMachine::BroadcastP2pConnectionChanged() const
{
    WifiP2pLinkedInfo p2pInfo;
    WifiSettings::GetInstance().GetP2pInfo(p2pInfo);
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pConnectionChangedEvent != nullptr) {
            callBackItem.second.OnP2pConnectionChangedEvent(p2pInfo);
        }
    }
}

void P2pStateMachine::BroadcastThisDeviceChanaged(const WifiP2pDevice &device) const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pThisDeviceChangedEvent != nullptr) {
            callBackItem.second.OnP2pThisDeviceChangedEvent(device);
        }
    }
}

void P2pStateMachine::BroadcastP2pDiscoveryChanged(bool isActive) const
{
    int status = isActive ? 1 : 0;
    WifiSettings::GetInstance().SetP2pDiscoverState(status);
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pDiscoveryChangedEvent != nullptr) {
            callBackItem.second.OnP2pDiscoveryChangedEvent(isActive);
        }
    }
}

void P2pStateMachine::BroadcastP2pGcJoinGroup(GcInfo &info) const
{
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pGcJoinGroupEvent) {
            callBackItem.second.OnP2pGcJoinGroupEvent(info);
        }
    }
}

void P2pStateMachine::BroadcastP2pGcLeaveGroup(WifiP2pDevice &device) const
{
    WifiP2pLinkedInfo p2pInfo;
    WifiSettings::GetInstance().GetP2pInfo(p2pInfo);
    auto gcInfos = p2pInfo.GetClientInfoList();
    GcInfo curGcInfo;
    for (auto gcInfo : gcInfos) {
        if (device.GetDeviceAddress() == gcInfo.mac) {
            curGcInfo = gcInfo;
        }
    }
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pGcLeaveGroupEvent) {
            callBackItem.second.OnP2pGcLeaveGroupEvent(curGcInfo);
        }
    }
}

void P2pStateMachine::BroadcastPersistentGroupsChanged() const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pGroupsChangedEvent != nullptr) {
            callBackItem.second.OnP2pGroupsChangedEvent();
        }
    }
}

void P2pStateMachine::BroadcastActionResult(P2pActionCallback action, ErrCode result) const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pActionResultEvent != nullptr) {
            callBackItem.second.OnP2pActionResultEvent(action, result);
        }
    }
}

void P2pStateMachine::BroadcastServiceResult(P2pServicerProtocolType serviceType,
    const std::vector<unsigned char> &respData, const WifiP2pDevice &srcDevice) const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pServiceAvailable != nullptr) {
            callBackItem.second.OnP2pServiceAvailable(serviceType, respData, srcDevice);
        }
    }
}

void P2pStateMachine::BroadcastDnsSdServiceResult(
    const std::string &instName, const std::string &regType, const WifiP2pDevice &srcDevice) const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pDnsSdServiceAvailable != nullptr) {
            callBackItem.second.OnP2pDnsSdServiceAvailable(instName, regType, srcDevice);
        }
    }
}

void P2pStateMachine::BroadcastDnsSdTxtRecordResult(const std::string &wholeDomainName,
    const std::map<std::string, std::string> &txtMap, const WifiP2pDevice &srcDevice) const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pDnsSdTxtRecordAvailable != nullptr) {
            callBackItem.second.OnP2pDnsSdTxtRecordAvailable(wholeDomainName, txtMap, srcDevice);
        }
    }
}

void P2pStateMachine::BroadcastUpnpServiceResult(
    const std::vector<std::string> &uniqueServiceNames, const WifiP2pDevice &srcDevice) const
{
    std::unique_lock<std::mutex> lock(cbMapMutex);
    for (const auto &callBackItem : p2pServiceCallbacks) {
        if (callBackItem.second.OnP2pUpnpServiceAvailable != nullptr) {
            callBackItem.second.OnP2pUpnpServiceAvailable(uniqueServiceNames, srcDevice);
        }
    }
}

void P2pStateMachine::RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callback)
{
    WIFI_LOGI("RegisterP2pServiceCallbacks, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::mutex> lock(cbMapMutex);
    p2pServiceCallbacks.insert_or_assign(callback.callbackModuleName, callback);
}

void P2pStateMachine::UnRegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callback)
{
    WIFI_LOGI("UnRegisterP2pServiceCallbacks, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::mutex> lock(cbMapMutex);
    p2pServiceCallbacks.erase(callback.callbackModuleName);
}

void P2pStateMachine::ClearAllP2pServiceCallbacks()
{
    WIFI_LOGI("ClearAllP2pServiceCallbacks");
    std::unique_lock<std::mutex> lock(cbMapMutex);
    p2pServiceCallbacks.clear();
}

bool P2pStateMachine::IsUsableGroupName(std::string nwName)
{
    if (nwName.empty()) {
        return false;
    }
    if (nwName.length() < MIN_GROUP_NAME_LENGTH || nwName.length() > MAX_GROUP_NAME_LENGTH) {
        return false;
    }
    return true;
}

P2pConfigErrCode P2pStateMachine::IsConfigUnusable(const WifiP2pConfigInternal &config)
{
    constexpr unsigned NETWORK_NAME_MAX_LENGTH = 32;
    constexpr int GROUP_OWNER_MAX_INTENT = 15;
    if (config.GetDeviceAddress().empty()) {
        WIFI_LOGE("P2pStateMachine::IsConfigUnusable: address is empty");
        return P2pConfigErrCode::MAC_EMPTY;
    }
    if (!MacAddress::IsValidMac(config.GetDeviceAddress().c_str())) {
        WIFI_LOGE("P2pStateMachine::IsConfigUnusable: invalid mac address");
        return P2pConfigErrCode::ERR_MAC_FORMAT;
    }
    WifiP2pDevice device = deviceManager.GetDevices(config.GetDeviceAddress());
    if (!device.IsValid()) {
        WIFI_LOGE("P2pStateMachine::IsConfigUnusable: failed to get device");
        return P2pConfigErrCode::MAC_NOT_FOUND;
    }
    if (config.GetGroupOwnerIntent() < AUTO_GROUP_OWNER_VALUE ||
        config.GetGroupOwnerIntent() > GROUP_OWNER_MAX_INTENT) {
        WIFI_LOGE("P2pStateMachine::IsConfigUnusable: invalid groupOwnerIntent");
        return P2pConfigErrCode::ERR_INTENT;
    }
    if (config.GetGroupName().length() > NETWORK_NAME_MAX_LENGTH) {
        WIFI_LOGE("P2pStateMachine::IsConfigUnusable: invalid group name");
        return P2pConfigErrCode::ERR_SIZE_NW_NAME;
    }
    return P2pConfigErrCode::SUCCESS;
}

bool P2pStateMachine::IsConfigUsableAsGroup(WifiP2pConfigInternal config)
{
    if (config.GetDeviceAddress().empty()) {
        return false;
    }
    if (IsUsableGroupName(config.GetGroupName()) && !config.GetPassphrase().empty()) {
        return true;
    }
    return false;
}

void P2pStateMachine::CancelSupplicantSrvDiscReq()
{
    if (serviceManager.GetQueryId().empty()) {
        return;
    }

    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().CancelReqServiceDiscovery(serviceManager.GetQueryId());
    if (retCode != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGI("The request has been processed normally.");
    } else {
        serviceManager.SetQueryId(std::string(""));
    }
    return;
}

void P2pStateMachine::NotifyUserInvitationSentMessage(const std::string &pin, const std::string &peerAddress) const
{
    WIFI_LOGI("P2pStateMachine::NotifyUserInvitationSentMessage  enter");
    std::function<void(AlertDialog &, std::any)> event = [](AlertDialog &dlg, std::any msg) {
        AlertDialog dlgBuf = dlg;
        std::any msgBuf = msg;
        WIFI_LOGI("The user closes the display window.");
    };
    AlertDialog &dialog = AbstractUI::GetInstance().Build();
    std::string message = "NotifyInvitationSent: " "Receiving Device Address:" + peerAddress + "PIN:" + pin;
    dialog.SetTitle("Invitation Sent");
    dialog.SetMessage(message);
    dialog.SetButton("OK", event, nullptr);
    AbstractUI::GetInstance().ShowAlerDialog(dialog);
}

void P2pStateMachine::NotifyUserProvDiscShowPinRequestMessage(const std::string &pin, const std::string &peerAddress)
{
    WIFI_LOGI("P2pStateMachine::NotifyUserProvDiscShowPinRequestMessage  enter");
    auto sendMessage =
        std::bind(static_cast<void (StateMachine::*)(int)>(&StateMachine::SendMessage), this, std::placeholders::_1);
    std::function<void(AlertDialog &, std::any)> acceptEvent = [=](AlertDialog &dlg, std::any msg) {
        AlertDialog dlgBuf = dlg;
        std::any msgBuf = msg;
        sendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_CONFIRM));
    };

    AlertDialog &dialog = AbstractUI::GetInstance().Build();
    std::string message = "NotifyP2pProvDiscShowPinRequest: " "Receiving Device Address:" + peerAddress + "PIN:" + pin;
    dialog.SetMessage(message);
    dialog.SetTitle("Invitation Sent");
    /* The third parameter supplements the state machine event. INTERNAL_CONN_USER_CONFIRM */
    dialog.SetButton("accepts", acceptEvent, nullptr);
    AbstractUI::GetInstance().ShowAlerDialog(dialog);
}

void P2pStateMachine::NotifyUserInvitationReceivedMessage()
{
    WIFI_LOGI("P2pStateMachine::NotifyUserInvitationReceivedMessage  enter");
    const std::string inputBoxPin("input pin:");
    auto sendMessage = std::bind(static_cast<void (StateMachine::*)(int, const std::any &)>(&StateMachine::SendMessage),
        this,
        std::placeholders::_1,
        std::placeholders::_2);
    const WpsInfo &wps = savedP2pConfig.GetWpsInfo();
    std::function<void(AlertDialog &, std::any)> acceptEvent = [=](AlertDialog &dlg, std::any msg) {
        std::any msgBuf = msg;
        std::any anyPin;
        if (wps.GetWpsMethod() == WpsMethod::WPS_METHOD_KEYPAD) {
            anyPin = dlg.GetInputBox(inputBoxPin);
        }
        sendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_ACCEPT), anyPin);
    };

    std::function<void(AlertDialog &, std::any)> rejectEvent = [=](AlertDialog &dlg, std::any msg) {
        AlertDialog dlgBuf = dlg;
        std::any andMsg = msg;
        /* PEER_CONNECTION_USER_REJECT -> INTERNAL_CONN_USER_ACCEPT @2022-11-24 */
        SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_ACCEPT), andMsg);
    };

    AlertDialog &dialog = AbstractUI::GetInstance().Build();
    std::string message = "NotifyInvitationReceived: "
        "Receiving device:" +
        deviceManager.GetDeviceName(savedP2pConfig.GetDeviceAddress());
    dialog.SetButton("accepts", acceptEvent, nullptr);
    dialog.SetButton("rejects", rejectEvent, nullptr);

    switch (wps.GetWpsMethod()) {
        case WpsMethod::WPS_METHOD_KEYPAD: {
            dialog.SetInputBox(inputBoxPin);
            break;
        }
        case WpsMethod::WPS_METHOD_DISPLAY: {
            message += std::string("PIN:") + wps.GetPin();
            break;
        }
        default:
            break;
    }
    dialog.SetMessage(message);
    AbstractUI::GetInstance().ShowAlerDialog(dialog);
}

void P2pStateMachine::P2pConnectByShowingPin(const WifiP2pConfigInternal &config) const
{
    if (config.GetDeviceAddress().empty()) {
        WIFI_LOGE("Invalid address parameter.");
        return;
    }

    WifiP2pDevice device = FetchNewerDeviceInfo(config.GetDeviceAddress());
    if (!device.IsValid()) {
        WIFI_LOGE("Invalid device obtained.");
        return;
    }

    std::string pin;
    if (WifiErrorNo::WIFI_IDL_OPT_OK !=
        WifiP2PHalInterface::GetInstance().Connect(config, device.IsGroupOwner(), pin)) {
        WIFI_LOGE("Connection failed.");
    }

    if (!pin.empty()) {
        WIFI_LOGI("connect return pin is %{private}s", pin.c_str());
        NotifyUserInvitationSentMessage(pin, config.GetDeviceAddress());
    }
}

void P2pStateMachine::HandlerDiscoverPeers()
{
    WIFI_LOGD("p2p_enabled_state recv CMD_DEVICE_DISCOVERS");
    CancelSupplicantSrvDiscReq();
    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().P2pFind(DISC_TIMEOUT_S);
    if (retCode == WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGD("call P2pFind successful, CMD_DEVICE_DISCOVERS successful.");
        BroadcastActionResult(P2pActionCallback::DiscoverDevices, ErrCode::WIFI_OPT_SUCCESS);
        BroadcastP2pDiscoveryChanged(true);
    } else {
        WIFI_LOGE("call P2pFind failed, ErrorCode: %{public}d", static_cast<int>(retCode));
        BroadcastActionResult(P2pActionCallback::DiscoverDevices, ErrCode::WIFI_OPT_FAILED);
    }
}

void P2pStateMachine::ChangeConnectedStatus(P2pConnectedState connectedState)
{
    WIFI_LOGI("ChangeConnectedStatus, connectedState: %{public}d", connectedState);
    WifiP2pLinkedInfo p2pInfo;
    WifiSettings::GetInstance().GetP2pInfo(p2pInfo);
    P2pConnectedState curP2pConnectedState = p2pInfo.GetConnectState();
    if (curP2pConnectedState == connectedState) {
        WIFI_LOGD("The connection status is the same, ignore this status!");
        return;
    }

    p2pInfo.SetConnectState(connectedState);
    WifiSettings::GetInstance().SaveP2pInfo(p2pInfo);
    groupManager.SaveP2pInfo(p2pInfo);

    if (connectedState == P2pConnectedState::P2P_CONNECTED) {
        std::string deviceAddress;
        savedP2pConfig.SetDeviceAddress(deviceAddress);
        UpdateOwnDevice(P2pDeviceStatus::PDS_CONNECTED);
        if (GetIsNeedDhcp() != DHCPTYPE::DHCP_LEGACEGO) {
            BroadcastP2pConnectionChanged();
        }
    }

    if (connectedState == P2pConnectedState::P2P_DISCONNECTED) {
        UpdateOwnDevice(P2pDeviceStatus::PDS_AVAILABLE);
        ClearWifiP2pInfo();
        BroadcastP2pConnectionChanged();
        WifiSettings::GetInstance().ClearLocalHid2dInfo();
        deviceManager.UpdateAllDeviceStatus(P2pDeviceStatus::PDS_AVAILABLE);
    }
    return;
}

void P2pStateMachine::ClearWifiP2pInfo()
{
    WifiP2pLinkedInfo p2pInfo;
    WifiSettings::GetInstance().SaveP2pInfo(p2pInfo);
    groupManager.SaveP2pInfo(p2pInfo);
}

bool P2pStateMachine::StartDhcpServer()
{
    Ipv4Address ipv4(Ipv4Address::defaultInetAddress);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    pDhcpResultNotify->SetP2pStateMachine(this, &groupManager);
    serverCallBack.OnServerSuccess = P2pStateMachine::DhcpResultNotify::OnDhcpServerSuccess;
    m_DhcpdInterface.RegisterDhcpCallBack(groupManager.GetCurrentGroup().GetInterface(), serverCallBack);
    const std::string ipAddress = DEFAULT_P2P_IPADDR;
    if (!m_DhcpdInterface.StartDhcpServerFromInterface(groupManager.GetCurrentGroup().GetInterface(),
                                                       ipv4, ipv6, ipAddress, true)) {
        return false;
    }
    SetWifiP2pInfoWhenGroupFormed(ipv4.GetAddressWithString());
    WifiP2pGroupInfo currGroup = groupManager.GetCurrentGroup();
    currGroup.SetGoIpAddress(ipv4.GetAddressWithString());
    groupManager.SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, currGroup);

    WIFI_LOGI("Start add route");
    WifiNetAgent::GetInstance().AddRoute(groupManager.GetCurrentGroup().GetInterface(),
        ipv4.GetAddressWithString(), ipv4.GetAddressPrefixLength());
    WIFI_LOGI("Start dhcp server for P2p finished.");
    WriteWifiP2pStateHiSysEvent(groupManager.GetCurrentGroup().GetInterface(), P2P_GO, P2P_ON);
    return true;
}

bool P2pStateMachine::StopDhcpServer()
{
    if (!groupManager.GetCurrentGroup().GetInterface().empty()) {
        WriteWifiP2pStateHiSysEvent(groupManager.GetCurrentGroup().GetInterface(), P2P_GO, P2P_OFF);
    }
    return m_DhcpdInterface.StopDhcp(groupManager.GetCurrentGroup().GetInterface());
}

P2pStateMachine* P2pStateMachine::DhcpResultNotify::pP2pStateMachine = nullptr;
WifiP2pGroupManager* P2pStateMachine::DhcpResultNotify::groupManager = nullptr;
P2pStateMachine::DhcpResultNotify::DhcpResultNotify()
{}

P2pStateMachine::DhcpResultNotify::~DhcpResultNotify()
{}

void P2pStateMachine::DhcpResultNotify::SetP2pStateMachine(P2pStateMachine *p2pStateMachine,
    WifiP2pGroupManager *pGroupManager)
{
    pP2pStateMachine = p2pStateMachine;
    groupManager = pGroupManager;
}

void P2pStateMachine::DhcpResultNotify::OnSuccess(int status, const char *ifname, DhcpResult *result)
{
    if (ifname == nullptr || result == nullptr) {
        WIFI_LOGE("P2P DhcpResultNotify OnSuccess, ifname or result is nullptr, status: %{public}d, ifname: %{public}s",
            status, ifname);
        return;
    }
    WIFI_LOGI("Enter P2P DhcpResultNotify::OnSuccess, status: %{public}d, ifname: %{public}s", status, ifname);
    WifiP2pLinkedInfo p2pInfo;
    WifiSettings::GetInstance().GetP2pInfo(p2pInfo);
    WIFI_LOGI("Set GO IP: %{private}s", result->strOptServerId);
    p2pInfo.SetIsGroupOwnerAddress(result->strOptServerId);
    WifiP2pGroupInfo currGroup = groupManager->GetCurrentGroup();
    currGroup.SetGoIpAddress(result->strOptServerId);
    groupManager->SetCurrentGroup(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, currGroup);
    WifiSettings::GetInstance().SaveP2pInfo(p2pInfo);
    groupManager->SaveP2pInfo(p2pInfo);
    pP2pStateMachine->BroadcastP2pConnectionChanged();
    WIFI_LOGI("Start add route on dhcp success");
    WifiNetAgent::GetInstance().AddRoute(ifname, result->strOptClientId, IpTools::GetMaskLength(result->strOptSubnet));
    WIFI_LOGI("DhcpResultNotify::OnSuccess end");
}

void P2pStateMachine::DhcpResultNotify::OnFailed(int status, const char *ifname, const char *reason)
{
    WIFI_LOGI("Enter DhcpResultNotify::OnFailed, status: %{public}d, reason: %{public}s. RemoveGroup: %{private}s",
        status,
        reason,
        ifname);
    std::string ifaceifname = ifname;
    if (pP2pStateMachine->p2pDevIface == ifaceifname) {
        pP2pStateMachine->p2pDevIface = "";
    }
    WifiP2PHalInterface::GetInstance().GroupRemove(ifaceifname);
}

void P2pStateMachine::DhcpResultNotify::OnDhcpServerSuccess(const char *ifname,
    DhcpStationInfo *stationInfos, size_t size)
{
    WIFI_LOGI("Dhcp notify ServerSuccess. ifname:%s", ifname);
    std::vector<GcInfo> gcInfos;
    for (size_t i = 0; i < size; i++) {
        GcInfo gcInfo;
        gcInfo.mac = stationInfos[i].macAddr;
        gcInfo.ip = stationInfos[i].ipAddr;
        gcInfo.host = stationInfos[i].deviceName;
        gcInfos.emplace_back(gcInfo);
    }
    if (ErrCode::WIFI_OPT_SUCCESS != pP2pStateMachine->AddClientInfo(gcInfos)) {
        WIFI_LOGE("AddClientInfo failed");
    }
}

void P2pStateMachine::StartDhcpClientInterface()
{
    WriteWifiP2pStateHiSysEvent(groupManager.GetCurrentGroup().GetInterface(), P2P_GC, P2P_ON);
    if (GetIsNeedDhcp() == DHCPTYPE::NO_DHCP) {
        WIFI_LOGI("The service of this time does not need DHCP.");
        return;
    }

    clientCallBack.OnIpSuccessChanged = DhcpResultNotify::OnSuccess;
    clientCallBack.OnIpFailChanged = DhcpResultNotify::OnFailed;
    pDhcpResultNotify->SetP2pStateMachine(this, &groupManager);
    int result = RegisterDhcpClientCallBack(groupManager.GetCurrentGroup().GetInterface().c_str(), &clientCallBack);
    if (result != 0) {
        WIFI_LOGE("RegisterDhcpClientCallBack failed!");
        return;
    }
    result = StartDhcpClient(groupManager.GetCurrentGroup().GetInterface().c_str(), false);
    if (result != 0) {
        WIFI_LOGE("StartDhcpClient failed!");
        return;
    }
    WIFI_LOGI("StartDhcpClient ok");
}

void P2pStateMachine::HandleP2pServiceResp(const WifiP2pServiceResponse &resp, const WifiP2pDevice &dev) const
{
    WIFI_LOGI("HandleP2pServiceResp");
    serviceManager.AddDeviceService(resp, dev);
    if (resp.GetServiceStatus() == P2pServiceStatus::PSRS_SERVICE_PROTOCOL_NOT_AVAILABLE) {
        WIFI_LOGD("Service protocol is not available.");
        return;
    }
    if (resp.GetProtocolType() == P2pServicerProtocolType::SERVICE_TYPE_BONJOUR) {
        WifiP2pDnsSdServiceResponse dnsSrvResp = WifiP2pDnsSdServiceResponse(resp);
        if (!dnsSrvResp.ParseData()) {
            WIFI_LOGE("Parse WifiP2pDnsServiceResponse failed!");
            return;
        }
        serviceManager.UpdateServiceName(dev.GetDeviceAddress(), dynamic_cast<WifiP2pServiceResponse &>(dnsSrvResp));
        if (dnsSrvResp.GetDnsType() == WifiP2pDnsSdServiceInfo::DNS_PTR_TYPE) {
            BroadcastDnsSdServiceResult(dnsSrvResp.GetInstanceName(), dnsSrvResp.GetQueryName(), dev);
            return;
        }
        if (dnsSrvResp.GetDnsType() == WifiP2pDnsSdServiceInfo::DNS_TXT_TYPE) {
            BroadcastDnsSdTxtRecordResult(dnsSrvResp.GetQueryName(), dnsSrvResp.GetTxtRecord(), dev);
            return;
        }
        WIFI_LOGE("Parse WifiP2pDnsSdServiceResponse Dnstype failed!");
        return;
    }
    if (resp.GetProtocolType() == P2pServicerProtocolType::SERVICE_TYPE_UP_NP) {
        WifiP2pUpnpServiceResponse upnpSrvResp =
            WifiP2pUpnpServiceResponse::Create(resp.GetServiceStatus(), resp.GetTransactionId(), resp.GetData());
        if (upnpSrvResp.ParseData()) {
            serviceManager.UpdateServiceName(
                dev.GetDeviceAddress(), dynamic_cast<WifiP2pServiceResponse &>(upnpSrvResp));
            BroadcastUpnpServiceResult(upnpSrvResp.GetUniqueServNames(), dev);
        } else {
            WIFI_LOGE("Parse WifiP2pUpnpServiceResponse failed!");
        }
        return;
    }

    BroadcastServiceResult(resp.GetProtocolType(), resp.GetData(), dev);
    return;
}

int P2pStateMachine::GetAvailableFreqByBand(GroupOwnerBand band) const
{
    std::vector<int> freqList;
    if (band != GroupOwnerBand::GO_BAND_2GHZ && band != GroupOwnerBand::GO_BAND_5GHZ) {
        WIFI_LOGE("Not 2.4GHz or 5GHz band!");
        return 0;
    }
    if (WifiP2PHalInterface::GetInstance().P2pGetSupportFrequenciesByBand(static_cast<int>(band), freqList) ==
        WifiErrorNo::WIFI_IDL_OPT_FAILED) {
        constexpr int DEFAULT_5G_FREQUENCY = 5745; // channal:149, frequency:5745
        if (band == GroupOwnerBand::GO_BAND_5GHZ) {
            WIFI_LOGE("Get support frequencies failed, use default 5g frequency!");
            return DEFAULT_5G_FREQUENCY;
        }
        constexpr int DEFAULT_2G_FREQUENCY = 2412;
        if (band == GroupOwnerBand::GO_BAND_2GHZ) {
            WIFI_LOGE("Get support frequencies failed, use default 2g frequency!");
            return DEFAULT_2G_FREQUENCY;
        }
        WIFI_LOGE("Cannot get support frequencies according to band, choose random frequency");
        return 0;
    }
    std::random_device rd;
    int randomIndex = std::abs(static_cast<int>(rd())) % freqList.size();
    int retFreq = freqList.at(randomIndex);
    return retFreq;
}

bool P2pStateMachine::SetGroupConfig(const WifiP2pConfigInternal &config, bool newGroup) const
{
    WifiErrorNo ret;
    IdlP2pGroupConfig wpaConfig;
    WifiP2pGroupInfo group;
    if (newGroup) {
        WIFI_LOGI("SetGroupConfig, new group");
        wpaConfig.ssid = config.GetGroupName();
        wpaConfig.psk = config.GetPassphrase();
        wpaConfig.bssid = deviceManager.GetThisDevice().GetDeviceAddress();
        const int p2pDisabled = 2;
        wpaConfig.disabled = p2pDisabled;
        const int p2pMode = 3;
        wpaConfig.mode = p2pMode;
    } else {
        WIFI_LOGI("SetGroupConfig, not new group");
        IdlP2pGroupConfig knownConfig;
        ret = WifiP2PHalInterface::GetInstance().P2pGetGroupConfig(config.GetNetId(), knownConfig);
        if (ret == WifiErrorNo::WIFI_IDL_OPT_FAILED) {
            WIFI_LOGW("P2pGetGroupConfig failed");
        }
        if (!config.GetGroupName().empty()) {
            wpaConfig.ssid = config.GetGroupName();
        } else {
            wpaConfig.ssid = knownConfig.ssid;
        }
        if (!config.GetPassphrase().empty()) {
            wpaConfig.psk = config.GetPassphrase();
        } else {
            WIFI_LOGI("Passphrase empty!");
            wpaConfig.psk = std::string("");
        }
        wpaConfig.authAlg = knownConfig.authAlg;
        wpaConfig.bssid = knownConfig.bssid;
        wpaConfig.keyMgmt = knownConfig.keyMgmt;
        wpaConfig.pairwise = knownConfig.pairwise;
        wpaConfig.proto = knownConfig.proto;
        wpaConfig.disabled = knownConfig.disabled;
        wpaConfig.mode = knownConfig.mode;
    }
    group.SetGroupName(config.GetGroupName());
    group.SetPassphrase(config.GetPassphrase());
    group.SetNetworkId(config.GetNetId());
    groupManager.AddOrUpdateGroup(group);
    ret = WifiP2PHalInterface::GetInstance().P2pSetGroupConfig(config.GetNetId(), wpaConfig);
    if (ret == WifiErrorNo::WIFI_IDL_OPT_FAILED) {
        return false;
    } else {
        return true;
    }
}

bool P2pStateMachine::DealCreateNewGroupWithConfig(const WifiP2pConfigInternal &config, int freq) const
{
    WifiP2pConfigInternal cfgBuf = config;
    int createdNetId = -1;
    int netId = cfgBuf.GetNetId();

    std::vector<WifiP2pGroupInfo> groupInfo = groupManager.GetGroups();
    for (auto iter = groupInfo.begin(); iter != groupInfo.end(); ++iter) {
        if (iter->GetGroupName() == config.GetGroupName()) {
            WIFI_LOGE("Cannot use a exist group name!");
            return false;
        }
    }

    WifiErrorNo ret = WifiP2PHalInterface::GetInstance().P2pAddNetwork(createdNetId);
    if (ret == WIFI_IDL_OPT_OK) {
        cfgBuf.SetNetId(createdNetId);
        if (!SetGroupConfig(cfgBuf, true)) {
            WIFI_LOGW("Some configuration settings failed!");
        }
        ret = WifiP2PHalInterface::GetInstance().GroupAdd(true, createdNetId, freq);
    }

    if (ret == WIFI_IDL_OPT_FAILED || netId == TEMPORARY_NET_ID) {
        WIFI_LOGD("Remove network %{public}d!", createdNetId);
        WifiP2PHalInterface::GetInstance().RemoveNetwork(createdNetId);
        WifiP2pGroupInfo removedInfo;
        removedInfo.SetNetworkId(createdNetId);
        groupManager.RemoveGroup(removedInfo);
    }

    UpdateGroupManager();
    UpdatePersistentGroups();
    return (ret == WIFI_IDL_OPT_FAILED) ? false : true;
}

bool P2pStateMachine::IsInterfaceReuse() const
{
    return !(WifiSettings::GetInstance().GetP2pIfaceName().compare("wlan0"));
}

void P2pStateMachine::UpdateGroupInfoToWpa() const
{
    WIFI_LOGI("Start update group info to wpa");
    /* 1) In the scenario of interface reuse, the configuration of sta may be deleted
     * 2) Dont remove p2p networks of wpa_s in initial phase after device reboot
     */
    if (IsInterfaceReuse()) {
        return;
    }
    std::vector<WifiP2pGroupInfo> grpInfo = groupManager.GetGroups();
    if (grpInfo.size() > 0) {
        if (WifiP2PHalInterface::GetInstance().RemoveNetwork(-1) != WIFI_IDL_OPT_OK) {
            WIFI_LOGE("Failed to delete all group info before update group info to wpa! Stop update!");
            return;
        }
    }

    int createdNetId = -1;
    WifiP2pGroupInfo grpBuf;
    IdlP2pGroupConfig wpaConfig;
    for (unsigned int i = 0; i < grpInfo.size(); ++i) {
        grpBuf = grpInfo.at(i);
        WifiErrorNo ret = WifiP2PHalInterface::GetInstance().P2pAddNetwork(createdNetId);
        if (ret == WIFI_IDL_OPT_OK) {
            grpBuf.SetNetworkId(createdNetId);
            wpaConfig.ssid = grpBuf.GetGroupName();
            wpaConfig.psk = grpBuf.GetPassphrase();
            wpaConfig.bssid = grpBuf.GetOwner().GetDeviceAddress();
            const int p2pDisabled = 2;
            wpaConfig.disabled = p2pDisabled;
            if (grpBuf.GetOwner().GetDeviceAddress() == deviceManager.GetThisDevice().GetDeviceAddress()) {
                const int p2pMode = 3;
                wpaConfig.mode = p2pMode;
            } else {
                wpaConfig.mode = 0;
            }
            WifiP2PHalInterface::GetInstance().P2pSetGroupConfig(createdNetId, wpaConfig);
            grpInfo.at(i) = grpBuf;
        } else {
            WIFI_LOGW("AddNetwork failed when add %{public}s group!", grpBuf.GetGroupName().c_str());
        }
    }
    return;
}

void P2pStateMachine::RemoveGroupByDevice(WifiP2pDevice &device) const
{
    int networkId = groupManager.GetGroupNetworkId(device);
    if (networkId != -1) {
        RemoveGroupByNetworkId(networkId);
    }
    return;
}


DHCPTYPE P2pStateMachine::GetIsNeedDhcp() const
{
    WIFI_LOGI("Get need dhcp flag %{public}d", (int)m_isNeedDhcp);
    return m_isNeedDhcp;
}

void P2pStateMachine::SetIsNeedDhcp(DHCPTYPE dhcpType)
{
    WIFI_LOGI("Set need dhcp flag %{public}d", dhcpType);
    m_isNeedDhcp = dhcpType;
}

void P2pStateMachine::ClearGroup() const
{
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    int n;
    std::string iface;

    if (getifaddrs(&ifaddr) == -1) {
        WIFI_LOGE("getifaddrs failed, error is %{public}d", errno);
        return;
    }
    for (ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
        if (strncmp("p2p-", ifa->ifa_name, P2P_PREFIX_LEN) == 0) {
            WIFI_LOGE("has p2p group, remove");
            iface.assign(ifa->ifa_name);
            WifiP2PHalInterface::GetInstance().GroupRemove(iface);
            // current p2p group can be created only one,
            // if there are multiple groups can be created in the future, the break need to be modified.
            break;
        }
    }
    freeifaddrs(ifaddr);
}
} // namespace Wifi
} // namespace OHOS
