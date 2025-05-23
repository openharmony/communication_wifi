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

#include "wifi_p2p_service.h"
#include "abstract_ui.h"
#include "ipc_skeleton.h"
#include "p2p_define.h"
#include "wifi_channel_helper.h"
#include "wifi_common_util.h"
#include "wifi_errcode.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_country_code_manager.h"
#include "wifi_p2p_hal_interface.h"
#include "ap_define.h"

DEFINE_WIFILOG_P2P_LABEL("WifiP2pService");

namespace OHOS {
namespace Wifi {
#define COUNTRY_CODE_JAPAN_L "jp"
#define COUNTRY_CODE_JAPAN_C "JP"
#define SOFT_BUS_UID 1024

std::map<int, int> g_listenSa = {{SOFTBUS_SERVER_SA_ID, SOFT_BUS_UID},
    {MIRACAST_SERVICE_SA_ID, MIRACAST_SERVICE_UID}};

WifiP2pService::WifiP2pService(P2pStateMachine &p2pStateMachine, WifiP2pDeviceManager &setDeviceMgr,
    WifiP2pGroupManager &setGroupMgr, WifiP2pServiceManager &setSvrMgr)
    : p2pStateMachine(p2pStateMachine),
      deviceManager(setDeviceMgr),
      groupManager(setGroupMgr),
      serviceManager(setSvrMgr)
{}

WifiP2pService::~WifiP2pService()
{
    ClearAllP2pServiceCallbacks();
}

ErrCode WifiP2pService::EnableP2p()
{
    WIFI_LOGI("EnableP2p");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_P2P_ENABLE));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DisableP2p()
{
    WIFI_LOGI("DisableP2p");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::SetEnhanceService(IEnhanceService* enhanceService)
{
    p2pStateMachine.SetEnhanceService(enhanceService);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DiscoverDevices()
{
    WIFI_LOGI("DiscoverDevices");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DEVICE_DISCOVERS));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::StopDiscoverDevices()
{
    WIFI_LOGI("StopDiscoverDevices");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_STOP_DEVICE_DISCOVERS));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DiscoverServices()
{
    WIFI_LOGI("DiscoverServices");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DISCOVER_SERVICES));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::StopDiscoverServices()
{
    WIFI_LOGI("StopDiscoverServices");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_STOP_DISCOVER_SERVICES));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::PutLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    WIFI_LOGI("PutLocalP2pService");
    const std::any info = srvInfo;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_PUT_LOCAL_SERVICE), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    WIFI_LOGI("DeleteLocalP2pService");
    const std::any info = srvInfo;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DEL_LOCAL_SERVICE), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request)
{
    WIFI_LOGI("RequestService");
    const std::any info = std::pair<WifiP2pDevice, WifiP2pServiceRequest>(device, request);
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REQUEST_SERVICE), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::StartP2pListen(int period, int interval)
{
    WIFI_LOGI("StartP2pListen");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_START_LISTEN), period, interval);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::StopP2pListen()
{
    WIFI_LOGI("StopP2pListen");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_STOP_LISTEN));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::CreateRptGroup(const WifiP2pConfig &config)
{
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(IPCSkeleton::GetCallingUid());
    WIFI_LOGI("CreateGroup name: %{private}s, address:%{private}s, addressType:%{public}d",
        config.GetGroupName().c_str(), config.GetDeviceAddress().c_str(), config.GetDeviceAddressType());
    WifiP2pConfigInternal configInternal(config);
    WpsInfo wps;
    wps.SetWpsMethod(WpsMethod::WPS_METHOD_PBC);
    configInternal.SetWpsInfo(wps);
    const std::any info = configInternal;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_FORM_RPT_GROUP), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::GetRptStationsList(std::vector<StationInfo> &result)
{
    auto devices = groupManager.GetCurrentGroup().GetClientDevices();
    if (devices.empty()) {
        WIFI_LOGI("GetRptStationsList is empty");
        return ErrCode::WIFI_OPT_SUCCESS;
    }

    WIFI_LOGI("GetRptStationsList size:%{public}d", static_cast<int>(devices.size()));
    for (const auto &dev : devices) {
        StationInfo info;
        info.bssid = dev.GetRandomDeviceAddress();
        info.bssidType = dev.GetDeviceAddressType();
        info.deviceName = dev.GetDeviceName();
        info.ipAddr = GETTING_INFO;
        result.push_back(info);
    }

    // get dhcp lease info, return full connected station info
    std::map<std::string, StationInfo> tmp;
    if (!p2pStateMachine.GetConnectedStationInfo(tmp)) {
        WIFI_LOGW("Get connected station info failed!");
        return ErrCode::WIFI_OPT_FAILED;
    }

    for (auto iter = result.begin(); iter != result.end(); ++iter) {
        auto itMap = tmp.find(iter->bssid);
        if (itMap == tmp.end()) {
            continue;
        }
        iter->deviceName = itMap->second.deviceName;
        iter->ipAddr = itMap->second.ipAddr;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::CreateGroup(const WifiP2pConfig &config)
{
    int callingUid = IPCSkeleton::GetCallingUid();
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(callingUid);
    WIFI_LOGI("CreateGroup name: %{private}s, address:%{private}s, addressType:%{public}d",
        config.GetGroupName().c_str(), config.GetDeviceAddress().c_str(), config.GetDeviceAddressType());
    WifiP2pConfigInternal configInternal(config);
    WpsInfo wps;
    wps.SetWpsMethod(WpsMethod::WPS_METHOD_PBC);
    configInternal.SetWpsInfo(wps);
    const std::any info = configInternal;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_FORM_GROUP), callingUid, 0, info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::RemoveGroup()
{
    WIFI_LOGI("RemoveGroup");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::RemoveGroupClient(const GcInfo &gcInfo)
{
    WIFI_LOGI("RemoveGroupClient");
    const std::any info = gcInfo;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP_CLIENT), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DeleteGroup(const WifiP2pGroupInfo &group)
{
    WIFI_LOGI("DeleteGroup");
    const std::any info = group;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::P2pConnect(const WifiP2pConfig &config)
{
    WIFI_LOGI("P2pConnect");
    int callingUid = IPCSkeleton::GetCallingUid();
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(callingUid);
    WifiP2pConfigInternal configInternal(config);
    WpsInfo wps;
    wps.SetWpsMethod(WpsMethod::WPS_METHOD_PBC);
    configInternal.SetWpsInfo(wps);
    p2pStateMachine.SetIsNeedDhcp(DHCPTYPE::DHCP_P2P);
    const std::any info = configInternal;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_CONNECT), callingUid, 0, info);

    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::P2pCancelConnect()
{
    WIFI_LOGI("P2pCancelConnect");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_CANCEL_CONNECT));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::SetP2pDeviceName(const std::string &devName)
{
    WIFI_LOGI("SetP2pDeviceName");
    const std::any info = devName;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_SET_DEVICE_NAME), info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo)
{
    WIFI_LOGD("enable = %{public}d device info = %{public}d port = %{public}d throughput = %{public}d\n",
        wfdInfo.GetWfdEnabled(), wfdInfo.GetDeviceInfo(), wfdInfo.GetCtrlPort(), wfdInfo.GetMaxThroughput());
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_SET_WFD_INFO), wfdInfo);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo)
{
    WIFI_LOGI("QueryP2pLinkedInfo");
    linkedInfo = groupManager.GetP2pInfo();
    if (linkedInfo.GetConnectState() == P2pConnectedState::P2P_DISCONNECTED) {
        return ErrCode::WIFI_OPT_SUCCESS;
    }
    WifiP2pGroupInfo groupInfo = groupManager.GetCurrentGroup();
    if (!groupInfo.IsGroupOwner()) {
        return ErrCode::WIFI_OPT_SUCCESS;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::GetCurrentGroup(WifiP2pGroupInfo &group)
{
    WIFI_LOGD("GetCurrentGroup");
    WifiP2pLinkedInfo p2pInfo;
    WifiConfigCenter::GetInstance().GetP2pInfo(p2pInfo);
    if (p2pInfo.GetConnectState() == P2pConnectedState::P2P_DISCONNECTED) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    WifiP2pGroupInfo copy = groupManager.GetCurrentGroup();
    group = copy;
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::GetP2pEnableStatus(int &status)
{
    WIFI_LOGI("GetP2pEnableStatus");
    status = WifiConfigCenter::GetInstance().GetP2pState();
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::GetP2pDiscoverStatus(int &status)
{
    WIFI_LOGI("GetP2pDiscoverStatus");
    status = WifiConfigCenter::GetInstance().GetP2pDiscoverState();
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::GetP2pConnectedStatus(int &status)
{
    WIFI_LOGI("GetP2pConnectedStatus");
    WifiP2pLinkedInfo p2pInfo;
    WifiConfigCenter::GetInstance().GetP2pInfo(p2pInfo);
    status = static_cast<int>(p2pInfo.GetConnectState());
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::QueryP2pDevices(std::vector<WifiP2pDevice> &devices)
{
    int size = deviceManager.GetDevicesList(devices);
    WIFI_LOGI("QueryP2pDevices, size:%{public}d", size);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::QueryP2pLocalDevice(WifiP2pDevice &device)
{
    LOGI("QueryP2pLocalDevice");
    device = deviceManager.GetThisDevice();
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups)
{
    WIFI_LOGI("QueryP2pGroups");
    groups = groupManager.GetGroups();
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::QueryP2pServices(std::vector<WifiP2pServiceInfo> &services)
{
    WIFI_LOGI("QueryP2pServices");
    serviceManager.GetDeviceServices(services);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::RegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks)
{
    WIFI_LOGI("RegisterP2pServiceCallbacks");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REGISTER_SERVICE_CB), callbacks);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::UnRegisterP2pServiceCallbacks(const IP2pServiceCallbacks &callbacks)
{
    WIFI_LOGI("UnRegisterP2pServiceCallbacks");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_UNREGISTER_SERVICE_CB), callbacks);
    return ErrCode::WIFI_OPT_SUCCESS;
}

void WifiP2pService::ClearAllP2pServiceCallbacks()
{
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_CLEAR_SERVICE_CB));
}

ErrCode WifiP2pService::Hid2dCreateGroup(const int frequency, FreqType type)
{
    WIFI_LOGI("Create hid2d group");
    int callingUid = IPCSkeleton::GetCallingUid();
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(callingUid);
    const std::any info = std::pair<int, FreqType>(frequency, type);
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_HID2D_CREATE_GROUP), callingUid, 0, info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::Hid2dConnect(const Hid2dConnectConfig& config)
{
    WIFI_LOGI("Hid2dConnect");
    int callingUid = IPCSkeleton::GetCallingUid();
    WifiConfigCenter::GetInstance().SaveP2pCreatorUid(callingUid);
    const std::any info = config;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_HID2D_CONNECT), callingUid, 0, info);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr)
{
    WIFI_LOGI("Hid2dRequestGcIp");

    WifiP2pGroupInfo group;
    ErrCode ret = GetCurrentGroup(group);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGI("Apply IP get current group failed!");
    }
    IpPool::InitIpPool(group.GetGoIpAddress());
    ipAddr = IpPool::GetIp(gcMac);
    return WIFI_OPT_SUCCESS;
}

void WifiP2pService::IncreaseSharedLink(int callingUid)
{
    WIFI_LOGI("Uid %{public}d increaseSharedLink", callingUid);
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_INCREASE_SHARE_LINK), callingUid);
}

void WifiP2pService::DecreaseSharedLink(int callingUid)
{
    WIFI_LOGI("Uid %{public}d decreaseSharedLink", callingUid);
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DECREASE_SHARE_LINK), callingUid);
}

ErrCode WifiP2pService::HandleBusinessSAException(int systemAbilityId)
{
    WIFI_LOGI("HandleBusinessSAException");
    if (SharedLinkManager::GetSharedLinkCount() == 0) {
        return WIFI_OPT_SUCCESS;
    }
    int callingUid = -1;
    if (g_listenSa.find(systemAbilityId) == g_listenSa.end()) {
        return WIFI_OPT_INVALID_PARAM;
    }
    SharedLinkManager::GetGroupUid(callingUid);
    if (callingUid == g_listenSa[systemAbilityId]) {
        SharedLinkManager::DecreaseSharedLink(callingUid);
        RemoveGroup();
        return WIFI_OPT_SUCCESS;
    } else {
        SharedLinkManager::ClearUidCount(g_listenSa[systemAbilityId]);
    }
    if (SharedLinkManager::GetSharedLinkCount() == 0) {
        RemoveGroup();
    }
    return WIFI_OPT_SUCCESS;
}

int WifiP2pService::GetP2pRecommendChannel(void)
{
    WIFI_LOGI("GetP2pRecommendChannel");
    const int COMMON_USING_2G_CHANNEL = 6;
    std::string countryCode;
    WifiCountryCodeManager::GetInstance().GetWifiCountryCode(countryCode);
    if (countryCode == COUNTRY_CODE_JAPAN_C || countryCode == COUNTRY_CODE_JAPAN_L) {
        return COMMON_USING_2G_CHANNEL;
    }
    int channel = 0; // 0 is invalid channel
    int COMMON_USING_5G_CHANNEL = 149;
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState == CONNECTED) {
        channel = FrequencyToChannel(linkedInfo.frequency);
        if (linkedInfo.band == static_cast<int>(BandType::BAND_5GHZ)) {
            const int RADAR_CHANNEL_MIN = 50;
            const int RADAR_CHANNEL_MAX = 64;
            if (channel < RADAR_CHANNEL_MIN || channel > RADAR_CHANNEL_MAX) {
                WIFI_LOGI("Recommend linked channel: %{public}d", channel);
                return channel;
            }
            // when connectted 5g sta whith radar channel then recommend channel on 36.
            COMMON_USING_5G_CHANNEL = 36;
        }
    }

    ChannelsTable channels;
    std::vector<int32_t> vec5GChannels;
    WifiChannelHelper::GetInstance().GetValidChannels(channels);
    if (channels.find(BandType::BAND_5GHZ) != channels.end()) {
        vec5GChannels = channels[BandType::BAND_5GHZ];
    }

    if (!vec5GChannels.empty()) {
        auto it = std::find(vec5GChannels.begin(), vec5GChannels.end(), COMMON_USING_5G_CHANNEL);
        if (it != vec5GChannels.end()) {
            channel = COMMON_USING_5G_CHANNEL;
        } else {
            channel = vec5GChannels[0];
        }
        WIFI_LOGI("Recommend 5G channel: %{public}d", channel);
        return channel;
    }
    channel = (channel == 0) ? COMMON_USING_2G_CHANNEL : channel;
    WIFI_LOGI("Recommend 2G channel: %{public}d", channel);
    return channel;
}

ErrCode WifiP2pService::Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene)
{
    WIFI_LOGI("Hid2dSetUpperScene");
    /* Not support currently */
    WIFI_LOGI("Set upper scene, ifName=%{public}s, scene=%{public}u, fps=%{public}d, bw=%{public}u",
        ifName.c_str(), scene.scene, scene.fps, scene.bw);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::MonitorCfgChange(void)
{
    WIFI_LOGI("MonitorCfgChange");
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DiscoverPeers(int32_t channelid)
{
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DISCOVER_PEERS), channelid);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::DisableRandomMac(int setmode)
{
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_DISABLE_RANDOM_MAC), setmode);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pService::SetGcIpAddress(const IpAddrInfo& ipInfo)
{
    WIFI_LOGI("SetGcIpAddress");
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_EVENT_IP_ADDRESS), ipInfo);
    return WIFI_OPT_SUCCESS;
}

void WifiP2pService::NotifyWscDialogConfirmResult(bool isAccept)
{
    WIFI_LOGI("Notify user auth response:%{public}d", isAccept);
    if (isAccept) {
        p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_ACCEPT));
    } else {
        p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::PEER_CONNECTION_USER_REJECT));
    }
}

ErrCode WifiP2pService::SetMiracastSinkConfig(const std::string& config)
{
    WIFI_LOGI("SetMiracastSinkConfig");
    const std::any info = config;
    p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_SET_MIRACAST_SINK_CONFIG), info);
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
