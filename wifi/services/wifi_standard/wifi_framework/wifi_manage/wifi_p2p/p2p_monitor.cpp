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
#include "p2p_monitor.h"
#include <climits>
#include "wifi_p2p_hal_interface.h"
#include "dhcpd_interface.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"
#include "p2p_define.h"
#include "wifi_hisysevent.h"
#include "wifi_event_callback.h"
#include "p2p_chr_reporter.h"

DEFINE_WIFILOG_P2P_LABEL("P2pMonitor");

namespace OHOS {
namespace Wifi {
P2pMonitor::P2pMonitor() : selectIfacName(), setMonitorIface(), mapHandler()
{}

P2pMonitor::~P2pMonitor() __attribute__((no_sanitize("cfi")))
{
    std::lock_guard<std::mutex> lock(monitorMutex);
    P2pHalCallback callback;
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    setMonitorIface.clear();
}

void P2pMonitor::Initialize()
{}

void P2pMonitor::MonitorBegins(const std::string &iface)
{
    using namespace std::placeholders;
    std::lock_guard<std::mutex> lock(monitorMutex);
    selectIfacName = iface;
    setMonitorIface.insert(iface);

    P2pHalCallback callback = {
        [this](int status) { this->OnConnectSupplicant(status); },
        [this](const HalP2pDeviceFound &deviceInfo) { this->WpaEventDeviceFound(deviceInfo); },
        [this](const std::string &p2pDeviceAddress) { this->WpaEventDeviceLost(p2pDeviceAddress); },
        [this](const std::string &srcAddress, short passwordId) { this->WpaEventGoNegRequest(srcAddress, passwordId); },
        [this]() { this->WpaEventGoNegSuccess(); },
        [this](int status) { this->WpaEventGoNegFailure(status); },
        [this](const HalP2pInvitationInfo &recvInfo) { this->WpaEventInvitationReceived(recvInfo); },
        [this](const std::string &bssid, int status) { this->WpaEventInvitationResult(bssid, status); },
        [this]() { this->WpaEventGroupFormationSuccess(); },
        [this](const std::string &failureReason) { this->WpaEventGroupFormationFailure(failureReason); },
        [this](const HalP2pGroupInfo &groupInfo) { this->WpaEventGroupStarted(groupInfo); },
        [this](const std::string &groupIfName, bool isGo) { this->WpaEventGroupRemoved(groupIfName, isGo); },
        [this](const std::string &p2pDeviceAddress) { this->WpaEventProvDiscPbcReq(p2pDeviceAddress); },
        [this](const std::string &p2pDeviceAddress) { this->WpaEventProvDiscPbcResp(p2pDeviceAddress); },
        [this](const std::string &p2pDeviceAddress) { this->WpaEventProvDiscEnterPin(p2pDeviceAddress); },
        [this](const std::string &p2pDeviceAddress, const std::string &generatedPin) {
            this->WpaEventProvDiscShowPin(p2pDeviceAddress, generatedPin);
        },
        [this]() { this->WpaEventProvDiscFailure(); },
        [this]() { this->WpaEventFindStopped(); },
        [this](const std::string &srcAddress, short updateIndicator, const std::vector<unsigned char> &tlvList) {
            this->WpaEventServDiscResp(srcAddress, updateIndicator, tlvList);
        },
        [this](const std::string &p2pDeviceAddress) { this->WpaEventApStaDisconnected(p2pDeviceAddress); },
        [this](const std::string &p2pDeviceAddress, const std::string &p2pGroupAddress) {
            this->WpaEventApStaConnected(p2pDeviceAddress, p2pGroupAddress);
        },
        [this]() { this->OnConnectSupplicantFailed(); },
        [this](const HalP2pServDiscReqInfo &reqInfo) { this->WpaEventServDiscReq(reqInfo); },
        [this](const std::string &ifName, int isGo) { this->WpaEventP2pIfaceCreated(ifName, isGo); },
        [this](const std::string &bssid, int reason) { this->WpaEventP2pConnectFailed(bssid, reason); },
        [this](int freq) { this->WpaEventP2pChannelSwitch(freq); },
        [this](const std::string &notifyParam) { this->WpaEventStaNotifyCallBack(notifyParam); },
    };

    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
}

void P2pMonitor::MonitorEnds(const std::string &iface)
{
    std::lock_guard<std::mutex> lock(monitorMutex);
    P2pHalCallback callback;
    WifiP2PHalInterface::GetInstance().RegisterP2pCallback(callback);
    setMonitorIface.erase(iface);
}

void P2pMonitor::RegisterIfaceHandler(const std::string &iface, const std::function<HandlerMethod> &handler)
{
    std::lock_guard<std::mutex> lock(monitorMutex);
    auto iter = mapHandler.find(iface);
    if (iter != mapHandler.end()) {
        iter->second = handler;
    } else {
        mapHandler.emplace(std::make_pair(iface, handler));
    }
}

void P2pMonitor::UnregisterHandler(const std::string &iface)
{
    std::lock_guard<std::mutex> lock(monitorMutex);
    auto iter = mapHandler.find(iface);
    if (iter != mapHandler.end()) {
        mapHandler.erase(iter);
    }
}

void P2pMonitor::MessageToStateMachine(
    const std::string &iface, P2P_STATE_MACHINE_CMD msgName, int param1, int param2, const std::any &messageObj) const
{
    std::lock_guard<std::mutex> lock(monitorMutex);
    if (setMonitorIface.count(iface) > 0) {
        auto iter = mapHandler.find(iface);
        if (iter != mapHandler.end()) {
            WIFI_LOGI("P2p Monitor event: iface [%{public}s], eventID [%{public}d]",
                iface.c_str(),
                static_cast<int>(msgName));
            const auto &handler = iter->second;
            handler(msgName, param1, param2, messageObj);
        } else {
            WIFI_LOGE("iface: %{private}s is not register handler.", iface.c_str());
        }
    } else {
        WIFI_LOGW("iface: %{public}s is not monitor.", iface.c_str());
    }
}

P2pStatus P2pMonitor::IntStatusToP2pStatus(int status) const
{
    std::map<P2pStatusCode, P2pStatus> translateMap;
    translateMap.insert(std::make_pair(P2pStatusCode::SUCCESS, P2pStatus::SUCCESS));
    translateMap.insert(std::make_pair(P2pStatusCode::SUCCESS_DEFERRED, P2pStatus::SUCCESS));
    translateMap.insert(std::make_pair(
        P2pStatusCode::FAIL_INFORMATION_IS_CURRENTLY_UNAVAILABLE, P2pStatus::INFORMATION_IS_CURRENTLY_UNAVAILABLE));
    translateMap.insert(
        std::make_pair(P2pStatusCode::FAIL_INCOMPATIBLE_PARAMETERS, P2pStatus::INCOMPATIBLE_PARAMETERS));
    translateMap.insert(std::make_pair(P2pStatusCode::FAIL_LIMIT_REACHED, P2pStatus::LIMIT_REACHED));
    translateMap.insert(std::make_pair(P2pStatusCode::FAIL_INVALID_PARAMETERS, P2pStatus::INVALID_PARAMETERS));
    translateMap.insert(
        std::make_pair(P2pStatusCode::FAIL_UNABLE_TO_ACCOMMODATE_REQUEST, P2pStatus::UNABLE_TO_ACCOMMODATE_REQUEST));
    translateMap.insert(
        std::make_pair(P2pStatusCode::FAIL_PREVIOUS_PROTOCOL_ERROR, P2pStatus::PREVIOUS_PROTOCOL_ERROR));
    translateMap.insert(std::make_pair(P2pStatusCode::FAIL_NO_COMMON_CHANNELS, P2pStatus::NO_COMMON_CHANNELS));
    translateMap.insert(std::make_pair(P2pStatusCode::FAIL_UNKNOWN_P2P_GROUP, P2pStatus::UNKNOWN_P2P_GROUP));
    translateMap.insert(std::make_pair(
        P2pStatusCode::FAIL_BOTH_DEVICE_INDICATED_INTENT_15, P2pStatus::BOTH_DEVICE_INDICATED_INTENT_15));
    translateMap.insert(std::make_pair(
        P2pStatusCode::FAIL_INCOMPATIBLE_PROVISIONING_METHOD, P2pStatus::INCOMPATIBLE_PROVISIONING_METHOD));
    translateMap.insert(std::make_pair(P2pStatusCode::FAIL_REJECTED_BY_USER, P2pStatus::REJECTED_BY_USER));

    P2pStatus ret = P2pStatus::UNKNOWN;
    auto iter = translateMap.find(static_cast<P2pStatusCode>(status));
    if (iter == translateMap.end()) {
        return ret;
    }
    ret = iter->second;
    return ret;
}

void P2pMonitor::Broadcast2SmConnectSupplicant(const std::string &iface, int status) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::WPA_CONNECTED_EVENT, status, 0, anyNone);
}

void P2pMonitor::Broadcast2SmDeviceFound(const std::string &iface, const WifiP2pDevice &device) const
{
    std::any anyDevice = device;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_DEVICE_FOUND, 0, 0, anyDevice);
}

void P2pMonitor::Broadcast2SmPrivateDeviceFound(const std::string &iface, const std::string &privateInfo) const
{
    std::any anyDevice = privateInfo;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_PRI_DEVICE_FOUND, 0, 0, anyDevice);
}

void P2pMonitor::Broadcast2SmDeviceLost(const std::string &iface, const WifiP2pDevice &device) const
{
    std::any anyDevice = device;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_DEVICE_LOST, 0, 0, anyDevice);
}

void P2pMonitor::Broadcast2SmGoNegRequest(const std::string &iface, const WifiP2pConfigInternal &config) const
{
    std::any anyConfig = config;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GO_NEG_REQUEST, 0, 0, anyConfig);
}

void P2pMonitor::Broadcast2SmGoNegSuccess(const std::string &iface) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GO_NEG_SUCCESS, 0, 0, anyNone);
}

void P2pMonitor::Broadcast2SmGoNegFailure(const std::string &iface, P2pStatus p2pStatus) const
{
    std::any anyNone;
    MessageToStateMachine(
        iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GO_NEG_FAILURE, static_cast<int>(p2pStatus), 0, anyNone);
}

void P2pMonitor::Broadcast2SmInvitationReceived(const std::string &iface, const WifiP2pGroupInfo &group) const
{
    std::any anyGroup = group;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_INVITATION_RECEIVED, 0, 0, anyGroup);
}

void P2pMonitor::Broadcast2SmInvitationResult(const std::string &iface, P2pStatus p2pStatus) const
{
    std::any anyNone;
    MessageToStateMachine(
        iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_INVITATION_RESULT, static_cast<int>(p2pStatus), 0, anyNone);
}

void P2pMonitor::Broadcast2SmGroupFormationSuccess(const std::string &iface) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_FORMATION_SUCCESS, 0, 0, anyNone);
}

void P2pMonitor::Broadcast2SmGroupFormationFailure(const std::string &iface, const std::string &reason) const
{
    std::any anyReason = reason;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_FORMATION_FAILURE, 0, 0, anyReason);
}

void P2pMonitor::Broadcast2SmGroupStarted(const std::string &iface, const WifiP2pGroupInfo &group) const
{
    std::any anyGroup = group;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_STARTED, 0, 0, anyGroup);
}

void P2pMonitor::Broadcast2SmGroupRemoved(const std::string &iface, const WifiP2pGroupInfo &group) const
{
    std::any anyGroup = group;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_GROUP_REMOVED, 0, 0, anyGroup);
}

void P2pMonitor::Broadcast2SmProvDiscPbcReq(const std::string &iface, const WifiP2pTempDiscEvent &event) const
{
    std::any anyEvent = event;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_PBC_REQ, 0, 0, anyEvent);
}

void P2pMonitor::Broadcast2SmProvDiscPbcResp(const std::string &iface, const WifiP2pTempDiscEvent &event) const
{
    std::any anyEvent = event;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_PBC_RESP, 0, 0, anyEvent);
}

void P2pMonitor::Broadcast2SmProvDiscEnterPin(const std::string &iface, const WifiP2pTempDiscEvent &event) const
{
    std::any anyEvent = event;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_ENTER_PIN, 0, 0, anyEvent);
}

void P2pMonitor::Broadcast2SmProvDiscShowPin(const std::string &iface, const WifiP2pTempDiscEvent &event) const
{
    std::any anyEvent = event;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_SHOW_PIN, 0, 0, anyEvent);
}

void P2pMonitor::Broadcast2SmProvDiscFailure(const std::string &iface) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_FAILURE, 0, 0, anyNone);
}

void P2pMonitor::Broadcast2SmFindStopped(const std::string &iface) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_FIND_STOPPED, 0, 0, anyNone);
}

void P2pMonitor::Broadcast2SmServDiscReq(const std::string &iface, const WifiP2pServiceRequestList &reqList) const
{
    std::any anyReqList = reqList;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_SERV_DISC_REQ, 0, 0, anyReqList);
}

void P2pMonitor::Broadcast2SmServDiscResp(const std::string &iface, const WifiP2pServiceResponseList &respList) const
{
    std::any anyRespList = respList;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_SERV_DISC_RESP, 0, 0, anyRespList);
}

void P2pMonitor::Broadcast2SmApStaDisconnected(const std::string &iface, const WifiP2pDevice &device) const
{
    std::any anyDevice = device;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::AP_STA_DISCONNECTED, 0, 0, anyDevice);
}

void P2pMonitor::Broadcast2SmApStaConnected(const std::string &iface, const WifiP2pDevice &device) const
{
    std::any anyDevice = device;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::AP_STA_CONNECTED, 0, 0, anyDevice);
}

void P2pMonitor::Broadcast2SmConnectSupplicantFailed(const std::string &iface) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::WPA_CONN_FAILED_EVENT, 0, 0, anyNone);
}

void P2pMonitor::Broadcast2SmP2pIfaceCreated(const std::string &iface, int type, const std::string &event) const
{
    std::any anyEvent = event;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_IFACE_CREATED, type, 0, anyEvent);
}

void P2pMonitor::Broadcast2SmConnectFailed(const std::string &iface, int reason, const WifiP2pDevice &device) const
{
    std::any anyDevice = device;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_CONNECT_FAILED, reason, 0, anyDevice);
}

void P2pMonitor::OnConnectSupplicant(int status) const
{
    WIFI_LOGD("OnConnectSupplicant callback");
    Broadcast2SmConnectSupplicant(selectIfacName, status);
}

void P2pMonitor::Broadcast2SmChSwitch(const std::string &iface, const WifiP2pGroupInfo &group) const
{
    std::any anyGroup = group;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_CH_SWITCH, 0, 0, anyGroup);
}

void P2pMonitor::Broadcast2SmChrEvent(const std::string &iface, const int &errCode) const
{
    std::any anyNone;
    MessageToStateMachine(iface, P2P_STATE_MACHINE_CMD::P2P_EVENT_CHR_REPORT, errCode, 0, anyNone);
}

void P2pMonitor::WpaEventDeviceFound(const HalP2pDeviceFound &deviceInfo) const
{
    const int minWfdLength = 6;
    WIFI_LOGI("onDeviceFound callback");
    WifiP2pDevice device;
    device.SetDeviceName(deviceInfo.deviceName);
    if (device.GetDeviceName().empty()) {
        WIFI_LOGE("Missing device name!");
        return;
    }
    device.SetGroupAddress(deviceInfo.srcAddress);
    device.SetDeviceAddress(deviceInfo.p2pDeviceAddress);
    device.SetPrimaryDeviceType(deviceInfo.primaryDeviceType);
    device.SetDeviceCapabilitys(deviceInfo.deviceCapabilities);
    device.SetGroupCapabilitys(deviceInfo.groupCapabilities);
    device.SetWpsConfigMethod(deviceInfo.configMethods);
    device.SetP2pDeviceStatus(P2pDeviceStatus::PDS_AVAILABLE);
    const int wfdInfoTwo = 2;
    const int wfdInfoThree = 3;
    const int wfdInfoFour = 4;
    const int wfdInfoFive = 5;
    if (deviceInfo.wfdDeviceInfo.size() >= minWfdLength) {
        WifiP2pWfdInfo wfdInfo(
            ((deviceInfo.wfdDeviceInfo[0] & 0xFF) << CHAR_BIT) + (deviceInfo.wfdDeviceInfo[1] & 0xFF),
            ((deviceInfo.wfdDeviceInfo[wfdInfoTwo] & 0xFF) << CHAR_BIT) +
                (deviceInfo.wfdDeviceInfo[wfdInfoThree] & 0xFF),
            ((deviceInfo.wfdDeviceInfo[wfdInfoFour] & 0xFF) << CHAR_BIT) +
                (deviceInfo.wfdDeviceInfo[wfdInfoFive] & 0xFF));
        device.SetWfdInfo(wfdInfo);
    }
    if (deviceInfo.wfdDeviceInfo.size() > minWfdLength) {
        std::string p2pDeviceAddress = deviceInfo.p2pDeviceAddress;
        std::string wfdDeviceInfo(reinterpret_cast<const char*>(deviceInfo.wfdDeviceInfo.data()),
            deviceInfo.wfdDeviceInfo.size());
        std::string privateInfo = p2pDeviceAddress + wfdDeviceInfo;
        Broadcast2SmPrivateDeviceFound(selectIfacName, privateInfo);
    }
    Broadcast2SmDeviceFound(selectIfacName, device);
}

void P2pMonitor::WpaEventDeviceLost(const std::string &p2pDeviceAddress) const
{
    WIFI_LOGI("onDeviceLost callback, p2pDeviceAddress:%{private}s", p2pDeviceAddress.c_str());
    WifiP2pDevice device;
    device.SetDeviceAddress(p2pDeviceAddress);
    if (device.GetDeviceAddress().empty()) {
        WIFI_LOGE("ERROR!");
        return;
    }
    device.SetP2pDeviceStatus(P2pDeviceStatus::PDS_UNAVAILABLE);

    Broadcast2SmDeviceLost(selectIfacName, device);
}

void P2pMonitor::WpaEventGoNegRequest(const std::string &srcAddress, short passwordId) const
{
    WIFI_LOGI("WpaEventGoNegRequest srcAddress:%{private}s, passwordId:%{private}hd", srcAddress.c_str(), passwordId);
    WifiP2pConfigInternal config;
    config.SetDeviceAddress(srcAddress);
    if (config.GetDeviceAddress().empty()) {
        WIFI_LOGE("ERROR!");
        return;
    }

    WpsInfo wps;
    switch (static_cast<WpsDevPasswordId>(passwordId)) {
        case WpsDevPasswordId::USER_SPECIFIED: {
            wps.SetWpsMethod(WpsMethod::WPS_METHOD_DISPLAY);
            break;
        }
        case WpsDevPasswordId::PUSHBUTTON: {
            wps.SetWpsMethod(WpsMethod::WPS_METHOD_PBC);
            break;
        }
        case WpsDevPasswordId::REGISTRAR_SPECIFIED: {
            wps.SetWpsMethod(WpsMethod::WPS_METHOD_KEYPAD);
            break;
        }
        default:
            wps.SetWpsMethod(WpsMethod::WPS_METHOD_PBC);
            break;
    }
    config.SetWpsInfo(wps);

    Broadcast2SmGoNegRequest(selectIfacName, config);
}

void P2pMonitor::WpaEventGoNegSuccess(void) const
{
    WIFI_LOGI("onGoNegotiationSuccess callback");
    Broadcast2SmGoNegSuccess(selectIfacName);
}

void P2pMonitor::WpaEventGoNegFailure(int status) const
{
    WIFI_LOGI("onGoNegotiationFailure callback status:%{public}d", status);
    P2pStatus p2pStatus = IntStatusToP2pStatus(status);
    Broadcast2SmGoNegFailure(selectIfacName, p2pStatus);
    P2pChrReporter::GetInstance().ReportErrCodeBeforeGroupFormationSucc(GROUP_OWNER_NEGOTIATION, status,
        P2P_CHR_DEFAULT_REASON_CODE);
}

void P2pMonitor::WpaEventInvitationReceived(const HalP2pInvitationInfo &recvInfo) const
{
    WIFI_LOGI("onInvitationReceived callback");
    WifiP2pGroupInfo group;
    group.SetNetworkId(recvInfo.persistentNetworkId);

    WifiP2pDevice device;
    device.SetDeviceAddress(recvInfo.srcAddress);
    if (device.GetDeviceAddress().empty()) {
        WIFI_LOGE("ERROR! device mac empty!");
        return;
    }
    group.AddClientDevice(device);

    WifiP2pDevice owner;
    if (recvInfo.goDeviceAddress.empty()) {
        owner.SetDeviceAddress(recvInfo.srcAddress);
    } else {
        owner.SetDeviceAddress(recvInfo.goDeviceAddress);
    }
    WIFI_LOGD("owner mac: %{private}s, persistentNetworkId:%{public}d.",
        owner.GetDeviceAddress().c_str(), recvInfo.persistentNetworkId);
    /**
     * If owner addr is empty, a NET ID is required, indicating a persistent group invitation.
     * After receiving the message, the state machine determines the case.
     */
    if (owner.GetDeviceAddress().empty()) {
        WIFI_LOGW("owner mac empty! wpa persistent_reconnect and skip invition msg.");
        return;
    }
    group.SetOwner(owner);

    Broadcast2SmInvitationReceived(selectIfacName, group);
    P2pChrReporter::GetInstance().SetWpsSuccess(true);
}

void P2pMonitor::WpaEventInvitationResult(const std::string &bssid, int status) const
{
    WIFI_LOGI("onInvitationResult callback, bssid:%{public}s, status:%{public}d",
        MacAnonymize(bssid).c_str(), status);
    P2pStatus p2pStatus = IntStatusToP2pStatus(status);
    Broadcast2SmInvitationResult(selectIfacName, p2pStatus);
}

void P2pMonitor::WpaEventGroupFormationSuccess(void) const
{
    WIFI_LOGD("onGroupFormationSuccess callback");
    Broadcast2SmGroupFormationSuccess(selectIfacName);
}

void P2pMonitor::WpaEventGroupFormationFailure(const std::string &failureReason) const
{
    WIFI_LOGD("onGroupFormationFailure callback, failureReason:%{public}s", failureReason.c_str());
    std::string reason(failureReason);
    Broadcast2SmGroupFormationFailure(selectIfacName, reason);
    if (failureReason == "FREQ_CONFLICT") {
        P2pChrReporter::GetInstance().ReportErrCodeBeforeGroupFormationSucc(GROUP_FORMATION,
            static_cast<int>(P2pStatus::NO_COMMON_CHANNELS), P2P_CHR_DEFAULT_REASON_CODE);
    }
}

void P2pMonitor::WpaEventGroupStarted(const HalP2pGroupInfo &groupInfo) const
{
    WIFI_LOGD("onGroupStarted callback");
    if (groupInfo.groupName.empty()) {
        WIFI_LOGE("Missing group interface name.");
        return;
    }

    WifiP2pGroupInfo group;
    group.SetInterface(groupInfo.groupName);
    group.SetGroupName(groupInfo.ssid);
    group.SetFrequency(groupInfo.frequency);
    group.SetIsGroupOwner(groupInfo.isGo);
    if (groupInfo.isGo) {
        group.SetPassphrase(groupInfo.passphrase);
    } else {
        group.SetPassphrase(std::string(groupInfo.psk));
    }
    if (groupInfo.isPersistent && groupInfo.psk.empty()) {
        WIFI_LOGE("groupinfo isPersistent and psk is null");
        group.SetIsPersistent(0);
    } else {
        group.SetIsPersistent(groupInfo.isPersistent);
    }
    WifiP2pDevice owner;
    owner.SetDeviceAddress(groupInfo.goDeviceAddress);
    owner.SetRandomDeviceAddress(groupInfo.goRandomAddress);

    group.SetOwner(owner);
    Broadcast2SmGroupStarted(selectIfacName, group);
}

void P2pMonitor::WpaEventGroupRemoved(const std::string &groupIfName, bool isGo) const
{
    WIFI_LOGD("onGroupRemoved callback, groupIfName:%{private}s, isGo:%{public}s", groupIfName.c_str(),
        (isGo) ? "true" : "false");
    if (groupIfName.empty()) {
        WIFI_LOGE("ERROR! No group name!");
        return;
    }
    WifiP2pGroupInfo group;
    group.SetInterface(groupIfName);
    group.SetIsGroupOwner(isGo);
    Broadcast2SmGroupRemoved(selectIfacName, group);
}

void P2pMonitor::WpaEventProvDiscPbcReq(const std::string &p2pDeviceAddress) const
{
    WIFI_LOGD("onProvisionDiscoveryPbcRequest callback, p2pDeviceAddress:%{private}s", p2pDeviceAddress.c_str());
    WifiP2pTempDiscEvent event;
    WifiP2pDevice tempDevice;
    tempDevice.SetDeviceAddress(p2pDeviceAddress);
    event.SetDevice(tempDevice);
    event.SetDiscEvent(DiscEvent::PBC_REQ);
    Broadcast2SmProvDiscPbcReq(selectIfacName, event);
}

void P2pMonitor::WpaEventProvDiscPbcResp(const std::string &p2pDeviceAddress) const
{
    WIFI_LOGD("onProvisionDiscoveryPbcResponse callback, p2pDeviceAddress:%{private}s", p2pDeviceAddress.c_str());
    WifiP2pTempDiscEvent event;
    WifiP2pDevice tempDevice;
    tempDevice.SetDeviceAddress(p2pDeviceAddress);
    event.SetDevice(tempDevice);
    event.SetDiscEvent(DiscEvent::PBC_RESP);
    Broadcast2SmProvDiscPbcResp(selectIfacName, event);
}

void P2pMonitor::WpaEventProvDiscEnterPin(const std::string &p2pDeviceAddress) const
{
    WIFI_LOGD("onProvisionDiscoveryEnterPin callback, p2pDeviceAddress:%{private}s", p2pDeviceAddress.c_str());
    WifiP2pTempDiscEvent event;
    WifiP2pDevice tempDevice;
    tempDevice.SetDeviceAddress(p2pDeviceAddress);
    event.SetDevice(tempDevice);
    event.SetDiscEvent(DiscEvent::ENTER_PIN);
    Broadcast2SmProvDiscEnterPin(selectIfacName, event);
}

void P2pMonitor::WpaEventProvDiscShowPin(const std::string &p2pDeviceAddress, const std::string &generatedPin) const
{
    WIFI_LOGD("onProvisionDiscoveryShowPin callback, p2pDeviceAddress:%{private}s, generatedPin:%{private}s",
        p2pDeviceAddress.c_str(),
        generatedPin.c_str());
    WifiP2pTempDiscEvent event;
    WifiP2pDevice tempDevice;
    tempDevice.SetDeviceAddress(p2pDeviceAddress);
    event.SetDevice(tempDevice);
    event.SetDiscEvent(DiscEvent::SHOW_PIN);
    event.SetPin(generatedPin);
    Broadcast2SmProvDiscShowPin(selectIfacName, event);
}

void P2pMonitor::WpaEventProvDiscFailure(void) const
{
    WIFI_LOGD("onProvisionDiscoveryFailure callback");
    Broadcast2SmProvDiscFailure(selectIfacName);
}

void P2pMonitor::WpaEventFindStopped(void) const
{
    WIFI_LOGD("onFindStopped callback");
    Broadcast2SmFindStopped(selectIfacName);
}

void P2pMonitor::WpaEventServDiscReq(const HalP2pServDiscReqInfo &reqInfo) const
{
    WIFI_LOGD("OnServDiscReq callback");
    WifiP2pServiceRequestList reqList;
    reqList.SetUpdateIndic(reqInfo.updateIndic);
    reqList.SetFrequency(reqInfo.freq);
    reqList.SetDialogToken(reqInfo.dialogToken);
    WifiP2pDevice device;
    device.SetDeviceAddress(reqInfo.mac);
    reqList.SetDevice(device);
    reqList.ParseTlvs2ReqList(reqInfo.tlvList);
    Broadcast2SmServDiscReq(selectIfacName, reqList);
}

void P2pMonitor::WpaEventServDiscResp(
    const std::string &srcAddress, short updateIndicator, const std::vector<unsigned char> &tlvList) const
{
    WIFI_LOGD("onServiceDiscoveryResponse callback");
    WifiP2pServiceResponseList respList;
    WifiP2pDevice device;
    device.SetDeviceAddress(srcAddress);
    respList.SetDevice(device);
    respList.SetUpdateIndic(updateIndicator);
    respList.ParseTlvs2RespList(tlvList);
    Broadcast2SmServDiscResp(selectIfacName, respList);
}

void P2pMonitor::WpaEventApStaDisconnected(const std::string &p2pDeviceAddress) const
{
    WIFI_LOGD("onStaDeauthorized callback, p2pDeviceAddress:%{private}s", p2pDeviceAddress.c_str());
    WifiP2pDevice device;
    device.SetDeviceAddress(p2pDeviceAddress);
    Broadcast2SmApStaDisconnected(selectIfacName, device);
}

void P2pMonitor::WpaEventApStaConnected(const std::string &p2pDeviceAddress, const std::string &p2pGroupAddress) const
{
    WIFI_LOGD("onStaAuthorized callback, p2pDeviceAddress: %{private}s, p2pGroupAddress: %{private}s",
        p2pDeviceAddress.c_str(), p2pGroupAddress.c_str());
    WifiP2pDevice device;
    device.SetDeviceAddress(p2pDeviceAddress);
    device.SetGroupAddress(p2pGroupAddress);
    device.SetRandomDeviceAddress(p2pGroupAddress);
    Broadcast2SmApStaConnected(selectIfacName, device);
    P2pChrReporter::GetInstance().ReportP2pInterfaceStateChange(static_cast<int>(P2pChrState::GC_CONNECTED),
        P2P_CHR_DEFAULT_REASON_CODE, P2P_CHR_DEFAULT_REASON_CODE);
}

void P2pMonitor::OnConnectSupplicantFailed(void) const
{
    WIFI_LOGD("OnConnectSupplicantFailed callback");
    Broadcast2SmConnectSupplicantFailed(selectIfacName);
}

void P2pMonitor::WpaEventP2pIfaceCreated(const std::string &ifName, int isGo) const
{
    WIFI_LOGI("onP2pIfaceCreated callback, ifname:%{private}s, isGo:%{public}s", ifName.c_str(),
        (isGo == 0) ? "false" : "true");
    if (ifName.empty()) {
        WIFI_LOGE("ERROR! No ifname!");
        return;
    }
    Broadcast2SmP2pIfaceCreated(selectIfacName, isGo, ifName);
}

void P2pMonitor::WpaEventP2pConnectFailed(const std::string &bssid, int reason) const
{
    WIFI_LOGD("WpaEventP2pConnectFailed callback, bssid:%{public}s, reason:%{public}d",
        MacAnonymize(bssid).c_str(), reason);
    WifiP2pDevice device;
    device.SetDeviceAddress(bssid);
    Broadcast2SmConnectFailed(selectIfacName, reason, device);
}

void P2pMonitor::WpaEventP2pChannelSwitch(int freq) const
{
    WIFI_LOGI("WpaEventP2pChannelSwitch callback, freq:%{public}d", freq);
    WifiP2pGroupInfo group;
    group.SetFrequency(freq);
    Broadcast2SmChSwitch(selectIfacName, group);
}

void P2pMonitor::WpaEventP2pChrReport(int errCode) const
{
    WIFI_LOGI("WpaEventP2pChrReport callback, errCode:%{public}d", errCode);
    Broadcast2SmChrEvent(selectIfacName, errCode);
}

void P2pMonitor::WpaEventStaNotifyCallBack(const std::string &notifyParam) const
{
    WIFI_LOGI("WpaEventStaNotifyCallBack callback, notifyParam:%{private}s", notifyParam.c_str());
    if (notifyParam.empty()) {
        WIFI_LOGE("WpaEventStaNotifyCallBack() notifyParam is empty");
        return;
    }
    std::string::size_type begPos = 0;
    if ((begPos = notifyParam.find(":")) == std::string::npos) {
        WIFI_LOGI("WpaEventStaNotifyCallBack() notifyParam not find :");
        return;
    }
    std::string type = notifyParam.substr(0, begPos);
    int num = CheckDataLegal(type);
    switch (num) {
        case static_cast<int>(WpaEventCallback::CSA_CHSWITCH_NUM): {
            std::string::size_type freqPos = 0;
            if ((freqPos = notifyParam.find("freq=")) == std::string::npos) {
                WIFI_LOGE("csa channel switch notifyParam not find frequency!");
                return;
            }
            std::string data = notifyParam.substr(freqPos + strlen("freq="));
            int freq = CheckDataLegal(data);
            WpaEventP2pChannelSwitch(freq);
            break;
        }
        case static_cast<int>(WpaEventCallback::CHR_EVENT_NUM): {
            std::string::size_type codePos = 0;
            if ((codePos = notifyParam.find("errCode=")) != std::string::npos) {
                std::string data = notifyParam.substr(codePos + strlen("errCode="));
                int errCode = stoi(data);
                WpaEventP2pChrReport(errCode);
            } else {
                P2pChrReporter::GetInstance().ProcessChrEvent(notifyParam.substr(begPos + 1));
            }
            break;
        }
        default:
            WIFI_LOGI("WpaEventStaNotifyCallBack() undefine event:%{public}d", num);
            break;
    }
}
}  // namespace Wifi
}  // namespace OHOS
