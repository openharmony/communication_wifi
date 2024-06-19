/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#include "self_cure_state_machine.h"
#include <vector>
#include <string>
#include "wifi_cmd_client.h"
#include "wifi_logger.h"
#include "mac_address.h"
#include "event_runner.h"
#include "wifi_sta_hal_interface.h"
#include "network_status_history_manager.h"
#include "wifi_hisysevent.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
const std::string CLASS_NAME = "WifiSelfCure";

DEFINE_WIFILOG_LABEL("SelfCureStateMachine");

const int WIFI6_SINGLE_ITEM_BYTE_LEN = 8;
const int WIFI6_SINGLE_MAC_LEN = 6;
const int HEXADECIMAL = 16;
const int WIFI6_MAX_BLA_LIST_NUM = 16;

SelfCureStateMachine::SelfCureStateMachine(int instId)
    : StateMachine("SelfCureStateMachine"),
      pDefaultState(nullptr),
      pConnectedMonitorState(nullptr),
      pDisconnectedMonitorState(nullptr),
      pConnectionSelfCureState(nullptr),
      pInternetSelfCureState(nullptr),
      pWifi6SelfCureState(nullptr),
      m_instId(instId)
{
}

SelfCureStateMachine::~SelfCureStateMachine()
{
    WIFI_LOGD("~SelfCureStateMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pConnectedMonitorState);
    ParsePointer(pDisconnectedMonitorState);
    ParsePointer(pConnectionSelfCureState);
    ParsePointer(pInternetSelfCureState);
    ParsePointer(pWifi6SelfCureState);
}

void SelfCureStateMachine::BuildStateTree()
{
    StatePlus(pDefaultState, nullptr);
    StatePlus(pConnectedMonitorState, pDefaultState);
    StatePlus(pDisconnectedMonitorState, pDefaultState);
    StatePlus(pConnectionSelfCureState, pDefaultState);
    StatePlus(pInternetSelfCureState, pDefaultState);
    StatePlus(pWifi6SelfCureState, pDefaultState);
}

ErrCode SelfCureStateMachine::InitSelfCureStates()
{
    WIFI_LOGD("Enter InitSelfCureStates\n");
    int tmpErrNumber;
    pDefaultState = new (std::nothrow)DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState);
    pConnectedMonitorState = new (std::nothrow)ConnectedMonitorState(this);
    tmpErrNumber += JudgmentEmpty(pConnectedMonitorState);
    pDisconnectedMonitorState = new (std::nothrow)DisconnectedMonitorState(this);
    tmpErrNumber += JudgmentEmpty(pDisconnectedMonitorState);
    pConnectionSelfCureState = new (std::nothrow)ConnectionSelfCureState(this);
    tmpErrNumber += JudgmentEmpty(pConnectionSelfCureState);
    pInternetSelfCureState = new (std::nothrow)InternetSelfCureState(this);
    tmpErrNumber += JudgmentEmpty(pInternetSelfCureState);
    pWifi6SelfCureState = new (std::nothrow)Wifi6SelfCureState(this);
    tmpErrNumber += JudgmentEmpty(pWifi6SelfCureState);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitSelfCureStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode SelfCureStateMachine::Initialize()
{
    if (!InitialStateMachine("SelfCureStateMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (InitSelfCureStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pDisconnectedMonitorState);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

/* --------------------------- state machine default state ------------------------------ */
SelfCureStateMachine::DefaultState::DefaultState(SelfCureStateMachine *selfCureStateMachine)
    : State("DefaultState"),
      pSelfCureStateMachine(selfCureStateMachine)
{
    WIFI_LOGD("DefaultState construct success\n.");
}

SelfCureStateMachine::DefaultState::~DefaultState() {}

void SelfCureStateMachine::DefaultState::GoInState()
{
    pSelfCureStateMachine->selfCureOnGoing = false;
    WIFI_LOGI("DefaultState GoInState function.");
}

void SelfCureStateMachine::DefaultState::GoOutState()
{
    WIFI_LOGI("DefaultState GoOutState function.");
    return;
}

bool SelfCureStateMachine::DefaultState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case 0: {
            ret = EXECUTED;
            break;
        }
        default:
            WIFI_LOGD("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine connected monitor state ------------------------------ */
SelfCureStateMachine::ConnectedMonitorState::ConnectedMonitorState(SelfCureStateMachine *selfCureStateMachine)
    : State("ConnectedMonitorState"),
      pSelfCureStateMachine(selfCureStateMachine)
{
    InitSelfCureCmsHandleMap();
    WIFI_LOGD("ConnectedMonitorState construct success\n.");
}

SelfCureStateMachine::ConnectedMonitorState::~ConnectedMonitorState() {}

void SelfCureStateMachine::ConnectedMonitorState::GoInState()
{
    WIFI_LOGI("ConnectedMonitorState GoInState function.");
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    lastConnectedBssid = linkedInfo.bssid;
    pSelfCureStateMachine->arpDetectionFailedCnt = 0;
    hasInternetRecently = false;
    portalUnthenEver = false;
    pSelfCureStateMachine->internetUnknown = false;
    userSetStaticIpConfig = false;
    pSelfCureStateMachine->selfCureOnGoing = false;
    ipv4DnsEnabled = true;
    wifiSwitchAllowed = false;
    mobileHotspot = linkedInfo.isDataRestricted == 1 ? true : false;
    lastSignalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.frequency);
    if (!SetupSelfCureMonitor()) {
        WIFI_LOGI("ConnectedMonitorState, config is null when connected broadcast received, delay to setup again.");
        pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR,
                                                    SELF_CURE_MONITOR_DELAYED_MS);
    }
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, FAST_ARP_DETECTED_MS);
    return;
}

void SelfCureStateMachine::ConnectedMonitorState::GoOutState()
{
    WIFI_LOGI("ConnectedMonitorState GoOutState function.");
    return;
}

bool SelfCureStateMachine::ConnectedMonitorState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("ConnectedMonitorState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    auto iter = selfCureCmsHandleFuncMap.find(msg->GetMessageName());
    if (iter != selfCureCmsHandleFuncMap.end()) {
        (this->*(iter->second))(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

int SelfCureStateMachine::ConnectedMonitorState::InitSelfCureCmsHandleMap()
{
    selfCureCmsHandleFuncMap[WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleResetupSelfCure;
    selfCureCmsHandleFuncMap[WIFI_CURE_CMD_PERIODIC_ARP_DETECTED] =
    &SelfCureStateMachine::ConnectedMonitorState::HandlePeriodicArpDetection;
    selfCureCmsHandleFuncMap[WIFI_CURE_CMD_ARP_FAILED_DETECTED] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleArpDetectionFailed;
    selfCureCmsHandleFuncMap[WIFI_CURE_CMD_INVALID_IP_CONFIRM] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleInvalidIp;
    selfCureCmsHandleFuncMap[WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleNetworkConnect;
    selfCureCmsHandleFuncMap[WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleNetworkDisconnect;
    selfCureCmsHandleFuncMap[WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleRssiLevelChange;
    selfCureCmsHandleFuncMap[WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED] =
    &SelfCureStateMachine::ConnectedMonitorState::HandleInternetFailedDetected;
    return WIFI_OPT_SUCCESS;
}

void SelfCureStateMachine::ConnectedMonitorState::TransitionToSelfCureState(int reason)
{
    if (mobileHotspot && reason != WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING) {
        WIFI_LOGI("transitionToSelfCureState, don't support SCE, do nothing or mobileHotspot = %{public}d.",
                  mobileHotspot);
        pSelfCureStateMachine->selfCureOnGoing = false;
        return;
    }
    WIFI_LOGI("transitionToSelfCureState, reason is : %{public}d.", reason);
    IpInfo wifiIpInfo;
    WifiSettings::GetInstance().GetIpInfo(wifiIpInfo, pSelfCureStateMachine->m_instId);
    IpV6Info wifiIpv6Info;
    WifiSettings::GetInstance().GetIpv6Info(wifiIpv6Info, pSelfCureStateMachine->m_instId);
    ipv4DnsEnabled = wifiIpInfo.primaryDns != 0 || wifiIpInfo.secondDns != 0;
    gatewayInvalid = wifiIpInfo.gateway == 0 && wifiIpv6Info.gateway == "";
    if (!ipv4DnsEnabled || gatewayInvalid) {
        WIFI_LOGI("transitionToSelfCureState, don't support SCE, do nothing or ipv4DnsEnabled = %{public}d.",
                  ipv4DnsEnabled);
        pSelfCureStateMachine->selfCureOnGoing = false;
        return;
    }
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, reason, SELF_CURE_DELAYED_MS);
    pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pInternetSelfCureState);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleResetupSelfCure(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleResetupSelfCure.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    SetupSelfCureMonitor();
    return;
}

void SelfCureStateMachine::ConnectedMonitorState::HandlePeriodicArpDetection(InternalMessage *msg)
{
    WIFI_LOGD("enter HandlePeriodicArpDetection.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine->PeriodicArpDetection();
    return;
}

void SelfCureStateMachine::ConnectedMonitorState::HandleNetworkConnect(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleNetworkConnect.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    GoInState();
    return;
}

void SelfCureStateMachine::ConnectedMonitorState::HandleNetworkDisconnect(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleNetworkDisconnect.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT);
    pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR);
    pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pDisconnectedMonitorState);
    return;
}

void SelfCureStateMachine::ConnectedMonitorState::HandleRssiLevelChange(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleRssiLevelChange.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    lastSignalLevel = pSelfCureStateMachine->GetCurSignalLevel();
    return;
}

void SelfCureStateMachine::ConnectedMonitorState::HandleArpDetectionFailed(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleArpDetectionFailed.");
    if (pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, lastConnectedBssid)) {
        return;
    }
    if (pSelfCureStateMachine->IsHttpReachable()) {
        WIFI_LOGI("Http Reachable.");
        pSelfCureStateMachine->selfCureOnGoing = false;
        return;
    }
    pSelfCureStateMachine->selfCureOnGoing = true;
    pSelfCureStateMachine->selfCureReason = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
    TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_TCP);
}

bool SelfCureStateMachine::ConnectedMonitorState::SetupSelfCureMonitor()
{
    configAuthType = pSelfCureStateMachine->GetAuthType();
    AssignIpMethod ipAssignment;
    pSelfCureStateMachine->GetIpAssignment(ipAssignment);
    userSetStaticIpConfig = ipAssignment == AssignIpMethod::STATIC;
    pSelfCureStateMachine->internetUnknown = NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(
        pSelfCureStateMachine->GetNetworkStatusHistory());
    hasInternetRecently = NetworkStatusHistoryManager::IsInternetAccessByHistory(
        pSelfCureStateMachine->GetNetworkStatusHistory());
    portalUnthenEver = NetworkStatusHistoryManager::IsPortalByHistory(
        pSelfCureStateMachine->GetNetworkStatusHistory());
    if (!mobileHotspot) {
        if ((!pSelfCureStateMachine->staticIpCureSuccess) &&
            (hasInternetRecently || pSelfCureStateMachine->internetUnknown) &&
            (pSelfCureStateMachine->IsIpAddressInvalid())) {
            pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INVALID_IP_CONFIRM, SELF_CURE_MONITOR_DELAYED_MS);
            return true;
        }
    }
    /** setup dns failed monitor when connected (the router's dns server maybe disabled). */
    if ((!mobileHotspot) && (!pSelfCureStateMachine->staticIpCureSuccess) && hasInternetRecently) {
        pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_DNS_FAILED_MONITOR, INTERNET_DETECT_INTERVAL_MS);
        return true;
    }
    return false;
}

void SelfCureStateMachine::ConnectedMonitorState::RequestReassocWithFactoryMac()
{
    pSelfCureStateMachine->useWithRandMacAddress = FAC_MAC_REASSOC;
    pSelfCureStateMachine->selfCureReason = WIFI_CURE_INTERNET_FAILED_RAND_MAC;
    TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_RAND_MAC);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleInvalidIp(InternalMessage *msg)
{
    pSelfCureStateMachine->selfCureOnGoing = true;
    if (pSelfCureStateMachine->IsHttpReachable()) {
        pSelfCureStateMachine->selfCureOnGoing = false;
        pSelfCureStateMachine->noTcpRxCounter = 0;
    } else {
        int selfCureType = (pSelfCureStateMachine->dhcpOfferPackets.size() >= 2) ?
                            WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY :
                            WIFI_CURE_INTERNET_FAILED_INVALID_IP;
        pSelfCureStateMachine->selfCureReason = selfCureType;
        TransitionToSelfCureState(selfCureType);
    }
}

void SelfCureStateMachine::ConnectedMonitorState::HandleInternetFailedDetected(InternalMessage *msg)
{
    WIFI_LOGI("HandleInternetFailedDetected, wifi has no internet when connected.");
    if (mobileHotspot && !pSelfCureStateMachine->IsWifi6Network(lastConnectedBssid)) {
        WIFI_LOGI("don't support selfcure, do nothing, mobileHotspot = %{public}d", mobileHotspot);
        return;
    }
    if (pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, lastConnectedBssid)) {
        WIFI_LOGI("%{public}s: TransToWifi6SelfCure", __FUNCTION__);
        return;
    }
    if (pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac()) {
        RequestReassocWithFactoryMac();
        return;
    }
    if (!pSelfCureStateMachine->staticIpCureSuccess && pSelfCureStateMachine->internetUnknown) {
        if (hasInternetRecently || portalUnthenEver) {
            pSelfCureStateMachine->selfCureReason = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
            TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_DNS);
        } else if (pSelfCureStateMachine->IfMultiGateway()) {
            pSelfCureStateMachine->selfCureReason = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
            TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_TCP);
        } else {
            WIFI_LOGI("HandleInternetFailedDetected, there is not a expectant condition!.");
        }
        return;
    }
    pSelfCureStateMachine->selfCureOnGoing = true;
    if (pSelfCureStateMachine->IsHttpReachable()) {
        pSelfCureStateMachine->selfCureOnGoing = false;
        pSelfCureStateMachine->noTcpRxCounter = 0;
        return;
    } else {
        pSelfCureStateMachine->selfCureReason = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
    }
    WIFI_LOGI("HandleInternetFailedDetected, http unreachable, transition to SelfCureState,"
        "selfCureReason: %{public}d", pSelfCureStateMachine->selfCureReason);
    TransitionToSelfCureState(pSelfCureStateMachine->selfCureReason);
}

/* --------------------------- state machine disconnect monitor state ------------------------------ */
SelfCureStateMachine::DisconnectedMonitorState::DisconnectedMonitorState(SelfCureStateMachine *selfCureStateMachine)
    : State("DisconnectedMonitorState"),
      pSelfCureStateMachine(selfCureStateMachine)
{
    WIFI_LOGD("DisconnectedMonitorState construct success\n.");
}

SelfCureStateMachine::DisconnectedMonitorState::~DisconnectedMonitorState() {}

void SelfCureStateMachine::DisconnectedMonitorState::GoInState()
{
    WIFI_LOGI("DisconnectedMonitorState GoInState function.");
    setStaticIpConfig = false;
    pSelfCureStateMachine->staticIpCureSuccess = false;
    pSelfCureStateMachine->isWifi6ArpSuccess = false;
    pSelfCureStateMachine->hasTestWifi6Reassoc = false;
    pSelfCureStateMachine->noAutoConnCounter = 0;
    pSelfCureStateMachine->noAutoConnReason = -1;
    pSelfCureStateMachine->selfCureOnGoing = false;
    pSelfCureStateMachine->connectedTimeMills = 0;
    pSelfCureStateMachine->dhcpOfferPackets.clear();
    pSelfCureStateMachine->useWithRandMacAddress = 0;
    return;
}

void SelfCureStateMachine::DisconnectedMonitorState::GoOutState()
{
    WIFI_LOGI("DisconnectedMonitorState GoOutState function.");
    return;
}

bool SelfCureStateMachine::DisconnectedMonitorState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("DisconnectedMonitorState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD: {
            ret = EXECUTED;
            pSelfCureStateMachine->HandleNetworkConnected();
            break;
        }
        default:
            WIFI_LOGD("DisconnectedMonitorState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine connection self cure state ------------------------------ */
SelfCureStateMachine::ConnectionSelfCureState::ConnectionSelfCureState(SelfCureStateMachine *selfCureStateMachine)
    : State("ConnectionSelfCureState"),
      pSelfCureStateMachine(selfCureStateMachine)
{
    WIFI_LOGD("ConnectionSelfCureState construct success\n.");
}

SelfCureStateMachine::ConnectionSelfCureState::~ConnectionSelfCureState() {}

void SelfCureStateMachine::ConnectionSelfCureState::GoInState()
{
    WIFI_LOGI("ConnectionSelfCureState GoInState function.");
    return;
}

void SelfCureStateMachine::ConnectionSelfCureState::GoOutState()
{
    WIFI_LOGI("ConnectionSelfCureState GoOutState function.");
    return;
}

bool SelfCureStateMachine::ConnectionSelfCureState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("ConnectionSelfCureState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case 0: {
            ret = EXECUTED;
            pSelfCureStateMachine->GetAuthType();
            break;
        }
        default:
            WIFI_LOGD("ConnectionSelfCureState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine internet self cure state ------------------------------ */
SelfCureStateMachine::InternetSelfCureState::InternetSelfCureState(SelfCureStateMachine *selfCureStateMachine)
    : State("InternetSelfCureState"),
      pSelfCureStateMachine(selfCureStateMachine)
{
    InitSelfCureIssHandleMap();
    WIFI_LOGD("InternetSelfCureState construct success\n.");
}

SelfCureStateMachine::InternetSelfCureState::~InternetSelfCureState() {}

void SelfCureStateMachine::InternetSelfCureState::GoInState()
{
    WIFI_LOGI("InternetSelfCureState GoInState function.");
    currentRssi = CURRENT_RSSI_INIT;
    selfCureFailedCounter = 0;
    currentAbnormalType = -1;
    lastSelfCureLevel = -1;
    currentSelfCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
    hasInternetRecently = false;
    portalUnthenEver = false;
    userSetStaticIpConfig = false;
    currentGateway = pSelfCureStateMachine->GetCurrentGateway();
    testedSelfCureLevel.clear();
    finalSelfCureUsed = false;
    delayedReassocSelfCure = false;
    delayedRandMacReassocSelfCure = false;
    delayedResetSelfCure = false;
    setStaticIp4InvalidIp = false;
    unConflictedIp = "";
    renewDhcpCount = 0;
    lastMultiGwSelfFailedType = -1;
    usedMultiGwSelfcure = false;

    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    currentRssi = linkedInfo.rssi;
    currentBssid = linkedInfo.bssid;
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, DEFAULT_ARP_DETECTED_MS);
    pSelfCureStateMachine->String2InternetSelfCureHistoryInfo(pSelfCureStateMachine->GetSelfCureHistoryInfo(),
                                                              selfCureHistoryInfo);
    hasInternetRecently = NetworkStatusHistoryManager::IsInternetAccessByHistory(
        pSelfCureStateMachine->GetNetworkStatusHistory());
    portalUnthenEver = NetworkStatusHistoryManager::IsPortalByHistory(
        pSelfCureStateMachine->GetNetworkStatusHistory());
    AssignIpMethod ipAssignment;
    pSelfCureStateMachine->GetIpAssignment(ipAssignment);
    userSetStaticIpConfig = ipAssignment == AssignIpMethod::STATIC;
    lastHasInetTimeMillis = pSelfCureStateMachine->GetLastHasInternetTime();
    configAuthType = pSelfCureStateMachine->GetAuthType();
    return;
}

void SelfCureStateMachine::InternetSelfCureState::GoOutState()
{
    WIFI_LOGD("InternetSelfCureState GoOutState function.");
    return;
}

bool SelfCureStateMachine::InternetSelfCureState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("InternetSelfCureState-msgCode = %{public}d is received.\n", msg->GetMessageName());
    auto iter = selfCureIssHandleFuncMap.find(msg->GetMessageName());
    if (iter != selfCureIssHandleFuncMap.end()) {
        (this->*(iter->second))(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

int SelfCureStateMachine::InternetSelfCureState::InitSelfCureIssHandleMap()
{
    selfCureIssHandleFuncMap[WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE] =
    &SelfCureStateMachine::InternetSelfCureState::HandleInternetFailedSelfCure;
    selfCureIssHandleFuncMap[WIFI_CURE_CMD_SELF_CURE_WIFI_LINK] =
    &SelfCureStateMachine::InternetSelfCureState::HandleSelfCureWifiLink;
    selfCureIssHandleFuncMap[WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD] =
    &SelfCureStateMachine::InternetSelfCureState::HandleNetworkDisconnected;
    selfCureIssHandleFuncMap[WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM] =
    &SelfCureStateMachine::InternetSelfCureState::HandleInternetRecovery;
    selfCureIssHandleFuncMap[WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT] =
    &SelfCureStateMachine::InternetSelfCureState::HandleRssiChangedEvent;
    selfCureIssHandleFuncMap[WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT] =
    &SelfCureStateMachine::InternetSelfCureState::HandleP2pDisconnected;
    selfCureIssHandleFuncMap[WIFI_CURE_CMD_PERIODIC_ARP_DETECTED] =
    &SelfCureStateMachine::InternetSelfCureState::HandlePeriodicArpDetecte;
    selfCureIssHandleFuncMap[WIFI_CURE_CMD_ARP_FAILED_DETECTED] =
    &SelfCureStateMachine::InternetSelfCureState::HandleArpFailedDetected;
    return WIFI_OPT_SUCCESS;
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetFailedSelfCure(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleInternetFailedSelfCure.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine->selfCureOnGoing = false;
    if (pSelfCureStateMachine->IsSuppOnCompletedState()) {
        SelectSelfCureByFailedReason(msg->GetParam1());
    }
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleSelfCureWifiLink(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleSelfCureWifiLink.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    if (pSelfCureStateMachine->IsSuppOnCompletedState()) {
        currentSelfCureLevel = msg->GetParam1();
        SelfCureWifiLink(msg->GetParam1());
    }
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleNetworkDisconnected(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleNetworkDisconnected.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM);
    pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pDisconnectedMonitorState);
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetRecovery(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleInternetRecovery.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    if (pSelfCureStateMachine->selfCureOnGoing) {
        HandleInternetRecoveryConfirm();
    }
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleRssiChangedEvent(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleRssiChangedEvent.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    currentRssi = msg->GetParam1();
    HandleRssiChanged();
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleP2pDisconnected(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleP2pDisconnected.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    HandleRssiChanged();
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandlePeriodicArpDetecte(InternalMessage *msg)
{
    WIFI_LOGD("enter HandlePeriodicArpDetecte.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine->PeriodicArpDetection();
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleArpFailedDetected(InternalMessage *msg)
{
    WIFI_LOGD("enter HandleArpFailedDetected.");
    if (pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, currentBssid)) {
        return;
    }
    if (pSelfCureStateMachine->selfCureOnGoing) {
        return;
    }
    pSelfCureStateMachine->selfCureOnGoing = true;
    if (pSelfCureStateMachine->IsHttpReachable()) {
        WIFI_LOGI("Http Reachable.");
        pSelfCureStateMachine->selfCureOnGoing = false;
    } else {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC);
    }
}

void SelfCureStateMachine::InternetSelfCureState::SelectSelfCureByFailedReason(int internetFailedType)
{
    WIFI_LOGI("SelectSelfCureByFailedReason, internetFailedType = %{public}d, userSetStaticIpConfig = %{public}d",
              internetFailedType, userSetStaticIpConfig);
    if (userSetStaticIpConfig && ((internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS) ||
                                  (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY) ||
                                  (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING))) {
        HandleInternetFailedAndUserSetStaticIp(internetFailedType);
        return;
    }
    int requestSelfCureLevel = SelectBestSelfCureSolution(internetFailedType);
    if (requestSelfCureLevel != WIFI_CURE_RESET_LEVEL_IDLE) {
        currentAbnormalType = internetFailedType;
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, requestSelfCureLevel);
        return;
    }
    if (pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        WIFI_LOGI("SelectSelfCureByFailedReason, use wifi reset to cure this failed type = %{public}d",
                  internetFailedType);
        currentAbnormalType = internetFailedType;
        if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS) {
            lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
        } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING) {
            lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
        } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_TCP) {
            lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        }
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_HIGH_RESET);
        return;
    }
    WIFI_LOGI("SelectSelfCureByFailedReason, no usable self cure for this failed type = %{public}d",
              internetFailedType);
    HandleHttpUnreachableFinally();
}

int SelfCureStateMachine::InternetSelfCureState::SelectBestSelfCureSolution(int internetFailedType)
{
    int bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
    bool multipleDhcpServer = pSelfCureStateMachine->dhcpOfferPackets.size() >= 2;
    bool noInternetWhenConnected =
        (lastHasInetTimeMillis <= 0 || lastHasInetTimeMillis < pSelfCureStateMachine->connectedTimeMills);
    WIFI_LOGD("SelectBestSelfCureSolution, multipleDhcpServer = %{public}d, noInternetWhenConnected = %{public}d",
              multipleDhcpServer, noInternetWhenConnected);
    if (internetFailedType == WIFI_CURE_INTERNET_FAILED_INVALID_IP) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING &&
               pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS &&
               pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_LOW_1_DNS)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_RAND_MAC &&
               pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_TCP &&
               pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    }
    WIFI_LOGD("SelectBestSelfCureSolution, internetFailedType = %{public}d, bestSelfCureLevel = %{public}d",
              internetFailedType, bestSelfCureLevel);
    return bestSelfCureLevel;
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureWifiLink(int requestCureLevel)
{
    WIFI_LOGI("SelfCureWifiLink, requestCureLevel = %{public}d, currentRssi = %{public}d",
              requestCureLevel, currentRssi);
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_1_DNS) {
        WIFI_LOGI("SelfCureForDns");
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP) {
        SelfCureForRenewDhcp(requestCureLevel);
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP) {
        SelfCureForInvalidIp();
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        SelfCureForReassoc(requestCureLevel);
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        SelfCureForRandMacReassoc();
    }
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForRenewDhcp(int requestCureLevel)
{
    WIFI_LOGI("begin to self cure for internet access: RenewDhcp");
    pSelfCureStateMachine->dhcpOfferPackets.clear();
    pSelfCureStateMachine->dhcpResultsTestDone.clear();
    pSelfCureStateMachine->selfCureOnGoing = true;
    testedSelfCureLevel.push_back(requestCureLevel);
    renewDhcpCount += 1;
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Get pStaService failed!");
        return;
    }
    if (pStaService->RenewDhcp()!=WIFI_OPT_SUCCESS) {
        WIFI_LOGE("RenewDhcp failed.\n");
    }
    pSelfCureStateMachine->StartTimer(WIFI_CURE_CMD_IP_CONFIG_TIMEOUT, DHCP_RENEW_TIMEOUT_MS);
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForInvalidIp()
{
    WIFI_LOGI("begin to self cure for internet access: InvalidIp");
    IpInfo dhcpResults;
    pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
    unConflictedIp = IpTools::ConvertIpv4Address(dhcpResults.ipAddress);
    if (selfCureForInvalidIpCnt < MAX_SELF_CURE_CNT_INVALID_IP) {
        IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
        if (pStaService == nullptr) {
            WIFI_LOGE("Get pStaService failed!");
            return;
        }
        if (pStaService->Disconnect()!=WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Disconnect failed.\n");
        }
        selfCureForInvalidIpCnt++;
    }
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForReassoc(int requestCureLevel)
{
    if ((currentRssi < MIN_VAL_LEVEL_3) || pSelfCureStateMachine->IfP2pConnected()) {
        WIFI_LOGI("delayedReassocSelfCure.");
        delayedReassocSelfCure = true;
        return;
    }
    WIFI_LOGI("begin to self cure for internet access: Reassoc");
    pSelfCureStateMachine->selfCureOnGoing = true;
    testedSelfCureLevel.push_back(requestCureLevel);
    delayedReassocSelfCure = false;
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Get pStaService failed!");
        return;
    }
    if (pStaService->ReAssociate() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ReAssociate failed.\n");
    }
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM, INTERNET_RECOVERY_TIME);
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForRandMacReassoc()
{
    if ((currentRssi < MIN_VAL_LEVEL_3) || pSelfCureStateMachine->IfP2pConnected()) {
        pSelfCureStateMachine->selfCureOnGoing = false;
        delayedReassocSelfCure = true;
        return;
    }
    WIFI_LOGI("begin to self cure for internet access: RandMacReassoc");
    pSelfCureStateMachine->selfCureOnGoing = true;
    delayedReassocSelfCure = false;
    pSelfCureStateMachine->useWithRandMacAddress = FAC_MAC_REASSOC;
    pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(FAC_MAC_REASSOC);
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Get pStaService failed!");
        return;
    }
    if (pStaService->ConnectToNetwork(networkId) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ConnectToNetwork failed.\n");
    }
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM, INTERNET_RECOVERY_TIME);
}

bool SelfCureStateMachine::InternetSelfCureState::SelectedSelfCureAcceptable()
{
    if (currentAbnormalType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS ||
        currentAbnormalType == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY) {
        lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
        if (pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_LOW_1_DNS)) {
            WIFI_LOGD("HTTP unreachable, use dns replace to cure for dns failed.");
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_LOW_1_DNS, 0);
            return true;
        }
    } else if (currentAbnormalType == WIFI_CURE_INTERNET_FAILED_TYPE_TCP) {
        lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        if (pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC)) {
            WIFI_LOGD("HTTP unreachable, use reassoc to cure for no rx pkt.");
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC,
                                               0);
            return true;
        }
    }
    return false;
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetFailedAndUserSetStaticIp(int internetFailedType)
{
    if (hasInternetRecently &&
        pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS) {
            lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
        } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING) {
            lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
        } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY) {
            lastSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        }
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_HIGH_RESET);
        return;
    }
    WIFI_LOGI("user set static ip config, ignore to update config for user.");
    if (!pSelfCureStateMachine->internetUnknown) {
        currentAbnormalType = WIFI_CURE_RESET_REJECTED_BY_STATIC_IP_ENABLED;
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleIpConfigTimeout()
{
    WIFI_LOGI("during self cure state. currentAbnormalType = %{public}d", currentAbnormalType);
    pSelfCureStateMachine->selfCureOnGoing = false;
    isRenewDhcpTimeout = true;
    std::vector<WifiScanInfo> scanResults;
    WifiSettings::GetInstance().GetScanInfoList(scanResults);
    if (currentAbnormalType == WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING &&
        pSelfCureStateMachine->IsEncryptedAuthType(configAuthType) &&
        pSelfCureStateMachine->GetBssidCounter(scanResults) <= DEAUTH_BSSID_CNT && !finalSelfCureUsed) {
        finalSelfCureUsed = true;
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_DEAUTH_BSSID);
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleIpConfigCompleted()
{
    WIFI_LOGI("msg removed because of ip config success.");
    pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_IP_CONFIG_TIMEOUT);
    isRenewDhcpTimeout = false;
    HandleIpConfigCompletedAfterRenewDhcp();
    if (isRenewDhcpTimeout) {
        HandleIpConfigCompletedAfterRenewDhcp();
    }
    WIFI_LOGI("msg removed because of rcv other dhcp offer.");
    pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_INVALID_DHCP_OFFER_EVENT);
}

void SelfCureStateMachine::InternetSelfCureState::HandleIpConfigCompletedAfterRenewDhcp()
{
    currentGateway = pSelfCureStateMachine->GetCurrentGateway();
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM, IP_CONFIG_CONFIRM_DELAYED_MS);
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetRecoveryConfirm()
{
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(selfCureHistoryInfo, currentSelfCureLevel, true);
    bool success = ConfirmInternetSelfCure(currentSelfCureLevel);
    if (success) {
        currentSelfCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
        selfCureFailedCounter = 0;
        hasInternetRecently = true;
    }
}

bool SelfCureStateMachine::InternetSelfCureState::ConfirmInternetSelfCure(int currentCureLevel)
{
    int curCureLevel = currentCureLevel;
    WIFI_LOGI("ConfirmInternetSelfCure, cureLevel = %{public}d ,last failed counter = %{public}d,"
              "finally = %{public}d",
              curCureLevel, selfCureFailedCounter, finalSelfCureUsed);
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_IDLE) {
        return false;
    }
    if (pSelfCureStateMachine->IsHttpReachable()) {
        if (currentCureLevel == WIFI_CURE_RESET_LEVEL_LOW_1_DNS && pSelfCureStateMachine->internetUnknown) {
            WIFI_LOGI("RequestUpdateDnsServers");
        }
        if (currentCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC &&
            pSelfCureStateMachine->useWithRandMacAddress == FAC_MAC_REASSOC &&
            pSelfCureStateMachine->IsUseFactoryMac()) {
            pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(FAC_MAC_REASSOC);
        }
        HandleHttpReachableAfterSelfCure(currentCureLevel);
        pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pConnectedMonitorState);
        return true;
    }
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC && pSelfCureStateMachine->internetUnknown) {
        HandleSelfCureFailedForRandMacReassoc();
        return false;
    }
    selfCureFailedCounter++;
    pSelfCureStateMachine->UpdateSelfCureHistoryInfo(selfCureHistoryInfo, currentCureLevel, false);
    pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistoryInfo.GetSelfCureHistory());
    WIFI_LOGI("HTTP unreachable, self cure failed for %{public}d, selfCureHistoryInfo = %{public}s", currentCureLevel,
              pSelfCureStateMachine->GetSelfCureHistoryInfo().c_str());
    pSelfCureStateMachine->selfCureOnGoing = false;
    if (finalSelfCureUsed) {
        HandleHttpUnreachableFinally();
        return false;
    }
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC && pSelfCureStateMachine->hasTestWifi6Reassoc &&
        pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac()) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, WIFI_CURE_INTERNET_FAILED_RAND_MAC);
        return false;
    }
    if (!HasBeenTested(WIFI_CURE_RESET_LEVEL_HIGH_RESET) &&
        pSelfCureStateMachine->SelfCureAcceptable(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        lastSelfCureLevel = curCureLevel;
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, WIFI_CURE_RESET_LEVEL_HIGH_RESET);
    } else {
        HandleHttpUnreachableFinally();
    }
    return false;
}

void SelfCureStateMachine::InternetSelfCureState::HandleSelfCureFailedForRandMacReassoc()
{
    if (pSelfCureStateMachine->useWithRandMacAddress == FAC_MAC_REASSOC && pSelfCureStateMachine->IsUseFactoryMac()) {
        WIFI_LOGI("HTTP unreachable, factory mac failed and use rand mac instead of");
        pSelfCureStateMachine->useWithRandMacAddress = RAND_MAC_REASSOC;
        pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(RAND_MAC_REASSOC);
        WifiLinkedInfo linkedInfo;
        WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
        int networkId = linkedInfo.networkId;
        IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
        if (pStaService == nullptr) {
            WIFI_LOGE("Get pStaService failed!");
            return;
        }
        if (pStaService->ConnectToNetwork(networkId) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("ConnectToNetwork failed.\n");
        }
        return;
    }
    selfCureFailedCounter++;
    UpdateSelfCureHistoryInfo(selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, false);
    WIFI_LOGI("HTTP unreachable, self cure failed for rand mac reassoc");
    pSelfCureStateMachine->selfCureOnGoing = false;
    pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, WIFI_CURE_INTERNET_FAILED_TYPE_DNS);
    return;
}

void SelfCureStateMachine::InternetSelfCureState::HandleHttpReachableAfterSelfCure(int currentCureLevel)
{
    WIFI_LOGI("HandleHttpReachableAfterSelfCure, currentCureLevel = %{public}d", currentCureLevel);
    pSelfCureStateMachine->UpdateSelfCureHistoryInfo(selfCureHistoryInfo, currentCureLevel, true);
    pSelfCureStateMachine->selfCureOnGoing = false;
    if (!setStaticIp4InvalidIp && currentCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
    }
    pSelfCureStateMachine->RequestArpConflictTest();
    pSelfCureStateMachine->staticIpCureSuccess = true;
}

void SelfCureStateMachine::InternetSelfCureState::HandleHttpUnreachableFinally()
{
    pSelfCureStateMachine->selfCureOnGoing = false;
}

bool SelfCureStateMachine::InternetSelfCureState::HasBeenTested(int cureLevel)
{
    for (int itemTestedSelfCureLevel : testedSelfCureLevel) {
        if (itemTestedSelfCureLevel == cureLevel) {
            return true;
        }
    }
    return false;
}

void SelfCureStateMachine::InternetSelfCureState::HandleRssiChanged()
{
    if ((currentRssi < MIN_VAL_LEVEL_3_5) && (!pSelfCureStateMachine->IfP2pConnected()) &&
        (!pSelfCureStateMachine->notAllowSelfcure)) {
        return;
    }
    if (delayedResetSelfCure) {
        HandleDelayedResetSelfCure();
        return;
    }
    if (!pSelfCureStateMachine->selfCureOnGoing && (delayedReassocSelfCure || delayedRandMacReassocSelfCure)) {
        pSelfCureStateMachine->selfCureOnGoing = true;
        if (!pSelfCureStateMachine->IsHttpReachable()) {
            WIFI_LOGD("HandleRssiChanged, HTTP failed, delayedReassoc = %{public}s, delayedRandMacReassoc = %{public}s",
                      std::to_string(delayedReassocSelfCure).c_str(),
                      std::to_string(delayedRandMacReassocSelfCure).c_str());
            pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
            if (delayedReassocSelfCure) {
                pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                   WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, 0);
            } else if (delayedRandMacReassocSelfCure) {
                pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                   WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, 0);
            }
        } else {
            pSelfCureStateMachine->selfCureOnGoing = false;
            delayedReassocSelfCure = false;
            delayedResetSelfCure = false;
            delayedRandMacReassocSelfCure = false;
            pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pConnectedMonitorState);
        }
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleDelayedResetSelfCure()
{
    pSelfCureStateMachine->selfCureOnGoing = true;
    if (!pSelfCureStateMachine->IsHttpReachable()) {
        WIFI_LOGD("HandleDelayedResetSelfCure, HTTP failed, delayedReset = %{public}s",
                  std::to_string(delayedResetSelfCure).c_str());
        pSelfCureStateMachine->StopTimer(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
        pSelfCureStateMachine->SendMessageAtFrontOfQueue(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                         WIFI_CURE_RESET_LEVEL_HIGH_RESET);
    } else {
        pSelfCureStateMachine->selfCureOnGoing = false;
        delayedReassocSelfCure = false;
        delayedResetSelfCure = false;
        delayedRandMacReassocSelfCure = false;
        pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pConnectedMonitorState);
    }
}

/* --------------------------- state machine wifi6 self cure state ------------------------------ */
SelfCureStateMachine::Wifi6SelfCureState::Wifi6SelfCureState(SelfCureStateMachine *selfCureStateMachine)
    : State("Wifi6SelfCureState"),
      pSelfCureStateMachine(selfCureStateMachine)
{
    WIFI_LOGD("Wifi6SelfCureState construct success\n.");
}

SelfCureStateMachine::Wifi6SelfCureState::~Wifi6SelfCureState() {}

void SelfCureStateMachine::Wifi6SelfCureState::GoInState()
{
    WIFI_LOGI("Wifi6SelfCureState GoInState function.");
    wifi6HtcArpDetectionFailedCnt = 0;
    wifi6ArpDetectionFailedCnt = 0;
    return;
}

void SelfCureStateMachine::Wifi6SelfCureState::GoOutState()
{
    WIFI_LOGI("Wifi6SelfCureState GoOutState function.");
    return;
}

bool SelfCureStateMachine::Wifi6SelfCureState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("Wifi6SelfCureState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_CURE_CMD_WIFI6_SELFCURE:
            ret = EXECUTED;
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
            break;
        case WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE:
            ret = EXECUTED;
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
            break;
        case WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED:
            ret = EXECUTED;
            PeriodicWifi6WithHtcArpDetect(msg);
            break;
        case WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED:
            ret = EXECUTED;
            PeriodicWifi6WithoutHtcArpDetect(msg);
            break;
        case WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED:
            ret = EXECUTED;
            HandleWifi6WithHtcArpFail(msg);
            break;
        case WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED:
            ret = EXECUTED;
            HandleWifi6WithoutHtcArpFail(msg);
            break;
        default:
            WIFI_LOGD("Wifi6SelfCureState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

void SelfCureStateMachine::Wifi6SelfCureState::PeriodicWifi6WithHtcArpDetect(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    if (!pSelfCureStateMachine->CanArpReachable()) {
        wifi6HtcArpDetectionFailedCnt++;
        WIFI_LOGI("wifi6 with htc arp detection failed, times : %{public}d", wifi6HtcArpDetectionFailedCnt);
        if (wifi6HtcArpDetectionFailedCnt == ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
            return;
        } else if (wifi6HtcArpDetectionFailedCnt > 0 && wifi6HtcArpDetectionFailedCnt < ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED,
                WIFI6_HTC_ARP_DETECTED_MS);
            return;
        }
    } else {
        WIFI_LOGI("wifi6 with htc arp detect success");
        wifi6HtcArpDetectionFailedCnt = 0;
        pSelfCureStateMachine->isWifi6ArpSuccess = true;
        pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, SELF_CURE_DELAYED_MS);
        pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pConnectedMonitorState);
        return;
    }
}

void SelfCureStateMachine::Wifi6SelfCureState::PeriodicWifi6WithoutHtcArpDetect(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    if (!pSelfCureStateMachine->CanArpReachable()) {
        wifi6ArpDetectionFailedCnt++;
        WIFI_LOGI("wifi6 without htc arp detection failed, times : %{public}d", wifi6ArpDetectionFailedCnt);
        if (wifi6ArpDetectionFailedCnt == ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
            return;
        } else if (wifi6ArpDetectionFailedCnt > 0 && wifi6ArpDetectionFailedCnt < ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED,
                WIFI6_HTC_ARP_DETECTED_MS);
            return;
        }
    } else {
        WIFI_LOGI("wifi6 without htc arp detect success");
        wifi6ArpDetectionFailedCnt = 0;
        pSelfCureStateMachine->isWifi6ArpSuccess = true;
        if (!pSelfCureStateMachine->IsHttpReachable()) {
            pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, SELF_CURE_DELAYED_MS);
        } else {
            pSelfCureStateMachine->selfCureOnGoing = false;
        }
        pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pConnectedMonitorState);
        return;
    }
}

void SelfCureStateMachine::Wifi6SelfCureState::HandleWifi6WithHtcArpFail(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->isWifi6ArpSuccess = false;
    Wifi6BlackListInfo wifi6BlackListInfo(ACTION_TYPE_HTC, pSelfCureStateMachine->GetNowMilliSeconds());
    std::string currentBssid = pSelfCureStateMachine->GetCurrentBssid();

    WifiSettings::GetInstance().InsertWifi6BlackListCache(currentBssid, wifi6BlackListInfo);
    WIFI_LOGI("add %{public}s to HTC bla list", MacAnonymize(currentBssid).c_str());
    pSelfCureStateMachine->SendBlaListToDriver();
    std::string param = "1";
    std::string ifName = "wlan0";
    if (WifiCmdClient::GetInstance().SendCmdToDriver(ifName, EVENT_AX_CLOSE_HTC, param) != 0) {
        WIFI_LOGE("%{public}s Ax Selfcure fail", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
}

void SelfCureStateMachine::Wifi6SelfCureState::HandleWifi6WithoutHtcArpFail(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    WIFI_LOGI("wifi6 without htc arp detect failed");
    std::string currentBssid = pSelfCureStateMachine->GetCurrentBssid();
    pSelfCureStateMachine->isWifi6ArpSuccess = false;
    Wifi6BlackListInfo wifi6BlackListInfo(ACTION_TYPE_WIFI6, pSelfCureStateMachine->GetNowMilliSeconds());

    WifiSettings::GetInstance().InsertWifi6BlackListCache(currentBssid, wifi6BlackListInfo);

    WIFI_LOGI("add %{public}s to wifi6 bla list", MacAnonymize(currentBssid).c_str());
    pSelfCureStateMachine->SendBlaListToDriver();
    Wifi6ReassocSelfcure();
}

void SelfCureStateMachine::Wifi6SelfCureState::Wifi6ReassocSelfcure()
{
    WIFI_LOGI("begin to self cure for wifi6 reassoc");
    pSelfCureStateMachine->hasTestWifi6Reassoc = true;
    pSelfCureStateMachine->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE,
        WIFI_CURE_INTERNET_FAILED_TYPE_TCP, SELF_CURE_DELAYED_MS);
    pSelfCureStateMachine->SwitchState(pSelfCureStateMachine->pInternetSelfCureState);
}

int64_t SelfCureStateMachine::GetNowMilliSeconds()
{
    auto nowSys = AppExecFwk::InnerEvent::Clock::now();
    auto epoch = nowSys.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
}

void SelfCureStateMachine::SendBlaListToDriver()
{
    std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
    WifiSettings::GetInstance().GetWifi6BlackListCache(wifi6BlackListCache);
    if (wifi6BlackListCache.empty()) {
        return;
    }
    AgeOutWifi6Black(wifi6BlackListCache);
    std::string param = BlackListToString(wifi6BlackListCache);
    std::string ifName = "wlan0";
    if (WifiCmdClient::GetInstance().SendCmdToDriver(ifName, EVENT_AX_BLA_LIST, param) != 0) {
        WIFI_LOGE("%{public}s set AxBlaList fail", __FUNCTION__);
        return;
    }
}

std::string SelfCureStateMachine::BlackListToString(std::map<std::string, Wifi6BlackListInfo> &map)
{
    std::string param;
    if (map.empty()) {
        return param;
    }
    int idx = map.size() >= WIFI6_MAX_BLA_LIST_NUM ? WIFI6_MAX_BLA_LIST_NUM : map.size();
    param.push_back(idx);
    for (auto iter : map) {
        std::string singleParam = ParseWifi6BlackListInfo(iter);
        if (singleParam.size() != WIFI6_SINGLE_ITEM_BYTE_LEN) {
            continue;
        }
        param.append(singleParam);
        if (param.size() >= WIFI6_MAX_BLA_LIST_NUM * WIFI6_SINGLE_ITEM_BYTE_LEN + 1) {
            break;
        }
    }
    return param;
}

std::string SelfCureStateMachine::ParseWifi6BlackListInfo(std::pair<std::string, Wifi6BlackListInfo> iter)
{
    std::string singleParam;
    std::string currBssid = iter.first;
    WIFI_LOGI("currBssid %{public}s", MacAnonymize(currBssid).c_str());
    for (int i = 0; i < WIFI6_SINGLE_MAC_LEN; i++) {
        std::string::size_type npos = currBssid.find(":");
        if (npos != std::string::npos) {
            std::string value = currBssid.substr(0, npos);
            singleParam.push_back(static_cast<uint8_t>(std::stoi(value, nullptr, HEXADECIMAL)));
            currBssid = currBssid.substr(npos + 1);
        } else {
            singleParam.push_back(static_cast<uint8_t>(std::stoi(currBssid, nullptr, HEXADECIMAL)));
        }
    }
    singleParam.push_back(static_cast<uint8_t>(iter.second.actionType));
    singleParam.push_back(0);
    return singleParam;
}

void SelfCureStateMachine::AgeOutWifi6Black(std::map<std::string, Wifi6BlackListInfo> &wifi6BlackListCache)
{
    for (auto iter = wifi6BlackListCache.begin(); iter != wifi6BlackListCache.end(); ++iter) {
        if (GetNowMilliSeconds() - iter->second.updateTime >= WIFI6_BLA_LIST_TIME_EXPIRED) {
            WifiSettings::GetInstance().RemoveWifi6BlackListCache(iter->first);
        }
    }
    if (wifi6BlackListCache.size() >= WIFI6_MAX_BLA_LIST_NUM) {
        int64_t earliestTime = std::numeric_limits<int64_t>::max();
        std::string delBssid;
        for (auto iter = wifi6BlackListCache.begin(); iter != wifi6BlackListCache.end(); ++iter) {
            if (iter->second.updateTime < earliestTime) {
                delBssid = iter->first;
                earliestTime = iter->second.updateTime;
            }
        }
        WifiSettings::GetInstance().RemoveWifi6BlackListCache(delBssid);
    }
}

void SelfCureStateMachine::SetHttpMonitorStatus(bool isHttpReachable)
{
    mIsHttpReachable = isHttpReachable;
}

int SelfCureStateMachine::GetCurSignalLevel()
{
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    int signalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.frequency);
    WIFI_LOGD("GetCurSignalLevel, signalLevel : %{public}d", signalLevel);
    return signalLevel;
}

bool SelfCureStateMachine::IsHttpReachable()
{
    return mIsHttpReachable;
}

std::vector<uint32_t> SelfCureStateMachine::TransIpAddressToVec(std::string addr)
{
    size_t pos = 0;
    std::vector<uint32_t> currAddr;
    while ((pos = addr.find('.')) != std::string::npos) {
        currAddr.push_back(stoi(addr.substr(0, pos)));
        addr.erase(0, pos + 1);
    }
    currAddr.push_back(stoi(addr));
    if (currAddr.size() != IP_ADDR_SIZE) {
        WIFI_LOGE("TransIpAddressToVec failed");
        return {0, 0, 0, 0};
    }
    return currAddr;
}

std::string SelfCureStateMachine::TransVecToIpAddress(std::vector<uint32_t> vec)
{
    std::string address = "";
    if (vec.size() != IP_ADDR_SIZE) {
        return address;
    }
    std::ostringstream stream;
    stream << vec[VEC_POS_0] << "." << vec[VEC_POS_1] << "." << vec[VEC_POS_2] << "." << vec[VEC_POS_3];
    address = stream.str();
    return address;
}

int SelfCureStateMachine::GetLegalIpConfiguration(IpInfo &dhcpResults)
{
    WifiSettings::GetInstance().GetIpInfo(dhcpResults);
    if ((dhcpResults.gateway != 0) && (dhcpResults.ipAddress != 0)) {
        std::string gateway = IpTools::ConvertIpv4Address(dhcpResults.gateway);
        std::string initialIpAddr = IpTools::ConvertIpv4Address(dhcpResults.ipAddress);
        int tryTimes = TRY_TIMES;
        int testCnt = 0;
        std::vector<std::string> conflictedIpAddr;
        std::string testIpAddr = initialIpAddr;
        /** find unconflicted ip */
        while (testCnt++ < tryTimes) {
            conflictedIpAddr.push_back(testIpAddr);
            testIpAddr = SelfCureStateMachine::GetNextIpAddr(gateway, initialIpAddr, conflictedIpAddr);
            if (DoSlowArpTest(testIpAddr)) {
                WIFI_LOGI("GetLegalIpConfiguration, find a new unconflicted one.");
                std::string newIpAddress = testIpAddr;
                WIFI_LOGI("newIpAddress, newIpAddress = %{private}s", newIpAddress.c_str());
                dhcpResults.ipAddress = IpTools::ConvertIpv4Address(newIpAddress);
                return 0;
            }
        }
        /** there is no unconflicted ip, use 156 as static ip */
        uint32_t newIpAddr = STATIC_IP_ADDR;
        std::vector<uint32_t> oldIpAddr = TransIpAddressToVec(IpTools::ConvertIpv4Address(dhcpResults.ipAddress));
        if (oldIpAddr.size() != IP_ADDR_SIZE) {
            return -1;
        }
        oldIpAddr[VEC_POS_3] = newIpAddr;
        std::string newIpAddress = TransVecToIpAddress(oldIpAddr);
        dhcpResults.ipAddress = IpTools::ConvertIpv4Address(newIpAddress);
        return 0;
    }
    return -1;
}

bool SelfCureStateMachine::CanArpReachable()
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiSettings::GetInstance().GetMacAddress(macAddress, m_instId);
    IpInfo ipInfo;
    WifiSettings::GetInstance().GetIpInfo(ipInfo, m_instId);
    std::string ipAddress = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ifName = WifiSettings::GetInstance().GetStaIfaceName();
    if (ipInfo.gateway == 0) {
        WIFI_LOGE("gateway is null");
        return false;
    }
    std::string gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    uint64_t arpRtt = 0;
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    for (int i = 0; i < DEFAULT_SLOW_NUM_ARP_PINGS; i++) {
        if (arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true, arpRtt)) {
            WriteArpInfoHiSysEvent(arpRtt, 0);
            return true;
        }
    }
    WriteArpInfoHiSysEvent(arpRtt, 1);
    return false;
}

bool SelfCureStateMachine::DoSlowArpTest(std::string testIpAddr)
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiSettings::GetInstance().GetMacAddress(macAddress, m_instId);
    std::string ipAddress = testIpAddr;
    std::string ifName = WifiSettings::GetInstance().GetStaIfaceName();
    IpInfo ipInfo;
    std::string gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    for (int i = 0; i < DEFAULT_SLOW_NUM_ARP_PINGS; i++) {
        if (arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, false)) {
            return true;
        }
    }
    return false;
}

bool SelfCureStateMachine::DoArpTest(std::string ipAddress, std::string gateway)
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiSettings::GetInstance().GetMacAddress(macAddress, m_instId);
    std::string ifName = WifiSettings::GetInstance().GetStaIfaceName();
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    return arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true);
}

std::string SelfCureStateMachine::GetNextIpAddr(const std::string gateway, const std::string currentAddr,
                                                std::vector<std::string> testedAddr)
{
    std::vector<uint32_t> ipAddr;
    if (gateway.empty() || currentAddr.empty() || testedAddr.size() ==0) {
        WIFI_LOGI("gateway is empty or currentAddr is empty or testedAddr.size() == 0");
        return "";
    }
    uint32_t newIp = 0;
    uint32_t getCnt = 1;
    ipAddr = TransIpAddressToVec(currentAddr);
    uint32_t iMAX = 250;
    uint32_t iMIN = 101;
    while (getCnt++ < GET_NEXT_IP_MAC_CNT) {
        std::vector<uint32_t> gwAddr;
        bool reduplicate = false;
        time_t now = time(nullptr);
        if (now >= 0) {
            srand(now);
        }
        uint32_t randomNum = 0;
        uint32_t fd = open("/dev/random", O_RDONLY); /* Obtain the random number by reading /dev/random */
        if (fd > 0) {
            read(fd, &randomNum, sizeof(uint32_t));
        }
        close(fd);
        uint32_t rand = (randomNum > 0 ? randomNum : -randomNum) % 100;
        newIp = rand + iMIN;
        gwAddr = TransIpAddressToVec(gateway);
        if (newIp == (gwAddr[VEC_POS_3] & 0xFF) || newIp == (ipAddr[VEC_POS_3] & 0xFF)) {
            continue;
        }
        for (size_t i = 0; i < testedAddr.size(); i++) {
            std::vector<uint32_t> tmp = TransIpAddressToVec(testedAddr[i]);
            if (newIp == (tmp[VEC_POS_3] & 0xFF)) {
                reduplicate = true;
                break;
            }
        }
        if (newIp > 0 && !reduplicate) {
            break;
        }
    }
    if (newIp > 1 && newIp <= iMAX && getCnt < GET_NEXT_IP_MAC_CNT) {
        ipAddr[VEC_POS_3] = newIp;
        return TransVecToIpAddress(ipAddr);
    }
    return "";
}

bool SelfCureStateMachine::IsIpAddressInvalid()
{
    IpInfo dhcpInfo;
    std::vector<uint32_t> currAddr;
    WifiSettings::GetInstance().GetIpInfo(dhcpInfo);
    if (dhcpInfo.ipAddress != 0) {
        std::string addr = IpTools::ConvertIpv4Address(dhcpInfo.ipAddress);
        currAddr = TransIpAddressToVec(addr);
        if ((currAddr.size() == IP_ADDR_SIZE)) {
            uint32_t intCurrAddr3 = (currAddr[VEC_POS_3] & 0xFF);
            uint32_t netmaskLenth = IpTools::GetMaskLength(IpTools::ConvertIpv4Address(dhcpInfo.netmask));
            bool ipEqualsGw = (dhcpInfo.ipAddress == dhcpInfo.gateway);
            bool invalidIp = (intCurrAddr3 == 0 || intCurrAddr3 == 1 || intCurrAddr3 == IP_ADDR_LIMIT);
            if ((ipEqualsGw) || ((netmaskLenth == NET_MASK_LENGTH) && (invalidIp))) {
                WIFI_LOGI("current rcvd ip is invalid, maybe no internet access, need to comfirm and cure it.");
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> SelfCureStateMachine::TransStrToVec(std::string str, char c)
{
    size_t pos = 0;
    std::vector<std::string> vec;
    while ((pos = str.find(c)) != std::string::npos) {
        vec.push_back(str.substr(0, pos));
        str.erase(0, pos + 1);
    }
    vec.push_back(str);
    return vec;
}

bool SelfCureStateMachine::IsUseFactoryMac()
{
    WifiLinkedInfo wifiLinkedInfo;
    std::string currMacAddress;
    std::string realMacAddress;
    WifiSettings::GetInstance().GetMacAddress(currMacAddress);
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddress);
    if (!currMacAddress.empty() && !realMacAddress.empty() && currMacAddress == realMacAddress) {
        WIFI_LOGI("use factory mac address currently.");
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IsSameEncryptType(const std::string scanInfoKeymgmt, const std::string deviceKeymgmt)
{
    if (deviceKeymgmt == "WPA-PSK") {
        return scanInfoKeymgmt.find("PSK") != std::string::npos;
    } else if (deviceKeymgmt == "WPA-EAP") {
        return scanInfoKeymgmt.find("EAP") != std::string::npos;
    } else if (deviceKeymgmt == "SAE") {
        return scanInfoKeymgmt.find("SAE") != std::string::npos;
    } else if (deviceKeymgmt == "NONE") {
        return (scanInfoKeymgmt.find("PSK") == std::string::npos) &&
               (scanInfoKeymgmt.find("EAP") == std::string::npos) && (scanInfoKeymgmt.find("SAE") == std::string::npos);
    } else {
        return false;
    }
}

int SelfCureStateMachine::GetBssidCounter(const std::vector<WifiScanInfo> &scanResults)
{
    WifiLinkedInfo wifiLinkedInfo;
    WifiDeviceConfig config;
    int counter = 0;
    if (scanResults.empty()) {
        WIFI_LOGI("scanResults ie empty.");
        return 0;
    }
    WifiSettings::GetInstance().GetLinkedInfo(wifiLinkedInfo);
    std::string currentSsid = wifiLinkedInfo.ssid;
    WifiSettings::GetInstance().GetDeviceConfig(wifiLinkedInfo.networkId, config);
    std::string configKey = config.keyMgmt;
    if (currentSsid.empty() || configKey.empty()) {
        return 0;
    }
    for (WifiScanInfo nextResult : scanResults) {
        std::string scanSsid = "\"" + nextResult.ssid + "\"";
        std::string capabilities = nextResult.capabilities;
        if (currentSsid == scanSsid && IsSameEncryptType(capabilities, configKey)) {
            counter += 1;
        }
    }
    return counter;
}

bool SelfCureStateMachine::IsNeedWifiReassocUseDeviceMac()
{
    if (GetSelfCureHistoryInfo().empty()) {
        WIFI_LOGI("SelfCureHistoryInfo is null!");
        return false;
    }
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    WIFI_LOGI("random MAC address is supported!");
    if (!CanArpReachable()) {
        WIFI_LOGI("arp is not reachable!");
        return false;
    }
    if (IsUseFactoryMac()) {
        WIFI_LOGI("use factory mac now!");
        return false;
    }
    std::vector<WifiScanInfo> scanResults;
    WifiSettings::GetInstance().GetScanInfoList(scanResults);
    if (GetBssidCounter(scanResults) < MULTI_BSSID_NUM) {
        WIFI_LOGI("not multi bssid condition!");
        return false;
    }
    bool hasInternetEver = NetworkStatusHistoryManager::HasInternetEverByHistory(GetNetworkStatusHistory());
    bool hasPortalHistory = NetworkStatusHistoryManager::IsPortalByHistory(GetNetworkStatusHistory());
    if (hasInternetEver || hasPortalHistory) {
        WIFI_LOGI("has internethistory, don't to reassoc with factory mac!");
        return false;
    }
    WifiSelfCureHistoryInfo selfCureInfo;
    std::string internetSelfCureHistory = GetSelfCureHistoryInfo();
    String2InternetSelfCureHistoryInfo(internetSelfCureHistory, selfCureInfo);
    if (selfCureInfo.randMacSelfCureConnectFailedCnt > SELF_CURE_RAND_MAC_CONNECT_FAIL_MAX_COUNT ||
        selfCureInfo.randMacSelfCureFailedCnt > SELF_CURE_RAND_MAC_MAX_COUNT) {
        WIFI_LOGI("has connect fail three times or randMac self cure fail 20 times!");
        return false;
    }
    auto now = std::chrono::system_clock::now();
    uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t lastConnectFailMs = selfCureInfo.lastRandMacSelfCureConnectFailedCntTs;
    if ((currentMs - lastConnectFailMs) < RAND_MAC_FAIL_EXPIRATION_AGE_MILLIS) {
        WIFI_LOGI("Too close to the last connection failure time return");
        return false;
    }
    return true;
#endif
    WIFI_LOGI("random MAC address is not supported!");
    return false;
}

int SelfCureStateMachine::String2InternetSelfCureHistoryInfo(const std::string selfCureHistory,
                                                             WifiSelfCureHistoryInfo &info)
{
    if (selfCureHistory.empty()) {
        WIFI_LOGE("InternetSelfCureHistoryInfo is empty!");
        return -1;
    }
    std::vector<std::string> histories = TransStrToVec(selfCureHistory, '|');
    if (histories.size() != SELFCURE_HISTORY_LENGTH) {
        WIFI_LOGE("self cure history length = %{public}lu", (unsigned long) histories.size());
        return -1;
    }
    if (SetSelfCureFailInfo(info, histories, SELFCURE_FAIL_LENGTH) != 0) {
        WIFI_LOGE("set self cure history information failed!");
    }
    if (SetSelfCureConnectFailInfo(info, histories, SELFCURE_FAIL_LENGTH) != 0) {
        WIFI_LOGE("set self cure connect history information failed!");
    }
    return 0;
}

int SelfCureStateMachine::SetSelfCureFailInfo(WifiSelfCureHistoryInfo &info, std::vector<std::string> histories,
                                              int cnt)
{
    if (histories.empty() || histories.size() != SELFCURE_HISTORY_LENGTH || cnt != SELFCURE_FAIL_LENGTH) {
        WIFI_LOGE("SetSelfCureFailInfo return");
        return -1;
    }
    // 0 to 12 is history subscript, which record the selfcure failed info, covert array to calss member
    for (int i = 0; i < cnt; i++) {
        if (i == 0) {
            info.dnsSelfCureFailedCnt = stoi(histories[i]);
        } else if (i == POS_DNS_FAILED_TS) {
            info.lastDnsSelfCureFailedTs = stoll(histories[i]);
        } else if (i == POS_RENEW_DHCP_FAILED_CNT) {
            info.renewDhcpSelfCureFailedCnt = stoi(histories[i]);
        } else if (i == POS_RENEW_DHCP_FAILED_TS) {
            info.lastRenewDhcpSelfCureFailedTs = stoll(histories[i]);
        } else if (i == POS_STATIC_IP_FAILED_CNT) {
            info.staticIpSelfCureFailedCnt = stoi(histories[i]);
        } else if (i == POS_STATIC_IP_FAILED_TS) {
            info.lastStaticIpSelfCureFailedTs = stoll(histories[i]);
        } else if (i == POS_REASSOC_FAILED_CNT) {
            info.reassocSelfCureFailedCnt = stoi(histories[i]);
        } else if (i == POS_REASSOC_FAILED_TS) {
            info.lastReassocSelfCureFailedTs = stoll(histories[i]);
        } else if (i == POS_RANDMAC_FAILED_CNT) {
            info.randMacSelfCureFailedCnt = stoi(histories[i]);
        } else if (i == POS_RANDMAC_FAILED_TS) {
            info.lastRandMacSelfCureFailedCntTs = stoll(histories[i]);
        } else if (i == POS_RESET_FAILED_CNT) {
            info.resetSelfCureFailedCnt = stoi(histories[i]);
        } else if (i == POS_RESET_FAILED_TS) {
            info.lastResetSelfCureFailedTs = stoll(histories[i]);
        } else {
            WIFI_LOGI("exception happen.");
        }
    }
    return 0;
}

int SelfCureStateMachine::SetSelfCureConnectFailInfo(WifiSelfCureHistoryInfo &info, std::vector<std::string> histories,
                                                     int cnt)
{
    if (histories.empty() || histories.size() != SELFCURE_HISTORY_LENGTH || cnt != SELFCURE_FAIL_LENGTH) {
        WIFI_LOGE("SetSelfCureFailInfo return");
        return -1;
    }
    // 12 to 17 is history subscript, which record the selfcure connect failed info, covert array to calss member
    for (int i = cnt; i < SELFCURE_HISTORY_LENGTH; i++) {
        if (i == POS_REASSOC_CONNECT_FAILED_CNT) {
            info.reassocSelfCureConnectFailedCnt = stoi(histories[i]);
        } else if (i == POS_REASSOC_CONNECT_FAILED_TS) {
            info.lastReassocSelfCureConnectFailedTs = stoll(histories[i]);
        } else if (i == POS_RANDMAC_CONNECT_FAILED_CNT) {
            info.randMacSelfCureConnectFailedCnt = stoi(histories[i]);
        } else if (i == POS_RANDMAC_CONNECT_FAILED_TS) {
            info.lastRandMacSelfCureConnectFailedCntTs = stoll(histories[i]);
        } else if (i == POS_RESET_CONNECT_FAILED_CNT) {
            info.resetSelfCureConnectFailedCnt = stoi(histories[i]);
        } else if (i == POS_RESET_CONNECT_FAILED_TS) {
            info.lastResetSelfCureConnectFailedTs = stoll(histories[i]);
        } else {
            WIFI_LOGI("exception happen.");
        }
    }
    return 0;
}

bool SelfCureStateMachine::IsSuppOnCompletedState()
{
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState == ConnState::CONNECTED) {
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IfPeriodicArpDetection()
{
    int curSignalLevel = GetCurSignalLevel();
    int state = WifiSettings::GetInstance().GetScreenState();
    WIFI_LOGD("IfPeriodicArpDetection, GetScreenState: %{public}d", state);
    return (curSignalLevel >= SIGNAL_LEVEL_2) && (!selfCureOnGoing) && (IsSuppOnCompletedState()) &&
           (state == MODE_STATE_OPEN);
}

void SelfCureStateMachine::PeriodicArpDetection()
{
    StopTimer(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
    if (!IfPeriodicArpDetection()) {
        WIFI_LOGI("PeriodicArpDetection, no need detection, just jump");
        MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, DEFAULT_ARP_DETECTED_MS);
        return;
    }
    if (!CanArpReachable()) {
        arpDetectionFailedCnt++;
        WIFI_LOGI("Periodic Arp Detection failed, times : %{public}d", arpDetectionFailedCnt);
        if (arpDetectionFailedCnt == ARP_DETECTED_FAILED_COUNT) {
            SendMessage(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        } else if (arpDetectionFailedCnt > 0 && arpDetectionFailedCnt < ARP_DETECTED_FAILED_COUNT) {
            MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, FAST_ARP_DETECTED_MS);
            return;
        }
    } else {
        WIFI_LOGD("Periodic Arp Detection success");
        arpDetectionFailedCnt = 0;
    }
    MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, DEFAULT_ARP_DETECTED_MS);
}

bool SelfCureStateMachine::ShouldTransToWifi6SelfCure(InternalMessage *msg, std::string currConnectedBssid)
{
    WIFI_LOGI("enter ShouldTransToWifi6SelfCure");
    if (currConnectedBssid.empty()) {
        return false;
    }
    if (!IsWifi6Network(currConnectedBssid) || isWifi6ArpSuccess || GetCurrentRssi() < MIN_VAL_LEVEL_3) {
        return false;
    }
    std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
    WifiSettings::GetInstance().GetWifi6BlackListCache(wifi6BlackListCache);
    if (wifi6BlackListCache.find(currConnectedBssid) == wifi6BlackListCache.end()) {
        MessageExecutedLater(WIFI_CURE_CMD_WIFI6_SELFCURE, SELF_CURE_DELAYED_MS);
        SwitchState(pWifi6SelfCureState);
        return true;
    } else {
        auto iter = wifi6BlackListCache.find(currConnectedBssid);
        if (iter->second.actionType == 0) {
            MessageExecutedLater(WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE, SELF_CURE_DELAYED_MS);
            SwitchState(pWifi6SelfCureState);
            return true;
        } else {
            WIFI_LOGD("don't need to do wifi6 selfcure");
        }
    }
    return false;
}

int SelfCureStateMachine::GetCurrentRssi()
{
    WifiLinkedInfo wifiLinkedInfo;
    if (WifiSettings::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("Get current link info failed!");
    }
    int currentRssi = wifiLinkedInfo.rssi;
    return currentRssi;
}

std::string SelfCureStateMachine::GetCurrentBssid()
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    std::string currentBssid = config.bssid;
    return currentBssid;
}

bool SelfCureStateMachine::IsWifi6Network(std::string currConnectedBssid)
{
    if (currConnectedBssid.empty()) {
        WIFI_LOGE("currConnectedBssid is empty");
        return false;
    }
    WifiLinkedInfo wifiLinkedInfo;
    if (WifiSettings::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("Get current link info failed!");
    }
    if (wifiLinkedInfo.supportedWifiCategory == WifiCategory::WIFI6 ||
        wifiLinkedInfo.supportedWifiCategory == WifiCategory::WIFI6_PLUS) {
        WIFI_LOGI("current network is wifi6 network");
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IfP2pConnected()
{
    WifiP2pLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetP2pInfo(linkedInfo);
    WIFI_LOGI("P2p connection state : %{public}d", linkedInfo.GetConnectState());
    return linkedInfo.GetConnectState() == P2pConnectedState::P2P_CONNECTED;
}

std::string SelfCureStateMachine::GetAuthType()
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    std::string keyMgmt = config.keyMgmt;
    return keyMgmt;
}

int SelfCureStateMachine::GetIpAssignment(AssignIpMethod &ipAssignment)
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    ipAssignment = config.wifiIpConfig.assignMethod;
    return 0;
}

time_t SelfCureStateMachine::GetLastHasInternetTime()
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    time_t lastHasInternetTime = config.lastHasInternetTime;
    return lastHasInternetTime;
}

uint32_t SelfCureStateMachine::GetNetworkStatusHistory()
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    uint32_t networkStatusHistory = config.networkStatusHistory;
    return networkStatusHistory;
}

std::string SelfCureStateMachine::GetSelfCureHistoryInfo()
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    std::string internetSelfCureHistory = config.internetSelfCureHistory;
    return internetSelfCureHistory;
}

int SelfCureStateMachine::SetSelfCureHistoryInfo(const std::string selfCureHistory)
{
    if (selfCureHistory =="0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0") {
        WIFI_LOGW("selfCureHistory is zero");
        return -1;
    }
    WifiDeviceConfig wifiDeviceConfig = GetCurrentWifiDeviceConfig();
    wifiDeviceConfig.internetSelfCureHistory = selfCureHistory;
    WifiSettings::GetInstance().AddDeviceConfig(wifiDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return 0;
}

int SelfCureStateMachine::GetIsReassocWithFactoryMacAddress()
{
    WifiDeviceConfig config = GetCurrentWifiDeviceConfig();
    int isReassocWithFactoryMacAddress = config.isReassocSelfCureWithFactoryMacAddress;
    return isReassocWithFactoryMacAddress;
}

int SelfCureStateMachine::SetIsReassocWithFactoryMacAddress(int isReassocWithFactoryMacAddress)
{
    WifiDeviceConfig wifiDeviceConfig = GetCurrentWifiDeviceConfig();
    wifiDeviceConfig.isReassocSelfCureWithFactoryMacAddress = isReassocWithFactoryMacAddress;
    WifiSettings::GetInstance().AddDeviceConfig(wifiDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return 0;
}

WifiDeviceConfig SelfCureStateMachine::GetCurrentWifiDeviceConfig()
{
    WifiLinkedInfo wifiLinkedInfo;
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("Get current link info failed!");
    }
    if (WifiSettings::GetInstance().GetDeviceConfig(wifiLinkedInfo.networkId, config) != 0) {
        WIFI_LOGE("Get device config failed!");
    }
    return config;
}

bool AllowSelfCure(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel)
{
    auto now = std::chrono::system_clock::now();
    uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        if ((historyInfo.reassocSelfCureConnectFailedCnt == 0) ||
            ((historyInfo.reassocSelfCureConnectFailedCnt >= 1) &&
             ((currentMs - historyInfo.lastReassocSelfCureConnectFailedTs) > DELAYED_DAYS_LOW))) {
            return true;
        }
    } else {
        if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
            if ((historyInfo.resetSelfCureConnectFailedCnt == 0) ||
                ((historyInfo.resetSelfCureConnectFailedCnt >= 1) &&
                 ((currentMs - historyInfo.lastResetSelfCureConnectFailedTs) > DELAYED_DAYS_LOW))) {
                return true;
            }
        }
    }
    return false;
}

bool DealDns(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, uint64_t currentMs)
{
    if (historyInfo.dnsSelfCureFailedCnt == 0 ||
        (historyInfo.dnsSelfCureFailedCnt == SELF_CURE_FAILED_ONE_CNT &&
         (currentMs - historyInfo.lastDnsSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.dnsSelfCureFailedCnt == SELF_CURE_FAILED_TWO_CNT &&
         (currentMs - historyInfo.lastDnsSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.dnsSelfCureFailedCnt >= SELF_CURE_FAILED_THREE_CNT &&
         (currentMs - historyInfo.lastDnsSelfCureFailedTs > DELAYED_DAYS_HIGH))) {
        return true;
    }
    return false;
}

bool DealRenewDhcp(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, uint64_t currentMs)
{
    if (historyInfo.renewDhcpSelfCureFailedCnt >= 0) {
        return true;
    }
    return false;
}

bool DealStaticIp(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, uint64_t currentMs)
{
    if (historyInfo.staticIpSelfCureFailedCnt <= SELF_CURE_FAILED_FOUR_CNT ||
        (historyInfo.staticIpSelfCureFailedCnt == SELF_CURE_FAILED_FIVE_CNT &&
         (currentMs - historyInfo.lastStaticIpSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.staticIpSelfCureFailedCnt == SELF_CURE_FAILED_SIX_CNT &&
         (currentMs - historyInfo.lastStaticIpSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.staticIpSelfCureFailedCnt >= SELF_CURE_FAILED_SEVEN_CNT &&
         (currentMs - historyInfo.lastStaticIpSelfCureFailedTs > DELAYED_DAYS_HIGH))) {
        return true;
    }
    return false;
}

bool DealMiddleReassoc(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, uint64_t currentMs)
{
    if ((historyInfo.reassocSelfCureFailedCnt == 0 ||
        (historyInfo.reassocSelfCureFailedCnt == SELF_CURE_FAILED_ONE_CNT &&
         (currentMs - historyInfo.lastReassocSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.reassocSelfCureFailedCnt == SELF_CURE_FAILED_TWO_CNT &&
         (currentMs - historyInfo.lastReassocSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.reassocSelfCureFailedCnt >= SELF_CURE_FAILED_THREE_CNT &&
         (currentMs - historyInfo.lastReassocSelfCureFailedTs > DELAYED_DAYS_HIGH))) &&
        AllowSelfCure(historyInfo, requestCureLevel)) {
        return true;
    }
    return false;
}

bool DealRandMacReassoc(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, uint64_t currentMs)
{
    if (historyInfo.randMacSelfCureFailedCnt < SELF_CURE_RAND_MAC_MAX_COUNT) {
        return true;
    }
    return false;
}

bool DealHighReset(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, uint64_t currentMs)
{
    if ((historyInfo.resetSelfCureFailedCnt <= SELF_CURE_FAILED_ONE_CNT ||
        (historyInfo.resetSelfCureFailedCnt == SELF_CURE_FAILED_TWO_CNT &&
         (currentMs - historyInfo.lastResetSelfCureFailedTs > DELAYED_DAYS_LOW)) ||
        (historyInfo.resetSelfCureFailedCnt == SELF_CURE_FAILED_THREE_CNT &&
         (currentMs - historyInfo.lastResetSelfCureFailedTs > DELAYED_DAYS_MID)) ||
        (historyInfo.resetSelfCureFailedCnt >= SELF_CURE_FAILED_FOUR_CNT &&
         (currentMs - historyInfo.lastResetSelfCureFailedTs > DELAYED_DAYS_HIGH))) &&
        AllowSelfCure(historyInfo, requestCureLevel)) {
        return true;
    }
    return false;
}

bool SelfCureStateMachine::SelfCureAcceptable(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel)
{
    auto now = std::chrono::system_clock::now();
    uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    bool ifAcceptable = false;
    switch (requestCureLevel) {
        case WIFI_CURE_RESET_LEVEL_LOW_1_DNS:
            ifAcceptable = DealDns(historyInfo, WIFI_CURE_RESET_LEVEL_LOW_1_DNS, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP:
            ifAcceptable = DealRenewDhcp(historyInfo, WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP:
            ifAcceptable = DealStaticIp(historyInfo, WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC:
            ifAcceptable = DealMiddleReassoc(historyInfo, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC:
            ifAcceptable = DealRandMacReassoc(historyInfo, WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, currentMs);
            break;
        case WIFI_CURE_RESET_LEVEL_HIGH_RESET:
            ifAcceptable = DealHighReset(historyInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET, currentMs);
            break;
        default:
            break;
    }
    return ifAcceptable;
}

bool SelfCureStateMachine::UpdateConnSelfCureFailedHistory()
{
    return false;
}

void SelfCureStateMachine::HandleNetworkConnected()
{
    if (!UpdateConnSelfCureFailedHistory()) {
        WIFI_LOGD("Config is null for update, delay 2s to update again.");
        MessageExecutedLater(WIFI_CURE_CMD_UPDATE_CONN_SELF_CURE_HISTORY, SELF_CURE_MONITOR_DELAYED_MS);
    }
    noAutoConnCounter = 0;
    autoConnectFailedNetworksRssi.clear();
    connectedTimeMills = clock();
    {
        std::lock_guard<std::mutex> lock(dhcpFailedBssidLock);
        dhcpFailedBssids.clear();
        dhcpFailedConfigKeys.clear();
    }
    SwitchState(pConnectedMonitorState);
}

bool SelfCureStateMachine::IsEncryptedAuthType(const std::string authType)
{
    if (authType == KEY_MGMT_WPA_PSK || authType == KEY_MGMT_SAE) {
        return true;
    }
    return false;
}

std::string SelfCureStateMachine::GetCurrentGateway()
{
    std::string gateway = "";
    IpInfo ipInfo;
    WifiSettings::GetInstance().GetIpInfo(ipInfo, m_instId);
    gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    WIFI_LOGI("Current gateway is : %{public}s.", IpAnonymize(gateway).c_str());
    return gateway;
}

void SelfCureStateMachine::UpdateSelfCureConnectHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                            bool success)
{
    auto now = std::chrono::system_clock::now();
    uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        if (success) {
            historyInfo.reassocSelfCureConnectFailedCnt = 0;
            historyInfo.lastReassocSelfCureConnectFailedTs = 0;
        } else {
            historyInfo.reassocSelfCureConnectFailedCnt += 1;
            historyInfo.lastReassocSelfCureConnectFailedTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        if (success) {
            historyInfo.randMacSelfCureConnectFailedCnt = 0;
            historyInfo.lastRandMacSelfCureConnectFailedCntTs = 0;
        } else {
            historyInfo.randMacSelfCureConnectFailedCnt += 1;
            historyInfo.lastRandMacSelfCureConnectFailedCntTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
        if (success) {
            historyInfo.resetSelfCureConnectFailedCnt = 0;
            historyInfo.lastResetSelfCureConnectFailedTs = 0;
        } else {
            historyInfo.resetSelfCureConnectFailedCnt += 1;
            historyInfo.lastResetSelfCureConnectFailedTs = currentMs;
        }
    }
}

void SelfCureStateMachine::UpdateSelfCureHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                     bool success)
{
    auto now = std::chrono::system_clock::now();
    uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_1_DNS) {
        if (success) {
            historyInfo.dnsSelfCureFailedCnt = 0;
            historyInfo.lastDnsSelfCureFailedTs = 0;
        } else {
            historyInfo.dnsSelfCureFailedCnt += 1;
            historyInfo.lastDnsSelfCureFailedTs = currentMs;
        }
    } else if ((requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP) ||
               (requestCureLevel == WIFI_CURE_RESET_LEVEL_DEAUTH_BSSID)) {
        if (success) {
            historyInfo.renewDhcpSelfCureFailedCnt = 0;
            historyInfo.lastRenewDhcpSelfCureFailedTs = 0;
        } else {
            historyInfo.renewDhcpSelfCureFailedCnt += 1;
            historyInfo.lastRenewDhcpSelfCureFailedTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        if (success) {
            historyInfo.staticIpSelfCureFailedCnt = 0;
            historyInfo.lastStaticIpSelfCureFailedTs = 0;
        } else {
            historyInfo.staticIpSelfCureFailedCnt += 1;
            historyInfo.lastStaticIpSelfCureFailedTs = currentMs;
        }
    } else {
        if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC ||
            requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC ||
            requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
            UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);
        }
    }
}

void SelfCureStateMachine::UpdateReassocAndResetHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                            bool success)
{
    auto now = std::chrono::system_clock::now();
    uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        if (success) {
            historyInfo.reassocSelfCureFailedCnt = 0;
            historyInfo.lastReassocSelfCureFailedTs = 0;
        } else {
            historyInfo.reassocSelfCureFailedCnt += 1;
            historyInfo.lastReassocSelfCureFailedTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        if (success) {
            historyInfo.randMacSelfCureFailedCnt = 0;
            historyInfo.lastRandMacSelfCureFailedCntTs = 0;
        } else {
            historyInfo.randMacSelfCureFailedCnt += 1;
            historyInfo.lastRandMacSelfCureFailedCntTs = currentMs;
        }
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
        if (success) {
            historyInfo.resetSelfCureFailedCnt = 0;
            historyInfo.lastResetSelfCureFailedTs = 0;
        } else {
            historyInfo.resetSelfCureFailedCnt += 1;
            historyInfo.lastResetSelfCureFailedTs = currentMs;
        }
    }
}

void SelfCureStateMachine::RequestArpConflictTest()
{
    IpInfo ipInfo;
    WifiSettings::GetInstance().GetIpInfo(ipInfo);
    std::string ipAddr = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    if (ipAddr != "" && DoSlowArpTest(ipAddr)) {
        WIFI_LOGI("RequestArpConflictTest, Upload static ip conflicted chr!");
    }
}

void SelfCureStateMachine::HandleP2pConnChanged(const WifiP2pLinkedInfo &info)
{
    if (info.GetConnectState() == P2pConnectedState::P2P_CONNECTED) {
        p2pConnected = true;
        return;
    }
    p2pConnected = false;
    if (GetCurStateName() == pInternetSelfCureState->GetStateName()) {
        SendMessage(WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT);
    }
}

bool SelfCureStateMachine::IfMultiGateway()
{
    return false;
}

} // namespace Wifi
} // namespace OHOS