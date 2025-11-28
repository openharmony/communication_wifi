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
#include "multi_gateway.h"
#include "wifi_manager.h"
#include "wifi_sta_hal_interface.h"
#include "network_status_history_manager.h"
#include "wifi_hisysevent.h"
#include "wifi_config_center.h"
#include "wifi_app_state_aware.h"
#include "ip_qos_monitor.h"
#include "wifi_net_agent.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_net_agent.h"
#include "parameter.h"
#include "wifi_common_event_helper.h"
#include "wifi_country_code_manager.h"
#include "self_cure_utils.h"
#include "wifi_global_func.h"
#include "wifi_chr_adapter.h"

namespace OHOS {
namespace Wifi {
const std::string CLASS_NAME = "WifiSelfCure";

DEFINE_WIFILOG_LABEL("SelfCureStateMachine");

const uint32_t CONNECT_NETWORK_RETRY = 1;
const uint32_t WIFI_SINGLE_ITEM_BYTE_LEN = 8;
const uint32_t WIFI_SINGLE_MAC_LEN = 6;
const uint32_t WIFI_MAX_BLA_LIST_NUM = 16;
const uint32_t DHCP_OFFER_COUNT = 2;
const std::string INIT_SELFCURE_HISTORY = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
const std::string COUNTRY_CODE_CN = "460";

SelfCureStateMachine::SelfCureStateMachine(int instId)
    : StateMachine("SelfCureStateMachine"),
      pDefaultState_(nullptr),
      pConnectedMonitorState_(nullptr),
      pDisconnectedMonitorState_(nullptr),
      pConnectionSelfCureState_(nullptr),
      pInternetSelfCureState_(nullptr),
      pWifi6SelfCureState_(nullptr),
      pNoInternetState_(nullptr),
      instId_(instId)
{
    mNetWorkDetect_ = sptr<NetStateObserver>(new NetStateObserver());
}

SelfCureStateMachine::~SelfCureStateMachine()
{
    WIFI_LOGI("~SelfCureStateMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState_);
    ParsePointer(pConnectedMonitorState_);
    ParsePointer(pDisconnectedMonitorState_);
    ParsePointer(pConnectionSelfCureState_);
    ParsePointer(pInternetSelfCureState_);
    ParsePointer(pWifi6SelfCureState_);
    ParsePointer(pNoInternetState_);
}

void SelfCureStateMachine::BuildStateTree()
{
    StatePlus(pDefaultState_, nullptr);
    StatePlus(pConnectedMonitorState_, pDefaultState_);
    StatePlus(pDisconnectedMonitorState_, pDefaultState_);
    StatePlus(pConnectionSelfCureState_, pDefaultState_);
    StatePlus(pInternetSelfCureState_, pDefaultState_);
    StatePlus(pWifi6SelfCureState_, pDefaultState_);
    StatePlus(pNoInternetState_, pDefaultState_);
}

ErrCode SelfCureStateMachine::InitSelfCureStates()
{
    WIFI_LOGI("Enter InitSelfCureStates\n");
    int tmpErrNumber;
    pDefaultState_ = new (std::nothrow)DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState_);
    pConnectedMonitorState_ = new (std::nothrow)ConnectedMonitorState(this);
    tmpErrNumber += JudgmentEmpty(pConnectedMonitorState_);
    pDisconnectedMonitorState_ = new (std::nothrow)DisconnectedMonitorState(this);
    tmpErrNumber += JudgmentEmpty(pDisconnectedMonitorState_);
    pConnectionSelfCureState_ = new (std::nothrow)ConnectionSelfCureState(this);
    tmpErrNumber += JudgmentEmpty(pConnectionSelfCureState_);
    pInternetSelfCureState_ = new (std::nothrow)InternetSelfCureState(this);
    tmpErrNumber += JudgmentEmpty(pInternetSelfCureState_);
    pWifi6SelfCureState_ = new (std::nothrow)Wifi6SelfCureState(this);
    tmpErrNumber += JudgmentEmpty(pWifi6SelfCureState_);
    pNoInternetState_ = new (std::nothrow)NoInternetState(this);
    tmpErrNumber += JudgmentEmpty(pNoInternetState_);
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
    SetFirstState(pDisconnectedMonitorState_);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

/* --------------------------- state machine default state ------------------------------ */
SelfCureStateMachine::DefaultState::DefaultState(SelfCureStateMachine *selfCureStateMachine)
    : State("DefaultState"),
      pSelfCureStateMachine_(selfCureStateMachine)
{
    WIFI_LOGD("DefaultState construct success.");
}

SelfCureStateMachine::DefaultState::~DefaultState() {}

void SelfCureStateMachine::DefaultState::GoInState()
{
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_IDLE, false);
    WIFI_LOGI("DefaultState GoInState function.");
}

void SelfCureStateMachine::DefaultState::GoOutState()
{
    WIFI_LOGI("DefaultState GoOutState function.");
}

bool SelfCureStateMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_CURE_CMD_FORCE_STOP_SELF_CURE:
            pSelfCureStateMachine_->ForceStopSelfCure();
            break;
        case WIFI_CURE_DHCP_OFFER_PKT_RCV: {
            IpInfo info;
            msg->GetMessageObj(info);
            HandleDhcpOfferPacketRcv(info);
            ret = EXECUTED;
            break;
        }
        case WIFI_CURE_CMD_P2P_ENHANCE_STATE_CHANGED: {
            int state = msg->GetParam1();
            HandleP2pEnhanceStateChange(state);
            ret = EXECUTED;
            break;
        }
        case WIFI_CURE_RESET_OFF_TIMEOUT:
        case WIFI_CURE_RESET_ON_TIMEOUT:
        case WIFI_CURE_REASSOC_TIMEOUT:
        case WIFI_CURE_CONNECT_TIMEOUT:
        case WIFI_CURE_DISCONNECT_TIMEOUT:
            pSelfCureStateMachine_->HandleSelfCureException(SCE_WIFI_STATUS_FAIL);
            ret = EXECUTED;
            break;
        case WIFI_CURE_CMD_STOP_SELF_CURE: {
            int status = msg->GetParam1();
            pSelfCureStateMachine_->HandleSceStopSelfCure(status);
            ret = EXECUTED;
            break;
        }
        default:
            WIFI_LOGD("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

void SelfCureStateMachine::DefaultState::HandleDhcpOfferPacketRcv(const IpInfo &info)
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("HandleDhcpOfferPacketRcv get pEnhanceService service failed!");
        return;
    }
    uint32_t retSize = 0;
    pEnhanceService->DealDhcpOfferResult(OperationCmd::DHCP_OFFER_ADD, info, retSize);
    WIFI_LOGI("dhcpOfferPackets size: %{public}u", retSize);
}

void SelfCureStateMachine::DefaultState::HandleP2pEnhanceStateChange(int state)
{
    pSelfCureStateMachine_->isP2pEnhanceConnected_ = (state == 1) ? true : false;
    if ((!pSelfCureStateMachine_->isP2pEnhanceConnected_) &&
       (pSelfCureStateMachine_->GetCurStateName() == pSelfCureStateMachine_->pInternetSelfCureState_->GetStateName())) {
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT);
    }
}
/* --------------------------- state machine connected monitor state ------------------------------ */
SelfCureStateMachine::ConnectedMonitorState::ConnectedMonitorState(SelfCureStateMachine *selfCureStateMachine)
    : State("ConnectedMonitorState"),
      pSelfCureStateMachine_(selfCureStateMachine)
{
    InitSelfCureCmsHandleMap();
    WIFI_LOGD("ConnectedMonitorState construct success.");
}

SelfCureStateMachine::ConnectedMonitorState::~ConnectedMonitorState() {}

void SelfCureStateMachine::ConnectedMonitorState::GoInState()
{
    WIFI_LOGI("ConnectedMonitorState GoInState function.");
    if (!pSelfCureStateMachine_->IsSuppOnCompletedState()) {
        WIFI_LOGI("%{public}s: Wifi connection not completed", __FUNCTION__);
        pSelfCureStateMachine_->MessageExecutedLater(
            WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD, SELF_CURE_MONITOR_DELAYED_MS);
    }
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_IDLE, false);
    pSelfCureStateMachine_->StopTimer(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD);
    SelfCureUtils::GetInstance().SetIpv6Disabled(false);
    IpQosMonitor::GetInstance().StartMonitor();
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    lastConnectedBssid_ = linkedInfo.bssid;
    pSelfCureStateMachine_->arpDetectionFailedCnt_ = 0;
    isHasInternetRecently_ = false;
    isPortalUnthenEver_ = false;
    pSelfCureStateMachine_->isInternetUnknown_ = false;
    isUserSetStaticIpConfig_ = false;
    isIpv4DnsEnabled_ = true;
    isWifiSwitchAllowed_ = false;
    isMobileHotspot_ = linkedInfo.isDataRestricted == 1 ? true : false;
    pSelfCureStateMachine_->connectNetworkRetryCnt_ = 0;
    WifiConfigCenter::GetInstance().SetLastNetworkId(linkedInfo.networkId);
    WifiConfigCenter::GetInstance().SetWifiSelfcureReset(false);
    pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(0);
    lastSignalLevel_ = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band,
        pSelfCureStateMachine_->instId_);
    lastDnsFailedCnt_ = 0;
    SelfCureUtils::GetInstance().ClearDnsFailedCounter();
    if (!SetupSelfCureMonitor()) {
        WIFI_LOGI("ConnectedMonitorState, config is null when connected broadcast received, delay to setup again.");
        pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR,
                                                     SELF_CURE_MONITOR_DELAYED_MS);
    }
    pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED,
                                                 FAST_ARP_DETECTED_MS);
    pSelfCureStateMachine_->MessageExecutedLater(CMD_INTERNET_STATUS_DETECT_INTERVAL,
                                                 INTERNET_STATUS_DETECT_INTERVAL_MS);
}

void SelfCureStateMachine::ConnectedMonitorState::GoOutState()
{
    WIFI_LOGI("ConnectedMonitorState GoOutState function.");
}

bool SelfCureStateMachine::ConnectedMonitorState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("ConnectedMonitorState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    auto iter = selfCureCmsHandleFuncMap_.find(msg->GetMessageName());
    if (iter != selfCureCmsHandleFuncMap_.end()) {
        (iter->second)(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

int SelfCureStateMachine::ConnectedMonitorState::InitSelfCureCmsHandleMap()
{
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR] = [this](InternalMessagePtr msg) {
        this->HandleResetupSelfCure(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_PERIODIC_ARP_DETECTED] = [this](InternalMessagePtr msg) {
        this->HandlePeriodicArpDetection(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_ARP_FAILED_DETECTED] = [this](InternalMessagePtr msg) {
        this->HandleArpDetectionFailed(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_INVALID_IP_CONFIRM] = [this](InternalMessagePtr msg) {
        this->HandleInvalidIp(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD] = [this](InternalMessagePtr msg) {
        this->HandleNetworkConnect(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD] = [this](InternalMessagePtr msg) {
        this->HandleNetworkDisconnect(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT] = [this](InternalMessagePtr msg) {
        this->HandleRssiLevelChange(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED] = [this](InternalMessagePtr msg) {
        this->HandleInternetFailedDetected(msg);
    };
    selfCureCmsHandleFuncMap_[CMD_INTERNET_STATUS_DETECT_INTERVAL] = [this](InternalMessagePtr msg) {
        this->HandleTcpQualityQuery(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT] = [this](InternalMessagePtr msg) {
        this->HandleGatewayChanged(msg);
    };
    selfCureCmsHandleFuncMap_[WIFI_CURE_CMD_DNS_FAILED_MONITOR] = [this](InternalMessagePtr msg) {
        this->HandleDnsFailedMonitor(msg);
    };
    return WIFI_OPT_SUCCESS;
}

void SelfCureStateMachine::ConnectedMonitorState::TransitionToSelfCureState(int reason)
{
    if (isMobileHotspot_ || pSelfCureStateMachine_->IsCustNetworkSelfCure()) {
        WIFI_LOGW("transitionToSelfCureState, don't support SCE, do nothing");
        return;
    }
    WIFI_LOGI("transitionToSelfCureState, reason is : %{public}d.", reason);
    IpInfo wifiIpInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(wifiIpInfo, pSelfCureStateMachine_->instId_);
    IpV6Info wifiIpv6Info;
    WifiConfigCenter::GetInstance().GetIpv6Info(wifiIpv6Info, pSelfCureStateMachine_->instId_);
    isIpv4DnsEnabled_ = wifiIpInfo.primaryDns != 0 || wifiIpInfo.secondDns != 0;
    isGatewayInvalid_ = wifiIpInfo.gateway == 0 && wifiIpv6Info.gateway == "";
    if (!isIpv4DnsEnabled_ || isGatewayInvalid_) {
        WIFI_LOGI("transitionToSelfCureState, don't support SCE, do nothing or isIpv4DnsEnabled_ = %{public}d.",
                  isIpv4DnsEnabled_);
        return;
    }
    pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, reason, SELF_CURE_DELAYED_MS);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pInternetSelfCureState_);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleResetupSelfCure(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleResetupSelfCure.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    SetupSelfCureMonitor();
}

void SelfCureStateMachine::ConnectedMonitorState::HandlePeriodicArpDetection(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandlePeriodicArpDetection.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine_->PeriodicArpDetection();
}

void SelfCureStateMachine::ConnectedMonitorState::HandleNetworkConnect(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleNetworkConnect.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    GoInState();
}

void SelfCureStateMachine::ConnectedMonitorState::HandleNetworkDisconnect(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleNetworkDisconnect.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine_->StopTimer(WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT);
    pSelfCureStateMachine_->StopTimer(WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleRssiLevelChange(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleRssiLevelChange.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    lastSignalLevel_ = pSelfCureStateMachine_->GetCurSignalLevel();
}

void SelfCureStateMachine::ConnectedMonitorState::HandleArpDetectionFailed(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleArpDetectionFailed.");
    if (pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, lastConnectedBssid_)) {
        return;
    }
    if (pSelfCureStateMachine_->IsHttpReachable()) {
        WIFI_LOGI("Http Reachable.");
        return;
    }
    pSelfCureStateMachine_->selfCureReason_ = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
    TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_TCP);
}

bool SelfCureStateMachine::ConnectedMonitorState::SetupSelfCureMonitor()
{
    WifiDeviceConfig config;
    if (pSelfCureStateMachine_->GetCurrentWifiDeviceConfig(config) == WIFI_OPT_SUCCESS) {
        configAuthType_ = pSelfCureStateMachine_->GetAuthType();
        AssignIpMethod ipAssignment;
        pSelfCureStateMachine_->GetIpAssignment(ipAssignment);
        isUserSetStaticIpConfig_ = ipAssignment == AssignIpMethod::STATIC;
        pSelfCureStateMachine_->isInternetUnknown_ = NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(
            pSelfCureStateMachine_->GetNetworkStatusHistory());
        isHasInternetRecently_ = NetworkStatusHistoryManager::IsInternetAccessByHistory(
            pSelfCureStateMachine_->GetNetworkStatusHistory());
        isPortalUnthenEver_ = NetworkStatusHistoryManager::IsPortalByHistory(
            pSelfCureStateMachine_->GetNetworkStatusHistory());
        WIFI_LOGI("SetupSelfCureMonitor, isInternetUnknown_: %{public}d," \
            " isHasInternetRecently_: %{public}d, isPortalUnthenEver_: %{public}d",
            pSelfCureStateMachine_->isInternetUnknown_, isHasInternetRecently_, isPortalUnthenEver_);
        if (!isMobileHotspot_) {
            if (IsGatewayChanged()) {
                WIFI_LOGI("current gateway is different with history gateway that has internet.");
                pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT,
                    GATEWAY_CHANGED_DETECT_DELAYED_MS);
                return true;
            }
        }
        /** setup dns failed monitor when connected (the router's dns server maybe disabled). */
        if ((!isMobileHotspot_) && (!pSelfCureStateMachine_->isStaticIpCureSuccess_) && isHasInternetRecently_) {
            pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_DNS_FAILED_MONITOR, INTERNET_DETECT_INTERVAL_MS);
        }
        return true;
    }
    return false;
}

bool SelfCureStateMachine::ConnectedMonitorState::IsGatewayChanged()
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("IsGatewayChanged get pEnhanceService service failed!");
        return false;
    }
    bool isChanged = false;
    pEnhanceService->IsGatewayChanged(isChanged);
    WIFI_LOGI("IsGatewayChanged, isChanged: %{public}d", isChanged);
    return isChanged;
}

void SelfCureStateMachine::ConnectedMonitorState::RequestReassocWithFactoryMac()
{
    pSelfCureStateMachine_->useWithRandMacAddress_ = FAC_MAC_REASSOC;
    pSelfCureStateMachine_->selfCureReason_ = WIFI_CURE_INTERNET_FAILED_RAND_MAC;
    TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_RAND_MAC);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleInvalidIp(InternalMessagePtr msg)
{
    if (pSelfCureStateMachine_->IsHttpReachable()) {
        pSelfCureStateMachine_->noTcpRxCounter_ = 0;
    } else {
        int selfCureType = pSelfCureStateMachine_->IsMultiDhcpOffer() ?
                            WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY :
                            WIFI_CURE_INTERNET_FAILED_INVALID_IP;
        pSelfCureStateMachine_->selfCureReason_ = selfCureType;
        TransitionToSelfCureState(selfCureType);
    }
}

void SelfCureStateMachine::ConnectedMonitorState::HandleDnsFailedMonitor(InternalMessagePtr msg)
{
    if (lastSignalLevel_ <= SIGNAL_LEVEL_1) {
        WIFI_LOGI("HandleDnsFailedMonitor, lastSignalLevel_ <= 1, next peroid.");
        lastDnsFailedCnt_ = SelfCureUtils::GetInstance().GetCurrentDnsFailedCounter();
        pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_DNS_FAILED_MONITOR, INTERNET_DETECT_INTERVAL_MS);
        return;
    }
    int32_t currentDnsFailedCnt = 0;
    currentDnsFailedCnt = SelfCureUtils::GetInstance().GetCurrentDnsFailedCounter();
    int32_t deltaFailedDns = (currentDnsFailedCnt - lastDnsFailedCnt_);
    WIFI_LOGI("HandleDnsFailedMonitor, deltaFailedDns is %{public}d", deltaFailedDns);
    lastDnsFailedCnt_ = currentDnsFailedCnt;
    if (deltaFailedDns >= DNS_FAILED_CNT) {
        if (pSelfCureStateMachine_->IsHttpReachable()) {
            WIFI_LOGI("HandleDnsFailedMonitor, HTTP detection succeeded.");
            return;
        }
        pSelfCureStateMachine_->selfCureReason_ = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_DNS);
    }
}

bool SelfCureStateMachine::ConnectedMonitorState::IsNeedSelfCure()
{
    if (pSelfCureStateMachine_->GetCurrentRssi() < MIN_VAL_LEVEL_3) {
        return false;
    }
    if (pSelfCureStateMachine_->IsCustNetworkSelfCure() || pSelfCureStateMachine_->isInternetFailureDetected_) {
        WIFI_LOGI("do not need selfcure, %{public}d", pSelfCureStateMachine_->isInternetFailureDetected_);
        return false;
    }

    if (!pSelfCureStateMachine_->IsSuppOnCompletedState()) {
        WIFI_LOGI("%{public}s: Wifi connection not completed", __FUNCTION__);
        return false;
    }
    pSelfCureStateMachine_->isInternetFailureDetected_ = true;
    return true;
}

void SelfCureStateMachine::ConnectedMonitorState::HandleInternetFailedDetected(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is null", __func__);
        return;
    }
    if (!IsNeedSelfCure()) {
        pSelfCureStateMachine_->isSelfcureDone_ = true;
        return;
    }
    WIFI_LOGI("HandleInternetFailedDetected, wifi has no internet when connected.");
    if (isMobileHotspot_ && !pSelfCureStateMachine_->IsWifi6Network(lastConnectedBssid_)) {
        WIFI_LOGI("don't support selfcure, do nothing, isMobileHotspot_ = %{public}d", isMobileHotspot_);
        return;
    }
    if (pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, lastConnectedBssid_)) {
        WIFI_LOGI("%{public}s: TransToWifi6SelfCure", __FUNCTION__);
        return;
    }

    if ((msg != nullptr) && (!pSelfCureStateMachine_->isInternetUnknown_)) {
        pSelfCureStateMachine_->isInternetUnknown_ = msg->GetParam1() == 1;
    }
    if (pSelfCureStateMachine_->IsNeedWifiReassocUseDeviceMac()) {
        RequestReassocWithFactoryMac();
        return;
    }
    // has no internet in history but not first connect, no need self cure
    bool forceNoHttpCheck = static_cast<bool>(msg->GetParam2());
    int64_t lastHasInetTime = static_cast<int64_t>(pSelfCureStateMachine_->GetLastHasInternetTime());
    if (lastHasInetTime <= 0 || lastHasInetTime < pSelfCureStateMachine_->connectedTime_) {
        forceNoHttpCheck = true;
    }

    if (!pSelfCureStateMachine_->isStaticIpCureSuccess_ && forceNoHttpCheck) {
        if (isHasInternetRecently_ || isPortalUnthenEver_ || pSelfCureStateMachine_->isInternetUnknown_) {
            pSelfCureStateMachine_->selfCureReason_ = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
            TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_DNS);
        } else {
            pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pNoInternetState_);
            WIFI_LOGI("Handle network disable, there is not a expectant condition!.");
        }
        return;
    }
    HandleInternetFailedDetectedInner();
}

void SelfCureStateMachine::ConnectedMonitorState::HandleInternetFailedDetectedInner()
{
    if (pSelfCureStateMachine_->IsHttpReachable()) {
        WIFI_LOGI("http is reachable, no need self cure");
        pSelfCureStateMachine_->noTcpRxCounter_ = 0;
        pSelfCureStateMachine_->isInternetFailureDetected_ = false;
        return;
    } else {
        int32_t currentDnsFailedCnt = SelfCureUtils::GetInstance().GetCurrentDnsFailedCounter();
        int32_t deltaFailedDns = (currentDnsFailedCnt - lastDnsFailedCnt_);
        lastDnsFailedCnt_ = currentDnsFailedCnt;
        pSelfCureStateMachine_->selfCureReason_ = deltaFailedDns >= DNS_FAILED_CNT ?
            WIFI_CURE_INTERNET_FAILED_TYPE_DNS : WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
    }
    WIFI_LOGI("HandleInternetFailedDetected, http unreachable, transition to SelfCureState,"
        "selfCureReason_: %{public}d", pSelfCureStateMachine_->selfCureReason_);
    TransitionToSelfCureState(pSelfCureStateMachine_->selfCureReason_);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleTcpQualityQuery(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine_->StopTimer(CMD_INTERNET_STATUS_DETECT_INTERVAL);
    if (WifiConfigCenter::GetInstance().GetScreenState() != MODE_STATE_CLOSE) {
        IpQosMonitor::GetInstance().QueryPackets();
        IpQosMonitor::GetInstance().QueryIpv6Packets();
    }
    pSelfCureStateMachine_->MessageExecutedLater(CMD_INTERNET_STATUS_DETECT_INTERVAL,
        INTERNET_STATUS_DETECT_INTERVAL_MS, MsgLogLevel::LOG_D);
}

void SelfCureStateMachine::ConnectedMonitorState::HandleGatewayChanged(InternalMessagePtr msg)
{
    WIFI_LOGI("enter HandleGatewayChanged");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    if (pSelfCureStateMachine_->IsMultiDhcpOffer() ||
        (isHasInternetRecently_ && pSelfCureStateMachine_->IsEncryptedAuthType(configAuthType_))) {
        if (pSelfCureStateMachine_->IsHttpReachable()) {
            return;
        }
        TransitionToSelfCureState(WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY);
    }
}

/* --------------------------- state machine disconnect monitor state ------------------------------ */
SelfCureStateMachine::DisconnectedMonitorState::DisconnectedMonitorState(SelfCureStateMachine *selfCureStateMachine)
    : State("DisconnectedMonitorState"),
      pSelfCureStateMachine_(selfCureStateMachine)
{
    WIFI_LOGD("DisconnectedMonitorState construct success.");
}

SelfCureStateMachine::DisconnectedMonitorState::~DisconnectedMonitorState() {}

void SelfCureStateMachine::DisconnectedMonitorState::GoInState()
{
    WIFI_LOGI("DisconnectedMonitorState GoInState function.");
    isSetStaticIpConfig_ = false;
    pSelfCureStateMachine_->isStaticIpCureSuccess_ = false;
    pSelfCureStateMachine_->isWifi6ArpSuccess_ = false;
    pSelfCureStateMachine_->isHasTestWifi6Reassoc_ = false;
    pSelfCureStateMachine_->noAutoConnCounter_ = 0;
    pSelfCureStateMachine_->noAutoConnReason_ = -1;
    pSelfCureStateMachine_->connectedTime_ = 0;
    pSelfCureStateMachine_->isInternetFailureDetected_ = false;
    pSelfCureStateMachine_->isSelfcureDone_ = false;
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_IDLE, false);
    pSelfCureStateMachine_->ClearDhcpOffer();
    pSelfCureStateMachine_->HandleWifiBlackListUpdateMsg();
}

void SelfCureStateMachine::DisconnectedMonitorState::GoOutState()
{
    WIFI_LOGI("DisconnectedMonitorState GoOutState function.");
}

bool SelfCureStateMachine::DisconnectedMonitorState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("DisconnectedMonitorState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD:
            ret = EXECUTED;
            pSelfCureStateMachine_->HandleNetworkConnected();
            pSelfCureStateMachine_->CheckConflictIpForSoftAp();
            break;
        case WIFI_CURE_CMD_WIFI7_DISCONNECT_COUNT:
            ret = EXECUTED;
            HandleNetworkConnectFailCount(msg);
            break;
        case WIFI_CURE_CMD_WIFI7_MLD_BACKOFF:
            ret = EXECUTED;
            HandleWifi7MldBackoff(msg);
            break;
        case WIFI_CURE_CMD_WIFI7_NON_MLD_BACKOFF:
            ret = EXECUTED;
            HandleWifi7WithoutMldBackoff(msg);
            break;
        case WIFI_CURE_CMD_WIFI7_BACKOFF_RECOVER:
            ret = EXECUTED;
            HandleWifi7BlacklistRecover(msg);
            break;
        default:
            WIFI_LOGD("DisconnectedMonitorState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

void SelfCureStateMachine::DisconnectedMonitorState::HandleWifi7BlacklistRecover(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s: msg is nullptr.", __FUNCTION__);
        return;
    }
    WifiLinkedInfo info;
    msg->GetMessageObj(info);
    if (info.bssid.empty()) {
        WIFI_LOGE("%{public}s: lastconnect bssid is empty.", __FUNCTION__);
        return;
    }
    WIFI_LOGI("remove %{public}s from wifi7 blalist.", MacAnonymize(info.bssid).c_str());
    WifiConfigCenter::GetInstance().RemoveWifiCategoryBlackListCache(EVENT_BE_BLA_LIST, info.bssid);
    pSelfCureStateMachine_->SendBlaListToDriver(EVENT_BE_BLA_LIST);
}

void SelfCureStateMachine::DisconnectedMonitorState::HandleWifi7WithoutMldBackoff(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s: msg is nullptr.", __FUNCTION__);
        return;
    }
    WifiLinkedInfo info;
    msg->GetMessageObj(info);
    if (info.bssid.empty()) {
        WIFI_LOGE("%{public}s: lastconnect bssid is empty.", __FUNCTION__);
        return;
    }
    WifiCategoryBlackListInfo wifi7BlackListInfo(ACTION_TYPE_WIFI7, GetCurrentTimeMilliSeconds());
    WifiConfigCenter::GetInstance().InsertWifiCategoryBlackListCache(EVENT_BE_BLA_LIST, info.bssid, wifi7BlackListInfo);
    WIFI_LOGI("add %{public}s to wifi7 blalist.", MacAnonymize(info.bssid).c_str());
    pSelfCureStateMachine_->SendBlaListToDriver(EVENT_BE_BLA_LIST);

    WifiCategoryConnectFailInfo wifi7ConnectFailInfo(ACTION_TYPE_RECOVER_FAIL,
        0, GetCurrentTimeMilliSeconds());
    WifiConfigCenter::GetInstance().UpdateWifiConnectFailListCache(EVENT_BE_BLA_LIST, info.bssid, wifi7ConnectFailInfo);
}

void SelfCureStateMachine::DisconnectedMonitorState::HandleWifi7MldBackoff(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s: msg is nullptr.", __FUNCTION__);
        return;
    }
    WifiLinkedInfo info;
    msg->GetMessageObj(info);
    if (info.bssid.empty()) {
        WIFI_LOGE("%{public}s: lastconnect bssid is empty.", __FUNCTION__);
        return;
    }
    WifiCategoryBlackListInfo wifi7BlackListInfo(ACTION_TYPE_MLD, GetCurrentTimeMilliSeconds());
    WifiConfigCenter::GetInstance().InsertWifiCategoryBlackListCache(EVENT_BE_BLA_LIST, info.bssid, wifi7BlackListInfo);
    WIFI_LOGI("add %{public}s to wifi7 blalist.", MacAnonymize(info.bssid).c_str());
    pSelfCureStateMachine_->SendBlaListToDriver(EVENT_BE_BLA_LIST);

    WifiCategoryConnectFailInfo wifi7ConnectFailInfo(ACTION_TYPE_WIFI7, 0,
                                                    GetCurrentTimeMilliSeconds());
    WifiConfigCenter::GetInstance().UpdateWifiConnectFailListCache(EVENT_BE_BLA_LIST, info.bssid, wifi7ConnectFailInfo);
}

void SelfCureStateMachine::DisconnectedMonitorState::HandleNetworkConnectFailCount(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s: msg is nullptr.", __FUNCTION__);
        return;
    }
    WifiLinkedInfo info;
    msg->GetMessageObj(info);
    if (info.bssid.empty()) {
        WIFI_LOGE("%{public}s: lastconnect bssid is empty.", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine_->AgeOutWifiConnectFailList();
    int actionType = ACTION_TYPE_MLD;
    std::map<std::string, WifiCategoryConnectFailInfo> connectFailCache;
    WifiConfigCenter::GetInstance().GetWifiConnectFailListCache(connectFailCache);
    WIFI_LOGI("add %{public}s to wifi7 connect fail list.", MacAnonymize(info.bssid).c_str());
    if (connectFailCache.find(info.bssid) != connectFailCache.end()) {
        actionType = connectFailCache[info.bssid].actionType;
    }
    WifiCategoryConnectFailInfo wifi7ConnectFailInfo(actionType, 1, GetCurrentTimeMilliSeconds());
    WifiConfigCenter::GetInstance().UpdateWifiConnectFailListCache(EVENT_BE_BLA_LIST, info.bssid, wifi7ConnectFailInfo);
    pSelfCureStateMachine_->ShouldTransToWifi7SelfCure(info);
}

/* --------------------------- state machine connection self cure state ------------------------------ */
SelfCureStateMachine::ConnectionSelfCureState::ConnectionSelfCureState(SelfCureStateMachine *selfCureStateMachine)
    : State("ConnectionSelfCureState"),
      pSelfCureStateMachine_(selfCureStateMachine)
{
    WIFI_LOGD("ConnectionSelfCureState construct success.");
}

SelfCureStateMachine::ConnectionSelfCureState::~ConnectionSelfCureState() {}

void SelfCureStateMachine::ConnectionSelfCureState::GoInState()
{
    WIFI_LOGI("ConnectionSelfCureState GoInState function.");
}

void SelfCureStateMachine::ConnectionSelfCureState::GoOutState()
{
    WIFI_LOGI("ConnectionSelfCureState GoOutState function.");
}

bool SelfCureStateMachine::ConnectionSelfCureState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("ConnectionSelfCureState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case 0: {
            ret = EXECUTED;
            pSelfCureStateMachine_->GetAuthType();
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
      pSelfCureStateMachine_(selfCureStateMachine)
{
    InitSelfCureIssHandleMap();
    WIFI_LOGD("InternetSelfCureState construct success.");
}

SelfCureStateMachine::InternetSelfCureState::~InternetSelfCureState() {}

void SelfCureStateMachine::InternetSelfCureState::GoInState()
{
    WIFI_LOGI("InternetSelfCureState GoInState function.");
    currentRssi_ = CURRENT_RSSI_INIT;
    currentAbnormalType_ = -1;
    currentSelfCureLevel_ = WIFI_CURE_RESET_LEVEL_IDLE;
    isHasInternetRecently_ = false;
    isPortalUnthenEver_ = false;
    isUserSetStaticIpConfig_ = false;
    testedSelfCureLevel_.clear();
    isFinalSelfCureUsed_ = false;
    isDelayedReassocSelfCure_ = false;
    isDelayedRandMacReassocSelfCure_ = false;
    isDelayedResetSelfCure_ = false;
    isSetStaticIp4InvalidIp_ = false;
    unConflictedIp_ = "";
    renewDhcpCount_ = 0;
    lastMultiGwSelfFailedType_ = -1;
    isUsedMultiGwSelfcure_ = false;
    pSelfCureStateMachine_->selfCureWifiLastState_ = WifiState::UNKNOWN;
    pSelfCureStateMachine_->selfCureL2State_ = SelfCureState::SCE_WIFI_INVALID_STATE;
    WifiConfigCenter::GetInstance().SetWifiSelfcureReset(false);

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    currentRssi_ = linkedInfo.rssi;
    currentBssid_ = linkedInfo.bssid;
    pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, DEFAULT_ARP_DETECTED_MS);
    SelfCureUtils::GetInstance().String2InternetSelfCureHistoryInfo(pSelfCureStateMachine_->GetSelfCureHistoryInfo(),
                                                                    selfCureHistoryInfo_);
    isHasInternetRecently_ = NetworkStatusHistoryManager::IsInternetAccessByHistory(
        pSelfCureStateMachine_->GetNetworkStatusHistory());
    isPortalUnthenEver_ = NetworkStatusHistoryManager::IsPortalByHistory(
        pSelfCureStateMachine_->GetNetworkStatusHistory());
    AssignIpMethod ipAssignment;
    pSelfCureStateMachine_->GetIpAssignment(ipAssignment);
    isUserSetStaticIpConfig_ = ipAssignment == AssignIpMethod::STATIC;
    lastHasInetTime_ = pSelfCureStateMachine_->GetLastHasInternetTime();
    configAuthType_ = pSelfCureStateMachine_->GetAuthType();
    WIFI_LOGI("isHasInternetRecently_: %{public}d, isPortalUnthenEver_: %{public}d, selfCureHistoryInfo_: %{public}s",
        isHasInternetRecently_, isPortalUnthenEver_, pSelfCureStateMachine_->GetSelfCureHistoryInfo().c_str());
    InitCurrentGateway();
}

void SelfCureStateMachine::InternetSelfCureState::GoOutState()
{
    WIFI_LOGI("InternetSelfCureState GoOutState function.");
    pSelfCureStateMachine_->UpdateSelfcureState(currentSelfCureLevel_, false);
    pSelfCureStateMachine_->ResetSelfCureParam();
}

bool SelfCureStateMachine::InternetSelfCureState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("InternetSelfCureState-msgCode = %{public}d is received.\n", msg->GetMessageName());
    auto iter = selfCureIssHandleFuncMap_.find(msg->GetMessageName());
    if (iter != selfCureIssHandleFuncMap_.end()) {
        (iter->second)(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

int SelfCureStateMachine::InternetSelfCureState::InitSelfCureIssHandleMap()
{
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE] = [this](InternalMessagePtr msg) {
        this->HandleInternetFailedSelfCure(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_SELF_CURE_WIFI_LINK] = [this](InternalMessagePtr msg) {
        this->HandleSelfCureWifiLink(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD] = [this](InternalMessagePtr msg) {
        this->HandleNetworkDisconnected(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM] = [this](InternalMessagePtr msg) {
        this->HandleInternetRecoveryConfirm(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT] = [this](InternalMessagePtr msg) {
        this->HandleRssiChangedEvent(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT] = [this](InternalMessagePtr msg) {
        this->HandleP2pDisconnected(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_PERIODIC_ARP_DETECTED] = [this](InternalMessagePtr msg) {
        this->HandlePeriodicArpDetecte(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_ARP_FAILED_DETECTED] = [this](InternalMessagePtr msg) {
        this->HandleArpFailedDetected(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_HTTP_REACHABLE_RCV] = [this](InternalMessagePtr msg) {
        this->HandleHttpReachableRecv(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_MULTI_GATEWAY] = [this](InternalMessagePtr msg) {
        this->SelfcureForMultiGateway(msg);
    };
    selfCureIssHandleFuncMap_[WIFI_CURE_CMD_SELF_CURE_FAILED] = [this](InternalMessagePtr msg) {
        this->HandleSelfCureResultFailed(msg);
    };
    return WIFI_OPT_SUCCESS;
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetFailedSelfCure(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleInternetFailedSelfCure.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    if (!pSelfCureStateMachine_->IsSuppOnCompletedState()) {
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
        return;
    }
    SelectSelfCureByFailedReason(msg->GetParam1());
}

void SelfCureStateMachine::InternetSelfCureState::HandleSelfCureWifiLink(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleSelfCureWifiLink.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    if (!pSelfCureStateMachine_->IsSuppOnCompletedState()) {
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
        return;
    }
    currentSelfCureLevel_ = msg->GetParam1();
    SelfCureWifiLink(msg->GetParam1());
}

void SelfCureStateMachine::InternetSelfCureState::HandleNetworkDisconnected(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleNetworkDisconnected.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine_->StopTimer(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetRecoveryConfirm(InternalMessagePtr msg)
{
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(selfCureHistoryInfo_, currentSelfCureLevel_, true);
    bool success = ConfirmInternetSelfCure(currentSelfCureLevel_);
    if (success) {
        pSelfCureStateMachine_->isInternetFailureDetected_ = false;
        currentSelfCureLevel_ = WIFI_CURE_RESET_LEVEL_IDLE;
        isHasInternetRecently_ = true;
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleRssiChangedEvent(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleRssiChangedEvent.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    currentRssi_ = msg->GetParam1();
    HandleRssiChanged();
}

void SelfCureStateMachine::InternetSelfCureState::HandleP2pDisconnected(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleP2pDisconnected.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    HandleRssiChanged();
}

void SelfCureStateMachine::InternetSelfCureState::HandlePeriodicArpDetecte(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandlePeriodicArpDetecte.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine_->PeriodicArpDetection();
}

void SelfCureStateMachine::InternetSelfCureState::HandleHttpReachableRecv(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleHttpReachableRecv.");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pSelfCureStateMachine_->SetSelfCureHistoryInfo(INIT_SELFCURE_HISTORY);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
}

void SelfCureStateMachine::InternetSelfCureState::HandleArpFailedDetected(InternalMessagePtr msg)
{
    WIFI_LOGD("enter HandleArpFailedDetected.");
    if (pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currentBssid_)) {
        return;
    }
    if (pSelfCureStateMachine_->isSelfCureOnGoing_) {
        return;
    }
    if (!pSelfCureStateMachine_->IsHttpReachable()) {
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC);
    }
}

void SelfCureStateMachine::InternetSelfCureState::SelectSelfCureByFailedReason(int internetFailedType)
{
    WIFI_LOGI("SelectSelfCureByFailedReason, internetFailedType = %{public}d, isUserSetStaticIpConfig_ = %{public}d",
              internetFailedType, isUserSetStaticIpConfig_);

    if (IsNeedMultiGatewaySelfcure()) {
        WIFI_LOGI("start multi gateway selfcure");
        lastMultiGwSelfFailedType_ = internetFailedType;
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_MULTI_GATEWAY);
        return;
    }

    if (isUserSetStaticIpConfig_ && ((internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS) ||
                                     (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY))) {
        HandleInternetFailedAndUserSetStaticIp(internetFailedType);
        return;
    }
    int requestSelfCureLevel = SelectBestSelfCureSolution(internetFailedType);
    if (requestSelfCureLevel != WIFI_CURE_RESET_LEVEL_IDLE) {
        currentAbnormalType_ = internetFailedType;
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, requestSelfCureLevel);
        return;
    }
    if (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        WIFI_LOGI("SelectSelfCureByFailedReason, use wifi reset to cure this failed type = %{public}d",
                  internetFailedType);
        currentAbnormalType_ = internetFailedType;
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_HIGH_RESET);
        return;
    }
    WIFI_LOGI("SelectSelfCureByFailedReason, no usable self cure for this failed type = %{public}d",
              internetFailedType);
    HandleHttpUnreachableFinally();
}

int SelfCureStateMachine::InternetSelfCureState::SelectBestSelfCureSolution(int internetFailedType)
{
    int bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
    bool multipleDhcpServer = pSelfCureStateMachine_->IsMultiDhcpOffer();
    bool noInternetWhenConnected =
        (lastHasInetTime_ <= 0 || lastHasInetTime_ < pSelfCureStateMachine_->connectedTime_);
    WIFI_LOGD("SelectBestSelfCureSolution, multipleDhcpServer = %{public}d, noInternetWhenConnected = %{public}d",
              multipleDhcpServer, noInternetWhenConnected);

    if ((multipleDhcpServer) && (noInternetWhenConnected) && (GetNextTestDhcpResults().ipAddress != 0) &&
        (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_,
                                                         WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP)) &&
        ((internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS) ||
        (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_TCP))) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        isConfigStaticIp4MultiDhcpServer_ = true;
    } else if ((internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY) &&
                (multipleDhcpServer) && (GetNextTestDhcpResults().ipAddress != 0) &&
                (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_,
                WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP))) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        isConfigStaticIp4MultiDhcpServer_ = true;
    } else if ((internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY) &&
                pSelfCureStateMachine_->IsEncryptedAuthType(configAuthType_) &&
                (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_,
                WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP))) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
    } else {
        bestSelfCureLevel = SelectBestSelfCureSolutionExt(internetFailedType);
    }
    WIFI_LOGI("SelectBestSelfCureSolution, internetFailedType = %{public}d, bestSelfCureLevel = %{public}d",
              internetFailedType, bestSelfCureLevel);
    return bestSelfCureLevel;
}

int SelfCureStateMachine::InternetSelfCureState::SelectBestSelfCureSolutionExt(int internetFailedType)
{
    int bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
    if (internetFailedType == WIFI_CURE_INTERNET_FAILED_INVALID_IP) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_DNS &&
                SelfCureUtils::GetInstance().SelfCureAcceptable(
                    selfCureHistoryInfo_,
                    WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_RAND_MAC &&
                SelfCureUtils::GetInstance().SelfCureAcceptable(
                    selfCureHistoryInfo_,
                    WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    } else if (internetFailedType == WIFI_CURE_INTERNET_FAILED_TYPE_TCP &&
                SelfCureUtils::GetInstance().SelfCureAcceptable(
                    selfCureHistoryInfo_,
                    WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC)) {
        bestSelfCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    }
    return bestSelfCureLevel;
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureWifiLink(int requestCureLevel)
{
    WIFI_LOGI("SelfCureWifiLink, requestCureLevel = %{public}d, currentRssi_ = %{public}d",
        requestCureLevel, currentRssi_);
    if (requestCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        SelfCureForStaticIp(requestCureLevel);
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP) {
        SelfCureForInvalidIp();
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        SelfCureForReassoc(requestCureLevel);
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        SelfCureForRandMacReassoc(requestCureLevel);
    } else if (requestCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
        SelfCureForReset(requestCureLevel);
    }
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForInvalidIp()
{
    WIFI_LOGI("begin to self cure for internet access: InvalidIp");
    IpInfo dhcpResults;
    pSelfCureStateMachine_->GetLegalIpConfiguration(dhcpResults);
    unConflictedIp_ = IpTools::ConvertIpv4Address(dhcpResults.ipAddress);
    if (selfCureForInvalidIpCnt_ < MAX_SELF_CURE_CNT_INVALID_IP) {
        IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
        if (pStaService == nullptr) {
            WIFI_LOGE("Get pStaService failed!");
            return;
        }
        if (pStaService->Disconnect()!=WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Disconnect failed.\n");
        }
        selfCureForInvalidIpCnt_++;
    }
}

IpInfo SelfCureStateMachine::InternetSelfCureState::GetNextTestDhcpResults()
{
    IpInfo ipInfo;
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("GetNextTestDhcpResults get pEnhanceService service failed!");
        return ipInfo;
    }
    bool isMultiDhcpServer = true;
    bool startSelfcure = false;
    pEnhanceService->GetStaticIpConfig(isMultiDhcpServer, startSelfcure, ipInfo);
    return ipInfo;
}

IpInfo SelfCureStateMachine::InternetSelfCureState::GetRecordDhcpResults()
{
    IpInfo ipInfo;
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("GetRecordDhcpResults get pEnhanceService service failed!");
        return ipInfo;
    }
    bool isMultiDhcpServer = false;
    bool startSelfcure = false;
    pEnhanceService->GetStaticIpConfig(isMultiDhcpServer, startSelfcure, ipInfo);
    std::string gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    if (!pSelfCureStateMachine_->DoSlowArpTest(gateway)) {
        pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM,
            DHCP_CONFIRM_DELAYED_MS);
        IpInfo dhcpResult;
        return dhcpResult;
    }
    return ipInfo;
}

void SelfCureStateMachine::InternetSelfCureState::InitCurrentGateway()
{
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, pSelfCureStateMachine_->instId_);
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("InitCurrentGateway get pEnhanceService service failed!");
        return;
    }
    uint32_t retSize = 0;
    pEnhanceService->DealDhcpOfferResult(OperationCmd::CURRENT_IP_INFO_SET, ipInfo, retSize);
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForStaticIp(int requestCureLevel)
{
    IpInfo dhcpResult;
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("SelfCureForStaticIp get pEnhanceService service failed!");
        return;
    }
    bool isMultiDhcpServer = isConfigStaticIp4MultiDhcpServer_ ? true : false;
    bool startSelfcure = true;
    if (isMultiDhcpServer) {
        pEnhanceService->GetStaticIpConfig(isMultiDhcpServer, startSelfcure, dhcpResult);
    } else {
        dhcpResult = GetRecordDhcpResults();
    }
    if (dhcpResult.gateway == 0 || dhcpResult.ipAddress == 0) {
        WIFI_LOGE("%{public}s: dhcpResult is null", __FUNCTION__);
        return;
    }
    std::string gatewayKey = IpTools::ConvertIpv4Address(dhcpResult.gateway);
    WIFI_LOGI("begin to self cure for internet access: TRY_NEXT_DHCP_OFFER");
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP, true);
    EnhanceWriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::GATEWAY_ABNORMAL));
    RequestUseStaticIpConfig(dhcpResult);
}

void SelfCureStateMachine::InternetSelfCureState::RequestUseStaticIpConfig(IpInfo &dhcpResult)
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, pSelfCureStateMachine_->instId_);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        return;
    }
    IpV6Info wifiIpV6Info;
    WifiConfigCenter::GetInstance().GetIpv6Info(wifiIpV6Info, pSelfCureStateMachine_->instId_);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config);
    WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(
        dhcpResult, wifiIpV6Info, config.wifiProxyconfig,
        pSelfCureStateMachine_->instId_);
    linkedInfo.ipAddress = dhcpResult.ipAddress;
    WifiConfigCenter::GetInstance().SaveIpInfo(dhcpResult);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, pSelfCureStateMachine_->instId_);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CONNECTION_CHANGE;
    cbMsg.msgData = ConnState::CONNECTED;
    cbMsg.linkInfo = linkedInfo;
    cbMsg.id = pSelfCureStateMachine_->instId_;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM, HTTP_DETECT_TIMEOUT);
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForReassoc(int requestCureLevel)
{
    if ((currentRssi_ < MIN_VAL_LEVEL_3) || pSelfCureStateMachine_->IfP2pConnected() ||
        pSelfCureStateMachine_->isP2pEnhanceConnected_) {
        WIFI_LOGI("delay reassoc selfcure");
        isDelayedReassocSelfCure_ = true;
        return;
    }
    WIFI_LOGI("begin to self cure for internet access: Reassoc");
    EnhanceWriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::TCP_RX_ABNORMAL));
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, true);
    testedSelfCureLevel_.push_back(requestCureLevel);
    isDelayedReassocSelfCure_ = false;
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Get pStaService failed!");
        return;
    }
    if (pStaService->ReAssociate() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ReAssociate failed.\n");
    }
    pSelfCureStateMachine_->SetSelfCureWifiTimeOut(SelfCureState::SCE_WIFI_REASSOC_STATE);
}

bool SelfCureStateMachine::InternetSelfCureState::IsNeedMultiGatewaySelfcure()
{
    WIFI_LOGI("isUsedMultiGwSelfcure_ is %{public}d", isUsedMultiGwSelfcure_);
    if (isUsedMultiGwSelfcure_) {
        return false;
    }
    return pSelfCureStateMachine_->IfMultiGateway();
}

void SelfCureStateMachine::InternetSelfCureState::SelfcureForMultiGateway(InternalMessagePtr msg)
{
    WIFI_LOGI("begin to self cure for internet access: multi gateway");
    if (!pSelfCureStateMachine_->IsSuppOnCompletedState()) {
        WIFI_LOGW("it is not connect, no need selfcure");
        return;
    }
    isUsedMultiGwSelfcure_ = true;
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY, true);
    std::string ipAddr = MultiGateway::GetInstance().GetGatewayIp();
    std::string macString = "";
    MultiGateway::GetInstance().GetNextGatewayMac(macString);
    if (macString.empty() || ipAddr.empty()) {
        WIFI_LOGE("macString or ipAddr is nullptr");
        pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY, false);
        if (lastMultiGwSelfFailedType_ != -1) {
            SelectSelfCureByFailedReason(lastMultiGwSelfFailedType_);
        }
        return;
    }

    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName();
    MultiGateway::GetInstance().SetStaticArp(ifaceName, ipAddr, macString);
    if (!pSelfCureStateMachine_->IsHttpReachable()) {
        MultiGateway::GetInstance().DelStaticArp(ifaceName, ipAddr);
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_MULTI_GATEWAY);
    } else {
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleSelfCureResultFailed(InternalMessagePtr msg)
{
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(selfCureHistoryInfo_, currentSelfCureLevel_, false);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForRandMacReassoc(int requestCureLevel)
{
    if ((currentRssi_ < MIN_VAL_LEVEL_3) || pSelfCureStateMachine_->IfP2pConnected() ||
        pSelfCureStateMachine_->isP2pEnhanceConnected_) {
        isDelayedRandMacReassocSelfCure_ = true;
        WIFI_LOGW("delay randmac self cure");
        return;
    }
    WIFI_LOGI("begin to self cure for internet access: RandMacReassoc");
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, true);
    isDelayedRandMacReassocSelfCure_ = false;
    pSelfCureStateMachine_->useWithRandMacAddress_ = FAC_MAC_REASSOC;
    pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(FAC_MAC_REASSOC);
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    WifiConfigCenter::GetInstance().SetLastNetworkId(networkId);
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Get pStaService failed!");
        return;
    }
    pStaService->Disconnect();
    pSelfCureStateMachine_->SetSelfCureWifiTimeOut(SelfCureState::SCE_WIFI_DISCONNECT_STATE);
}

void SelfCureStateMachine::InternetSelfCureState::SelfCureForReset(int requestCureLevel)
{
    WIFI_LOGI("enter SelfCureForReset, isInternetUnknown_: %{public}d, isHasInternetRecently_: %{public}d",
        pSelfCureStateMachine_->isInternetUnknown_, isHasInternetRecently_);
    if ((pSelfCureStateMachine_->isInternetUnknown_) || (!isHasInternetRecently_) ||
        (pSelfCureStateMachine_->IsSettingsPage())) {
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pNoInternetState_);
        return;
    }

    if ((currentRssi_ < MIN_VAL_LEVEL_3_5) || pSelfCureStateMachine_->IfP2pConnected() ||
        pSelfCureStateMachine_->isP2pEnhanceConnected_) {
        WIFI_LOGI("delay Reset self cure");
        isDelayedResetSelfCure_ = true;
        return;
    }
    WIFI_LOGI("begin to self cure for internet access: Reset");

    pSelfCureStateMachine_->SetSelfCureWifiTimeOut(SelfCureState::SCE_WIFI_OFF_STATE);
    WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(true);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_HIGH_RESET, true);
    pSelfCureStateMachine_->StopTimer(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
    isDelayedResetSelfCure_ = false;
    testedSelfCureLevel_.push_back(requestCureLevel);

    WifiLinkedInfo wifiLinkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(wifiLinkedInfo);
    WifiConfigCenter::GetInstance().SetLastNetworkId(wifiLinkedInfo.networkId);
    WifiConfigCenter::GetInstance().SetWifiSelfcureReset(true);
    if (WifiManager::GetInstance().GetWifiTogglerManager() == nullptr) {
        WIFI_LOGE("SelfCureForReset, GetWifiTogglerManager get failed");
        return;
    }
    auto &wifiControllerMachine = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    if (wifiControllerMachine == nullptr) {
        WIFI_LOGE("selfcureForReset, wifiControllerMachine get failed");
        return;
    }
    wifiControllerMachine->SelfcureResetWifi(pSelfCureStateMachine_->instId_);
}

bool SelfCureStateMachine::InternetSelfCureState::SelectedSelfCureAcceptable()
{
    if (currentAbnormalType_ == WIFI_CURE_INTERNET_FAILED_TYPE_DNS ||
        currentAbnormalType_ == WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY) {
        if (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
            WIFI_LOGD("HTTP unreachable, use dns replace to cure for dns failed.");
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                WIFI_CURE_RESET_LEVEL_HIGH_RESET, 0);
            return true;
        }
    } else if (currentAbnormalType_ == WIFI_CURE_INTERNET_FAILED_TYPE_TCP) {
        if (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_,
            WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC)) {
            WIFI_LOGD("HTTP unreachable, use reassoc to cure for no rx pkt.");
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC,
                                                0);
            return true;
        }
    }
    return false;
}

void SelfCureStateMachine::InternetSelfCureState::HandleInternetFailedAndUserSetStaticIp(int internetFailedType)
{
    if (isHasInternetRecently_ &&
        SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK, WIFI_CURE_RESET_LEVEL_HIGH_RESET);
        return;
    }
    WIFI_LOGI("user set static ip config, ignore to update config for user.");
    if (!pSelfCureStateMachine_->isInternetUnknown_) {
        currentAbnormalType_ = WIFI_CURE_RESET_REJECTED_BY_STATIC_IP_ENABLED;
    }
}

bool SelfCureStateMachine::InternetSelfCureState::ConfirmInternetSelfCure(int currentCureLevel)
{
    WIFI_LOGI("ConfirmInternetSelfCure, cureLevel = %{public}d, finally = %{public}d",
        currentCureLevel, isFinalSelfCureUsed_);
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_IDLE) {
        return false;
    }
    if (pSelfCureStateMachine_->IsHttpReachable()) {
        HandleHttpReachableAfterSelfCure(currentCureLevel);
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
        return true;
    }
    HandleConfirmInternetSelfCureFailed(currentCureLevel);
    return false;
}

void SelfCureStateMachine::InternetSelfCureState::HandleConfirmInternetSelfCureFailed(int currentCureLevel)
{
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC) {
        HandleSelfCureFailedForRandMacReassoc();
        return;
    }
    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(selfCureHistoryInfo_, currentCureLevel, false);
    pSelfCureStateMachine_->SetSelfCureHistoryInfo(selfCureHistoryInfo_.GetSelfCureHistory());
    WIFI_LOGI("HTTP unreachable, self cure failed for %{public}d, selfCureHistoryInfo_ = %{public}s", currentCureLevel,
              pSelfCureStateMachine_->GetSelfCureHistoryInfo().c_str());
    pSelfCureStateMachine_->UpdateSelfcureState(currentCureLevel, false);
    if (isFinalSelfCureUsed_) {
        HandleHttpUnreachableFinally();
        return;
    }
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC &&
        pSelfCureStateMachine_->isHasTestWifi6Reassoc_ &&
        pSelfCureStateMachine_->IsNeedWifiReassocUseDeviceMac()) {
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE,
                                            WIFI_CURE_INTERNET_FAILED_RAND_MAC);
        return;
    }
    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        if (GetNextTestDhcpResults().ipAddress != 0) {
            WIFI_LOGI("HTTP unreachable, and has next dhcp results, try next one.");
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP, 0);
            return;
        }
        isConfigStaticIp4MultiDhcpServer_ = false;
        if (SelectedSelfCureAcceptable()) {
            return;
        }
    }
    if (!HasBeenTested(WIFI_CURE_RESET_LEVEL_HIGH_RESET) &&
        SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_HIGH_RESET)) {
        pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, WIFI_CURE_RESET_LEVEL_HIGH_RESET);
    } else {
        HandleHttpUnreachableFinally();
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleSelfCureFailedForRandMacReassoc()
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    if (pSelfCureStateMachine_->useWithRandMacAddress_ == FAC_MAC_REASSOC &&
        pSelfCureStateMachine_->IsUseFactoryMac()) {
        WIFI_LOGI("HTTP unreachable, factory mac failed and use rand mac instead of");
        pSelfCureStateMachine_->useWithRandMacAddress_ = RAND_MAC_REASSOC;
        pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(RAND_MAC_REASSOC);
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
        int networkId = linkedInfo.networkId;
        WifiConfigCenter::GetInstance().SetLastNetworkId(networkId);
        IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
        if (pStaService == nullptr) {
            WIFI_LOGE("Get pStaService failed!");
            return;
        }
        pStaService->Disconnect();
        pSelfCureStateMachine_->SetSelfCureWifiTimeOut(SelfCureState::SCE_WIFI_DISCONNECT_STATE);
        return;
    }
    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(selfCureHistoryInfo_,
                                                           WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, false);
    WIFI_LOGI("HTTP unreachable, self cure failed for rand mac reassoc");
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, false);
    pSelfCureStateMachine_->useWithRandMacAddress_ = 0;
    pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(0);
    pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE, WIFI_CURE_INTERNET_FAILED_TYPE_DNS);
}

void SelfCureStateMachine::InternetSelfCureState::HandleHttpReachableAfterSelfCure(int currentCureLevel)
{
    WIFI_LOGI("HandleHttpReachableAfterSelfCure, currentCureLevel = %{public}d", currentCureLevel);
    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(selfCureHistoryInfo_, currentCureLevel, true);
    pSelfCureStateMachine_->UpdateSelfcureState(currentSelfCureLevel_, false);
    if (!isSetStaticIp4InvalidIp_ && currentCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        currentAbnormalType_ = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine_->RequestArpConflictTest();
        pSelfCureStateMachine_->isStaticIpCureSuccess_ = true;
    }

    if (currentCureLevel == WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP) {
        EnhanceWriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::STATIC_IP_SELFCURE_SUCC));
    } else if (currentCureLevel == WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC) {
        EnhanceWriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::REASSOC_SELFCURE_SUCC));
    } else if (currentCureLevel == WIFI_CURE_RESET_LEVEL_HIGH_RESET) {
        EnhanceWriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::RESET_SELFCURE_SUCC));
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleHttpUnreachableFinally()
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pNoInternetState_);
}

bool SelfCureStateMachine::InternetSelfCureState::HasBeenTested(int cureLevel)
{
    for (int itemTestedSelfCureLevel : testedSelfCureLevel_) {
        if (itemTestedSelfCureLevel == cureLevel) {
            return true;
        }
    }
    return false;
}

void SelfCureStateMachine::InternetSelfCureState::HandleRssiChanged()
{
    if (currentRssi_ < MIN_VAL_LEVEL_3_5 || pSelfCureStateMachine_->isP2pEnhanceConnected_ ||
        pSelfCureStateMachine_->isP2pConnected_) {
        WIFI_LOGW("no need deal rssi change");
        return;
    }

    if (isDelayedResetSelfCure_) {
        HandleDelayedResetSelfCure();
        return;
    }
    if (!pSelfCureStateMachine_->isSelfCureOnGoing_ &&
        (isDelayedReassocSelfCure_ || isDelayedRandMacReassocSelfCure_)) {
        if (!pSelfCureStateMachine_->IsHttpReachable()) {
            WIFI_LOGD("HandleRssiChanged, HTTP failed, delayedReassoc = %{public}s, delayedRandMacReassoc = %{public}s",
                      std::to_string(isDelayedReassocSelfCure_).c_str(),
                      std::to_string(isDelayedRandMacReassocSelfCure_).c_str());
            pSelfCureStateMachine_->StopTimer(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
            if (isDelayedReassocSelfCure_) {
                pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                    WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, 0);
            } else if (isDelayedRandMacReassocSelfCure_) {
                pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                    WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, 0);
            }
        } else {
            isDelayedReassocSelfCure_ = false;
            isDelayedResetSelfCure_ = false;
            isDelayedRandMacReassocSelfCure_ = false;
            pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
        }
    }
}

void SelfCureStateMachine::InternetSelfCureState::HandleDelayedResetSelfCure()
{
    if (!pSelfCureStateMachine_->IsHttpReachable()) {
        WIFI_LOGD("HandleDelayedResetSelfCure, HTTP failed, delayedReset = %{public}s",
                  std::to_string(isDelayedResetSelfCure_).c_str());
        pSelfCureStateMachine_->StopTimer(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
        pSelfCureStateMachine_->SendMessageAtFrontOfQueue(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
                                                          WIFI_CURE_RESET_LEVEL_HIGH_RESET);
    } else {
        isDelayedReassocSelfCure_ = false;
        isDelayedResetSelfCure_ = false;
        isDelayedRandMacReassocSelfCure_ = false;
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
    }
}

/* --------------------------- state machine wifi6 self cure state ------------------------------ */
SelfCureStateMachine::Wifi6SelfCureState::Wifi6SelfCureState(SelfCureStateMachine *selfCureStateMachine)
    : State("Wifi6SelfCureState"),
      pSelfCureStateMachine_(selfCureStateMachine)
{
    WIFI_LOGD("Wifi6SelfCureState construct success.");
}

SelfCureStateMachine::Wifi6SelfCureState::~Wifi6SelfCureState() {}

void SelfCureStateMachine::Wifi6SelfCureState::GoInState()
{
    WIFI_LOGI("Wifi6SelfCureState GoInState function.");
    wifi6HtcArpDetectionFailedCnt_ = 0;
    wifi6ArpDetectionFailedCnt_ = 0;
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_WIFI6, true);
}

void SelfCureStateMachine::Wifi6SelfCureState::GoOutState()
{
    WIFI_LOGI("Wifi6SelfCureState GoOutState function.");
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_WIFI6, false);
}

bool SelfCureStateMachine::Wifi6SelfCureState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGD("Wifi6SelfCureState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_CURE_CMD_WIFI6_SELFCURE:
            ret = EXECUTED;
            internetValue_ = msg->GetParam1();
            isForceHttpCheck_ = msg->GetParam2();
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
            break;
        case WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE:
            ret = EXECUTED;
            internetValue_ = msg->GetParam1();
            isForceHttpCheck_ = msg->GetParam2();
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
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
        case WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD:
            ret = EXECUTED;
            pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
            break;
        default:
            WIFI_LOGD("Wifi6SelfCureState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

void SelfCureStateMachine::Wifi6SelfCureState::PeriodicWifi6WithHtcArpDetect(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    if (!pSelfCureStateMachine_->CanArpReachable()) {
        wifi6HtcArpDetectionFailedCnt_++;
        WIFI_LOGI("wifi6 with htc arp detection failed, times : %{public}d", wifi6HtcArpDetectionFailedCnt_);
        if (wifi6HtcArpDetectionFailedCnt_ == ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
            return;
        } else if (wifi6HtcArpDetectionFailedCnt_ > 0 && wifi6HtcArpDetectionFailedCnt_ < ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED,
                WIFI6_HTC_ARP_DETECTED_MS);
            return;
        }
    } else {
        WIFI_LOGI("wifi6 with htc arp detect success");
        wifi6HtcArpDetectionFailedCnt_ = 0;
        pSelfCureStateMachine_->isWifi6ArpSuccess_ = true;
        pSelfCureStateMachine_->isInternetFailureDetected_ = false;
        pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, internetValue_,
            isForceHttpCheck_, 0);
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
        return;
    }
}

void SelfCureStateMachine::Wifi6SelfCureState::PeriodicWifi6WithoutHtcArpDetect(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    if (!pSelfCureStateMachine_->CanArpReachable()) {
        wifi6ArpDetectionFailedCnt_++;
        WIFI_LOGI("wifi6 without htc arp detection failed, times : %{public}d", wifi6ArpDetectionFailedCnt_);
        if (wifi6ArpDetectionFailedCnt_ == ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
            return;
        } else if (wifi6ArpDetectionFailedCnt_ > 0 && wifi6ArpDetectionFailedCnt_ < ARP_DETECTED_FAILED_COUNT) {
            pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED,
                WIFI6_HTC_ARP_DETECTED_MS);
            return;
        }
    } else {
        WIFI_LOGI("wifi6 without htc arp detect success");
        wifi6ArpDetectionFailedCnt_ = 0;
        pSelfCureStateMachine_->isWifi6ArpSuccess_ = true;
        if (!pSelfCureStateMachine_->IsHttpReachable()) {
            pSelfCureStateMachine_->isInternetFailureDetected_ = false;
            pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, internetValue_,
                isForceHttpCheck_, SELF_CURE_DELAYED_MS);
        }
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
        return;
    }
}

void SelfCureStateMachine::Wifi6SelfCureState::HandleWifi6WithHtcArpFail(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine_->isWifi6ArpSuccess_ = false;
    WifiCategoryBlackListInfo wifi6BlackListInfo(ACTION_TYPE_HTC, GetCurrentTimeMilliSeconds());
    std::string currentBssid = pSelfCureStateMachine_->GetCurrentBssid();
    if (currentBssid.empty()) {
        WIFI_LOGE("%{public}s currentBssid is empty", __FUNCTION__);
        Wifi6ReassocSelfcure();
        return;
    }
    WifiConfigCenter::GetInstance().InsertWifiCategoryBlackListCache(EVENT_AX_BLA_LIST,
        currentBssid, wifi6BlackListInfo);
    WIFI_LOGI("add %{public}s to HTC bla list", MacAnonymize(currentBssid).c_str());
    pSelfCureStateMachine_->SendBlaListToDriver(EVENT_AX_BLA_LIST);
    std::string param = "1";
    std::string ifName = "wlan0";
    if (WifiCmdClient::GetInstance().SendCmdToDriver(ifName, EVENT_AX_CLOSE_HTC, param) != 0) {
        WIFI_LOGE("%{public}s Ax Selfcure fail", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine_->SendMessage(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
}

void SelfCureStateMachine::Wifi6SelfCureState::HandleWifi6WithoutHtcArpFail(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is nullptr", __FUNCTION__);
        return;
    }
    WIFI_LOGI("wifi6 without htc arp detect failed");
    std::string currentBssid = pSelfCureStateMachine_->GetCurrentBssid();
    if (currentBssid.empty()) {
        WIFI_LOGE("%{public}s currentBssid is empty", __FUNCTION__);
        Wifi6ReassocSelfcure();
        return;
    }
    pSelfCureStateMachine_->isWifi6ArpSuccess_ = false;
    WifiCategoryBlackListInfo wifi6BlackListInfo(ACTION_TYPE_WIFI6, GetCurrentTimeMilliSeconds());

    WifiConfigCenter::GetInstance().InsertWifiCategoryBlackListCache(EVENT_AX_BLA_LIST,
        currentBssid, wifi6BlackListInfo);

    WIFI_LOGI("add %{public}s to wifi6 bla list", MacAnonymize(currentBssid).c_str());
    pSelfCureStateMachine_->SendBlaListToDriver(EVENT_AX_BLA_LIST);
    Wifi6ReassocSelfcure();
}

void SelfCureStateMachine::Wifi6SelfCureState::Wifi6ReassocSelfcure()
{
    WIFI_LOGI("begin to self cure for wifi6 reassoc");
    pSelfCureStateMachine_->isHasTestWifi6Reassoc_ = true;
    pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE,
        WIFI_CURE_INTERNET_FAILED_TYPE_TCP, SELF_CURE_DELAYED_MS);
    pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pInternetSelfCureState_);
}

/* --------------------------- state machine noInternet state ------------------------------ */
SelfCureStateMachine::NoInternetState::NoInternetState(SelfCureStateMachine *selfCureStateMachine)
    : State("NoInternetState"),
      pSelfCureStateMachine_(selfCureStateMachine)
{
    WIFI_LOGD("NoInternetState construct success.");
}

SelfCureStateMachine::NoInternetState::~NoInternetState() {}

void SelfCureStateMachine::NoInternetState::GoInState()
{
    WIFI_LOGI("NoInternetState GoInState function.");
    pSelfCureStateMachine_->isSelfcureDone_ = true;
    SelfCureUtils::GetInstance().ReportNoInternetChrEvent();
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_IDLE, false);
    pSelfCureStateMachine_->MessageExecutedLater(CMD_INTERNET_STATUS_DETECT_INTERVAL,
        NO_INTERNET_DETECT_INTERVAL_MS);
}

void SelfCureStateMachine::NoInternetState::GoOutState()
{
    WIFI_LOGI("NoInternetState GoOutState function.");
}

bool SelfCureStateMachine::NoInternetState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("NoInternetState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case CMD_INTERNET_STATUS_DETECT_INTERVAL:
            ret = EXECUTED;
            pSelfCureStateMachine_->StopTimer(CMD_INTERNET_STATUS_DETECT_INTERVAL);
            if (WifiConfigCenter::GetInstance().GetScreenState() != MODE_STATE_CLOSE) {
                IpQosMonitor::GetInstance().QueryPackets();
            }
            pSelfCureStateMachine_->MessageExecutedLater(CMD_INTERNET_STATUS_DETECT_INTERVAL,
                NO_INTERNET_DETECT_INTERVAL_MS);
            break;
        case WIFI_CURE_CMD_HTTP_REACHABLE_RCV:
            ret = EXECUTED;
            pSelfCureStateMachine_->SetSelfCureHistoryInfo(INIT_SELFCURE_HISTORY);
            pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pConnectedMonitorState_);
            break;
        case WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD:
            ret = EXECUTED;
            pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pDisconnectedMonitorState_);
            break;
        case WIFI_CURE_CMD_PERIODIC_ARP_DETECTED:
            ret = EXECUTED;
            pSelfCureStateMachine_->PeriodicArpDetection();
            break;
        case WIFI_CURE_CMD_ARP_FAILED_DETECTED:
            ret = EXECUTED;
            HandleArpFailedDetected(msg);
            break;
        default:
            WIFI_LOGD("NoInternetState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

void SelfCureStateMachine::NoInternetState::HandleArpFailedDetected(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGW("HandleArpFailedDetected, msg is nullptr");
        return;
    }
    std::string currentBssid = pSelfCureStateMachine_->GetCurrentBssid();
    if (pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currentBssid)) {
        return;
    }

    std::string selfCureHistory = pSelfCureStateMachine_->GetSelfCureHistoryInfo();
    WifiSelfCureHistoryInfo selfCureInfo;
    SelfCureUtils::GetInstance().String2InternetSelfCureHistoryInfo(selfCureHistory, selfCureInfo);
    if (SelfCureUtils::GetInstance().SelfCureAcceptable(selfCureInfo, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC)) {
        WIFI_LOGI("arp failed, try to reassoc");
        pSelfCureStateMachine_->MessageExecutedLater(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK,
            WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, 0, SELF_CURE_DELAYED_MS);
        pSelfCureStateMachine_->SwitchState(pSelfCureStateMachine_->pInternetSelfCureState_);
    }
}

void SelfCureStateMachine::SendBlaListToDriver(int blaListType)
{
    AgeOutWifiCategoryBlack(blaListType);
    std::map<std::string, WifiCategoryBlackListInfo> wifiBlackListCache;
    WifiConfigCenter::GetInstance().GetWifiCategoryBlackListCache(blaListType, wifiBlackListCache);
    std::string param = BlackListToString(wifiBlackListCache);
    std::string ifName = "wlan0";
    if (WifiCmdClient::GetInstance().SendCmdToDriver(ifName, blaListType, param) != 0) {
        WIFI_LOGE("%{public}s set BlaList fail", __FUNCTION__);
        return;
    }
}

std::string SelfCureStateMachine::BlackListToString(std::map<std::string, WifiCategoryBlackListInfo> &map)
{
    std::string param;
    uint32_t idx = map.size() >= WIFI_MAX_BLA_LIST_NUM ? WIFI_MAX_BLA_LIST_NUM : map.size();
    param.push_back(idx);
    if (idx == 0u) {
        return param;
    }
    for (auto iter : map) {
        std::string singleParam = ParseWifiCategoryBlackListInfo(iter);
        if (singleParam.size() != WIFI_SINGLE_ITEM_BYTE_LEN) {
            continue;
        }
        param.append(singleParam);
        if (param.size() >= WIFI_MAX_BLA_LIST_NUM * WIFI_SINGLE_ITEM_BYTE_LEN + 1) {
            break;
        }
    }
    return param;
}

std::string SelfCureStateMachine::ParseWifiCategoryBlackListInfo(std::pair<std::string, WifiCategoryBlackListInfo> iter)
{
    std::string singleParam;
    std::string currBssid = iter.first;
    WIFI_LOGI("currBssid %{public}s", MacAnonymize(currBssid).c_str());
    for (uint32_t i = 0; i < WIFI_SINGLE_MAC_LEN; i++) {
        std::string::size_type npos = currBssid.find(":");
        if (npos != std::string::npos) {
            std::string value = currBssid.substr(0, npos);
            singleParam.push_back(static_cast<uint8_t>(CheckDataLegalHex(value)));
            currBssid = currBssid.substr(npos + 1);
        } else {
            if (currBssid.empty()) {
                WIFI_LOGI("currBssid is empty");
                break;
            }
            singleParam.push_back(static_cast<uint8_t>(CheckDataLegalHex(currBssid)));
        }
    }
    singleParam.push_back(static_cast<uint8_t>(iter.second.actionType));
    singleParam.push_back(0);
    return singleParam;
}

bool SelfCureStateMachine::AgeOutWifiCategoryBlack(int blaListType)
{
    bool isUpdate = false;
    std::map<std::string, WifiCategoryBlackListInfo> blackListCache;
    WifiConfigCenter::GetInstance().GetWifiCategoryBlackListCache(blaListType, blackListCache);
    if (blackListCache.empty()) {
        return false;
    }
    if (blaListType != EVENT_AX_BLA_LIST && blaListType != EVENT_BE_BLA_LIST) {
        WIFI_LOGE("AgeOutWifiCategoryBlack wrong type.");
        return false;
    }
    for (auto iter = blackListCache.begin(); iter != blackListCache.end(); ++iter) {
        if (GetCurrentTimeMilliSeconds() - iter->second.updateTime >= WIFI_BLA_LIST_TIME_EXPIRED) {
            WifiConfigCenter::GetInstance().RemoveWifiCategoryBlackListCache(blaListType, iter->first);
            isUpdate = true;
            WIFI_LOGI("%{public}s blaListType:%{public}d remove bssid: %{public}s for ageOut", __FUNCTION__,
                blaListType, MacAnonymize(iter->first).c_str());
        }
    }
    if (blackListCache.size() >= WIFI_MAX_BLA_LIST_NUM) {
        int64_t earliestTime = std::numeric_limits<int64_t>::max();
        std::string delBssid;
        for (auto iter = blackListCache.begin(); iter != blackListCache.end(); ++iter) {
            if (iter->second.updateTime < earliestTime) {
                delBssid = iter->first;
                earliestTime = iter->second.updateTime;
            }
        }
        WifiConfigCenter::GetInstance().RemoveWifiCategoryBlackListCache(blaListType, delBssid);
        isUpdate = true;
        WIFI_LOGI("%{public}s blaListType:%{public}d remove bssid: %{public}s for reach max size", __FUNCTION__,
            blaListType, MacAnonymize(delBssid).c_str());
    }
    return isUpdate;
}

void SelfCureStateMachine::AgeOutWifiConnectFailList()
{
    std::map<std::string, WifiCategoryConnectFailInfo> connectFailListCache;
    WifiConfigCenter::GetInstance().GetWifiConnectFailListCache(connectFailListCache);
    for (auto iter = connectFailListCache.begin(); iter != connectFailListCache.end(); ++iter) {
        if (GetCurrentTimeMilliSeconds() - iter->second.updateTime >= WIFI_CONNECT_FAIL_LIST_TIME_EXPIRED) {
            WifiConfigCenter::GetInstance().RemoveWifiConnectFailListCache(iter->first);
        }
    }
    if (connectFailListCache.size() >= WIFI_MAX_BLA_LIST_NUM) {
        int64_t earliestTime = std::numeric_limits<int64_t>::max();
        std::string delBssid;
        for (auto iter = connectFailListCache.begin(); iter != connectFailListCache.end(); ++iter) {
            if (iter->second.updateTime < earliestTime) {
                delBssid = iter->first;
                earliestTime = iter->second.updateTime;
            }
        }
        WifiConfigCenter::GetInstance().RemoveWifiConnectFailListCache(delBssid);
    }
}

void SelfCureStateMachine::SetHttpMonitorStatus(bool isHttpReachable)
{
    isHttpReachable_ = isHttpReachable;
    detectionCond_.notify_all();
}

int SelfCureStateMachine::GetCurSignalLevel()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int signalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band, instId_);
    WIFI_LOGD("GetCurSignalLevel, signalLevel : %{public}d", signalLevel);
    return signalLevel;
}

bool SelfCureStateMachine::IsHttpReachable()
{
    WIFI_LOGI("IsHttpReachable network detect start");
    if (mNetWorkDetect_ == nullptr) {
        WIFI_LOGI("mNetWorkDetect_");
        return isHttpReachable_;
    }
    mNetWorkDetect_->StartWifiDetection();
    std::unique_lock<std::mutex> locker(detectionMtx_);
    detectionCond_.wait_for(locker, std::chrono::milliseconds(HTTP_DETECT_TIMEOUT));
    WIFI_LOGI("IsHttpReachable network detect end, result is %{public}d", isHttpReachable_);
    return isHttpReachable_;
}

int SelfCureStateMachine::GetLegalIpConfiguration(IpInfo &dhcpResults)
{
    WifiConfigCenter::GetInstance().GetIpInfo(dhcpResults);
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
            testIpAddr = SelfCureUtils::GetInstance().GetNextIpAddr(gateway, initialIpAddr, conflictedIpAddr);
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
        std::vector<uint32_t> oldIpAddr = SelfCureUtils::GetInstance().TransIpAddressToVec(
            IpTools::ConvertIpv4Address(dhcpResults.ipAddress));
        if (oldIpAddr.size() != IP_ADDR_SIZE) {
            return -1;
        }
        oldIpAddr[VEC_POS_3] = newIpAddr;
        std::string newIpAddress = SelfCureUtils::GetInstance().TransVecToIpAddress(oldIpAddr);
        dhcpResults.ipAddress = IpTools::ConvertIpv4Address(newIpAddress);
        return 0;
    }
    return -1;
}

bool SelfCureStateMachine::CanArpReachable()
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddress, instId_);
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, instId_);
    std::string ipAddress = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName();
    if (ipInfo.gateway == 0) {
        WIFI_LOGE("gateway is null");
        return false;
    }
    std::string gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    uint64_t arpRtt = 0;
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    for (int i = 0; i < DEFAULT_SLOW_NUM_ARP_PINGS; i++) {
        if (arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true, arpRtt)) {
            EnhanceWriteArpInfoHiSysEvent(arpRtt, 0);
            return true;
        }
    }
    EnhanceWriteArpInfoHiSysEvent(arpRtt, 1);
    return false;
}

bool SelfCureStateMachine::DoSlowArpTest(const std::string& testIpAddr)
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddress, instId_);
    std::string ipAddress = testIpAddr;
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName();
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

bool SelfCureStateMachine::DoArpTest(std::string& ipAddress, std::string& gateway)
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddress, instId_);
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName();
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    return arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true);
}

bool SelfCureStateMachine::IsIpAddressInvalid()
{
    IpInfo dhcpInfo;
    std::vector<uint32_t> currAddr;
    WifiConfigCenter::GetInstance().GetIpInfo(dhcpInfo);
    if (dhcpInfo.ipAddress != 0) {
        std::string addr = IpTools::ConvertIpv4Address(dhcpInfo.ipAddress);
        currAddr = SelfCureUtils::GetInstance().TransIpAddressToVec(addr);
        if ((currAddr.size() == IP_ADDR_SIZE)) {
            uint32_t intCurrAddr3 = (currAddr[VEC_POS_3] & 0xFF);
            uint32_t netmaskLenth =
                static_cast<uint32_t>(IpTools::GetMaskLength(IpTools::ConvertIpv4Address(dhcpInfo.netmask)));
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

bool SelfCureStateMachine::IsUseFactoryMac()
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    WifiLinkedInfo wifiLinkedInfo;
    std::string currMacAddress;
    std::string realMacAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(currMacAddress);
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddress);
    if (!currMacAddress.empty() && !realMacAddress.empty() && currMacAddress == realMacAddress) {
        WIFI_LOGI("use factory mac address currently.");
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IsNeedWifiReassocUseDeviceMac()
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("%{public}s: GetCurrentWifiDeviceConfig failed!", __FUNCTION__);
        return false;
    }
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    WIFI_LOGD("random MAC address is supported!");
    if (!CanArpReachable()) {
        WIFI_LOGI("arp is not reachable!");
        return false;
    }
    if (IsUseFactoryMac()) {
        WIFI_LOGI("use factory mac now!");
        return false;
    }
    std::vector<WifiScanInfo> scanResults;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    if (GetBssidCounter(config, scanResults) < MULTI_BSSID_NUM) {
        WIFI_LOGI("not multi bssid condition!");
        return false;
    }
    bool hasInternetEver = NetworkStatusHistoryManager::HasInternetEverByHistory(GetNetworkStatusHistory());
    bool isPortalNetwork = config.isPortal;
    if (hasInternetEver || isPortalNetwork) {
        WIFI_LOGI("hasinternet or portal network, don't to reassoc with factory mac!");
        return false;
    }
    WifiSelfCureHistoryInfo selfCureInfo;
    std::string internetSelfCureHistory = GetSelfCureHistoryInfo();
    SelfCureUtils::GetInstance().String2InternetSelfCureHistoryInfo(internetSelfCureHistory, selfCureInfo);
    if (selfCureInfo.randMacSelfCureConnectFailedCnt > SELF_CURE_RAND_MAC_CONNECT_FAIL_MAX_COUNT ||
        selfCureInfo.randMacSelfCureFailedCnt > SELF_CURE_RAND_MAC_MAX_COUNT) {
        WIFI_LOGI("has connect fail three times or randMac self cure fail 20 times!");
        return false;
    }
    auto now = std::chrono::system_clock::now();
    int64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    int64_t lastConnectFailMs = selfCureInfo.lastRandMacSelfCureConnectFailedCntTs;
    if ((currentMs - lastConnectFailMs) < RAND_MAC_FAIL_EXPIRATION_AGE_MILLIS) {
        WIFI_LOGI("Too close to the last connection failure time return");
        return false;
    }
    return true;
#endif
    WIFI_LOGI("random MAC address is not supported!");
    return false;
}

bool SelfCureStateMachine::IsSuppOnCompletedState()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.supplicantState == SupplicantState::COMPLETED) {
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IfPeriodicArpDetection()
{
    int curSignalLevel = GetCurSignalLevel();
    int state = WifiConfigCenter::GetInstance().GetScreenState();
    WIFI_LOGD("IfPeriodicArpDetection, GetScreenState: %{public}d", state);
    return (curSignalLevel >= SIGNAL_LEVEL_2) && (!isSelfCureOnGoing_) && (IsSuppOnCompletedState()) &&
           (state == MODE_STATE_OPEN);
}

void SelfCureStateMachine::PeriodicArpDetection()
{
    StopTimer(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
    if (!IfPeriodicArpDetection()) {
        WIFI_LOGD("PeriodicArpDetection, no need detection, just jump");
        MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, DEFAULT_ARP_DETECTED_MS);
        return;
    }
    if (!CanArpReachable()) {
        arpDetectionFailedCnt_++;
        WIFI_LOGI("Periodic Arp Detection failed, times : %{public}d", arpDetectionFailedCnt_);
        if (arpDetectionFailedCnt_ == ARP_DETECTED_FAILED_COUNT) {
            SendMessage(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        } else if (arpDetectionFailedCnt_ > 0 && arpDetectionFailedCnt_ < ARP_DETECTED_FAILED_COUNT) {
            MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, FAST_ARP_DETECTED_MS);
            return;
        }
    } else {
        WIFI_LOGI("Periodic Arp Detection success");
        arpDetectionFailedCnt_ = 0;
    }
    MessageExecutedLater(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED, DEFAULT_ARP_DETECTED_MS);
}

bool SelfCureStateMachine::ShouldTransToWifi6SelfCure(InternalMessagePtr msg, std::string currConnectedBssid)
{
    WIFI_LOGI("enter ShouldTransToWifi6SelfCure");
    if (currConnectedBssid.empty() || msg== nullptr) {
        WIFI_LOGE("currConnectedBssid is empty or msg is nullptr");
        return false;
    }
    if (!IsWifi6Network(currConnectedBssid) || isWifi6ArpSuccess_ || GetCurrentRssi() < MIN_VAL_LEVEL_3) {
        return false;
    }
    int32_t arg = isInternetUnknown_ ? 1 : 0;
    std::map<std::string, WifiCategoryBlackListInfo> wifi6BlackListCache;
    WifiConfigCenter::GetInstance().GetWifiCategoryBlackListCache(EVENT_AX_BLA_LIST, wifi6BlackListCache);
    if (wifi6BlackListCache.find(currConnectedBssid) == wifi6BlackListCache.end()) {
        MessageExecutedLater(WIFI_CURE_CMD_WIFI6_SELFCURE, arg, msg->GetParam2(), SELF_CURE_DELAYED_MS);
        SwitchState(pWifi6SelfCureState_);
        return true;
    } else {
        auto iter = wifi6BlackListCache.find(currConnectedBssid);
        if (iter->second.actionType == 0) {
            MessageExecutedLater(WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE, arg, msg->GetParam2(), SELF_CURE_DELAYED_MS);
            SwitchState(pWifi6SelfCureState_);
            return true;
        } else {
            WIFI_LOGI("don't need to do wifi6 selfcure");
        }
    }
    return false;
}

int SelfCureStateMachine::GetWifi7SelfCureType(int connectFailTimes, WifiLinkedInfo &info)
{
    std::vector<WifiScanInfo> scanResults;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    int scanRssi = GetScanRssi(info.bssid, scanResults);
    WifiCategory wifiCategory = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetWifiCategoryRecord(info.bssid);
    WIFI_LOGI("GetWifi7SelfCureType scanRssi %{public}d, wifiCategory: %{public}d, connectFailTimes: %{public}d",
        scanRssi, static_cast<int>(wifiCategory), connectFailTimes);
    if ((wifiCategory == WifiCategory::WIFI7 || wifiCategory == WifiCategory::WIFI7_PLUS)
        && connectFailTimes >= SELF_CURE_WIFI7_CONNECT_FAIL_MAX_COUNT && scanRssi >= MIN_VAL_LEVEL_3) {
        return WIFI7_SELFCURE_DISCONNECTED;
    }
    return WIFI7_NO_SELFCURE;
}

void SelfCureStateMachine::ShouldTransToWifi7SelfCure(WifiLinkedInfo &info)
{
    WIFI_LOGI("enter ShouldTransToWifi7SelfCure");
    if (info.bssid.empty()) {
        return;
    }
    std::map<std::string, WifiCategoryConnectFailInfo> connectFailListCache;
    WifiConfigCenter::GetInstance().GetWifiConnectFailListCache(connectFailListCache);
    auto iterConnectFail = connectFailListCache.find(info.bssid);
    if (iterConnectFail == connectFailListCache.end()) {
        WIFI_LOGE("no bssid in connectFailListCache");
        return;
    }
    int wifi7SelfCureType = GetWifi7SelfCureType(iterConnectFail->second.connectFailTimes, info);
    if (wifi7SelfCureType == WIFI7_SELFCURE_DISCONNECTED) {
        std::map<std::string, WifiCategoryBlackListInfo> blackListCache;
        WifiConfigCenter::GetInstance().GetWifiCategoryBlackListCache(EVENT_BE_BLA_LIST, blackListCache);
        auto iterBlackList = blackListCache.find(info.bssid);
        if (iterBlackList == blackListCache.end()) {
            WIFI_LOGI("start wifi7 with mld backoff");
            SendMessage(WIFI_CURE_CMD_WIFI7_MLD_BACKOFF, info);
        } else if (iterBlackList->second.actionType == ACTION_TYPE_MLD) {
            WIFI_LOGI("start wifi7 without mld backoff");
            SendMessage(WIFI_CURE_CMD_WIFI7_NON_MLD_BACKOFF, info);
        } else if (iterBlackList->second.actionType == ACTION_TYPE_WIFI7
            && iterConnectFail->second.actionType == ACTION_TYPE_RECOVER_FAIL) {
            WIFI_LOGI("start wifi7 selfcure fail recover");
            SendMessage(WIFI_CURE_CMD_WIFI7_BACKOFF_RECOVER, info);
        }
    } else {
        WIFI_LOGD("don't need to do wifi7 selfcure");
    }
}

void SelfCureStateMachine::HandleWifiBlackListUpdateMsg()
{
    if (AgeOutWifiCategoryBlack(EVENT_BE_BLA_LIST)) {
        SendBlaListToDriver(EVENT_BE_BLA_LIST);
    }
    if (AgeOutWifiCategoryBlack(EVENT_AX_BLA_LIST)) {
        SendBlaListToDriver(EVENT_AX_BLA_LIST);
    }
}

int SelfCureStateMachine::GetScanRssi(std::string currentBssid, const std::vector<WifiScanInfo> scanResults)
{
    for (WifiScanInfo nextResult : scanResults) {
        if (currentBssid == nextResult.bssid) {
            return nextResult.rssi;
        }
    }
    return CURRENT_RSSI_INIT;
}

int SelfCureStateMachine::GetCurrentRssi()
{
    WifiLinkedInfo wifiLinkedInfo;
    if (WifiConfigCenter::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("Get current link info failed!");
    }
    int currentRssi_ = wifiLinkedInfo.rssi;
    return currentRssi_;
}

std::string SelfCureStateMachine::GetCurrentBssid()
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get current bssid failed!");
        return "";
    }
    std::string currentBssid_ = config.bssid;
    return currentBssid_;
}

bool SelfCureStateMachine::IsWifi6Network(std::string currConnectedBssid)
{
    if (currConnectedBssid.empty()) {
        WIFI_LOGE("currConnectedBssid is empty");
        return false;
    }
    WifiLinkedInfo wifiLinkedInfo;
    if (WifiConfigCenter::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("Get current link info failed!");
    }
    if (wifiLinkedInfo.supportedWifiCategory == WifiCategory::WIFI6 ||
        wifiLinkedInfo.supportedWifiCategory == WifiCategory::WIFI6_PLUS) {
        WIFI_LOGI("current network is wifi6 network");
        return true;
    }
    std::map<std::string, WifiCategoryBlackListInfo> wifi7BlackListCache;
    WifiConfigCenter::GetInstance().GetWifiCategoryBlackListCache(EVENT_BE_BLA_LIST, wifi7BlackListCache);
    auto iter = wifi7BlackListCache.find(currConnectedBssid);
    if (iter != wifi7BlackListCache.end() &&
        iter->second.actionType == ACTION_TYPE_WIFI7 &&
        (wifiLinkedInfo.supportedWifiCategory == WifiCategory::WIFI7 ||
        wifiLinkedInfo.supportedWifiCategory == WifiCategory::WIFI7_PLUS)) {
        WIFI_LOGI("current network is wifi7 network but in wifi6 mode");
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IfP2pConnected()
{
    WifiP2pLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetP2pInfo(linkedInfo);
    WIFI_LOGI("P2p connection state : %{public}d", linkedInfo.GetConnectState());
    return linkedInfo.GetConnectState() == P2pConnectedState::P2P_CONNECTED;
}

std::string SelfCureStateMachine::GetAuthType()
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetAuthType failed!");
        return "";
    }
    std::string keyMgmt = config.keyMgmt;
    return keyMgmt;
}

int SelfCureStateMachine::GetIpAssignment(AssignIpMethod &ipAssignment)
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetIpAssignment failed!");
        return -1;
    }
    ipAssignment = config.wifiIpConfig.assignMethod;
    return 0;
}

time_t SelfCureStateMachine::GetLastHasInternetTime()
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetLastHasInternetTime failed!");
        return -1;
    }
    time_t lastHasInternetTime = config.lastHasInternetTime;
    return lastHasInternetTime;
}

uint32_t SelfCureStateMachine::GetNetworkStatusHistory()
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetNetworkStatusHistory failed!");
        return 0;
    }
    uint32_t networkStatusHistory = config.networkStatusHistory;
    return networkStatusHistory;
}

std::string SelfCureStateMachine::GetSelfCureHistoryInfo()
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetSelfCureHistoryInfo failed!");
        return "";
    }
    std::string internetSelfCureHistory = config.internetSelfCureHistory;
    return internetSelfCureHistory;
}

int SelfCureStateMachine::SetSelfCureHistoryInfo(const std::string selfCureHistory)
{
    WIFI_LOGI("enter %{public}s", __FUNCTION__);
    if (selfCureHistory == "") {
        WIFI_LOGW("selfCureHistory is empty");
        return -1;
    }
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SetSelfCureHistoryInfo failed!");
        return -1;
    }
    config.internetSelfCureHistory = selfCureHistory;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return 0;
}

int SelfCureStateMachine::GetIsReassocWithFactoryMacAddress()
{
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetIsReassocWithFactoryMacAddress failed!");
        return 0;
    }
    int isReassocWithFactoryMacAddress = config.isReassocSelfCureWithFactoryMacAddress;
    return isReassocWithFactoryMacAddress;
}

bool SelfCureStateMachine::IsCustNetworkSelfCure()
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("IsCustNetworkSelfCure get pEnhanceService service failed!");
        return false;
    }
    WifiDeviceConfig config;
    if (GetCurrentWifiDeviceConfig(config) != WIFI_OPT_SUCCESS) {
        return false;
    }
    if (pEnhanceService->IsItCustNetwork(config)) {
        WIFI_LOGD("selfcure is not triggered under currrent network.");
        return true;
    }
    return false;
}

int SelfCureStateMachine::SetIsReassocWithFactoryMacAddress(int isReassocWithFactoryMacAddress)
{
    int networkId = WifiConfigCenter::GetInstance().GetLastNetworkId();
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        WIFI_LOGE("SetIsReassocWithFactoryMacAddress Get device config failed!");
        return -1;
    }
    config.isReassocSelfCureWithFactoryMacAddress = isReassocWithFactoryMacAddress;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return 0;
}

ErrCode SelfCureStateMachine::GetCurrentWifiDeviceConfig(WifiDeviceConfig &config)
{
    WifiLinkedInfo wifiLinkedInfo;
    if (WifiConfigCenter::GetInstance().GetLinkedInfo(wifiLinkedInfo) != 0) {
        WIFI_LOGE("Get current link info failed!");
        return WIFI_OPT_FAILED;
    }
    if (WifiSettings::GetInstance().GetDeviceConfig(wifiLinkedInfo.networkId, config) != 0) {
        WIFI_LOGE("Get device config failed!, netId is %{public}d", wifiLinkedInfo.networkId);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
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
    noAutoConnCounter_ = 0;
    autoConnectFailedNetworksRssi_.clear();
    connectedTime_ = static_cast<int64_t>(time(nullptr));
    {
        std::lock_guard<std::mutex> lock(dhcpFailedBssidLock_);
        dhcpFailedBssids_.clear();
        dhcpFailedConfigKeys_.clear();
    }
    SwitchState(pConnectedMonitorState_);
}

bool SelfCureStateMachine::IsEncryptedAuthType(const std::string authType)
{
    if (authType == KEY_MGMT_WPA_PSK || authType == KEY_MGMT_WAPI_PSK || authType == KEY_MGMT_SAE) {
        return true;
    }
    return false;
}

void SelfCureStateMachine::RecoverySoftAp()
{
    if (WifiManager::GetInstance().GetWifiTogglerManager() == nullptr) {
        WIFI_LOGI("GetWifiTogglerManager is nullptr!!");
        return;
    }
    WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, 0);
    WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(1, 0);
}
 
bool SelfCureStateMachine::IsSoftApSsidSameWithWifi(const HotspotConfig& curApConfig)
{
    WifiLinkedInfo linkedInfo;
    WifiDeviceConfig config;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config);
    bool isSameSsid = (curApConfig.GetSsid() == linkedInfo.ssid);
    bool isSamePassword = (curApConfig.GetPreSharedKey() == config.preSharedKey);
    std::string().swap(config.preSharedKey);
    bool isSameSecurityType = ("WPA2-PSK" == config.keyMgmt || "WPA-PSK" == config.keyMgmt);
    if (isSameSsid && isSameSecurityType && !isSamePassword) {
        return true;
    }
    return false;
}
 
void SelfCureStateMachine::CheckConflictIpForSoftAp()
{
    IpInfo ipInfo;
    HotspotConfig curApConfig;
    WifiSettings::GetInstance().GetHotspotConfig(curApConfig, 0);
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo);
    WIFI_LOGI("CheckConflictIpForSoftAp enter!");
    if (!WifiConfigCenter::GetInstance().GetSoftapToggledState()) {
        WIFI_LOGI("softap not started, return!");
        return;
    }
    if (WifiManager::GetInstance().GetWifiTogglerManager() == nullptr) {
        WIFI_LOGI("GetWifiTogglerManager is nullptr!!");
        return;
    }
    if (IsSoftApSsidSameWithWifi(curApConfig)) {
        WIFI_LOGI("sta and sofap have same ssid and PSK, close softap!");
        WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, 0);
        return;
    }
    if (IpTools::ConvertIpv4Address(ipInfo.gateway) == curApConfig.GetIpAddress()) {
        WIFI_LOGI("sta and sofap gateway conflict, recovery softap!");
        RecoverySoftAp();
    }
}

void SelfCureStateMachine::RequestArpConflictTest()
{
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo);
    std::string ipAddr = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    if (ipAddr != "" && DoSlowArpTest(ipAddr)) {
        WIFI_LOGI("RequestArpConflictTest, Upload static ip conflicted chr!");
    }
}

void SelfCureStateMachine::HandleP2pConnChanged(const WifiP2pLinkedInfo &info)
{
    if (info.GetConnectState() == P2pConnectedState::P2P_CONNECTED) {
        isP2pConnected_ = true;
        return;
    }
    isP2pConnected_ = false;
    if (GetCurStateName() == pInternetSelfCureState_->GetStateName()) {
        SendMessage(WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT);
    }
}

bool SelfCureStateMachine::IsWifiSelfcureDone()
{
    if (IsSelfCureOnGoing()) {
        return false;
    }
    return isSelfcureDone_;
}

bool SelfCureStateMachine::IfMultiGateway()
{
    MultiGateway::GetInstance().GetGatewayAddr(instId_);
    int32_t gatewayCnt = MultiGateway::GetInstance().GetGatewayNum();
    EnhanceWriteArpInfoHiSysEvent(0, 0, gatewayCnt);
    return MultiGateway::GetInstance().IsMultiGateway();
}

bool SelfCureStateMachine::IsSettingsPage()
{
    std::string page = WifiSettings::GetInstance().GetPackageName("SETTINGS");
    if (WifiAppStateAware::GetInstance().IsForegroundApp(page)) {
        WIFI_LOGI("settings page, do not allow reset self cure");
        return true;
    }
    return false;
}

bool SelfCureStateMachine::IsSelfCureOnGoing()
{
    return isSelfCureOnGoing_;
}

bool SelfCureStateMachine::IsSelfCureL2Connecting()
{
    return selfCureL2State_ != SelfCureState::SCE_WIFI_INVALID_STATE;
}

void SelfCureStateMachine::ForceStopSelfCure()
{
    if (GetCurStateName() != pDisconnectedMonitorState_->GetStateName()) {
        WIFI_LOGI("stop selfcure");
        SwitchState(pDisconnectedMonitorState_);
    }
}

void SelfCureStateMachine::StopSelfCureWifi(int32_t status)
{
    SendMessage(WIFI_CURE_CMD_FORCE_STOP_SELF_CURE);
    if (selfCureL2State_ == SelfCureState::SCE_WIFI_INVALID_STATE) {
        return;
    }
    HandleSceStopSelfCure(status);
}

bool SelfCureStateMachine::IsMultiDhcpOffer()
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("IsMultiDhcpOffer get pEnhanceService service failed!");
        return false;
    }
    uint32_t retSize = 0;
    IpInfo info;
    pEnhanceService->DealDhcpOfferResult(OperationCmd::DHCP_OFFER_SIZE_GET, info, retSize);
    return retSize >= DHCP_OFFER_COUNT;
}

void SelfCureStateMachine::ClearDhcpOffer()
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("ClearDhcpOffer get pEnhanceService service failed!");
        return;
    }
    uint32_t retSize = 0;
    IpInfo info;
    pEnhanceService->DealDhcpOfferResult(OperationCmd::DHCP_OFFER_CLEAR, info, retSize);
}

void SelfCureStateMachine::UpdateSelfcureState(int currentCureLevel, bool isSelfCureOnGoing)
{
    if (isSelfCureOnGoing_ == isSelfCureOnGoing && currentCureLevel != WIFI_CURE_RESET_LEVEL_HIGH_RESET_WIFI_ON) {
        WIFI_LOGW("selfCureOnGoing state is not change");
        return;
    }
    isSelfCureOnGoing_ = isSelfCureOnGoing;
    WIFI_LOGI("UpdateSelfcureState currentCureLevel: %{public}d, isSelfCureOnGoing: %{public}d",
        currentCureLevel, isSelfCureOnGoing);
    int32_t selfcureType = SelfCureUtils::GetInstance().GetSelfCureType(currentCureLevel);
    if (selfcureType == 0) {
        WIFI_LOGW("selfcureType is invalid");
        return;
    }
    int currentPid = static_cast<int>(getpid());
    WifiCommonEventHelper::PublishSelfcureStateChangedEvent(currentPid, selfcureType, isSelfCureOnGoing);
}

bool SelfCureStateMachine::CheckSelfCureWifiResult(int event)
{
    if (selfCureL2State_ == SelfCureState::SCE_WIFI_INVALID_STATE) {
        return false;
    }
    WifiState wifiState = static_cast<WifiState>(WifiConfigCenter::GetInstance().GetWifiState(instId_));
    if (wifiState == WifiState::DISABLING || wifiState == WifiState::DISABLED) {
        if (!WifiConfigCenter::GetInstance().GetWifiSelfcureReset()) {
            WIFI_LOGI("user may close wifi during reassoc or reconnect self-cure going");
            StopSelfCureDelay(SCE_WIFI_STATUS_ABORT, 0);
            return false;
        }
    }
    if ((selfCureWifiLastState_ > wifiState) && (selfCureL2State_ != SelfCureState::SCE_WIFI_OFF_STATE) &&
        (selfCureWifiLastState_ != WifiState::UNKNOWN)) {
        WIFI_LOGI("user may toggle wifi! stop selfcure, last State: %{public}d, current state: %{public}d",
            selfCureWifiLastState_, wifiState);
        StopSelfCureDelay(SCE_WIFI_STATUS_ABORT, 0);
        return false;
    }
    selfCureWifiLastState_ = wifiState;
    bool retValue = true;
    switch (selfCureL2State_) {
        case SelfCureState::SCE_WIFI_OFF_STATE:
            if (wifiState == WifiState::DISABLED) {
                StopTimer(WIFI_CURE_RESET_OFF_TIMEOUT);
                HandleSelfCureNormal();
            }
            break;
        case SelfCureState::SCE_WIFI_ON_STATE:
            if (wifiState == WifiState::ENABLED) {
                StopTimer(WIFI_CURE_RESET_ON_TIMEOUT);
                HandleSelfCureNormal();
            }
            break;
        case SelfCureState::SCE_WIFI_CONNECT_STATE:
            retValue = CheckSelfCureConnectState();
            break;
        case SelfCureState::SCE_WIFI_REASSOC_STATE:
            CheckSelfCureReassocState();
            break;
        case SelfCureState::SCE_WIFI_DISCONNECT_STATE:
            CheckSelfCureDisconnectState();
            break;
        default:
            retValue = false;
            break;
    }
    return retValue;
}

bool SelfCureStateMachine::CheckSelfCureConnectState()
{
    WifiLinkedInfo info;
    WifiConfigCenter::GetInstance().GetLinkedInfo(info);
    // only effective in scenarios where the connection is interrupted
    if (info.detailedState == DetailedState::DISCONNECTED &&
        info.disconnTriggerMode == DisconnState::DISCONNECTED) {
        HandleSelfCureException(SCE_WIFI_STATUS_FAIL);
        if (connectNetworkRetryCnt_ >= CONNECT_NETWORK_RETRY) {
            return false; // while reconnect fail, should not ignore sta connect event callback
        }
    }
    if (selfCureNetworkLastState_ == info.detailedState) {
        WIFI_LOGW("state not change, state is %{public}d", selfCureNetworkLastState_);
        return true;
    }
    selfCureNetworkLastState_ = info.detailedState;
    if (selfCureNetworkLastState_ == DetailedState::CONNECTED) {
        WIFI_LOGI("wifi connect > CMD_SCE_WIFI_CONNECT_TIMEOUT msg removed state = %{public}d",
            selfCureNetworkLastState_);
        HandleSelfCureNormal();
    }
    return true;
}

void SelfCureStateMachine::CheckSelfCureReassocState()
{
    WifiLinkedInfo info;
    WifiConfigCenter::GetInstance().GetLinkedInfo(info);
    if ((selfCureNetworkLastState_ == info.detailedState) &&
        (info.detailedState != DetailedState::CONNECTION_REJECT)) {
        WIFI_LOGW("state not change, state is %{public}d", selfCureNetworkLastState_);
        return;
    }
    selfCureNetworkLastState_ = info.detailedState;
    WIFI_LOGI("selfCureNetworkLastState_ is %{public}d", selfCureNetworkLastState_);
    if (selfCureNetworkLastState_ == DetailedState::CONNECTED) {
        WIFI_LOGI("wifi reassoc > CMD_SCE_WIFI_REASSOC_TIMEOUT msg removed state = %{public}d",
            selfCureNetworkLastState_);
        HandleSelfCureNormal();
    } else if ((selfCureNetworkLastState_ == DetailedState::DISCONNECTED) ||
        (selfCureNetworkLastState_ == DetailedState::CONNECTION_REJECT)) {
        WIFI_LOGI("wifi reassoc failed");
        StopTimer(WIFI_CURE_REASSOC_TIMEOUT);
        HandleSelfCureException(SCE_WIFI_STATUS_FAIL);
    }
}

void SelfCureStateMachine::CheckSelfCureDisconnectState()
{
    WifiLinkedInfo info;
    WifiConfigCenter::GetInstance().GetLinkedInfo(info);
    if (info.detailedState == DetailedState::DISCONNECTED) {
        StopTimer(WIFI_CURE_DISCONNECT_TIMEOUT);
        HandleSelfCureNormal();
    }
}

void SelfCureStateMachine::HandleSelfCureNormal()
{
    switch (selfCureL2State_) {
        case SelfCureState::SCE_WIFI_OFF_STATE: {
            SetSelfCureWifiTimeOut(SCE_WIFI_ON_STATE);
            break;
        }
        case SelfCureState::SCE_WIFI_DISCONNECT_STATE:  // fall through
        case SelfCureState::SCE_WIFI_ON_STATE: {
            WIFI_LOGI("HandleSelfCureNormal wifi on OK or disconnect ok! -> wifi connect");
            if (selfCureL2State_ == SelfCureState::SCE_WIFI_ON_STATE) {
                UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_HIGH_RESET_WIFI_ON, true);
            }
            int networkId = WifiConfigCenter::GetInstance().GetLastNetworkId();
            IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(instId_);
            if (pStaService == nullptr) {
                WIFI_LOGE("Get %{public}s service failed!", WIFI_SERVICE_STA);
                return;
            }
            if (pStaService->ConnectToNetwork(networkId, NETWORK_SELECTED_BY_SELFCURE) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("connect to network failed");
                HandleSelfCureException(SCE_WIFI_STATUS_FAIL);
                return;
            }
            SetSelfCureWifiTimeOut(SCE_WIFI_CONNECT_STATE);
            break;
        }
        case SelfCureState::SCE_WIFI_CONNECT_STATE:
        case SelfCureState::SCE_WIFI_REASSOC_STATE:
            WIFI_LOGI("HandleSelfCureNormal, wifi connect/reassoc/reconnect ok!");
            StopSelfCureDelay(SCE_WIFI_STATUS_SUCC, WIFI_CURE_CONN_SUCCESS_MS);
            break;
        default:
            WIFI_LOGE("HandleSelfCureNormal, unvalid selfCureL2State_");
            break;
    }
}

void SelfCureStateMachine::HandleSelfCureException(int reasonCode)
{
    switch (selfCureL2State_) {
        case SelfCureState::SCE_WIFI_OFF_STATE:
            WIFI_LOGI("HandleSelfCureException, wifi off fail! -> wifi off");
            StopSelfCureDelay(SCE_WIFI_STATUS_FAIL, 0);
            break;
        case SelfCureState::SCE_WIFI_ON_STATE:
            WIFI_LOGI("HandleSelfCureException, wifi on fail! -> wifi on");
            StopSelfCureDelay(SCE_WIFI_STATUS_FAIL, 0);
            break;
        case SelfCureState::SCE_WIFI_DISCONNECT_STATE:
            HandleSelfCureDisconnectException();
            break;
        case SelfCureState::SCE_WIFI_CONNECT_STATE:
        case SelfCureState::SCE_WIFI_REASSOC_STATE: {
            WIFI_LOGI("HandleSelfCureException, wifi connect/reassoc/reconnect fail! retry = %{public}d",
                connectNetworkRetryCnt_);
            if (connectNetworkRetryCnt_ >= CONNECT_NETWORK_RETRY) {
                HandleConnectFailed();
                StopSelfCureDelay(SCE_WIFI_STATUS_FAIL, 0);
                break;
            }
            connectNetworkRetryCnt_++;
            if ((selfCureL2State_ == SCE_WIFI_CONNECT_STATE) && (useWithRandMacAddress_ == FAC_MAC_REASSOC)) {
                useWithRandMacAddress_ = RAND_MAC_REASSOC;
                SetIsReassocWithFactoryMacAddress(RAND_MAC_REASSOC);
            }
            IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(instId_);
            if (pStaService == nullptr) {
                WIFI_LOGE("pStaService get failed");
                return;
            }
            pStaService->Disconnect();
            SetSelfCureWifiTimeOut(SCE_WIFI_DISCONNECT_STATE);
            break;
        }
        default:
            WIFI_LOGE("HandleSelfCureException, unvalid selfCureL2State_");
            break;
    }
}

void SelfCureStateMachine::HandleSelfCureDisconnectException()
{
    WIFI_LOGI("HandleSelfCureException, disconnect timeout! -> connect");
    int networkId = WifiConfigCenter::GetInstance().GetLastNetworkId();
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(instId_);
    if (pStaService == nullptr) {
        WIFI_LOGE("pStaService get failed");
        return;
    }
    if (pStaService->ConnectToNetwork(networkId, NETWORK_SELECTED_BY_SELFCURE) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("connect to network failed");
        StopSelfCureDelay(SCE_WIFI_STATUS_FAIL, 0);
        return;
    }
    SetSelfCureWifiTimeOut(SCE_WIFI_CONNECT_STATE);
}

void SelfCureStateMachine::SetSelfCureWifiTimeOut(SelfCureState wifiSelfCureState)
{
    selfCureL2State_ = wifiSelfCureState;
    switch (selfCureL2State_) {
        case SelfCureState::SCE_WIFI_OFF_STATE:
            WIFI_LOGI("SetSelfCureWifiTimeOut send delay message CMD_SELFCURE_WIFI_OFF_TIMEOUT");
            MessageExecutedLater(WIFI_CURE_RESET_OFF_TIMEOUT, WIFI_CURE_OFF_TIMEOUT_MS);
            break;
        case SelfCureState::SCE_WIFI_ON_STATE:
            WIFI_LOGI("SetSelfCureWifiTimeOut send delay message CMD_SELFCURE_WIFI_ON_TIMEOUT");
            MessageExecutedLater(WIFI_CURE_RESET_ON_TIMEOUT, WIFI_CURE_ON_TIMEOUT_MS);
            break;
        case SelfCureState::SCE_WIFI_REASSOC_STATE:
            WIFI_LOGI("SetSelfCureWifiTimeOut send delay message CMD_SELFCURE_WIFI_REASSOC_TIMEOUT");
            selfCureNetworkLastState_ = DetailedState::DISCONNECTED;
            MessageExecutedLater(WIFI_CURE_REASSOC_TIMEOUT, WIFI_CURE_REASSOC_TIMEOUT_MS);
            break;
        case SelfCureState::SCE_WIFI_CONNECT_STATE: {
            WIFI_LOGI("SetSelfCureWifiTimeOut send delay message CMD_SELFCURE_WIFI_CONNECT_TIMEOUT");
            int32_t delayMs = WIFI_CURE_CONNECT_TIMEOUT_MS;
            if (WifiConfigCenter::GetInstance().GetScreenState() != MODE_STATE_OPEN) {
                delayMs += WIFI_CURE_CONNECT_TIMEOUT_MS;
            }
            MessageExecutedLater(WIFI_CURE_CONNECT_TIMEOUT, delayMs);
            break;
        }
        case SelfCureState::SCE_WIFI_DISCONNECT_STATE:
            MessageExecutedLater(WIFI_CURE_DISCONNECT_TIMEOUT, WIFI_CURE_DISCONNECT_TIMEOUT_MS);
            break;
        default:
            WIFI_LOGW("SetSelfCureWifiTimeOut, unvalid selfcurestate");
            break;
    }
}

void SelfCureStateMachine::StopSelfCureDelay(int status, int delay)
{
    if (delay == 0) {
        HandleSceStopSelfCure(status);
    } else {
        MessageExecutedLater(WIFI_CURE_CMD_STOP_SELF_CURE, status, 0, delay);
    }
}

void SelfCureStateMachine::HandleSceStopSelfCure(int status)
{
    WIFI_LOGI("HandleSceStopSelfCure status %{public}d", status);
    ResetSelfCureParam();
    NotifySelfCureCompleted(status);
}

void SelfCureStateMachine::NotifySelfCureCompleted(int status)
{
    if (status == SCE_WIFI_STATUS_SUCC) {
        MessageExecutedLater(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM, 0);
    } else if ((status == SCE_WIFI_STATUS_FAIL) || (status == SCE_WIFI_STATUS_ABORT) ||
        (status == SCE_WIFI_STATUS_LOST)) {
        MessageExecutedLater(WIFI_CURE_CMD_SELF_CURE_FAILED, 0);
    }
}

void SelfCureStateMachine::ResetSelfCureParam()
{
    selfCureNetworkLastState_ = DetailedState::IDLE;
    selfCureWifiLastState_ = WifiState::UNKNOWN;
    selfCureL2State_ = SelfCureState::SCE_WIFI_INVALID_STATE;
    connectNetworkRetryCnt_ = 0;
    WifiConfigCenter::GetInstance().SetWifiSelfcureReset(false);
    StopTimer(WIFI_CURE_RESET_OFF_TIMEOUT);
    StopTimer(WIFI_CURE_RESET_ON_TIMEOUT);
    StopTimer(WIFI_CURE_REASSOC_TIMEOUT);
    StopTimer(WIFI_CURE_CONNECT_TIMEOUT);
    StopTimer(WIFI_CURE_DISCONNECT_TIMEOUT);
}

void SelfCureStateMachine::HandleConnectFailed()
{
    WIFI_LOGI("enter HandleConnectFailed");
    if (useWithRandMacAddress_ != 0 && isSelfCureOnGoing_) {
        useWithRandMacAddress_ = 0;
        WifiDeviceConfig config;
        int networkId = WifiConfigCenter::GetInstance().GetLastNetworkId();
        if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
            WIFI_LOGE("%{public}s: GetDeviceConfig failed!.", __FUNCTION__);
            return;
        }
        // Connect failed, updateSelfcureConnectHistoryInfo
        WifiSelfCureHistoryInfo selfCureHistoryInfo;
        std::string internetSelfCureHistory = config.internetSelfCureHistory;
        SelfCureUtils::GetInstance().String2InternetSelfCureHistoryInfo(internetSelfCureHistory, selfCureHistoryInfo);
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(selfCureHistoryInfo, requestCureLevel, false);
        config.internetSelfCureHistory = selfCureHistoryInfo.GetSelfCureHistory();
        config.isReassocSelfCureWithFactoryMacAddress = 0;
        config.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        WifiSettings::GetInstance().AddDeviceConfig(config);
        WifiSettings::GetInstance().SyncDeviceConfig();
    }
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Get pStaService failed");
        return;
    }
    pStaService->Disconnect();
}
} // namespace Wifi
} // namespace OHOS