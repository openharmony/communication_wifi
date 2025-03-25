/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include <string>
#include <vector>
#include <map>
#include "block_connect_service.h"
#include "iscan_service.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_pro_state_machine.h"
#include "wifi_service_manager.h"
#include "wifi_pro_utils.h"
#include "network_black_list_manager.h"
#include "wifi_manager.h"
#include "wifi_settings.h"
#include "network_status_history_manager.h"
#include "self_cure_state_machine.h"
#include "self_cure_utils.h"
#include "ip_qos_monitor.h"
#include "wifi_global_func.h"

namespace OHOS {
namespace Wifi {
namespace {
const std::string WIFI_PRO_STATE_MACHINE = "WifiProStateMachine";
constexpr int32_t DEFAULT_RSSI = -200;
constexpr int32_t DEFAULT_SCAN_INTERVAL = 10 * 1000; // ms
constexpr int64_t BLOCKLIST_VALID_TIME = 120 * 1000;  // ms
constexpr int64_t SELF_CURE_RSSI_THRESHOLD = -70;
constexpr int64_t DEFAULT_NET_DISABLE_DETECT_COUNT = 2;
constexpr int64_t MIN_TCP_TX = 2;
constexpr int64_t MIN_DNS_FAILED_CNT = 2;
// show reason
std::map<WifiSwitchReason, std::string> g_switchReason = {
    {WIFI_SWITCH_REASON_NO_INTERNET, "NO_INTERNET"},
    {WIFI_SWITCH_REASON_POOR_RSSI, "POOR_RSSI"},
    {WIFI_SWITCH_REASON_STRONG_RSSI_INTERNET_SLOW, "STRONG_RSSI_INTERNET_SLOW"},
    {WIFI_SWITCH_REASON_POOR_RSSI_INTERNET_SLOW, "POOR_RSSI_INTERNET_SLOW"},
    {WIFI_SWITCH_REASON_BACKGROUND_CHECK_AVAILABLE_WIFI, "BACKGROUND_CHECK_AVAILABLE_WIFI"},
    {WIFI_SWITCH_REASON_APP_QOE_SLOW, "APP_QOE_SLOW"},
};
}

DEFINE_WIFILOG_LABEL("WifiProStateMachine");

WifiProStateMachine::WifiProStateMachine(int32_t instId)
    : StateMachine(WIFI_PRO_STATE_MACHINE),
    instId_(instId)
{
    WIFI_LOGI("Enter WifiProStateMachine");
}

WifiProStateMachine::~WifiProStateMachine()
{
    WIFI_LOGI("Enter ~WifiProStateMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState_);
    ParsePointer(pWifiProEnableState_);
    ParsePointer(pWifiProDisabledState_);
    ParsePointer(pWifiConnectedState_);
    ParsePointer(pWifiDisConnectedState_);
    ParsePointer(pWifiHasNetState_);
    ParsePointer(pWifiNoNetState_);
    ParsePointer(pWifiPortalState_);
}

void WifiProStateMachine::BuildStateTree()
{
    StatePlus(pDefaultState_, nullptr);
    StatePlus(pWifiProEnableState_, pDefaultState_);
    StatePlus(pWifiProDisabledState_, pDefaultState_);
    StatePlus(pWifiConnectedState_, pWifiProEnableState_);
    StatePlus(pWifiDisConnectedState_, pWifiProEnableState_);
    StatePlus(pWifiHasNetState_, pWifiConnectedState_);
    StatePlus(pWifiNoNetState_, pWifiConnectedState_);
    StatePlus(pWifiPortalState_, pWifiConnectedState_);
}

ErrCode WifiProStateMachine::InitWifiProStates()
{
    WIFI_LOGI("Enter InitWifiProStates");
    int32_t tmpErrNumber = 0;
    pDefaultState_ = new (std::nothrow)DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState_);
    pWifiProEnableState_ = new (std::nothrow)WifiProEnableState(this);
    tmpErrNumber += JudgmentEmpty(pWifiProEnableState_);
    pWifiProDisabledState_ = new (std::nothrow)WifiProDisabledState(this);
    tmpErrNumber += JudgmentEmpty(pWifiProDisabledState_);
    pWifiConnectedState_ = new (std::nothrow)WifiConnectedState(this);
    tmpErrNumber += JudgmentEmpty(pWifiConnectedState_);
    pWifiDisConnectedState_ = new (std::nothrow)WifiDisconnectedState(this);
    tmpErrNumber += JudgmentEmpty(pWifiDisConnectedState_);
    pWifiHasNetState_ = new (std::nothrow)WifiHasNetState(this);
    tmpErrNumber += JudgmentEmpty(pWifiHasNetState_);
    pWifiNoNetState_ = new (std::nothrow)WifiNoNetState(this);
    tmpErrNumber += JudgmentEmpty(pWifiNoNetState_);
    pWifiPortalState_ = new (std::nothrow)WifiPortalState(this);
    tmpErrNumber += JudgmentEmpty(pWifiPortalState_);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitWifiProStates someone state is null");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiProStateMachine::Initialize()
{
    if (!InitialStateMachine(WIFI_PRO_STATE_MACHINE)) {
        WIFI_LOGE("Initial WifiProStateMachine failed.");
        return WIFI_OPT_FAILED;
    }
    if (InitWifiProStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pWifiProEnableState_);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

bool WifiProStateMachine::IsKeepCurrWifiConnected()
{
    // First detect nonet and user select, do not switch
    if (currentState_ == WifiProState::WIFI_NONET && WifiProUtils::IsUserSelectNetwork() && isFirstNetDectect_) {
        WIFI_LOGI("IsKeepCurrWifiConnected, user select and nonet.");
        return true;
    }

    if (WifiProUtils::IsAppInWhiteLists()) {
        WIFI_LOGI("IsKeepCurrWifiConnected, in app white lists.");
        return true;
    }

    // AP+STA scene, do not switch
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(instId_);
    if (curState == WifiOprMidState::RUNNING) {
        WIFI_LOGI("IsKeepCurrWifiConnected, ap is running, do not switch");
        return true;
    }

    // signal bridge
    auto rptManager = WifiManager::GetInstance().GetRptInterface(instId_);
    if (rptManager != nullptr && rptManager->IsRptRunning()) {
        WIFI_LOGI("IsKeepCurrWifiConnected, rpt is running, do not switch");
        return true;
    }
    return false;
}

bool WifiProStateMachine::HasWifiSwitchRecord()
{
    RefreshConnectedNetWork();
    if (pCurrWifiInfo_ == nullptr) {
        return false;
    }

    if (pCurrWifiDeviceConfig_ != nullptr && pCurrWifiDeviceConfig_->lastTrySwitchWifiTimestamp > 0) {
        int64_t now = WifiProUtils::GetCurrentTimeMs();
        // less than 14 days
        if (now - pCurrWifiDeviceConfig_->lastTrySwitchWifiTimestamp < WIFI_SWITCH_RECORD_MAX_TIME) {
            WIFI_LOGI("HasWifiSwitchRecord, has switch record in 14 days");
            return true;
        }
    }
    return false;
}

void WifiProStateMachine::RefreshConnectedNetWork()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    WIFI_LOGD("RefreshConnectedNetWork, connState:%{public}d,"
        "supplicantState:%{public}d.", linkedInfo.connState, static_cast<int32_t>(linkedInfo.supplicantState));
    if (!WifiProUtils::IsSupplicantConnecting(linkedInfo.supplicantState)) {
        currentBssid_ = "";
        currentSsid_ = "";
        currentRssi_ = DEFAULT_RSSI;
        return;
    }

    pCurrWifiInfo_ = std::make_shared<WifiLinkedInfo>(linkedInfo);
    currentBssid_ = linkedInfo.bssid;
    currentSsid_ = linkedInfo.ssid;
    currentRssi_ = linkedInfo.rssi;
    std::vector<WifiDeviceConfig> configs;
    WifiSettings::GetInstance().GetDeviceConfig(configs);
    if (configs.empty()) {
        WIFI_LOGI("RefreshConnectedNetWork, config is empty");
        return;
    }
    for (auto &wifiDeviceConfig : configs) {
        if (wifiDeviceConfig.networkId == linkedInfo.networkId) {
            WIFI_LOGD("RefreshConnectedNetWork, find device config.");
            pCurrWifiDeviceConfig_ = std::make_shared<WifiDeviceConfig>(wifiDeviceConfig);
        }
    }
}

bool WifiProStateMachine::IsReachWifiScanThreshold(int32_t signalLevel)
{
    WIFI_LOGD("IsReachWifiScanThreshold, rssiLevel:%{public}d.", signalLevel);
    if (signalLevel == SIG_LEVEL_4) {
        return false;
    }

    if (signalLevel < SIG_LEVEL_3) {
        return true;
    }

    if (HasWifiSwitchRecord()) {
        WIFI_LOGI("IsReachWifiScanThreshold, ap is not strong enough, and has switch record.");
        return true;
    }

    if (HasAvailableSsidToSwitch()) {
        WIFI_LOGI("IsReachWifiScanThreshold, ap is not strong enough, and has available ap.");
        return true;
    }

    WIFI_LOGI("IsReachWifiScanThreshold, ap is not strong enough, no need to switch.");
    return false;
}

bool WifiProStateMachine::HasAvailableSsidToSwitch()
{
    return false;
}

void WifiProStateMachine::SetSwitchReason(WifiSwitchReason reason)
{
    targetBssid_ = "";
    wifiSwitchReason_ = reason;
}

bool WifiProStateMachine::IsDisableWifiAutoSwitch()
{
    bool isCallingInCs = IsCallingInCs();
    if ((isDisableWifiAutoSwitch_) || isCallingInCs) {
        WIFI_LOGW("isDisableWifiAutoSwitch:%{public}d, isCallingInCs:%{public}d.",
            isDisableWifiAutoSwitch_, isCallingInCs);
        return false;
    }
    return true;
}

void WifiProStateMachine::Wifi2WifiFinish()
{
    isWifi2WifiSwitching_ = false;
    badBssid_ = "";
    badSsid_ = "";
    targetBssid_ = "";
}

bool WifiProStateMachine::IsFullscreen()
{
    return false;
}

bool WifiProStateMachine::IsCallingInCs()
{
    return false;
}

void WifiProStateMachine::UpdateWifiSwitchTimeStamp()
{
    int64_t now = WifiProUtils::GetCurrentTimeMs();
    WifiLinkedInfo linkedInfo;
    WifiDeviceConfig config;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config) == 0) {
        config.lastTrySwitchWifiTimestamp = now;
        WifiSettings::GetInstance().AddDeviceConfig(config);
        WifiSettings::GetInstance().SyncDeviceConfig();
    } else {
        WIFI_LOGW("UpdateWifiSwitchTimeStamp, get device config failed");
    }
}

void WifiProStateMachine::HandleWifi2WifiSucsess(int64_t blackListTime)
{
    WIFI_LOGI("Enter HandleWifi2WifiSucsess");
    auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
    if (!badBssid_.empty()) {
        networkBlackListManager.AddWifiBlocklist(badBssid_);
        MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST, badBssid_, blackListTime);
        networkBlackListManager.CleanTempWifiBlockList();
    }
    RefreshConnectedNetWork();
}

void WifiProStateMachine::HandleWifi2WifiFailed()
{
    WIFI_LOGI("wifitowifi step X: wifi to Wifi Failed Finally.");
    auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
    if (networkBlackListManager.IsFailedMultiTimes(targetBssid_)) {
        WIFI_LOGI("HandleWifi2WifiFailed, add to abnormal black list:%{public}s.", MacAnonymize(targetBssid_).c_str());
        networkBlackListManager.AddAbnormalWifiBlocklist(targetBssid_);
        networkBlackListManager.CleanTempWifiBlockList();
    }
}

void WifiProStateMachine::FastScan(std::vector<WifiScanInfo> &scanInfoList)
{
    WIFI_LOGI("Enter FastScan.");
    OHOS::Wifi::WifiScanParams params;
    for (auto iter : scanInfoList) {
        params.freqs.push_back(iter.frequency);
    }
    params.scanStyle = 0;
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(instId_);
    if (pScanService == nullptr ||
        pScanService->ScanWithParam(params, true, ScanType::SCAN_TYPE_WIFIPRO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGI("FastScan error, do full channel scan.");
        SendMessage(EVENT_REQUEST_SCAN_DELAY);
    }
}

bool WifiProStateMachine::TrySelfCure(bool forceNoHttpCheck)
{
    if (isWifi2WifiSwitching_) {
        WIFI_LOGI("Wifi2Wifi Switching");
        return false;
    }
    WIFI_LOGI("TrySelfCure.");

    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId_);
    do {
        if (pSelfCureService == nullptr) {
            WIFI_LOGE("pSelfCureService nullptr.");
            break;
        }

        if (pSelfCureService->IsSelfCureOnGoing()) {
            WIFI_LOGI("SelfCureOnGoing.");
            break;
        }

        if (!WifiProUtils::IsWifiConnected(instId_)) {
            WIFI_LOGI("WifiDisconnected.");
            break;
        }

        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);

        // issatisfy min rssi
        if (linkedInfo.rssi > SELF_CURE_RSSI_THRESHOLD) {
            pSelfCureService->NotifyInternetFailureDetected(forceNoHttpCheck);
        } else {
            WIFI_LOGI("not reach rssi threshold.");
        }
    } while (0);
    return true;
}

bool WifiProStateMachine::SelectNetwork(NetworkSelectionResult &networkSelectionResult,
    NetworkSelectType networkSelectType, std::vector<InterScanInfo> &scanInfos)
{
    NetworkSelectType mNetworkSelectType;
    if (wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI_QOE_BAD;
    } else if (wifiSwitchReason_ == WIFI_SWITCH_REASON_NO_INTERNET) {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI_NONET;
    } else {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI;
    }
    BlockConnectService::GetInstance().UpdateAllNetworkSelectStatus();
    std::unique_ptr<NetworkSelectionManager> pNetworkSelectionManager = std::make_unique<NetworkSelectionManager>();
    if (pNetworkSelectionManager->SelectNetwork(networkSelectionResult, mNetworkSelectType, scanInfos)) {
        WIFI_LOGI("Wifi2Wifi select network result, ssid: %{public}s, bssid: %{public}s.",
            SsidAnonymize(networkSelectionResult.interScanInfo.ssid).c_str(),
            MacAnonymize(networkSelectionResult.interScanInfo.bssid).c_str());
        return true;
    }
 
    WIFI_LOGW("Wifi2Wifi select network failed");
    return false;
}

bool WifiProStateMachine::IsSatisfiedWifi2WifiCondition()
{
    if (isWifi2WifiSwitching_) {
        WIFI_LOGI("IsSatisfiedWifi2WifiCondition, wifi2Wifi is switching.");
        return false;
    }
 
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("IsSatisfiedWifi2WifiCondition, self cure ongoing.");
        return false;
    }

    if (IsKeepCurrWifiConnected()) {
        return false;
    }

    if (!IsDisableWifiAutoSwitch()) {
        return false;
    }

    return true;
}

bool WifiProStateMachine::TryWifi2Wifi(const NetworkSelectionResult &networkSelectionResult)
{
    if (wifiSwitchReason_ == WIFI_SWITCH_REASON_POOR_RSSI) {
        StopTimer(EVENT_REQUEST_SCAN_DELAY);
    }
    UpdateWifiSwitchTimeStamp();

    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(instId_);
    if (pStaService == nullptr) {
        WIFI_LOGE("TryWifi2Wifi: pStaService is invalid");
        return false;
    }

    int32_t networkId = networkSelectionResult.wifiDeviceConfig.networkId;
    badBssid_ = currentBssid_;
    badSsid_ = currentSsid_;
    targetBssid_ = networkSelectionResult.interScanInfo.bssid;
    isWifi2WifiSwitching_ = true;
    WIFI_LOGE("TryWifi2Wifi: Switch reason : %{public}s", (g_switchReason[wifiSwitchReason_]).c_str());
    if (pStaService->StartConnectToBssid(networkId, targetBssid_, NETWORK_SELECTED_BY_AUTO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("TryWifi2Wifi: ConnectToNetwork failed.");
        return false;
    }
    return true;
}

bool WifiProStateMachine::FullScan()
{
    WIFI_LOGD("start Fullscan");
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(instId_);
    if (pScanService == nullptr) {
        WIFI_LOGI("TryStartScan, pService is nullptr.");
        return WIFI_OPT_FAILED;
    }
    return pScanService->Scan(true, ScanType::SCAN_TYPE_WIFIPRO);
}
/* --------------------------- state machine default state ------------------------------ */
WifiProStateMachine::DefaultState::DefaultState(WifiProStateMachine *pWifiProStateMachine)
    : State("DefaultState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("DefaultState construct success.");
}

WifiProStateMachine::DefaultState::~DefaultState() {}

void WifiProStateMachine::DefaultState::GoInState()
{
    WIFI_LOGI("Enter DefaultState GoInState function.");
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_DEFAULT;
}

void WifiProStateMachine::DefaultState::GoOutState()
{
    WIFI_LOGI("Enter DefaultState GoOutState function.");
}

bool WifiProStateMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("DefaultState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_NOTIFY_WIFI_PRO_SWITCH_CHANGED:
            HandleWifiProSwitchChanged(msg);
            break;
        case EVENT_REMOVE_BLOCK_LIST:
            HandleRemoveBlockList(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::DefaultState::HandleRemoveBlockList(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("HandleRemoveBlockList: msg is nullptr.");
        return;
    }

    std::string bssid;
    msg->GetMessageObj(bssid);
    NetworkBlockListManager::GetInstance().RemoveWifiBlocklist(bssid);
}

void WifiProStateMachine::DefaultState::HandleWifiProSwitchChanged(const InternalMessagePtr msg)
{
    // the wifiPro switch is on by default
    if (msg == nullptr) {
        WIFI_LOGI("DefaultState, msg is nullptr.");
        return;
    }
    pWifiProStateMachine_->isWifiProEnabled_ = static_cast<bool>(msg->GetParam1());
    if (pWifiProStateMachine_->isWifiProEnabled_) {
        WIFI_LOGI("state transition: DefaultState -> WifiProEnableState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiProEnableState_);
    } else {
        WIFI_LOGI("state transition: DefaultState -> WifiProDisableState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiProDisabledState_);
    }
}

/* --------------------------- state machine enbale state ------------------------------ */
WifiProStateMachine::WifiProEnableState::WifiProEnableState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiProEnableState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("Enter WifiProEnableState.");
}

WifiProStateMachine::WifiProEnableState::~WifiProEnableState()
{
    WIFI_LOGD("Enter ~WifiProEnableState.");
}

void WifiProStateMachine::WifiProEnableState::GoInState()
{
    WIFI_LOGI("WifiProEnableState GoInState function.");
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_PRO_ENABLE;
    TransitionNetState();
}

void WifiProStateMachine::WifiProEnableState::GoOutState()
{
    WIFI_LOGI("WifiProEnableState GoOutState function.");
}

bool WifiProStateMachine::WifiProEnableState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGD("WifiProEnableState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_CONNECT_STATE_CHANGED:
            HandleWifiConnectStateChangedInEnable(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiProEnableState::TransitionNetState()
{
    if (WifiProUtils::IsWifiConnected(pWifiProStateMachine_->instId_)) {
        WIFI_LOGI("state transition: WifiProEnableState -> WifiConnectedState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
    } else {
        WIFI_LOGI("state transition: WifiProEnableState -> WifiDisConnectedStat.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiDisConnectedState_);
    }
}

void WifiProStateMachine::WifiProEnableState::HandleWifiConnectStateChangedInEnable(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("ProEnableState, msg is nullptr.");
        return;
    }
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
        WIFI_LOGI("state transition: WifiProEnableState -> WifiConnectedState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
        WifiLinkedInfo linkedInfo;
        msg->GetMessageObj(linkedInfo);
        pWifiProStateMachine_->perf5gHandoverService_.OnConnected(linkedInfo);
    } else if (state == static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED)) {
        WIFI_LOGI("state transition: WifiProEnableState -> WifiDisConnectedStat.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiDisConnectedState_);
        pWifiProStateMachine_->perf5gHandoverService_.OnDisconnected();
    } else {
        return;
    }
}

/* --------------------------- state machine disbaled state ------------------------------ */
WifiProStateMachine::WifiProDisabledState::WifiProDisabledState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiProDisabledState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("WifiProDisabledState construct success.");
}

WifiProStateMachine::WifiProDisabledState::~WifiProDisabledState() {}

void WifiProStateMachine::WifiProDisabledState::GoInState()
{
    WIFI_LOGI("WifiProDisabledState GoInState function.");
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_PRO_DISABLE;
}

void WifiProStateMachine::WifiProDisabledState::GoOutState()
{
    WIFI_LOGI("WifiProDisabledState GoOutState function.");
}

bool WifiProStateMachine::WifiProDisabledState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiProDisabledState-msgCode=%{public}d is received.", msg->GetMessageName());
    return false;
}
/* --------------------------- state machine connected state ------------------------------ */
WifiProStateMachine::WifiConnectedState::WifiConnectedState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiConnectedState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("WifiConnectedState construct success.");
}

WifiProStateMachine::WifiConnectedState::~WifiConnectedState() {}

void WifiProStateMachine::WifiConnectedState::GoInState()
{
    WIFI_LOGI("WifiConnectedState GoInState function.");
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_CONNECTED;
    pWifiProStateMachine_->RefreshConnectedNetWork();
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
    if (networkBlackListManager.IsInTempWifiBlockList(linkedInfo.bssid)) {
        networkBlackListManager.CleanTempWifiBlockList();
    }
    InitConnectedState();
}

void WifiProStateMachine::WifiConnectedState::GoOutState()
{
    WIFI_LOGI("WifiConnectedState GoOutState function.");
}

bool WifiProStateMachine::WifiConnectedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiConnectedState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            HandleHttpResult(msg);
            break;
        case EVENT_WIFI_CONNECT_STATE_CHANGED:
            HandleWifiConnectStateChangedInConnected(msg);
            break;
        case EVENT_QOE_REPORT:
            pWifiProStateMachine_->perf5gHandoverService_.QoeUpdate(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiConnectedState::InitConnectedState()
{
    if (pWifiProStateMachine_->duanBandHandoverType_ == ROAM_SCENE) {
        pWifiProStateMachine_->duanBandHandoverType_ = 0;
    }
    pWifiProStateMachine_->isFirstNetDectect_ = true;
}

void WifiProStateMachine::WifiConnectedState::HandleHttpResult(const InternalMessagePtr msg)
{
    WIFI_LOGI("Enter HandleHttpResult.");
    if (msg == nullptr) {
        WIFI_LOGI("HttpResultInConnected, msg is nullptr.");
        return;
    }
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_DISABLED) &&
        (pWifiProStateMachine_->currentState_ != WifiProState::WIFI_NONET)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiNoNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiNoNetState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL) &&
        (pWifiProStateMachine_->currentState_ != WifiProState::WIFI_PORTAL)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiPortalState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiPortalState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED) &&
        (pWifiProStateMachine_->currentState_ != WifiProState::WIFI_HASNET)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiHasNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiHasNetState_);
    }
}

void WifiProStateMachine::WifiConnectedState::HandleWifiConnectStateChangedInConnected(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("ConnectedChangedState, msg is nullptr.");
        return;
    }
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiDisconnectedState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiDisConnectedState_);
        pWifiProStateMachine_->perf5gHandoverService_.OnDisconnected();
    } else {
        if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
            WifiLinkedInfo linkedInfo;
            msg->GetMessageObj(linkedInfo);
            pWifiProStateMachine_->perf5gHandoverService_.OnConnected(linkedInfo);
            if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
                pWifiProStateMachine_->isWifi2WifiSwitching_ = false;
                pWifiProStateMachine_->HandleWifi2WifiSucsess(BLOCKLIST_VALID_TIME);
            }
        }
        pWifiProStateMachine_->disconnectToConnectedState_ = false;
    }
}
/* --------------------------- state machine disconnected state ------------------------------ */
WifiProStateMachine::WifiDisconnectedState::WifiDisconnectedState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiDisconnectedState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("WifiDisconnectedState construct success.");
}

WifiProStateMachine::WifiDisconnectedState::~WifiDisconnectedState() {}

void WifiProStateMachine::WifiDisconnectedState::GoInState()
{
    WIFI_LOGI("WifiDisconnectedState GoInState function.");
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_DISCONNECTED;
    if (!pWifiProStateMachine_->isWifi2WifiSwitching_) {
        auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
        networkBlackListManager.CleanAbnormalWifiBlocklist();
    }
}

void WifiProStateMachine::WifiDisconnectedState::GoOutState()
{
    WIFI_LOGI("WifiDisconnectedState GoOutState function.");
}

bool WifiProStateMachine::WifiDisconnectedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiDisconnectedState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_CONNECT_STATE_CHANGED:
            HandleWifiConnectStateChangedInDisconnected(msg);
            break;
        case EVENT_WIFI2WIFI_FAILED:
            HandleWifi2WifiFailedEvent(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiDisconnectedState::HandleWifiConnectStateChangedInDisconnected(
    const InternalMessagePtr msg)
{
    WIFI_LOGD("Enter HandleWifiConnectStateChangedInDisconnected.");
    if (msg == nullptr) {
        WIFI_LOGI("DisconnectedState, msg is nullptr.");
        return;
    }
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
        WifiLinkedInfo linkedInfo;
        msg->GetMessageObj(linkedInfo);
        pWifiProStateMachine_->perf5gHandoverService_.OnConnected(linkedInfo);
        if (pWifiProStateMachine_->isWifi2WifiSwitching_ && pWifiProStateMachine_->targetBssid_ != linkedInfo.bssid) {
            WIFI_LOGI("selected bssid and switched bssid are not same:selected bssid:%{public}s,"
                      "switched bssid:%{public}s,",
                MacAnonymize(pWifiProStateMachine_->targetBssid_).c_str(),
                MacAnonymize(linkedInfo.bssid).c_str());
            NetworkBlockListManager::GetInstance().AddWifiBlocklist(linkedInfo.bssid);
            pWifiProStateMachine_->MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST,
                linkedInfo.bssid, BLOCKLIST_VALID_TIME);
            pWifiProStateMachine_->HandleWifi2WifiFailed();
        } else if (pWifiProStateMachine_->isWifi2WifiSwitching_
            && pWifiProStateMachine_->targetBssid_ == linkedInfo.bssid) {
            pWifiProStateMachine_->HandleWifi2WifiSucsess(BLOCKLIST_VALID_TIME);
        }

        WIFI_LOGI("state transition: WifiDisconnectedState -> WifiConnectedState.");
        pWifiProStateMachine_->disconnectToConnectedState_ = true;
        pWifiProStateMachine_->Wifi2WifiFinish();
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
    }
}

void WifiProStateMachine::WifiDisconnectedState::HandleWifi2WifiFailedEvent(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("DisconnectedState, msg is nullptr.");
        return;
    }
    int32_t state = msg->GetParam1();
    WIFI_LOGW("HandleWifi2Wifi error : %{public}d", state);
    pWifiProStateMachine_->HandleWifi2WifiFailed();
    pWifiProStateMachine_->Wifi2WifiFinish();
}
/* --------------------------- state machine link has net state ------------------------------ */
WifiProStateMachine::WifiHasNetState::WifiHasNetState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiHasNetState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("WifiHasNetState construct success.");
}

WifiProStateMachine::WifiHasNetState::~WifiHasNetState() {}

void WifiProStateMachine::WifiHasNetState::GoInState()
{
    WIFI_LOGI("WifiHasNetState GoInState function.");
    WifiHasNetStateInit();
}

void WifiProStateMachine::WifiHasNetState::WifiHasNetStateInit()
{
    rssiLevel0Or1ScanedCounter_ = 0;
    rssiLevel2Or3ScanedCounter_ = 0;
    mLastTcpTxCounter_ = 0;
    mLastTcpRxCounter_ = 0;
    mLastDnsFailedCnt_ = 0;
    pWifiProStateMachine_->isWifi2WifiSwitching_ = false;
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_HASNET;
    pWifiProStateMachine_->SendMessage(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL);
    pWifiProStateMachine_->perf5gHandoverService_.NetworkStatusChanged(NetworkStatus::HAS_INTERNET);
}

void WifiProStateMachine::WifiHasNetState::GoOutState()
{
    WIFI_LOGI("WifiHasNetState GoOutState function.");
    pWifiProStateMachine_->StopTimer(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL);
    pWifiProStateMachine_->isFirstNetDectect_ = false;
    return;
}

bool WifiProStateMachine::WifiHasNetState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiHasNetState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_RSSI_CHANGED:
            HandleRssiChangedInHasNet(msg);
            break;
        case EVENT_REQUEST_SCAN_DELAY:
            HandleReuqestScanInHasNet(msg);
            break;
        case EVENT_HANDLE_SCAN_RESULT:
            HandleScanResultInHasNet(msg);
            break;
        case EVENT_REQUEST_NETWORK_DETECT:
            RequestHttpDetect();
            break;
        case EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL:
            ParseQoeInfoAndRequestDetect();
            break;
        case EVENT_QOE_APP_SLOW:
            HandleWifiQoeSlow();
            break;
        case EVENT_SIGNAL_INFO_CHANGE:
            pWifiProStateMachine_->perf5gHandoverService_.HandleSignalInfoChange(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiHasNetState::HandleRssiChangedInHasNet(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("RssiChanged, msg is nullptr.");
        return;
    }
    pWifiProStateMachine_->currentRssi_ = msg->GetParam1();
    if ((pWifiProStateMachine_->isWifi2WifiSwitching_)) {
        WIFI_LOGI("HasNetState, isWifi2WifiSwitching:%{public}d.", pWifiProStateMachine_->isWifi2WifiSwitching_);
        return;
    }

    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    WIFI_LOGI("HasNetState, signalLevel:%{public}d.", signalLevel);
    bool hasSwitchRecord = pWifiProStateMachine_->HasWifiSwitchRecord();
    if (signalLevel == SIG_LEVEL_4 && hasSwitchRecord) {
        rssiLevel2Or3ScanedCounter_ = 0;
        rssiLevel0Or1ScanedCounter_ = 0;
    }

    if (!pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel)) {
        WIFI_LOGD("HandleRssiChangedInHasNet, StopTimer EVENT_REQUEST_SCAN_DELAY.");
        pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
        return;
    }

    ISelfCureService *pSelfCureService =
        WifiServiceManager::GetInstance().GetSelfCureServiceInst(pWifiProStateMachine_->instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("self cure ongoing.");
        return;
    }

    pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
    pWifiProStateMachine_->SendMessage(EVENT_REQUEST_SCAN_DELAY, static_cast<int32_t>(hasSwitchRecord));
}

void WifiProStateMachine::WifiHasNetState::HandleReuqestScanInHasNet(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleReuqestScanInHasNet, msg is nullptr.");
        return;
    }

    // selfcure onging, pending scan for 10s
    ISelfCureService *pSelfCureService =
        WifiServiceManager::GetInstance().GetSelfCureServiceInst(pWifiProStateMachine_->instId_);
    bool hasSwitchRecord = static_cast<bool>(msg->GetParam1());
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("HandleReuqestScanInHasNet: self cure is ongoing.");
        pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
        pWifiProStateMachine_->MessageExecutedLater(EVENT_REQUEST_SCAN_DELAY, hasSwitchRecord, DEFAULT_SCAN_INTERVAL);
        return;
    }

    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (!pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel)) {
        return;
    }

    pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_POOR_RSSI);
    TryStartScan(hasSwitchRecord, signalLevel);
}

void WifiProStateMachine::WifiHasNetState::TryStartScan(bool hasSwitchRecord, int32_t signalLevel)
{
    // calculate the interval and the max scan counter.
    int32_t scanInterval = WifiProUtils::GetScanInterval(hasSwitchRecord, signalLevel);
    int32_t scanMaxCounter = WifiProUtils::GetMaxCounter(hasSwitchRecord, signalLevel);
    if ((signalLevel == SIG_LEVEL_2 || signalLevel == SIG_LEVEL_3) &&
        rssiLevel2Or3ScanedCounter_ < scanMaxCounter) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
            "rssiLevel2Or3ScanedCounter:%{public}d.", signalLevel, rssiLevel2Or3ScanedCounter_);
        auto ret = pWifiProStateMachine_->FullScan();
        if (ret == WIFI_OPT_SUCCESS) {
            rssiLevel2Or3ScanedCounter_++;
        }
        pWifiProStateMachine_->MessageExecutedLater(EVENT_REQUEST_SCAN_DELAY, hasSwitchRecord, scanInterval);
    } else if ((signalLevel < SIG_LEVEL_2) && (rssiLevel0Or1ScanedCounter_ < scanMaxCounter)) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
            "rssiLevel0Or1ScanedCounter:%{public}d.", signalLevel, rssiLevel0Or1ScanedCounter_);
        auto ret = pWifiProStateMachine_->FullScan();
        if (ret == WIFI_OPT_SUCCESS) {
            rssiLevel0Or1ScanedCounter_++;
        }
        pWifiProStateMachine_->MessageExecutedLater(EVENT_REQUEST_SCAN_DELAY, hasSwitchRecord, scanInterval);
    } else {
        WIFI_LOGI("TryStartScan, do not scan, signalLevel:%{public}d,scanMaxCounter:%{public}d.",
            signalLevel, scanMaxCounter);
    }
}

void WifiProStateMachine::WifiHasNetState::HandleScanResultInHasNet(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleScanResultInHasNet, msg is nullptr.");
        return;
    }
    std::vector<InterScanInfo> scanInfos;
    msg->GetMessageObj(scanInfos);

    if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
        WIFI_LOGI("HandleScanResultInHasNet, Wifi2WifiSwitching.");
        return;
    }

    pWifiProStateMachine_->perf5gHandoverService_.ScanResultUpdated(scanInfos);
    pWifiProStateMachine_->targetBssid_ = pWifiProStateMachine_->perf5gHandoverService_.Switch5g();
    if (pWifiProStateMachine_->targetBssid_ != "") {
        WIFI_LOGI("HandleScanResultInHasNet, perf 5g tried to switch.");
        pWifiProStateMachine_->badBssid_ = pWifiProStateMachine_->currentBssid_;
        pWifiProStateMachine_->isWifi2WifiSwitching_ = true;
        return;
    }
    // Make sure the wifipro lag switch is done only once
    if (pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW && !qoeSwitch_) {
        WIFI_LOGI("HandleScanResultInHasNet, qoe has tried to switch.");
        return;
    }
    qoeSwitch_ = false;

    WIFI_LOGI("wifi to wifi step 1: select network.");
    if (!pWifiProStateMachine_->SelectNetwork(pWifiProStateMachine_->networkSelectionResult_,
        NetworkSelectType::WIFI2WIFI, scanInfos)) {
        WIFI_LOGI("wifi to wifi step X: Wifi2Wifi select network fail.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        return;
    }

    WIFI_LOGI("wifi to wifi step 2: receive good ap.");
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (!pWifiProStateMachine_->IsSatisfiedWifi2WifiCondition()) {
        pWifiProStateMachine_->Wifi2WifiFinish();
        return;
    }
    // when wifiSwitchReason is APP_QOE_SLOW, skip IsReachWifiScanThreshold
    if (pWifiProStateMachine_->wifiSwitchReason_ != WIFI_SWITCH_REASON_APP_QOE_SLOW &&
        signalLevel > SIG_LEVEL_2) {
        pWifiProStateMachine_->Wifi2WifiFinish();
        return;
    }

    WIFI_LOGI("wifi to wifi step 3: try wifi2wifi.");
    if (!pWifiProStateMachine_->TryWifi2Wifi(pWifiProStateMachine_->networkSelectionResult_)) {
        WIFI_LOGI("wifi to wifi step X: TryWifi2Wifi Failed.");
        pWifiProStateMachine_->Wifi2WifiFinish();
    }
}

void WifiProStateMachine::WifiHasNetState::RequestHttpDetect()
{
    WIFI_LOGI("Enter RequestHttpDetect.");
    sptr<NetStateObserver> mNetWorkDetect = sptr<NetStateObserver>(new NetStateObserver());
    mNetWorkDetect->StartWifiDetection();
    netDiasableDetectCount_ = 0;
}

void WifiProStateMachine::WifiHasNetState::ParseQoeInfoAndRequestDetect()
{
    pWifiProStateMachine_->StopTimer(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL);
    pWifiProStateMachine_->MessageExecutedLater(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL,
        INTERNET_STATUS_DETECT_INTERVAL_MS);
    int64_t mCurrentTcpTxCounter = IpQosMonitor::GetInstance().GetCurrentTcpTxCounter();
    int64_t mCurrentTcpRxCounter = IpQosMonitor::GetInstance().GetCurrentTcpRxCounter();
    int32_t mCurrentDnsFailedCnt = SelfCureUtils::GetInstance().GetCurrentDnsFailedCounter();

    // caculate delta of TX RX DNSFailedCount
    int64_t deltaTcpTxPkts = mCurrentTcpTxCounter - mLastTcpTxCounter_;
    int64_t deltaTcpRxPkts = mCurrentTcpRxCounter - mLastTcpRxCounter_;
    int32_t deltaFailedDns = mCurrentDnsFailedCnt - mLastDnsFailedCnt_;
    mLastTcpTxCounter_ = mCurrentTcpTxCounter;
    mLastTcpRxCounter_ = mCurrentTcpRxCounter;
    mLastDnsFailedCnt_ = mCurrentDnsFailedCnt;
    WIFI_LOGI("deltaTcpTxPkts = %{public}" PRId64 ", deltaTcpRxPkts = %{public}" PRId64 ", deltaFailedDns = %{public}d"
              ", nedisable = %{public}d",
        deltaTcpTxPkts, deltaTcpRxPkts, deltaFailedDns, netDiasableDetectCount_);

    // if Rx = 0 DNSFailedCount >=2  detect network
    if (deltaTcpRxPkts == 0 && deltaFailedDns >= MIN_DNS_FAILED_CNT) {
        WIFI_LOGI("Rx = 0 && DNSFailed > 2 detect");
        pWifiProStateMachine_->SendMessage(EVENT_REQUEST_NETWORK_DETECT);
        return;
    }

    // if Rx = 0 Tx >=2  Count++, if Count >= 2 detect network
    if (deltaTcpRxPkts == 0 && deltaTcpTxPkts >= MIN_TCP_TX) {
        netDiasableDetectCount_++;
        if (netDiasableDetectCount_ >= DEFAULT_NET_DISABLE_DETECT_COUNT) {
            WIFI_LOGI("Rx = 0 Tx >=2 Count >= 2 detect");
            pWifiProStateMachine_->SendMessage(EVENT_REQUEST_NETWORK_DETECT);
        }
        return;
    }
    netDiasableDetectCount_ = 0;
}

void WifiProStateMachine::WifiHasNetState::HandleWifiQoeSlow()
{
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (signalLevel >= SIG_LEVEL_3) {
        WIFI_LOGI("wifi to wifi, app qoe slow");
        pWifiProStateMachine_->FullScan();
        pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_APP_QOE_SLOW);
        qoeSwitch_ = true;
    }
}
/* --------------------------- state machine no net state ------------------------------ */
WifiProStateMachine::WifiNoNetState::WifiNoNetState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiNoNetState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("WifiNoNetState construct success.");
}

WifiProStateMachine::WifiNoNetState::~WifiNoNetState() {}

void WifiProStateMachine::WifiNoNetState::GoInState()
{
    WIFI_LOGI("WifiNoNetState GoInState function.");
    HandleNoNetChanged();
}

void WifiProStateMachine::WifiNoNetState::GoOutState()
{
    WIFI_LOGI("WifiNoNetState GoOutState function.");
    pWifiProStateMachine_->isFirstNetDectect_ = false;
}

bool WifiProStateMachine::WifiNoNetState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGD("WifiNoNetState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_HANDLE_SCAN_RESULT:
            HandleWifiNoInternet(msg);
            ret = EXECUTED;
            break;
        case EVENT_REQUEST_SCAN_DELAY:
            HandleReuqestScanInNoNet(msg);
            ret = EXECUTED;
            break;
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            ret = HandleHttpResultInNoNet(msg);
            break;
        default:
            return ret;
    }
    return ret;
}

void WifiProStateMachine::WifiNoNetState::HandleWifiNoInternet(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleWifiNoInternet, msg is nullptr.");
        return;
    }
    std::vector<InterScanInfo> scanInfos;
    msg->GetMessageObj(scanInfos);

    if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
        WIFI_LOGI("HandleWifiNoInternet Wifi2WifiSwitching.");
        return;
    }

    WIFI_LOGI("NoNetSwitch 1: select network.");
    if (!pWifiProStateMachine_->SelectNetwork(pWifiProStateMachine_->networkSelectionResult_,
        NetworkSelectType::WIFI2WIFI, scanInfos)) {
        if (!fullScan_) {
            WIFI_LOGI("fastscan select net failed, try full scan.");
            pWifiProStateMachine_->SendMessage(EVENT_REQUEST_SCAN_DELAY);
            return;
        }
        WIFI_LOGI("NoInternet X: select network fail.");
        if (pWifiProStateMachine_->TrySelfCure(false)) {
            pWifiProStateMachine_->Wifi2WifiFinish();
        }
        return;
    }

    WIFI_LOGI("NoNetSwitch 2: receive good ap.");
    if (!pWifiProStateMachine_->IsSatisfiedWifi2WifiCondition()) {
        if (pWifiProStateMachine_->TrySelfCure(false)) {
            pWifiProStateMachine_->Wifi2WifiFinish();
        }
        return;
    }

    WIFI_LOGI("NoNetSwitch step 3: try wifi2wifi.");
    if (!pWifiProStateMachine_->TryWifi2Wifi(pWifiProStateMachine_->networkSelectionResult_)) {
        WIFI_LOGI("NoNetSwitch step X: TryWifi2Wifi Failed.");
        pWifiProStateMachine_->Wifi2WifiFinish();
    }
}

void WifiProStateMachine::WifiNoNetState::HandleReuqestScanInNoNet(const InternalMessagePtr msg)
{
    WIFI_LOGI("HandleReuqestScanInNoNet, enter.");
    if (msg == nullptr) {
        WIFI_LOGI("ReuqestScanInNoNet, msg is nullptr.");
        return;
    }
    pWifiProStateMachine_->FullScan();
    fullScan_ = true;
}

void WifiProStateMachine::WifiNoNetState::HandleNoNetChanged()
{
    WIFI_LOGI("HandleNoNetChanged, enter.");
    fullScan_ = false;
    pWifiProStateMachine_->isWifi2WifiSwitching_ = false;
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_NONET;
    pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_NO_INTERNET);
    pWifiProStateMachine_->perf5gHandoverService_.NetworkStatusChanged(NetworkStatus::NO_INTERNET);
 
    // issatisfy scan
    ISelfCureService *pSelfCureService =
        WifiServiceManager::GetInstance().GetSelfCureServiceInst(pWifiProStateMachine_->instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("self cure ongoing.");
        return;
    }

    // Fastscan Or fullScan
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    if (scanInfoList.size() == 0) {
        WIFI_LOGI("HandleNoNetChanged, error, do full channel scan.");
        pWifiProStateMachine_->SendMessage(EVENT_REQUEST_SCAN_DELAY);
        return;
    }

    pWifiProStateMachine_->FastScan(scanInfoList);
    return;
}

bool WifiProStateMachine::WifiNoNetState::HandleHttpResultInNoNet(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("ReuqestScanInNoNet, msg is nullptr.");
        return NOT_EXECUTED;
    }
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_DISABLED)) {
        pWifiProStateMachine_->FullScan();
        return EXECUTED;
    }
    return NOT_EXECUTED;
}
/* --------------------------- state machine portal state ------------------------------ */
WifiProStateMachine::WifiPortalState::WifiPortalState(WifiProStateMachine *pWifiProStateMachine)
    : State("WifiPortalState"),
      pWifiProStateMachine_(pWifiProStateMachine)
{
    WIFI_LOGD("WifiPortalState construct success.");
}

WifiProStateMachine::WifiPortalState::~WifiPortalState() {}

void WifiProStateMachine::WifiPortalState::GoInState()
{
    WIFI_LOGI("WifiPortalState GoInState function.");
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_PORTAL;
    pWifiProStateMachine_->perf5gHandoverService_.NetworkStatusChanged(NetworkStatus::PORTAL);
}

void WifiProStateMachine::WifiPortalState::GoOutState()
{
    WIFI_LOGI("WifiPortalState GoOutState function.");
    pWifiProStateMachine_->isFirstNetDectect_ = false;
}

bool WifiProStateMachine::WifiPortalState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiPortalState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_HANDLE_SCAN_RESULT:
            break;
        default:
            return false;
    }
    return true;
}

} // namespace Wifi
} // namespace OHOS