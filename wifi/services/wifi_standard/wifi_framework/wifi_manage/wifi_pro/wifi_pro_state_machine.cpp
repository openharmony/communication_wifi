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
#include "iscan_service.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_pro_state_machine.h"
#include "wifi_service_manager.h"
#include "wifi_pro_utils.h"
#include "network_black_list_manager.h"

namespace OHOS {
namespace Wifi {
namespace {
const std::string WIFI_PRO_STATE_MACHINE = "WifiProStateMachine";
constexpr int32_t DEFAULT_RSSI = -200;
constexpr int32_t DEFAULT_SCAN_INTERVAL = 10 * 1000; // ms
constexpr int64_t BLOCKLIST_VALID_TIME = 120 * 1000; // ms
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
    if (WifiProUtils::IsUserSelectNetwork() && (!isWifiNoInternet_)) {
        WIFI_LOGI("IsKeepCurrWifiConnected, user select network.");
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
    WIFI_LOGI("RefreshConnectedNetWork, connState:%{public}d,"
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
            WIFI_LOGI("RefreshConnectedNetWork, find device config.");
            pCurrWifiDeviceConfig_ = std::make_shared<WifiDeviceConfig>(wifiDeviceConfig);
        }
    }
}

bool WifiProStateMachine::IsReachWifiScanThreshold(int32_t signalLevel)
{
    WIFI_LOGI("IsReachWifiScanThreshold, rssiLevel:%{public}d.", signalLevel);
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
    pWifiProStateMachine_->isWifiProEnabled_ = true;
    WIFI_LOGI("state transition: DefaultState -> WifiProEnableState.");
    pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiProEnableState_);
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
    pWifiProStateMachine_->isWifiNoInternet_ = false;
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
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
        WIFI_LOGI("state transition: WifiProEnableState -> WifiConnectedState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
    } else if (state == static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED)) {
        WIFI_LOGI("state transition: WifiProEnableState -> WifiDisConnectedStat.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiDisConnectedState_);
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
    switch (msg->GetMessageName()) {
        case EVENT_NOTIFY_WIFI_PRO_SWITCH_CHANGED:
            HandleWifiProSwitchChanged(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiProDisabledState::HandleWifiProSwitchChanged(const InternalMessagePtr msg)
{
    pWifiProStateMachine_->isWifiProEnabled_ = static_cast<bool>(msg->GetParam1());
    if (pWifiProStateMachine_->isWifiProEnabled_) {
        WIFI_LOGI("state transition: WifiProDisabledState -> WifiProEnableState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiProEnableState_);
    }
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
            HandleHttpResultInConnected(msg);
            break;
        case EVENT_WIFI_CONNECT_STATE_CHANGED:
            HandleWifiConnectStateChangedInConnected(msg);
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
    } else {
        pWifiProStateMachine_->isWifiNoInternet_ = false;
    }
}

void WifiProStateMachine::WifiConnectedState::HandleWifiConnectStateChangedInConnected(
    const InternalMessagePtr msg)
{
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiDisconnectedState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiDisConnectedState_);
    } else {
        pWifiProStateMachine_->disconnectToConnectedState_ = false;
    }
}

void WifiProStateMachine::WifiConnectedState::HandleHttpResultInConnected(const InternalMessagePtr msg)
{
    int32_t state = msg->GetParam1();
    WIFI_LOGI("Enter HandleHttpResultInConnected, state:%{public}d.", state);

    if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_DISABLED)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiNoNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiNoNetState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL)) {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiNoNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiNoNetState_);
    } else {
        WIFI_LOGI("state transition: WifiConnectedState -> WifiHasNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiHasNetState_);
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
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiDisconnectedState::HandleWifiConnectStateChangedInDisconnected(
    const InternalMessagePtr msg)
{
    WIFI_LOGD("Enter HandleWifiConnectStateChangedInDisconnected.");
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
        WIFI_LOGI("state transition: WifiDisconnectedState -> WifiConnectedState.");
        pWifiProStateMachine_->disconnectToConnectedState_ = true;
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
    }
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
    isScanTriggered_ = false;
    isWifi2WifiSwitching_ = false;
    targetBssid_ = "";
    pWifiProStateMachine_->isWifiNoInternet_ = false;
}

void WifiProStateMachine::WifiHasNetState::GoOutState()
{
    WIFI_LOGI("WifiHasNetState GoOutState function.");
    return;
}

bool WifiProStateMachine::WifiHasNetState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiHasNetState-msgCode=%{public}d is received.", msg->GetMessageName());
    bool ret = true;
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_RSSI_CHANGED:
            HandleRssiChangedInHasNet(msg);
            break;
        case EVENT_WIFI_CONNECT_STATE_CHANGED:
            ret = HandleConnectStateChangedInHasNet(msg);
            break;
        case EVENT_REQUEST_SCAN_DELAY:
            HandleReuqestScanInHasNet(msg);
            break;
        case EVENT_HANDLE_SCAN_RESULT:
            HandleScanResultInHasNet(msg);
            break;
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            HandleHttpResultInHasNet(msg);
            break;
        case EVENT_WIFI2WIFI_FAILED:
            HandleWifi2WifiFailed(false);
            break;
        default:
            return false;
    }
    return ret;
}

void WifiProStateMachine::WifiHasNetState::HandleHttpResultInHasNet(const InternalMessagePtr msg)
{
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL)) {
        WIFI_LOGI("HandleHttpResultInHasNet, state transition: WifiHasNetState -> WifiPortalState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiPortalState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL)) {
        WIFI_LOGI("HandleHttpResultInHasNet, state transition: WifiHasNetState -> WifiNoNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiNoNetState_);
    } else {
        return;
    }
}

void WifiProStateMachine::WifiHasNetState::HandleRssiChangedInHasNet(const InternalMessagePtr msg)
{
    pWifiProStateMachine_->currentRssi_ = msg->GetParam1();
    if ((isWifi2WifiSwitching_) || (pWifiProStateMachine_->isWifiNoInternet_)) {
        WIFI_LOGI("HasNetState, isWifi2WifiSwitching:%{public}d,isWifiNoInternet:%{public}d.",
            isWifi2WifiSwitching_, pWifiProStateMachine_->isWifiNoInternet_);
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
        WIFI_LOGI("HandleRssiChangedInHasNet, StopTimer EVENT_REQUEST_SCAN_DELAY.");
        pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
        return;
    }

    if (!IsSatisfiedWifiOperationCondition()) {
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

    if (WifiProUtils::IsUserSelectNetwork() && signalLevel == SIG_LEVEL_2) {
        WIFI_LOGI("HandleReuqestScanInHasNet, user select network and signal = 2.");
        return;
    }

    TryStartScan(hasSwitchRecord, signalLevel);
}

void WifiProStateMachine::WifiHasNetState::TryStartScan(bool hasSwitchRecord, int32_t signalLevel)
{
    // calculate the interval and the max scan counter.
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(pWifiProStateMachine_->instId_);
    if (pScanService == nullptr) {
        WIFI_LOGI("TryStartScan, pService is nullptr.");
        return;
    }

    int32_t scanInterval = WifiProUtils::GetScanInterval(hasSwitchRecord, signalLevel);
    int32_t scanMaxCounter = WifiProUtils::GetMaxCounter(hasSwitchRecord, signalLevel);
    if ((signalLevel == SIG_LEVEL_2 || signalLevel == SIG_LEVEL_3) &&
        rssiLevel2Or3ScanedCounter_ < scanMaxCounter) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
            "rssiLevel2Or3ScanedCounter:%{public}d.", signalLevel, rssiLevel2Or3ScanedCounter_);
        rssiLevel2Or3ScanedCounter_++;
        pScanService->Scan(true);
        isScanTriggered_ = true;
        pWifiProStateMachine_->MessageExecutedLater(EVENT_REQUEST_SCAN_DELAY, hasSwitchRecord, scanInterval);
    } else if ((signalLevel < SIG_LEVEL_2) && (rssiLevel0Or1ScanedCounter_ < scanMaxCounter)) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
            "rssiLevel0Or1ScanedCounter:%{public}d.", signalLevel, rssiLevel0Or1ScanedCounter_);
        rssiLevel0Or1ScanedCounter_++;
        pScanService->Scan(true);
        isScanTriggered_ = true;
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

    if (!isScanTriggered_) {
        WIFI_LOGI("HandleScanResultInHasNet, scan is not triggered, skip network selection.");
        return;
    }

    WIFI_LOGI("start to wifi2wifi select network.");
    std::unique_ptr<NetworkSelectionManager> pNetworkSelectionManager = std::make_unique<NetworkSelectionManager>();
    NetworkSelectionResult networkSelectionResult;
    if (pNetworkSelectionManager->SelectNetwork(networkSelectionResult, NetworkSelectType::WIFI2WIFI, scanInfos)) {
        std::string &bssid = networkSelectionResult.interScanInfo.bssid;
        std::string &ssid = networkSelectionResult.interScanInfo.ssid;
        WIFI_LOGI("Wifi2Wifi select network result, ssid: %{public}s, bssid: %{public}s.",
            SsidAnonymize(ssid).c_str(), MacAnonymize(bssid).c_str());
        targetBssid_ = networkSelectionResult.interScanInfo.bssid;
        isScanTriggered_ = false;
        HandleCheckResultInHasNet(networkSelectionResult);
    } else {
        WIFI_LOGI("wifi to wifi step X: Wifi2Wifi select network fail.");
        Wifi2WifiFailed();
    }
}

bool WifiProStateMachine::WifiHasNetState::IsSatisfiedWifiOperationCondition()
{
    if (pWifiProStateMachine_->isWifiNoInternet_) {
        WIFI_LOGI("IsSatisfiedWifiOperationCondition, wifi no internet.");
        return false;
    }

    if (isWifi2WifiSwitching_) {
        WIFI_LOGI("IsSatisfiedWifiOperationCondition, wifi2Wifi is processing.");
        return false;
    }

    ISelfCureService *pSelfCureService =
        WifiServiceManager::GetInstance().GetSelfCureServiceInst(pWifiProStateMachine_->instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("IsSatisfiedWifiOperationCondition, self cure ongoing.");
        return false;
    }

    return true;
}

bool WifiProStateMachine::WifiHasNetState::HandleConnectStateChangedInHasNet(
    const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleConnectStateChangedInHasNet, msg is nullptr.");
        return true;
    }

    WIFI_LOGI("receive wifi2wifi Result,isWifi2WifiSwitching = %{public}d.", isWifi2WifiSwitching_);
    int32_t state = msg->GetParam1();
    std::string bssid;
    msg->GetMessageObj(bssid);
    if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
        if (!isWifi2WifiSwitching_) {
            return true;
        }

        if (targetBssid_ != bssid) {
            WIFI_LOGI("selected bssid and switched bssid are not same:selected bssid:%{public}s,"
                "switched bssid:%{public}s,",
                MacAnonymize(targetBssid_).c_str(), MacAnonymize(bssid).c_str());
            NetworkBlockListManager::GetInstance().AddWifiBlocklist(bssid);
            pWifiProStateMachine_->MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST, bssid, BLOCKLIST_VALID_TIME);
            HandleWifi2WifiFailed(true);
        } else {
            HandleWifi2WifiSucsess();
        }
    } else {
        WIFI_LOGI("HasNetState, network disconnected");
    }
    return true;
}

void WifiProStateMachine::WifiHasNetState::HandleWifi2WifiSucsess()
{
    WIFI_LOGI("Enter HandleWifi2WifiSucsess");
    auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
    networkBlackListManager.AddWifiBlocklist(pWifiProStateMachine_->badBssid_);
    pWifiProStateMachine_->MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST, pWifiProStateMachine_->badBssid_,
        BLOCKLIST_VALID_TIME);
    networkBlackListManager.CleanTempWifiBlockList();
    pWifiProStateMachine_->RefreshConnectedNetWork();
    isWifi2WifiSwitching_ = false;
    WIFI_LOGI("state transition: WifiHasNetState -> WifiConnectedState.");
    pWifiProStateMachine_->disconnectToConnectedState_ = false;
    pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
}

void WifiProStateMachine::WifiHasNetState::HandleWifi2WifiFailed(bool isConnected)
{
    WIFI_LOGI("wifi to wifi step X: wifi to Wifi Failed Finally.");
    auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
    if (networkBlackListManager.IsFailedMultiTimes(targetBssid_)) {
        WIFI_LOGI("HandleWifi2WifiFailed, add to abnormal black list:%{public}s.",
            MacAnonymize(targetBssid_).c_str());
        networkBlackListManager.AddAbnormalWifiBlocklist(targetBssid_);
        networkBlackListManager.CleanTempWifiBlockList();
    }
    isWifi2WifiSwitching_ = false;
    isScanTriggered_ = false;
    pWifiProStateMachine_->badBssid_ = "";
    targetBssid_ = "";
    if (isConnected) {
        pWifiProStateMachine_->disconnectToConnectedState_ = false;
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
    } else {
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiDisConnectedState_);
    }
}

void WifiProStateMachine::WifiHasNetState::HandleCheckResultInHasNet(
    const NetworkSelectionResult &networkSelectionResult)
{
    WIFI_LOGI("wifi to wifi step 2: receive good ap in has net state.");
    if (!IsSatisfiedWifiOperationCondition()) {
        WIFI_LOGI("wifi to wifi step 3: target AP is not reach handover threshold.");
        return;
    }

    // rssi conditions and Wifi2WifiThreshold conditions have been considered when selecting a network.
    WIFI_LOGI("wifi to wifi step 3: target AP reach handover threshold.");
    // User preference is not considered for now
    TryWifiHandoverPreferentially(networkSelectionResult);
}

void WifiProStateMachine::WifiHasNetState::TryWifiHandoverPreferentially(
    const NetworkSelectionResult &networkSelectionResult)
{
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (!pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel)) {
        WIFI_LOGI("TryWifiHandoverPreferentially, do not reach wifi scan threshold.");
        return;
    }

    // Non-default network does not switch
    if (!WifiProUtils::IsDefaultNet()) {
        WIFI_LOGI("TryWifiHandoverPreferentially, not default network, do not switch wifi.");
        return;
    }

    WIFI_LOGW("try wifi --> wifi only, current rssi:%{public}d.", signalLevel);
    TryWifiRoveOut(networkSelectionResult);
}

void WifiProStateMachine::WifiHasNetState::TryWifiRoveOut(const NetworkSelectionResult &networkSelectionResult)
{
    WIFI_LOGI("wifi to wifi step 4: try wifi Rove Out.");
    if (pWifiProStateMachine_->IsKeepCurrWifiConnected()) {
        return;
    }

    HandleWifiRoveOut(networkSelectionResult);
}

void WifiProStateMachine::WifiHasNetState::HandleWifiRoveOut(const NetworkSelectionResult &networkSelectionResult)
{
    bool isCallingInCs = IsCallingInCs();
    if ((isDisableWifiAutoSwitch_) || isCallingInCs) {
        WIFI_LOGW("isDisableWifiAutoSwitch:%{public}d, isCallingInCs:%{public}d.",
            isDisableWifiAutoSwitch_, isCallingInCs);
        return;
    }

    TryWifi2Wifi(networkSelectionResult);
}

void WifiProStateMachine::WifiHasNetState::TryWifi2Wifi(const NetworkSelectionResult &networkSelectionResult)
{
    pWifiProStateMachine_->badBssid_ = pWifiProStateMachine_->currentBssid_;
    pWifiProStateMachine_->badSsid_ = pWifiProStateMachine_->currentSsid_;
    pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);

    if (pWifiProStateMachine_->isWifiNoInternet_) {
        pWifiProStateMachine_->wifiSwitchReason_ = WIFI_SWITCH_REASON_NO_INTERNET;
    } else {
        pWifiProStateMachine_->wifiSwitchReason_ = WIFI_SWITCH_REASON_POOR_RSSI;
    }

    if (!HandleWifiToWifi(pWifiProStateMachine_->wifiSwitchReason_, networkSelectionResult)) {
        WIFI_LOGI("wifi to wifi step X: HandleWifiToWifi Failed.");
        Wifi2WifiFailed();
    }
}

void WifiProStateMachine::WifiHasNetState::Wifi2WifiFailed()
{
    isWifi2WifiSwitching_ = false;
    isScanTriggered_ = false;
    pWifiProStateMachine_->badBssid_ = "";
    targetBssid_ = "";
}

bool WifiProStateMachine::WifiHasNetState::HandleWifiToWifi(int32_t switchReason,
    const NetworkSelectionResult &networkSelectionResult)
{
    WIFI_LOGI("wifi to wifi step 5: handle wifi2wifi command.");
    if (switchReason == WIFI_SWITCH_REASON_POOR_RSSI) {
        WIFI_LOGI("wifi to wifi step 5.5: direct wifi 2 wifi handover.");
        UpdateWifiSwitchTimeStamp();
        return TrySwitchWifiNetwork(networkSelectionResult);
    }

    return true;
}

void WifiProStateMachine::WifiHasNetState::UpdateWifiSwitchTimeStamp()
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
        WIFI_LOGI("UpdateWifiSwitchTimeStamp, get device config failed");
    }
}

bool WifiProStateMachine::WifiHasNetState::TrySwitchWifiNetwork(
    const NetworkSelectionResult &networkSelectionResult)
{
    int32_t networkId = networkSelectionResult.wifiDeviceConfig.networkId;
    WIFI_LOGI("wifi to wifi step 7: start to connect to new wifi.");
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(pWifiProStateMachine_->instId_);
    if (pStaService == nullptr) {
        WIFI_LOGE("TrySwitchWifiNetwork, pStaService is invalid");
        return false;
    }
    isWifi2WifiSwitching_ = true;
    if (pStaService->ConnectToNetwork(networkId, NETWORK_SELECTED_BY_AUTO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("TrySwitchWifiNetwork, ConnectToNetwork failed.");
        return false;
    }

    return true;
}

bool WifiProStateMachine::WifiHasNetState::IsCallingInCs()
{
    return false;
}

bool WifiProStateMachine::WifiHasNetState::IsFullscreen()
{
    return false;
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
    pWifiProStateMachine_->isWifiNoInternet_ = true;
}

void WifiProStateMachine::WifiNoNetState::GoOutState()
{
    WIFI_LOGI("WifiNoNetState GoOutState function.");
}

bool WifiProStateMachine::WifiNoNetState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiNoNetState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            HandleHttpResultInNoNet(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiNoNetState::HandleHttpResultInNoNet(const InternalMessagePtr msg)
{
    WIFI_LOGD("Enter HandleHttpResultInNoNet.");
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED)) {
        WIFI_LOGI("HandleHttpResultInNoNet, state transition: WifiNoNetState -> WifiHasNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiHasNetState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL)) {
        WIFI_LOGI("HandleHttpResultInNoNet, state transition: WifiNoNetState -> WifiPortalState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiPortalState_);
    } else {
        return;
    }
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
    pWifiProStateMachine_->isWifiNoInternet_ = false;
}

void WifiProStateMachine::WifiPortalState::GoOutState()
{
    WIFI_LOGI("WifiPortalState GoOutState function.");
}

bool WifiProStateMachine::WifiPortalState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("WifiPortalState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            HandleHttpResultInPortal(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiPortalState::HandleHttpResultInPortal(
    const InternalMessagePtr msg)
{
    WIFI_LOGD("Enter HandleHttpResultInPortal.");
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED)) {
        WIFI_LOGI("HandleHttpResultInPortal, state transition: WifiPortalState -> WifiHasNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiHasNetState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_DISABLED)) {
        WIFI_LOGI("HandleHttpResultInPortal, state transition: WifiPortalState -> WifiNoNetState.");
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiNoNetState_);
    } else {
        return;
    }
}
} // namespace Wifi
} // namespace OHOS