/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_intelligence_state_machine.h"
#include "wifi_pro_common.h"
#include "wifi_common_util.h"
#include "wifi_service_manager.h"
#include "wifi_manager.h"
#include "wifi_config_center.h"

namespace OHOS {
namespace Wifi {
namespace {
const std::string WIFI_INTELLIGENCE_STATE_MACHINE = "WifiIntelligenceStateMachine";
const int PING_PONG_TIME = 5 * 1000;
const int PING_PONG_INTERVAL_TIME = 30 * 60 * 1000;
const int PING_PONG_MAX_PUNISH_TIME = 300 * 1000;
const int PING_PONG_PUNISH_TIME = 30 * 1000;
const int AUTO_OPEN_RSSI_VALUE = -75;
const int SCAN_TOTLE_TIMES = 20;
const int SCAN_TYPE_SHORT = 0;
const int SCAN_TYPE_ONE = 1;
const int SCAN_TYPE_TWO = 2;
const int SCAN_TYPE_THREE = 3;
const int SCAN_INTERVAL_NORMAL_1 = 1 * 60 * 1000;
const int SCAN_INTERVAL_NORMAL_3 = 3 * 60 * 1000;
const int SCAN_INTERVAL_NORMAL_5 = 5 * 60 * 1000;
const int SCAN_INTERVAL_SHORT = 20 * 1000;
const int AUTO_OPEN_WIFI_DELAY_TIME = 3 * 1000;
}
DEFINE_WIFILOG_LABEL("WifiIntelligenceStateMachine");

WifiIntelligenceStateMachine::WifiIntelligenceStateMachine(int32_t instId)
    : StateMachine(WIFI_INTELLIGENCE_STATE_MACHINE),
    instId_(instId)
{
    WIFI_LOGI("Enter WifiIntelligenceStateMachine");
}

WifiIntelligenceStateMachine::~WifiIntelligenceStateMachine()
{
    WIFI_LOGI("Enter ~WifiIntelligenceStateMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState_);
    ParsePointer(pInitialState_);
    ParsePointer(pEnabledState_);
    ParsePointer(pDisabledState_);
    ParsePointer(pStopState_);
    ParsePointer(pConnectedState_);
    ParsePointer(pDisconnectedState_);
    ParsePointer(pInternetReadyState_);
    ParsePointer(pNoInternetState_);
}

void WifiIntelligenceStateMachine::BuildStateTree()
{
    StatePlus(pDefaultState_, nullptr);
    StatePlus(pInitialState_, pDefaultState_);
    StatePlus(pEnabledState_, pDefaultState_);
    StatePlus(pDisabledState_, pDefaultState_);
    StatePlus(pStopState_, pDefaultState_);
    StatePlus(pConnectedState_, pEnabledState_);
    StatePlus(pDisconnectedState_, pEnabledState_);
    StatePlus(pInternetReadyState_, pConnectedState_);
    StatePlus(pNoInternetState_, pConnectedState_);
}

ErrCode WifiIntelligenceStateMachine::InitWifiIntelligenceStates()
{
    WIFI_LOGI("Enter InitWifiIntelligenceStates");
    int32_t tmpErrNumber = 0;
    pDefaultState_ = new (std::nothrow)DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState_);
    pInitialState_ = new (std::nothrow)InitialState(this);
    tmpErrNumber += JudgmentEmpty(pInitialState_);
    pEnabledState_ = new (std::nothrow)EnabledState(this);
    tmpErrNumber += JudgmentEmpty(pEnabledState_);
    pDisabledState_ = new (std::nothrow)DisabledState(this);
    tmpErrNumber += JudgmentEmpty(pDisabledState_);
    pStopState_ = new (std::nothrow)StopState(this);
    tmpErrNumber += JudgmentEmpty(pStopState_);
    pConnectedState_ = new (std::nothrow)ConnectedState(this);
    tmpErrNumber += JudgmentEmpty(pConnectedState_);
    pDisconnectedState_ = new (std::nothrow)DisconnectedState(this);
    tmpErrNumber += JudgmentEmpty(pDisconnectedState_);
    pInternetReadyState_ = new (std::nothrow)InternetReadyState(this);
    tmpErrNumber += JudgmentEmpty(pInternetReadyState_);
    pNoInternetState_ = new (std::nothrow)NoInternetState(this);
    tmpErrNumber += JudgmentEmpty(pNoInternetState_);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitWifiIntelligenceStates someone state is null");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiIntelligenceStateMachine::Initialize()
{
    if (!InitialStateMachine(WIFI_INTELLIGENCE_STATE_MACHINE)) {
        WIFI_LOGE("Initial WifiProStateMachine failed.");
        return WIFI_OPT_FAILED;
    }
    if (InitWifiIntelligenceStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    ApInfoHelper::GetInstance().Init();
    BuildStateTree();
    SetFirstState(pInitialState_);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

/* --------------------------- state machine default state ------------------------------ */
WifiIntelligenceStateMachine::DefaultState::DefaultState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("DefaultState"),
      pWifiIntelligenceStateMachine_(pWifiIntelligenceStateMachine)
{
    WIFI_LOGD("DefaultState construct success.");
}

WifiIntelligenceStateMachine::DefaultState::~DefaultState() {}

void WifiIntelligenceStateMachine::DefaultState::GoInState()
{
    WIFI_LOGI("Enter DefaultState GoInState function.");
}

void WifiIntelligenceStateMachine::DefaultState::GoOutState()
{
    WIFI_LOGI("Enter DefaultState GoOutState function.");
}

bool WifiIntelligenceStateMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("DefaultState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_CONNECT_STATE_CHANGED: {
            ret = EXECUTED;
            int32_t state = msg->GetParam1();
            if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
                pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pConnectedState_);
            } else if (state == static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED)) {
                pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pDisconnectedState_);
            }
            break;
        }
        case EVENT_WIFI_ENABLED: {
            ret = EXECUTED;
            pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pEnabledState_);
            break;
        }
        case EVENT_WIFI_DISABLED: {
            ret = EXECUTED;
            int32_t state = msg->GetParam1();
            if (state == static_cast<int>(OperateResState::CLOSE_WIFI_SUCCEED)) {
                pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pStopState_);
            } else if (state == static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED)) {
                pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pDisabledState_);
            }
            break;
        }
        case EVENT_SCREEN_ON: {
            ret = EXECUTED;
            pWifiIntelligenceStateMachine_->SendMessage(EVENT_HANDLE_STATE_CHANGE);
            break;
        }
        case EVENT_SCREEN_OFF: {
            ret = EXECUTED;
            pWifiIntelligenceStateMachine_->StopScanAp();
            break;
        }
        case EVENT_SCAN_AGAIN: {
            ret = EXECUTED;
            pWifiIntelligenceStateMachine_->FullScan();
            break;
        }
        default:
            WIFI_LOGW("DefaultState msg %{public}d.", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine initial state ------------------------------ */
WifiIntelligenceStateMachine::InitialState::InitialState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("InitialState"),
      pWifiIntelligenceStateMachine_(pWifiIntelligenceStateMachine)
{
    WIFI_LOGD("InitialState construct success.");
}

WifiIntelligenceStateMachine::InitialState::~InitialState() {}

void WifiIntelligenceStateMachine::InitialState::GoInState()
{
    WIFI_LOGI("Enter InitialState GoInState function.");
    pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = false;
    if (WifiConfigCenter::GetInstance().GetWifiMidState() != WifiOprMidState::RUNNING) {
        pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pDisabledState_);
    }
}

void WifiIntelligenceStateMachine::InitialState::GoOutState()
{
    WIFI_LOGI("Enter InitialState GoOutState function.");
}

bool WifiIntelligenceStateMachine::InitialState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGD("InitialState-msgCode=%{public}d is received.", msg->GetMessageName());
    return ret;
}

/* --------------------------- state machine enabled state ------------------------------ */
WifiIntelligenceStateMachine::EnabledState::EnabledState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("EnabledState")
{
    WIFI_LOGD("EnabledState construct success.");
}

WifiIntelligenceStateMachine::EnabledState::~EnabledState() {}

void WifiIntelligenceStateMachine::EnabledState::GoInState()
{
    WIFI_LOGI("Enter EnabledState GoInState function.");
    ApInfoHelper::GetInstance().ResetAllBalcklist();
}

void WifiIntelligenceStateMachine::EnabledState::GoOutState()
{
    WIFI_LOGI("Enter EnabledState GoOutState function.");
}

bool WifiIntelligenceStateMachine::EnabledState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("EnabledState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_ENABLED:
            ret = EXECUTED;
            break;
        default:
            WIFI_LOGD("EnabledState-msgCode=%{public}d not handle.", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine disabled state ------------------------------ */
WifiIntelligenceStateMachine::DisabledState::DisabledState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("DisabledState"),
      pWifiIntelligenceStateMachine_(pWifiIntelligenceStateMachine)
{
    WIFI_LOGD("DisabledState construct success.");
}

WifiIntelligenceStateMachine::DisabledState::~DisabledState() {}

void WifiIntelligenceStateMachine::DisabledState::GoInState()
{
    WIFI_LOGI("Enter DisabledState GoInState function.");
    pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = false;
    pWifiIntelligenceStateMachine_->StopScanAp();
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    if (scanInfoList.size() == 0) {
        WIFI_LOGE("get scan result is null.");
    }
    if (!pWifiIntelligenceStateMachine_->mTargetSsid_.empty()) {
        ApInfoHelper::GetInstance().SetBlackListBySsid(pWifiIntelligenceStateMachine_->mTargetSsid_,
            pWifiIntelligenceStateMachine_->mTargetAuthType_, 1);
    }
    pWifiIntelligenceStateMachine_->mTargetSsid_ = "";
    pWifiIntelligenceStateMachine_->mTargetAuthType_ = "";
    ApInfoHelper::GetInstance().ResetBlacklist(scanInfoList, 1);
    pWifiIntelligenceStateMachine_->InitPunishParameter();
}

void WifiIntelligenceStateMachine::InitPunishParameter()
{
    mLastCellChangeScanTime_ = 0;
    mLastScanPingpongTime_ = 0;
    mScanPingpongNum_ = 1;
}

void WifiIntelligenceStateMachine::DisabledState::GoOutState()
{
    WIFI_LOGI("Enter DisabledState GoOutState function.");
}

bool WifiIntelligenceStateMachine::DisabledState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("DisabledState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_CONFIGURATION_CHANGED: {
            ret = EXECUTED;
            if (WifiConfigCenter::GetInstance().IsScreenLandscape()) {
                break;
            }
        }
        case EVENT_CELL_STATE_CHANGE:
        case EVENT_HANDLE_STATE_CHANGE:
            ret = EXECUTED;
            HandleMsgStateChange(msg);
            break;
        case EVENT_WIFI_FIND_TARGET:
            ret = EXECUTED;
            HandleWifiFindTarget(msg);
            break;
        case EVENT_HANDLE_SCAN_RESULT:
            ret = EXECUTED;
            pWifiIntelligenceStateMachine_->UpdateScanResult(msg);
            break;
        case EVENT_WIFI_HANLE_OPEN:
            ret = EXECUTED;
            HandleWifiOpen(msg);
            break;
        case EVENT_WIFI_DISABLED:
            ret = EXECUTED;
            break;
        case EVENT_WIFI_CONNECT_STATE_CHANGED: {
            int32_t state = msg->GetParam1();
            if (state == static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED)) {
                ret = EXECUTED;
            }
            break;
        }
        default:
            WIFI_LOGI("DisabledState-msgCode=%{public}d not handle.", msg->GetMessageName());
            break;
    }
    return ret;
}

void WifiIntelligenceStateMachine::DisabledState::HandleMsgStateChange(InternalMessagePtr msg)
{
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    std::string cellId = ApInfoHelper::GetInstance().GetCurrentCellIdInfo();
    WIFI_LOGI("HandleMsgStateChange, cur cellId = %{private}s", cellId.c_str());
    if (cellId.empty()) {
        WIFI_LOGE("HandleMsgStateChange, current cell id is null.");
        return;
    }

    if (!ApInfoHelper::GetInstance().IsCellIdExit(cellId)) {
        std::vector<WifiScanInfo> scanInfoList;
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
        WIFI_LOGI("mIsAutoOpenSearch_:%{public}d, mTargetApInfoDatas_.size:%{public}lu, scanInfoList.size:%{public}lu",
            pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_,
            pWifiIntelligenceStateMachine_->mTargetApInfoDatas_.size(), scanInfoList.size());
        if (pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ &&
            pWifiIntelligenceStateMachine_->mTargetApInfoDatas_.size() > 0 && scanInfoList.size() > 0 &&
            pWifiIntelligenceStateMachine_->IsHasTargetAp(scanInfoList)) {
            pWifiIntelligenceStateMachine_->ProcessScanResult(scanInfoList,
                ApInfoHelper::GetInstance().GetCurrentCellIdInfo());
            pWifiIntelligenceStateMachine_->UpdateScanResult(msg);
            return;
        }
        pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = false;
        pWifiIntelligenceStateMachine_->StopScanAp();
        return;
    }

    std::vector<ApInfoData> datas = ApInfoHelper::GetInstance().GetMonitorDatas(cellId);
    pWifiIntelligenceStateMachine_->mTargetApInfoDatas_ = FilterFromBlackList(datas);
    WIFI_LOGI("mTargetApInfoDatas_.size:%{public}lu", pWifiIntelligenceStateMachine_->mTargetApInfoDatas_.size());
    if (pWifiIntelligenceStateMachine_->mTargetApInfoDatas_.size() > 0 && screenState == MODE_STATE_OPEN &&
        WifiConfigCenter::GetInstance().GetWifiMidState() != WifiOprMidState::RUNNING) {
        if (msg->GetMessageName() == EVENT_CELL_STATE_CHANGE) {
            pWifiIntelligenceStateMachine_->SetPingPongPunishTime();
            if (pWifiIntelligenceStateMachine_->IsInPingpongPunishTime()) {
                return;
            }
            pWifiIntelligenceStateMachine_->mLastScanPingpongTime_ = GetCurrentTimeMilliSeconds();
        }
        pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = true;
        pWifiIntelligenceStateMachine_->FullScan();
    } else {
        pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = false;
        pWifiIntelligenceStateMachine_->StopScanAp();
    }
}

bool WifiIntelligenceStateMachine::ProcessScanResult(std::vector<WifiScanInfo> scanInfoList, std::string cellId)
{
    bool checkResult = false;
    if (scanInfoList.size() == 0) {
        WIFI_LOGE("scan result is null.");
        return checkResult;
    }
    for (auto &scanResult : scanInfoList) {
        ApInfoData data;
        int index = ApInfoHelper::GetInstance().GetApInfoByBssid(scanResult.bssid, data);
        if (index != -1) {
            if (!ApInfoHelper::GetInstance().IsCellIdExit(cellId)) {
                ApInfoHelper::GetInstance().AddCellInfo(data.bssid, cellId);
                checkResult = true;
                std::vector<CellInfoData> cellInfos;
                ApInfoHelper::GetInstance().QueryCellIdInfoByParam({{CellIdInfoTable::BSSID, data.bssid}},
                    cellInfos);
                data.cellInfos = cellInfos;
            }
        }
    }
    return checkResult;
}

bool WifiIntelligenceStateMachine::IsHasTargetAp(std::vector<WifiScanInfo> &scanInfoList)
{
    for (auto &scanInfo : scanInfoList) {
        if (IsInTargetAp(scanInfo.bssid, scanInfo.ssid) && !IsInBlacklist(scanInfo.bssid)) {
            WIFI_LOGI("scan results has target ap.");
            return true;
        }
    }
    WIFI_LOGI("scan result has no target ap.");
    return false;
}

bool WifiIntelligenceStateMachine::IsInBlacklist(std::string bssid)
{
    ApInfoData data;
    int index = ApInfoHelper::GetInstance().GetApInfoByBssid(bssid, data);
    if (index == -1) {
        return false;
    }
    return data.inBlacklist == 1 ? true : false;
}

void WifiIntelligenceStateMachine::DisabledState::HandleWifiFindTarget(InternalMessagePtr msg)
{
    pWifiIntelligenceStateMachine_->StartTimer(EVENT_WIFI_HANLE_OPEN, AUTO_OPEN_WIFI_DELAY_TIME);
}

void WifiIntelligenceStateMachine::DisabledState::HandleWifiOpen(InternalMessagePtr msg)
{
    auto staState = WifiConfigCenter::GetInstance().GetWifiDetailState();
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState();
    if (staState == WifiDetailState::STATE_SEMI_ACTIVE && !WifiConfigCenter::GetInstance().IsScreenLandscape() &&
        screenState == MODE_STATE_OPEN &&
        (apState != WifiOprMidState::OPENING && apState != WifiOprMidState::RUNNING)) {
        WIFI_LOGI("HandleWifiOpen, open wifi.");
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
        return;
    } else if (staState == WifiDetailState::STATE_SEMI_ACTIVATING &&
        !WifiConfigCenter::GetInstance().IsScreenLandscape() && screenState == MODE_STATE_OPEN &&
        (apState != WifiOprMidState::OPENING && apState != WifiOprMidState::RUNNING)) {
        WIFI_LOGI("HandleWifiOpen, open wifi wait.");
        pWifiIntelligenceStateMachine_->StartTimer(EVENT_WIFI_HANLE_OPEN, AUTO_OPEN_WIFI_DELAY_TIME);
        return;
    }
    WIFI_LOGI("HandleWifiOpen, can't open wifi.");
    return;
}

void WifiIntelligenceStateMachine::UpdateScanResult(InternalMessagePtr msg)
{
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    WIFI_LOGI("UpdateScanResult, results size:%{public}lu", scanInfoList.size());
    if (!HandleScanResult(scanInfoList)) {
        mScanTimes_++;
        if (mScanTimes_ < SCAN_TOTLE_TIMES) {
            if (IsInMonitorNearbyAp(scanInfoList) && !mIsScanInShort_) {
                mIsScanInShort_ = true;
                mScanType_ = SCAN_TYPE_SHORT;
            }
            SetScanIntervel(mScanType_);
        } else {
            if (mScanType_ == SCAN_TYPE_THREE) {
                StopTimer(EVENT_SCAN_AGAIN);
                mScanTimes_ = 0;
                mScanType_ = SCAN_TYPE_ONE;
            } else {
                mScanType_++;
                mScanTimes_ = 0;
                SetScanIntervel(mScanType_);
            }
        }
    }
}

void WifiIntelligenceStateMachine::SetScanIntervel(int32_t scanType)
{
    int scanInterval = SCAN_INTERVAL_NORMAL_1;
    switch (scanType) {
        case SCAN_TYPE_SHORT:
            scanInterval = SCAN_INTERVAL_SHORT;
            break;
        case SCAN_TYPE_ONE:
            scanInterval = SCAN_INTERVAL_NORMAL_1;
            break;
        case SCAN_TYPE_TWO:
            scanInterval = SCAN_INTERVAL_NORMAL_3;
            break;
        case SCAN_TYPE_THREE:
            scanInterval = SCAN_INTERVAL_NORMAL_5;
            break;
        default:
            scanInterval = SCAN_INTERVAL_NORMAL_1;
            break;
    }
    StartTimer(EVENT_SCAN_AGAIN, scanInterval);
}

std::vector<ApInfoData> WifiIntelligenceStateMachine::DisabledState::FilterFromBlackList(std::vector<ApInfoData> &datas)
{
    std::vector<ApInfoData> results;
    for (ApInfoData data : datas) {
        if (!data.inBlacklist) {
            results.push_back(data);
        }
    }
    return results;
}

void WifiIntelligenceStateMachine::SetPingPongPunishTime()
{
    if (mLastCellChangeScanTime_ == 0) {
        mLastCellChangeScanTime_ = GetCurrentTimeMilliSeconds();
        return;
    }
    if (GetCurrentTimeMilliSeconds() - mLastCellChangeScanTime_ < PING_PONG_TIME) {
        WIFI_LOGI("setPingpongPunishTime is inPunish time");

        if (mLastScanPingpongTime_ == 0) {
            mScanPingpongNum_ = 1;
            mLastScanPingpongTime_ = GetCurrentTimeMilliSeconds();
        } else {
            if (GetCurrentTimeMilliSeconds() - mLastScanPingpongTime_ > PING_PONG_INTERVAL_TIME) {
                mScanPingpongNum_ = 1;
            } else {
                mScanPingpongNum_++;
            }
            WIFI_LOGI("setPingpongPunishTime mScanPingpongNum = %{public}d", mScanPingpongNum_);
        }
    } else {
        WIFI_LOGI("setPingpongPunishTime is not inPunish time");
    }
    mLastCellChangeScanTime_ = GetCurrentTimeMilliSeconds();
}

bool WifiIntelligenceStateMachine::IsInPingpongPunishTime()
{
    WIFI_LOGI("isInPingpongPunishTime mScanPingpongNum = %{public}d", mScanPingpongNum_);
    int punishTime = (mScanPingpongNum_ * PING_PONG_PUNISH_TIME)
        > PING_PONG_MAX_PUNISH_TIME ? PING_PONG_MAX_PUNISH_TIME : (mScanPingpongNum_ * PING_PONG_PUNISH_TIME);
    if (GetCurrentTimeMilliSeconds() - mLastScanPingpongTime_ < punishTime) {
        WIFI_LOGI("isInPingpongPunishTime punishTime = %{public}d", punishTime);
        return true;
    } else {
        WIFI_LOGI("isInPingpongPunishTime is not in punishTime");
        return false;
    }
}

/* --------------------------- state machine stop state ------------------------------ */
WifiIntelligenceStateMachine::StopState::StopState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("StopState"),
      pWifiIntelligenceStateMachine_(pWifiIntelligenceStateMachine)
{
    WIFI_LOGD("StopState construct success.");
}

WifiIntelligenceStateMachine::StopState::~StopState() {}

void WifiIntelligenceStateMachine::StopState::GoInState()
{
    WIFI_LOGI("Enter StopState GoInState function.");
}

void WifiIntelligenceStateMachine::StopState::GoOutState()
{
    WIFI_LOGI("Enter StopState GoOutState function.");
}

bool WifiIntelligenceStateMachine::StopState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("StopState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_WIFI_DISABLED: {
            ret = EXECUTED;
            int32_t state = msg->GetParam1();
            if (state == static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED)) {
                pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pDisabledState_);
            }
            break;
        }
        default:
            break;
    }
    return ret;
}

/* --------------------------- state machine disconnected state ------------------------------ */
WifiIntelligenceStateMachine::DisconnectedState::DisconnectedState(
    WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("DisconnectedState"),
      pWifiIntelligenceStateMachine_(pWifiIntelligenceStateMachine)
{
    WIFI_LOGD("DisconnectedState construct success.");
}

WifiIntelligenceStateMachine::DisconnectedState::~DisconnectedState() {}

void WifiIntelligenceStateMachine::DisconnectedState::GoInState()
{
    WIFI_LOGI("Enter DisconnectedState GoInState function.");
}

void WifiIntelligenceStateMachine::DisconnectedState::GoOutState()
{
    WIFI_LOGI("Enter DisconnectedState GoOutState function.");
}

bool WifiIntelligenceStateMachine::DisconnectedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("DisconnectedState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_UPDATE_TARGET_SSID: {
            ret = EXECUTED;
            pWifiIntelligenceStateMachine_->mTargetSsid_ = "";
            pWifiIntelligenceStateMachine_->mTargetAuthType_ = "";
            break;
        }
        default:
            WIFI_LOGI("DisconnectedState-msgCode=%{public}d not handle.", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine connected state ------------------------------ */
WifiIntelligenceStateMachine::ConnectedState::ConnectedState(
    WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("ConnectedState"),
      pWifiIntelligenceStateMachine_(pWifiIntelligenceStateMachine)
{
    WIFI_LOGD("ConnectedState construct success.");
}

WifiIntelligenceStateMachine::ConnectedState::~ConnectedState() {}

void WifiIntelligenceStateMachine::ConnectedState::GoInState()
{
    WIFI_LOGI("Enter ConnectedState GoInState function.");
    if (pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_) {
        pWifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = false;
        pWifiIntelligenceStateMachine_->mTargetApInfoDatas_.clear();
        pWifiIntelligenceStateMachine_->StopScanAp();
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config);
    pWifiIntelligenceStateMachine_->mTargetSsid_ = config.ssid;
    pWifiIntelligenceStateMachine_->mTargetAuthType_ = config.keyMgmt;
}

void WifiIntelligenceStateMachine::ConnectedState::GoOutState()
{
    WIFI_LOGI("Enter ConnectedState GoOutState function.");
}

bool WifiIntelligenceStateMachine::ConnectedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("ConnectedState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            ret = EXECUTED;
            HandleWifiInternetChangeRes(msg);
            break;
        default:
            break;
    }
    return ret;
}

void WifiIntelligenceStateMachine::ConnectedState::HandleWifiInternetChangeRes(const InternalMessagePtr msg)
{
    WIFI_LOGD("Enter HandleWifiInternetChangeRes.");
    if (msg == nullptr) {
        WIFI_LOGI("HandleWifiInternetChangeRes, msg is nullptr.");
        return;
    }

    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_DISABLED)) {
        pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pNoInternetState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL)) {
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
        ApInfoHelper::GetInstance().DeleteApInfoBySsidForPortal(linkedInfo);
        pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pNoInternetState_);
    } else if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED)) {
        pWifiIntelligenceStateMachine_->SwitchState(pWifiIntelligenceStateMachine_->pInternetReadyState_);
    }
}

/* --------------------------- state machine internet ready state ------------------------------ */
WifiIntelligenceStateMachine::InternetReadyState::InternetReadyState(
    WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("InternetReadyState")
{
    WIFI_LOGD("InternetReadyState construct success.");
}

WifiIntelligenceStateMachine::InternetReadyState::~InternetReadyState() {}

void WifiIntelligenceStateMachine::InternetReadyState::GoInState()
{
    WIFI_LOGI("Enter InternetReadyState GoInState function.");
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    bool isMobileAp = linkedInfo.isDataRestricted;
    if (!linkedInfo.bssid.empty() && !isMobileAp) {
        /* to do get cellId info and add cur ap info to apinfoManager*/
        std::string cellId = ApInfoHelper::GetInstance().GetCurrentCellIdInfo();
        ApInfoHelper::GetInstance().AddApInfo(cellId, linkedInfo.networkId);
    } else if (isMobileAp) {
        WIFI_LOGI("mobileAp, no need to add current ap.");
    }
}

void WifiIntelligenceStateMachine::InternetReadyState::GoOutState()
{
    WIFI_LOGI("Enter InternetReadyState GoOutState function.");
}

bool WifiIntelligenceStateMachine::InternetReadyState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("InternetReadyState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_CELL_STATE_CHANGE:
        case EVENT_SCREEN_ON: {
            ret = EXECUTED;
            /* to do update apinfo's cell id*/
            WifiLinkedInfo linkedInfo;
            WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
            bool isMobileAp = linkedInfo.isDataRestricted;
            if (!isMobileAp) {    
                std::string cellId = ApInfoHelper::GetInstance().GetCurrentCellIdInfo();
                if (!cellId.empty()) {
                    ApInfoHelper::GetInstance().AddApInfo(cellId, linkedInfo.networkId);
                }
            }
            break;
        }
        case EVENT_CHECK_WIFI_INTERNET_RESULT: {
            int32_t state = msg->GetParam1();
            if (state == static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED)) {
                ret = EXECUTED;
            }
            break;
        }
        default:
            WIFI_LOGI("InternetReadyState-msgCode=%{public}d not handle.", msg->GetMessageName());
            break;
    }
    return ret;
}

/* --------------------------- state machine noInternet state ------------------------------ */
WifiIntelligenceStateMachine::NoInternetState::NoInternetState(
    WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine)
    : State("NoInternetState")
{
    WIFI_LOGD("NoInternetState construct success.");
}

WifiIntelligenceStateMachine::NoInternetState::~NoInternetState() {}

void WifiIntelligenceStateMachine::NoInternetState::GoInState()
{
    WIFI_LOGI("Enter NoInternetState GoInState function.");
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (!linkedInfo.bssid.empty()) {
        ApInfoHelper::GetInstance().DelApInfos(linkedInfo.bssid);
    }
}

void WifiIntelligenceStateMachine::NoInternetState::GoOutState()
{
    WIFI_LOGI("Enter NoInternetState GoOutState function.");
}

bool WifiIntelligenceStateMachine::NoInternetState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGD("NoInternetState-msgCode=%{public}d is received.", msg->GetMessageName());
    return ret;
}

bool WifiIntelligenceStateMachine::FullScan()
{
    WIFI_LOGD("start Fullscan");
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(instId_);
    if (pScanService == nullptr) {
        WIFI_LOGI("TryStartScan, pService is nullptr.");
        return WIFI_OPT_FAILED;
    }
    return pScanService->Scan(false);
}

bool WifiIntelligenceStateMachine::HandleScanResult(std::vector<WifiScanInfo> scanInfoList)
{
    if (scanInfoList.size() == 0) {
        return false;
    }
    bool hasApInBlacklist = false;
    bool hasTargetAp = false;
    std::string cellId = ApInfoHelper::GetInstance().GetCurrentCellIdInfo();

    for (auto &scanInfo : scanInfoList) {
        ApInfoData data;
        int index = ApInfoHelper::GetInstance().GetApInfoByBssid(scanInfo.bssid, data);
        if (index == -1) {
            continue;
        }
        bool isInTargetApVec = IsInTargetAp(scanInfo.bssid, scanInfo.ssid);
        bool isTargetAp = isInTargetApVec || (data.ssid == scanInfo.ssid);
        if (!isTargetAp) {
            continue;
        }
        if (data.inBlacklist) {
            hasApInBlacklist = true;
            break;
        }
        if (!isInTargetApVec && !data.bssid.empty() && !cellId.empty()) {
            InlineUpdateCellInfo(data, cellId);
             mTargetApInfoDatas_.push_back(data);
        }
        if (scanInfo.rssi >= AUTO_OPEN_RSSI_VALUE) {
            hasTargetAp = true;
            WIFI_LOGI("HandleScanResult, hasTargetAp=true, ssid=%{public}s, bssid=%{public}s",
                SsidAnonymize(scanInfo.ssid).c_str(), MacAnonymize(scanInfo.bssid).c_str());
        } else {
            WIFI_LOGI("HandleScanResult, AP RSSI is weak, ssid=%{public}s, bssid=%{public}s",
                SsidAnonymize(scanInfo.ssid).c_str(), MacAnonymize(scanInfo.bssid).c_str());
        }
    }

    if (hasApInBlacklist) {
        WIFI_LOGI("Has tartget in blacklist, update record.");
        ApInfoHelper::GetInstance().ResetBlacklist(scanInfoList, 1);
        return true;
    } else {
        if (hasTargetAp) {
            SendMessage(EVENT_WIFI_FIND_TARGET);
            return true;
        }
    }
    return false;
}

bool WifiIntelligenceStateMachine::IsInTargetAp(std::string bssid, std::string ssid)
{
    if (mTargetApInfoDatas_.size() == 0) {
        return false;
    }
    for (auto targetApInfo : mTargetApInfoDatas_) {
        if (targetApInfo.bssid == bssid && targetApInfo.ssid == ssid) {
            WIFI_LOGI("IsInTargetAp, yes!");
            return true;
        }
    }
    return false;
}

void WifiIntelligenceStateMachine::InlineUpdateCellInfo(ApInfoData data, std::string cellId)
{
    if (!ApInfoHelper::GetInstance().IsCellIdExit(cellId)) {
        ApInfoHelper::GetInstance().AddCellInfo(data.bssid, cellId);
        std::vector<CellInfoData> cellInfos;
        ApInfoHelper::GetInstance().QueryCellIdInfoByParam({{CellIdInfoTable::BSSID, data.bssid}}, cellInfos);
        if (cellInfos.size() != 0) {
            data.cellInfos = cellInfos;
        }
    } else {
        WIFI_LOGI("inlineUpdataApCellInfo info is already there");
    }
}

bool WifiIntelligenceStateMachine::IsInMonitorNearbyAp(const std::vector<WifiScanInfo>& scanInfoList)
{
    if (mTargetApInfoDatas_.size() == 0) {
        return false;
    }
    for (const auto &scanResult : scanInfoList) {
        for (const auto &apInfo : mTargetApInfoDatas_) {
            for (const auto &nearbyAp : apInfo.nearbyApInfos) {
                if (nearbyAp == scanResult.bssid) {
                    return true;
                }
            }
        }
    }
    return false;
}

void WifiIntelligenceStateMachine::StopScanAp()
{
    mScanTimes_ = 0;
    mScanType_ = SCAN_TYPE_ONE;
    StopTimer(EVENT_SCAN_AGAIN);
}
}
}