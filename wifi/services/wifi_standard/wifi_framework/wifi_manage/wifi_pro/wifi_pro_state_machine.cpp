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
#include "wifi_pro_chr.h"
#include "wifi_channel_helper.h"
#include "ienhance_service.h"
#include "wifi_enhance_defs.h"

namespace OHOS {
namespace Wifi {
namespace {
const std::string WIFI_PRO_STATE_MACHINE = "WifiProStateMachine";
const uint32_t LANDSCAPE_LIMIT_SWITHCH_LIST_MAX_SIZE = 50;
constexpr int32_t DEFAULT_RSSI = -200;
constexpr int32_t DEFAULT_SCAN_INTERVAL = 10 * 1000; // ms
constexpr int64_t BLOCKLIST_VALID_TIME = 120 * 1000;  // ms
constexpr int64_t BLOCKLIST_5GVALID_TIME = 10 * 60 * 1000;  // ms
constexpr int64_t SELF_CURE_RSSI_THRESHOLD = -70;
constexpr int64_t DEFAULT_NET_DISABLE_DETECT_COUNT = 2;
constexpr int64_t MIN_TCP_TX = 2;
constexpr int64_t MIN_DNS_FAILED_CNT = 2;
constexpr int32_t WIFI_PRO_DETECT_TIMEOUT = 16 * 1000;  // ms
constexpr int64_t MAX_INTERVAL_TIME = 120 * 1000 * 1000;
constexpr int64_t SCREEN_ON_DURATIONSECS = 30 * 1000 * 1000;
constexpr int64_t DEFAULT_SCAN_INTERVAL_TIME = 20 * 1000 * 1000;
constexpr int64_t POOR5G_SWITCH_2GTHRESHOLD = -76;
constexpr int32_t DEFAULT_SELFCURE_INTERVAL = 10 * 1000; // ms
// show reason
std::map<WifiSwitchReason, std::string> g_switchReason = {
    {WIFI_SWITCH_REASON_NO_INTERNET, "NO_INTERNET"},
    {WIFI_SWITCH_REASON_POOR_RSSI, "POOR_RSSI"},
    {WIFI_SWITCH_REASON_STRONG_RSSI_INTERNET_SLOW, "STRONG_RSSI_INTERNET_SLOW"},
    {WIFI_SWITCH_REASON_POOR_RSSI_INTERNET_SLOW, "POOR_RSSI_INTERNET_SLOW"},
    {WIFI_SWITCH_REASON_BACKGROUND_CHECK_AVAILABLE_WIFI, "BACKGROUND_CHECK_AVAILABLE_WIFI"},
    {WIFI_SWITCH_REASON_APP_QOE_SLOW, "APP_QOE_SLOW"},
    {WIFI_SWITCH_REASON_HIGHER_CATEGORY, "HIGHER_CATEGORY"}
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
    if (currentState_ == WifiProState::WIFI_NONET && WifiProUtils::IsUserSelectNetwork() && !isFirstDectectHasNet_) {
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_NONET_BEFORE_CONNECT);
        WIFI_LOGI("IsKeepCurrWifiConnected, user select and nonet.");
        return true;
    }

    if (WifiProUtils::IsAppInWhiteLists()) {
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_APP_WHITE_LISTS);
        WIFI_LOGI("IsKeepCurrWifiConnected, in app white lists.");
        return true;
    }

    // AP+STA scene, do not switch
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(instId_);
    if (curState == WifiOprMidState::RUNNING) {
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_AP_STA_ON);
        WIFI_LOGI("IsKeepCurrWifiConnected, ap is running, do not switch");
        return true;
    }

    // signal bridge
    auto rptManager = WifiManager::GetInstance().GetRptInterface(instId_);
    if (rptManager != nullptr && rptManager->IsRptRunning()) {
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_SIGNAL_BRIDGE_ON);
        WIFI_LOGI("IsKeepCurrWifiConnected, rpt is running, do not switch");
        return true;
    }

    if (WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_CLOSE) {
        WIFI_LOGI("IsKeepCurrWifiConnected: screen state off.");
        return true;
    }

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
    if (CheckDeviceTypeByVendorCountry()) {
        WIFI_LOGI("IsKeepCurrWifiConnected, IsItVersion, do not switch");
        return true;
    }
#endif

    return false;
}

bool WifiProStateMachine::IsKeepCurrWifiConnectedExtral()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        WIFI_LOGE("IsKeepCurrWifiConnectedExtral : disconnected.");
        return true;
    }

    if (wifiSwitchReason_ == WIFI_SWITCH_REASON_POOR_RSSI && linkedInfo.band == static_cast<int>(BandType::BAND_5GHZ) &&
        networkSelectionResult_.interScanInfo.band == static_cast<int>(BandType::BAND_2GHZ)) {
        if (linkedInfo.rssi >= POOR5G_SWITCH_2GTHRESHOLD) {
            WIFI_LOGI("IsKeepCurrWifiConnectedExtral : cur5g rssi %{public}d, tar2.4g.", linkedInfo.rssi);
            return true;
        }
    }

    WifiLinkedInfo linkedInfoWlan1;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfoWlan1, 1);
    if (linkedInfoWlan1.networkId != INVALID_NETWORK_ID &&
        networkSelectionResult_.interScanInfo.bssid == linkedInfoWlan1.bssid) {
        WIFI_LOGI("IsKeepCurrWifiConnectedExtral : TarAp is wlan1.");
        return true;
    }
    return false;
}

bool WifiProStateMachine::HasWifiSwitchRecord()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        WIFI_LOGI("HasWifiSwitchRecord : cur disconnected.");
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
    currentBand_ = linkedInfo.band;
    currentWifiCategory_ = linkedInfo.supportedWifiCategory;
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
        WIFI_LOGD("IsReachWifiScanThreshold, ap is not strong enough, and has switch record.");
        return true;
    }

    if (HasAvailableSsidToSwitch()) {
        WIFI_LOGD("IsReachWifiScanThreshold, ap is not strong enough, and has available ap.");
        return true;
    }

    WIFI_LOGD("IsReachWifiScanThreshold, ap is not strong enough, no need to switch.");
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
    if (isCallingInCs) {
        WIFI_LOGW("isCallingInCs : %{public}d", isCallingInCs);
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_ISCALLING);
        return false;
    }
 
    if (isDisableWifiAutoSwitch_) {
        WIFI_LOGW("DisableWifiAutoSwitch!");
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_NOT_ALLOW_AUTOSWITCH);
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

void WifiProStateMachine::HandleWifi2WifiSucsess()
{
    WIFI_LOGI("Enter HandleWifi2WifiSucsess");
    auto &networkBlackListManager = NetworkBlockListManager::GetInstance();
    if (!badBssid_.empty()) {
        networkBlackListManager.AddWifiBlocklist(badBssid_);
        MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST, badBssid_, BLOCKLIST_VALID_TIME);
        networkBlackListManager.CleanTempWifiBlockList();
    }
    Handle5GWifiTo2GWifi();
    HandleHigherCategoryToLowerCategory();
}

void WifiProStateMachine::Handle5GWifiTo2GWifi()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.band == static_cast<int>(BandType::BAND_2GHZ) &&
        currentBand_ == static_cast<int>(BandType::BAND_5GHZ)) {
        NetworkBlockListManager::GetInstance().AddPerf5gBlocklist(badBssid_);
        if (NetworkBlockListManager::GetInstance().IsOverTwiceInPerf5gBlocklist(badBssid_)) {
            MessageExecutedLater(EVENT_REMOVE_5GBLOCK_LIST, badBssid_, BLOCKLIST_5GVALID_TIME);
        } else {
            MessageExecutedLater(EVENT_REMOVE_5GBLOCK_LIST, badBssid_, BLOCKLIST_VALID_TIME);
        }
    }
}

void WifiProStateMachine::HandleHigherCategoryToLowerCategory()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.supportedWifiCategory < currentWifiCategory_) {
        NetworkBlockListManager::GetInstance().AddPerf5gBlocklist(badBssid_);
        if (NetworkBlockListManager::GetInstance().IsOverTwiceInPerf5gBlocklist(badBssid_)) {
            MessageExecutedLater(EVENT_REMOVE_5GBLOCK_LIST, badBssid_, BLOCKLIST_5GVALID_TIME);
            WIFI_LOGI("HandleHigherCategoryToLowerCategory: Added previous bssid %{public}s to Perf5gBlocklist(10).",
                MacAnonymize(badBssid_).c_str());
        } else {
            MessageExecutedLater(EVENT_REMOVE_5GBLOCK_LIST, badBssid_, BLOCKLIST_VALID_TIME);
            WIFI_LOGI("HandleHigherCategoryToLowerCategory: Added previous bssid %{public}s to Perf5gBlocklist(2).",
                MacAnonymize(badBssid_).c_str());
        }
    }
}

void WifiProStateMachine::HandleWifi2WifiFailed()
{
    WIFI_LOGI("wifitowifi step X: wifi to Wifi Failed Finally.");
    NetworkBlockListManager::GetInstance().AddWifiBlocklist(targetBssid_);
    MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST, targetBssid_, BLOCKLIST_VALID_TIME);
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

    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(instId_);
    if (pScanService == nullptr ||
        pScanService->ScanWithParam(params, true, ScanType::SCAN_TYPE_WIFIPRO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGI("FastScan error, do full channel scan.");
        SendMessage(EVENT_REQUEST_SCAN_DELAY);
        return;
    }
    WifiProChr::GetInstance().RecordScanChrCnt(CHR_EVENT_WIFIPRO_FAST_SCAN_CNT);
}

bool WifiProStateMachine::TrySelfCure(bool forceNoHttpCheck)
{
    if (isWifi2WifiSwitching_) {
        WIFI_LOGI("Wifi2Wifi Switching");
        return false;
    }
    WIFI_LOGI("TrySelfCure.");

    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId_);
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(instId_);
    do {
        if (pSelfCureService == nullptr) {
            WIFI_LOGE("pSelfCureService nullptr.");
            break;
        }

        if (pStaService == nullptr) {
            WIFI_LOGE("pStaService is invalid");
            return false;
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
        OperateResState lastCheckNetState = OperateResState::CONNECT_NETWORK_NORELATED;
        pStaService->GetDetectNetState(lastCheckNetState);
        // issatisfy min rssi
        if (linkedInfo.rssi > SELF_CURE_RSSI_THRESHOLD &&
            lastCheckNetState == OperateResState::CONNECT_NETWORK_DISABLED) {
            pSelfCureService->NotifyInternetFailureDetected(forceNoHttpCheck);
        } else {
            WIFI_LOGI("Failure to meet the conditions for selfcure.");
        }
    } while (0);
    return true;
}

bool WifiProStateMachine::SelectNetwork(NetworkSelectionResult &networkSelectionResult,
    const std::vector<InterScanInfo> &scanInfos)
{
    NetworkSelectType mNetworkSelectType;
    if (wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI_QOE_BAD;
    } else if (wifiSwitchReason_ == WIFI_SWITCH_REASON_NO_INTERNET) {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI_NONET;
    } else if (wifiSwitchReason_ == WIFI_SWITCH_REASON_PORTAL) {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI_PORTAL;
    } else {
        mNetworkSelectType = NetworkSelectType::WIFI2WIFI;
    }
    BlockConnectService::GetInstance().UpdateAllNetworkSelectStatus();
    std::unique_ptr<NetworkSelectionManager> pNetworkSelectionManager = std::make_unique<NetworkSelectionManager>();
    std::string failReason;
    if (pNetworkSelectionManager->SelectNetwork(networkSelectionResult, mNetworkSelectType, scanInfos, failReason)) {
        WIFI_HILOG_COMM_INFO("Wifi2Wifi select network result, ssid: %{public}s, bssid: %{public}s.",
            SsidAnonymize(networkSelectionResult.interScanInfo.ssid).c_str(),
            MacAnonymize(networkSelectionResult.interScanInfo.bssid).c_str());
        WifiProChr::GetInstance().RecordSelectNetChrCnt(true);
        return true;
    }
    WifiProChr::GetInstance().RecordSelectNetChrCnt(false);
    WIFI_LOGW("Wifi2Wifi select network failed");
    return false;
}

bool WifiProStateMachine::IsSatisfiedWifi2WifiCondition()
{
    if (isWifi2WifiSwitching_) {
        WIFI_LOGI("IsSatisfiedWifi2WifiCondition, wifi2Wifi is switching.");
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_SWITCHING);
        return false;
    }
 
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_SELFCURING);
        WIFI_LOGI("IsSatisfiedWifi2WifiCondition, self cure ongoing.");
        return false;
    }

    if (IsKeepCurrWifiConnected() || IsKeepCurrWifiConnectedExtral()) {
        return false;
    }

    if (!IsDisableWifiAutoSwitch()) {
        return false;
    }

    return true;
}

bool WifiProStateMachine::TryWifi2Wifi(const NetworkSelectionResult &networkSelectionResult)
{
    if (wifiSwitchReason_ == WIFI_SWITCH_REASON_POOR_RSSI || wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        StopTimer(EVENT_REQUEST_SCAN_DELAY);
    }
    UpdateWifiSwitchTimeStamp();

    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(instId_);
    if (pStaService == nullptr) {
        WIFI_LOGE("TryWifi2Wifi: pStaService is invalid");
        return false;
    }

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        WIFI_LOGE("TryWifi2Wifi: current state : disconnected.");
        return false;
    }

    int32_t networkId = networkSelectionResult.wifiDeviceConfig.networkId;
    badBssid_ = currentBssid_;
    badSsid_ = currentSsid_;
    targetBssid_ = networkSelectionResult.interScanInfo.bssid;
    isWifi2WifiSwitching_ = true;
    WifiProChr::GetInstance().RecordWifiProConnectTime();
    WifiProChr::GetInstance().RecordGatewayInfoBeforeSwitch();
    WIFI_HILOG_COMM_ERROR("TryWifi2Wifi: Switch reason : %{public}s", (g_switchReason[wifiSwitchReason_]).c_str());
    if (pStaService->StartConnectToBssid(networkId, targetBssid_, NETWORK_SELECTED_BY_WIFIPRO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("TryWifi2Wifi: ConnectToNetwork failed.");
        return false;
    }
    /* Record Chr: WiFi switches triggered by scans of a specific scanStyle */
    RecordChrApSwitchCountInfo();
    return true;
}

void WifiProStateMachine::RecordChrApSwitchCountInfo()
{
    ScanStatisticInfo scanStatisticInfo;
    int scanStyle = WifiConfigCenter::GetInstance().GetScanStyle();
    if (scanStyle == SCAN_TYPE_LOW_PRIORITY) {
        scanStatisticInfo.lpScanApSwtCnt++;
    } else if (scanStyle == SCAN_DEFAULT_TYPE) {
        scanStatisticInfo.scanApSwtCnt++;
    }
    WriteWifiScanInfoHiSysEvent(scanStatisticInfo);
}

ErrCode WifiProStateMachine::FullScan()
{
    WIFI_LOGD("start Fullscan");
    int32_t signalLevel = WifiProUtils::GetSignalLevel(instId_);
#ifndef OHOS_ARCH_LITE
    if (currentState_ == WifiProState::WIFI_HASNET && WifiConfigCenter::GetInstance().IsScreenLandscape() &&
        signalLevel >= SIG_LEVEL_2 && InLandscapeSwitchLimitList()) {
        WIFI_LOGI("FullScan ScreenLandscape and InLandscapeSwitchLimitList.");
        return WIFI_OPT_SUCCESS;
    }
#endif
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(instId_);
    if (pScanService == nullptr) {
        WIFI_LOGI("TryStartScan, pService is nullptr.");
        return WIFI_OPT_FAILED;
    }
    WifiProChr::GetInstance().RecordScanChrCnt(CHR_EVENT_WIFIPRO_FULL_SCAN_CNT);
    return pScanService->Scan(true, ScanType::SCAN_TYPE_WIFIPRO);
}

bool WifiProStateMachine::GenelinkSelectNetwork(const std::vector<InterScanInfo> &scanInfos)
{
    bool ret = false;
#ifndef OHOS_ARCH_LITE
    IEnhanceService  *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        return ret;
    }

    int type = pEnhanceService->GenelinkInterface(MultiLinkDefs::QUERY_SELECT_NETWORK_TYPE, 0);
    if (type != MultiLinkDefs::SELECT_NETWORK_MASTER && type != MultiLinkDefs::SELECT_NETWORK_SLAVE) {
        return ret;
    }

    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(INSTID_WLAN0);
    if (pStaService == nullptr && type == MultiLinkDefs::SELECT_NETWORK_MASTER) {
        return ret;
    }
    // notify genelink that selection start
    pEnhanceService->GenelinkInterface(MultiLinkDefs::NOTIFY_SELECT_NETWORK, MultiLinkDefs::SELECT_NETWORK_START);

    NetworkSelectionResult selectionResult;
    NetworkSelectType networkSelectType = NetworkSelectType::AUTO_CONNECT;
    std::unique_ptr<NetworkSelectionManager> pNetworkSelection = std::make_unique<NetworkSelectionManager>();
    std::string failReason;
    ret = pNetworkSelection->SelectNetwork(selectionResult, networkSelectType, scanInfos, failReason);
    // notify genelink that selection is done regardless of result
    pEnhanceService->GenelinkInterface(MultiLinkDefs::NOTIFY_SELECT_NETWORK, MultiLinkDefs::SELECT_NETWORK_STOP);
    if (!ret) {
        WIFI_LOGI("%{public}s failed: reason:%{public}s", __func__, failReason.c_str());
        return ret;
    }

    std::string &targetBssid = selectionResult.interScanInfo.bssid;
    selectionResult.wifiDeviceConfig.bssid = selectionResult.interScanInfo.bssid;
    WIFI_LOGI("%{public}s select network result, ssid: %{public}s, bssid: %{public}s", __func__,
        SsidAnonymize(selectionResult.interScanInfo.ssid).c_str(), MacAnonymize(targetBssid).c_str());
    selectionResult.wifiDeviceConfig.rssi = selectionResult.interScanInfo.rssi;

    ErrCode code = pEnhanceService->NotifyGenelinkSelectedConfig(selectionResult.wifiDeviceConfig);
    if (type == MultiLinkDefs::SELECT_NETWORK_MASTER && code == WIFI_OPT_SUCCESS) {
        code = pStaService->StartConnectToBssid(selectionResult.wifiDeviceConfig.networkId, targetBssid,
            NETWORK_SELECTED_BY_GENELINK);
        WIFI_LOGE("genelink: ConnectToNetwork %{public}s.", code == WIFI_OPT_SUCCESS ? "true" : "false");
    }
    ret = (code == WIFI_OPT_SUCCESS);
#endif
    return ret;
}

void WifiProStateMachine::ProcessSwitchResult(const InternalMessagePtr msg)
{
    WifiLinkedInfo linkedInfo;
    msg->GetMessageObj(linkedInfo);
    perf5gHandoverService_.OnConnected(linkedInfo);
    if (isWifi2WifiSwitching_ && targetBssid_ != linkedInfo.bssid) {
        WIFI_LOGI("selected bssid and switched bssid are not same:selected bssid:%{public}s,"
                  "switched bssid:%{public}s,",
            MacAnonymize(targetBssid_).c_str(),
            MacAnonymize(linkedInfo.bssid).c_str());
        WifiProChr::GetInstance().RecordSwitchChrCnt(false);
        HandleWifi2WifiFailed();
    } else if (isWifi2WifiSwitching_ && targetBssid_ == linkedInfo.bssid) {
        WifiProChr::GetInstance().RecordSwitchChrCnt(true);
        WifiProChr::GetInstance().RecordWifiProSwitchSuccTime();
        HandleWifi2WifiSucsess();
        WifiProChr::GetInstance().RecordGatewayInfoAfterSwitch();
    } else if (!disconnectToConnectedState_ && currentBssid_ != linkedInfo.bssid) {
        NetworkBlockListManager::GetInstance().AddWifiBlocklist(currentBssid_);
        MessageExecutedLater(EVENT_REMOVE_BLOCK_LIST, currentBssid_, BLOCKLIST_VALID_TIME);
    }
    Wifi2WifiFinish();
}

bool WifiProStateMachine::InLandscapeSwitchLimitList()
{
#ifndef OHOS_ARCH_LITE
    std::vector<PackageInfo> specialList;
    if (WifiSettings::GetInstance().GetPackageInfoByName("LandscapeSwitchLimitList", specialList) != 0) {
        WIFI_LOGE("ProcessSwitchInfoRequest GetPackageInfoByName failed");
        return false;
    }
 
    for (size_t i = 0; i < specialList.size() && i < LANDSCAPE_LIMIT_SWITHCH_LIST_MAX_SIZE; ++i) {
        if (WifiAppStateAware::GetInstance().IsForegroundApp(specialList[i].name)) {
            return true;
        }
    }
#endif
    return false;
}

bool WifiProStateMachine::IsAllowScan(bool hasSwitchRecord)
{
    if (WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_CLOSE) {
        WIFI_LOGI("IsAllowScan: screen state off.");
        return false;
    }
 
    // selfcure onging, pending scan for 10s
    ISelfCureService *pSelfCureService =
        WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("IsAllowScan: self cure is ongoing.");
        StopTimer(EVENT_REQUEST_SCAN_DELAY);
        MessageExecutedLater(EVENT_REQUEST_SCAN_DELAY, hasSwitchRecord, DEFAULT_SCAN_INTERVAL);
        return false;
    }
    return true;
}

bool WifiProStateMachine::IsFirstConnectAndNonet()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        WIFI_LOGE("IsFirstConnectAndNonet: current state : disconnected.");
        return true;
    }
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config) != 0) {
        WIFI_LOGE("IsFirstConnectAndNonet: Failed to get device config.");
        return true;
    }
    return currentState_ == WifiProState::WIFI_NONET && WifiProUtils::IsUserSelectNetwork() &&
           config.numAssociation <= 1 && !isFirstDectectHasNet_;
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
        case EVENT_REMOVE_5GBLOCK_LIST:
            HandleRemove5GBlockList(msg);
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

void WifiProStateMachine::DefaultState::HandleRemove5GBlockList(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("HandleRemove5GBlockList: msg is nullptr.");
        return;
    }
 
    std::string bssid;
    msg->GetMessageObj(bssid);
    NetworkBlockListManager::GetInstance().RemovePerf5gBlocklist(bssid);
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
        pWifiProStateMachine_->perf5gHandoverService_.OnDisconnectedExternal();
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
    pWifiProStateMachine_->isFirstDectectHasNet_ = false;
}

void WifiProStateMachine::WifiConnectedState::HandleHttpResult(const InternalMessagePtr msg)
{
    WIFI_LOGD("Enter HandleHttpResult.");
    if (msg == nullptr) {
        WIFI_LOGI("HttpResultInConnected, msg is nullptr.");
        return;
    }
    pWifiProStateMachine_->StopTimer(EVENT_DETECT_TIMEOUT);
    pWifiProStateMachine_->mHttpDetectedAllowed_ = true;
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
        pWifiProStateMachine_->perf5gHandoverService_.OnDisconnectedExternal();
    } else {
        pWifiProStateMachine_->disconnectToConnectedState_ = false;
        if (state == static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED)) {
            pWifiProStateMachine_->ProcessSwitchResult(msg);
            pWifiProStateMachine_->RefreshConnectedNetWork();
        }
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
    } else {
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_WIFI2WIFI_SWITCH,
                WifiDisconnectReason::DISCONNECT_BY_NO_REASON);
        }
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
        WIFI_LOGI("state transition: WifiDisconnectedState -> WifiConnectedState.");
        pWifiProStateMachine_->disconnectToConnectedState_ = true;
        pWifiProStateMachine_->ProcessSwitchResult(msg);
        pWifiProStateMachine_->SwitchState(pWifiProStateMachine_->pWifiConnectedState_);
    }
}

void WifiProStateMachine::WifiDisconnectedState::HandleWifi2WifiFailedEvent(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("DisconnectedState, msg is nullptr.");
        return;
    }
    if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
        int32_t state = msg->GetParam1();
        WIFI_LOGW("HandleWifi2Wifi error : %{public}d", state);
        WifiProChr::GetInstance().RecordSwitchChrCnt(false);
        pWifiProStateMachine_->HandleWifi2WifiFailed();
        pWifiProStateMachine_->Wifi2WifiFinish();
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
    rssiLevel4ScanedCounter_ = 0;
    mLastTcpTxCounter_ = 0;
    mLastTcpRxCounter_ = 0;
    mLastDnsFailedCnt_ = 0;
    netDisableDetectCount_ = 0;
    pWifiProStateMachine_->isWifi2WifiSwitching_ = false;
    qoeScaning_ = false;
    isLpScanTriggered_ = false;
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_HASNET;
    // Remove the network monitoring function of wifipro itself
    pWifiProStateMachine_->perf5gHandoverService_.NetworkStatusChanged(NetworkStatus::HAS_INTERNET);
}

void WifiProStateMachine::WifiHasNetState::GoOutState()
{
    WIFI_LOGI("WifiHasNetState GoOutState function.");
    pWifiProStateMachine_->StopTimer(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL);
    pWifiProStateMachine_->isFirstDectectHasNet_ = true;
    isLpScanTriggered_ = false;
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
            RequestHttpDetect(false);
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
        case EVENT_DETECT_TIMEOUT:
            RequestHttpDetect(true);
            break;
        case EVENT_EMLSR_STATE_CHANGED:
            HandleWifiEmlsrStateChanged(msg);
            break;
        default:
            return false;
    }
    return true;
}

void WifiProStateMachine::WifiHasNetState::HandleWifiEmlsrStateChanged(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleWifiEmlsrStateChanged, msg is nullptr.");
        return;
    }
    WifiLinkedInfo linkedInfo;
    msg->GetMessageObj(linkedInfo);
    pWifiProStateMachine_->perf5gHandoverService_.OnConnected(linkedInfo);
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
    if (signalLevel == SIG_LEVEL_4) {
        rssiLevel2Or3ScanedCounter_ = 0;
        rssiLevel0Or1ScanedCounter_ = 0;
    }

    if (!pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel) &&
        pWifiProStateMachine_->wifiSwitchReason_ != WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        WIFI_LOGD("HandleRssiChangedInHasNet, StopTimer EVENT_REQUEST_SCAN_DELAY.");
        pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
        return;
    } else if (!pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel) &&
               pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        WIFI_LOGD("HandleRssiChangedInHasNet, qoe slow.");
        return;
    }

    pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_POOR_RSSI);
    qoeScaning_ = false;
    WifiProChr::GetInstance().RecordWifiProStartTime(WIFI_SWITCH_REASON_POOR_RSSI);
    pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
    pWifiProStateMachine_->SendMessage(
        EVENT_REQUEST_SCAN_DELAY, static_cast<int32_t>(pWifiProStateMachine_->HasWifiSwitchRecord()));
}

void WifiProStateMachine::WifiHasNetState::HandleReuqestScanInHasNet(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleReuqestScanInHasNet, msg is nullptr.");
        return;
    }

    bool hasSwitchRecord = static_cast<bool>(msg->GetParam1());
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    // when not allow scan, clean flag qoeScaning_
    if ((!pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel) ||
        pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) &&
        !pWifiProStateMachine_->IsAllowScan(hasSwitchRecord)) {
        qoeScaning_ = false;
        return;
    }
    TryStartScan(hasSwitchRecord, signalLevel);
}

void WifiProStateMachine::WifiHasNetState::TryStartScan(bool hasSwitchRecord, int32_t signalLevel)
{
    if (pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        qoeScaning_ = true;
    }
    ErrCode ret = WIFI_OPT_FAILED;
    // calculate the interval and the max scan counter.
    int32_t scanInterval = WifiProUtils::GetScanInterval(hasSwitchRecord, signalLevel);
    int32_t scanMaxCounter = WifiProUtils::GetMaxCounter(hasSwitchRecord, signalLevel);
    if (signalLevel == SIG_LEVEL_4 && rssiLevel4ScanedCounter_ < scanMaxCounter &&
        pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
                  "rssiLevel4ScanedCounter_:%{public}d.", signalLevel, rssiLevel4ScanedCounter_);
        StartScanWithDynamicStrategy(rssiLevel4ScanedCounter_, hasSwitchRecord, scanInterval);
    } else if ((signalLevel == SIG_LEVEL_2 || signalLevel == SIG_LEVEL_3) &&
               rssiLevel2Or3ScanedCounter_ < scanMaxCounter) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
            "rssiLevel2Or3ScanedCounter:%{public}d.", signalLevel, rssiLevel2Or3ScanedCounter_);
        StartScanWithDynamicStrategy(rssiLevel2Or3ScanedCounter_, hasSwitchRecord, scanInterval);
    } else if ((signalLevel < SIG_LEVEL_2) && (rssiLevel0Or1ScanedCounter_ < scanMaxCounter)) {
        WIFI_LOGI("TryStartScan, start scan, signalLevel:%{public}d,"
            "rssiLevel0Or1ScanedCounter:%{public}d.", signalLevel, rssiLevel0Or1ScanedCounter_);
        StartScanWithDynamicStrategy(rssiLevel0Or1ScanedCounter_, hasSwitchRecord, scanInterval);
    } else {
        WIFI_LOGI("TryStartScan, do not scan, signalLevel:%{public}d,scanMaxCounter:%{public}d.",
            signalLevel, scanMaxCounter);
    }
    // qoe scan times reset
    if (pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW &&
        ((signalLevel == SIG_LEVEL_4 && rssiLevel4ScanedCounter_ >= scanMaxCounter) ||
            (signalLevel == SIG_LEVEL_3 && rssiLevel2Or3ScanedCounter_ >= scanMaxCounter)) && ret == WIFI_OPT_FAILED) {
        WIFI_LOGI("HandleReuqestScanInHasNet, reset qoe state.");
        qoeScaning_ = false;
    }
}

void WifiProStateMachine::WifiHasNetState::StartScanWithDynamicStrategy(int32_t &rssiLevelScanedCounter,
    bool hasSwitchRecord, int32_t scanInterval)
{
    auto ret = IsSatisfiedLpScanCondition() ? ExecuteDynamicScan(rssiLevelScanedCounter) :
        pWifiProStateMachine_->FullScan();
    if (ret == WIFI_OPT_SUCCESS) {
        rssiLevelScanedCounter++;
    }
    pWifiProStateMachine_->MessageExecutedLater(EVENT_REQUEST_SCAN_DELAY, hasSwitchRecord, scanInterval);
}
 
bool WifiProStateMachine::WifiHasNetState::IsSatisfiedLpScanCondition()
{
    IEnhanceService  *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr || !pEnhanceService->IsSupportLpScanAbility()) {
        WIFI_LOGE("do not satisfy Lp scan condition.");
        return false;
    }
    return pWifiProStateMachine_->perf5gHandoverService_.HasHiddenNetworkSsid() ? false : true;
}
 
ErrCode WifiProStateMachine::WifiHasNetState::ExecuteDynamicScan(int rssiLevelScanedCounter)
{
    auto ret = WIFI_OPT_FAILED;
    const int two = 2;
    if (rssiLevelScanedCounter % two == 0) {
        return pWifiProStateMachine_->FullScan();
    }
    ret = StartLpScan();
    if (ret != WIFI_OPT_SUCCESS) {
        ret = pWifiProStateMachine_->FullScan();
    }
    return ret;
}
 
ErrCode WifiProStateMachine::WifiHasNetState::StartLpScan()
{
    WIFI_LOGI("start LP scan in HasNet.\n");
    WifiScanParams params;
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    isConnected24G_ = WifiChannelHelper::GetInstance().IsValid24GHz(linkedInfo.frequency);
    isConnected5G_ = WifiChannelHelper::GetInstance().IsValid5GHz(linkedInfo.frequency);
    if (isConnected24G_) {
        WifiChannelHelper::GetInstance().GetAvailableScanFreqs(ScanBandType::SCAN_BAND_5_GHZ_WITH_DFS,
            params.freqs);
    } else if (isConnected5G_) {
        WifiChannelHelper::GetInstance().GetAvailableScanFreqs(ScanBandType::SCAN_BAND_24_GHZ,
            params.freqs);
    } else {
        WIFI_LOGE("Get scan frequence failed! Current frequence is not 2.4G or 5G.");
        return WIFI_OPT_FAILED;
    }
 
    params.scanStyle = SCAN_TYPE_LOW_PRIORITY;
    IScanService *pScanService =
        WifiServiceManager::GetInstance().GetScanServiceInst(pWifiProStateMachine_->instId_);
    if (pScanService == nullptr ||
        pScanService->ScanWithParam(params, false, ScanType::SCAN_TYPE_WIFIPRO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("start Lp scan failed!");
        return WIFI_OPT_FAILED;
    }
    isLpScanTriggered_ = true;
    return WIFI_OPT_SUCCESS;
}
 
ErrCode WifiProStateMachine::WifiHasNetState::ScanByPerf5gTable(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("start scanByPerf5gTable.");
    std::vector<WifiScanInfo> results;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(results);
 
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
 
    isConnected24G_ = WifiChannelHelper::GetInstance().IsValid24GHz(linkedInfo.frequency);
    isConnected5G_ = WifiChannelHelper::GetInstance().IsValid5GHz(linkedInfo.frequency);
 
    std::set<RelationAp> allRelationAps;
    const auto getRelationBssid = [this](RelationInfo& relationInfo) -> std::string& {
        return this->isConnected24G_ ? relationInfo.bssid24g_ : relationInfo.relationBssid5g_;
    };
 
    int apNum = apMaxNum_;
    for (auto &scanInfo : results) {
        if (apNum-- == 0) {
            break;
        }
        WifiDeviceConfig config;
        std::string mgmt;
        scanInfo.GetDeviceMgmt(mgmt);
        if (WifiSettings::GetInstance().GetDeviceConfig(scanInfo.ssid, mgmt, config,
            pWifiProStateMachine_->instId_) < 0) {
            continue;
        }
        if ((isConnected24G_ && WifiChannelHelper::GetInstance().IsValid5GHz(scanInfo.frequency)) ||
            (isConnected5G_ && WifiChannelHelper::GetInstance().IsValid24GHz(scanInfo.frequency))) {
            std::vector<RelationAp> relationAps;
            pWifiProStateMachine_->perf5gHandoverService_.pDualBandRepostitory_->LoadRelationApInfo(
                scanInfo.bssid, relationAps, getRelationBssid);
            allRelationAps.insert(relationAps.begin(), relationAps.end());
        }
    }
 
    if (allRelationAps.empty()) {
        WIFI_LOGE("relation Ap is empty! start select Net!");
        HandleScanResultInHasNetInner(scanInfos);
        return WIFI_OPT_SUCCESS;
    }
 
    WifiScanParams params;
    for (auto iter = allRelationAps.begin(); iter != allRelationAps.end(); iter++) {
        params.freqs.push_back(iter->apInfo_.frequency);
    }
 
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(pWifiProStateMachine_->instId_);
    if (pScanService == nullptr ||
        pScanService->ScanWithParam(params, false, ScanType::SCAN_TYPE_WIFIPRO) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ScanByPerf5gTable failed!");
        HandleScanResultInHasNetInner(scanInfos);
    }
    return WIFI_OPT_SUCCESS;
}

void WifiProStateMachine::WifiHasNetState::HandleScanResultInHasNet(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleScanResultInHasNet, msg is nullptr.");
        return;
    }

    std::vector<InterScanInfo> scanInfos;
    msg->GetMessageObj(scanInfos);
    if (pWifiProStateMachine_->GenelinkSelectNetwork(scanInfos)) {
        return;
    }
    WifiProChr::GetInstance().RecordCountWiFiPro(true);
    if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
        WIFI_LOGI("HandleScanResultInHasNet, Wifi2WifiSwitching.");
        return;
    }

    // Make sure the wifipro lag switch is done only once
    if (pWifiProStateMachine_->wifiSwitchReason_ == WIFI_SWITCH_REASON_APP_QOE_SLOW && !qoeSwitch_) {
        WIFI_LOGI("HandleScanResultInHasNet, qoe has tried to switch.");
        WifiProChr::GetInstance().RecordCountWiFiPro(false);
        return;
    }
    qoeSwitch_ = false;
    if (isLpScanTriggered_) {
        isLpScanTriggered_ = false;
        ScanByPerf5gTable(scanInfos);
    } else {
        if (HandleScanResultInHasNetInner(scanInfos)) {
            return;
        }
    }
    if (Try5gHandover(scanInfos)) {
            WIFI_LOGI("HandleScanResultInHasNet: 5G handover successful.");
            return;
    }
    if (TryHigherCategoryNetworkSelection(scanInfos)) {
        WIFI_LOGI("HandleScanResultInHasNet: Higher category selection successful.");
        return;
    }
}

bool WifiProStateMachine::WifiHasNetState::HandleScanResultInHasNetInner(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("wifi to wifi step 1: select network.");
    if (!pWifiProStateMachine_->SelectNetwork(pWifiProStateMachine_->networkSelectionResult_, scanInfos)) {
        WIFI_LOGI("wifi to wifi step X: Wifi2Wifi select network fail.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        return false;
    }

    WIFI_LOGI("wifi to wifi step 2: receive good ap.");
    if (!pWifiProStateMachine_->IsSatisfiedWifi2WifiCondition()) {
        pWifiProStateMachine_->Wifi2WifiFinish();
        return false;
    }

    // when wifiSwitchReason is APP_QOE_SLOW, skip IsReachWifiScanThreshold
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (pWifiProStateMachine_->wifiSwitchReason_ != WIFI_SWITCH_REASON_APP_QOE_SLOW &&
        signalLevel > SIG_LEVEL_2) {
        pWifiProStateMachine_->Wifi2WifiFinish();
        return false;
    }
    
#ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().IsScreenLandscape() && signalLevel >= SIG_LEVEL_2 &&
        pWifiProStateMachine_->InLandscapeSwitchLimitList()) {
        WIFI_LOGI("KeepCurrWifiConnected ScreenLandscape and InLandscapeSwitchLimitList.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        return false;
    }
#endif
 
    WIFI_LOGI("wifi to wifi step 3: try wifi2wifi.");
    if (!pWifiProStateMachine_->TryWifi2Wifi(pWifiProStateMachine_->networkSelectionResult_)) {
        WIFI_LOGI("wifi to wifi step X: TryWifi2Wifi Failed.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        return false;
    }
    return true;
}

bool WifiProStateMachine::WifiHasNetState::Try5gHandover(const std::vector<InterScanInfo> &scanInfos)
{
    std::vector<InterScanInfo> mutableScanInfos = scanInfos;
    pWifiProStateMachine_->perf5gHandoverService_.ScanResultUpdated(mutableScanInfos);
    pWifiProStateMachine_->targetBssid_ = pWifiProStateMachine_->perf5gHandoverService_.Switch5g();
    if (pWifiProStateMachine_->targetBssid_ != "") {
        WIFI_LOGI("Try5gHandover, perf 5g tried to switch.");
        pWifiProStateMachine_->badBssid_ = pWifiProStateMachine_->currentBssid_;
        pWifiProStateMachine_->isWifi2WifiSwitching_ = true;
        return true;
    }
    WIFI_LOGI("Try5gHandover: 5G handover not available.");
    return false;
}

bool WifiProStateMachine::WifiHasNetState::TryHigherCategoryNetworkSelection(
    const std::vector<InterScanInfo> &scanInfos)
{
    if (WifiProUtils::IsUserSelectNetwork()) {
        WIFI_LOGI("TryHigherCategoryNetworkSelection, user select network, do not switch.");
        WifiProChr::GetInstance().RecordReasonNotSwitchChrCnt(WIFIPRO_USER_SELECT);
        return false;
    }
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (signalLevel < SIG_LEVEL_3) {
        WIFI_LOGI("TryHigherCategoryNetworkSelection: current signal level %{public}d, skip switching.", signalLevel);
        return false;
    }
    WIFI_LOGI("TryHigherCategoryNetworkSelection: Starting higher category network selection.");
    // 设置WiFi7+强场切换原因，使用统一的网络选择接口
    WifiSwitchReason previousReason = pWifiProStateMachine_->wifiSwitchReason_;
    pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_HIGHER_CATEGORY);
    // 同步 CHR 的切换开始原因，确保后续打点记录使用正确的 switch reason
    WifiProChr::GetInstance().RecordWifiProStartTime(WIFI_SWITCH_REASON_HIGHER_CATEGORY);

      // 1. 使用新的辅助函数获取所有 Higher Category 候选网络
    std::vector<InterScanInfo> higherCategoryCandidates;
    if (!pWifiProStateMachine_->GetFilteredCandidates(
        scanInfos, NetworkSelectType::HIGHER_CATEGORY,
        higherCategoryCandidates)) {
        WIFI_LOGI("TryHigherCategoryNetworkSelection: No suitable higher category network found.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        pWifiProStateMachine_->SetSwitchReason(previousReason);
        WifiProChr::GetInstance().RecordWifiProStartTime(previousReason);
        return false;
    }

    // 2. 使用 IsAutoReconnectPreferred (内部用 AUTO_CONNECT) 比较候选网络和当前网络
    NetworkSelectionResult outSelectionResult;
    if (!pWifiProStateMachine_->IsAutoReconnectPreferred(higherCategoryCandidates, scanInfos, outSelectionResult)) {
        WIFI_LOGI("TryHigherCategoryNetworkSelection: AUTO_CONNECT selection failed, skip switching.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        pWifiProStateMachine_->SetSwitchReason(previousReason);
        WifiProChr::GetInstance().RecordWifiProStartTime(previousReason);
        return false;
    }

    // IsAutoReconnectPreferred 返回 true 意味着选出了一个更优的网络, 且不是当前网络
    WIFI_LOGI("TryHigherCategoryNetworkSelection: AUTO_CONNECT selected %{public}s as winner, attempting switch.",
              SsidAnonymize(outSelectionResult.interScanInfo.ssid).c_str());
    if (!pWifiProStateMachine_->TryWifi2Wifi(outSelectionResult)) {
        WIFI_LOGI("TryHigherCategoryNetworkSelection: TryWifi2Wifi failed to start connection.");
        pWifiProStateMachine_->Wifi2WifiFinish();
        pWifiProStateMachine_->SetSwitchReason(previousReason);
        WifiProChr::GetInstance().RecordWifiProStartTime(previousReason);
        return false;
    }
    return true;
}

void WifiProStateMachine::WifiHasNetState::RequestHttpDetect(bool forceHttpDetect)
{
    const bool shouldDetect = forceHttpDetect || (pWifiProStateMachine_->mHttpDetectedAllowed_ &&
                                                     netDisableDetectCount_ < DEFAULT_NET_DISABLE_DETECT_COUNT);
    WIFI_LOGI("forceHttpDetect %{public}d, mHttpDetectedAllowed_ %{public}d, netDisableDetectCount_ %{public}d",
        forceHttpDetect, pWifiProStateMachine_->mHttpDetectedAllowed_, netDisableDetectCount_);
    if (!shouldDetect) {
        WIFI_LOGI("Has RequestHttpDetect.");
        return;
    }
    sptr<NetStateObserver> mNetWorkDetect = sptr<NetStateObserver>(new NetStateObserver());
    mNetWorkDetect->StartWifiDetection();
    pWifiProStateMachine_->mHttpDetectedAllowed_ = false;
    netDisableDetectCount_++;
    // Start the timeout timer when the probe is not forced
    if (!forceHttpDetect) {
        pWifiProStateMachine_->StartTimer(EVENT_DETECT_TIMEOUT, WIFI_PRO_DETECT_TIMEOUT);
    }
}

void WifiProStateMachine::WifiHasNetState::ParseQoeInfoAndRequestDetect()
{
    pWifiProStateMachine_->StopTimer(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL);
    InternalMessagePtr msg = pWifiProStateMachine_->CreateMessage(EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL);
    msg->msgLogLevel_ = MsgLogLevel::LOG_D;
    pWifiProStateMachine_->MessageExecutedLater(msg, INTERNET_STATUS_DETECT_INTERVAL_MS);
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
    WIFI_LOGD("deltaTcpTxPkts = %{public}" PRId64 ", deltaTcpRxPkts = %{public}" PRId64 ", deltaFailedDns = %{public}d"
              ", nedisable = %{public}d",
        deltaTcpTxPkts, deltaTcpRxPkts, deltaFailedDns, netDisableDetectCount_);
    // if Rx = 0 DNSFailedCount >=2 or  Rx = 0 Tx >=2
    if (deltaTcpRxPkts == 0 && (deltaFailedDns >= MIN_DNS_FAILED_CNT || deltaTcpTxPkts >= MIN_TCP_TX)) {
        pWifiProStateMachine_->SendMessage(EVENT_REQUEST_NETWORK_DETECT);
    } else {
        netDisableDetectCount_ = 0;
    }
}

void WifiProStateMachine::WifiHasNetState::HandleWifiQoeSlow()
{
    int32_t signalLevel = WifiProUtils::GetSignalLevel(pWifiProStateMachine_->instId_);
    if (signalLevel >= SIG_LEVEL_3) {
        WIFI_LOGI("wifi to wifi, app qoe slow");
        qoeSwitch_ = true;
        if (!qoeScaning_) {
            WIFI_LOGI("wifi to wifi, app qoe slow, try scan");
            pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_APP_QOE_SLOW);
            WifiProChr::GetInstance().RecordWifiProStartTime(WIFI_SWITCH_REASON_APP_QOE_SLOW);
            bool hasSwitchRecord = pWifiProStateMachine_->HasWifiSwitchRecord();
            pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SCAN_DELAY);
            pWifiProStateMachine_->SendMessage(EVENT_REQUEST_SCAN_DELAY, static_cast<int32_t>(hasSwitchRecord));
            rssiLevel4ScanedCounter_ = 0;
            rssiLevel2Or3ScanedCounter_ = 0;
        }
    }
}

bool WifiProStateMachine::GetFilteredCandidates(const std::vector<InterScanInfo>& scanInfos,
    NetworkSelectType selectType, std::vector<InterScanInfo>& outCandidates)
{
    BlockConnectService::GetInstance().UpdateAllNetworkSelectStatus();
    std::unique_ptr<NetworkSelectionManager> pNetworkSelectionManager = std::make_unique<NetworkSelectionManager>();
    if (!pNetworkSelectionManager) {
        WIFI_LOGE("GetFilteredCandidates: Failed to create NetworkSelectionManager.");
        return false;
    }

    std::vector<NetworkSelection::NetworkCandidate> networkCandidates;
    pNetworkSelectionManager->GetAllDeviceConfigs(networkCandidates, scanInfos);

    auto factory = std::make_unique<NetworkSelectorFactory>();
    auto selectorOpt = factory->GetNetworkSelector(selectType);
    if (!selectorOpt.has_value()) {
        WIFI_LOGE("GetFilteredCandidates: Failed to obtain selector for type %{public}d.",
            static_cast<int>(selectType));
        WifiProChr::GetInstance().RecordSelectNetChrCnt(false);
        return false;
    }
    auto &selector = selectorOpt.value();

    pNetworkSelectionManager->TryNominate(networkCandidates, selector);

    std::vector<NetworkSelection::NetworkCandidate *> bestCandidates;
    selector->GetBestCandidates(bestCandidates);

    if (bestCandidates.empty()) {
        WIFI_LOGI("GetFilteredCandidates: Selector filtered out all candidates.");
        WifiProChr::GetInstance().RecordSelectNetChrCnt(false);
        return false;
    }

    for (auto *nc : bestCandidates) {
        if (nc != nullptr) {
            outCandidates.push_back(nc->interScanInfo);
        }
    }

    WIFI_LOGI("GetFilteredCandidates: Found %{public}zu candidates for select type %{public}d.",
        outCandidates.size(), static_cast<int>(selectType));
    return true;
}

bool WifiProStateMachine::IsAutoReconnectPreferred(
    const std::vector<InterScanInfo> &higherCategoryCandidates,
    const std::vector<InterScanInfo> &scanInfos,
    NetworkSelectionResult &outSelectionResult)
{
    if (!pCurrWifiInfo_) {
        WIFI_LOGE("IsAutoReconnectPreferred: Current WiFi info is null.");
        return false;
    }

    // Find the InterScanInfo for the current network from the scan results
    const InterScanInfo* currentCandidate = nullptr;
    for (const auto& scanInfo : scanInfos) {
        if (scanInfo.bssid == pCurrWifiInfo_->bssid) {
            currentCandidate = &scanInfo;
            break;
        }
    }

    if (currentCandidate == nullptr) {
        WIFI_LOGW("IsAutoReconnectPreferred: Could not find current network in scan results.");
        return false;
    }

    // Build candidate vector: current first, then all higher-category candidates
    std::vector<InterScanInfo> candidatesToCompare;
    candidatesToCompare.push_back(*currentCandidate);
    for (const auto &cand : higherCategoryCandidates) {
        candidatesToCompare.push_back(cand);
    }

    // Use NetworkSelectionManager with AUTO_CONNECT to determine the best one among current+all candidates
    std::unique_ptr<NetworkSelectionManager> pNetworkSelectionManager = std::make_unique<NetworkSelectionManager>();
    NetworkSelectionResult selectionResult;
    std::string failReason;

    if (!pNetworkSelectionManager->SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT,
        candidatesToCompare, failReason)) {
        WIFI_LOGI("IsAutoReconnectPreferred: AUTO_CONNECT selection failed: %{public}s", failReason.c_str());
        return false;
    }

    WIFI_LOGI("IsAutoReconnectPreferred: Selection winner is %{public}s.",
        MacAnonymize(selectionResult.interScanInfo.bssid).c_str());

    // Fill outSelectionResult for caller
    outSelectionResult = selectionResult;

    // If winner is not the current network, then a higher-category candidate won
    if (selectionResult.interScanInfo.bssid != pCurrWifiInfo_->bssid) {
        WIFI_LOGI("IsAutoReconnectPreferred: A higher-category candidate was selected by AUTO_CONNECT. Allow switch.");
        WifiProChr::GetInstance().RecordSelectNetChrCnt(true);
        return true;
    }
    WifiProChr::GetInstance().RecordSelectNetChrCnt(false);
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
    pWifiProStateMachine_->MessageExecutedLater(EVENT_REQUEST_SELFCURE_DELAY, DEFAULT_SELFCURE_INTERVAL);
    HandleNoNetChanged();
}

void WifiProStateMachine::WifiNoNetState::GoOutState()
{
    WIFI_LOGI("WifiNoNetState GoOutState function.");
    pWifiProStateMachine_->StopTimer(EVENT_REQUEST_SELFCURE_DELAY);
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
        case EVENT_REQUEST_SELFCURE_DELAY:
            HandleReuqestSelfCure();
            ret = EXECUTED;
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
    WifiProChr::GetInstance().RecordCountWiFiPro(true);
    if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
        WIFI_LOGI("HandleWifiNoInternet Wifi2WifiSwitching.");
        return;
    }

    WIFI_LOGI("NoNetSwitch 1: select network.");
    if (!pWifiProStateMachine_->SelectNetwork(pWifiProStateMachine_->networkSelectionResult_, scanInfos)) {
        if (!fullScan_) {
            WIFI_LOGI("fastscan select net failed, try full scan.");
            pWifiProStateMachine_->SendMessage(EVENT_REQUEST_SCAN_DELAY);
            return;
        }
        WIFI_LOGI("NoInternet X: select network fail.");
        HandleReuqestSelfCure();
        return;
    }

    WIFI_LOGI("NoNetSwitch 2: receive good ap.");
    if (!pWifiProStateMachine_->IsSatisfiedWifi2WifiCondition()) {
        HandleReuqestSelfCure();
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
    if (!pWifiProStateMachine_->IsAllowScan(pWifiProStateMachine_->HasWifiSwitchRecord())) {
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
    WifiProChr::GetInstance().RecordWifiProStartTime(WIFI_SWITCH_REASON_NO_INTERNET);
    isSelfCure_.store(false);
 
    // issatisfy scan
    ISelfCureService *pSelfCureService =
        WifiServiceManager::GetInstance().GetSelfCureServiceInst(pWifiProStateMachine_->instId_);
    if (pSelfCureService != nullptr && pSelfCureService->IsSelfCureOnGoing()) {
        WIFI_LOGI("self cure ongoing.");
        return;
    }
    if (!pWifiProStateMachine_->IsAllowScan(pWifiProStateMachine_->HasWifiSwitchRecord())) {
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
        if (WifiProUtils::IsUserSelectNetwork() && !isFirstDectectHasNet_) {
            WIFI_LOGI("user actively select no-net network, do not allow scan.");
        } else {
            pWifiProStateMachine_->FullScan();
        }
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

void WifiProStateMachine::WifiNoNetState::HandleReuqestSelfCure()
{
    if (isSelfCure_.load()) {
        WIFI_LOGI("SelfCure has already been done.");
        return;
    }
    isSelfCure_.store(true);
    if (pWifiProStateMachine_->TrySelfCure(false)) {
        pWifiProStateMachine_->Wifi2WifiFinish();
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
    pWifiProStateMachine_->isWifi2WifiSwitching_ = false;
    pWifiProStateMachine_->currentState_ = WifiProState::WIFI_PORTAL;
    pWifiProStateMachine_->perf5gHandoverService_.NetworkStatusChanged(NetworkStatus::PORTAL);
    pWifiProStateMachine_->SetSwitchReason(WIFI_SWITCH_REASON_PORTAL);

    if (WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_OPEN) {
        screenOnTimeStamp_ = GetElapsedMicrosecondsSinceBoot();
    } else {
        screenOnTimeStamp_ = 0;
    }
}

void WifiProStateMachine::WifiPortalState::GoOutState()
{
    WIFI_LOGI("WifiPortalState GoOutState function.");
    scanIntervalTime_ = DEFAULT_SCAN_INTERVAL_TIME;
    lastScanTimeStamp_ = 0;
    WifiConfigCenter::GetInstance().SetBrowserState(false);
}

bool WifiProStateMachine::WifiPortalState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGD("WifiPortalState-msgCode=%{public}d is received.", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case EVENT_HANDLE_SCAN_RESULT:
            HandleWifiScanResultInPortal(msg);
            ret = EXECUTED;
            break;
        case EVENT_CHECK_WIFI_INTERNET_RESULT:
            ret = HandleHttpResultInPortal(msg);
            break;
        default:
            return ret;
    }
    return ret;
}

void WifiProStateMachine::WifiPortalState::HandleWifiScanResultInPortal(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("HandleWifiScanResultInPortal: msg is nullptr.");
        return;
    }
    std::vector<InterScanInfo> scanInfos;
    msg->GetMessageObj(scanInfos);
    if (pWifiProStateMachine_->isWifi2WifiSwitching_) {
        WIFI_LOGI("HandleWifiScanResultInPortal: Wifi2WifiSwitching.");
        return;
    }

    if (WifiConfigCenter::GetInstance().GetDeviceType() == ProductDeviceType::TV ||
        WifiConfigCenter::GetInstance().GetBrowserState() ||
        WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_CLOSE) {
        WIFI_LOGI("HandleWifiScanResultInPortal: browser opened just now or screen off, cannot switch");
        return;
    }

    if (screenOnTimeStamp_ != 0) {
        auto currentTime = GetElapsedMicrosecondsSinceBoot();
        if ((currentTime - screenOnTimeStamp_) < SCREEN_ON_DURATIONSECS) {
            WIFI_LOGI("HandleWifiScanResultInPortal: screen-on is not enough.");
            return;
        }
    }

    if (!pWifiProStateMachine_->SelectNetwork(pWifiProStateMachine_->networkSelectionResult_, scanInfos)) {
        WIFI_LOGI("Portal: select network fail.");
        return;
    }

    if (!pWifiProStateMachine_->IsSatisfiedWifi2WifiCondition()) {
        WIFI_LOGI("HandleWifiScanResultInPortal: don't meet wifi2wifi condition.");
        return;
    }

    if (!pWifiProStateMachine_->TryWifi2Wifi(pWifiProStateMachine_->networkSelectionResult_)) {
        WIFI_LOGI("PortalSwitch step X: TryWifi2Wifi Failed.");
        pWifiProStateMachine_->Wifi2WifiFinish();
    }
}

bool WifiProStateMachine::WifiPortalState::HandleHttpResultInPortal(const InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("ReuqestScanInPortal, msg is nullptr.");
        return EXECUTED;
    }
    int32_t state = msg->GetParam1();
    if (state == static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL)) {
        if (WifiConfigCenter::GetInstance().GetDeviceType() == ProductDeviceType::TV ||
            WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_CLOSE ||
            WifiConfigCenter::GetInstance().GetBrowserState()) {
            WIFI_LOGI("IsNotAllowedToScan: screen state off or open browser.");
            return EXECUTED;
        }

        if (screenOnTimeStamp_ != 0) {
            auto currentTime = GetElapsedMicrosecondsSinceBoot();
            if ((currentTime - screenOnTimeStamp_) < SCREEN_ON_DURATIONSECS) {
                WIFI_LOGI("HandleHttpResultInPortal: screen-on is not enough.");
                return EXECUTED;
            }
        }

        auto checkTimeStamp = GetElapsedMicrosecondsSinceBoot();
        if (lastScanTimeStamp_ == 0 || (checkTimeStamp - lastScanTimeStamp_) > scanIntervalTime_) {
            pWifiProStateMachine_->FullScan();
            lastScanTimeStamp_ = GetElapsedMicrosecondsSinceBoot();
            scanIntervalTime_ = std::min(scanIntervalTime_ + scanIntervalTime_, MAX_INTERVAL_TIME);
            WIFI_LOGI("HandleHttpResultInPortal:: FullScan executed.");
            return EXECUTED;
        }
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

} // namespace Wifi
} // namespace OHOS
