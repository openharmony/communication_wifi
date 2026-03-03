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

#include "scan_service.h"
#include <cinttypes>
#include "wifi_global_func.h"
#include "wifi_internal_msg.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_channel_helper.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"
#include "wifi_common_event_helper.h"
#include "wifi_code_convert.h"
#include "wifi_sensor_scene.h"
#include "wifi_service_manager.h"
#include "scan_chr.h"
#include "wifi_pro_utils.h"
#include "network_status_history_manager.h"
DEFINE_WIFILOG_SCAN_LABEL("ScanService");

#define MIN(A, B) (((A) >= (B)) ? (B) : (A))
#define MAX(A, B) (((A) >= (B)) ? (A) : (B))

namespace OHOS {
namespace Wifi {
ScanService::ScanService(int instId)
    : pScanStateMachine(nullptr),
      pScanMonitor(nullptr),
      scanStartedFlag(false),
      scanConfigStoreIndex(0),
      pnoScanStartTime(0),
      staStatus(static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)),
      isPnoScanBegined(false),
      autoNetworkSelection(false),
      lastSystemScanTime(0),
      pnoScanFailedNum(0),
      systemScanFailedNum(0),
      disableScanFlag(false),
      customCurrentTime(0),
      customSceneForbidCount(0),
      scanTrustMode(false),
      lastFreezeState(false),
      isAbsFreezeScaned(false),
      scanResultBackup(-1),
      mEnhanceService(nullptr),
      m_instId(instId),
      lastNetworkQuality(0),
      chipsetCategory(static_cast<int>(WifiCategory::DEFAULT)),
      chipsetFeatrureCapability(0),
      isChipsetInfoObtained(false)
{}

ScanService::~ScanService()
{
    WIFI_LOGI("Enter ~ScanService.\n");

    if (pScanMonitor != nullptr) {
        pScanMonitor->SetScanStateMachine(nullptr);
        delete pScanMonitor;
        pScanMonitor = nullptr;
    }

    if (pScanStateMachine != nullptr) {
        delete pScanStateMachine;
        pScanStateMachine = nullptr;
    }
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->ClearScanInfoList();
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->CleanWifiCategoryRecord();
}

bool ScanService::InitScanService(const IScanSerivceCallbacks &scanSerivceCallbacks)
{
    WIFI_LOGI("Enter ScanService::InitScanService.\n");
    {
        std::unique_lock<std::shared_mutex> lock(mScanCallbackMutex);
        mScanSerivceCallbacks = scanSerivceCallbacks;
    }
    pScanStateMachine = new (std::nothrow) ScanStateMachine(m_instId);
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("Alloc pScanStateMachine failed.\n");
        return false;
    }

    if (!pScanStateMachine->InitScanStateMachine()) {
        WIFI_LOGE("InitScanStateMachine failed.\n");
        return false;
    }

    if (!pScanStateMachine->EnrollScanStatusListener(
        [this](ScanStatusReport &scanStatusReport) { this->HandleScanStatusReport(scanStatusReport); })) {
        WIFI_LOGE("ScanStateMachine_->EnrollScanStatusListener failed.\n");
        return false;
    }
    pScanMonitor = new (std::nothrow) ScanMonitor(m_instId);
    if (pScanMonitor == nullptr) {
        WIFI_LOGE("Alloc pScanMonitor failed.\n");
        return false;
    }

    if (!pScanMonitor->InitScanMonitor()) {
        WIFI_LOGE("InitScanMonitor failed.\n");
        return false;
    }

    pScanMonitor->SetScanStateMachine(pScanStateMachine);
    int delayMs = 100;
    pScanStateMachine->MessageExecutedLater(static_cast<int>(CMD_SCAN_PREPARE), delayMs);
    GetScanControlInfo();
#ifndef OHOS_ARCH_LITE
    std::string moduleName = "ScanService_" + std::to_string(m_instId);
    m_scanObserver = std::make_shared<WifiCountryCodeChangeObserver>(moduleName, *pScanStateMachine);
    if (m_scanObserver == nullptr) {
        WIFI_LOGI("m_scanObserver is null\n");
        return false;
    }
    WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_scanObserver);
#endif
    return true;
}

void ScanService::UnInitScanService()
{
    WIFI_LOGI("Enter UnInitScanService.\n");
#ifndef OHOS_ARCH_LITE
    // deregistration country code change notification
    WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(m_scanObserver);
#endif
    pScanMonitor->UnInitScanMonitor();
    pScanStateMachine->StopTimer(static_cast<int>(SYSTEM_SCAN_TIMER));
    pScanStateMachine->StopTimer(static_cast<int>(DISCONNECTED_SCAN_TIMER));
    pScanStateMachine->StopTimer(static_cast<int>(RESTART_PNO_SCAN_TIMER));
    pScanStateMachine->SendMessage(static_cast<int>(CMD_SCAN_FINISH));
    scanStartedFlag = false;
    return;
}

void ScanService::RegisterP2pEnhanceCallback()
{
    P2pEnhanceCallback p2pEnhanceStateChangeCallback = [this](const std::string &ifName, int32_t state,
        int32_t frequency) {
            this->P2pEnhanceStateChange(ifName, state, frequency);
    };
    if (mEnhanceService == nullptr) {
        WIFI_LOGE("%{public}s, get mEnhanceService failed!", __FUNCTION__);
        return;
    }
    ErrCode ret = mEnhanceService->RegisterP2pEnhanceCallback(WIFI_SERVICE_SCAN, p2pEnhanceStateChangeCallback);
    WIFI_LOGI("%{public}s, result %{public}d.", __FUNCTION__, ret);
}

void ScanService::P2pEnhanceStateChange(const std::string &ifName, int32_t state, int32_t frequency)
{
    WIFI_LOGI("P2pEnhanceStateChange, state %{public}d, frequency %{public}d.", state, frequency);
    int p2pEnhanceState = -1;
    int p2pEnahnceFreq = 0;
    if (state == P2P_ENHANCE_BC_CONNECT_SUCC || state == P2P_ENHANCE_BC_SWITCH_NOTIFY_SUCC) {
        p2pEnhanceState = 1;
        p2pEnahnceFreq = frequency;
    } else if (state == P2P_ENHANCE_BC_DESTROYED) {
        p2pEnhanceState = 0;
        p2pEnahnceFreq = 0;
    } else {
        WIFI_LOGD("No need to handle the state");
    }
    if ((lastP2pEnhanceState != p2pEnhanceState) && (p2pEnhanceState != -1)) {
        lastP2pEnhanceState = p2pEnhanceState;
        WifiConfigCenter::GetInstance().SetP2pEnhanceState(p2pEnhanceState);
        WifiConfigCenter::GetInstance().SetP2pEnhanceFreq(p2pEnahnceFreq);
    }
}

void ScanService::RegisterScanCallbacks(const IScanSerivceCallbacks &iScanSerivceCallbacks)
{
    mScanSerivceCallbacks = iScanSerivceCallbacks;
}

void ScanService::SetEnhanceService(IEnhanceService* enhanceService)
{
    mEnhanceService = enhanceService;
}

void ScanService::HandleScanStatusReport(ScanStatusReport &scanStatusReport)
{
    WIFI_LOGI("Enter HandleScanStatusReport, status:%{public}d", scanStatusReport.status);

    switch (scanStatusReport.status) {
        case SCAN_STARTED_STATUS: {
            CHECK_NULL_AND_RETURN_NULL(pScanStateMachine)
            RegisterP2pEnhanceCallback();
            scanStartedFlag = true;
            /* Pno scan maybe has started, stop it first. */
            pScanStateMachine->SendMessage(CMD_STOP_PNO_SCAN);
            ReportScanStartEvent();
            SystemScanProcess(true);
            break;
        }
        case SCAN_FINISHED_STATUS: {
            ReportScanStopEvent();
            break;
        }
        case COMMON_SCAN_SUCCESS: {
            HandleCommonScanInfo(scanStatusReport.requestIndexList, scanStatusReport.scanInfoList);
            break;
        }
        case COMMON_SCAN_FAILED: {
            HandleCommonScanFailed(scanStatusReport.requestIndexList);
            break;
        }
        case PNO_SCAN_INFO: {
            pnoScanFailedNum = 0;
            HandlePnoScanInfo(scanStatusReport.scanInfoList);
            break;
        }
        case PNO_SCAN_FAILED: {
            CHECK_NULL_AND_RETURN_NULL(pScanStateMachine)
            /* Start the timer and restart the PNO scanning after a delay. */
            pScanStateMachine->StartTimer(static_cast<int>(RESTART_PNO_SCAN_TIMER), RESTART_PNO_SCAN_TIME);
            EndPnoScan();
            break;
        }
        case SCAN_INNER_EVENT: {
            HandleInnerEventReport(scanStatusReport.innerEvent);
            break;
        }
        default: {
            WIFI_LOGI("HandleStatusReport: status is error.\n");
            break;
        }
    }
    return;
}

void ScanService::HandleInnerEventReport(ScanInnerEventType innerEvent)
{
    WIFI_LOGI("Enter HandleInnerEventReport.\n");

    switch (innerEvent) {
        case SYSTEM_SCAN_TIMER: {
            HandleSystemScanTimeout();
            break;
        }
        case DISCONNECTED_SCAN_TIMER: {
            HandleDisconnectedScanTimeout();
            break;
        }
        case RESTART_PNO_SCAN_TIMER: {
            RestartPnoScanTimeOut();
            break;
        }
        case RESTART_SYSTEM_SCAN_TIMER: {
            RestartSystemScanTimeOut();
            break;
        }
        case RESTART_COMMON_SCAN_TIMER: {
            RestartCommonScanAfterLpScanFailed();
            break;
        }
        case SYSTEM_SINGLE_SCAN_TIMER: {
            HandleSystemSingleScanTimeOut();
            break;
        }
        default: {
            break;
        }
    }
}

ErrCode ScanService::Scan(ScanType scanType, int scanStyle)
{
    WIFI_LOGI("Enter Scan, scanType:%{public}d, scanStyle:%{public}d.\n", static_cast<int>(scanType),
        static_cast<int>(scanStyle));
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanType(scanType);
    if (!scanStartedFlag) {
        WIFI_LOGE("Scan service has not started.\n");
        return WIFI_OPT_FAILED;
    }
    if (scanStyle == SCAN_TYPE_LOW_PRIORITY && (mEnhanceService == nullptr ||
        !mEnhanceService->IsSupportLpScanAbility())) {
        WIFI_LOGE("scanStyle is %{public}d, but do not support LP scan.\n", scanStyle);
        return WIFI_OPT_FAILED;
    }

    if (ScanControlInner(scanType, scanStyle) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
 
    ScanConfig scanConfig;
    /*
     * Invoke the interface provided by the configuration center to obtain the
     * hidden network list.
     */
    int uid = 0;
#ifndef OHOS_ARCH_LITE
    uid = GetCallingUid();
#endif
    if (scanStyle != SCAN_TYPE_LOW_PRIORITY) {
        if (uid != LOCATOR_SA_UID && !GetHiddenNetworkSsidList(scanConfig.hiddenNetworkSsid)) {
            WIFI_LOGE("GetHiddenNetworkSsidList failed.\n");
        }
    }
 
    scanConfig.scanBand = SCAN_BAND_BOTH_WITH_DFS;
    scanConfig.fullScanFlag = true;
    scanConfig.scanType = scanType;
    scanConfig.scanStyle = scanStyle;
    if (!SingleScan(scanConfig)) {
        WIFI_LOGE("SingleScan failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::ScanWithParam(const WifiScanParams &params, ScanType scanType)
{
    WIFI_LOGI("Enter ScanWithParam, freqs num:%{public}d.\n", (int)params.freqs.size());
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanType(scanType);
 
    if (params.scanStyle == SCAN_TYPE_LOW_PRIORITY && (mEnhanceService == nullptr ||
        !mEnhanceService->IsSupportLpScanAbility())) {
        WIFI_LOGE("scanStyle is %{public}d, but do not support LP scan.\n", params.scanStyle);
        return WIFI_OPT_FAILED;
    }

    ScanConfig scanConfig;
    scanConfig.scanStyle = params.scanStyle;
    if (!scanStartedFlag) {
        WIFI_LOGE("Scan service has not started.\n");
        return WIFI_OPT_FAILED;
    }
 
    if (ScanControlInner(scanType, scanConfig.scanStyle) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
 
    if ((params.band < static_cast<int>(SCAN_BAND_UNSPECIFIED)) ||
        (params.band > static_cast<int>(SCAN_BAND_BOTH_WITH_DFS))) {
        WIFI_LOGE("params.band is error.\n");
        return WIFI_OPT_FAILED;
    }
 
    /* When the frequency is specified, the band must be SCAN_BAND_UNSPECIFIED. */
    if (params.freqs.empty() && (params.band == static_cast<int>(SCAN_BAND_UNSPECIFIED))) {
        WIFI_LOGE("params is error.\n");
        return WIFI_OPT_FAILED;
    }
 
    scanConfig.fullScanFlag = params.ssid.empty() && params.bssid.empty() &&
        (params.band == static_cast<int>(SCAN_BAND_BOTH_WITH_DFS));

    if (scanConfig.scanStyle != SCAN_TYPE_LOW_PRIORITY) {
        if (!params.ssid.empty()) {
            scanConfig.hiddenNetworkSsid.push_back(params.ssid);
            // for gbk hiddenNetworkSsID
            AddSsidToHiddenNetworkList(params.ssid, scanConfig.hiddenNetworkSsid);
        } else if (!GetHiddenNetworkSsidList(scanConfig.hiddenNetworkSsid)) {
            /*
            * Invoke the interface provided by the configuration center to obtain the
            * hidden network list.
            */
            WIFI_LOGE("GetHiddenNetworkSsidList failed.\n");
        }
    }
    
    scanConfig.scanBand = static_cast<ScanBandType>(params.band);
    scanConfig.scanFreqs.assign(params.freqs.begin(), params.freqs.end());
    scanConfig.ssid = params.ssid;
    scanConfig.bssid = params.bssid;
    scanConfig.scanType = scanType;
    scanConfig.scanningWithParamFlag = true;
 
    if (!SingleScan(scanConfig)) {
        WIFI_LOGE("SingleScan failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void ScanService::AddSsidToHiddenNetworkList(const std::string ssid, std::vector<std::string>& hiddenNetworkSsidList)
{
    std::string gbkSsid = WifiCodeConvertUtil::Utf8ToGbk(ssid);
    if (gbkSsid != ssid && !gbkSsid.empty()) {
        hiddenNetworkSsidList.push_back(gbkSsid);
    }
}

ErrCode ScanService::ScanControlInner(ScanType scanType, int &scanStyle)
{
    if (scanType == ScanType::SCAN_TYPE_EXTERN) {
        ErrCode rlt = AllowScanByType(ScanType::SCAN_TYPE_EXTERN, scanStyle);
        if (rlt != WIFI_OPT_SUCCESS) {
            return rlt;
        }
    } else if (scanType == ScanType::SCAN_TYPE_WIFIPRO || scanType == ScanType::SCAN_TYPE_5G_AP) {
        ErrCode rlt = AllowScanByType(scanType, scanStyle);
        if (rlt != WIFI_OPT_SUCCESS) {
            return rlt;
        }
    } else if (scanType == ScanType::SCAN_TYPE_HIDDEN_AP) {
        if (scanStyle == SCAN_TYPE_LOW_PRIORITY) {
            return WIFI_OPT_FAILED;
        }
        return WIFI_OPT_SUCCESS;
    } else {
        if (!AllowScanByDisableScanCtrl()) {
            WIFI_LOGW("internal scan not allow by disable scan control.");
            WifiScanChr::GetInstance().RecordScanChrLimitInfo(
                WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
                ScanLimitType::SCAN_DISABLE);
            return WIFI_OPT_FAILED;
        }
        if (!AllowScanByHid2dState(scanType, scanStyle)) {
            WIFI_LOGW("internal scan not allow by hid2d state");
            return WIFI_OPT_FAILED;
        }
        if (!AllowScanByActionListen()) {
            WIFI_LOGW("internal scan not allow by ActionListen condition");
            return WIFI_OPT_FAILED;
        }
        if (!AllowScanByGameScene(scanType, scanStyle)) {
            WIFI_LOGW("internal scan not allow by Game Scene");
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::DisableScan(bool disable)
{
    LOGI("Enter DisableScan");
    if (disableScanFlag == disable) {
        if (!disable) {
            SystemScanProcess(true);
        }
        return WIFI_OPT_SUCCESS;
    }
    disableScanFlag = disable;
    if (disableScanFlag) {
        pScanStateMachine->SendMessage(static_cast<int>(CMD_DISABLE_SCAN));
    } else {
        pScanStateMachine->SendMessage(static_cast<int>(CMD_SCAN_PREPARE));
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    LOGI("Enter StartWifiPnoScan isStart:%{public}d", isStartAction);
    if (isStartAction) {
        StopPnoScan();
        pnoScanIntervalMode.scanIntervalMode.interval = periodMs / 1000;
        BeginPnoScan();
    } else {
        StopPnoScan();
        WriteWifiPnoScanHiSysEvent(MODE_STATE_CLOSE, suspendReason);
    }
    return WIFI_OPT_SUCCESS;
}

void ScanService::StopPnoScan()
{
    if (!isPnoScanBegined) {
        return;
    }
    EndPnoScan();
    pnoScanFailedNum = 0;
    pScanStateMachine->StopTimer(static_cast<int>(RESTART_PNO_SCAN_TIMER));
}

bool ScanService::SingleScan(ScanConfig &scanConfig)
{
    WIFI_LOGI("Enter SingleScan.\n");

    GetAllowBandFreqsControlInfo(scanConfig.scanBand, scanConfig.scanFreqs);
    if ((scanConfig.scanBand == SCAN_BAND_UNSPECIFIED) && (scanConfig.scanFreqs.empty())) {
        WIFI_LOGE("Have no allowed band or freq.\n");
        return false;
    }

    InterScanConfig interConfig;
    interConfig.fullScanFlag = scanConfig.fullScanFlag;
    interConfig.hiddenNetworkSsid.assign(scanConfig.hiddenNetworkSsid.begin(), scanConfig.hiddenNetworkSsid.end());
    interConfig.scanStyle = scanConfig.scanStyle;

    /* Specified frequency */
    if (scanConfig.scanBand == SCAN_BAND_UNSPECIFIED) {
        interConfig.scanFreqs.assign(scanConfig.scanFreqs.begin(), scanConfig.scanFreqs.end());
        /*
         * When band is SCAN_BAND_BOTH_WITH_DFS, need to scan all frequency,
         * scanFreqs can be empty.
         */
    } else if (scanConfig.scanBand != SCAN_BAND_BOTH_WITH_DFS) {
        /* Converting frequency bands to frequencies. */
        if (!WifiChannelHelper::GetInstance().GetAvailableScanFreqs(scanConfig.scanBand, interConfig.scanFreqs)) {
            WIFI_LOGE("GetBandFreqs failed.\n");
            return false;
        }
    }

    /* Save the configuration. */
    int requestIndex = StoreRequestScanConfig(scanConfig, interConfig);
    if (requestIndex == MAX_SCAN_CONFIG_STORE_INDEX) {
        WIFI_LOGE("StoreRequestScanConfig failed.\n");
        return false;
    }

    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("pScanStateMachine is null.\n");
        return false;
    }
    /* Construct a message. */
    InternalMessagePtr interMessage =
        pScanStateMachine->CreateMessage(static_cast<int>(CMD_START_COMMON_SCAN), requestIndex);
    if (interMessage == nullptr) {
        std::unique_lock<std::mutex> lock(scanConfigMapMutex);
        scanConfigMap.erase(requestIndex);
        WIFI_LOGE("CreateMessage failed.\n");
        return false;
    }

#ifndef OHOS_ARCH_LITE
    /* Check whether to perform fast scan based on historical information after wifi is enable. */
    CheckNeedFastScan(interConfig.scanFreqs);
#endif

    if (!AddScanMessageBody(interMessage, interConfig)) {
        std::unique_lock<std::mutex> lock(scanConfigMapMutex);
        scanConfigMap.erase(requestIndex);
        MessageManage::GetInstance().ReclaimMsg(interMessage);
        WIFI_LOGE("AddScanMessageBody failed.\n");
        return false;
    }
    pScanStateMachine->SendMessage(interMessage);

    return true;
}

bool ScanService::GetBandFreqs(ScanBandType band, std::vector<int> &freqs)
{
    WIFI_LOGI("Enter GetBandFreqs.\n");

    switch (band) {
        case SCAN_BAND_24_GHZ: {
            freqs.assign(freqs2G.begin(), freqs2G.end());
            return true;
        }

        case SCAN_BAND_5_GHZ: {
            freqs.assign(freqs5G.begin(), freqs5G.end());
            return true;
        }

        case SCAN_BAND_BOTH: {
            freqs.insert(freqs.end(), freqs2G.begin(), freqs2G.end());
            freqs.insert(freqs.end(), freqs5G.begin(), freqs5G.end());
            return true;
        }

        case SCAN_BAND_5_GHZ_DFS_ONLY: {
            freqs.assign(freqsDfs.begin(), freqsDfs.end());
            return true;
        }

        case SCAN_BAND_5_GHZ_WITH_DFS: {
            freqs.insert(freqs.end(), freqs5G.begin(), freqs5G.end());
            freqs.insert(freqs.end(), freqsDfs.begin(), freqsDfs.end());
            return true;
        }

        case SCAN_BAND_BOTH_WITH_DFS: {
            freqs.insert(freqs.end(), freqs2G.begin(), freqs2G.end());
            freqs.insert(freqs.end(), freqs5G.begin(), freqs5G.end());
            freqs.insert(freqs.end(), freqsDfs.begin(), freqsDfs.end());
            return true;
        }

        default:
            WIFI_LOGE("bandType(%{public}d) is error.\n", band);
            return false;
    }
}

bool ScanService::AddScanMessageBody(InternalMessagePtr interMessage, const InterScanConfig &interConfig)
{
    WIFI_LOGI("Enter AddScanMessageBody.\n");

    if (interMessage == nullptr) {
        WIFI_LOGE("interMessage is null.\n");
        return false;
    }

    interMessage->AddIntMessageBody(interConfig.hiddenNetworkSsid.size());
    std::vector<std::string>::const_iterator iter = interConfig.hiddenNetworkSsid.begin();
    for (; iter != interConfig.hiddenNetworkSsid.end(); ++iter) {
        interMessage->AddStringMessageBody(*iter);
    }

    interMessage->AddIntMessageBody(interConfig.scanFreqs.size());
    std::vector<int>::const_iterator iterFreq = interConfig.scanFreqs.begin();
    for (; iterFreq != interConfig.scanFreqs.end(); ++iterFreq) {
        interMessage->AddIntMessageBody(*iterFreq);
    }

    interMessage->AddIntMessageBody(static_cast<int>(interConfig.fullScanFlag));
    interMessage->AddIntMessageBody(interConfig.backScanPeriod);
    interMessage->AddIntMessageBody(interConfig.bssidsNumPerScan);
    interMessage->AddIntMessageBody(interConfig.maxScansCache);
    interMessage->AddIntMessageBody(interConfig.maxBackScanPeriod);
    interMessage->AddIntMessageBody(interConfig.scanStyle);

    return true;
}

int ScanService::StoreRequestScanConfig(const ScanConfig &scanConfig, const InterScanConfig &interConfig)
{
    WIFI_LOGI("Enter StoreRequestScanConfig.\n");

    int i = 0;
    for (i = 0; i < MAX_SCAN_CONFIG_STORE_INDEX; i++) {
        scanConfigStoreIndex++;
        if (scanConfigStoreIndex >= MAX_SCAN_CONFIG_STORE_INDEX) {
            scanConfigStoreIndex = 0;
        }
        {
            std::unique_lock<std::mutex> lock(scanConfigMapMutex);
            ScanConfigMap::iterator iter = scanConfigMap.find(scanConfigStoreIndex);
            if (iter == scanConfigMap.end()) {
                break;
            }
        }
    }

    if (i == MAX_SCAN_CONFIG_STORE_INDEX) {
        return MAX_SCAN_CONFIG_STORE_INDEX;
    }

    StoreScanConfig storeScanConfig;
    storeScanConfig.ssid = scanConfig.ssid;
    storeScanConfig.bssid = scanConfig.bssid;
    storeScanConfig.scanFreqs.assign(interConfig.scanFreqs.begin(), interConfig.scanFreqs.end());

    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    storeScanConfig.scanTime =
        static_cast<int64_t>(times.tv_sec) * SECOND_TO_MICRO_SECOND + times.tv_nsec / SECOND_TO_MILLI_SECOND;
    storeScanConfig.fullScanFlag = scanConfig.fullScanFlag;
    storeScanConfig.scanType = scanConfig.scanType;
    storeScanConfig.scanStyle = scanConfig.scanStyle;
    storeScanConfig.scanningWithParamFlag = scanConfig.scanningWithParamFlag;

    std::unique_lock<std::mutex> lock(scanConfigMapMutex);
    scanConfigMap.insert(std::pair<int, StoreScanConfig>(scanConfigStoreIndex, storeScanConfig));
    WIFI_LOGI("StoreRequestScanConfig, add success, scanConfigStoreIndex: %{public}d", scanConfigStoreIndex);
    return scanConfigStoreIndex;
}

void ScanService::HandleCommonScanFailed(std::vector<int> &requestIndexList)
{
    WIFI_LOGI("Enter HandleCommonScanFailed, requestIndexList size: %{public}d.",
        static_cast<int>(requestIndexList.size()));

    std::unique_lock<std::mutex> lock(scanConfigMapMutex);
    bool needRestartSystemScan = false;
    bool needReportScanResult = false;
    /* Indicates if LP scan failed */
    bool lpScanFailed = true;

    for (std::vector<int>::iterator reqIter = requestIndexList.begin(); reqIter != requestIndexList.end(); ++reqIter) {
        ScanConfigMap::iterator configIter = scanConfigMap.find(*reqIter);
        /* No configuration found. */
        if (configIter == scanConfigMap.end()) {
            continue;
        }
 
        if (configIter->second.scanStyle != SCAN_TYPE_LOW_PRIORITY) {
            lpScanFailed = false;
        }

        if (configIter->second.scanType != ScanType::SCAN_TYPE_SYSTEMTIMER) {
            needReportScanResult = true;
        } else {
            needRestartSystemScan = true;
            systemScanFailedNum++;
        }
        scanConfigMap.erase(*reqIter);
    }
 
    if (needRestartSystemScan) {
        HandleSystemScanFailed();
    } else if (lpScanFailed) {
        HandleLpScanFailed();
    }

    if (needReportScanResult) {
        /* Notification of the end of scanning. */
        ReportScanFinishEvent(static_cast<int>(ScanHandleNotify::SCAN_FAIL));
        scanResultBackup = static_cast<int>(ScanHandleNotify::SCAN_FAIL);
    }
    WifiCommonEventHelper::PublishScanFinishedEvent(static_cast<int>(ScanHandleNotify::SCAN_FAIL), "OnScanFinished");
    return;
}

void ScanService::HandleSystemScanFailed()
{
    if (pScanStateMachine != nullptr && systemScanFailedNum < MAX_SYSTEM_SCAN_FAILED_NUM &&
        staStatus == static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)) {
        pScanStateMachine->StopTimer(static_cast<int>(RESTART_SYSTEM_SCAN_TIMER));
        pScanStateMachine->StartTimer(static_cast<int>(RESTART_SYSTEM_SCAN_TIMER), RESTART_SYSTEM_SCAN_TIME);
    }
}
 
void ScanService::HandleLpScanFailed()
{
    WIFI_LOGI("LP Scan is aborted.");
    WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::LP_SCAN_ABORT_CNT);
    if (pScanStateMachine != nullptr && AllowCommonScanOnLpScanFailure()) {
        pScanStateMachine->StopTimer(static_cast<int>(RESTART_COMMON_SCAN_TIMER));
        pScanStateMachine->StartTimer(static_cast<int>(RESTART_COMMON_SCAN_TIMER), RESTART_COMMON_SCAN_TIME);
    }
}

bool ScanService::AllowCommonScanOnLpScanFailure()
{
    Hid2dUpperScene softbusScene;
    Hid2dUpperScene castScene;
    Hid2dUpperScene miracastScene;
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SOFT_BUS_SERVICE_UID, softbusScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(CAST_ENGINE_SERVICE_UID, castScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MIRACAST_SERVICE_UID, miracastScene);
    WifiNetworkControlInfo NetworkControlInfo = WifiConfigCenter::GetInstance().GetNetworkControlInfo();
    if (((softbusScene.scene & 0x07) > 0 && (softbusScene.scene & 0x07) <= 0x03) ||
        (castScene.scene & 0x07) > 0 || (miracastScene.scene & 0x07) > 0 ||
        NetworkControlInfo.state == GameSceneId::MSG_GAME_ENTER_PVP_BATTLE ||
        NetworkControlInfo.state == GameSceneId::MSG_GAME_STATE_FOREGROUND) {
        WIFI_LOGW("can not restart common scan after Lp scan failed.");
        return false;
    }
    return true;
}

void ScanService::HandleCommonScanInfo(
    std::vector<int> &requestIndexList, std::vector<InterScanInfo> &scanInfoList)
{
    WIFI_LOGI("HandleCommonScanInfo, requestIndexList size: %{public}d.", static_cast<int>(requestIndexList.size()));
    if (!isChipsetInfoObtained) {
        InitChipsetInfo();
    }
    bool fullScanStored = false;
    {
        std::unique_lock<std::mutex> lock(scanConfigMapMutex);
        HandleScanResults(requestIndexList, scanInfoList, fullScanStored);
    }
    pScanStateMachine->StopTimer(static_cast<int>(RESTART_SYSTEM_SCAN_TIMER));
    if (fullScanStored) {
        TryToRestoreSavedNetwork();
    }
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    int64_t availableTime = static_cast<int64_t>(times.tv_sec) * SECOND_TO_MICRO_SECOND +
        times.tv_nsec / SECOND_TO_MILLI_SECOND;
    if (mEnhanceService != nullptr) {
        mEnhanceService->SetEnhanceParam(availableTime);
    }
    /* Send the scanning result to the module registered for listening. */
    ScanInfoHandlerMap::iterator handleIter = scanInfoHandlerMap.begin();
    for (; handleIter != scanInfoHandlerMap.end(); ++handleIter) {
        if (handleIter->second) {
            handleIter->second(scanInfoList);
        }
    }

    /* Send the result to the interface service. */
    ReportScanInfos(scanInfoList);

    return;
}

void ScanService::HandleScanResults(std::vector<int> &requestIndexList, std::vector<InterScanInfo> &scanInfoList,
    bool &fullScanStored)
{
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    //fill wifiRiskType based on whole scanInfoList
    GetWifiRiskType(scanInfoList);
#endif
    bool needReportScanResult = false;
    for (std::vector<int>::iterator reqIter = requestIndexList.begin(); reqIter != requestIndexList.end(); ++reqIter) {
        ScanConfigMap::iterator configIter = scanConfigMap.find(*reqIter);
        /* No configuration found. */
        if (configIter == scanConfigMap.end()) {
            continue;
        }
        if (configIter->second.scanType != ScanType::SCAN_TYPE_SYSTEMTIMER) {
            needReportScanResult = true;
        } else {
            systemScanFailedNum = 0;
        }
        /* Full Scan Info. */
        if (configIter->second.fullScanFlag) {
            if (fullScanStored) {
                scanConfigMap.erase(*reqIter);
                continue;
            }
            if (StoreFullScanInfo(configIter->second, scanInfoList)) {
                fullScanStored = true;
                scanResultBackup = static_cast<int>(ScanHandleNotify::SCAN_OK);
            } else {
                WIFI_LOGE("StoreFullScanInfo failed.\n");
            }
            /* Specify Scan Info. */
        } else {
            if (!StoreUserScanInfo(configIter->second, scanInfoList)) {
                WIFI_LOGE("StoreUserScanInfo failed.\n");
            }
            scanResultBackup = static_cast<int>(ScanHandleNotify::SCAN_OK);
        }
        scanConfigMap.erase(*reqIter);
    }
    if (needReportScanResult) {
        ReportScanFinishEvent(static_cast<int>(ScanHandleNotify::SCAN_OK));
    } else {
        WIFI_LOGI("No need to report scan finish event.\n");
    }
    WifiCommonEventHelper::PublishScanFinishedEvent(static_cast<int>(ScanHandleNotify::SCAN_OK), "OnScanFinished");
}

int ScanService::GetWifiMaxSupportedMaxSpeed(const InterScanInfo &scanInfo, const int &maxNumberSpatialStreams)
{
    int wifiStandard = 0;
    bool is11bMode = scanInfo.IsWifi11bMode();
    scanInfo.GetWifiStandard(wifiStandard);
    return WifiMaxThroughput(wifiStandard, is11bMode, scanInfo.channelWidth,
        MAX_RSSI, maxNumberSpatialStreams, 0);
}

void ScanService::ConvertScanInfo(WifiScanInfo &scanInfo, const InterScanInfo &interInfo)
{
    scanInfo.bssid = interInfo.bssid;
    scanInfo.bssidType = REAL_DEVICE_ADDRESS;
    scanInfo.ssid = interInfo.ssid;
    scanInfo.oriSsid = interInfo.oriSsid;
    scanInfo.capabilities = interInfo.capabilities;
    scanInfo.frequency = interInfo.frequency;
    scanInfo.channelWidth = interInfo.channelWidth;
    scanInfo.centerFrequency0 = interInfo.centerFrequency0;
    scanInfo.centerFrequency1 = interInfo.centerFrequency1;
    scanInfo.rssi = interInfo.rssi;
    scanInfo.securityType = interInfo.securityType;
    scanInfo.infoElems = interInfo.infoElems;
    scanInfo.features = interInfo.features;
    scanInfo.timestamp = interInfo.timestamp;
    scanInfo.band = interInfo.band;
    scanInfo.disappearCount = 0;
    scanInfo.maxSupportedRxLinkSpeed = GetWifiMaxSupportedMaxSpeed(interInfo, MAX_RX_SPATIAL_STREAMS);
    scanInfo.maxSupportedTxLinkSpeed = GetWifiMaxSupportedMaxSpeed(interInfo, MAX_TX_SPATIAL_STREAMS);
    interInfo.GetWifiStandard(scanInfo.wifiStandard);
    scanInfo.isHiLinkNetwork = interInfo.isHiLinkNetwork;
    scanInfo.isHiLinkProNetwork = interInfo.isHiLinkProNetwork;
    scanInfo.supportedWifiCategory = interInfo.supportedWifiCategory;
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    scanInfo.riskType = interInfo.riskType;
#endif
}
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
void ScanService::GetWifiRiskType(std::vector<InterScanInfo> &scanInfos)
{
    if (scanInfos.size() == 0) {
        return;
    }
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    std::unordered_map<std::string, int> ssidBssidCount;
    std::unordered_set<std::string> reportedCloneWifi;
    for (const auto& wifi : scanInfos) {
        if (wifi.ssid.empty()) {
            continue;
        }
        std::string key = wifi.ssid + "--" + wifi.bssid;
        ssidBssidCount[key]++;
    }
    for (auto& wifi : scanInfos) {
        std::string key = wifi.ssid + "--" + wifi.bssid;
        if (ssidBssidCount[key] > 1) {
            wifi.riskType = WifiRiskType::CLONE_ATTACK;
            if (reportedCloneWifi.count(key) == 0) {
                ReportWifiCloneAttackHiSysEvent(wifi);
                reportedCloneWifi.insert(key);
            }
            continue;
        }
        if (wifi.securityType == WifiSecurity::OPEN) {
            wifi.riskType = pEnhanceService != nullptr && pEnhanceService->CheckScanInfoInUnsafeWiFiWhiteList(wifi) \
            ? WifiRiskType::NORMAL : WifiRiskType::OPEN;
        } else {
            wifi.riskType = WifiRiskType::NORMAL;
        }
    }
}

void ScanService::ReportWifiCloneAttackHiSysEvent(const InterScanInfo &interInfo)
{
    WifiRiskInfo wifiRiskInfo;
    wifiRiskInfo.riskType = static_cast<int>(WifiRiskInfoReason::WIFI_COPY_NETWORK);
    wifiRiskInfo.ssid = interInfo.ssid;
    wifiRiskInfo.bssid = interInfo.bssid;
    wifiRiskInfo.frequency = interInfo.frequency;
    wifiRiskInfo.band = interInfo.band;
    wifiRiskInfo.rssi = interInfo.rssi;
    WriteWifiRiskInfoHiSysEvent(wifiRiskInfo);
}
#endif

void ScanService::MergeScanResult(std::vector<WifiScanInfo> &results, std::vector<WifiScanInfo> &storeInfoList)
{
    for (auto storedIter = storeInfoList.begin(); storedIter != storeInfoList.end(); ++storedIter) {
        bool find = false;
        for (auto iter = results.begin(); iter != results.end(); ++iter) {
            if (iter->bssid == storedIter->bssid) {
                iter = results.erase(iter);
                find = true;
                break;
            }
        }
        if (!find) {
#ifdef SUPPORT_RANDOM_MAC_ADDR
            WifiConfigCenter::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
                storedIter->bssid, "");
#endif
            WIFI_LOGI("ScanInfo add new ssid=%{public}s bssid=%{public}s rssi=%{public}d, wifiCategory:%{public}d",
                SsidAnonymize(storedIter->ssid).c_str(), MacAnonymize(storedIter->bssid).c_str(), storedIter->rssi,
                static_cast<int>(storedIter->supportedWifiCategory));
        }
        results.push_back(*storedIter);
    }

    WIFI_LOGI("Save %{public}d scan results.", (int)(results.size()));
    if (WifiConfigCenter::GetInstance().GetWifiScanConfig()->SaveScanInfoList(results) != 0) {
        WIFI_LOGE("SaveScanInfoList failed.\n");
    }
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService != nullptr && pEnhanceService->CheckScanInfo(false)) {
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SaveExternalScanInfoList(results);
    }
    WifiConfigCenter::GetInstance().UpdateLinkedInfo(m_instId);
}

void ScanService::TryToRestoreSavedNetwork()
{
    WifiScanParams params;
    std::vector<WifiScanInfo> results;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(results);
    std::vector<std::string> savedNetworkSsid;
    GetSavedNetworkSsidList(savedNetworkSsid);
    for (auto iter = results.begin(); iter != results.end(); ++iter) {
        if (iter->disappearCount > 0
            && std::find(savedNetworkSsid.begin(), savedNetworkSsid.end(), iter->ssid) != savedNetworkSsid.end()) {
            params.freqs.push_back(iter->frequency);
        }
    }
    if (!params.freqs.empty()) {
        ScanWithParam(params, ScanType::SCAN_TYPE_SYSTEMTIMER);
    }
}

bool ScanService::StoreFullScanInfo(
    const StoreScanConfig &scanConfig, std::vector<InterScanInfo> &scanInfoList)
{
    WIFI_LOGI("Enter StoreFullScanInfo.\n");
    /* Filtering result. */
    WIFI_LOGI("scanConfig.scanTime is %" PRId64 ".\n", scanConfig.scanTime);
    WIFI_LOGI("Receive %{public}d scan results.\n", (int)(scanInfoList.size()));
    if (scanInfoList.size() == 0) {
        /* Don't overwrite ScanInfoList */
        std::vector<WifiScanInfo> results;
        int ret = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(results);
        if (ret != 0) {
            WIFI_LOGW("GetScanInfoList return error. \n");
        }
        for (auto iter = results.begin(); iter != results.end(); ++iter) {
            iter->disappearCount++;
        }
        if (WifiConfigCenter::GetInstance().GetWifiScanConfig()->SaveScanInfoList(results) != 0) {
            WIFI_LOGE("SaveScanInfoList failed.\n");
        }
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr && pEnhanceService->CheckScanInfo(false)) {
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->SaveExternalScanInfoList(results);
        }
        return true;
    }

    std::vector<WifiScanInfo> storeInfoList;
    for (auto iter = scanInfoList.begin(); iter != scanInfoList.end(); ++iter) {
        WifiScanInfo scanInfo;
        if (mEnhanceService != nullptr) {
            iter->supportedWifiCategory = mEnhanceService->GetWifiCategory(iter->infoElems,
                chipsetCategory, chipsetFeatrureCapability);
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->RecordWifiCategory(
                iter->bssid, iter->supportedWifiCategory);
            WIFI_LOGD("GetWifiCategory supportedWifiCategory=%{public}d.\n",
                static_cast<int>(iter->supportedWifiCategory));
        }
        ConvertScanInfo(scanInfo, *iter);
        storeInfoList.push_back(scanInfo);
    }

    std::vector<WifiScanInfo> results;
    int ret = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(results);
    if (ret != 0) {
        WIFI_LOGW("GetScanInfoList return error. \n");
    }
    for (auto iter = results.begin(); iter != results.end(); ++iter) {
        iter->disappearCount++;
    }
    MergeScanResult(results, storeInfoList);

    return true;
}

bool ScanService::StoreUserScanInfo(const StoreScanConfig &scanConfig, std::vector<InterScanInfo> &scanInfoList)
{
    WIFI_LOGI("Enter StoreUserScanInfo.\n");

    std::vector<WifiScanInfo> storeInfoList;
    std::vector<InterScanInfo>::const_iterator iter = scanInfoList.begin();
    for (; iter != scanInfoList.end(); ++iter) {
        /* frequency filtering. */
        if (!scanConfig.scanFreqs.empty()) {
            if (std::find(scanConfig.scanFreqs.begin(), scanConfig.scanFreqs.end(), iter->frequency) ==
                scanConfig.scanFreqs.end()) {
                continue;
            }
        }

        /* SSID filtering. */
        if ((!scanConfig.ssid.empty()) && (scanConfig.ssid != iter->ssid)) {
            continue;
        }

        /* BSSID filtering. */
        if ((!scanConfig.bssid.empty()) && (scanConfig.bssid != iter->bssid)) {
            continue;
        }

        WifiScanInfo scanInfo;
        ConvertScanInfo(scanInfo, *iter);
        storeInfoList.push_back(scanInfo);
    }
    if (storeInfoList.empty()) {
        WIFI_LOGI("Specified channel scan no results.\n");
        return false;
    }

    std::vector<WifiScanInfo> results;
    int ret = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(results);
    if (ret != 0) {
        WIFI_LOGW("GetScanInfoList return error. \n");
    }
    MergeScanResult(results, storeInfoList);

    /*
     * The specified parameter scanning is initiated by the system and
     * store in the configuration center.
     */
    ReportStoreScanInfos(scanInfoList);

    return true;
}

void ScanService::ReportScanStartEvent()
{
    std::shared_lock<std::shared_mutex> lock(mScanCallbackMutex);
    mScanSerivceCallbacks.OnScanStartEvent(m_instId);
}

void ScanService::ReportScanStopEvent()
{
    std::shared_lock<std::shared_mutex> lock(mScanCallbackMutex);
    mScanSerivceCallbacks.OnScanStopEvent(m_instId);
}

void ScanService::ReportScanFinishEvent(int event)
{
    std::shared_lock<std::shared_mutex> lock(mScanCallbackMutex);
    mScanSerivceCallbacks.OnScanFinishEvent(event, m_instId);
}

void ScanService::ReportScanInfos(std::vector<InterScanInfo> &interScanList)
{
    WIFI_LOGI("Enter ScanService::ReportScanInfos.\n");
    std::shared_lock<std::shared_mutex> lock(mScanCallbackMutex);
    mScanSerivceCallbacks.OnScanInfoEvent(interScanList, m_instId);
    return;
}

void ScanService::ReportStoreScanInfos(std::vector<InterScanInfo> &interScanList)
{
    WIFI_LOGI("Enter ScanService::ReportStoreScanInfos.\n");
    std::shared_lock<std::shared_mutex> lock(mScanCallbackMutex);
    mScanSerivceCallbacks.OnStoreScanInfoEvent(interScanList, m_instId);
    return;
}

bool ScanService::BeginPnoScan()
{
    WIFI_LOGI("Enter BeginPnoScan.\n");
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanType(ScanType::SCAN_TYPE_PNO);

    if (isPnoScanBegined) {
        WIFI_LOGI("PNO scan has started.\n");
        return false;
    }
    int scanStyle = SCAN_DEFAULT_TYPE;
    ErrCode rlt = AllowScanByType(ScanType::SCAN_TYPE_PNO, scanStyle);
    if (rlt != WIFI_OPT_SUCCESS) {
        return false;
    }

    PnoScanConfig pnoScanConfig;
    /* Obtain the network list from the configuration center. */
    if (!GetSavedNetworkSsidList(pnoScanConfig.savedNetworkSsid)) {
        WIFI_LOGE("GetSavedNetworkSsidList failed.\n");
        return false;
    }
    if (pnoScanConfig.savedNetworkSsid.size() == 0) {
        WIFI_LOGE("Have no saved network, not need to start PNO scan.\n");
        return false;
    }
    if (!GetHiddenNetworkSsidList(pnoScanConfig.hiddenNetworkSsid)) {
        WIFI_LOGE("GetHiddenNetworkSsidList failed.\n");
        return false;
    }

    pnoScanConfig.scanInterval = DEFAULT_PNO_SCAN_INTERVAL;
    /* Querying a Scan Policy */
    if (pnoScanIntervalMode.scanIntervalMode.interval > 0) {
        pnoScanConfig.scanInterval = pnoScanIntervalMode.scanIntervalMode.interval;
    }

    pnoScanConfig.minRssi2Dot4Ghz = WifiSettings::GetInstance().GetMinRssi2Dot4Ghz(m_instId);
    pnoScanConfig.minRssi5Ghz = WifiSettings::GetInstance().GetMinRssi5Ghz(m_instId);

    InterScanConfig interConfig;
    interConfig.fullScanFlag = true;
    if (!WifiChannelHelper::GetInstance().GetAvailableScanFreqs(SCAN_BAND_BOTH_WITH_DFS, interConfig.scanFreqs)) {
        WIFI_LOGE("GetBandFreqs failed.\n");
        return false;
    }

    if (!PnoScan(pnoScanConfig, interConfig)) {
        WIFI_LOGE("PnoScan failed.\n");
        return false;
    }
    isPnoScanBegined = true;
    WriteWifiPnoScanHiSysEvent(MODE_STATE_OPEN, 0);

    return true;
}

bool ScanService::PnoScan(const PnoScanConfig &pnoScanConfig, const InterScanConfig &interScanConfig)
{
    WIFI_LOGI("Enter PnoScan.\n");
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("pScanStateMachine is null.\n");
        return false;
    }
    /* Construct a message. */
    InternalMessagePtr interMessage = pScanStateMachine->CreateMessage(CMD_START_PNO_SCAN);
    if (interMessage == nullptr) {
        WIFI_LOGE("CreateMessage failed.\n");
        return false;
    }

    if (!AddPnoScanMessageBody(interMessage, pnoScanConfig)) {
        MessageManage::GetInstance().ReclaimMsg(interMessage);
        WIFI_LOGE("AddPnoScanMessageBody failed.\n");
        return false;
    }

    if (!AddScanMessageBody(interMessage, interScanConfig)) {
        MessageManage::GetInstance().ReclaimMsg(interMessage);
        WIFI_LOGE("AddScanMessageBody failed.\n");
        return false;
    }

    WIFI_LOGI("Begin: send message.");
    pScanStateMachine->SendMessage(interMessage);
    WIFI_LOGI("End: send message.");

    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    pnoScanStartTime =
        static_cast<int64_t>(times.tv_sec) * SECOND_TO_MILLI_SECOND + times.tv_nsec / SECOND_TO_MICRO_SECOND;

    return true;
}

bool ScanService::AddPnoScanMessageBody(InternalMessagePtr interMessage, const PnoScanConfig &pnoScanConfig)
{
    WIFI_LOGI("Enter AddPnoScanMessageBody.\n");

    if (interMessage == nullptr) {
        WIFI_LOGE("interMessage is null.\n");
        return false;
    }

    interMessage->AddIntMessageBody(pnoScanConfig.scanInterval);
    interMessage->AddIntMessageBody(pnoScanConfig.minRssi2Dot4Ghz);
    interMessage->AddIntMessageBody(pnoScanConfig.minRssi5Ghz);

    interMessage->AddIntMessageBody(pnoScanConfig.hiddenNetworkSsid.size());
    auto iter = pnoScanConfig.hiddenNetworkSsid.begin();
    for (; iter != pnoScanConfig.hiddenNetworkSsid.end(); ++iter) {
        interMessage->AddStringMessageBody(*iter);
    }

    interMessage->AddIntMessageBody(pnoScanConfig.savedNetworkSsid.size());
    auto iter2 = pnoScanConfig.savedNetworkSsid.begin();
    for (; iter2 != pnoScanConfig.savedNetworkSsid.end(); ++iter2) {
        interMessage->AddStringMessageBody(*iter2);
    }

    interMessage->AddIntMessageBody(pnoScanConfig.freqs.size());
    auto iter3 = pnoScanConfig.freqs.begin();
    for (; iter3 != pnoScanConfig.freqs.end(); ++iter3) {
        interMessage->AddIntMessageBody(*iter3);
    }

    return true;
}

void ScanService::HandlePnoScanInfo(std::vector<InterScanInfo> &scanInfoList)
{
    WIFI_LOGI("Enter HandlePnoScanInfo.\n");
    InitChipsetInfo();
    std::vector<InterScanInfo> filterScanInfo;
    std::vector<InterScanInfo>::iterator iter = scanInfoList.begin();
    for (; iter != scanInfoList.end(); ++iter) {
        if ((iter->timestamp / SECOND_TO_MILLI_SECOND) > pnoScanStartTime) {
            filterScanInfo.push_back(*iter);
            WIFI_LOGD("InterScanInfo bssid:%{public}s, ssid:%{public}s, capabilities:%{public}s,"
                "frequency:%{public}d, rssi:%{public}d, timestamp:%" PRId64 ".\n",
                MacAnonymize(iter->bssid).c_str(), SsidAnonymize(iter->ssid).c_str(), iter->capabilities.c_str(),
                iter->frequency, iter->rssi, iter->timestamp);
        }
        if (mEnhanceService != nullptr) {
            WifiCategory category = mEnhanceService->GetWifiCategory(iter->infoElems,
                chipsetCategory, chipsetFeatrureCapability);
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->RecordWifiCategory(iter->bssid, category);
        }
    }

    /* Send the scanning result to the module registered for listening. */
    PnoScanInfoHandlerMap::iterator handleIter = pnoScanInfoHandlerMap.begin();
    for (; handleIter != pnoScanInfoHandlerMap.end(); ++handleIter) {
        if (handleIter->second) {
            handleIter->second(filterScanInfo);
        }
    }

    /* send message to main service. */
    ReportScanInfos(filterScanInfo);

    return;
}

void ScanService::EndPnoScan()
{
    WIFI_LOGI("Enter EndPnoScan.\n");

    if (!isPnoScanBegined) {
        return;
    }
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("pScanStateMachine is null.\n");
        return;
    }
    pScanStateMachine->SendMessage(CMD_STOP_PNO_SCAN);
    isPnoScanBegined = false;
    return;
}

void ScanService::HandleScreenStatusChanged()
{
    WIFI_LOGI("Enter HandleScreenStatusChanged.");
    SystemScanProcess(staStatus == static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED));
    SystemSingleScanProcess();
    return;
}

void ScanService::HandleStaStatusChanged(int status)
{
    WIFI_LOGI("Enter HandleStaStatusChanged, change to status: %{public}d.", status);

    staStatus = status;
    switch (staStatus) {
        case static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED): {
            DisconnectedTimerScan();
            SystemScanProcess(true);
            SystemSingleScanProcess();
            break;
        }
        case static_cast<int>(OperateResState::CONNECT_AP_CONNECTED): {
            SystemScanProcess(false);
            SystemSingleScanProcess();
            std::unique_lock<std::mutex> lock(scanConfigMapMutex);
            scanConfigMap.clear();
            break;
        }
        default: {
            StopSystemScan();
        }
    }
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetStaScene(GetStaScene());
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetStaSceneForbidCount(0);
    return;
}

void ScanService::HandleNetworkQualityChanged(int status)
{
    WIFI_LOGI("Enter HandleNetworkQualityChanged, change to status: %{public}d.", status);
    if (lastNetworkQuality == status) {
        return;
    }
    switch (status) {
        case static_cast<int>(OperateResState::CONNECT_NETWORK_DISABLED): {
            SystemScanProcess(true);
            break;
        }
        case static_cast<int>(OperateResState::CONNECT_NETWORK_ENABLED): {
            SystemScanProcess(false);
            break;
        }
        default: {
            break;
        }
    }
    lastNetworkQuality = status;
}

void ScanService::HandleMovingFreezeChanged()
{
    LOGI("Enter HandleMovingFreezeChanged.");
    int freezeState = WifiConfigCenter::GetInstance().GetFreezeModeState();
    /* Moving -> Freeze, set the scanned flag to false. */
    if (!lastFreezeState && freezeState) {
        WIFI_LOGW("set movingFreeze scanned false.");
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetMovingFreezeScaned(false);
    }
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    if (staStatus != static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED) || screenState == MODE_STATE_CLOSE) {
        WIFI_LOGW("Moving change do nothing.");
        return;
    }
        lastFreezeState = freezeState;
    SystemScanProcess(false);
}

void ScanService::HandleCustomStatusChanged(int customScene, int customSceneStatus)
{
    WIFI_LOGI("Enter HandleCustomStatusChanged.");
    WIFI_LOGD("sizeof(time_t):%{public}d", int(sizeof(time_t)));

    time_t now = time(nullptr);
    WIFI_LOGI("customScene:%{public}d, status:%{public}d", customScene, customSceneStatus);
    if (customSceneStatus == MODE_STATE_OPEN) {
        customSceneTimeMap.insert(std::pair<int, int>(customScene, now));
    }
    if (customSceneStatus == MODE_STATE_CLOSE) {
        customSceneTimeMap.erase(customScene);
    }
    SystemScanProcess(false);
    customSceneForbidCount = 0;

    return;
}

void ScanService::HandleGetCustomSceneState(std::map<int, time_t>& sceneMap) const
{
    sceneMap = customSceneTimeMap;
}

void ScanService::HandleAutoConnectStateChanged(bool success)
{
    WIFI_LOGI("Enter HandleAutoConnectStateChanged\n");
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    bool isOutdoorScene = WifiSensorScene::GetInstance().IsOutdoorScene();
    if (staStatus == static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED) && screenState != MODE_STATE_CLOSE &&
        !success && systemScanIntervalMode.scanIntervalMode.count <= 1 && !isOutdoorScene) {
        if (Scan(ScanType::SCAN_TYPE_SYSTEMTIMER) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Scan failed.");
        }
        std::unique_lock<std::mutex> lock(scanControlInfoMutex);
        systemScanIntervalMode.scanIntervalMode.count++;
    }
}

void ScanService::SystemScanProcess(bool scanAtOnce)
{
    WIFI_LOGI("Enter SystemScanProcess, scanAtOnce:%{public}d.", scanAtOnce);
    StopSystemScan();

    int state = WifiConfigCenter::GetInstance().GetScreenState();
    WIFI_LOGI("Screen state(1:OPEN, 2:CLOSE): %{public}d.", state);
    if (state == MODE_STATE_OPEN || state == MODE_STATE_DEFAULT) {
        {
            std::unique_lock<std::mutex> lock(scanControlInfoMutex);
            int i = 0;
            for (auto iter = scanControlInfo.scanIntervalList.begin(); iter != scanControlInfo.scanIntervalList.end();
                ++iter) {
                if (iter->scanScene == SCAN_SCENE_ALL && iter->scanMode == ScanMode::SYSTEM_TIMER_SCAN &&
                    iter->isSingle == false) {
                    WIFI_LOGI("iter[%{public}d]: intervalMode:%{public}d, interval:%{public}d, count:%{public}d",
                        i++, iter->intervalMode, iter->interval, iter->count);
                    systemScanIntervalMode.scanIntervalMode.intervalMode = iter->intervalMode;
                    systemScanIntervalMode.scanIntervalMode.interval = iter->interval;
                    systemScanIntervalMode.scanIntervalMode.count = iter->count;
                    systemScanIntervalMode.expScanCount = 0;
                }
            }
        }
        StartSystemTimerScan(scanAtOnce);
    } else {
        if (!BeginPnoScan()) {
            WIFI_LOGE("BeginPnoScan failed.");
            return;
        }
    }

    return;
}

void ScanService::ResetSingleScanCountAndMessage()
{
    currSingleScanCount = 0;
    pScanStateMachine->StopTimer(static_cast<int>(SYSTEM_SINGLE_SCAN_TIMER));
}

void ScanService::AddSingleScanCountAndMessage(int delaySeconds)
{
    currSingleScanCount++;
    pScanStateMachine->StopTimer(static_cast<int>(SYSTEM_SINGLE_SCAN_TIMER));
    pScanStateMachine->StartTimer(static_cast<int>(SYSTEM_SINGLE_SCAN_TIMER), delaySeconds * SECOND_TO_MILLI_SECOND);
}

void ScanService::SystemSingleScanProcess()
{
    int scanStyle = SCAN_DEFAULT_TYPE;
    if (AllowScanByType(ScanType::SCAN_TYPE_SINGLE_SCAN_TIMER, scanStyle) == WIFI_OPT_SUCCESS) {
        WIFI_LOGI("%{public}s : allowSingleScan success.", __FUNCTION__);
        StartSingleScanWithoutControlTimer(scanStyle);
    }
}

void ScanService::GetRelatedFreqs(int &lastStaFreq, int &p2pFreq, int &p2pEnhanceFreq)
{
    WifiP2pGroupInfo currentP2pGroupInfo = WifiConfigCenter::GetInstance().GetCurrentP2pGroupInfo();
    p2pFreq = currentP2pGroupInfo.GetFrequency();
    p2pEnhanceFreq = WifiConfigCenter::GetInstance().GetP2pEnhanceFreq();
    lastStaFreq = WifiConfigCenter::GetInstance().GetLastConnStaFreq();
}

void ScanService::StartSingleScanWithoutControlTimer(int scanStyle)
{
    int lastStaFreq = 0;
    int p2pFreq = 0;
    int p2pEnhanceFreq = 0;
    GetRelatedFreqs(lastStaFreq, p2pFreq, p2pEnhanceFreq);
    WIFI_LOGI("%{public}s : lastStaFreq = %{public}d, p2pFreq = %{public}d, p2pEnhanceFreq = %{public}d."
        "currSingleScanCount = %{public}d",
        __FUNCTION__, lastStaFreq, p2pFreq, p2pEnhanceFreq, currSingleScanCount.load());
 
    if (AllowScanByType(ScanType::SCAN_TYPE_SINGLE_SCAN_TIMER, scanStyle) == WIFI_OPT_FAILED) {
        WIFI_LOGE("%{public}s : not allow single scan, clear timer and currSingleScanCount.", __FUNCTION__);
        ResetSingleScanCountAndMessage();
        return;
    }
 
    SelectTheFreqToSingleScan(lastStaFreq, p2pFreq, p2pEnhanceFreq, scanStyle);
}
 
void ScanService::SelectTheFreqToSingleScan(const int lastStaFreq, const int p2pFreq,
    const int p2pEnhanceFreq, int scanStyle)
{
    if (WifiChannelHelper::GetInstance().IsValidFreq(p2pFreq) &&
        currSingleScanCount.load() == SCAN_P2P_BEFORE_ALL_FREQ_SCAN) {
        /* scan p2pFreq first */
        StartSingleScanWithoutControl(p2pFreq, scanStyle);
        AddSingleScanCountAndMessage(DELAY_FIVE_SECONDS);
    } else if (WifiChannelHelper::GetInstance().IsValidFreq(p2pEnhanceFreq) &&
        (p2pFreq != p2pEnhanceFreq) && currSingleScanCount.load() == SCAN_P2PENHANCE_BEFORE_ALL_FREQ_SCAN) {
        /* scan p2pEnhanceFreq second if (p2pFreq != p2pEnhanceFreq) */
        StartSingleScanWithoutControl(p2pEnhanceFreq, scanStyle);
        AddSingleScanCountAndMessage(DELAY_FIVE_SECONDS);
    } else if (WifiChannelHelper::GetInstance().IsValidFreq(lastStaFreq) &&
        currSingleScanCount.load() == SCAN_STA_BEFORE_ALL_FREQ_SCAN) {
        /* scan lastStaFreq second third */
        StartSingleScanWithoutControl(lastStaFreq, scanStyle);
        AddSingleScanCountAndMessage(DELAY_FIVE_SECONDS);
    } else if (currSingleScanCount.load() > SCAN_STA_BEFORE_ALL_FREQ_SCAN) {
        /* scan all freqs in a single scan way */
        std::vector<int32_t> freqs;
        if (WifiChannelHelper::GetInstance().GetAvailableScanFreqs(SCAN_BAND_BOTH, freqs)) {
            WIFI_LOGI("%{public}s : get all freq fail.", __FUNCTION__);
        }
        if (currSingleScanCount.load() - SCAN_STA_BEFORE_ALL_FREQ_SCAN < static_cast<int>(freqs.size())) {
            StartSingleScanWithoutControl(freqs[currSingleScanCount.load() - SCAN_STA_BEFORE_ALL_FREQ_SCAN], scanStyle);
            AddSingleScanCountAndMessage(DELAY_ONE_SECOND);
        } else {
           WIFI_LOGI("%{public}s : all single scan done, clear timer and currSingleScanCount.", __FUNCTION__);
           ResetSingleScanCountAndMessage();
        }
    } else {
        /* lastStaFreq or p2pFreq or p2pEnhance is not valid, just add currSingleScanCount and try next single scan */
        AddSingleScanCountAndMessage(0);
    }
}

void ScanService::StartSingleScanWithoutControl(int freq, int scanStyle)
{
    WIFI_LOGI("enter StartSingleScanWithoutControl, freq:%{public}d, scanStyle:%{public}d", freq, scanStyle);
    WifiScanParams params;
    if (!scanStartedFlag) {
        WIFI_LOGE("%{public}s scan service has not started.", __FUNCTION__);
        return;
    }
 
    params.ssid = "";
    params.bssid = "";
    params.band = SCAN_BAND_UNSPECIFIED;
    params.freqs.push_back(freq);
 
    ScanConfig scanConfig;
    if (scanStyle != SCAN_TYPE_LOW_PRIORITY) {
        if (!GetHiddenNetworkSsidList(scanConfig.hiddenNetworkSsid)) {
            WIFI_LOGE("GetHiddenNetworkSsidList failed.\n");
        }
    }
    scanConfig.scanBand = static_cast<ScanBandType>(params.band);
    scanConfig.scanFreqs.assign(params.freqs.begin(), params.freqs.end());
    scanConfig.ssid = params.ssid;
    scanConfig.bssid = params.bssid;
    scanConfig.scanType = ScanType::SCAN_TYPE_SINGLE_SCAN_TIMER;
    scanConfig.scanningWithParamFlag = true;
    scanConfig.scanStyle = scanStyle;
    if (!SingleScan(scanConfig)) {
        WIFI_LOGE("SingleScan failed.\n");
        return;
    }
    return;
}

void ScanService::StopSystemScan()
{
    WIFI_LOGI("Enter StopSystemScan.");
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("pScanStateMachine is null.\n");
        return;
    }
    pScanStateMachine->StopTimer(static_cast<int>(SYSTEM_SCAN_TIMER));
    pScanStateMachine->StopTimer(static_cast<int>(RESTART_SYSTEM_SCAN_TIMER));
    EndPnoScan();
    pnoScanFailedNum = 0;
    systemScanFailedNum = 0;
    pScanStateMachine->StopTimer(static_cast<int>(RESTART_PNO_SCAN_TIMER));
    return;
}

void ScanService::StartSystemTimerScan(bool scanAtOnce)
{
    WIFI_LOGI("Enter StartSystemTimerScan, scanAtOnce: %{public}d.", scanAtOnce);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanType(ScanType::SCAN_TYPE_SYSTEMTIMER);
    int scanStyle = SCAN_DEFAULT_TYPE;
    ErrCode rlt = AllowScanByType(ScanType::SCAN_TYPE_SYSTEMTIMER, scanStyle);
    if (rlt == WIFI_OPT_FAILED) {
        return;
    }
    int scanTime = SYSTEM_SCAN_INIT_TIME;
    if (systemScanIntervalMode.scanIntervalMode.interval > 0) {
        scanTime = systemScanIntervalMode.scanIntervalMode.interval;
    }
    if (rlt == WIFI_OPT_SUCCESS) {
        struct timespec times = { 0, 0 };
        clock_gettime(CLOCK_BOOTTIME, &times);
        int64_t nowTime =
            static_cast<int64_t>(times.tv_sec) * SECOND_TO_MILLI_SECOND + times.tv_nsec / SECOND_TO_MICRO_SECOND;
        int sinceLastScan = 0;
        if (lastSystemScanTime != 0) {
            sinceLastScan = nowTime - lastSystemScanTime;
        }

        /*
        * The scan is performed immediately, the first scan is required,
        * or the time since the last scan is longer than the scan interval.
        */
        if (scanAtOnce || (lastSystemScanTime == 0) ||
            (sinceLastScan / SECOND_TO_MILLI_SECOND >= systemScanIntervalMode.scanIntervalMode.interval)) {
            if (Scan(ScanType::SCAN_TYPE_SYSTEMTIMER) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("Scan failed.");
            }
            lastSystemScanTime = nowTime;
        } else {
            scanTime = systemScanIntervalMode.scanIntervalMode.interval - sinceLastScan / SECOND_TO_MILLI_SECOND;
        }
    }
    WIFI_LOGI("StartSystemTimerScan, scanTime: %{public}d,  interval:%{public}d,  count:%{public}d",
        scanTime,
        systemScanIntervalMode.scanIntervalMode.interval,
        systemScanIntervalMode.scanIntervalMode.count);
    pScanStateMachine->StartTimer(static_cast<int>(SYSTEM_SCAN_TIMER), scanTime * SECOND_TO_MILLI_SECOND);

    return;
}

void ScanService::HandleSystemScanTimeout()
{
    StartSystemTimerScan(true);
    return;
}

void ScanService::DisconnectedTimerScan()
{
    WIFI_LOGI("Enter DisconnectedTimerScan.\n");
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("pScanStateMachine is null.\n");
        return;
    }
    if (WifiConfigCenter::GetInstance().GetWifiState(m_instId) != static_cast<int>(WifiState::ENABLED)) {
        return;
    }
    pScanStateMachine->StopTimer(static_cast<int>(DISCONNECTED_SCAN_TIMER));
    pScanStateMachine->StartTimer(static_cast<int>(DISCONNECTED_SCAN_TIMER), DISCONNECTED_SCAN_INTERVAL);
    return;
}

void ScanService::HandleDisconnectedScanTimeout()
{
    WIFI_LOGI("Enter HandleDisconnectedScanTimeout.\n");

    if (WifiConfigCenter::GetInstance().GetWifiState(m_instId) != static_cast<int>(WifiState::ENABLED)) {
        return;
    }
    if (staStatus != static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)) {
        return;
    }
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("pScanStateMachine is null.\n");
        return;
    }
    if (Scan(ScanType::SCAN_TYPE_SYSTEMTIMER) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Scan failed.");
    }
    pScanStateMachine->StopTimer(static_cast<int>(DISCONNECTED_SCAN_TIMER));
    pScanStateMachine->StartTimer(static_cast<int>(DISCONNECTED_SCAN_TIMER), DISCONNECTED_SCAN_INTERVAL);

    return;
}

void ScanService::RestartPnoScanTimeOut()
{
    WIFI_LOGI("Enter RestartPnoScanTimeOut.\n");
    pnoScanFailedNum++;
    if (pnoScanFailedNum > MAX_PNO_SCAN_FAILED_NUM) {
        WIFI_LOGE("Over max pno failed number.");
        return;
    }

    if (!BeginPnoScan()) {
        WIFI_LOGE("BeginPnoScan failed.");
        return;
    }

    return;
}

void ScanService::RestartSystemScanTimeOut()
{
    WIFI_LOGI("Enter RestartSystemScanTimeOut.\n");
    if (Scan(ScanType::SCAN_TYPE_SYSTEMTIMER) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("RestartSystemScanTimeOut failed.");
    }
}

void ScanService::HandleSystemSingleScanTimeOut()
{
    StartSingleScanWithoutControlTimer();
}

void ScanService::RestartCommonScanAfterLpScanFailed()
{
    WIFI_LOGI("Enter RestartCommonScanAfterLpScanFailed.\n");
    if (Scan(ScanType::SCAN_DEFAULT) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("RestartCommonScan failed.");
    }
}

void ScanService::GetScanControlInfo()
{
    WIFI_LOGI("Enter GetScanControlInfo.\n");

    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    if (WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanControlInfo(scanControlInfo) != 0) {
        WIFI_LOGE("GetScanControlInfo failed");
    }
    std::map<std::string, std::vector<PackageInfo>> packageInfoMap;
    if (WifiSettings::GetInstance().GetPackageInfoMap(packageInfoMap) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetPackageInfoMap failed");
    }
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetPackageInfo(packageInfoMap);
    scan_thermal_trust_list = packageInfoMap["scan_thermal_filter"];
    scan_frequency_trust_list = packageInfoMap["scan_frequency_filter"];
    scan_screen_off_trust_list = packageInfoMap["scan_screen_off_filter"];
    scan_gps_block_list = packageInfoMap["scan_gps_filter"];
    scan_hid2d_list = packageInfoMap["scan_hid2d_filter"];
    return;
}

ErrCode ScanService::AllowExternScan(ScanType scanType, int &scanStyle)
{
    WIFI_LOGI("Enter AllowExternScan SUPPORT_SCAN_CONTROL.\n");
    int appId = 0;
#ifndef OHOS_ARCH_LITE
    appId = GetCallingUid();
#endif
    ScanMode scanMode = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetAppRunningState();
    WIFI_LOGI("AllowExternScan, scanMode is %{public}d", (int)scanMode);
    if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE) {
        WIFI_LOGI("Enter AllowExternScan FactoryMode, extern scan has allowed.");
        return WIFI_OPT_SUCCESS;
    }

    if (!AllowExternScanByIntervalMode(appId, SCAN_SCENE_FREQUENCY_ORIGIN, scanMode)) {
        WIFI_LOGW("extern scan not allow by origin interval mode");
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::INTERVAL);
        return WIFI_OPT_FAILED;
    }

    if (!AllowScanByDisableScanCtrl()) {
        WIFI_LOGW("extern scan not allow by disable scan control.");
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::SCAN_DISABLE);
        return WIFI_OPT_FAILED;
    }

    if (!AllowScanByGameScene(scanType, scanStyle)) {
        WIFI_LOGW("extern scan not allow by gamescene scan control.");
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::GAME_SCENE);
        return WIFI_OPT_FAILED;
    }

    WIFI_LOGI("extern scan has allowed");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowSystemTimerScan(ScanType scanType, int &scanStyle)
{
    WIFI_LOGI("Enter AllowSystemTimerScan.\n");
    if (scanStyle == SCAN_TYPE_LOW_PRIORITY) {
        WIFI_LOGW("Not allow LP scan in system timer scan");
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::LP_SCANSTYLE));
        return WIFI_OPT_FAILED;
    }
    if (GetDeviceType() == ProductDeviceType::GLASSES) {
        return WIFI_OPT_FAILED;
    }
    if (WifiConfigCenter::GetInstance().GetWifiState(m_instId) != static_cast<int>(WifiState::ENABLED)) {
        WIFI_LOGW("system timer scan not allow when wifi disable");
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::WIFI_DISABLE));
        return WIFI_OPT_FAILED;
    }
    if (!AllowScanByDisableScanCtrl()) {
        WIFI_LOGW("system timer scan not allow by disable scan control.");
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::SCAN_DISABLE));
        return WIFI_OPT_FAILED;
    }
    if (!AllowScanByGameScene(scanType, scanStyle)) {
        WIFI_LOGW("system timer scan not allow by gamescene scan control.");
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::GAME_SCENE));
        return WIFI_OPT_FAILED;
    }
    /* The network is connected and cannot be automatically switched. */
    autoNetworkSelection = WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover(m_instId);
    if ((staStatus == static_cast<int>(OperateResState::CONNECT_AP_CONNECTED)) && (!autoNetworkSelection)) {
        WIFI_LOGW("system timer scan not allowed for CONNECT_AP_CONNECTED");
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::CANNOT_SWITCH_AP));
        return WIFI_OPT_FAILED;
    }

    if (staStatus != static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED) &&
        staStatus != static_cast<int>(OperateResState::CONNECT_AP_CONNECTED)) {
        WIFI_LOGW("system timer scan not allowed for staStatus: %{public}d.", staStatus);
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::STA_STATE));
        return WIFI_OPT_SCAN_NEXT_PERIOD;
    }

    return AllowSystemTimerScanExtra(scanType, scanStyle);
}
 
ErrCode ScanService::AllowSystemTimerScanExtra(ScanType scanType, int &scanStyle)
{
    int staScene = GetStaScene();
    /* Determines whether to allow scanning based on the STA status. */
    if (staScene == SCAN_SCENE_MAX) {
        WIFI_LOGW("system timer scan not allowed for invalid staScene: %{public}d", staScene);
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::STA_STATE));
        return WIFI_OPT_SCAN_NEXT_PERIOD;
    }

    if (!AllowScanByHid2dState(scanType, scanStyle)) {
        WIFI_LOGW("system timer scan not allow by hid2d state");
        return WIFI_OPT_SCAN_NEXT_PERIOD;
    }

    if (!AllowScanByActionListen()) {
        WIFI_LOGW("system timer scan not allow by ActionListen condition");
        return WIFI_OPT_SCAN_NEXT_PERIOD;
    }

    if (!AllowScanDuringStaScene(staScene, ScanMode::SYSTEM_TIMER_SCAN)) {
        WIFI_LOGW("system timer scan not allowed, staScene: %{public}d", staScene);
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::DURING_STA));
        return WIFI_OPT_SCAN_NEXT_PERIOD;
    }

    if (!AllowScanDuringCustomScene(ScanMode::SYSTEM_TIMER_SCAN)) {
        WIFI_LOGW("system timer scan not allowed");
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::CUSTOM_SCENE));
        return WIFI_OPT_SCAN_NEXT_PERIOD;
    }

#ifdef SUPPORT_SCAN_CONTROL
    SystemScanByInterval(staScene, systemScanIntervalMode.scanIntervalMode.interval,
        systemScanIntervalMode.scanIntervalMode.count);
#else
    if (!AllowScanByMovingFreeze(ScanMode::SYSTEM_TIMER_SCAN)) {
        WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::MOVING_FREEZE));
        return WIFI_OPT_MOVING_FREEZE_CTRL;
    }

    {
        std::unique_lock<std::mutex> lock(scanControlInfoMutex);
        for (auto iter = scanControlInfo.scanIntervalList.begin(); iter != scanControlInfo.scanIntervalList.end();
            ++iter) {
            if (iter->scanScene == SCAN_SCENE_ALL && iter->scanMode == ScanMode::SYSTEM_TIMER_SCAN &&
                iter->isSingle == false) {
                if (!SystemScanByInterval(systemScanIntervalMode.expScanCount,
                    systemScanIntervalMode.scanIntervalMode.interval, systemScanIntervalMode.scanIntervalMode.count)) {
                    WriteScanLimitHiSysEvent("SYSTEM_SCAN", static_cast<int>(ScanLimitType::INTERVAL));
                    return WIFI_OPT_FAILED;
                }
            }
        }
    }
#endif
    WIFI_LOGI("allow system timer scan");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowPnoScan(ScanType scanType, int &scanStyle)
{
    WIFI_LOGD("Enter AllowPnoScan.\n");
    if (scanStyle == SCAN_TYPE_LOW_PRIORITY) {
        WIFI_LOGW("Not allow LP scan in PNO");
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::LP_SCANSTYLE));
        return WIFI_OPT_FAILED;
    }
    if (GetDeviceType() == ProductDeviceType::GLASSES) {
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::GLASSES_SCENE));
        return WIFI_OPT_FAILED;
    }
    if (WifiConfigCenter::GetInstance().GetWifiState(m_instId) != static_cast<int>(WifiState::ENABLED)) {
        WIFI_LOGW("pnoScan not allow when wifi disable");
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::WIFI_DISABLE));
        return WIFI_OPT_FAILED;
    }
    if (staStatus != static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)) {
        WIFI_LOGE("NOT allow PNO scan for staStatus: %{public}d", staStatus);
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::STA_STATE));
        return WIFI_OPT_FAILED;
    }

    if (!AllowScanByHid2dState(scanType, scanStyle)) {
        WIFI_LOGW("pnoScan scan not allow by hid2d state");
        return WIFI_OPT_FAILED;
    }
    int staScene = GetStaScene();
    if (staScene == SCAN_SCENE_MAX) {
        WIFI_LOGE("NOT allow PNO scan for staScene: %{public}d", staScene);
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::STA_STATE));
        return WIFI_OPT_FAILED;
    }
    if (!AllowScanDuringStaScene(staScene, ScanMode::PNO_SCAN)) {
        WIFI_LOGW("pnoScan is not allowed for forbid map, staScene is %{public}d", staScene);
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::DURING_STA));
        return WIFI_OPT_FAILED;
    }
    if (!AllowScanDuringCustomScene(ScanMode::PNO_SCAN)) {
        WIFI_LOGD("pnoScan is not allowed for forbid map");
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::CUSTOM_SCENE));
        return WIFI_OPT_FAILED;
    }

#ifndef SUPPORT_SCAN_CONTROL
    {
        std::unique_lock<std::mutex> lock(scanControlInfoMutex);
        for (auto iter = scanControlInfo.scanIntervalList.begin(); iter != scanControlInfo.scanIntervalList.end();
            ++iter) {
            if (iter->scanScene == SCAN_SCENE_ALL && iter->scanMode == ScanMode::PNO_SCAN && iter->isSingle == false) {
                pnoScanIntervalMode.scanIntervalMode.intervalMode = iter->intervalMode;
                pnoScanIntervalMode.scanIntervalMode.interval = iter->interval;
                pnoScanIntervalMode.scanIntervalMode.count = iter->count;
                if (!PnoScanByInterval(pnoScanIntervalMode.fixedScanCount, pnoScanIntervalMode.fixedCurrentTime,
                    pnoScanIntervalMode.scanIntervalMode.interval, pnoScanIntervalMode.scanIntervalMode.count)) {
                    WIFI_LOGW("pnoScan is not allowed for interval mode");
                    WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::INTERVAL));
                    return WIFI_OPT_FAILED;
                }
            }
        }
    }
#endif

    if (!AllowScanByDisableScanCtrl()) {
        WIFI_LOGW("pnoScan not allow by disable scan control.");
        WriteScanLimitHiSysEvent("PNO_SCAN", static_cast<int>(ScanLimitType::SCAN_DISABLE));
        return WIFI_OPT_FAILED;
    }

    WIFI_LOGI("pno scan is allowed");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowWifiProScan(ScanType scanType, int &scanStyle)
{
    if (GetDeviceType() == ProductDeviceType::GLASSES) {
        return WIFI_OPT_FAILED;
    }

    if (!AllowScanByHid2dState(scanType, scanStyle)) {
        WIFI_LOGW("internal scan not allow by hid2d state");
        return WIFI_OPT_FAILED;
    }

    if (!AllowScanByActionListen()) {
        WIFI_LOGW("internal scan not allow by ActionListen condition");
        return WIFI_OPT_FAILED;
    }

    int state = WifiConfigCenter::GetInstance().GetScreenState();
    if (state == MODE_STATE_CLOSE) {
        WIFI_LOGW("internal scan not allow by Screen Off");
        WriteScanLimitHiSysEvent("WIFIPRO_SCAN", static_cast<int>(ScanLimitType::SCREEN_OFF));
        return WIFI_OPT_FAILED;
    }

    if (staStatus != static_cast<int>(OperateResState::CONNECT_AP_CONNECTED)) {
        WIFI_LOGW("NOT allow scan for staStatus: %{public}d", staStatus);
        WriteScanLimitHiSysEvent("WIFIPRO_SCAN", static_cast<int>(ScanLimitType::STA_STATE));
        return WIFI_OPT_FAILED;
    }

    return WIFI_OPT_SUCCESS;
}
 
ErrCode ScanService::Allow5GApScan(ScanType scanType, int &scanStyle)
{
    if (GetDeviceType() == ProductDeviceType::GLASSES) {
        return WIFI_OPT_FAILED;
    }

    if (AllowWifiProScan(scanType, scanStyle) == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }

    // game optimization going
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowSystemSingleScan(ScanType scanType, int &scanStyle)
{
    if (GetDeviceType() == ProductDeviceType::GLASSES) {
        return WIFI_OPT_FAILED;
    }
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    if (screenState != MODE_STATE_OPEN) {
        return WIFI_OPT_FAILED;
    }
    if (staStatus != static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)) {
        return WIFI_OPT_FAILED;
    }
    Hid2dUpperScene shareScene;
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SHARE_SERVICE_UID, shareScene);
    if ((shareScene.scene & 0x01) > 0) {
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::HID2D_CLONE);
        return WIFI_OPT_FAILED;
    }
    // single scan requires controled by Hid2d or ActionListen
    if (AllowScanByHid2dState(scanType, scanStyle) && AllowScanByActionListen()) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowScanByType(ScanType scanType, int &scanStyle)
{
    ErrCode allScanResult = WIFI_OPT_SUCCESS;
    switch (scanType) {
        case ScanType::SCAN_TYPE_EXTERN:
            allScanResult = AllowExternScan(scanType, scanStyle);
            break;
        case ScanType::SCAN_TYPE_SYSTEMTIMER:
            allScanResult = AllowSystemTimerScan(scanType, scanStyle);
            break;
        case ScanType::SCAN_TYPE_PNO:
            allScanResult = AllowPnoScan(scanType, scanStyle);
            break;
        case ScanType::SCAN_TYPE_WIFIPRO:
            allScanResult = AllowWifiProScan(scanType, scanStyle);
            break;
        case ScanType::SCAN_TYPE_5G_AP:
            allScanResult = Allow5GApScan(scanType, scanStyle);
            break;
        case ScanType::SCAN_TYPE_SINGLE_SCAN_TIMER:
            allScanResult = AllowSystemSingleScan(scanType, scanStyle);
            break;
        default:
            LOGE("scanType error.\n");
            break;
    }

    WIFI_LOGI("AllowScanByType, scanType:%{public}d, scanStyle:%{public}d, allScanResult:%{public}d",
        scanType, scanStyle, static_cast<int>(allScanResult));
    return allScanResult;
}

void ScanService::SetScanTrustMode()
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    scanTrustMode = true;
}

void ScanService::ResetToNonTrustMode()
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    scanTrustMode = false;
}

bool ScanService::IsScanTrustMode() const
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    return scanTrustMode;
}

void ScanService::AddScanTrustSceneId(int sceneId)
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    scanTrustSceneIds.emplace(sceneId);
}

void ScanService::ClearScanTrustSceneIds()
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    scanTrustSceneIds.clear();
}

bool ScanService::IsInScanTrust(int sceneId) const
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    if (scanTrustSceneIds.find(sceneId) != scanTrustSceneIds.end()) {
        return true;
    }

    return false;
}

bool ScanService::IsMovingFreezeState(ScanMode appRunMode) const
{
    int freezeState = WifiConfigCenter::GetInstance().GetFreezeModeState();
    int noChargerPlugModeState = WifiConfigCenter::GetInstance().GetNoChargerPlugModeState();
    if (appRunMode == ScanMode::APP_BACKGROUND_SCAN || appRunMode == ScanMode::SYS_BACKGROUND_SCAN) {
        return freezeState == MODE_STATE_OPEN && noChargerPlugModeState == MODE_STATE_OPEN;
    } else if (appRunMode == ScanMode::SYSTEM_TIMER_SCAN || appRunMode == ScanMode::PNO_SCAN) {
        return freezeState == MODE_STATE_OPEN;
    } else {
        return false;
    }
}

bool ScanService::IsMovingFreezeScaned() const
{
    return WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetMovingFreezeScaned();
}

ErrCode ScanService::ApplyTrustListPolicy(ScanType scanType)
{
    LOGE("Enter ApplyTrustListPolicy.");
    ErrCode policyResult = WIFI_OPT_SUCCESS;

    SetScanTrustMode();
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanType(scanType);
    int scanStyle = SCAN_DEFAULT_TYPE;
    policyResult = AllowScanByType(scanType, scanStyle);
    if (policyResult != WIFI_OPT_SUCCESS) {
        WIFI_LOGW("AllowScanByType failed.");
    }
    ResetToNonTrustMode();
    WIFI_LOGI("apply trust list policy, ErrCode=%{public}d", static_cast<int>(policyResult));

    return policyResult;
}

int ScanService::GetStaScene()
{
    WIFI_LOGD("Enter GetStaScene.\n");

    switch (staStatus) {
        case static_cast<int>(OperateResState::CONNECT_AP_CONNECTED):
            return SCAN_SCENE_CONNECTED;

        case static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED):
            return SCAN_SCENE_DISCONNCTED;

        case static_cast<int>(OperateResState::CONNECT_CONNECTING):
            return SCAN_SCENE_CONNECTING;

        case static_cast<int>(OperateResState::CONNECT_OBTAINING_IP):
            return SCAN_SCENE_OBTAINING_IP;

        case static_cast<int>(OperateResState::CONNECT_ASSOCIATING):
            return SCAN_SCENE_ASSOCIATING;

        case static_cast<int>(OperateResState::CONNECT_ASSOCIATED):
            return SCAN_SCENE_ASSOCIATED;

        default:
            return SCAN_SCENE_MAX;
    }
}

bool ScanService::IsExternScanning() const
{
    WIFI_LOGI("Enter IsExternScanning.\n");

    std::unique_lock<std::mutex> lock(scanConfigMapMutex);
    for (auto iter = scanConfigMap.begin(); iter != scanConfigMap.end(); ++iter) {
        if (iter->second.scanType != ScanType::SCAN_TYPE_SYSTEMTIMER) {
            return true;
        }
    }
    return false;
}

bool ScanService::IsScanningWithParam()
{
    WIFI_LOGI("Enter IsScanningWithParam.\n");

    std::unique_lock<std::mutex> lock(scanConfigMapMutex);
    for (auto iter = scanConfigMap.begin(); iter != scanConfigMap.end(); ++iter) {
        if (iter->second.scanningWithParamFlag) {
            return true;
        }
    }
    return false;
}

void ScanService::GetAllowBandFreqsControlInfo(ScanBandType &scanBand, std::vector<int> &freqs)
{
    WIFI_LOGI("Enter GetAllowBandFreqsControlInfo.\n");

    int staScene = GetStaScene();

    bool allow24Ghz = true;
    bool allow5Ghz = true;
    if (!AllowScanDuringStaScene(staScene, ScanMode::BAND_24GHZ_SCAN)) {
        allow24Ghz = false;
    }
    if (!AllowScanDuringStaScene(staScene, ScanMode::BAND_5GHZ_SCAN)) {
        allow5Ghz = false;
    }
    if (!AllowScanDuringCustomScene(ScanMode::BAND_24GHZ_SCAN)) {
        allow24Ghz = false;
    }
    if (!AllowScanDuringCustomScene(ScanMode::BAND_5GHZ_SCAN)) {
        allow5Ghz = false;
    }

    {
        std::unique_lock<std::mutex> lock(scanControlInfoMutex);
        for (auto iter = scanControlInfo.scanForbidList.begin(); iter != scanControlInfo.scanForbidList.end(); ++iter) {
            if (iter->scanScene == SCAN_SCENE_ALL) {
                if (iter->scanMode == ScanMode::BAND_24GHZ_SCAN) {
                    allow24Ghz = false;
                }
                if (iter->scanMode == ScanMode::BAND_5GHZ_SCAN) {
                    allow5Ghz = false;
                }
            }
        }
    }

    if ((!allow24Ghz) && (!allow5Ghz)) {
        WIFI_LOGE("Both 2.4G and 5G are not allowed");
        scanBand = SCAN_BAND_UNSPECIFIED;
        freqs.clear();
        return;
    }

    if (!allow24Ghz) {
        scanBand = ConvertBandNotAllow24G(scanBand);
        Delete24GhzFreqs(freqs);
    }

    if (!allow5Ghz) {
        scanBand = ConvertBandNotAllow5G(scanBand);
        Delete5GhzFreqs(freqs);
    }

    return;
}

ScanBandType ScanService::ConvertBandNotAllow24G(ScanBandType scanBand)
{
    WIFI_LOGI("Enter ConvertBandNotAllow24G.\n");

    switch (scanBand) {
        case SCAN_BAND_24_GHZ:
            return SCAN_BAND_UNSPECIFIED;

        case SCAN_BAND_5_GHZ:
        case SCAN_BAND_5_GHZ_DFS_ONLY:
        case SCAN_BAND_5_GHZ_WITH_DFS:
            return scanBand;

        case SCAN_BAND_BOTH:
            return SCAN_BAND_5_GHZ;

        case SCAN_BAND_BOTH_WITH_DFS:
            return SCAN_BAND_5_GHZ_WITH_DFS;

        default:
            return SCAN_BAND_UNSPECIFIED;
    }
}

ScanBandType ScanService::ConvertBandNotAllow5G(ScanBandType scanBand)
{
    WIFI_LOGI("Enter ConvertBandNotAllow5G.\n");

    switch (scanBand) {
        case SCAN_BAND_24_GHZ:
        case SCAN_BAND_BOTH:
        case SCAN_BAND_BOTH_WITH_DFS:
            return SCAN_BAND_24_GHZ;

        case SCAN_BAND_5_GHZ:
        case SCAN_BAND_5_GHZ_DFS_ONLY:
        case SCAN_BAND_5_GHZ_WITH_DFS:
        default:
            return SCAN_BAND_UNSPECIFIED;
    }
}

void ScanService::Delete24GhzFreqs(std::vector<int> &freqs)
{
    WIFI_LOGI("Enter Delete24GhzFreqs.\n");

    auto iter = freqs.begin();
    while (iter != freqs.end()) {
        if (*iter < FREQS_24G_MAX_VALUE) {
            iter = freqs.erase(iter);
        } else {
            ++iter;
        }
    }

    return;
}

void ScanService::Delete5GhzFreqs(std::vector<int> &freqs)
{
    WIFI_LOGI("Enter Delete24GhzFreqs.\n");

    auto iter = freqs.begin();
    while (iter != freqs.end()) {
        if (*iter > FREQS_5G_MIN_VALUE) {
            iter = freqs.erase(iter);
        } else {
            ++iter;
        }
    }

    return;
}

void ScanService::GetSavedNetworkFreq(std::vector<int> &scanFreqs)
{
    std::vector<WifiDeviceConfig> deviceConfigs;
    std::vector<int32_t> availableFreqs;

    if (WifiSettings::GetInstance().GetDeviceConfig(deviceConfigs) != 0) {
        WIFI_LOGE("GetDeviceConfig failed");
        return;
    }
    if (!WifiChannelHelper::GetInstance().GetAvailableScanFreqs(ScanBandType::SCAN_BAND_BOTH_WITH_DFS,
        availableFreqs)) {
        WIFI_LOGE("GetAvailableScanFreqs failed");
        return;
    }
    for (auto dev : deviceConfigs) {
        if (std::find(scanFreqs.begin(), scanFreqs.end(), dev.frequency) == scanFreqs.end() &&
            std::find(availableFreqs.begin(), availableFreqs.end(), dev.frequency) != availableFreqs.end()) {
            scanFreqs.push_back(dev.frequency);
        }
    }
}

void ScanService::CheckNeedFastScan(std::vector<int> &scanFreqs)
{
    if (GetDeviceType() != ProductDeviceType::WEARABLE && GetDeviceType() != ProductDeviceType::TV) {
        WIFI_LOGD("Not wearable or tv device, do not fast scan");
        return;
    }
    /* If scan freqs is empty, the freq for the first periodic scanning is selected based on
     * the historical connection freq.
    */
    if (systemScanIntervalMode.scanIntervalMode.count == 1 && scanFreqs.empty() == 0 &&
        WifiConfigCenter::GetInstance().IsNeedFastScan()) {
        WifiConfigCenter::GetInstance().SetFastScan(false);
        GetSavedNetworkFreq(scanFreqs);
    }
}

bool ScanService::GetSavedNetworkSsidList(std::vector<std::string> &savedNetworkSsid)
{
    WIFI_LOGI("Enter GetSavedNetworkSsidList.\n");

    std::vector<WifiDeviceConfig> deviceConfigs;
    if (WifiSettings::GetInstance().GetDeviceConfig(deviceConfigs) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetDeviceConfig failed");
        return false;
    }
    std::sort(deviceConfigs.begin(), deviceConfigs.end(), [](WifiDeviceConfig deviceA, WifiDeviceConfig deviceB) {
        return deviceA.lastConnectTime > deviceB.lastConnectTime;
    });
    for (auto iter = deviceConfigs.begin(); iter != deviceConfigs.end(); ++iter) {
        if ((!(iter->isPasspoint)) && (!(iter->isEphemeral))) {
            savedNetworkSsid.push_back(iter->ssid);
        }
    }
    WIFI_LOGI("Saved network list size:%{public}d", (int)savedNetworkSsid.size());
    return true;
}

bool ScanService::GetHiddenNetworkSsidList(std::vector<std::string> &hiddenNetworkSsid)
{
    WIFI_LOGI("Enter GetHiddenNetworkSsidList.\n");

    std::vector<WifiDeviceConfig> deviceConfigs;
    if (WifiSettings::GetInstance().GetDeviceConfig(deviceConfigs) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetDeviceConfig failed");
        return false;
    }
    for (auto iter = deviceConfigs.begin(); iter != deviceConfigs.end();) {
        if (!iter->hiddenSSID) {
            iter = deviceConfigs.erase(iter);
            continue;
        }
        if (iter->networkSelectionStatus.connectChoice != iter->networkId) {
            ++iter;
            continue;
        }
        // Add the user-selected SSID to the scan list with priority.
        hiddenNetworkSsid.push_back(iter->ssid);
        AddSsidToHiddenNetworkList(iter->ssid, hiddenNetworkSsid);
        iter = deviceConfigs.erase(iter);
    }
    std::sort(deviceConfigs.begin(), deviceConfigs.end(), [](WifiDeviceConfig deviceA, WifiDeviceConfig deviceB) {
        time_t aTime = deviceA.lastHasInternetTime == -1 ? deviceA.lastConnectTime : deviceA.lastHasInternetTime;
        time_t bTime = deviceB.lastHasInternetTime == -1 ? deviceB.lastConnectTime : deviceB.lastHasInternetTime;
        return aTime > bTime;
    });
    for (auto iter = deviceConfigs.begin(); iter != deviceConfigs.end(); ++iter) {
        hiddenNetworkSsid.push_back(iter->ssid);
        // for gbk hiddenNetworkSsID
        AddSsidToHiddenNetworkList(iter->ssid, hiddenNetworkSsid);
    }

    WIFI_LOGI("Find %{public}d hidden NetworkSsid.\n", (int)hiddenNetworkSsid.size());
    return true;
}

void ScanService::ClearScanControlValue()
{
    WIFI_LOGI("Enter ClearScanControlValue.\n");

    customCurrentTime = 0;
    appForbidList.clear();
    scanBlocklist.clear();
    fullAppForbidList.clear();
    customSceneTimeMap.clear();
}

void ScanService::SetStaCurrentTime()
{
    WIFI_LOGD("Enter SetStaCurrentTime.\n");
    time_t now = time(0);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetStaCurrentTime(now);

    int state = WifiConfigCenter::GetInstance().GetScreenState();
    if (state == MODE_STATE_CLOSE) {
        int scanStyle = SCAN_DEFAULT_TYPE;
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanType(ScanType::SCAN_TYPE_PNO);
        if (AllowScanByType(ScanType::SCAN_TYPE_PNO, scanStyle) != WIFI_OPT_SUCCESS) {
            EndPnoScan();
            pnoScanFailedNum = 0;
            pScanStateMachine->StopTimer(static_cast<int>(RESTART_PNO_SCAN_TIMER));
        }
    }
    return;
}

bool ScanService::AllowScanDuringScanning(ScanMode scanMode) const
{
    WIFI_LOGI("Enter AllowScanDuringScanning.\n");

    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    for (auto iter = scanControlInfo.scanForbidList.begin(); iter != scanControlInfo.scanForbidList.end(); ++iter) {
        if (iter->scanScene == SCAN_SCENE_SCANNING && iter->scanMode == scanMode) {
            WIFI_LOGW("scan not allow by scanning scene.");
            return false;
        }
    }
    return true;
}

bool ScanService::AllowScanDuringStaScene(int staScene, ScanMode scanMode)
{
    WIFI_LOGI("Enter AllowScanDuringStaScene, staScene:%{public}d, scanMode:%{public}d",
        staScene, scanMode);

    time_t now = time(nullptr);
    if (now < 0) {
        WIFI_LOGW("time return invalid!\n.");
        return false;
    }
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    for (auto iter = scanControlInfo.scanForbidList.begin(); iter != scanControlInfo.scanForbidList.end(); ++iter) {
        /* forbid scan mode found in scan scene. */
        if (iter->scanScene == staScene && iter->scanMode == scanMode) {
            /* forbidCount=0 and forbidTime=0, directly forbid scan. */
            if ((iter->forbidTime == 0) && (iter->forbidCount == 0)) {
                WIFI_LOGW("Scan is forbidden by staScene.");
                return false;
            }
            /* Unconditional scan control for forbidCount times */
            int staSceneForbidCount = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetStaSceneForbidCount();
            if ((iter->forbidCount > 0) && (iter->forbidCount - staSceneForbidCount > 0)) {
                WIFI_LOGW("Scan is forbidden in forbidCount.");
                staSceneForbidCount++;
                return false;
            }
            /* Scan interval less than forbidTime, forbid scan. */
            time_t staCurrentTime = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetStaCurrentTime();
            if ((iter->forbidTime > 0) && (now - staCurrentTime <= iter->forbidTime)) {
                WIFI_LOGW("Scan is forbidden in forbidTime.");
                return false;
            }
        }
    }

    return true;
}

bool ScanService::AllowScanDuringCustomScene(ScanMode scanMode)
{
    WIFI_LOGD("Enter AllowScanDuringCustomScene.\n");

    bool isTrustListMode = IsScanTrustMode();
    for (auto customIter = customSceneTimeMap.begin(); customIter != customSceneTimeMap.end(); ++customIter) {
        if (isTrustListMode && IsInScanTrust(customIter->first)) {
            WIFI_LOGD("Trust list mode,sceneId(%{public}d) in the list, continue.", customIter->first);
            continue;
        }

        if (!AllowCustomSceneCheck(customIter, scanMode)) {
            return false;
        }
    }
    return true;
}

bool ScanService::AllowCustomSceneCheck(const std::map<int, time_t>::const_iterator &customIter, ScanMode scanMode)
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    for (auto iter = scanControlInfo.scanForbidList.begin(); iter != scanControlInfo.scanForbidList.end(); ++iter) {
        if (iter->scanScene == customIter->first && iter->scanMode == scanMode) {
            /* forbidCount=0 and forbidTime=0, directly forbid scan. */
            if ((iter->forbidTime == 0) && (iter->forbidCount == 0)) {
                WIFI_LOGW("Scan is forbidden by staScene.");
                return false;
            }
            /* Unconditional scan control for forbidCount times. */
            if (iter->forbidCount > 0 && iter->forbidCount - customSceneForbidCount > 0) {
                customSceneForbidCount++;
                WIFI_LOGW("Unconditional scan control for forbidCount times, customSceneForbidCount:%{public}d.",
                    customSceneForbidCount);
                return false;
            }
            /* Scan interval less than forbidTime, forbid scan. */
            time_t now = time(nullptr);
            if (iter->forbidTime > 0 && iter->forbidTime > now - customIter->second) {
                WIFI_LOGW("Scan interval less than forbidTime, forbid scan, forbidTime:%{public}d.",
                    iter->forbidTime);
                return false;
            }
        }
    }

    return true;
}

bool ScanService::AllowExternScanByIntervalMode(int appId, int scanScene, ScanMode scanMode)
{
    WIFI_LOGI("Enter AllowExternScanByIntervalMode.\n");

    if (IsAppInFilterList(scan_frequency_trust_list)) {
        return true;
    }
    bool isTrustListMode = IsScanTrustMode();
    if (isTrustListMode && IsInScanTrust(scanScene)) {
        WIFI_LOGD("Trust list mode,sceneId(%{public}d) in the list, return true.", scanScene);
        return true;
    }

    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    for (auto intervalListIter = scanControlInfo.scanIntervalList.begin();
         intervalListIter != scanControlInfo.scanIntervalList.end();
         ++intervalListIter) {
        /* Determine whether control is required in the current scene and scan mode. */
        if (intervalListIter->scanScene == scanScene && intervalListIter->scanMode == scanMode) {
            /* If a single application is distinguished. */
            if (intervalListIter->isSingle) {
                if (!AllowSingleAppScanByInterval(appId, *intervalListIter)) {
                    return false;
                }
            } else {
                if (!AllowFullAppScanByInterval(appId, *intervalListIter)) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool ScanService::PnoScanByInterval(int &fixedScanCount, time_t &fixedScanTime, int interval, int count)
{
    WIFI_LOGI("Enter PnoScanByInterval.\n");

    time_t now = time(nullptr);
    /* First scan */
    if (fixedScanCount == 0) {
        fixedScanCount++;
        fixedScanTime = now;
        return true;
    }
    if (now - fixedScanTime >= interval) {
        fixedScanCount = 1;
        fixedScanTime = now;
        return true;
    }
    if (fixedScanCount > count) {
        return false;
    }
    fixedScanCount++;
    return true;
}

#ifdef SUPPORT_SCAN_CONTROL
bool ScanService::SystemScanByInterval(int staScene, int &interval, int &count)
{
    WIFI_LOGI("Enter SystemScanByInterval.\n");
    int state = WifiConfigCenter::GetInstance().GetScreenState();
    if (state == MODE_STATE_OPEN || state == MODE_STATE_DEFAULT) {
        if (staScene == SCAN_SCENE_CONNECTED) {
            SystemScanConnectedPolicy(interval);
        } else if (staScene == SCAN_SCENE_DISCONNCTED) {
            SystemScanDisconnectedPolicy(interval, count);
        }
    }
    return true;
}
#else
bool ScanService::SystemScanByInterval(int &expScanCount, int &interval, int &count)
{
    WIFI_LOGI("Enter SystemScanByInterval.\n");
    /*
     * Exponential interval. The value of interval is the initial value.
     * After the value is multiplied by 2, the last fixed interval is used.
     */
    if (expScanCount > 0 && count > 1) {
        interval *= DOUBLE_SCAN_INTERVAL;
        count--;
    }
    expScanCount++;
    return true;
}
#endif

bool ScanService::ExternScanByInterval(int appId, SingleAppForbid &singleAppForbid)
{
    WIFI_LOGI("Enter ExternScanByInterval.\n");

    switch (singleAppForbid.scanIntervalMode.intervalMode) {
        case IntervalMode::INTERVAL_FIXED:
            return AllowScanByIntervalFixed(singleAppForbid.fixedScanCount, singleAppForbid.fixedCurrentTime,
                singleAppForbid.scanIntervalMode.interval, singleAppForbid.scanIntervalMode.count);

        case IntervalMode::INTERVAL_EXP:
            return AllowScanByIntervalExp(singleAppForbid.expScanCount, singleAppForbid.scanIntervalMode.interval,
                singleAppForbid.scanIntervalMode.count);

        case IntervalMode::INTERVAL_CONTINUE:
            return AllowScanByIntervalContinue(singleAppForbid.continueScanTime, singleAppForbid.lessThanIntervalCount,
                singleAppForbid.scanIntervalMode.interval, singleAppForbid.scanIntervalMode.count);

        case IntervalMode::INTERVAL_BLOCKLIST:
            WIFI_LOGI("INTERVAL_BLOCKLIST IntervalMode.\n");
            return AllowScanByIntervalBlocklist(appId, singleAppForbid.blockListScanTime,
                singleAppForbid.lessThanIntervalCount, singleAppForbid.scanIntervalMode.interval,
                singleAppForbid.scanIntervalMode.count);

        default:
            return true;
    }
}

bool ScanService::AllowSingleAppScanByInterval(int appId, ScanIntervalMode scanIntervalMode)
{
    WIFI_LOGI("Enter AllowSingleAppScanByInterval.\n");
    bool appIdExisted = false;
    for (auto forbidListIter = appForbidList.begin(); forbidListIter != appForbidList.end(); ++forbidListIter) {
        if (forbidListIter->appID == appId &&
            forbidListIter->scanIntervalMode.scanScene == scanIntervalMode.scanScene &&
            forbidListIter->scanIntervalMode.scanMode == scanIntervalMode.scanMode) {
            appIdExisted = true;
        }
    }
    /* If the appId is the first scan request, add it to appForbidList. */
    if (!appIdExisted) {
        SingleAppForbid singleAppForbid;
        singleAppForbid.appID = appId;
        singleAppForbid.scanIntervalMode.scanScene = scanIntervalMode.scanScene;
        singleAppForbid.scanIntervalMode.scanMode = scanIntervalMode.scanMode;
        singleAppForbid.scanIntervalMode.interval = scanIntervalMode.interval;
        singleAppForbid.scanIntervalMode.intervalMode = scanIntervalMode.intervalMode;
        singleAppForbid.scanIntervalMode.count = scanIntervalMode.count;
        appForbidList.push_back(singleAppForbid);
    }
    for (auto iter = appForbidList.begin(); iter != appForbidList.end(); ++iter) {
        if (iter->appID == appId && iter->scanIntervalMode.scanScene == scanIntervalMode.scanScene &&
            iter->scanIntervalMode.scanMode == scanIntervalMode.scanMode) {
            if (!ExternScanByInterval(appId, *iter)) {
                WIFI_LOGI("AllowSingleAppScanByInterval:false.");
                return false;
            }
        }
    }
    WIFI_LOGI("AllowSingleAppScanByInterval:true.");
    return true;
}

bool ScanService::AllowFullAppScanByInterval(int appId, ScanIntervalMode scanIntervalMode)
{
    WIFI_LOGI("Enter AllowFullAppScanByInterval.\n");

    bool fullAppExisted = false;
    for (auto fullAppForbidIter = fullAppForbidList.begin(); fullAppForbidIter != fullAppForbidList.end();
        ++fullAppForbidIter) {
        if (fullAppForbidIter->scanIntervalMode.scanScene == scanIntervalMode.scanScene &&
            fullAppForbidIter->scanIntervalMode.scanMode == scanIntervalMode.scanMode) {
            fullAppExisted = true;
        }
    }
    if (!fullAppExisted) {
        SingleAppForbid singleAppForbid;
        singleAppForbid.scanIntervalMode.scanScene = scanIntervalMode.scanScene;
        singleAppForbid.scanIntervalMode.scanMode = scanIntervalMode.scanMode;
        singleAppForbid.scanIntervalMode.interval = scanIntervalMode.interval;
        singleAppForbid.scanIntervalMode.intervalMode = scanIntervalMode.intervalMode;
        singleAppForbid.scanIntervalMode.count = scanIntervalMode.count;
        fullAppForbidList.push_back(singleAppForbid);
    }
    for (auto iter = fullAppForbidList.begin(); iter != fullAppForbidList.end(); ++iter) {
        if (iter->scanIntervalMode.scanScene == scanIntervalMode.scanScene &&
            iter->scanIntervalMode.scanMode == scanIntervalMode.scanMode) {
            if (!ExternScanByInterval(appId, *iter)) {
                WIFI_LOGI("AllowFullAppScanByInterval:false.");
                return false;
            }
        }
    }
    WIFI_LOGI("AllowFullAppScanByInterval:true.");
    return true;
}

bool ScanService::AllowScanByIntervalFixed(int &fixedScanCount, time_t &fixedScanTime, int &interval, int &count)
{
    WIFI_LOGI("Enter AllowScanByIntervalFixed.\n");

    time_t now = time(nullptr);
    /* First scan */
    if (fixedScanCount == 0) {
        fixedScanCount++;
        fixedScanTime = now;
        return true;
    }
    /* The scanning interval is greater than interval, and counting is restarted. */
    if (now - fixedScanTime >= interval) {
        fixedScanCount = 1;
        fixedScanTime = now;
        return true;
    }
    /* *
     * Scan is forbidden because the scanning interval is less than interval
     * and the number of scan times exceeds count.
     */
    if (fixedScanCount >= count) {
        return false;
    }
    fixedScanCount++;
    return true;
}

bool ScanService::AllowScanByIntervalExp(int &expScanCount, int &interval, int &count)
{
    WIFI_LOGI("Enter AllowScanByIntervalExp.\n");

    /*
     * Exponential interval. The value of interval is the initial value.
     * After the value is multiplied by 2, the last fixed interval is used.
     */
    if (expScanCount > 0 && count > 1) {
        interval *= DOUBLE_SCAN_INTERVAL;
        count--;
    }
    expScanCount++;
    return true;
}

bool ScanService::AllowScanByIntervalContinue(time_t &continueScanTime, int &lessThanIntervalCount, int &interval,
    int &count)
{
    WIFI_LOGI("Enter AllowScanByIntervalContinue.\n");

    WIFI_LOGD("lessThanIntervalCount:%{public}d, interval:%{public}d, count:%{public}d", lessThanIntervalCount,
        interval, count);
    time_t now = time(nullptr);
    /* First scan */
    if (continueScanTime == 0) {
        continueScanTime = now;
        return true;
    }
    /* If count is less than interval, the subsequent interval must be greater than interval. */
    if (now - continueScanTime < interval) {
        lessThanIntervalCount++;
        if (lessThanIntervalCount < count) {
            continueScanTime = now;
            return true;
        }
        /* If the scanning interval is not exceeded continuously, the counter is cleared. */
        lessThanIntervalCount = 0;
        return false;
    }
    /* If the scanning interval is not exceeded continuously, the counter is cleared. */
    lessThanIntervalCount = 0;
    continueScanTime = now;
    return true;
}

bool ScanService::AllowScanByIntervalBlocklist(
    int appId, time_t &blockListScanTime, int &lessThanIntervalCount, int &interval, int &count)
{
    WIFI_LOGI("Enter AllowScanByIntervalBlocklist.\n");

    time_t now = time(nullptr);
    if (now - blockListScanTime >= interval) {
        for (auto iter = scanBlocklist.begin(); iter != scanBlocklist.end();) {
            if (*iter == appId) {
                iter = scanBlocklist.erase(iter);
            } else {
                ++iter;
            }
        }
        blockListScanTime = now;
        return true;
    }
    /* If the app ID is in the blocklist, extern scan is forbidden. */
    if (std::find(scanBlocklist.begin(), scanBlocklist.end(), appId) != scanBlocklist.end()) {
        WIFI_LOGW("extern scan not allowed by blocklist");
        return false;
    }
    /* First scan */
    if (blockListScanTime == 0) {
        blockListScanTime = now;
        WIFI_LOGW("blockListScanTime, first scan.");
        return true;
    }
    /**
     * If the number of consecutive count times is less than the value of interval,
     * the user is added to the blocklist and cannot be scanned.
     */
    if (now - blockListScanTime < interval) {
        lessThanIntervalCount++;
        if (lessThanIntervalCount < count) {
            blockListScanTime = now;
            WIFI_LOGD("blockListScanTime, lessThanIntervalCount(%{public}d),return true.", lessThanIntervalCount);
            return true;
        }
        /**
         * If the accumulated scanning interval is less than interval and the number of times
         * is greater than count, the user is blocklisted forbidding scanning.
         */
        scanBlocklist.push_back(appId);
        WIFI_LOGI("scanBlocklist.push_back(appId), return false.");
        return false;
    }
    blockListScanTime = now;
    return true;
}

bool ScanService::AllowScanByDisableScanCtrl()
{
    std::unique_lock<std::mutex> lock(scanControlInfoMutex);
    return !disableScanFlag;
}

bool ScanService::AllowScanByMovingFreeze(ScanMode appRunMode)
{
    LOGI("Enter AllowScanByMovingFreeze.\n");

    /* moving freeze trust mode. */
    bool isTrustListMode = IsScanTrustMode();
    if (isTrustListMode && IsInScanTrust(-1)) {
        WIFI_LOGD("Trust list mode,sceneId(MovingFreeze) in the list, return true.");
        return true;
    }

    if (!IsMovingFreezeState(appRunMode)) {
        WIFI_LOGD("It's not in the movingfreeze mode, return true.");
        return true;
    }

    if (!IsMovingFreezeScaned()) {
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetMovingFreezeScaned(true);
        WIFI_LOGD("In movingfreeze mode, return true for the first scan.");
        return true;
    } else {
        WIFI_LOGW("In movingfreeze mode, return false for the already scanned.");
        return false;
    }

    return true;
}

bool ScanService::AllowLpScan(ScanType scanType)
{
    if (mEnhanceService != nullptr && mEnhanceService->IsSupportLpScanAbility() &&
        (scanType != ScanType::SCAN_TYPE_PNO && scanType != ScanType::SCAN_TYPE_SYSTEMTIMER)) {
        return true;
    }
    return false;
}

bool ScanService::AllowScanByHid2dState(ScanType scanType, int &scanStyle)
{
    LOGD("Enter AllowScanByHid2dState.\n");
    Hid2dUpperScene softbusScene, castScene, shareScene, mouseCrossScene, miracastScene;
    WifiP2pLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SOFT_BUS_SERVICE_UID, softbusScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(CAST_ENGINE_SERVICE_UID, castScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MIRACAST_SERVICE_UID, miracastScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SHARE_SERVICE_UID, shareScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MOUSE_CROSS_SERVICE_UID, mouseCrossScene);
    WifiConfigCenter::GetInstance().GetP2pInfo(linkedInfo);

    if (IsAppInFilterList(scan_hid2d_list)) {
        WIFI_LOGI("ScanService::AllowScanByHid2dState, no need to control this scan");
        return true;
    }
    int64_t hid2dSceneLastSetTime = WifiConfigCenter::GetInstance().GetHid2dSceneLastSetTime();
    int64_t intervalTime = GetIntervalTime(hid2dSceneLastSetTime);
    if (intervalTime < 0) {
      WIFI_LOGE("time error, abandon this scan and reset the hid2dSceneLastSetTime.");
      WifiConfigCenter::GetInstance().SetHid2dSceneLastSetTime(0);
      return false;
    }
    if (hid2dSceneLastSetTime != 0 && intervalTime > HID2D_TIMEOUT_INTERVAL
        && linkedInfo.GetConnectState() == P2pConnectedState::P2P_DISCONNECTED
        && WifiConfigCenter::GetInstance().GetP2pEnhanceState() == 0) {
        WIFI_LOGW("allow scan, and clear scene.");
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo();
        return true;
    }
    // scene bit 0-2 is valid, 0x01: video, 0x02: audio, 0x04: file,
    // scene & 0x07 > 0 means one of them takes effect.
    if ((softbusScene.scene & 0x07) > 0) {
        if ((softbusScene.scene & 0x07) <= 0x03 && AllowLpScan(scanType)) {
            scanStyle = SCAN_TYPE_LOW_PRIORITY;
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::LP_SCAN_UNCTRL_CNT);
            WIFI_LOGI("LP Scan is allowed in cast/softbus hid2d.");
            return true;
        }
        WIFI_LOGW("Scan is not allowed in softbus hid2d.");
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::HID2D_SOFTBUS);
        return false;
    } else if ((castScene.scene & 0x07) > 0) {
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::HID2D_CAST);
        if (AllowLpScan(scanType)) {
            scanStyle = SCAN_TYPE_LOW_PRIORITY;
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::LP_SCAN_UNCTRL_CNT);
            WIFI_LOGI("LP Scan is allowed in cast hid2d.");
            return true;
        }
        WIFI_LOGW("Scan is not allowed in cast hid2d.");
        return false;
    } else if ((miracastScene.scene & 0x07) > 0) {
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::HID2D_MIRACAST);
        if (AllowLpScan(scanType)) {
            scanStyle = SCAN_TYPE_LOW_PRIORITY;
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::LP_SCAN_UNCTRL_CNT);
            WIFI_LOGI("LP Scan is allowed in miracast hid2d.");
            return true;
        }
        WIFI_LOGW("Scan is not allowed in miracast hid2d.");
        return false;
    } else if ((shareScene.scene & 0x07) > 0) {
        WIFI_LOGW("Scan is not allowed in share hid2d.");
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::HID2D_SHARE);
        return false;
    } else if ((mouseCrossScene.scene & 0x07) > 0) {
        WIFI_LOGW("Scan is not allowed in mouse cross hid2d.");
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::HID2D_CROSS);
        return false;
    } else {
        WIFI_LOGD("allow hid2d scan");
    }
    return true;
}

bool ScanService::AllowScanByActionListen()
{
#ifdef SUPPORT_SCAN_CONTROL_ACTION_LISTEN
    if (mEnhanceService != nullptr && mEnhanceService->IsInActionListenState()) {
        WifiScanChr::GetInstance().RecordScanChrLimitInfo(
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(),
            ScanLimitType::ACTION_LISTEN);
        WIFI_LOGW("Scan is not allowed in ActionListen condition.");
        return false;
    }
#endif
    return true;
}

bool ScanService::AllowScanByGameScene(ScanType scanType, int &scanStyle)
{
    if (staStatus == static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)) {
        return true;
    }
    WifiNetworkControlInfo NetworkControlInfo = WifiConfigCenter::GetInstance().GetNetworkControlInfo();
    if (NetworkControlInfo.state == GameSceneId::MSG_GAME_ENTER_PVP_BATTLE ||
        NetworkControlInfo.state == GameSceneId::MSG_GAME_STATE_FOREGROUND) {
        if (AllowLpScan(scanType)) {
            scanStyle = SCAN_TYPE_LOW_PRIORITY;
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::LP_SCAN_UNCTRL_CNT);
            WIFI_LOGI("LP Scan is allowed in GameScene.");
            return true;
        }
        WIFI_LOGW("Interval scan is not allowed in GameScene condition AllowScanByGameScene = %{public}d",
            NetworkControlInfo.state);
        return false;
    }
    return true;
}

int64_t ScanService::GetIntervalTime(int64_t startTime)
{
  struct timespec times = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &times);
  int64_t currentMs =
    static_cast<int64_t>(times.tv_sec) * SECOND_TO_MILLI_SECOND + times.tv_nsec / SECOND_TO_MICRO_SECOND;
  return currentMs - startTime;
}

bool ScanService::IsPackageInTrustList(const std::string &trustList, int sceneId,
    const std::string &appPackageName) const
{
    std::vector<std::string> trustPackages;
    SplitString(trustList, "|", trustPackages);

    bool bFind = false;
    for (const auto &package : trustPackages) {
        if (package == appPackageName) {
            WIFI_LOGD("IsPackageInTrustList=true");
            bFind = true;
            break;
        }
    }

    if (!bFind) {
        WIFI_LOGD("sceneId=%{public}d, appName=%{public}s trustList=%{public}s, not in the lists.", sceneId,
            appPackageName.c_str(), trustList.c_str());
    }

    return bFind;
}

ErrCode ScanService::SetNetworkInterfaceUpDown(bool upDown)
{
    WIFI_LOGI("Enter ScanService::SetNetworkInterfaceUpDown.\n");
    int res = WifiStaHalInterface::GetInstance().SetNetworkInterfaceUpDown(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), upDown);
    if (res != static_cast<int>(WIFI_HAL_OPT_OK)) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

bool ScanService::IsAppInFilterList(const std::vector<PackageInfo> &packageFilter) const
{
    std::string packageName = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetAppPackageName();
    for (auto iter = packageFilter.begin(); iter != packageFilter.end(); iter++) {
        if (iter->name == packageName) {
            return true;
        }
    }
    return false;
}

void ScanService::SystemScanConnectedPolicy(int &interval)
{
    WIFI_LOGI("Enter SystemScanConnectedPolicy");
    WifiLinkedInfo linkedInfo;
    WifiDeviceConfig wifiDeviceConfig;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, wifiDeviceConfig);
    if (linkedInfo.detailedState == DetailedState::WORKING) {
        interval = SYSTEM_SCAN_INTERVAL_ONE_HOUR;
    } else if (WifiProUtils::IsUserSelectNetwork() &&
        !NetworkStatusHistoryManager::HasInternetEverByHistory(wifiDeviceConfig.networkStatusHistory)) {
        WIFI_LOGI("user actively select no-net network and no-net in history, set interval as one hour.");
        interval = SYSTEM_SCAN_INTERVAL_ONE_HOUR;
    } else {
        interval *= DOUBLE_SCAN_INTERVAL;
        if (IsMovingFreezeState(ScanMode::SYSTEM_TIMER_SCAN)) {
            if (interval > SYSTEM_SCAN_INTERVAL_FIVE_MINUTE) {
                interval = SYSTEM_SCAN_INTERVAL_FIVE_MINUTE;
            }
        } else {
            if (interval > SYSTEM_SCAN_INTERVAL_160_SECOND) {
                interval = SYSTEM_SCAN_INTERVAL_160_SECOND;
            }
        }
    }
}

void ScanService::SystemScanDisconnectedPolicy(int &interval, int &count)
{
    WIFI_LOGI("Enter SystemScanDisconnectedPolicy");
    int scanGenieState = WifiConfigCenter::GetInstance().GetScanGenieState();
    if (scanGenieState == MODE_STATE_OPEN) {
        if (count < SYSTEM_SCAN_COUNT_3_TIMES) {
            interval = SYSTEM_SCAN_INTERVAL_10_SECOND;
        } else if (count < SYSTEM_SCAN_COUNT_3_TIMES * DOUBLE_SCAN_INTERVAL) {
            interval = SYSTEM_SCAN_INTERVAL_30_SECOND;
        } else {
            if (IsMovingFreezeState(ScanMode::SYSTEM_TIMER_SCAN)) {
                interval = SYSTEM_SCAN_INTERVAL_FIVE_MINUTE;
            } else {
                interval = SYSTEM_SCAN_INTERVAL_60_SECOND;
            }
        }
        count++;
    } else {
        interval *= DOUBLE_SCAN_INTERVAL;
        if (IsMovingFreezeState(ScanMode::SYSTEM_TIMER_SCAN)) {
            if (interval > SYSTEM_SCAN_INTERVAL_FIVE_MINUTE) {
                interval = SYSTEM_SCAN_INTERVAL_FIVE_MINUTE;
            }
        } else {
            if (interval > SYSTEM_SCAN_INTERVAL_160_SECOND) {
                interval = SYSTEM_SCAN_INTERVAL_160_SECOND;
            }
        }
    }
}

void ScanService::InitChipsetInfo()
{
    WIFI_LOGI("Enter InitChipsetInfo");
    if (isChipsetInfoObtained) {
        return;
    }
    if (WifiStaHalInterface::GetInstance().GetChipsetCategory(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), chipsetCategory) != WIFI_HAL_OPT_OK
        || WifiStaHalInterface::GetInstance().GetChipsetWifiFeatrureCapability(
            WifiConfigCenter::GetInstance().GetStaIfaceName(), chipsetFeatrureCapability) != WIFI_HAL_OPT_OK) {
                WIFI_LOGE("GetChipsetCategory or GetChipsetWifiFeatrureCapability failed.\n");
                isChipsetInfoObtained = false;
    } else {
        isChipsetInfoObtained = true;
    }
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService != nullptr) {
        pEnhanceService->SetChipSetInfos(chipsetCategory, chipsetFeatrureCapability);
    }
}

void ScanService::ResetScanInterval()
{
    WIFI_LOGI("Enter ResetScanInterval");
    systemScanIntervalMode.scanIntervalMode.interval = SYSTEM_SCAN_INTERVAL_10_SECOND;
}

#ifndef OHOS_ARCH_LITE
ErrCode ScanService::WifiCountryCodeChangeObserver::OnWifiCountryCodeChanged(const std::string &wifiCountryCode)
{
    if (strcasecmp(m_lastWifiCountryCode.c_str(), wifiCountryCode.c_str()) == 0) {
        WIFI_LOGI("wifi country code is same, scan not update, code=%{public}s", wifiCountryCode.c_str());
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGI("deal wifi country code changed, code=%{public}s", wifiCountryCode.c_str());
    InternalMessagePtr msg = m_stateMachineObj.CreateMessage();
    CHECK_NULL_AND_RETURN(msg, WIFI_OPT_FAILED);
    msg->SetMessageName(static_cast<int>(SCAN_UPDATE_COUNTRY_CODE));
    msg->AddStringMessageBody(wifiCountryCode);
    m_stateMachineObj.SendMessage(msg);
    m_lastWifiCountryCode = wifiCountryCode;
    return WIFI_OPT_SUCCESS;
}

std::string ScanService::WifiCountryCodeChangeObserver::GetListenerModuleName()
{
    return m_listenerModuleName;
}
#endif

int CalculateBitPerTone(int snrDb)
{
    int bitPerTone;
    if (snrDb <= SNR_BIT_PER_TONE_LUT_MAX) {
        size_t lutInIdx = static_cast<size_t>(MAX(snrDb, SNR_BIT_PER_TONE_LUT_MIN)) - SNR_BIT_PER_TONE_LUT_MIN;
        size_t lutSize = sizeof(SNR_BIT_PER_TONE_LUT) / sizeof(int);
        lutInIdx = MIN(lutInIdx, lutSize - 1);
        bitPerTone = SNR_BIT_PER_TONE_LUT[lutInIdx];
    } else {
        bitPerTone = snrDb * SNR_BIT_PER_TONE_HIGH_SNR_SCALE;
    }
    return bitPerTone;
}

int CalculateAirTimeFraction(int channelUtilization, int channelWidthFactor)
{
    int airTimeFraction20MHZ = MAX_CHANNEL_UTILIZATION - channelUtilization;
    int airTimeFraction = airTimeFraction20MHZ;

    for (int i = 1; i <= channelWidthFactor; ++i) {
        airTimeFraction *= airTimeFraction;
        airTimeFraction /= MAX_CHANNEL_UTILIZATION;
    }
    WIFI_LOGD("airTime20: %{public}d airTime: %{public}d", airTimeFraction20MHZ, airTimeFraction);
    return airTimeFraction;
}

int WifiMaxThroughput(int wifiStandard, bool is11bMode, WifiChannelWidth channelWidth, int rssiDbm,
                      int maxNumSpatialStream, int channelUtilization)
{
    int channelWidthFactor;
    int numTonePerSym;
    int symDurationNs;
    int maxBitsPerTone;
    if (maxNumSpatialStream < 1) {
        WIFI_LOGI("maxNumSpatialStream < 1 due to wrong implementation. Overridden to 1");
        maxNumSpatialStream = 1;
    }
    if (wifiStandard == WIFI_MODE_UNDEFINED) {
        return -1;
    } else if (wifiStandard == WIFI_802_11A ||
    wifiStandard == WIFI_802_11B ||
    wifiStandard == WIFI_802_11G) {
        numTonePerSym = TONE_PER_SYM_11ABG;
        channelWidthFactor = 0;
        maxNumSpatialStream = MAX_NUM_SPATIAL_STREAM_11ABG;
        maxBitsPerTone = MAX_BITS_PER_TONE_11ABG;
        symDurationNs = SYM_DURATION_11ABG_NS;
    } else if (wifiStandard == WIFI_802_11N) {
        if (channelWidth == WifiChannelWidth::WIDTH_20MHZ) {
            numTonePerSym = TONE_PER_SYM_11N_20MHZ;
            channelWidthFactor = 0;
        } else {
            numTonePerSym = TONE_PER_SYM_11N_40MHZ;
            channelWidthFactor = 1;
        }
        maxNumSpatialStream = MIN(maxNumSpatialStream, MAX_NUM_SPATIAL_STREAM_11N);
        maxBitsPerTone = MAX_BITS_PER_TONE_11N;
        symDurationNs = SYM_DURATION_11N_NS;
    } else if (wifiStandard == WIFI_802_11AC) {
        if (channelWidth == WifiChannelWidth::WIDTH_20MHZ) {
            numTonePerSym = TONE_PER_SYM_11AC_20MHZ;
            channelWidthFactor = 0;
        } else if (channelWidth == WifiChannelWidth::WIDTH_40MHZ) {
            numTonePerSym = TONE_PER_SYM_11AC_40MHZ;
            channelWidthFactor = 1;
        } else if (channelWidth == WifiChannelWidth::WIDTH_80MHZ) {
            numTonePerSym = TONE_PER_SYM_11AC_80MHZ;
            channelWidthFactor = 2;
        } else {
            numTonePerSym = TONE_PER_SYM_11AC_160MHZ;
            channelWidthFactor = 3;
        }
        maxNumSpatialStream = MIN(maxNumSpatialStream, MAX_NUM_SPATIAL_STREAM_11AC);
        maxBitsPerTone = MAX_BITS_PER_TONE_11AC;
        symDurationNs = SYM_DURATION_11AC_NS;
    } else {
        if (channelWidth == WifiChannelWidth::WIDTH_20MHZ) {
            numTonePerSym = TONE_PER_SYM_11AX_20MHZ;
            channelWidthFactor = 0;
        } else if (channelWidth == WifiChannelWidth::WIDTH_40MHZ) {
            numTonePerSym = TONE_PER_SYM_11AX_40MHZ;
            channelWidthFactor = 1;
        } else if (channelWidth == WifiChannelWidth::WIDTH_80MHZ) {
            numTonePerSym = TONE_PER_SYM_11AX_80MHZ;
            channelWidthFactor = 2;
        } else {
            numTonePerSym = TONE_PER_SYM_11AX_160MHZ;
            channelWidthFactor = 3;
        }
        maxNumSpatialStream = MIN(maxNumSpatialStream, MAX_NUM_SPATIAL_STREAM_11AX);
        maxBitsPerTone = MAX_BITS_PER_TONE_11AX;
        symDurationNs = SYM_DURATION_11AX_NS;
    }
    int noiseFloorDbBoost = TWO_DB * channelWidthFactor;
    int noiseFloorDbm = NOISE_FLOOR_20MHZ_DBM + noiseFloorDbBoost + SNR_MARGIN_DB;
    int snrDb = rssiDbm - noiseFloorDbm;

    int bitPerTone = CalculateBitPerTone(snrDb);
    bitPerTone = MIN(bitPerTone, maxBitsPerTone);

    long long bitPerToneTotal = static_cast<long long>(bitPerTone) * maxNumSpatialStream;
    long long numBitPerSym = bitPerToneTotal * numTonePerSym;
    long phyRateMbps = (int)((numBitPerSym * MICRO_TO_NANO_RATIO) / (symDurationNs * BIT_PER_TONE_SCALE));
    int airTimeFraction = CalculateAirTimeFraction(channelUtilization, channelWidthFactor);
    int throughputMbps = (phyRateMbps * airTimeFraction) / MAX_CHANNEL_UTILIZATION;
    if (is11bMode) {
        throughputMbps = MIN(throughputMbps, B_MODE_MAX_MBPS);
    }
    return throughputMbps;
}
}  // namespace Wifi
}  // namespace OHOS
