/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_scan_manager.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_common_event_helper.h"
#include "wifi_system_timer.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#include "wifi_sa_manager.h"
#endif

DEFINE_WIFILOG_LABEL("WifiScanManager");

namespace OHOS {
namespace Wifi {
WifiScanManager::WifiScanManager()
{
    WIFI_LOGI("create WifiScanManager");
    InitScanCallback();
}

IScanSerivceCallbacks& WifiScanManager::GetScanCallback()
{
    return mScanCallback;
}

#ifndef OHOS_ARCH_LITE
static void UnloadScanSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_SCAN_ABILITY_ID);
    WifiManager::GetInstance().GetWifiScanManager()->StopUnloadScanSaTimer();
}

void WifiScanManager::StopUnloadScanSaTimer(void)
{
    WIFI_LOGI("StopUnloadScanSaTimer! unloadScanSaTimerId:%{public}u", unloadScanSaTimerId);
    std::unique_lock<std::mutex> lock(unloadScanSaTimerMutex);
    if (unloadScanSaTimerId == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(unloadScanSaTimerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(unloadScanSaTimerId);
    unloadScanSaTimerId = 0;
    return;
}

void WifiScanManager::StartUnloadScanSaTimer(void)
{
    WIFI_LOGI("StartUnloadScanSaTimer! unloadScanSaTimerId:%{public}u", unloadScanSaTimerId);
    std::unique_lock<std::mutex> lock(unloadScanSaTimerMutex);
    if (unloadScanSaTimerId == 0) {
        std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, true, false);
        wifiSysTimer->SetCallbackInfo(UnloadScanSaTimerCallback);
        unloadScanSaTimerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
        int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetWallTimeMs();
        MiscServices::TimeServiceClient::GetInstance()->StartTimer(unloadScanSaTimerId,
            currentTime + TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("StartUnloadScanSaTimer success! unloadScanSaTimerId:%{public}u", unloadScanSaTimerId);
    }
    return;
}
#endif

void WifiScanManager::CheckAndStartScanService(int instId)
{
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState(instId);
    WIFI_LOGI("CheckAndStartScanService scanState: %{public}d", static_cast<int>(scanState));
    if (scanState != WifiOprMidState::CLOSED) {
        /* If the scanning function is enabled when the STA is not enabled, you need to start the scheduled
             scanning function immediately when the STA is enabled. */
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
        if (pService != nullptr) {
            pService->OnClientModeStatusChanged(static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED));
        }
        return;
    }
    if (!WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::OPENING, instId)) {
        WIFI_LOGW("Failed to set scan mid state opening!");
        return;
    }
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_SCAN) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_SCAN);
            break;
        }
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_SCAN);
            break;
        }
        errCode = pService->RegisterScanCallbacks(mScanCallback);
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register scan service callback failed!");
            break;
        }
        errCode = pService->Init();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("init scan service failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            break;
        }
        errCode = pService->SetEnhanceService(pEnhanceService);
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetEnhanceService failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN, instId);
    }
    return;
}

void WifiScanManager::CheckAndStopScanService(int instId)
{
    /**
     * Check unload SCAN service
     * When anytime scanning is enabled and the control policy allows, airplane
     * mode and power saving mode are disabled.   --- Do not disable the scan
     * service. Otherwise, disable the SCAN service.
     */
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState(instId);
    WIFI_LOGI("[CheckAndStopScanService] scanState %{public}d!", static_cast<int>(scanState));
    if (scanState != WifiOprMidState::OPENING && scanState != WifiOprMidState::RUNNING) {
        return;
    }
    ScanControlInfo info;
    WifiConfigCenter::GetInstance().GetScanControlInfo(info, instId);
    if (WifiConfigCenter::GetInstance().IsScanAlwaysActive() && IsAllowScanAnyTime(info) &&
        WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_CLOSE &&
        WifiConfigCenter::GetInstance().GetPowerSavingModeState() == MODE_STATE_CLOSE) {
        return;
    }
    /* After check condition over, begin unload SCAN service */
    if (WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSING, instId)) {
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
        if (pService == nullptr) {
            WIFI_LOGE("[CheckAndStopScanService] scan service is null.");
            WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE, instId);
            WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSED, instId);
            return;
        }
        ErrCode ret = pService->UnInit();
        if (ret != WIFI_OPT_SUCCESS) { // scan service is not exist
            WIFI_LOGE("[CheckAndStopScanService] UnInit service failed!");
        }
        WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSED, instId);
    }
}

void WifiScanManager::CloseScanService(int instId)
{
    WIFI_LOGI("close scan service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN, instId);
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED, instId);
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("CloseScanService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::OPENING || staState == WifiOprMidState::RUNNING) {
        CheckAndStartScanService(instId);
        return;
    }
#ifndef OHOS_ARCH_LITE
    StartUnloadScanSaTimer();
#endif
    return;
}

void WifiScanManager::InitScanCallback(void)
{
    using namespace std::placeholders;
    mScanCallback.OnScanStartEvent = std::bind(&WifiScanManager::DealScanOpenRes, this, _1);
    mScanCallback.OnScanStopEvent = std::bind(&WifiScanManager::DealScanCloseRes, this, _1);
    mScanCallback.OnScanFinishEvent = std::bind(&WifiScanManager::DealScanFinished, this, _1, _2);
    mScanCallback.OnScanInfoEvent = std::bind(&WifiScanManager::DealScanInfoNotify, this, _1, _2);
    mScanCallback.OnStoreScanInfoEvent = std::bind(&WifiScanManager::DealStoreScanInfoEvent, this, _1, _2);
}

void WifiScanManager::DealScanOpenRes(int instId)
{
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
}

void WifiScanManager::DealScanCloseRes(int instId)
{
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE, instId);
}

void WifiScanManager::DealScanFinished(int state, int instId)
{
    WIFI_LOGE("%{public}s, state: %{public}d!", __func__, state);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_SCAN_STATE_CHANGE;
    cbMsg.msgData = state;
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishScanFinishedEvent(state,"OnScanFinished");
}

void WifiScanManager::DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId)
{
    WIFI_LOGI("DealScanInfoNotify: InterScanInfo size: %{public}d", static_cast<int>(results.size()));
    if (results.empty()
        && WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId) == WifiOprMidState::RUNNING) {
        ConvertScanInfo(results);
    }

    if (WifiConfigCenter::GetInstance().GetWifiMidState(instId) == WifiOprMidState::RUNNING) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
        if (pService != nullptr) {
            pService->ConnectivityManager(results);
        }
    }
}

void WifiScanManager::DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId)
{
    WIFI_LOGI("DealStoreScanInfoEvent");
}

void WifiScanManager::ConvertScanInfo(std::vector<InterScanInfo> &interScanInfo)
{
    std::vector<WifiScanInfo> scanInfo;
    WifiConfigCenter::GetInstance().GetScanInfoList(scanInfo);
    for (auto &item : scanInfo) {
        InterScanInfo tmp;
        tmp.ssid = item.ssid;
        tmp.bssid = item.bssid;
        tmp.frequency = item.frequency;
        tmp.rssi = item.rssi;
        tmp.timestamp = item.timestamp;
        tmp.capabilities = item.capabilities;
        tmp.channelWidth = item.channelWidth;
        tmp.centerFrequency0 = item.centerFrequency0;
        tmp.centerFrequency1 = item.centerFrequency1;
        tmp.securityType = item.securityType;
        tmp.infoElems = item.infoElems;
        tmp.features = item.features;
        tmp.band = item.band;
        interScanInfo.emplace_back(tmp);
    }
    WIFI_LOGI("ConvertScanInfo: scanInfo size: %{public}d, interScanInfo size: %{public}d",
        static_cast<int>(scanInfo.size()), static_cast<int>(interScanInfo.size()));
    return;
}
}  // namespace Wifi
}  // namespace OHOS