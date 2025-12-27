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
#include "scan_interface.h"
#include "wifi_logger.h"
#include "wifi_settings.h"

DEFINE_WIFILOG_SCAN_LABEL("ScanInterface");

namespace OHOS {
namespace Wifi {
ScanInterface::ScanInterface(int instId) : pScanService(nullptr), m_instId(instId)
{}

ScanInterface::~ScanInterface()
{
    WIFI_LOGI("Enter ScanInterface::~ScanInterface.");
    std::lock_guard<std::mutex> lock(mutex);
    if (pScanService != nullptr) {
        delete pScanService;
        pScanService = nullptr;
    }
}

ErrCode ScanInterface::Init()
{
    WIFI_LOGI("Enter ScanInterface::Init.\n");

    std::lock_guard<std::mutex> lock(mutex);
    if (pScanService == nullptr) {
        pScanService = new (std::nothrow)ScanService(m_instId);
        if (pScanService == nullptr) {
            WIFI_LOGE("New ScanService failed.\n");
            return WIFI_OPT_INVALID_PARAM;
        }

        if (!(pScanService->InitScanService(mScanSerivceCallbacks))) {
            WIFI_LOGE("InitScanService failed.\n");
            delete pScanService;
            pScanService = nullptr;
            return WIFI_OPT_INVALID_PARAM;
        }
    }

    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::UnInit()
{
    WIFI_LOGI("Enter ScanInterface::UnInit.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->UnInitScanService();
    return WIFI_OPT_SUCCESS;
}

// scanType takes precedence over externFlag, when scanType is not SCAN_DEFAULT, externFlag invalid
ErrCode ScanInterface::Scan(bool externFlag, ScanType scanType, int scanStyle)
{
    WIFI_LOGI("Enter ScanInterface::Scan, scanType:%{public}d, scanStyle:%{public}d\n",
        static_cast<int>(scanType), static_cast<int>(scanStyle));
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    if (scanType != ScanType::SCAN_DEFAULT) {
        return pScanService->Scan(scanType, scanStyle);
    }
    return pScanService->Scan(externFlag ? ScanType::SCAN_TYPE_EXTERN : ScanType::SCAN_TYPE_NATIVE_EXTERN, scanStyle);
}
 
// scanType takes precedence over externFlag, when scanType is not SCAN_DEFAULT, externFlag invalid
ErrCode ScanInterface::ScanWithParam(const WifiScanParams &wifiScanParams, bool externFlag,
    ScanType scanType)
{
    WIFI_LOGI("Enter ScanInterface::ScanWithParam\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    if (scanType != ScanType::SCAN_DEFAULT) {
        return pScanService->ScanWithParam(wifiScanParams, scanType);
    }
    return pScanService->ScanWithParam(wifiScanParams,
        externFlag ? ScanType::SCAN_TYPE_EXTERN : ScanType::SCAN_TYPE_NATIVE_EXTERN);
}

ErrCode ScanInterface::DisableScan(bool disable)
{
    WIFI_LOGI("Enter ScanInterface::DisableScan, disable=%{public}d.", disable);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    return pScanService->DisableScan(disable);
}

ErrCode ScanInterface::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    WIFI_LOGI("Enter ScanInterface::StartWifiPnoScan");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    return pScanService->StartWifiPnoScan(isStartAction, periodMs, suspendReason);
}

ErrCode ScanInterface::OnScreenStateChanged(int screenState)
{
    WIFI_LOGI("Enter ScanInterface::OnScreenStateChanged, screenState=%{public}d.", screenState);

    if (screenState != MODE_STATE_OPEN && screenState != MODE_STATE_CLOSE) {
        WIFI_LOGE("screenState param is error");
        return WIFI_OPT_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->HandleScreenStatusChanged();
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnStandbyStateChanged(bool sleeping)
{
    WIFI_LOGI("Enter ScanInterface::OnStandbyStateChanged, sleeping=%{public}d.", sleeping);
    if (sleeping) {
        return WIFI_OPT_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    return pScanService->Scan(ScanType::SCAN_TYPE_SYSTEMTIMER);
}

ErrCode ScanInterface::OnClientModeStatusChanged(int staStatus, int networkId)
{
    WIFI_LOGI("Enter ScanInterface::OnClientModeStatusChanged, staStatus=%{public}d.", staStatus);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    if (staStatus == static_cast<int>(OperateResState::CONNECT_NETWORK_DISABLED)
        || staStatus == static_cast<int>(OperateResState::CONNECT_NETWORK_ENABLED)) {
        pScanService->HandleNetworkQualityChanged(staStatus);
    } else if (staStatus == static_cast<int>(OperateResState::CONNECT_MISS_MATCH)) {
        if (networkId != INVALID_NETWORK_ID) {
            WifiDeviceConfig deviceConfig;
            WifiScanParams wifiScanParams;
            if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig, m_instId) != 0) {
                WIFI_LOGE("OnClientModeStatusChanged GetDeviceConfig failed networkId=%{public}d.", networkId);
                return WIFI_OPT_FAILED;
            }
            WIFI_LOGI("start new scan for hidden ssid");
            wifiScanParams.ssid = std::string(deviceConfig.ssid);
            wifiScanParams.band = SCAN_BAND_BOTH_WITH_DFS;
            pScanService->ScanWithParam(wifiScanParams, ScanType::SCAN_TYPE_NATIVE_EXTERN);
        }
    } else {
        pScanService->HandleStaStatusChanged(staStatus);
        pScanService->SetStaCurrentTime();
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnAppRunningModeChanged(ScanMode appRunMode)
{
    WIFI_LOGI("Enter ScanInterface::OnAppRunningModeChanged, appRunMode=%{public}d\n", static_cast<int>(appRunMode));
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnMovingFreezeStateChange()
{
    LOGI("Enter ScanInterface::OnMovingFreezeStateChange");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->HandleMovingFreezeChanged();
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnCustomControlStateChanged(int customScene, int customSceneStatus)
{
    WIFI_LOGI("Enter ScanInterface::OnCustomControlStateChanged\n");

    if (customSceneStatus != MODE_STATE_OPEN && customSceneStatus != MODE_STATE_CLOSE) {
        WIFI_LOGE("screenState param is error");
        return WIFI_OPT_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->HandleCustomStatusChanged(customScene, customSceneStatus);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnGetCustomSceneState(std::map<int, time_t>& sceneMap)
{
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("Enter ScanInterface::OnGetCustomSceneState\n");
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->HandleGetCustomSceneState(sceneMap);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnControlStrategyChanged()
{
    WIFI_LOGI("Enter ScanInterface::OnControlStrategyChanged\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->ClearScanControlValue();
    pScanService->GetScanControlInfo();
    pScanService->SystemScanProcess(true);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnAutoConnectStateChanged(bool success)
{
    WIFI_LOGI("Enter ScanInterface::OnAutoConnectStateChanged, success:%{public}d", success);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->HandleAutoConnectStateChanged(success);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::RegisterScanCallbacks(const IScanSerivceCallbacks &scanSerivceCallbacks)
{
    mScanSerivceCallbacks = scanSerivceCallbacks;
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::SetEnhanceService(IEnhanceService *enhanceService)
{
    WIFI_LOGI("Enter ScanInterface::SetEnhanceService\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->SetEnhanceService(enhanceService);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::SetNetworkInterfaceUpDown(bool upDown)
{
    LOGI("Enter ScanInterface::SetNetworkInterfaceUpDown.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    if (pScanService->SetNetworkInterfaceUpDown(upDown) != WIFI_OPT_SUCCESS) {
        LOGE("SetNetworkInterfaceUpDown failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::ResetScanInterval()
{
    WIFI_LOGI("Enter ScanInterface::ResetScanInterval.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pScanService, WIFI_OPT_FAILED);
    pScanService->ResetScanInterval();
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS