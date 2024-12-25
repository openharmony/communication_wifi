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

DEFINE_WIFILOG_SCAN_LABEL("ScanInterface");

namespace OHOS {
namespace Wifi {
ScanInterface::ScanInterface(int instId) : pScanService(nullptr), m_instId(instId)
{}

ScanInterface::~ScanInterface()
{
    WIFI_LOGI("Enter ScanInterface::~ScanInterface.");
}

ErrCode ScanInterface::Init()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::UnInit()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::Scan(bool externFlag, ScanType scanType)
{
    WIFI_LOGI("Enter ScanInterface::Scan\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::ScanWithParam(const WifiScanParams &wifiScanParams, bool externFlag, ScanType scanType)
{
    WIFI_LOGI("Enter ScanInterface::ScanWithParam\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::DisableScan(bool disable)
{
    WIFI_LOGI("Enter ScanInterface::DisableScan, disable=%{public}d.", disable);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnScreenStateChanged(int screenState)
{
    WIFI_LOGI("Enter ScanInterface::OnScreenStateChanged, screenState=%{public}d.", screenState);
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnStandbyStateChanged(bool sleeping)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnClientModeStatusChanged(int staStatus)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnAppRunningModeChanged(ScanMode appRunMode)
{
    WIFI_LOGI("Enter ScanInterface::OnAppRunningModeChanged, appRunMode=%{public}d\n", static_cast<int>(appRunMode));
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnMovingFreezeStateChange()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnCustomControlStateChanged(int customScene, int customSceneStatus)
{
    WIFI_LOGI("Enter ScanInterface::OnCustomControlStateChanged\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnGetCustomSceneState(std::map<int, time_t>& sceneMap)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnControlStrategyChanged()
{
    WIFI_LOGI("Enter ScanInterface::OnControlStrategyChanged\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::OnAutoConnectStateChanged(bool success)
{
    WIFI_LOGI("Enter ScanInterface::OnAutoConnectStateChanged\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::RegisterScanCallbacks(const IScanSerivceCallbacks &scanSerivceCallbacks)
{
    mScanSerivceCallbacks = scanSerivceCallbacks;
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::SetEnhanceService(IEnhanceService *enhanceService)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanInterface::SetNetworkInterfaceUpDown(bool upDown)
{
    return WIFI_OPT_SUCCESS;
}

}  // namespace Wifi
}  // namespace OHOS