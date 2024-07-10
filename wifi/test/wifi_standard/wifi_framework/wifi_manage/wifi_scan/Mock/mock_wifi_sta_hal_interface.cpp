/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "mock_wifi_scan_interface.h"

namespace OHOS {
namespace Wifi {
namespace WifiStaHalInterface {
WifiErrorNo Scan(const WifiHalScanParam &scanParam)
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.scan ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.queryScanInfos ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StartPnoScan(const WifiHalPnoScanParam &scanParam)
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.startPnoScan ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StopPnoScan(void)
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.stopPnoScan ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.getSupportFre ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StartWifi()
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.startWifi ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StoPWifi()
{
    return MockWifiScanInterface::GetInstance().pWifiStaHalInfo.stopWifi ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}
};
}  // namespace Wifi
}  // namespace OHOS