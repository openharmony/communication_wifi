/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "wifi_scan_controller.h"
#include "wifi_logger.h"
#include "wifi_service_manager.h"
#include "iscan_service.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiScanController");

WifiScanController::WifiScanController(std::vector<std::shared_ptr<IDualBandScanStrategy>> scanStrategys)
    : scanStrategys_(scanStrategys)
{}
WifiScanController::~WifiScanController()
{}
bool WifiScanController::TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
    std::unordered_set<int> &monitorApFreqs, int scanStyle)
{
    if (scanStrategys_.empty()) {
        WIFI_LOGI("WifiScanController::TryToScanv, scanStrategys is empty");
        return false;
    }
    for (auto &scanStrategy : scanStrategys_) {
        if (scanStrategy->TryToScan(rssi, needScanInMonitor, connectedApFreq, monitorApFreqs, scanStyle)) {
            return true;
        }
    }
    return false;
}
bool WifiScanController::IsFastScan()
{
    for (auto &scanStrategy : scanStrategys_) {
        if (scanStrategy->IsFastScan()) {
            return true;
        }
    }
    return false;
}
bool WifiScanController::IsActiveScansExhausted()
{
    for (auto &scanStrategy : scanStrategys_) {
        if (scanStrategy->IsActiveScansExhausted()) {
            return true;
        }
    }
    return false;
}

StrongRssiScanStrategy::StrongRssiScanStrategy()
    : strongRssiRange_({-45, -55, -65}), strongRssiScanThreshold_({1, 1, 1}),
    strongRssiScanCount_({0, 0, 0})
{}
StrongRssiScanStrategy::~StrongRssiScanStrategy()
{}
bool StrongRssiScanStrategy::TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
    std::unordered_set<int> &monitorApFreqs, int scanStyle)
{
    if (rssi < strongRssiRange_.back()) {
        return false;
    }
    bool canScan = false;
    int strongRssiRangeIndex;
    int size = static_cast<int>(strongRssiRange_.size());
    for (int index = 0; index < size; index++) {
        if (rssi >= strongRssiRange_[index]) {
            if (strongRssiScanCount_[index] < strongRssiScanThreshold_[index]) {
                canScan = true;
                strongRssiRangeIndex = index;
            }
            break;
        }
    }
    if (canScan) {
        WIFI_LOGI("StrongRssiTryToScan, start to scan rssi = %{public}d", rssi);
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst();
        if (pScanService == nullptr) {
            return false;
        }
        auto result = pScanService->Scan(true, ScanType::SCAN_TYPE_5G_AP, scanStyle);
        if (result == WIFI_OPT_SUCCESS) {
            strongRssiScanCount_[strongRssiRangeIndex]++;
            return true;
        } else {
            WIFI_LOGW("StrongRssiTryToScan scan failed, result = %{public}d", result);
        }
    }
    return false;
}
bool StrongRssiScanStrategy::IsFastScan()
{
    return false;
}
bool StrongRssiScanStrategy::IsActiveScansExhausted()
{
    return false;
}
// PeriodicScanStrategy
constexpr int FAST_SCAN_NUM = 3;
constexpr int SCAN_NUM_THRESHOLD = 5;
constexpr int DEFAULT_SCAN_INTERVAL = 60;

PeriodicScanStrategy::PeriodicScanStrategy() : scanNumCount_(0)
{
    lastScanTimePoint_ = steady_clock::now();
}
PeriodicScanStrategy::~PeriodicScanStrategy()
{}
bool PeriodicScanStrategy::TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
    std::unordered_set<int> &monitorApFreqs, int scanStyle)
{
    if (IsActiveScansExhausted()) {
        return false;
    }
    if (!needScanInMonitor) {
        return false;
    }
    int scanInterval = GetScanInterval(static_cast<int>(monitorApFreqs.size()));
    steady_clock::time_point nowTimePoint = steady_clock::now();
    duration<double> elapsedSeconds = nowTimePoint - lastScanTimePoint_;
    if (elapsedSeconds.count() < scanInterval) {
        return false;
    }
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pScanService == nullptr) {
        WIFI_LOGI("PeriodicTryToScan scan failed, GetScanServiceInst is return null");
        return false;
    }
    ErrCode scanResult;
    WIFI_LOGI("PeriodicTryToScan, start scan on rssi %{public}d IsFastScan(%{public}d)", rssi, IsFastScan());
    if (IsFastScan()) {
        std::vector<int> scanFreqs;
        scanFreqs.assign(monitorApFreqs.begin(), monitorApFreqs.end());
        scanFreqs.push_back(connectedApFreq);
        WifiScanParams wifiScanParams;
        wifiScanParams.freqs = scanFreqs;
        wifiScanParams.scanStyle = scanStyle;
        scanResult = pScanService->ScanWithParam(wifiScanParams, true, ScanType::SCAN_TYPE_5G_AP);
    } else {
        scanResult = pScanService->Scan(true, ScanType::SCAN_TYPE_5G_AP, scanStyle);
    }
    if (scanResult == WIFI_OPT_SUCCESS) {
        lastScanTimePoint_ = steady_clock::now();
        scanNumCount_++;
        return true;
    }
    WIFI_LOGW("PeriodicTryToScan, scan failed, result = %{public}d", scanResult);
    return false;
}
bool PeriodicScanStrategy::IsFastScan()
{
    return scanNumCount_ < FAST_SCAN_NUM;
}
bool PeriodicScanStrategy::IsActiveScansExhausted()
{
    return scanNumCount_ >= SCAN_NUM_THRESHOLD;
}
int PeriodicScanStrategy::GetScanInterval(int monitorApFreqNum)
{
    if (!IsFastScan()) {
        return DEFAULT_SCAN_INTERVAL;
    }
    for (int index = 0; index < MONITOR_AP_FRE_RANGE_SIZE; index++) {
        if (monitorApFreqNum <= monitorApNumRange_[index]) {
            return fastScanInterval_[index][scanNumCount_];
        }
    }
    return DEFAULT_SCAN_INTERVAL;
}
}  // namespace Wifi
}  // namespace OHOS