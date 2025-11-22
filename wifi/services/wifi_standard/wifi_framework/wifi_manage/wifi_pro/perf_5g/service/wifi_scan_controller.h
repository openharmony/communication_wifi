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

#ifndef OHOS_WIFI_PRO_PERF_5G_WIFI_SCAN_CONTROLLER_H
#define OHOS_WIFI_PRO_PERF_5G_WIFI_SCAN_CONTROLLER_H
#include "i_dual_band_scan_strategy.h"
#include <vector>
namespace OHOS {
namespace Wifi {
using namespace std::chrono;
const int32_t MONITOR_AP_FRE_RANGE_SIZE = 3;
const int32_t FAST_SCAN_INTERVAL_SIZE = 3;

class WifiScanController : public IDualBandScanStrategy {
public:
    explicit WifiScanController(std::vector<std::shared_ptr<IDualBandScanStrategy>> scanStrategys);
    ~WifiScanController() override;
    bool TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
        std::unordered_set<int> &monitorApFreqs, int scanStyle = SCAN_DEFAULT_TYPE) override;
    bool IsFastScan() override;
    bool IsActiveScansExhausted() override;
private:
    std::vector<std::shared_ptr<IDualBandScanStrategy>> scanStrategys_;
};

class StrongRssiScanStrategy : public IDualBandScanStrategy {
public:
    StrongRssiScanStrategy();
    ~StrongRssiScanStrategy() override;
    bool TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
        std::unordered_set<int> &monitorApFreqs, int scanStyle = SCAN_DEFAULT_TYPE) override;
    bool IsFastScan() override;
    bool IsActiveScansExhausted() override;
private:
    std::vector<int> strongRssiRange_;
    std::vector<int> strongRssiScanThreshold_;
    std::vector<int> strongRssiScanCount_;
};

class PeriodicScanStrategy : public IDualBandScanStrategy {
public:
    PeriodicScanStrategy();
    ~PeriodicScanStrategy() override;
    bool TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
        std::unordered_set<int> &monitorApFreqs, int scanStyle = SCAN_DEFAULT_TYPE) override;
    bool IsFastScan() override;
    bool IsActiveScansExhausted() override;
private:
    int monitorApNumRange_[MONITOR_AP_FRE_RANGE_SIZE] = {2, 5, 1000};
    int fastScanInterval_[FAST_SCAN_INTERVAL_SIZE][FAST_SCAN_INTERVAL_SIZE] = {{0, 20, 20}, {0, 20, 40}, {0, 60, 60}};
    int scanNumCount_;
    steady_clock::time_point lastScanTimePoint_;
    int GetScanInterval(int monitorApFreqNum);
};

}  // namespace Wifi
}  // namespace OHOS
#endif