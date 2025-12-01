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

#ifndef OHOS_WIFI_PRO_PERF_5G_I_DUAL_BAND_SCAN_STRATEGY_H
#define OHOS_WIFI_PRO_PERF_5G_I_DUAL_BAND_SCAN_STRATEGY_H
#include <unordered_set>
#include "wifi_scan_msg.h"
namespace OHOS {
namespace Wifi {

class IDualBandScanStrategy {
public:
    virtual ~IDualBandScanStrategy() = default;
    virtual bool TryToScan(int rssi, bool needScanInMonitor, int connectedApFreq,
        std::unordered_set<int> &monitorApFreqs, int scanStyle = SCAN_DEFAULT_TYPE) = 0;
    virtual bool IsFastScan() = 0;
    virtual bool IsActiveScansExhausted() = 0;
};

}  // namespace Wifi
}  // namespace OHOS
#endif