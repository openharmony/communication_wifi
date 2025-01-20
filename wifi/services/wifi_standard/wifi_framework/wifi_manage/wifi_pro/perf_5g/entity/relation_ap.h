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

#ifndef OHOS_WIFI_PRO_PERF_5G_RELATION_AP_H
#define OHOS_WIFI_PRO_PERF_5G_RELATION_AP_H
#include "relation_info.h"
#include "ap_connection_info.h"
#include <string>
#include "inter_scan_info.h"
#include "network_status_history_manager.h"
#include "connected_ap.h"

namespace OHOS {
namespace Wifi {

class RelationAp {
public:
    RelationAp();
    ~RelationAp();
    void UpdateInfo(InterScanInfo &relationApScanInfo, int currentApRssi);
    void InitMonitorInfo();
    bool IsSatisfySwitchRssi();
    void UpdateTriggerScanRssiThreshold(int currentApRssi);
    bool CanTriggerScan(int currentApEstimatedRssi);
    void IsSelectedSwitch();
public:
    ApInfo apInfo_;
    RelationInfo relationInfo_;
private:
    int triggerScanRssiThreshold_;
    int switch5gRssiThreshold_;
    int maxRssiOnScanResult_;
    int initalTriggerScanRssiTh_;
    void SetMaxRssiOnScanResult(int rssi);
    int GetAdjacentApUpdateTriggerScanRssiStep();
};

}  // namespace Wifi
}  // namespace OHOS
#endif