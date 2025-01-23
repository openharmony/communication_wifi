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

#include "relation_ap.h"
#include "wifi_logger.h"
#include "wifi_pro_common.h"
#include "dual_band_utils.h"
#include "wifi_global_func.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("RelationAp");

constexpr int DEFAULT_TARGET_RSSI = -65;
constexpr int GOOD_RTT_THRESHOLD = 1500;
constexpr int WIFI_SCAN_LARGER_INTERVAL_THRESHOLDS = 20;
constexpr int WIFI_SCAN_LARGER_INTERVAL = 10;
constexpr int WIFI_SCAN_INTERVAL = 5;
constexpr int WIFI_MAX_SCAN_THRESHOLD = -30;
constexpr int WIFI_MIN_SCAN_THRESHOLD = -90;


RelationAp::RelationAp()
{}
RelationAp::~RelationAp()
{}
void RelationAp::UpdateInfo(InterScanInfo &relationApScanInfo, int currentApRssi)
{
    apInfo_.rssi = relationApScanInfo.rssi;
    apInfo_.frequency = relationApScanInfo.frequency;
    apInfo_.channelWidth = relationApScanInfo.channelWidth;
    apInfo_.wifiCategory = relationApScanInfo.supportedWifiCategory;
    apInfo_.ssid = relationApScanInfo.ssid;

    if (IsValid5GHz(apInfo_.frequency)) {
        if (relationInfo_.maxRssi_ < currentApRssi || (relationInfo_.maxRssi_ == currentApRssi
            && relationInfo_.relationRssiWhenMaxRssi_ < apInfo_.rssi)) {
            relationInfo_.maxRssi_ = currentApRssi;
            relationInfo_.relationRssiWhenMaxRssi_ = apInfo_.rssi;
        }
    } else {
        if (relationInfo_.maxRelationRssi_ < currentApRssi
            || (relationInfo_.maxRelationRssi_ == currentApRssi
            && relationInfo_.rssiWhenMaxRelationRssi_ < apInfo_.rssi)) {
            relationInfo_.maxRelationRssi_ = currentApRssi;
            relationInfo_.rssiWhenMaxRelationRssi_ = apInfo_.rssi;
        }
    }
    SetMaxRssiOnScanResult(relationApScanInfo.rssi);
}
void RelationAp::InitMonitorInfo()
{
    switch5gRssiThreshold_ = apInfo_.apConnectionInfo.GetRssiSatisfyRttThreshold(GOOD_RTT_THRESHOLD,
        DEFAULT_TARGET_RSSI);
    triggerScanRssiThreshold_ = relationInfo_.GetTriggerScanRssiThreshold(switch5gRssiThreshold_);
    initalTriggerScanRssiTh_ = triggerScanRssiThreshold_;
    WIFI_LOGI("%{public}s, switch5gRssiThreshold_(%{public}d), triggerScanRssiThreshold_(%{public}d)",
        __FUNCTION__, switch5gRssiThreshold_, triggerScanRssiThreshold_);
}
bool RelationAp::IsSatisfySwitchRssi()
{
    return apInfo_.rssi >= switch5gRssiThreshold_;
}
void RelationAp::UpdateTriggerScanRssiThreshold(int currentApRssi)
{
    if (relationInfo_.IsAdjacent() && currentApRssi >= triggerScanRssiThreshold_) {
        return;
    }
    if (!relationInfo_.IsAdjacent() && currentApRssi <= triggerScanRssiThreshold_) {
        return;
    }
    if (relationInfo_.IsOnSameRouter()) {
        triggerScanRssiThreshold_ = relationInfo_.UpdateSameApTriggerScanRssiThreshold(triggerScanRssiThreshold_,
            switch5gRssiThreshold_, currentApRssi, apInfo_.rssi);
    } else {
        if (relationInfo_.IsAdjacent()) {
            int scanInterval = GetAdjacentApUpdateTriggerScanRssiStep();
            triggerScanRssiThreshold_ += scanInterval;
            if (triggerScanRssiThreshold_ >= WIFI_MAX_SCAN_THRESHOLD) {
                triggerScanRssiThreshold_ = initalTriggerScanRssiTh_;
            }
        } else {
            triggerScanRssiThreshold_ -= WIFI_SCAN_INTERVAL;
            if (triggerScanRssiThreshold_ <= WIFI_MIN_SCAN_THRESHOLD) {
                triggerScanRssiThreshold_ = initalTriggerScanRssiTh_;
            }
        }
    }
}
bool RelationAp::CanTriggerScan(int currentApEstimatedRssi)
{
    if (relationInfo_.IsAdjacent()) {
        if (currentApEstimatedRssi >= triggerScanRssiThreshold_) {
            return true;
        }
    } else {
        if (currentApEstimatedRssi <= triggerScanRssiThreshold_) {
            return true;
        }
    }
    return false;
}
void RelationAp::IsSelectedSwitch()
{
    relationInfo_.maxScanRssi_ = triggerScanRssiThreshold_;
    relationInfo_.minTargetRssi_ = switch5gRssiThreshold_;
}
void RelationAp::SetMaxRssiOnScanResult(int rssi)
{
    if (apInfo_.rssi > maxRssiOnScanResult_) {
        maxRssiOnScanResult_ = apInfo_.rssi;
    }
}
int RelationAp::GetAdjacentApUpdateTriggerScanRssiStep()
{
    if (maxRssiOnScanResult_ == INVALID_RSSI) {
        return WIFI_SCAN_INTERVAL;
    }
    if (switch5gRssiThreshold_ - maxRssiOnScanResult_ > WIFI_SCAN_LARGER_INTERVAL_THRESHOLDS) {
        return WIFI_SCAN_LARGER_INTERVAL;
    }
    return WIFI_SCAN_INTERVAL;
}

}  // namespace Wifi
}  // namespace OHOS