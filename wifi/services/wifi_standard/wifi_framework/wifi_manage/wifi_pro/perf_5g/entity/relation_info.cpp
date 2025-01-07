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

#include "relation_info.h"
#include "dual_band_utils.h"
#include <algorithm>
#include <cstdlib>
#include "wifi_logger.h"
#include "wifi_pro_common.h"
#include "wifi_global_func.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("RelationInfo");

constexpr int MAYBE_SAME_ROUTER_AP = 0;
constexpr int NO_SAME_ROUTER_AP = 1;
constexpr int ADJACENT_RELATIONSHIP_RSSI_THRESHOLD = 10;
constexpr int RSSI_RANGE_LOW_DBM = -105;
constexpr int RSSI_RANGE_HIGH_DBM = -45;
constexpr int SWITCH_SCAN_RSSI_GAP_ADJACENT = 5;
constexpr int MIN_DALTA_TARGET_RSSI = -5;
constexpr int MAX_DALTA_TARGET_RSSI = 5;
constexpr int BSSID_RSSI_STEP_DBM = 5;
constexpr int BSSID_RSSI_OVERFLOW_DBM = 10;

RelationInfo::RelationInfo() : id_(-1)
{}
RelationInfo::RelationInfo(std::string bssid, std::string relationBssid, std::string scanRssiThreshold)
    : bssid24g_(bssid), relationBssid5g_(relationBssid)
{
    id_ = -1;
    maxScanRssi_ = INVALID_RSSI;
    minTargetRssi_ = INVALID_RSSI;
    meanP_ = DualBandUtils::GetMeanPforLearnAlg();
    meanPversion_ = DualBandUtils::GetMeanPVersion();
    maxRssi_ = INVALID_RSSI;
    relationRssiWhenMaxRssi_ = INVALID_RSSI;
    maxRelationRssi_ = INVALID_RSSI;
    rssiWhenMaxRelationRssi_ = INVALID_RSSI;
    if (DualBandUtils::IsSameRouterAp(bssid, relationBssid)) {
        relateType_ = MAYBE_SAME_ROUTER_AP;
    } else {
        relateType_ = NO_SAME_ROUTER_AP;
    }
    SetSameApTriggerScanRssiThreshold(scanRssiThreshold);
}
RelationInfo::~RelationInfo()
{}
bool RelationInfo::IsOnSameRouter()
{
    return (relateType_ == MAYBE_SAME_ROUTER_AP) && IsAdjacent();
}
bool RelationInfo::IsAdjacent()
{
    int rssiGapOn24g = abs(maxRssi_ - relationRssiWhenMaxRssi_);
    if (maxRelationRssi_ != INVALID_RSSI
        && rssiWhenMaxRelationRssi_ != INVALID_RSSI) {
        int rssiGapOn5g = abs(maxRelationRssi_ - rssiWhenMaxRelationRssi_);
        return rssiGapOn24g <= ADJACENT_RELATIONSHIP_RSSI_THRESHOLD &&
            rssiGapOn5g <= ADJACENT_RELATIONSHIP_RSSI_THRESHOLD;
    }
    return rssiGapOn24g <= ADJACENT_RELATIONSHIP_RSSI_THRESHOLD;
}
void RelationInfo::SetMaxRssiOnRelationAp(int maxRelationRssi, int rssiWhenMaxRelationRssi)
{
    maxRelationRssi_ = maxRelationRssi;
    rssiWhenMaxRelationRssi_ = rssiWhenMaxRelationRssi;
}
void RelationInfo::SetMaxRssi(int maxRssi, int relationRssiWhenMaxRssi)
{
    maxRssi_ = maxRssi;
    relationRssiWhenMaxRssi_ = relationRssiWhenMaxRssi;
}
std::string RelationInfo::GetScanRssiThreshold()
{
    if (sameApTriggerScanRssiThreshold_.empty()) {
        return "";
    }
    return DualBandUtils::IntArrToString(sameApTriggerScanRssiThreshold_, DualBandUtils::comma);
}
int RelationInfo::GetTriggerScanRssiThreshold(int switchRssiThreshold)
{
    if (IsOnSameRouter()) {
        WIFI_LOGI("%{public}s, is on same router", __FUNCTION__);
        return GetSameApScanRssiThreshold(switchRssiThreshold);
    }
    if (IsAdjacent()) {
        WIFI_LOGI("%{public}s, is adjacent ap", __FUNCTION__);
        return switchRssiThreshold - SWITCH_SCAN_RSSI_GAP_ADJACENT;
    }
    if (maxScanRssi_ != INVALID_RSSI
        && minTargetRssi_ != INVALID_RSSI) {
        int daltaTargetRssi = switchRssiThreshold - minTargetRssi_;
        if (daltaTargetRssi < MIN_DALTA_TARGET_RSSI) {
            daltaTargetRssi = MIN_DALTA_TARGET_RSSI;
        } else if (daltaTargetRssi > MAX_DALTA_TARGET_RSSI) {
            daltaTargetRssi = MAX_DALTA_TARGET_RSSI;
        }
        WIFI_LOGI("%{public}s, not adjacent ap,maxrssi=%{public}d,maxScanRssi_=%{public}d, daltaTargetRssi=%{public}d",
            __FUNCTION__, maxRssi_, maxScanRssi_, daltaTargetRssi);
        return std::min(maxRssi_, maxScanRssi_ - daltaTargetRssi);
    }
    WIFI_LOGI("%{public}s, not adjacent ap,return maxrssi=%{public}d", __FUNCTION__, maxRssi_);
    return maxRssi_;
}
int RelationInfo::UpdateSameApTriggerScanRssiThreshold(int triggerScanRssiThreshold,
    int switchRssiThreshold, int current24gApRssi, int relation5gApRssi)
{
    if (current24gApRssi < RSSI_RANGE_LOW_DBM) {
        return triggerScanRssiThreshold;
    }
    int newTriggerScanRssiTh = triggerScanRssiThreshold;
    if (relation5gApRssi < switchRssiThreshold) {
        newTriggerScanRssiTh += BSSID_RSSI_STEP_DBM;
        if (newTriggerScanRssiTh > RSSI_RANGE_HIGH_DBM) {
            newTriggerScanRssiTh = RSSI_RANGE_HIGH_DBM;
        }
    } else {
        if (relation5gApRssi > (switchRssiThreshold + BSSID_RSSI_OVERFLOW_DBM) &&
            current24gApRssi < (triggerScanRssiThreshold + BSSID_RSSI_OVERFLOW_DBM)) {
            newTriggerScanRssiTh -= BSSID_RSSI_STEP_DBM;
        }
    }
    if (switchRssiThreshold == RSSI_RANGE_HIGH_DBM) {
        return triggerScanRssiThreshold;
    }
    int size = RSSI_RANGE_HIGH_DBM - RSSI_RANGE_LOW_DBM + 1;
    for (int index = 0; index < size; ++index) {
        sameApTriggerScanRssiThreshold_[index] =
            ((RSSI_RANGE_HIGH_DBM - newTriggerScanRssiTh) *
                (sameApTriggerScanRssiThreshold_[index] - switchRssiThreshold))
                    / (RSSI_RANGE_HIGH_DBM - switchRssiThreshold) + newTriggerScanRssiTh;
    }
    return GetSameApScanRssiThreshold(switchRssiThreshold);
}
void RelationInfo::SetSameApTriggerScanRssiThreshold(std::string scanRssiThreshold)
{
    if (!IsOnSameRouter()) {
        return;
    }
    if (scanRssiThreshold.empty()) {
        int size = RSSI_RANGE_HIGH_DBM - RSSI_RANGE_LOW_DBM + 1;
        for (int index = 0; index < size; index++) {
            sameApTriggerScanRssiThreshold_.push_back(RSSI_RANGE_LOW_DBM + index);
        }
    } else {
        sameApTriggerScanRssiThreshold_ = SplitStringToIntVector(scanRssiThreshold, ",");
    }
}
int RelationInfo::GetSameApScanRssiThreshold(int switchRssiThreshold)
{
    if (switchRssiThreshold < RSSI_RANGE_LOW_DBM || switchRssiThreshold > RSSI_RANGE_HIGH_DBM) {
        WIFI_LOGW("%{public}s, switchRssiThre(%{public}d) over range, low(%{public}d), high(%{public}d), return 0",
            __FUNCTION__, switchRssiThreshold, RSSI_RANGE_LOW_DBM, RSSI_RANGE_HIGH_DBM);
        return 0;
    }
    if (sameApTriggerScanRssiThreshold_.empty()) {
        WIFI_LOGW("%{public}s, sameApTriggerScanRssiThreshold_ is empty, return 0", __FUNCTION__);
        return 0;
    }
    return sameApTriggerScanRssiThreshold_[switchRssiThreshold - RSSI_RANGE_LOW_DBM];
}

}  // namespace Wifi
}  // namespace OHOS