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

#ifndef OHOS_WIFI_PRO_PERF_5G_RELATION_INFO_H
#define OHOS_WIFI_PRO_PERF_5G_RELATION_INFO_H

#include <string>
#include "wifi_pro_common.h"

namespace OHOS {
namespace Wifi {

class RelationInfo {
public:
    RelationInfo();
    RelationInfo(std::string bssid, std::string relationBssid, std::string scanRssiThreshold = "");
    ~RelationInfo();
    bool IsOnSameRouter();
    bool IsAdjacent();
    void SetMaxRssiOnRelationAp(int maxRelationRssi, int rssiWhenMaxRelationRssi);
    void SetMaxRssi(int maxRssi, int relationRssiWhenMaxRssi);
    std::string GetScanRssiThreshold();
    int GetTriggerScanRssiThreshold(int switchRssiThreshold);
    int UpdateSameApTriggerScanRssiThreshold(int triggerScanRssiThreshold,
        int switchRssiThreshold, int current24gApRssi, int relation5gApRssi);
    void SetSameApTriggerScanRssiThreshold(std::string scanRssiThreshold);
public:
    long id_;
    std::string bssid24g_;
    std::string relationBssid5g_;
    int relateType_;
    int maxScanRssi_;
    int minTargetRssi_;
    std::string meanP_;
    int meanPversion_;
    int maxRssi_;
    int relationRssiWhenMaxRssi_;
    int maxRelationRssi_;
    int rssiWhenMaxRelationRssi_;
private:
    std::vector<int> sameApTriggerScanRssiThreshold_;
    int GetSameApScanRssiThreshold(int switchRssiThreshold);
};

}  // namespace Wifi
}  // namespace OHOS
#endif