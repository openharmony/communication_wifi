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

#ifndef OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_REPOSTITORY_H
#define OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_REPOSTITORY_H

#include "i_dual_band_data_source.h"
#include "connected_ap.h"
#include <memory>
#include <vector>
#include "relation_ap.h"
#include <unordered_set>

namespace OHOS {
namespace Wifi {

class DualBandRepostitory {
public:
    explicit DualBandRepostitory(std::shared_ptr<IDualBandDataSource> pDualBandDataSource);
    ~DualBandRepostitory();
    void LoadApHistoryInfo(ApInfo &apInfo, bool &hasHistoryInfo);
    void LoadRelationApInfo(std::string bssid, std::vector<RelationAp> &relationApInfo,
        std::function<std::string(RelationInfo&)> GetRelationBssidFunc);
    void DeleteAll(std::unordered_set<std::string> &bssids);
    void RemoveDuplicateDatas();
    void SaveApInfo(ApInfo &apInfo);
    void SaveRelationApInfo(std::vector<RelationAp> &relationApInfo);
    std::vector<RelationAp> QueryRelationApInfos(std::unordered_set<std::string> &bssidSet);
private:
    std::shared_ptr<IDualBandDataSource> pDualBandDataSource_;
};

}  // namespace Wifi
}  // namespace OHOS
#endif