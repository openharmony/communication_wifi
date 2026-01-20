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

#ifndef OHOS_WIFI_PRO_PERF_5G_I_DUAL_BAND_DATA_SOURCE_H
#define OHOS_WIFI_PRO_PERF_5G_I_DUAL_BAND_DATA_SOURCE_H

#include <unordered_set>
#include <vector>
#include "switchable_ap_info.h"
#include "relation_info.h"

namespace OHOS {
namespace Wifi {

class IDualBandDataSource {
public:
    virtual ~IDualBandDataSource() = default;
    virtual bool Connection();
    virtual bool QueryApInfo(std::string &bssid, SwitchableApInfo &apInfo);
    virtual bool QueryRelationInfo(std::string &bssid, std::vector<RelationInfo> &relationInfos);
    virtual bool DeleteAll(std::unordered_set<std::string> &bssids);
    virtual bool RemoveDuplicateDatas();
    virtual bool SaveApInfo(SwitchableApInfo &apInfo);
    virtual void SaveApInfos(std::vector<SwitchableApInfo> &apInfos);
    virtual void SaveRelationInfos(std::vector<RelationInfo> &relationInfos);
    virtual bool QueryApInfos(std::unordered_set<std::string> &bssidSet, std::vector<SwitchableApInfo> &apInfos);
};

}  // namespace Wifi
}  // namespace OHOS

#endif