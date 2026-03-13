/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") override;
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

#ifndef OHOS_WIFI_PRO_5G_PERF_DUAL_BAND_RDB_HELPER_H
#define OHOS_WIFI_PRO_5G_PERF_DUAL_BAND_RDB_HELPER_H

#include "i_dual_band_data_source.h"
#include "wifi_rdb_manager.h"

namespace OHOS {
namespace Wifi {

class DualBandRdbHelper : public IDualBandDataSource {
public:
    bool Connection() override;
    bool QueryApInfo(std::string &bssid, SwitchableApInfo &apInfo) override;
    bool QueryRelationInfo(std::string &bssid, std::vector<RelationInfo> &relationInfos) override;
    bool DeleteAll(std::unordered_set<std::string> &bssids) override;
    bool RemoveDuplicateDatas() override;
    bool SaveApInfo(SwitchableApInfo &apInfo) override;
    void SaveApInfos(std::vector<SwitchableApInfo> &apInfos) override;
    void SaveRelationInfos(std::vector<RelationInfo> &relationInfos) override;
    bool QueryApInfos(std::unordered_set<std::string> &bssidSet, std::vector<SwitchableApInfo> &apInfos) override;
private:
    bool SaveRelationInfo(RelationInfo &relationInfo);
    void BuildApInfo(NativeRdb::RowEntity &rowEntity, SwitchableApInfo &apInfo);
    void CreateApRecordBucket(SwitchableApInfo &apInfo, NativeRdb::ValuesBucket &valuesBucket);
    void CreateRelationBucket(RelationInfo &relationInfo, NativeRdb::ValuesBucket &valuesBucket);
    void BuildRelationInfo(RelationInfo &relationInfo, const NativeRdb::RowEntity &rowEntity);
};

}  // namespace Wifi
}  // namespace OHOS
#endif