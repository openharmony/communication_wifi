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

#include "dual_band_repostitory.h"
#include "wifi_logger.h"
#include "switchable_ap_info.h"
#include "wifi_pro_common.h"
#include "network_status_history_manager.h"
#include <cstddef>

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("DualBandRepostitory");

const static size_t SAVE_MAX_SIZE = 1000;

DualBandRepostitory::DualBandRepostitory(std::shared_ptr<IDualBandDataSource> pDualBandDataSource)
    : pDualBandDataSource_(pDualBandDataSource)
{
    WIFI_LOGI("DualBandRepostitory");
}
DualBandRepostitory::~DualBandRepostitory()
{
    WIFI_LOGI("~DualBandRepostitory");
}
void DualBandRepostitory::LoadApHistoryInfo(ApInfo &apInfo, bool &hasHistoryInfo)
{
    SwitchableApInfo historyApInfo;
    pDualBandDataSource_->QueryApInfo(apInfo.bssid, historyApInfo);
    if (historyApInfo.bssid == "") {
        return;
    }
    apInfo.networkStatus = static_cast<NetworkStatus>(historyApInfo.networkStatus);
    apInfo.id = historyApInfo.id;
    hasHistoryInfo = true;
    historyApInfo.BuildApConnectionInfo(apInfo.apConnectionInfo);
}
void DualBandRepostitory::LoadRelationApInfo(std::string bssid, std::vector<RelationAp> &relationApInfo,
    std::function<std::string(RelationInfo&)> GetRelationBssidFunc)
{
    std::vector<RelationInfo> relationInfos;
    pDualBandDataSource_->QueryRelationInfo(bssid, relationInfos);
    if (relationInfos.empty()) {
        return;
    }
    std::unordered_set<std::string> switchableApBssidSet;
    for (auto &relationInfo : relationInfos) {
        switchableApBssidSet.insert(GetRelationBssidFunc(relationInfo));
    }
    std::vector<RelationAp> relationApInfos = QueryRelationApInfos(switchableApBssidSet);
    for (auto &relationInfo : relationInfos) {
        for (auto &apInfo : relationApInfos) {
            if (apInfo.apInfo_.bssid == GetRelationBssidFunc(relationInfo)) {
                apInfo.relationInfo_ = relationInfo;
                relationApInfo.push_back(apInfo);
            }
        }
    }
}
void DualBandRepostitory::DeleteAll(std::unordered_set<std::string> &bssids)
{
    pDualBandDataSource_->DeleteAll(bssids);
}
void DualBandRepostitory::SaveApInfo(ApInfo &apInfo)
{
    SwitchableApInfo switchableApInfo(apInfo);
    pDualBandDataSource_->SaveApInfo(switchableApInfo);
}
void DualBandRepostitory::SaveRelationApInfo(std::vector<RelationAp> &relationApInfo)
{
    if (relationApInfo.empty() || relationApInfo.size() >= SAVE_MAX_SIZE) {
        WIFI_LOGI("SaveRelationApInfo, relationApInfos is empty or too more");
        return;
    }
    std::vector<SwitchableApInfo> switchableApInfos;
    std::vector<RelationInfo> relationInfos;
    for (auto &relationAp : relationApInfo) {
        SwitchableApInfo switchableApInfo(relationAp.apInfo_);
        switchableApInfos.push_back(switchableApInfo);
        relationInfos.push_back(relationAp.relationInfo_);
    }
    WIFI_LOGI("SaveRelationApInfo, start save apinfo and relationinfo");
    pDualBandDataSource_->SaveApInfos(switchableApInfos);
    pDualBandDataSource_->SaveRelationInfos(relationInfos);
}
std::vector<RelationAp> DualBandRepostitory::QueryRelationApInfos(std::unordered_set<std::string> &bssidSet)
{
    std::vector<SwitchableApInfo> switchableApInfos;
    pDualBandDataSource_->QueryApInfos(bssidSet, switchableApInfos);
    std::vector<RelationAp> relationAps;
    for (auto &switchableApInfo : switchableApInfos) {
        RelationAp relationAp;
        switchableApInfo.BuildApInfo(relationAp.apInfo_);
        relationAps.push_back(relationAp);
    }
    return relationAps;
}

}  // namespace Wifi
}  // namespace OHOS