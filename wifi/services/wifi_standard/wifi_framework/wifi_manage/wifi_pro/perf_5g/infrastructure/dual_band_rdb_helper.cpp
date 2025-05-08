/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "dual_band_rdb_helper.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("DualBandRdbHelper");

namespace PerfApRecordTable {
    const std::string TABLE_NAME = "perf_ap_record";
    const std::string ID = "id";
    const std::string NETWORK_ID = "networkId";
    const std::string SSID = "ssid";
    const std::string BSSID = "bssid";
    const std::string KEY_MGMT = "keyMgmt";
    const std::string FREQUENCY = "frequency";
    const std::string NETWORK_STATUS = "networkStatus";
    const std::string RTT_PRODUCT = "rttProduct";
    const std::string RTT_PACKET_VOLUME = "rttPacketVolume";
    const std::string OTA_LOST_RATES = "otaLostRates";
    const std::string OTA_PKT_VOLUMES = "otaPktVolumes";
    const std::string OTA_BAD_PKT_PRODUCTS = "otaBadPktProducts";
    const std::string TOTAL_USE_TIME = "totalUseTime";
    const std::string UPDATE_TIME = "updateTime";
}
namespace PerfApRelationTable {
    const std::string TABLE_NAME = "perf_ap_relation";
    const std::string ID = "id";
    const std::string BSSID_24G = "bssid24g";
    const std::string RELATION_BSSID_5G = "relationBssid5g";
    const std::string RELATE_TYPE = "relateType";
    const std::string MAX_SCAN_RSSI = "maxScanRssi";
    const std::string MIN_TARGET_RSSI = "minTargetRssi";
    const std::string MEAN_P = "meanP";
    const std::string MEAN_P_VERSION = "meanPversion";
    const std::string MAX_RSSI = "maxRssi";
    const std::string RELATION_RSSI_WHEN_MAX_RSSI = "relationRssiWhenMaxRssi";
    const std::string MAX_RELATION_RSSI = "maxRelationRssi";
    const std::string RSSI_WHEN_MAX_RELATION_RSSI = "rssiWhenMaxRelationRssi";
    const std::string SCAN_RSSI_THRESHOLD = "scanRssiThreshold";
    const std::string UPDATE_TIME = "updateTime";
}

bool DualBandRdbHelper::Connection()
{
    return true;
}
bool DualBandRdbHelper::QueryApInfo(std::string &bssid, SwitchableApInfo &apInfo)
{
    std::shared_ptr<WifiRdbManager> pRdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (pRdbManager == nullptr) {
        WIFI_LOGE("QueryApInfo Failed,WIFI_PRO rdbManager is nullptr");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(PerfApRecordTable::TABLE_NAME);
    predicates.EqualTo(PerfApRecordTable::BSSID, bssid);
    std::vector<std::string> apColums = {PerfApRecordTable::ID, PerfApRecordTable::NETWORK_ID, PerfApRecordTable::SSID,
        PerfApRecordTable::BSSID, PerfApRecordTable::KEY_MGMT, PerfApRecordTable::FREQUENCY,
        PerfApRecordTable::NETWORK_STATUS, PerfApRecordTable::RTT_PRODUCT, PerfApRecordTable::RTT_PACKET_VOLUME,
        PerfApRecordTable::OTA_LOST_RATES, PerfApRecordTable::OTA_PKT_VOLUMES, PerfApRecordTable::OTA_BAD_PKT_PRODUCTS,
        PerfApRecordTable::TOTAL_USE_TIME};
    auto resultSet = pRdbManager->Query(predicates, apColums);
    if (!resultSet) {
        WIFI_LOGE("QueryApInfo Failed,resultSet is nullptr");
        return false;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        WIFI_LOGE("QueryApInfo read Db error: resultSetNum: %{public}d", resultSetNum);
        return false;
    }
    NativeRdb::RowEntity rowEntity;
    if (resultSet->GetRow(rowEntity) == NativeRdb::E_OK) {
        BuildApInfo(rowEntity, apInfo);
    }
    resultSet->Close();
    return true;
}
bool DualBandRdbHelper::QueryRelationInfo(std::string &bssid, std::vector<RelationInfo> &relationInfos)
{
    std::shared_ptr<WifiRdbManager> pRdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (pRdbManager == nullptr) {
        WIFI_LOGE("QueryRelationInfo Failed,WIFI_PRO rdbManager is nullptr");
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(PerfApRelationTable::TABLE_NAME);
    predicates.EqualTo(PerfApRelationTable::BSSID_24G, bssid);
    predicates.Or();
    predicates.EqualTo(PerfApRelationTable::RELATION_BSSID_5G, bssid);
    std::vector<std::string> relationColums = {PerfApRelationTable::ID,
        PerfApRelationTable::BSSID_24G, PerfApRelationTable::RELATION_BSSID_5G,
        PerfApRelationTable::RELATE_TYPE, PerfApRelationTable::MAX_SCAN_RSSI, PerfApRelationTable::MIN_TARGET_RSSI,
        PerfApRelationTable::MEAN_P, PerfApRelationTable::MEAN_P_VERSION, PerfApRelationTable::MAX_RSSI,
        PerfApRelationTable::RELATION_RSSI_WHEN_MAX_RSSI,
        PerfApRelationTable::MAX_RELATION_RSSI, PerfApRelationTable::RSSI_WHEN_MAX_RELATION_RSSI,
        PerfApRelationTable::SCAN_RSSI_THRESHOLD};
    auto resultSet = pRdbManager->Query(predicates, relationColums);
    if (!resultSet) {
        WIFI_LOGE("QueryRelationInfo Failed,resultSet is nullptr");
        return false;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        NativeRdb::RowEntity rowEntity;
        if (resultSet->GetRow(rowEntity) == NativeRdb::E_OK) {
            RelationInfo relationInfo;
            BuildRelationInfo(relationInfo, rowEntity);
            relationInfos.push_back(relationInfo);
        }
    }
    resultSet->Close();
    WIFI_LOGE("QueryRelationInfo, relationInfos size(%{public}zu)", relationInfos.size());
    return true;
}
bool DualBandRdbHelper::DeleteAll(std::unordered_set<std::string> &bssids)
{
    std::shared_ptr<WifiRdbManager> pRdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (pRdbManager == nullptr) {
        WIFI_LOGE("DeleteAll Failed,WIFI_PRO rdbManager is nullptr");
        return false;
    }
    NativeRdb::AbsRdbPredicates relationPredicates(PerfApRelationTable::TABLE_NAME);
    std::vector<std::string> bssidVector(bssids.begin(), bssids.end());
    relationPredicates.In(PerfApRelationTable::BSSID_24G, bssidVector);
    relationPredicates.Or();
    relationPredicates.In(PerfApRelationTable::RELATION_BSSID_5G, bssidVector);
    int deleteRowCount = 0;
    bool deleteRelation = pRdbManager->Delete(deleteRowCount, relationPredicates);
    WIFI_LOGI("Deleted relation: deleteRowCount:%{public}d", deleteRowCount);
    NativeRdb::AbsRdbPredicates apRecordPredicates(PerfApRecordTable::TABLE_NAME);
    apRecordPredicates.In(PerfApRecordTable::BSSID, bssidVector);
    deleteRowCount = 0;
    bool deleteApRecord = pRdbManager->Delete(deleteRowCount, apRecordPredicates);
    WIFI_LOGI("Deleted ap record: deleteRowCount:%{public}d", deleteRowCount);
    return deleteRelation || deleteApRecord;
}
bool DualBandRdbHelper::SaveApInfo(SwitchableApInfo &apInfo)
{
    std::shared_ptr<WifiRdbManager> pRdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (pRdbManager == nullptr) {
        WIFI_LOGE("SaveApInfo Failed,WIFI_PRO rdbManager is nullptr");
        return false;
    }
    NativeRdb::ValuesBucket apRecordBucket;
    CreateApRecordBucket(apInfo, apRecordBucket);
    bool result;
    if (apInfo.id == -1) {
        result = pRdbManager->Insert(PerfApRecordTable::TABLE_NAME, apRecordBucket);
    } else {
        NativeRdb::AbsRdbPredicates apRecordPredicates(PerfApRecordTable::TABLE_NAME);
        apRecordPredicates.EqualTo(PerfApRecordTable::ID, int64_t(apInfo.id));
        result = pRdbManager->Update(apRecordBucket, apRecordPredicates);
    }
    return result;
}
void DualBandRdbHelper::SaveApInfos(std::vector<SwitchableApInfo> &apInfos)
{
    for (auto &apInfo : apInfos) {
        SaveApInfo(apInfo);
    }
}
void DualBandRdbHelper::SaveRelationInfos(std::vector<RelationInfo> &relationInfos)
{
    for (auto &relationInfo : relationInfos) {
        SaveRelationInfo(relationInfo);
    }
}
bool DualBandRdbHelper::QueryApInfos(std::unordered_set<std::string> &bssidSet, std::vector<SwitchableApInfo> &apInfos)
{
    std::shared_ptr<WifiRdbManager> pRdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (pRdbManager == nullptr) {
        WIFI_LOGE("QueryApInfos Failed,WIFI_PRO rdbManager is nullptr");
        return false;
    }
    std::vector<std::string> bssids(bssidSet.begin(), bssidSet.end());
    NativeRdb::AbsRdbPredicates predicates(PerfApRecordTable::TABLE_NAME);
    predicates.In(PerfApRecordTable::BSSID, bssids);
    std::vector<std::string> apColums = {PerfApRecordTable::ID, PerfApRecordTable::NETWORK_ID, PerfApRecordTable::SSID,
        PerfApRecordTable::BSSID, PerfApRecordTable::KEY_MGMT, PerfApRecordTable::FREQUENCY,
        PerfApRecordTable::NETWORK_STATUS, PerfApRecordTable::RTT_PRODUCT, PerfApRecordTable::RTT_PACKET_VOLUME,
        PerfApRecordTable::OTA_LOST_RATES, PerfApRecordTable::OTA_PKT_VOLUMES, PerfApRecordTable::OTA_BAD_PKT_PRODUCTS,
        PerfApRecordTable::TOTAL_USE_TIME};
    auto resultSet = pRdbManager->Query(predicates, apColums);
    if (!resultSet) {
        WIFI_LOGE("QueryApInfos Failed,resultSet is nullptr");
        return false;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        NativeRdb::RowEntity rowEntity;
        if (resultSet->GetRow(rowEntity) == NativeRdb::E_OK) {
            SwitchableApInfo apInfo;
            BuildApInfo(rowEntity, apInfo);
            apInfos.push_back(apInfo);
        }
    }
    resultSet->Close();
    return true;
}
bool DualBandRdbHelper::SaveRelationInfo(RelationInfo &relationInfo)
{
    std::shared_ptr<WifiRdbManager> pRdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (pRdbManager == nullptr) {
        WIFI_LOGE("SaveRelationInfo Failed,WIFI_PRO rdbManager is nullptr");
        return false;
    }
    NativeRdb::ValuesBucket relationBucket;
    CreateRelationBucket(relationInfo, relationBucket);
    if (relationInfo.id_ == -1) {
        return pRdbManager->Insert(PerfApRelationTable::TABLE_NAME, relationBucket);
    } else {
        NativeRdb::AbsRdbPredicates relationPredicates(PerfApRelationTable::TABLE_NAME);
        relationPredicates.EqualTo(PerfApRelationTable::ID, int64_t(relationInfo.id_));
        return pRdbManager->Update(relationBucket, relationPredicates);
    }
}
void DualBandRdbHelper::BuildApInfo(NativeRdb::RowEntity &rowEntity, SwitchableApInfo &apInfo)
{
    apInfo.id = static_cast<long>(int64_t(rowEntity.Get(PerfApRecordTable::ID)));
    apInfo.networkId = static_cast<int>(rowEntity.Get(PerfApRecordTable::NETWORK_ID));
    apInfo.ssid = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::SSID));
    apInfo.bssid = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::BSSID));
    apInfo.keyMgmt = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::KEY_MGMT));
    apInfo.frequency = static_cast<int>(rowEntity.Get(PerfApRecordTable::FREQUENCY));
    apInfo.networkStatus = static_cast<int>(rowEntity.Get(PerfApRecordTable::NETWORK_STATUS));
    apInfo.rttProduct = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::RTT_PRODUCT));
    apInfo.rttPacketVolume = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::RTT_PACKET_VOLUME));
    apInfo.otaLostRates = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::OTA_LOST_RATES));
    apInfo.otaPktVolumes = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::OTA_PKT_VOLUMES));
    apInfo.otaBadPktProducts = static_cast<std::string>(rowEntity.Get(PerfApRecordTable::OTA_BAD_PKT_PRODUCTS));
    apInfo.totalUseTime = static_cast<long>(int64_t(rowEntity.Get(PerfApRecordTable::TOTAL_USE_TIME)));
}
void DualBandRdbHelper::CreateApRecordBucket(SwitchableApInfo &apInfo, NativeRdb::ValuesBucket &valuesBucket)
{
    valuesBucket.PutInt(PerfApRecordTable::NETWORK_ID, apInfo.networkId);
    valuesBucket.PutString(PerfApRecordTable::SSID, apInfo.ssid);
    valuesBucket.PutString(PerfApRecordTable::BSSID, apInfo.bssid);
    valuesBucket.PutString(PerfApRecordTable::KEY_MGMT, apInfo.keyMgmt);
    valuesBucket.PutInt(PerfApRecordTable::FREQUENCY, apInfo.frequency);
    valuesBucket.PutInt(PerfApRecordTable::NETWORK_STATUS, apInfo.networkStatus);
    valuesBucket.PutString(PerfApRecordTable::RTT_PRODUCT, apInfo.rttProduct);
    valuesBucket.PutString(PerfApRecordTable::RTT_PACKET_VOLUME, apInfo.rttPacketVolume);
    valuesBucket.PutString(PerfApRecordTable::OTA_LOST_RATES, apInfo.otaLostRates);
    valuesBucket.PutString(PerfApRecordTable::OTA_PKT_VOLUMES, apInfo.otaPktVolumes);
    valuesBucket.PutString(PerfApRecordTable::OTA_BAD_PKT_PRODUCTS, apInfo.otaBadPktProducts);
    valuesBucket.PutLong(PerfApRecordTable::TOTAL_USE_TIME, apInfo.totalUseTime);
}
void DualBandRdbHelper::CreateRelationBucket(RelationInfo &relationInfo, NativeRdb::ValuesBucket &valuesBucket)
{
    valuesBucket.PutString(PerfApRelationTable::BSSID_24G, relationInfo.bssid24g_);
    valuesBucket.PutString(PerfApRelationTable::RELATION_BSSID_5G, relationInfo.relationBssid5g_);
    valuesBucket.PutInt(PerfApRelationTable::RELATE_TYPE, relationInfo.relateType_);
    valuesBucket.PutInt(PerfApRelationTable::MAX_SCAN_RSSI, relationInfo.maxScanRssi_);
    valuesBucket.PutInt(PerfApRelationTable::MIN_TARGET_RSSI, relationInfo.minTargetRssi_);
    valuesBucket.PutString(PerfApRelationTable::MEAN_P, relationInfo.meanP_);
    valuesBucket.PutInt(PerfApRelationTable::MEAN_P_VERSION, relationInfo.meanPversion_);
    valuesBucket.PutInt(PerfApRelationTable::MAX_RSSI, relationInfo.maxRssi_);
    valuesBucket.PutInt(PerfApRelationTable::RELATION_RSSI_WHEN_MAX_RSSI, relationInfo.relationRssiWhenMaxRssi_);
    valuesBucket.PutInt(PerfApRelationTable::MAX_RELATION_RSSI, relationInfo.maxRelationRssi_);
    valuesBucket.PutInt(PerfApRelationTable::RSSI_WHEN_MAX_RELATION_RSSI, relationInfo.rssiWhenMaxRelationRssi_);
    valuesBucket.PutString(PerfApRelationTable::SCAN_RSSI_THRESHOLD, relationInfo.GetScanRssiThreshold());
}
void DualBandRdbHelper::BuildRelationInfo(RelationInfo &relationInfo, const NativeRdb::RowEntity &rowEntity)
{
    relationInfo.id_ = static_cast<long>(int64_t(rowEntity.Get(PerfApRelationTable::ID)));
    relationInfo.bssid24g_ = static_cast<std::string>(rowEntity.Get(PerfApRelationTable::BSSID_24G));
    relationInfo.relationBssid5g_ =
        static_cast<std::string>(rowEntity.Get(PerfApRelationTable::RELATION_BSSID_5G));
    relationInfo.relateType_ = static_cast<int>(rowEntity.Get(PerfApRelationTable::RELATE_TYPE));
    relationInfo.maxScanRssi_ = static_cast<int>(rowEntity.Get(PerfApRelationTable::MAX_SCAN_RSSI));
    relationInfo.minTargetRssi_ = static_cast<int>(rowEntity.Get(PerfApRelationTable::MIN_TARGET_RSSI));
    relationInfo.meanP_ = static_cast<std::string>(rowEntity.Get(PerfApRelationTable::MEAN_P));
    relationInfo.meanPversion_ = static_cast<int>(rowEntity.Get(PerfApRelationTable::MEAN_P_VERSION));
    relationInfo.maxRssi_ = static_cast<int>(rowEntity.Get(PerfApRelationTable::MAX_RSSI));
    relationInfo.relationRssiWhenMaxRssi_ =
        static_cast<int>(rowEntity.Get(PerfApRelationTable::RELATION_RSSI_WHEN_MAX_RSSI));
    relationInfo.maxRelationRssi_ = static_cast<int>(rowEntity.Get(PerfApRelationTable::MAX_RELATION_RSSI));
    relationInfo.rssiWhenMaxRelationRssi_ =
        static_cast<int>(rowEntity.Get(PerfApRelationTable::RSSI_WHEN_MAX_RELATION_RSSI));
    relationInfo.SetSameApTriggerScanRssiThreshold(
        static_cast<std::string>(rowEntity.Get(PerfApRelationTable::SCAN_RSSI_THRESHOLD)));
}

}  // namespace Wifi
}  // namespace OHOS