/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "ap_info_helper.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"
#include "core_service_client.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("ApInfoHelper");

constexpr int32_t DB_BSSID_MAX_QUANTA = 500;
constexpr int32_t DB_NEARBY_BSSID_MAX_QUANTA = 20;
constexpr int32_t DB_CELLID_MAX_QUANTA = 50;
constexpr int32_t QUERY_FAILED = 0;
constexpr int32_t QUERY_NO_RECORD = 1;
constexpr int32_t QUERY_HAS_RECORD = 2;

ApInfoHelper &ApInfoHelper::GetInstance()
{
    static ApInfoHelper gApInfoHelper;
    return gApInfoHelper;
}

ApInfoHelper::ApInfoHelper()
{
    WIFI_LOGI("Enter ApInfoHelper");
}

ApInfoHelper::~ApInfoHelper()
{
    WIFI_LOGI("Enter ~ApInfoHelper");
}

int32_t ApInfoHelper::Init()
{
    WIFI_LOGI("Init");
    wifiDataBaseUtils_ = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("get wifipro database manager failed.");
        return WIFI_OPT_FAILED;
    }
    GetAllApInfos();
    return WIFI_OPT_SUCCESS;
}

bool ApInfoHelper::IsCellIdExit(std::string cellId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &apInfo : apInfos_) {
        for (auto &cellData : apInfo.cellInfos) {
            if (cellData.cellId == cellId) {
                WIFI_LOGI("curren cell Id match apInfos, cellId is %{private}s", cellId.c_str());
                return true;
            }
        }
    }
    WIFI_LOGI("not find same celldata.");
    return false;
}

std::vector<ApInfoData> ApInfoHelper::GetMonitorDatas(std::string cellId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ApInfoData> datas;
    for (auto &apInfo : apInfos_) {
        for (auto &cellData : apInfo.cellInfos) {
            if (cellData.cellId == cellId) {
                datas.push_back(apInfo);
                continue;
            }
        }
    }
    return datas;
}

bool ApInfoHelper::GetAllApInfos()
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return false;
    }
    std::map<std::string, std::string> queryParams;
    std::vector<ApInfoData> apInfoVec;
    int32_t queryRet = QueryBssidInfoByParam(queryParams, apInfoVec);
    if (queryRet != QUERY_HAS_RECORD || apInfoVec.empty()) {
        WIFI_LOGE("GetAllApInfos, no result.");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    apInfos_ = apInfoVec;
    for (auto &apInfo : apInfos_) {
        std::vector<CellInfoData> curCellInfos;
        QueryCellIdInfoByParam({{CellIdInfoTable::BSSID, apInfo.bssid}}, curCellInfos);
        apInfo.cellInfos = curCellInfos;

        std::vector<std::string> curNearbyApInfos;
        QueryNearbyInfoByParam({{NearByApInfoTable::BSSID, apInfo.bssid}}, curNearbyApInfos);
        apInfo.nearbyApInfos = curNearbyApInfos;
        WIFI_LOGI("GetAllApInfos, apInfo.bssid:%{public}s, apInfo.ssid:%{public}s.",
            MacAnonymize(apInfo.bssid).c_str(), SsidAnonymize(apInfo.ssid).c_str());
    }
    return true;
}

void ApInfoHelper::DelApInfoByBssid(const std::string &bssid)
{
    WIFI_LOGI("DelApInfoByBssid:%{public}s", MacAnonymize(bssid).c_str());
    DelBssidInfo(bssid);
    DelCellInfoByBssid(bssid);
    DelNearbyApInfo(bssid);
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = apInfos_.begin(); iter != apInfos_.end();) {
        if (iter->bssid == bssid) {
            iter = apInfos_.erase(iter);
        } else {
            iter++;
        }
    }
}

void ApInfoHelper::DelAllApInfo()
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
 
        return;
    }
    std::string deleteAllBssidSql = "delete from ";
    deleteAllBssidSql.append(BssidInfoTable::TABLE_NAME);
    bool deletebssidRet = wifiDataBaseUtils_->ExecuteSql(deleteAllBssidSql);
 
    std::string deleteAllCellIdSql = "delete from ";
    deleteAllCellIdSql.append(CellIdInfoTable::TABLE_NAME);
    bool deleteCellIdRet = wifiDataBaseUtils_->ExecuteSql(deleteAllCellIdSql);

    std::string deleteAllNearBySql = "delete from ";
    deleteAllNearBySql.append(NearByApInfoTable::TABLE_NAME);
    bool deleteNearByRet = wifiDataBaseUtils_->ExecuteSql(deleteAllNearBySql);
 
    WIFI_LOGI("%{public}s, deletebssidRet=%{public}d, deleteCellIdRet=%{public}d, deleteNearByRet=%{public}d",
        __func__, deletebssidRet, deleteCellIdRet, deleteNearByRet);
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ApInfoData>().swap(apInfos_);
    WIFI_LOGI("DelAllApInfo success.");
}

void ApInfoHelper::AddApInfo(std::string cellId, int32_t networkId)
{
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    ApInfoData data;
    int32_t index = GetApInfoByBssid(config.bssid, data);
    if (index == -1) {
        AddNewApInfo(cellId, config);
        return;
    }
    if (data.cellInfos.size() >= DB_CELLID_MAX_QUANTA) {
        DelApInfoByBssid(config.bssid);
    } else {
        if (!IsCellIdExitByData(data, cellId)) {
            AddCellInfo(config.bssid, cellId);
            AddNearbyApInfo(config.bssid);
            std::vector<CellInfoData> curCellInfos;
            QueryCellIdInfoByParam({{CellIdInfoTable::BSSID, config.bssid}}, curCellInfos);
            if (curCellInfos.size() != 0) {
                data.cellInfos = curCellInfos;
            }
            std::vector<std::string> curNearbyApInfos;
            QueryNearbyInfoByParam({{NearByApInfoTable::BSSID, config.bssid}}, curNearbyApInfos);
            if (curNearbyApInfos.size() != 0) {
                data.nearbyApInfos = curNearbyApInfos;
            }
        } else {
            WIFI_LOGI("addCurrentApInfo info is already there");
        }
        data.bssid = config.bssid;
        data.ssid = config.ssid;
        data.frequency = config.frequency;
        data.authType = config.keyMgmt;
        data.time = GetCurrentTimeMilliSeconds();
        data.inBlacklist = 0;
        data.isHomeAp = 0;
        SaveBssidInfo(data);
    }
}

void ApInfoHelper::AddNewApInfo(const std::string &cellId, const WifiDeviceConfig &config)
{
    ApInfoData data;
    if (apInfos_.size() >= DB_BSSID_MAX_QUANTA) {
        ApInfoData oldestData;
        int32_t index = GetOldestApInfoData(oldestData);
        if (index != -1) {
            DelApInfoByBssid(oldestData.bssid);
        }
    }
    data.time = GetCurrentTimeMilliSeconds();
    data.authType = config.keyMgmt;
    data.bssid = config.bssid;
    data.ssid = config.ssid;
    data.frequency = config.frequency;
    data.inBlacklist = 0;
    data.isHomeAp = 0;
    SaveBssidInfo(data);
    AddCellInfo(config.bssid, cellId);
    AddNearbyApInfo(config.bssid);
    std::vector<CellInfoData> curCellInfos;
    QueryCellIdInfoByParam({{CellIdInfoTable::BSSID, config.bssid}}, curCellInfos);
    data.cellInfos = curCellInfos;
    std::vector<std::string> curNearbyApInfos;
    QueryNearbyInfoByParam({{NearByApInfoTable::BSSID, config.bssid}}, curNearbyApInfos);
    data.nearbyApInfos = curNearbyApInfos;
    std::lock_guard<std::mutex> lock(mutex_);
    apInfos_.push_back(data);
    return;
}

int32_t ApInfoHelper::GetOldestApInfoData(ApInfoData &data)
{
    if (apInfos_.size() == 0) {
        return -1;
    }
    int32_t index = 0;
    ApInfoData oldestData = apInfos_.at(0);
    auto iter = apInfos_.begin();
    for (; iter != apInfos_.end();) {
        if (iter->time < oldestData.time) {
            oldestData = *iter;
            index = std::distance(apInfos_.begin(), iter);
        }
    }
    data = oldestData;
    return index;
}

int32_t ApInfoHelper::QueryCellIdInfoByParam(const std::map<std::string, std::string> &queryParams,
    std::vector<CellInfoData> &cellInfoVector)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(CellIdInfoTable::TABLE_NAME);
    if (!queryParams.empty()) {
        auto it = queryParams.begin();
        auto end = queryParams.end();
        while (it != end) {
            auto nextIt = std::next(it);
            predicates.EqualTo(it->first, it->second);
            if (nextIt != end) {
                predicates.And();
            }
            ++it;
        }
    }
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
        WIFI_LOGE("%{public}s, all query fail", __func__);
        return QUERY_FAILED;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, query empty", __func__);
        return QUERY_NO_RECORD;
    }
    do {
        int32_t columnCnt = 0;
        std::string bssid;
        CellInfoData curCellInfo;
        resultSet->GetString(columnCnt++, bssid);
        resultSet->GetString(columnCnt++, curCellInfo.cellId);
        resultSet->GetInt(columnCnt++, curCellInfo.rssi);
        cellInfoVector.emplace_back(curCellInfo);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    return QUERY_HAS_RECORD;
}

int32_t ApInfoHelper::GetApInfoByBssid(const std::string &bssid, ApInfoData &data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t index = -1;
    auto iter = apInfos_.begin();
    if (apInfos_.size() == 0) {
        WIFI_LOGE("GetApInfoByBssid no apInfos_.");
        return -1;
    }
    for (; iter != apInfos_.end();) {
        if (iter->bssid == bssid) {
            WIFI_LOGI("GetApInfoByBssid, apInfo.bssid:%{public}s, apInfo.ssid:%{public}s",
                MacAnonymize(iter->bssid).c_str(), SsidAnonymize(iter->ssid).c_str());
            index = std::distance(apInfos_.begin(), iter);
            data = *iter;
            break;
        }
        iter++;
    }
    return index;
}

bool ApInfoHelper::IsCellIdExitByData(ApInfoData info, std::string cellId)
{
    for (CellInfoData data : info.cellInfos) {
        if (data.cellId == cellId) {
            WIFI_LOGI("IsCellIdExitByData, yes!");
            return true;
        }
    }
    return false;
}

int32_t ApInfoHelper::QueryBssidInfoByParam(const std::map<std::string, std::string> &queryParams,
    std::vector<ApInfoData> &apInfoVector)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(BssidInfoTable::TABLE_NAME);
    if (!queryParams.empty()) {
        auto it = queryParams.begin();
        auto end = queryParams.end();
        while (it != end) {
            auto nextIt = std::next(it);
            predicates.EqualTo(it->first, it->second);
            if (nextIt != end) {
                predicates.And();
            }
            ++it;
        }
    }
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
        WIFI_LOGE("%{public}s, all query fail", __func__);
        return QUERY_FAILED;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, query empty", __func__);
        return QUERY_NO_RECORD;
    }
    do {
        int32_t columnCnt = 0;
        ApInfoData curApInfo;
        resultSet->GetString(columnCnt++, curApInfo.bssid);
        resultSet->GetString(columnCnt++, curApInfo.ssid);
        resultSet->GetLong(columnCnt++, curApInfo.time);
        resultSet->GetInt(columnCnt++, curApInfo.inBlacklist);
        resultSet->GetString(columnCnt++, curApInfo.authType);
        resultSet->GetInt(columnCnt++, curApInfo.frequency);
        resultSet->GetInt(columnCnt++, curApInfo.isHomeAp);
        WIFI_LOGI("%{public}s, cur ApInfo bssid:%{public}s, ssid:%{public}s",
            __func__, MacAnonymize(curApInfo.bssid).c_str(), SsidAnonymize(curApInfo.ssid).c_str());
        apInfoVector.emplace_back(curApInfo);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    return QUERY_HAS_RECORD;
}

bool ApInfoHelper::SaveBssidInfo(ApInfoData &apInfoData)
{
    if (wifiDataBaseUtils_ == nullptr || apInfoData.bssid.empty()) {
        WIFI_LOGE("SaveBssidInfo fail, wifiDataBaseUtils_ is nullptr or bssid empty.");
        return false;
    }
    std::vector<ApInfoData> apInfoVec;
    int32_t queryRet = QueryBssidInfoByParam({{BssidInfoTable::BSSID, apInfoData.bssid}}, apInfoVec);
    NativeRdb::ValuesBucket bssidInfo;
    bssidInfo.PutString(BssidInfoTable::BSSID, apInfoData.bssid);
    bssidInfo.PutString(BssidInfoTable::SSID, apInfoData.ssid);
    bssidInfo.PutLong(BssidInfoTable::TIME, apInfoData.time);
    bssidInfo.PutInt(BssidInfoTable::IN_BLACK_LIST, apInfoData.inBlacklist);
    bssidInfo.PutString(BssidInfoTable::AUTH_TYPE, apInfoData.authType);
    bssidInfo.PutInt(BssidInfoTable::FREQUENCY, apInfoData.frequency);
    bssidInfo.PutInt(BssidInfoTable::IS_HOME_AP, apInfoData.isHomeAp);
    WIFI_LOGI("SaveBssidInfo, bssid:%{public}s, ssid:%{public}s, inblacklist:%{public}d",
        MacAnonymize(apInfoData.bssid).c_str(), SsidAnonymize(apInfoData.ssid).c_str(), apInfoData.inBlacklist);
    if (queryRet == QUERY_NO_RECORD) {
        bool executeRet = wifiDataBaseUtils_->Insert(BssidInfoTable::TABLE_NAME, bssidInfo);
        WIFI_LOGI("SaveBssidInfo, insert ret=%{public}d", executeRet);
        return executeRet;
    } else if (queryRet == QUERY_HAS_RECORD) {
        NativeRdb::AbsRdbPredicates predicates(BssidInfoTable::TABLE_NAME);
        predicates.EqualTo(BssidInfoTable::BSSID, apInfoData.bssid);
        bool executeRet = wifiDataBaseUtils_->Update(bssidInfo, predicates);
        WIFI_LOGI("SaveBssidInfo, update ret=%{public}d", executeRet);
        return executeRet;
    }
    WIFI_LOGE("SaveBssidInfo fail.");
    return false;
}

int32_t ApInfoHelper::DelBssidInfo(std::string bssid)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(BssidInfoTable::TABLE_NAME);
    predicates.EqualTo(BssidInfoTable::BSSID, bssid);
    int32_t deleteRowCount = 0;
    wifiDataBaseUtils_->Delete(deleteRowCount, predicates);
    return deleteRowCount;
}

void ApInfoHelper::AddCellInfo(std::string bssid, std::string cellId)
{
    if (wifiDataBaseUtils_ == nullptr || bssid.empty()) {
        WIFI_LOGE("AddCellInfo fail, wifiDataBaseUtils_ is nullptr or bssid empty.");
        return;
    }
    std::vector<CellInfoData> vecCellInfos;
    int32_t queryRet = QueryCellIdInfoByParam({{CellIdInfoTable::BSSID, bssid}, {CellIdInfoTable::CELL_ID, cellId}},
        vecCellInfos);
    if (queryRet == QUERY_NO_RECORD) {
        NativeRdb::ValuesBucket cellInfo;
        cellInfo.PutString(CellIdInfoTable::BSSID, bssid);
        cellInfo.PutString(CellIdInfoTable::CELL_ID, cellId);
        cellInfo.PutInt(CellIdInfoTable::RSSI, -1);
        bool executeRet = wifiDataBaseUtils_->Insert(CellIdInfoTable::TABLE_NAME, cellInfo);
        WIFI_LOGI("%{public}s, ret=%{public}d", __func__, executeRet);
        return;
    } else if (queryRet == QUERY_HAS_RECORD) {
        WIFI_LOGI("%{public}s, already exists", __func__);
        return;
    }
    WIFI_LOGE("%{public}s fail", __func__);
}

int32_t ApInfoHelper::DelCellInfoByBssid(std::string bssid)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(CellIdInfoTable::TABLE_NAME);
    predicates.EqualTo(CellIdInfoTable::BSSID, bssid);
    int32_t deleteRowCount = 0;
    wifiDataBaseUtils_->Delete(deleteRowCount, predicates);
    return deleteRowCount;
}

int32_t ApInfoHelper::AddNearbyApInfo(std::string bssid)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return false;
    }
    std::vector<WifiScanInfo> scanResults;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    int32_t num = 0;
    for (auto &result : scanResults) {
        if (num < DB_NEARBY_BSSID_MAX_QUANTA) {
            std::vector<std::string> nearbyInfoVec;
            int32_t queryRet = QueryNearbyInfoByParam({{NearByApInfoTable::BSSID, bssid},
                {NearByApInfoTable::NEAR_BY_BSSID, result.bssid}}, nearbyInfoVec);
            if (queryRet == QUERY_NO_RECORD) {
                NativeRdb::ValuesBucket nearbyApInfo;
                nearbyApInfo.PutString(NearByApInfoTable::BSSID, bssid);
                nearbyApInfo.PutString(NearByApInfoTable::NEAR_BY_BSSID, result.bssid);
                bool executeRet = wifiDataBaseUtils_->Insert(NearByApInfoTable::TABLE_NAME, nearbyApInfo);
                WIFI_LOGD("AddNearbyApInfo, ret=%{public}d", executeRet);
            } else if (queryRet == QUERY_HAS_RECORD) {
                WIFI_LOGD("AddNearbyApInfo recors is alreay in.");
            }
            num++;
        }
    }
    return num;
}

int32_t ApInfoHelper::QueryNearbyInfoByParam(const std::map<std::string, std::string> &queryParams,
    std::vector<std::string> &nearbyInfoVector)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(NearByApInfoTable::TABLE_NAME);
    if (!queryParams.empty()) {
        auto it = queryParams.begin();
        auto end = queryParams.end();
        while (it != end) {
            auto nextIt = std::next(it);
            predicates.EqualTo(it->first, it->second);
            if (nextIt != end) {
                predicates.And();
            }
            ++it;
        }
    }
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
        WIFI_LOGE("%{public}s, all query fail", __func__);
        return QUERY_FAILED;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        resultSet->Close();
        WIFI_LOGD("%{public}s, query empty", __func__);
        return QUERY_NO_RECORD;
    }
    do {
        int32_t columnCnt = 0;
        std::string bssid;
        std::string curNearbyApInfo;
        resultSet->GetString(columnCnt++, bssid);
        resultSet->GetString(columnCnt++, curNearbyApInfo);
        nearbyInfoVector.emplace_back(curNearbyApInfo);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    return QUERY_HAS_RECORD;
}

int32_t ApInfoHelper::DelNearbyApInfo(std::string bssid)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return false;
    }
    NativeRdb::AbsRdbPredicates predicates(NearByApInfoTable::TABLE_NAME);
    predicates.EqualTo(NearByApInfoTable::BSSID, bssid);
    int32_t deleteRowCount = 0;
    wifiDataBaseUtils_->Delete(deleteRowCount, predicates);
    WIFI_LOGI("DelNearbyApInfo, deleteRowCount:%{public}d", deleteRowCount);
    return deleteRowCount;
}

void ApInfoHelper::DelApInfoBySsid(const std::string &ssid, const std::string &keyMgmt)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = apInfos_.begin(); iter != apInfos_.end();) {
        if (iter->ssid == ssid && iter->authType == keyMgmt) {
            DelBssidInfo(iter->bssid);
            DelCellInfoByBssid(iter->bssid);
            DelNearbyApInfo(iter->bssid);
            iter = apInfos_.erase(iter);
        } else {
            iter++;
        }
    }
}

void ApInfoHelper::UpdateBssidIsBlacklist(std::string bssid, int32_t inBlacklist)
{
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return;
    }
    std::vector<ApInfoData> apInfoVec;
    int32_t queryRet = QueryBssidInfoByParam({{BssidInfoTable::BSSID, bssid}}, apInfoVec);
    if (queryRet == QUERY_HAS_RECORD) {
        for (auto &apInfo : apInfoVec) {
            NativeRdb::AbsRdbPredicates predicates(BssidInfoTable::TABLE_NAME);
            predicates.EqualTo(BssidInfoTable::BSSID, apInfo.bssid);
            NativeRdb::ValuesBucket bssidIdInfo;
            bssidIdInfo.PutInt(BssidInfoTable::IN_BLACK_LIST, inBlacklist);
            bool executeRet = wifiDataBaseUtils_->Update(bssidIdInfo, predicates);
            WIFI_LOGI("UpdateBssidIsBlacklist, bssid:%{public}s, ret=%{public}d",
                MacAnonymize(apInfo.bssid).c_str(), executeRet);
        }
        return;
    } else if (queryRet == QUERY_NO_RECORD) {
        WIFI_LOGI("UpdateBssidIsBlacklist, no such bssid:%{public}s", MacAnonymize(bssid).c_str());
        return;
    }
    WIFI_LOGE("UpdateBssidIsBlacklist query fail.");
}

void ApInfoHelper::SetBlackListBySsid(std::string ssid, std::string authType, int32_t isBlacklist)
{
    WIFI_LOGI("SetBlackListBySsid, isBlacklist:%{public}d", isBlacklist);
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &info : apInfos_) {
        if (info.ssid == ssid && info.authType == authType && info.inBlacklist != isBlacklist) {
            info.inBlacklist = isBlacklist;
            UpdateBssidIsBlacklist(info.bssid, isBlacklist);
        }
    }
}

void ApInfoHelper::ResetBlacklist(std::vector<WifiScanInfo> scanInfoList, int32_t isBlacklist)
{
    if (scanInfoList.size() == 0) {
        WIFI_LOGE("scan result is null.");
        return;
    }
    WIFI_LOGI("ResetBlacklist, isBlacklist:%{public}d", isBlacklist);
    for (auto &scanResult : scanInfoList) {
        ApInfoData data;
        int32_t index = GetApInfoByBssid(scanResult.bssid, data);
        if (index == -1) {
            continue;
        }
        if (data.inBlacklist != isBlacklist) {
            WIFI_LOGI("ResetBlacklist, scanResult ssid:%{public}s, data.ssid:%{public}s",
                SsidAnonymize(scanResult.ssid).c_str(), SsidAnonymize(data.ssid).c_str());
            SetBlackListBySsid(data.ssid, data.authType, isBlacklist);
        }
    }
}

void ApInfoHelper::ResetAllBalcklist()
{
    WIFI_LOGI("ResetAllBalcklist");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &apInfo : apInfos_) {
        if (apInfo.inBlacklist) {
            apInfo.inBlacklist = 0;
            UpdateBssidIsBlacklist(apInfo.bssid, 0);
        }
    }
}

std::string ApInfoHelper::GetCurrentCellIdInfo()
{
    int32_t curSlotId = -1;
    int32_t ret = DelayedRefSingleton<Telephony::CoreServiceClient>::GetInstance().GetPrimarySlotId(curSlotId);
    if (ret != 0 || curSlotId < 0) {
        WIFI_LOGE("GetPrimarySlotId fail, ret:%{public}d, slotId: %{public}d", ret, curSlotId);
        return "";
    }
    std::vector<sptr<Telephony::CellInformation>> cellInformations;
    DelayedRefSingleton<Telephony::CoreServiceClient>::GetInstance().GetCellInfoList(curSlotId, cellInformations);
    int32_t cellSize = static_cast<int32_t>(cellInformations.size());
    WIFI_LOGI("current cellInformations size = %{public}d, curSlotId = %{public}d", cellSize, curSlotId);
    LinkedCellInfo currentCell;
    for (sptr<Telephony::CellInformation> infoItem : cellInformations) {
        if (!infoItem->GetIsCamped()) {
            WIFI_LOGI("GetIsCamped return false");
            continue;
        }
        Telephony::CellInformation::CellType cellType = infoItem->GetNetworkType();
        WIFI_LOGI("%{public}s:current cellType = %{public}d", __func__, cellType);
        switch (cellType) {
            case Telephony::CellInformation::CellType::CELL_TYPE_LTE: {
                GetLteCellInfo(infoItem, currentCell);
                break;
            }
            case Telephony::CellInformation::CellType::CELL_TYPE_NR: {
                GetNrCellInfo(infoItem, currentCell);
                break;
            }
            default:
                WIFI_LOGI("not get lte or nr cell info, cellType = %{public}d", cellType);
                break;
        }
    }
    WIFI_LOGI("GetCurrentCellIdInfo, cellInfo:%{private}s",
        (std::to_string(currentCell.cellId) + currentCell.mcc + currentCell.mnc).c_str());
    return std::to_string(currentCell.cellId) + currentCell.mcc + currentCell.mnc;
}

void ApInfoHelper::GetLteCellInfo(sptr<Telephony::CellInformation> infoItem, LinkedCellInfo &currentCell)
{
    auto lteCellInfo = static_cast<Telephony::LteCellInformation *>(infoItem.GetRefPtr());
    if (lteCellInfo != nullptr) {
        currentCell.cellId = lteCellInfo->GetCellId();
        currentCell.mcc = lteCellInfo->GetMcc();
        currentCell.mnc = lteCellInfo->GetMnc();
        currentCell.rat = RatType::LTE_TYPE;
        currentCell.rssi = lteCellInfo->GetSignalIntensity();
    }
}

void ApInfoHelper::GetNrCellInfo(sptr<Telephony::CellInformation> infoItem, LinkedCellInfo &currentCell)
{
    auto nrCellInfo = static_cast<Telephony::NrCellInformation *>(infoItem.GetRefPtr());
    if (nrCellInfo != nullptr) {
        currentCell.cellId = nrCellInfo->GetNci();  // nr制式cellId为nci
        currentCell.mcc = nrCellInfo->GetMcc();
        currentCell.mnc = nrCellInfo->GetMnc();
        currentCell.rat = RatType::NR_TYPE;
        currentCell.rssi = nrCellInfo->GetSignalIntensity();
    }
}
}
}