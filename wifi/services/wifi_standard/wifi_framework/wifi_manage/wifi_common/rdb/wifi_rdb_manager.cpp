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

#include "wifi_rdb_manager.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiRdbManager");

const std::string WIFI_DATABASE_PATH = "/data/service/el1/public/wifi";
const std::string WIFI_PRO_RDB_NAME = "/wifi_pro.db";
constexpr int32_t WIFI_PRO_DATABASE_VERSION = 2;
const std::string WIFI_HISTORY_RECORD_DATEBASE_NAME = "/wifi_history_record.db";
constexpr int WIFI_HISTORY_RECORD_DATABASE_VERSION = 2;

static std::map<RdbType, std::shared_ptr<WifiRdbManager>> g_rdbManagerInstanceMap;
static std::mutex g_mutex;
std::shared_ptr<WifiRdbManager> WifiRdbManager::GetRdbManger(const RdbType &rdbType)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    switch (rdbType) {
        case RdbType::WIFI_PRO:
            if (g_rdbManagerInstanceMap.find(RdbType::WIFI_PRO) == g_rdbManagerInstanceMap.end()) {
                g_rdbManagerInstanceMap.insert_or_assign(RdbType::WIFI_PRO,
                    std::make_shared<WifiRdbManager>(WIFI_DATABASE_PATH + WIFI_PRO_RDB_NAME,
                        WIFI_PRO_DATABASE_VERSION, std::make_shared<WifiRdbManager::WifiProRdbOpenCallback>()));
            }
            return g_rdbManagerInstanceMap[RdbType::WIFI_PRO];
        case RdbType::WIFI_HISTORY_RECORD:
            if (g_rdbManagerInstanceMap.find(RdbType::WIFI_HISTORY_RECORD) == g_rdbManagerInstanceMap.end()) {
                g_rdbManagerInstanceMap.insert_or_assign(RdbType::WIFI_HISTORY_RECORD,
                    std::make_shared<WifiRdbManager>(
                        WIFI_DATABASE_PATH + WIFI_HISTORY_RECORD_DATEBASE_NAME,
                        WIFI_HISTORY_RECORD_DATABASE_VERSION,
                        std::make_shared<WifiRdbManager::WifiHistoryRecordRdbCallback>()));
            }
            return g_rdbManagerInstanceMap[RdbType::WIFI_HISTORY_RECORD];
        default :
            return nullptr;
    }
}
WifiRdbManager::WifiRdbManager(std::string rdbPath, int32_t rdbVersion,
    std::shared_ptr<NativeRdb::RdbOpenCallback> pRdbOpenCallback) : pRdbOpenCallback_(pRdbOpenCallback),
    rdbPath_(rdbPath), rdbVersion_(rdbVersion)
{}
WifiRdbManager::~WifiRdbManager()
{}
bool WifiRdbManager::Insert(const std::string &tableName, const NativeRdb::ValuesBucket &valuesBucket)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("Insert rdbStore is null");
        return false;
    }
    int64_t rowId = -1;
    auto ret = rdbStore->InsertWithConflictResolution(rowId, tableName, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    WIFI_LOGD("Insert after rowId = %{public}" PRId64, rowId);
    return ret == NativeRdb::E_OK;
}
bool WifiRdbManager::Update(const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &predicates)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("update rdbStore is null");
        return false;
    }
    int32_t rowId = -1;
    rdbStore->Update(rowId, valuesBucket, predicates);
    return rowId != -1;
}
bool WifiRdbManager::ExecuteSql(const std::string &sql, const std::vector<NativeRdb::ValueObject> &args)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("ExecuteSql rdbStore is null");
        return false;
    }
    auto ret = rdbStore->ExecuteSql(sql, args);
    return ret == NativeRdb::E_OK;
}
std::shared_ptr<NativeRdb::ResultSet> WifiRdbManager::Query(const NativeRdb::AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("Query rdbStore is null");
        return nullptr;
    }
    auto absSharedResultSet = rdbStore->Query(predicates, columns);
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        WIFI_LOGE("Query absSharedResultSet is null");
        return nullptr;
    }
    return absSharedResultSet;
}
std::shared_ptr<NativeRdb::AbsSharedResultSet> WifiRdbManager::QuerySql(const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("QuerySql rdbStore is null");
        return nullptr;
    }
    auto absSharedResultSet = rdbStore->QuerySql(sql);
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        WIFI_LOGE("QuerySql absSharedResultSet is null");
        return nullptr;
    }
    return absSharedResultSet;
}
bool WifiRdbManager::Delete(int &deletedRowCount, const NativeRdb::AbsRdbPredicates &predicates)
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("Delete rdbStore is null");
        return false;
    }
    int32_t ret = rdbStore->Delete(deletedRowCount, predicates);
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("Delete fail ret = %{public}d", ret);
        return false;
    }
    return true;
}

bool WifiRdbManager::RemoveDuplicateDatas()
{
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        WIFI_LOGE("rdbStore is null");
        return false;
    }
 
    std::string apRecordSql = R"(
        DELETE FROM perf_ap_record
        WHERE id NOT IN (
            SELECT MAX(t1.id)
            FROM perf_ap_record t1
            GROUP BY 
                t1.networkId, t1.ssid, t1.bssid, t1.keyMgmt, t1.frequency
        );
    )";
 
 
    std::string apRelationSql = R"(
        DELETE FROM perf_ap_relation
        WHERE id NOT IN (
            SELECT MAX(t1.id)
            FROM perf_ap_relation t1
            GROUP BY 
                t1.bssid24g, t1.relationBssid5g, t1.relateType
        );
    )";
 
    int32_t ret1 = rdbStore->ExecuteSql(apRecordSql);
    if (ret1 != NativeRdb::E_OK) {
        WIFI_LOGE("Remove perf_ap_record duplicateDatas fail!");
        return false;
    }
    int32_t ret2 = rdbStore->ExecuteSql(apRelationSql);
    if (ret2 != NativeRdb::E_OK) {
        WIFI_LOGE("Remove perf_ap_relation duplicateDatas fail!");
        return false;
    }
    return true;
}

std::shared_ptr<NativeRdb::RdbStore> WifiRdbManager::GetRdbStore()
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    if (rdbStore_ != nullptr) {
        return rdbStore_;
    }
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbPath_);
    int32_t errCode = NativeRdb::E_OK;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, rdbVersion_,
        *pRdbOpenCallback_, errCode);
    DelayCloseRdbStore();
    return rdbStore_;
}

int32_t WifiRdbManager::WifiProRdbOpenCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    WIFI_LOGI("WifiProRdbOpenCallback OnCreate");
    int32_t ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS perf_ap_record (id INTEGER not null primary key autoincrement,"
        "networkId INTEGER, ssid TEXT, bssid TEXT, keyMgmt TEXT, frequency INTEGER, networkStatus INTEGER,"
        "rttProduct TEXT, rttPacketVolume TEXT, otaLostRates TEXT, otaPktVolumes TEXT, otaBadPktProducts TEXT,"
        "totalUseTime INTEGER, createTime DATETIME DEFAULT (DATETIME('now', 'localtime')), updateTime DATETIME);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("perf_ap_record create failed");
    }
    ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS perf_ap_relation (id INTEGER not null primary key autoincrement,"
        "bssid24g TEXT, relationBssid5g TEXT, relateType INTEGER, maxScanRssi INTEGER, minTargetRssi INTEGER,"
        "meanP TEXT, meanPversion INTEGER, maxRssi INTEGER, relationRssiWhenMaxRssi INTEGER, maxRelationRssi INTEGER,"
        "rssiWhenMaxRelationRssi INTEGER, scanRssiThreshold TEXT,"
        "createTime DATETIME DEFAULT (DATETIME('now', 'localtime')), updateTime DATETIME);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("perf_ap_relation create failed");
    }
    ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS bssid_info_table (bssid TEXT, "
        "ssid TEXT, time BIGINT, inBlacklist INTEGER, authType TEXT, frequency INTEGER, isHomeAp INTEGER);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("bssid_info_table creat failed");
    }
    ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS cellid_info_table (bssid TEXT, cellId TEXT, rssi INTEGER);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("cellid_info_table creat failed");
    }
    ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS nearby_ap_info_table (bssid TEXT, nearbyBssid TEXT);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("nearby_ap_info_table creat failed");
    }
    return NativeRdb::E_OK;
}

int32_t WifiRdbManager::WifiProRdbOpenCallback::OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion,
    int32_t targetVersion)
{
    WIFI_LOGI("WifiProRdbOpenCallback OnUpgrade");
    int32_t ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS bssid_info_table (bssid TEXT, "
        "ssid TEXT, time BIGINT, inBlacklist INTEGER, authType TEXT, frequency INTEGER, isHomeAp INTEGER);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("bssid_info_table creat failed");
    }
    ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS cellid_info_table (bssid TEXT, cellId TEXT, rssi INTEGER);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("cellid_info_table creat failed");
    }
    ret = rdbStore.ExecuteSql(
        "CREATE TABLE IF NOT EXISTS nearby_ap_info_table (bssid TEXT, nearbyBssid TEXT);");
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("nearby_ap_info_table creat failed");
    }
    WIFI_LOGI("WifiProRdbOpenCallback::OnUpgrade, creatTable success.");
    return NativeRdb::E_OK;
}

int32_t WifiRdbManager::WifiHistoryRecordRdbCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    std::string wifiHistoryRecordCreateTableSql = "CREATE TABLE IF NOT EXISTS ";
    wifiHistoryRecordCreateTableSql.append(AP_CONNECTION_DURATION_INFO_TABLE_NAME)
        .append(" (networkId INTEGER, ssid STRING, bssid STRING, keyMgmt STRING, "
        "firstConnectedTime BIGINT, currentConnectedTime BIGINT, totalUseTime BIGINT, totalUseTimeAtNight BIGINT, "
        "totalUseTimeAtWeekend BIGINT, markedAsHomeApTime BIGINT);");
    int32_t ret = rdbStore.ExecuteSql(wifiHistoryRecordCreateTableSql);
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("create ap_connection_duration_info table fail, err: %{public}d ", ret);
        return NativeRdb::E_ERROR;
    }

    ret = CreateEnterpriseApInfoTable(rdbStore);
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("create enterprise_ap_info table fail, err: %{public}d ", ret);
        return NativeRdb::E_ERROR;
    }
    WIFI_LOGI("OnCreate, CreateTable ExecuteSql success");
    return NativeRdb::E_OK;
}
 
int32_t WifiRdbManager::WifiHistoryRecordRdbCallback::OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion,
    int32_t targetVersion)
{
    int32_t ret = CreateEnterpriseApInfoTable(rdbStore);
    if (ret != NativeRdb::E_OK) {
        WIFI_LOGE("create enterprise_ap_info table fail, err: %{public}d ", ret);
        return NativeRdb::E_ERROR;
    }
    WIFI_LOGI("OnUpgrade, CreateTable ExecuteSql success");
    return NativeRdb::E_OK;
}

void WifiRdbManager::DelayCloseRdbStore()
{
    WIFI_LOGI("DelayCloseRdbStore");
    std::weak_ptr<WifiRdbManager> weakPtr = shared_from_this();
    std::thread([weakPtr]() {
        WIFI_LOGI("DelayCloseRdbStore thread begin");
        constexpr int CLOSE_RDB_STORE_DELAY_TIME = 20;
        std::this_thread::sleep_for(std::chrono::seconds(CLOSE_RDB_STORE_DELAY_TIME));
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr != nullptr) {
            std::lock_guard<std::mutex> lock(sharedPtr->mutexLock_);
            sharedPtr->rdbStore_ = nullptr;
        }
    }).detach();
}

int32_t WifiRdbManager::CreateEnterpriseApInfoTable(NativeRdb::RdbStore &rdbStore)
{
    WIFI_LOGI("%{public}s enter", __func__);
    std::string enterpriseApCreateTableSql = "CREATE TABLE IF NOT EXISTS ";
    enterpriseApCreateTableSql.append(ENTERPRISE_AP_INFO_TABLE_NAME)
        .append(" (ssid STRING, keyMgmt STRING);");
    return rdbStore.ExecuteSql(enterpriseApCreateTableSql);
}
}  // namespace Wifi
}  // namespace OHOS