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

#ifndef OHOS_WIFI_COMMON_RDB_WIFI_RDB_MANAGER_H
#define OHOS_WIFI_COMMON_RDB_WIFI_RDB_MANAGER_H

#include <cstdint>
#include <string>
#include "rdb_helper.h"
namespace OHOS {
namespace Wifi {
enum RdbType {
    WIFI_PRO,
    WIFI_HISTORY_RECORD,
};

class WifiRdbManager {
public:
    class WifiProRdbOpenCallback : public NativeRdb::RdbOpenCallback {
    public:
        WifiProRdbOpenCallback() = default;
        virtual ~WifiProRdbOpenCallback() = default;
        int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
        int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion) override;
    };

    class WifiHistoryRecordRdbCallback : public NativeRdb::RdbOpenCallback {
    public:
        WifiHistoryRecordRdbCallback() = default;
        virtual ~WifiHistoryRecordRdbCallback() = default;
        int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
        int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t currentVersion, int32_t targetVersion) override;
    };
public:
    static std::shared_ptr<WifiRdbManager> GetRdbManger(const RdbType &rdbType);
    WifiRdbManager(std::string rdbPath, int32_t rdbVersion,
        std::shared_ptr<NativeRdb::RdbOpenCallback> pRdbOpenCallback);
    ~WifiRdbManager();
    bool Insert(const std::string &tableName, const NativeRdb::ValuesBucket &valuesBucket);
    bool Update(const NativeRdb::ValuesBucket &valuesBucket, const NativeRdb::AbsRdbPredicates &predicates);
    bool ExecuteSql(const std::string &sql, const std::vector<NativeRdb::ValueObject> &args = {});
    std::shared_ptr<NativeRdb::ResultSet> Query(const NativeRdb::AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<NativeRdb::ValueObject> &bindArgs = {});
    bool Delete(int &deletedRowCount, const NativeRdb::AbsRdbPredicates &predicates);

private:
    std::shared_ptr<NativeRdb::RdbOpenCallback> pRdbOpenCallback_;
    std::string rdbPath_;
    int32_t rdbVersion_;
    std::shared_ptr<NativeRdb::RdbStore> GetRdbStore();
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::mutex mutexLock_;
};

}  // namespace Wifi
}  // namespace OHOS
#endif