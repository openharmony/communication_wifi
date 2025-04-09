/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "wifi_rdb_manager.h"
#include "wifi_logger.h"

using namespace testing::ext;
using namespace OHOS::Wifi;

class WifiRdbManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiRdbManagerTest, GetRdbManger_WifiPro, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);
}

HWTEST_F(WifiRdbManagerTest, GetRdbManger_WifiHistoryRecord, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_HISTORY_RECORD);
    ASSERT_NE(rdbManager, nullptr);
}

HWTEST_F(WifiRdbManagerTest, Insert_Success, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);

    OHOS::NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt("networkId", 1);
    valuesBucket.PutString("ssid", "test_ssid");
    valuesBucket.PutString("bssid", "test_bssid");

    bool result = rdbManager->Insert("perf_ap_record", valuesBucket);
    ASSERT_TRUE(result);
}

HWTEST_F(WifiRdbManagerTest, Update_Success, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);

    OHOS::NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt("networkId", 1);
    valuesBucket.PutString("ssid", "updated_ssid");

    OHOS::NativeRdb::AbsRdbPredicates predicates("perf_ap_record");
    predicates.EqualTo("networkId", 1);

    bool result = rdbManager->Update(valuesBucket, predicates);
    ASSERT_TRUE(result);
}

HWTEST_F(WifiRdbManagerTest, ExecuteSql_Success, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);

    std::string sql = "DELETE FROM perf_ap_record WHERE networkId = 1";
    std::vector<OHOS::NativeRdb::ValueObject> args;

    bool result = rdbManager->ExecuteSql(sql, args);
    ASSERT_TRUE(result);
}

HWTEST_F(WifiRdbManagerTest, Query_Success, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);

    OHOS::NativeRdb::AbsRdbPredicates predicates("perf_ap_record");
    predicates.EqualTo("networkId", 1);
    std::vector<std::string> columns = {"networkId", "ssid", "bssid"};

    auto resultSet = rdbManager->Query(predicates, columns);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(WifiRdbManagerTest, QuerySql_Success, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);

    std::string sql = "SELECT * FROM perf_ap_record WHERE networkId = 1";
    std::vector<OHOS::NativeRdb::ValueObject> bindArgs;

    auto resultSet = rdbManager->QuerySql(sql, bindArgs);
    ASSERT_NE(resultSet, nullptr);
}

HWTEST_F(WifiRdbManagerTest, Delete_Success, TestSize.Level1)
{
    auto rdbManager = WifiRdbManager::GetRdbManger(RdbType::WIFI_PRO);
    ASSERT_NE(rdbManager, nullptr);

    OHOS::NativeRdb::AbsRdbPredicates predicates("perf_ap_record");
    predicates.EqualTo("networkId", 1);

    int deletedRowCount = 0;
    bool result = rdbManager->Delete(deletedRowCount, predicates);
    ASSERT_TRUE(result);
}
