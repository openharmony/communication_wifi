/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include "network_status_history_manager.h"
#include "log.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
    static std::string g_errLog;
    void NetworkStatusManagerCallback(const LogType type, const LogLevel level,
                                      const unsigned int domain, const char *tag,
                                      const char *msg)
    {
        g_errLog = msg;
    }
class NetworkStatusHistoryManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        LOG_SetCallback(NetworkStatusManagerCallback);
    }
    virtual void TearDown() {}
};

HWTEST_F(NetworkStatusHistoryManagerTest, UpdateTest01, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11;
    NetworkStatus networkStatus = NetworkStatus::UNKNOWN;
    NetworkStatusHistoryManager::Update(networkStatusHistory, networkStatus);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(NetworkStatusHistoryManagerTest, IsInternetAccessByHistory01, TestSize.Level1)
{
    uint32_t networkStatusHistory = 3;
    EXPECT_TRUE(NetworkStatusHistoryManager::IsInternetAccessByHistory(networkStatusHistory) == false);
}

HWTEST_F(NetworkStatusHistoryManagerTest, ModifyAllHistoryRecordTest, TestSize.Level1)
{
    // portal 10 -> no internet 11
    unsigned int oldNetworkStatusHistory1 = 663;  // 663: historyRecord 00000000001010010111
    unsigned int newNetworkStatusHistory1 = 983;  // 983: historyRecord 00000000001111010111
    NetworkStatusHistoryManager::ModifyAllHistoryRecord(oldNetworkStatusHistory1,
        NetworkStatus::PORTAL, NetworkStatus::NO_INTERNET);
    EXPECT_TRUE(oldNetworkStatusHistory1 == newNetworkStatusHistory1);
 
    // portal 10 -> has internet 01
    unsigned int oldNetworkStatusHistory2 = 663;  // 663: historyRecord 00000000001010010111
    unsigned int newNetworkStatusHistory2 = 343;  // 343: historyRecord 00000000000101010111
    NetworkStatusHistoryManager::ModifyAllHistoryRecord(oldNetworkStatusHistory2,
        NetworkStatus::PORTAL, NetworkStatus::HAS_INTERNET);
    EXPECT_TRUE(oldNetworkStatusHistory2 == newNetworkStatusHistory2);
 
    // has internet 01 -> portal 10
    unsigned int oldNetworkStatusHistory3 = 663;  // 663: historyRecord 00000000001010010111
    unsigned int newNetworkStatusHistory3 = 683;  // 683: historyRecord 00000000001010101011
    NetworkStatusHistoryManager::ModifyAllHistoryRecord(oldNetworkStatusHistory3,
        NetworkStatus::HAS_INTERNET, NetworkStatus::PORTAL);
    EXPECT_TRUE(oldNetworkStatusHistory3 == newNetworkStatusHistory3);
 
    // has internet 01 -> no internet 11
    unsigned int oldNetworkStatusHistory4 = 663;  // 663: historyRecord 00000000001010010111
    unsigned int newNetworkStatusHistory4 = 703;  // 703: historyRecord 00000000001010111111
    NetworkStatusHistoryManager::ModifyAllHistoryRecord(oldNetworkStatusHistory4,
        NetworkStatus::HAS_INTERNET, NetworkStatus::NO_INTERNET);
    EXPECT_TRUE(oldNetworkStatusHistory4 == newNetworkStatusHistory4);
}
} // WIFI
} // OHOS