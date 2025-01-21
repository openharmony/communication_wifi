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
                                      const unsigned int domain, const char *tag, const char *msg)
    {
        g_errLog = msg;
    }
class NetworkStatusHistoryManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() 
    {
        LOG_SetCallback(NetworkCallback);
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

} // WIFI
} // OHOS