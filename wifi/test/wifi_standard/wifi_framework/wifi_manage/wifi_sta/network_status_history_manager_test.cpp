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
#include <vector>
#include "network_status_history_manager.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class NetworkStatusHistoryManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(NetworkStatusHistoryManagerTest, InsertUnKnown, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11111111111111111111;
    NetworkStatusHistoryManager::Insert(networkStatusHistory, NetworkStatus::UNKNOWN);
    EXPECT_EQ(networkStatusHistory, 0b11111111111111111100);
}

HWTEST_F(NetworkStatusHistoryManagerTest, InsertHasInternet, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11111111111111111111;
    NetworkStatusHistoryManager::Insert(networkStatusHistory, NetworkStatus::HAS_INTERNET);
    EXPECT_EQ(networkStatusHistory, 0b11111111111111111101);
}

HWTEST_F(NetworkStatusHistoryManagerTest, InsertPortal, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11111111111111111111;
    NetworkStatusHistoryManager::Insert(networkStatusHistory, NetworkStatus::PORTAL);
    EXPECT_EQ(networkStatusHistory, 0b11111111111111111110);
}

HWTEST_F(NetworkStatusHistoryManagerTest, InsertNoInternet, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11111111111111111111;
    NetworkStatusHistoryManager::Insert(networkStatusHistory, NetworkStatus::NO_INTERNET);
    EXPECT_EQ(networkStatusHistory, 0b11111111111111111111);
}

HWTEST_F(NetworkStatusHistoryManagerTest, UpdateUnKnown, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11;
    NetworkStatusHistoryManager::Update(networkStatusHistory, NetworkStatus::UNKNOWN);
    EXPECT_EQ(networkStatusHistory, 0b00);
}

HWTEST_F(NetworkStatusHistoryManagerTest, UpdateHasInternet, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11;
    NetworkStatusHistoryManager::Update(networkStatusHistory, NetworkStatus::HAS_INTERNET);
    EXPECT_EQ(networkStatusHistory, 0b01);
}

HWTEST_F(NetworkStatusHistoryManagerTest, UpdatePortal, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b11;
    NetworkStatusHistoryManager::Update(networkStatusHistory, NetworkStatus::PORTAL);
    EXPECT_EQ(networkStatusHistory, 0b10);
}

HWTEST_F(NetworkStatusHistoryManagerTest, UpdateNoInternet, TestSize.Level1)
{
    uint32_t networkStatusHistory = 0b10;
    NetworkStatusHistoryManager::Update(networkStatusHistory, NetworkStatus::NO_INTERNET);
    EXPECT_EQ(networkStatusHistory, 0b11);
}

HWTEST_F(NetworkStatusHistoryManagerTest, IsInternetAccessByHistory, TestSize.Level1)
{
    EXPECT_FALSE(NetworkStatusHistoryManager::IsInternetAccessByHistory(0));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsInternetAccessByHistory(0b01));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsInternetAccessByHistory(0b0111));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsInternetAccessByHistory(0b010100));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b01011101011101110101));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b01010101011101110101));
}

HWTEST_F(NetworkStatusHistoryManagerTest, IsAllowRecoveryByHistory, TestSize.Level1)
{
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b10));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b01));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b11));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b0111));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b0110));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b0101));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b1111));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b010111));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b01011101011101110101));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsAllowRecoveryByHistory(0b01010101011101110101));
}

HWTEST_F(NetworkStatusHistoryManagerTest, IsPortalByHistory, TestSize.Level1)
{
    EXPECT_FALSE(NetworkStatusHistoryManager::IsPortalByHistory(0));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsPortalByHistory(0b01));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsPortalByHistory(0b11));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsPortalByHistory(0b10));
}

HWTEST_F(NetworkStatusHistoryManagerTest, HasInternetEverByHistory, TestSize.Level1)
{
    EXPECT_FALSE(NetworkStatusHistoryManager::HasInternetEverByHistory(0));
    EXPECT_FALSE(NetworkStatusHistoryManager::HasInternetEverByHistory(0b10));
    EXPECT_FALSE(NetworkStatusHistoryManager::HasInternetEverByHistory(0b11));
    EXPECT_TRUE(NetworkStatusHistoryManager::HasInternetEverByHistory(0b01));
}

HWTEST_F(NetworkStatusHistoryManagerTest, IsEmptyNetworkStatusHistory, TestSize.Level1)
{
    EXPECT_FALSE(NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(0b01));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(0b10));
    EXPECT_FALSE(NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(0b11));
    EXPECT_TRUE(NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(0));
}
} // Wifi
} // OHOS