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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_protect_manager.h"
#include "wifi_log.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "mock_wifi_settings.h"

using namespace OHOS::Wifi;
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

class WifiProtectManagerTest : public Test {
public:
    void SetUp() override
    {}

    void TearDown() override
    {}
};

HWTEST_F(WifiProtectManagerTest, IsValidProtectMode_ReturnsTrueForValidModes, TestSize.Level1)
{
    EXPECT_TRUE(WifiProtectManager::IsValidProtectMode(WifiProtectMode::WIFI_PROTECT_FULL));
    EXPECT_TRUE(WifiProtectManager::IsValidProtectMode(WifiProtectMode::WIFI_PROTECT_SCAN_ONLY));
    EXPECT_TRUE(WifiProtectManager::IsValidProtectMode(WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF));
    EXPECT_TRUE(WifiProtectManager::IsValidProtectMode(WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY));
}

HWTEST_F(WifiProtectManagerTest, IsValidProtectMode_ReturnsFalseForInvalidMode, TestSize.Level1)
{
    EXPECT_FALSE(WifiProtectManager::IsValidProtectMode(static_cast<WifiProtectMode>(100)));
}

HWTEST_F(WifiProtectManagerTest, IsHeldWifiProtect_ReturnsTrueIfProtectIsHeld, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");

    EXPECT_TRUE(wifiProtectManager.IsHeldWifiProtect("com.example.app"));
}

HWTEST_F(WifiProtectManagerTest, IsHeldWifiProtect_ReturnsFalseIfProtectIsNotHeld, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");

    EXPECT_FALSE(wifiProtectManager.IsHeldWifiProtect("com.example.otherapp"));
}

HWTEST_F(WifiProtectManagerTest, GetNearlyProtectMode_ReturnsCorrectMode, TestSize.Level1)
{
    // Add simulated wifi connection results
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = OHOS::Wifi::ConnState::CONNECTED;
    wifiLinkedInfo.bssid = "11:22:33:44:55:66";
    EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    ASSERT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
}

// Add more test cases as needed