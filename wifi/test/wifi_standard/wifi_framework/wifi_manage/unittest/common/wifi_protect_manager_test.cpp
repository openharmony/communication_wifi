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

constexpr int TEN = 10;

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

HWTEST_F(WifiProtectManagerTest, GetNearlyProtectModeTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::SCANNING;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
}

HWTEST_F(WifiProtectManagerTest, GetNearlyProtectModeTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::CONNECTED;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    wifiProtectManager.mForceHiPerfMode = true;
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
}

HWTEST_F(WifiProtectManagerTest, GetNearlyProtectModeTest003, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::CONNECTED;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    wifiProtectManager.mForceLowLatencyMode = true;
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
}

HWTEST_F(WifiProtectManagerTest, GetNearlyProtectModeTest004, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::CONNECTED;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    wifiProtectManager.AddProtect(WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "com.example.app");
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
}

HWTEST_F(WifiProtectManagerTest, GetWifiProtectTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    std::string name = "";
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.GetWifiProtect(WifiProtectMode::WIFI_PROTECT_NO_HELD, name), false);
}

HWTEST_F(WifiProtectManagerTest, GetWifiProtectTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.GetWifiProtect(WifiProtectMode::WIFI_PROTECT_FULL, "com.example.app"), true);
}

HWTEST_F(WifiProtectManagerTest, GetWifiProtectTest003, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.GetWifiProtect(WifiProtectMode::WIFI_PROTECT_NO_HELD, "com.example.app"), false);
}

HWTEST_F(WifiProtectManagerTest, GetWifiProtectTest004, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    for (int i = 0; i < 101; i++) {
        wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    }
    EXPECT_EQ(wifiProtectManager.GetWifiProtect(WifiProtectMode::WIFI_PROTECT_NO_HELD, "com.example2.app"), false);
}

HWTEST_F(WifiProtectManagerTest, ChangeToPerfModeTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.ChangeToPerfMode(true), true);
}

HWTEST_F(WifiProtectManagerTest, HandleScreenStateChangedTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::SCANNING;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    wifiProtectManager.mCurrentOpMode = wifiProtectManager.GetNearlyProtectMode();
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
    EXPECT_EQ(wifiProtectManager.ChangeWifiPowerMode(), true);
    wifiProtectManager.HandleScreenStateChanged(true);
}

HWTEST_F(WifiProtectManagerTest, UpdateWifiClientConnectedTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::SCANNING;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    wifiProtectManager.mCurrentOpMode = wifiProtectManager.GetNearlyProtectMode();
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
    EXPECT_EQ(wifiProtectManager.ChangeWifiPowerMode(), true);
    wifiProtectManager.UpdateWifiClientConnected(true);
}

HWTEST_F(WifiProtectManagerTest, AddProtectTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.AddProtect(WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, ""), true);
}

HWTEST_F(WifiProtectManagerTest, AddProtectTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.AddProtect(WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "com.example.app"), true);
    EXPECT_EQ(wifiProtectManager.AddProtect(WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "com.example.app"), true);
}

HWTEST_F(WifiProtectManagerTest, PutWifiProtectTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    EXPECT_EQ(wifiProtectManager.PutWifiProtect(""), false);
    EXPECT_EQ(wifiProtectManager.PutWifiProtect("com.example.app"), false);
}

HWTEST_F(WifiProtectManagerTest, PutWifiProtectTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
        WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "com.example.app");
    wifiProtectManager.mWifiProtects.push_back(pProtect);
    EXPECT_EQ(wifiProtectManager.PutWifiProtect("com.example.app"), true);
}

HWTEST_F(WifiProtectManagerTest, PutWifiProtectTest003, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
        WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "com.example.app");
    wifiProtectManager.mWifiProtects.push_back(pProtect);
    EXPECT_EQ(wifiProtectManager.PutWifiProtect("com.example.app"), true);
}

HWTEST_F(WifiProtectManagerTest, ChangeWifiPowerModeTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    wifiProtectManager.mCurrentOpMode = WifiProtectMode::WIFI_PROTECT_NO_HELD;
    linkedInfo.connState == ConnState::SCANNING;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    EXPECT_EQ(wifiProtectManager.GetNearlyProtectMode(), WifiProtectMode::WIFI_PROTECT_NO_HELD);
    EXPECT_EQ(wifiProtectManager.ChangeWifiPowerMode(), true);
}

HWTEST_F(WifiProtectManagerTest, ChangeWifiPowerModeTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    wifiProtectManager.mCurrentOpMode = WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF;
    linkedInfo.connState == ConnState::SCANNING;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    EXPECT_EQ(wifiProtectManager.ChangeWifiPowerMode(), false);
}

HWTEST_F(WifiProtectManagerTest, ChangeWifiPowerModeTest003, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    WifiLinkedInfo linkedInfo;
    wifiProtectManager.mCurrentOpMode = WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY;
    linkedInfo.connState == ConnState::SCANNING;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    EXPECT_EQ(wifiProtectManager.ChangeWifiPowerMode(), false);
}

HWTEST_F(WifiProtectManagerTest, SetLowLatencyModeTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.SetLowLatencyMode(true), false);
}

HWTEST_F(WifiProtectManagerTest, SetLowLatencyModeTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.SetLowLatencyMode(false), false);
}

HWTEST_F(WifiProtectManagerTest, GetFgLowlatyProtectCountTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
        WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "com.example.app");
    int state = static_cast<int>(OHOS::AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    pProtect->SetAppState(state);
    wifiProtectManager.mWifiProtects.push_back(pProtect);
    
    EXPECT_EQ(wifiProtectManager.GetFgLowlatyProtectCount(), 1);
}

HWTEST_F(WifiProtectManagerTest, OnAppDiedTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
        WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "com.example.app");
    wifiProtectManager.mWifiProtects.push_back(pProtect);
    wifiProtectManager.OnAppDied("com.example.app");
    EXPECT_NE(wifiProtectManager.mFullHighPerfProtectsAcquired, TEN);
}

HWTEST_F(WifiProtectManagerTest, OnAppDiedTest002, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
        WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "com.example.app");
    wifiProtectManager.mWifiProtects.push_back(pProtect);
    wifiProtectManager.OnAppDied("com.example.app");
    EXPECT_NE(wifiProtectManager.mFullHighPerfProtectsAcquired, TEN);
}

HWTEST_F(WifiProtectManagerTest, OnAppForegroudChangedTest001, TestSize.Level1)
{
    WifiProtectManager wifiProtectManager;
    wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app");
    EXPECT_EQ(wifiProtectManager.InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "com.example.app"),true);
    wifiProtectManager.OnAppForegroudChanged("com.example.app", 1);
}
// Add more test cases as needed