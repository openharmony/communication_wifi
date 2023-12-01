/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_protect_manager.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiProtectTest");
constexpr int NETWORK_ID = 15;
constexpr int TYPE = 3;
constexpr int SCORE = 0;
constexpr int STATE = 0;
constexpr int UID = 0;
constexpr int ZERO = 0;
constexpr int WIFI_OPT_SUCCESS = 0;
constexpr int WIFI_OPT_RETURN = -1;
constexpr int MIN_RSSI_2DOT_4GHZ = -80;
constexpr int MIN_RSSI_5GZ = -77;
class WifiProtectTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiProtectTest, InitWifiProtectTest, TestSize.Level1)
{
    WIFI_LOGI("ClearScanInfoListTest enter!");
    bool result = WifiProtectManager::GetInstance().InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "wifiprotect");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, GetWifiProtectTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiProtectTest enter!");
    bool result = WifiProtectManager::GetInstance().GetWifiProtect(WifiProtectMode::WIFI_PROTECT_FULL, "wifiprotect");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().GetWifiProtect(WifiProtectMode::WIFI_PROTECT_SCAN_ONLY, "wifiprotect");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().GetWifiProtect(WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "wifiprotect");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().GetWifiProtect(WifiProtectMode::WIFI_PROTECT_NO_HELD, nullptr);
    EXPECT_FALSE(result);
    result = WifiProtectManager::GetInstance().GetWifiProtect(WifiProtectMode::WIFI_PROTECT_NO_HELD, "wifiprotect");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, IsHeldWifiProtectTest, TestSize.Level1)
{
    WIFI_LOGI("IsHeldWifiProtectTest enter!");
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL, "wifiprotext");
    std::shared_ptr<WifiProtect> pProtext = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL, "wifiprotect");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtect);
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtext);
    bool result = WifiProtectManager::GetInstance().IsHeldWifiProtect("wifiprotect");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().IsHeldWifiProtect("wifiprotest");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, GetNearlyProtectModeTest, TestSize.Level1)
{
    WIFI_LOGI("GetNearlyProtectMode enter!");
    WifiProtectMode result = WifiProtectManager::GetInstance().GetNearlyProtectMode();
    EXPECT_EQ(result, WifiProtectMode::WIFI_PROTECT_NO_HELD);
}

HWTEST_F(WifiProtectTest, GetNearlyProtectModeTest, TestSize.Level1)
{
    WIFI_LOGI("GetNearlyProtectMode enter!");
    bool result = WifiProtectManager::GetInstance().ChangeToPerfMode(true);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, ChangeWifiPowerModeTest, TestSize.Level1)
{
    WIFI_LOGI("ChangeWifiPowerModeTest enter!");
    result = WifiProtectManager::GetInstance().ChangeWifiPowerMode();
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, HandleScreenStateChangedTest, TestSize.Level1)
{
    WIFI_LOGI("HandleScreenStateChanged enter!");
    result = WifiProtectManager::GetInstance().HandleScreenStateChanged(true);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, AddProtectTest, TestSize.Level1)
{
    WIFI_LOGI("AddProtect enter!");
    bool result = WifiProtectManager::GetInstance().AddProtect(WifiProtectMode::WIFI_PROTECT_FULL, "wifiprotect");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().AddProtect(WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "wifiprotect");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().AddProtect(WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "wifiprotect");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, PutWifiProtectTest, TestSize.Level1)
{
    WIFI_LOGI("PutWifiProtectTest enter!");
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "wifiprotect");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtect);
    bool result = WifiProtectManager::GetInstance().PutWifiProtect("wifiprotext");
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().PutWifiProtect("wifiprotect");
    EXPECT_TRUE(result);
    pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "wifiprotext");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtect);
    result = WifiProtectManager::GetInstance().PutWifiProtect("wifiprotext");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, GetFgLowlatyProtectCountTest, TestSize.Level1)
{
    WIFI_LOGI("GetFgLowlatyProtectCount enter!");
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "wifiprotect");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtect);
    bool result = WifiProtectManager::GetInstance().GetFgLowlatyProtectCount();
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, SetLowLatencyModeTest, TestSize.Level1)
{
    WIFI_LOGI("SetLowLatencyMode enter!");
    bool result = WifiProtectManager::GetInstance().SetLowLatencyMode(true);
    EXPECT_TRUE(result);
    result = WifiProtectManager::GetInstance().SetLowLatencyMode(false);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, RegisterAppStateObserverTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterAppStateObserverTest enter!");
    bool result = WifiProtectManager::GetInstance().RegisterAppStateObserver();
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, OnAppDiedTest, TestSize.Level1)
{
    WIFI_LOGI("OnAppDiedTest enter!");
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "wifiprotect");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtect);
    WifiProtectManager::GetInstance().OnAppDied("wifiprotect");
    std::shared_ptr<WifiProtect> pProtext = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL_LOW_LATENCY, "wifiprotext");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtext);
    WifiProtectManager::GetInstance().OnAppDied("wifiprotext");
}

HWTEST_F(WifiProtectTest, OnAppForegroudChangedTest, TestSize.Level1)
{
    WIFI_LOGI("OnAppForegroudChangedTest enter!");
    std::shared_ptr<WifiProtect> pProtect = std::make_shared<WifiProtect>(WifiProtectType::WIFI_PROTECT_COMMON,
    WifiProtectMode::WIFI_PROTECT_FULL_HIGH_PERF, "wifiprotect");
    WifiProtectManager::GetInstance().mWifiProtects.push_back(pProtect);
    WifiProtectManager::GetInstance().OnAppForegroudChanged("wifiprotext", 0);
}
}  // namespace Wifi
}  // namespace OHOS