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
#include "wifi_msg.h"
#include "mock_wifi_settings.h"

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
const std::string g_errLog = "wifitest";
DEFINE_WIFILOG_LABEL("WifiProtectTest");
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
    bool result = WifiProtectManager::GetInstance().InitWifiProtect(WifiProtectType::WIFI_PROTECT_COMMON, "wifi");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiProtectTest, OnAppDiedTest, TestSize.Level1)
{
    WIFI_LOGI("OnAppDiedTest enter!");

    // Add simulated wifi connection results
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = OHOS::Wifi::ConnState::CONNECTED;
    wifiLinkedInfo.bssid = "11:22:33:44:55:66";
    EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

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
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}
}  // namespace Wifi
}  // namespace OHOS