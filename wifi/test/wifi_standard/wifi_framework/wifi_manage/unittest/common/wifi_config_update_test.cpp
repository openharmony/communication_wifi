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
#include "wifi_log.h"
#include "wifi_logger.h"
#include "wifi_config_update.h"
using namespace OHOS;
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


class WifiConfigUpdateTest : public Test {
public:
    void SetUp() {}
    void TearDown() {}

protected:
    WifiConfigUpdate wifiConfigUpdate;
};

HWTEST_F(WifiConfigUpdateTest, LibUtilsTest, TestSize.Level1)
{
    void* handleTest;
    LibraryUtils libUtils("libwifi_config_update.z.so", handleTest, false);
    using SaveWifiConfigFunc = void(*)(const char*, const char*, const char*);
    SaveWifiConfigFunc saveWifiConfigTest = (SaveWifiConfigFunc)libUtils.GetFunc("SaveWifiConfiguration");
    ASSERT_NE(saveWifiConfigTest, nullptr);
    ASSERT_NE(handleTest, nullptr);
}

HWTEST_F(WifiConfigUpdateTest, SaveWifiConfig, TestSize.Level1)
{
    const char* ssid = "TestSSID";
    const char* keyMgmt = "WPA-PSK";
    const char* preSharedKey = "TestPassword";
    wifiConfigUpdate.SaveWifiConfig(ssid, keyMgmt, preSharedKey);
    EXPECT_NE(wifiConfigUpdate.handle_, nullptr);
}
