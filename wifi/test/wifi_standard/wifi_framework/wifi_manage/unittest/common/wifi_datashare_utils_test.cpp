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
#include "data_ability_observer_stub.h"
#include "wifi_datashare_utils.h"
#include "datashare_predicates.h"
#include "wifi_log.h"
#include "wifi_logger.h"
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const std::string g_errLog = "wifitest";
class WifiMockModeObserver : public AAFwk::DataAbilityObserverStub {
public:
    WifiMockModeObserver() = default;

    ~WifiMockModeObserver() = default;

    void OnChange() {};
};
class WifiDataShareHelperUtilsTest : public Test {
public:
    void SetUp() override
    {
        observer = sptr<WifiMockModeObserver>(new (std::nothrow)WifiMockModeObserver());
    }

    void TearDown() override
    {
    }

protected:
    std::string value;
    sptr<WifiMockModeObserver> observer;
};

HWTEST_F(WifiDataShareHelperUtilsTest, Query_ReturnsSuccess, TestSize.Level1)
{
    Uri uri("datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true");
    std::string key = "wifi_on";
    bool onlySettingsData = true;
    ErrCode result = WifiDataShareHelperUtils::GetInstance().Query(uri, key, value, onlySettingsData);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiDataShareHelperUtilsTest, Insert_ReturnsFailed, TestSize.Level1)
{
    Uri uri("datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true");
    std::string key = "wifi_on";
    value = "1";
    ErrCode result = WifiDataShareHelperUtils::GetInstance().Insert(uri, key, value);
    EXPECT_EQ(result, WIFI_OPT_FAILED);
}

HWTEST_F(WifiDataShareHelperUtilsTest, Update_ReturnsFailed, TestSize.Level1)
{
    Uri uri("datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true");
    std::string key = "wifi_on";
    value = "0";
    ErrCode result = WifiDataShareHelperUtils::GetInstance().Update(uri, key, value);
    EXPECT_EQ(result, WIFI_OPT_FAILED);
}

HWTEST_F(WifiDataShareHelperUtilsTest, RegisterObserver_ReturnsSuccess, TestSize.Level1)
{
    Uri uri("datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true");
    ErrCode result = WifiDataShareHelperUtils::GetInstance().RegisterObserver(uri, observer);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiDataShareHelperUtilsTest, UnRegisterObserver_ReturnsSuccess, TestSize.Level1)
{
    Uri uri("datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true");
    ErrCode result = WifiDataShareHelperUtils::GetInstance().UnRegisterObserver(uri, observer);

    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

}
}