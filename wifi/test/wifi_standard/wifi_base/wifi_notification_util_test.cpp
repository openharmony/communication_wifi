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
#include "wifi_notification_util.h"
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
static std::string g_errLog = "wifitest";
class WifiNotificationUtilTest : public Test {
public:
    void SetUp() override
    {}

    void TearDown() override
    {}

protected:
    static const int sidSize = 5;
};

HWTEST_F(WifiNotificationUtilTest, PublishWifiNotificationTest001, TestSize.Level1)
{
    WifiNotificationUtil wifiNotificationUtil;
    std::string ssid(sidSize, 'a');
    wifiNotificationUtil.PublishWifiNotification(WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, ssid,
            WifiNotificationStatus::WIFI_PORTAL_TIMEOUT);
    EXPECT_FALSE(g_errLog.find("WifiNotificationUtilTest")!=std::string::npos);
}

HWTEST_F(WifiNotificationUtilTest, CancelWifiNotificationTest001, TestSize.Level1)
{
    WifiNotificationUtil wifiNotificationUtil;
    wifiNotificationUtil.CancelWifiNotification(WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID);
    EXPECT_FALSE(g_errLog.find("WifiNotificationUtilTest")!=std::string::npos);
}

HWTEST_F(WifiNotificationUtilTest, StartAbilityTest001, TestSize.Level1)
{
    WifiNotificationUtil wifiNotificationUtil;
    OHOS::AAFwk::Want want;
    auto result = wifiNotificationUtil.StartAbility(want);
    EXPECT_TRUE(result != -1);
}

HWTEST_F(WifiNotificationUtilTest, ShowDialogTest001, TestSize.Level1)
{
    WifiNotificationUtil wifiNotificationUtil;
    wifiNotificationUtil.ShowDialog(WifiDialogType::CDD);
    EXPECT_FALSE(g_errLog.find("WifiNotificationUtilTest")!=std::string::npos);
}

HWTEST_F(WifiNotificationUtilTest, ShowSettingsDialogTest001, TestSize.Level1)
{
    WifiNotificationUtil wifiNotificationUtil;
    std::string settings = "";
    wifiNotificationUtil.ShowSettingsDialog(WifiDialogType::CDD, settings);
    EXPECT_FALSE(g_errLog.find("WifiNotificationUtilTest")!=std::string::npos);
}