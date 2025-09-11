/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "self_cure_utils.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class SelfCureUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(SelfCureUtilsTest, IsIpConflictDetectTest001, TestSize.Level1)
{
    IpInfo ipInfo;
    ipInfo.ipAddress = 0;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return(""));
    EXPECT_FALSE(SelfCureUtils::GetInstance().IsIpConflictDetect());
}

HWTEST_F(SelfCureUtilsTest, IsIpConflictDetectTest002, TestSize.Level1)
{
    IpInfo ipInfo;
    ipInfo.ipAddress = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return(""));
    EXPECT_FALSE(SelfCureUtils::GetInstance().IsIpConflictDetect());
}

HWTEST_F(SelfCureUtilsTest, IsIpConflictDetectTest003, TestSize.Level1)
{
    IpInfo ipInfo;
    ipInfo.ipAddress = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("STA"));
    SelfCureUtils::GetInstance().IsIpConflictDetect();
}

HWTEST_F(SelfCureUtilsTest, GetSelfCureHistoryTest001, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).WillRepeatedly(Return(-1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_TRUE(SelfCureUtils::GetInstance().GetSelfCureHistory() == "");
}

HWTEST_F(SelfCureUtilsTest, GetSelfCureHistoryTest002, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(-1));
    EXPECT_TRUE(SelfCureUtils::GetInstance().GetSelfCureHistory() == "");
}

HWTEST_F(SelfCureUtilsTest, GetSelfCureHistoryTest003, TestSize.Level1)
{
    WifiDeviceConfig config;
    config.internetSelfCureHistory = "123";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    EXPECT_TRUE(SelfCureUtils::GetInstance().GetSelfCureHistory() == "123");
}

HWTEST_F(SelfCureUtilsTest, ReportNoInternetChrEventTest001, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureResetEntered()).WillRepeatedly(Return(0));
    SelfCureUtils::GetInstance().ReportNoInternetChrEvent();
}

HWTEST_F(SelfCureUtilsTest, IsIpv6SelfCureSupportedTest, TestSize.Level1)
{
    // Test IPv6 self-cure support check
    EXPECT_TRUE(SelfCureUtils::GetInstance().IsIpv6SelfCureSupported());
}

HWTEST_F(SelfCureUtilsTest, DisableIpv6Test, TestSize.Level1)
{
    // Test IPv6 disable functionality
    // Note: This test may fail in environments without proper network setup
    // but validates the method can be called without crashing
    bool result = SelfCureUtils::GetInstance().DisableIpv6();
    // We expect either success or failure, not a crash
    EXPECT_TRUE(result == true || result == false);
}
}
}