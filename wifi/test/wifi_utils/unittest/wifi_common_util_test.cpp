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

#include "wifi_common_util.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing::ext;using ::testing::_;
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
constexpr int FREQ_2G_MIN = 2412;
constexpr int CHANNEL_14_FREQ = 2484;
constexpr int FREQ_5G_MIN = 5170;
constexpr int CHANNEL_5G_MIN = 34;
constexpr int MIN_24G_CHANNEL = 1;
constexpr int MIN_5G_CHANNEL = 36;
constexpr int CHANNEL_14 = 14;
constexpr int WIFI_MAC_LENS = 6;
constexpr int FREQ_CHANNEL_36 = 5180;

class WifiCommonUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};
HWTEST_F(WifiCommonUtilTest, MacStrToArrayTest, TestSize.Level1)
{
    std::string strmac = "00:55:DD:ff:MM";
    unsigned char mac[WIFI_MAC_LENS];
    MacStrToArray(strmac, mac);
}

HWTEST_F(WifiCommonUtilTest, Ip2NumberTest, TestSize.Level1)
{
    std::string strIp = "00:55:DD:ff:MM";
    Ip2Number(strIp);
}

HWTEST_F(WifiCommonUtilTest, GetBrokerProcessNameByPidTest, TestSize.Level1)
{
    int uid = FREQ_5G_MIN;
    int pid = CHANNEL_14;
    GetBrokerProcessNameByPid(uid, pid);
}

HWTEST_F(WifiCommonUtilTest, FrequencyToChannelTest, TestSize.Level1)
{
    EXPECT_EQ(FrequencyToChannel(FREQ_2G_MIN), 1);
    EXPECT_EQ(FrequencyToChannel(CHANNEL_14_FREQ), CHANNEL_14);
    EXPECT_EQ(FrequencyToChannel(FREQ_5G_MIN), CHANNEL_5G_MIN);
    EXPECT_EQ(FrequencyToChannel(CHANNEL_5G_MIN), INVALID_FREQ_OR_CHANNEL);
}

HWTEST_F(WifiCommonUtilTest, ChannelToFrequencyTest, TestSize.Level1)
{
    EXPECT_EQ(ChannelToFrequency(MIN_24G_CHANNEL), FREQ_2G_MIN);
    EXPECT_EQ(ChannelToFrequency(MIN_5G_CHANNEL), FREQ_CHANNEL_36);
    EXPECT_EQ(ChannelToFrequency(FREQ_2G_MIN), INVALID_FREQ_OR_CHANNEL);
}

HWTEST_F(WifiCommonUtilTest, SsidAnonymizeTest, TestSize.Level1)
{
    std::string str = "00:55:DD:ff:MM";
    SsidAnonymize(str);
    std::string strs = "00";
    SsidAnonymize(strs);
    std::string strIp = "00:55:DD";
    SsidAnonymize(strIp);
}
}  // namespace Wifi
}  // namespace OHOS