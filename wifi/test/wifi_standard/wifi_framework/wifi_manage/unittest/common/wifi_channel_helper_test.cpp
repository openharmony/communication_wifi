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
#include "wifi_channel_helper.h"

using namespace OHOS::Wifi;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

class WifiChannelHelperTest : public testing::Test {
protected:
    void SetUp() override
    {}

    void TearDown() override
    {}
};

HWTEST_F(WifiChannelHelperTest, TestGetValidBands, TestSize.Level1)
{
    std::vector<BandType> bands = {};
    WifiChannelHelper::GetInstance().GetValidBands(bands);
}

HWTEST_F(WifiChannelHelperTest, TestSetValidChannels, TestSize.Level1)
{
    ChannelsTable validChannels = {
        { BandType::BAND_2GHZ, { 2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472 }},
        { BandType::BAND_5GHZ, { 5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825 }}};
    WifiChannelHelper::GetInstance().SetValidChannels(validChannels);
}

HWTEST_F(WifiChannelHelperTest, TestGetValidChannels, TestSize.Level1)
{
    ChannelsTable validChannels;
    WifiChannelHelper::GetInstance().GetValidChannels(validChannels);
}

HWTEST_F(WifiChannelHelperTest, TestUpdateValidChannels, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiChannelHelper::GetInstance().UpdateValidChannels(ifaceName);

    ifaceName = "wlan1";
    WifiChannelHelper::GetInstance().UpdateValidChannels(ifaceName);
}
