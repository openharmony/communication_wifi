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

constexpr int FREP_2G_MIN = 2412;
constexpr int FREP_5G_MIN = 5170;
constexpr int CHANNEL_14_FREP = 2484;
constexpr int CENTER_FREP_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_5G = 34;
constexpr int CHANNEL_2G = 14;

HWTEST_F(WifiChannelHelperTest, TestGetValidBands, TestSize.Level1)
{
    std::vector<BandType> bands = {};
    WifiChannelHelper::GetInstance().GetValidBands(bands);
    EXPECT_EQ(WifiChannelHelper::GetInstance().GetValidBands(bands), 0);
}

HWTEST_F(WifiChannelHelperTest, TestSetValidChannels, TestSize.Level1)
{
    ChannelsTable validChannels = {
        { BandType::BAND_2GHZ, { 2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472 }},
        { BandType::BAND_5GHZ, { 5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825 }}};
    WifiChannelHelper::GetInstance().SetValidChannels(validChannels);
    EXPECT_EQ(WifiChannelHelper::GetInstance().SetValidChannels(validChannels), 0);
}

HWTEST_F(WifiChannelHelperTest, TestGetValidChannels, TestSize.Level1)
{
    ChannelsTable validChannels;
    WifiChannelHelper::GetInstance().GetValidChannels(validChannels);
    EXPECT_EQ(WifiChannelHelper::GetInstance().GetValidChannels(validChannels), 0);
}

HWTEST_F(WifiChannelHelperTest, TestUpdateValidChannels, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiChannelHelper::GetInstance().UpdateValidChannels(ifaceName);

    ifaceName = "wlan1";
    WifiChannelHelper::GetInstance().UpdateValidChannels(ifaceName);
}

HWTEST_F(WifiChannelHelperTest, UpdateValidFreqsTest, TestSize.Level1)
{
    WifiChannelHelper::GetInstance().UpdateValidFreqs();
}

HWTEST_F(WifiChannelHelperTest, GetAvailableScanFreqsTest, TestSize.Level1)
{
    std::vector<int32_t> freqs;
    WifiChannelHelper::GetInstance().GetAvailableScanFreqs(ScanBandType::SCAN_BAND_24_GHZ, freqs);
    EXPECT_EQ(WifiChannelHelper::GetInstance().GetAvailableScanFreqs(ScanBandType::SCAN_BAND_24_GHZ, freqs), true);
}

HWTEST_F(WifiChannelHelperTest, IsFreqDbacTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().IsFreqDbac(2412, 2417));
    EXPECT_FALSE(WifiChannelHelper::GetInstance().IsFreqDbac(2412, 5200));
}

HWTEST_F(WifiChannelHelperTest, IsChannelDbacTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().IsChannelDbac(1, 2));
    EXPECT_FALSE(WifiChannelHelper::GetInstance().IsChannelDbac(1, 40));
}

HWTEST_F(WifiChannelHelperTest, TransformFrequencyIntoChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(2412) == 1);
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(5200) == 40);
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(52000) == -1);
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(200) == -1);
}

HWTEST_F(WifiChannelHelperTest, TransformFrequencyIntoChannelTest1, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = FREP_2G_MIN;
    freqVector.push_back(target);
    WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_2G_MIN) != 0);
}

HWTEST_F(WifiChannelHelperTest, TransformFrequencyIntoChannelTest2, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = CHANNEL_14_FREP;
    freqVector.push_back(target);
    WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_2G) != 0);
}

HWTEST_F(WifiChannelHelperTest, TransformFrequencyIntoChannelTest3, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = FREP_5G_MIN;
    freqVector.push_back(target);
    WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_5G) != 0);
}

HWTEST_F(WifiChannelHelperTest, TransformFrequencyIntoChannelTest4, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = CHANNEL_2G_MIN;
    freqVector.push_back(target);
    freqVector.push_back(FREP_5G_MIN);
    WifiChannelHelper::GetInstance().TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_5G) != 0);
}

HWTEST_F(WifiChannelHelperTest, TransformChannelToFrequencyTest, TestSize.Level1)
{
    WifiChannelHelper::GetInstance().TransformChannelToFrequency(1);
    EXPECT_EQ(WifiChannelHelper::GetInstance().TransformChannelToFrequency(1), -1);
}

HWTEST_F(WifiChannelHelperTest, TransformFreqToBandTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformFreqToBand(2412) == BandType::BAND_2GHZ);
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformFreqToBand(5200) == BandType::BAND_5GHZ);
}

HWTEST_F(WifiChannelHelperTest, TransformChannelToBandTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformChannelToBand(1) == BandType::BAND_2GHZ);
    EXPECT_TRUE(WifiChannelHelper::GetInstance().TransformChannelToBand(40) == BandType::BAND_5GHZ);
}

HWTEST_F(WifiChannelHelperTest, IsValid24GHzTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().IsValid24GHz(2412));
    EXPECT_FALSE(WifiChannelHelper::GetInstance().IsValid24GHz(5200));
}

HWTEST_F(WifiChannelHelperTest, IsValid5GHzTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().IsValid24GHz(2412));
    EXPECT_FALSE(WifiChannelHelper::GetInstance().IsValid24GHz(5200));
}

HWTEST_F(WifiChannelHelperTest, IsValid24GChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().IsValid24GChannel(1));
    EXPECT_FALSE(WifiChannelHelper::GetInstance().IsValid24GChannel(40));
}

HWTEST_F(WifiChannelHelperTest, IsValid5GChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(WifiChannelHelper::GetInstance().IsValid24GChannel(1));
    EXPECT_FALSE(WifiChannelHelper::GetInstance().IsValid24GChannel(40));
}