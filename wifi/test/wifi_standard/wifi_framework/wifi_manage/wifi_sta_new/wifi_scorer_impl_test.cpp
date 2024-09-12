/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "wifi_scorer_impl.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

constexpr int HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[10] = {
    0, 8000, 4000, 2000, 1000, 16, 8, 4, 2, 1};
constexpr int WIFI_2G_BAND_SCORE_HISTORY_NETWORK = 29;

namespace OHOS {
namespace Wifi {
class WifiScorerImplTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}

public:
};

HWTEST_F(WifiScorerImplTest, ScoreTest01, TestSize.Level1)
{
    InterScanInfo interScanInfo;
    interScanInfo.frequency = 2442;
    NetworkSelection::NoInternetNetworkStatusHistoryScorer  noInternetScore;
    NetworkSelection::NetworkCandidate networkCandidate(interScanInfo);
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 13;
    int realscore = (int)noInternetScore.Score(networkCandidate);
    int expcetScore = HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[1] + WIFI_2G_BAND_SCORE_HISTORY_NETWORK;
    EXPECT_FALSE(realscore == expcetScore);
}

HWTEST_F(WifiScorerImplTest, ScoreTest02, TestSize.Level1)
{
    InterScanInfo interScanInfo;
    interScanInfo.frequency = 2447;
    NetworkSelection::NoInternetNetworkStatusHistoryScorer  noInternetScore;
    NetworkSelection::NetworkCandidate networkCandidate(interScanInfo);
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 221;
    int realscore = (int)noInternetScore.Score(networkCandidate);
    int expcetScore = HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[1] + HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[3] +
            WIFI_2G_BAND_SCORE_HISTORY_NETWORK;
    EXPECT_FALSE(realscore == expcetScore);
}

HWTEST_F(WifiScorerImplTest, ScoreTest03, TestSize.Level1)
{
    InterScanInfo interScanInfo;
    interScanInfo.frequency = 5000;
    NetworkSelection::NoInternetNetworkStatusHistoryScorer  noInternetScore;
    NetworkSelection::NetworkCandidate networkCandidate(interScanInfo);
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 1046389;
    int realscore = (int)noInternetScore.Score(networkCandidate);
    int expcetScore = HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[4] +  HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[6] +
        HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[8] +  HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[9];
    EXPECT_FALSE(realscore == expcetScore);
}

HWTEST_F(WifiScorerImplTest, ScoreTest04, TestSize.Level1)
{
    InterScanInfo interScanInfo;
    interScanInfo.frequency = 5200;
    NetworkSelection::NoInternetNetworkStatusHistoryScorer  noInternetScore;
    NetworkSelection::NetworkCandidate networkCandidate(interScanInfo);
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 917341;
    int realscore = (int)noInternetScore.Score(networkCandidate);
    int expcetScore = HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[1] +  HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[6] +
        HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[7] +  HISTORY_NETWORK_STATUS_WEIGHTED_SCORE[9];
    EXPECT_FALSE(realscore == expcetScore);
}

} // WIFI
} // OHOS