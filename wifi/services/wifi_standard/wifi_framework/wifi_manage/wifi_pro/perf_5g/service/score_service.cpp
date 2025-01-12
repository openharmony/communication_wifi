/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include "score_service.h"
#include <cmath>
#include "dual_band_utils.h"
#include "wifi_global_func.h"

namespace OHOS {
namespace Wifi {

ScoreService::ScoreService(std::vector<IScoreCalculator *> scoreCalculators)
    : scoreCalculators_(scoreCalculators)
{}
ScoreService::~ScoreService()
{}
void ScoreService::CalculateScore(ApInfo &apInfo, ScoreResult &scoreResult)
{
    for (const auto &scoreCalculator : scoreCalculators_) {
        if (scoreCalculator->IsSatisfied(apInfo)) {
            scoreCalculator->Calculate(apInfo, scoreResult);
        }
    }
}

// RssiScoreCalculator
RssiScoreCalculator::RssiScoreCalculator() : rssi_({-45, -55, -65, -75, -82}),
    score_({25, 20, 15, 5, 0})
{}
RssiScoreCalculator::~RssiScoreCalculator()
{}
bool RssiScoreCalculator::IsSatisfied(ApInfo &apInfo)
{
    return true;
}
void RssiScoreCalculator::Calculate(ApInfo &apInfo, ScoreResult &scoreResult)
{
    int rssiScore = 0;
    int rssiSize = static_cast<int>(rssi_.size());
    for (int index = 0; index < rssiSize; index++) {
        if (apInfo.rssi < rssi_[index]) {
            continue;
        }
        rssiScore += score_[index];
        int exceedRssi = apInfo.rssi - rssi_[index];
        if (index > 0 && exceedRssi > 0) {
            double avgScore = (double) (score_[index - 1] - score_[index])
                / (double) (rssi_[index - 1] - rssi_[index]);
            double exceedScore = exceedRssi * avgScore;
            rssiScore += std::round(exceedScore);
        }
        break;
    }
    scoreResult.totalScore += rssiScore;
}

ConnectTimeScoreCalculator::ConnectTimeScoreCalculator() : connectHourTime_({100, 50, 10, 5}), score_({5, 3, 1, 0})
{}
ConnectTimeScoreCalculator::~ConnectTimeScoreCalculator()
{}
bool ConnectTimeScoreCalculator::IsSatisfied(ApInfo &apInfo)
{
    return true;
}
void ConnectTimeScoreCalculator::Calculate(ApInfo &apInfo, ScoreResult &scoreResult)
{
    int connectTimeScore = 0;
    int useTotalHour = apInfo.apConnectionInfo.GetTotalUseHour();
    int connectHourTimeSize = static_cast<int>(connectHourTime_.size());
    for (int index = 0; index < connectHourTimeSize; index++) {
        if (useTotalHour < connectHourTime_[index]) {
            continue;
        }
        connectTimeScore += score_[index];
        int exceedHour = useTotalHour - connectHourTime_[index];
        if (index > 0 && exceedHour > 0) {
            double avgScore = (double) (score_[index - 1] - score_[index])
                / (double) (connectHourTime_[index - 1] - connectHourTime_[index]);
            double exceedScore = exceedHour * avgScore;
            connectTimeScore += std::round(exceedScore);
        }
        break;
    }
    scoreResult.totalScore += connectTimeScore;
}

AvgRttScoreCalculator::AvgRttScoreCalculator()
    : avgRtt_({400, 800, 1200, 2000, 4000, 16000}), score_({15, 10, 5, 0, -5, -10})
{}
AvgRttScoreCalculator::~AvgRttScoreCalculator()
{}
bool AvgRttScoreCalculator::IsSatisfied(ApInfo &apInfo)
{
    return true;
}
void AvgRttScoreCalculator::Calculate(ApInfo &apInfo, ScoreResult &scoreResult)
{
    unsigned long avgRttOnRssi = apInfo.apConnectionInfo.GetAvgRttOnRssi(apInfo.rssi);
    if (avgRttOnRssi == 0) {
        return;
    }
    int avgRttScore = 0;
    int avgRttSize = static_cast<int>(avgRtt_.size());
    for (int index = 0; index < avgRttSize; index++) {
        if (avgRttOnRssi > static_cast<unsigned long>(avgRtt_[index])) {
            if (index == avgRttSize - 1) {
                avgRttScore += score_[index];
            }
            continue;
        }
        avgRttScore += score_[index];
        int exceedAvgRtt = avgRtt_[index] - avgRttOnRssi;
        if (index > 0 && exceedAvgRtt > 0) {
            double avgScore = (double) (score_[index - 1] - score_[index])
                / (double) (avgRtt_[index] - avgRtt_[index - 1]);
            double exceedScore = exceedAvgRtt * avgScore;
            avgRttScore += std::round(exceedScore);
        }
        break;
    }
    scoreResult.totalScore += avgRttScore;
}

PacketLostScoreCalculator::PacketLostScoreCalculator()
    : packetLossRate_({0.05, 0.1, 0.2, 0.4, 0.6, 0.8}), score_({15, 10, 5, 0, -5, -10})
{}
PacketLostScoreCalculator::~PacketLostScoreCalculator()
{}
bool PacketLostScoreCalculator::IsSatisfied(ApInfo &apInfo)
{
    return true;
}
void PacketLostScoreCalculator::Calculate(ApInfo &apInfo, ScoreResult &scoreResult)
{
    int lossScore = 0;
    double lostRate = apInfo.apConnectionInfo.GetLostRate();
    int packetLossRateSize = static_cast<int>(packetLossRate_.size());
    for (int index = 0; index < packetLossRateSize; index++) {
        if (DualBandUtils::Compare(lostRate, packetLossRate_[index]) > 0) {
            if (index == packetLossRateSize - 1) {
                lossScore += score_[index];
            }
            continue;
        }
        lossScore += score_[index];
        double exceedLostRate = packetLossRate_[index] - lostRate;
        if (index > 0 && DualBandUtils::Compare(exceedLostRate, 0.0) > 0) {
            double avgScore = (double) (score_[index - 1] - score_[index])
                / (double) (packetLossRate_[index] - packetLossRate_[index - 1]);
            double exceedScore = avgScore * exceedLostRate;
            lossScore += std::round(exceedScore);
        }
        break;
    }
    scoreResult.totalScore += lossScore;
}

Ap5gScoreCalculator::Ap5gScoreCalculator(std::string connectedApBssid) : connectedApBssid_(connectedApBssid)
{}
Ap5gScoreCalculator::~Ap5gScoreCalculator()
{}
bool Ap5gScoreCalculator::IsSatisfied(ApInfo &apInfo)
{
    return IsValid5GHz(apInfo.frequency);
}
void Ap5gScoreCalculator::Calculate(ApInfo &apInfo, ScoreResult &scoreResult)
{
    if (DualBandUtils::IsSameRouterAp(connectedApBssid_, apInfo.bssid)) {
        int sameRout5gScore = 6;
        scoreResult.totalScore += sameRout5gScore;
    }
    if (IsBtConnected()) {
        int btConnected5gScore = 10;
        scoreResult.totalScore += btConnected5gScore;
    }
}
bool Ap5gScoreCalculator::IsBtConnected()
{
    return false;
}

WifiCategoryScoreCalculator::WifiCategoryScoreCalculator()
{}
WifiCategoryScoreCalculator::~WifiCategoryScoreCalculator()
{}
bool WifiCategoryScoreCalculator::IsSatisfied(ApInfo &apInfo)
{
    return true;
}
constexpr int WIFI7_PLUS_EMLSR_SCORE = 7;
constexpr int WIFI7_MLSR_SCORE = 6;
constexpr int WIFI6_PLUS_160M_SCORE = 5;
constexpr int WIFI6_PLUS_SCORE = 4;
constexpr int WIFI6_160M_SCORE = 3;
constexpr int WIFI6_SCORE = 2;
constexpr int DEFAULT_SCORE = 1;

void WifiCategoryScoreCalculator::Calculate(ApInfo &apInfo, ScoreResult &scoreResult)
{
    switch (apInfo.wifiCategory) {
        case WifiCategory::WIFI7_PLUS:
            scoreResult.totalScore += WIFI7_PLUS_EMLSR_SCORE;
            break;
        case WifiCategory::WIFI7:
            scoreResult.totalScore += WIFI7_MLSR_SCORE;
            break;
        case WifiCategory::WIFI6_PLUS:
            if (apInfo.channelWidth == WifiChannelWidth::WIDTH_160MHZ) {
                scoreResult.totalScore += WIFI6_PLUS_160M_SCORE;
            } else {
                scoreResult.totalScore += WIFI6_PLUS_SCORE;
            }
            break;
        case WifiCategory::WIFI6:
            if (apInfo.channelWidth == WifiChannelWidth::WIDTH_160MHZ) {
                scoreResult.totalScore += WIFI6_160M_SCORE;
            } else {
                scoreResult.totalScore += WIFI6_SCORE;
            }
            break;
        default:
            scoreResult.totalScore += DEFAULT_SCORE;
            break;
    }
}
}  // namespace Wifi
}  // namespace OHOS