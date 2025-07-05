/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "dual_band_selector.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"
#include "dual_band_learning_alg_service.h"
#include "dual_band_utils.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("DualBandSelector");

static void PrintSatisfyRssiAps(std::vector<CandidateRelationApInfo> &candidateRelationApInfos)
{
    std::stringstream associateInfo;
    for (auto iter : candidateRelationApInfos) {
        if (associateInfo.rdbuf() ->in_avail() != 0) {
            associateInfo << ",";
        }
        if (iter.apInfo.bssid.length() < MAC_LAST2) {
            WIFI_LOGE("PrintSatisfyRssiAps, mac length error");
            continue;
        }
        associateInfo << "\"" << SsidAnonymize(iter.apInfo.ssid) << "_" <<
            iter.apInfo.keyMgmt << "_" << iter.apInfo.bssid.substr(iter.apInfo.bssid.length() - MAC_LAST2) <<"\"";
    }
    WIFI_LOGI("SatisfyRssiAps [%{public}s]", associateInfo.str().c_str());
}

std::shared_ptr<CandidateRelationApInfo> DualBandSelector::Select(ApInfo &currentApInfo,
    std::vector<CandidateRelationApInfo> &candidateRelationApInfos)
{
    PrintSatisfyRssiAps(candidateRelationApInfos);
    ScoreResult currentApScoreResult;
    CalculateScore(currentApScoreResult, currentApInfo, candidateRelationApInfos);
    CandidateRelationApInfo *bestCandidateRelationAp =
        GetBestCandidateRelationApInfo(candidateRelationApInfos, currentApInfo.bssid);
    if (bestCandidateRelationAp == nullptr) {
        return nullptr;
    }
    WIFI_LOGI("DualBandSelector::Select, currentap Score(%{public}d), bestAp Score(%{public}d), tar(%{public}s)",
        currentApScoreResult.totalScore, bestCandidateRelationAp->scoreResult.totalScore,
        MacAnonymize(bestCandidateRelationAp->apInfo.bssid).data());
    std::vector<DualBandSelectionStrategy *> dualBandSelectionStrategys;
    MakeSelectionStrategy(currentApInfo.bssid, dualBandSelectionStrategys, *bestCandidateRelationAp,
        currentApScoreResult);
    std::shared_ptr<CandidateRelationApInfo> selectRelationAp = nullptr;
    for (auto &selectionStrategy : dualBandSelectionStrategys) {
        if (selectionStrategy->IsSelected()) {
            WIFI_LOGI("selectionStrategy name is %{public}s", selectionStrategy->GetName().data());
            selectRelationAp = std::make_shared<CandidateRelationApInfo>(*bestCandidateRelationAp);
            selectRelationAp->selectStrategyName = selectionStrategy->GetName();
            break;
        }
    }
    for (auto pSelectionStrategy : dualBandSelectionStrategys) {
        delete pSelectionStrategy;
    }
    dualBandSelectionStrategys.clear();
    return selectRelationAp;
}
CandidateRelationApInfo* DualBandSelector::GetBestCandidateRelationApInfo(
    std::vector<CandidateRelationApInfo> &candidateRelationApInfos, std::string connectedApBssid)
{
    CandidateRelationApInfo *pBestCandidateRelationApInfo = nullptr;
    for (auto &candidateRelationApInfo : candidateRelationApInfos) {
        if (pBestCandidateRelationApInfo == nullptr) {
            pBestCandidateRelationApInfo = &candidateRelationApInfo;
        } else if (pBestCandidateRelationApInfo->scoreResult.totalScore
            < candidateRelationApInfo.scoreResult.totalScore) {
            pBestCandidateRelationApInfo = &candidateRelationApInfo;
        } else if (pBestCandidateRelationApInfo->scoreResult.totalScore
            == candidateRelationApInfo.scoreResult.totalScore
            && DualBandUtils::IsSameRouterAp(connectedApBssid, candidateRelationApInfo.apInfo.bssid)) {
            pBestCandidateRelationApInfo = &candidateRelationApInfo;
        }
    }
    return pBestCandidateRelationApInfo;
}
void DualBandSelector::CalculateScore(ScoreResult &currentApScoreResult, ApInfo &currentApInfo,
    std::vector<CandidateRelationApInfo> &candidateRelationApInfos)
{
    std::vector<IScoreCalculator *> scoreCalculators;
    MakeScoreCalculators(scoreCalculators, currentApInfo.bssid);
    ScoreService scoreService(scoreCalculators);
    for (auto &candidateRelationApInfo : candidateRelationApInfos) {
        scoreService.CalculateScore(candidateRelationApInfo.apInfo, candidateRelationApInfo.scoreResult);
    }
    scoreService.CalculateScore(currentApInfo, currentApScoreResult);
    for (auto pScoreCalculator : scoreCalculators) {
        delete pScoreCalculator;
    }
    scoreCalculators.clear();
}
void DualBandSelector::MakeSelectionStrategy(std::string connectedApBssid,
    std::vector<DualBandSelectionStrategy *> &dualBandSelectionStrategys,
    CandidateRelationApInfo &bestCandidateRelationApInfo, ScoreResult &currentApScoreResult)
{
    dualBandSelectionStrategys.push_back(new Ap5gScoreSelectionStrategy(bestCandidateRelationApInfo));
    dualBandSelectionStrategys.push_back(new SameAp5gSelectionStrategy(bestCandidateRelationApInfo, connectedApBssid));
    dualBandSelectionStrategys.push_back(new Ap5gScoreGreater24gSelectionStrategy(bestCandidateRelationApInfo,
        currentApScoreResult));
    dualBandSelectionStrategys.push_back(new LearningAlgSelectionStrategy(bestCandidateRelationApInfo));
}
void DualBandSelector::MakeScoreCalculators(std::vector<IScoreCalculator *> &scoreCalculators,
    std::string connectedApBssid)
{
    scoreCalculators.push_back(new RssiScoreCalculator());
    scoreCalculators.push_back(new ConnectTimeScoreCalculator());
    scoreCalculators.push_back(new AvgRttScoreCalculator());
    scoreCalculators.push_back(new PacketLostScoreCalculator());
    scoreCalculators.push_back(new Ap5gScoreCalculator(connectedApBssid));
    scoreCalculators.push_back(new WifiCategoryScoreCalculator());
}

constexpr int HANDOVER_5G_DIRECTLY_SCORE = 40;
constexpr int HANDOVER_5G_DEFAULT_RSSI = -70;
constexpr int HANDOVER_5G_DIRECTLY_RSSI = HANDOVER_5G_DEFAULT_RSSI;

DualBandSelectionStrategy::DualBandSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo,
    std::string selectionStrategyName) : selectionStrategyName_(selectionStrategyName),
    candidateRelationApInfo_(candidateRelationApInfo)
{}
DualBandSelectionStrategy::~DualBandSelectionStrategy()
{}
std::string DualBandSelectionStrategy::GetName()
{
    return selectionStrategyName_;
}

// Ap5gScoreSelectionStrategy
Ap5gScoreSelectionStrategy::Ap5gScoreSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo)
    : DualBandSelectionStrategy(candidateRelationApInfo, SelectStrategyName::AP_5G_SCORE)
{}
Ap5gScoreSelectionStrategy::~Ap5gScoreSelectionStrategy()
{}
bool Ap5gScoreSelectionStrategy::IsSelected()
{
    if (candidateRelationApInfo_.scoreResult.totalScore >= HANDOVER_5G_DIRECTLY_SCORE
        && candidateRelationApInfo_.apInfo.rssi >= HANDOVER_5G_DIRECTLY_RSSI) {
        return true;
    }
    WIFI_LOGI("Ap5gScoreFilter: tarApRssi: %{public}d", candidateRelationApInfo_.apInfo.rssi);
    return false;
}

// SameAp5gSelectionStrategy
SameAp5gSelectionStrategy::SameAp5gSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo,
    std::string connectedApBssid)
    : DualBandSelectionStrategy(candidateRelationApInfo, SelectStrategyName::SAME_AP_5G),
    connectedApBssid_(connectedApBssid)
{}
SameAp5gSelectionStrategy::~SameAp5gSelectionStrategy()
{}
bool SameAp5gSelectionStrategy::IsSelected()
{
    int handover5gSignalRssi = -65;
    bool isSameRouterAp = DualBandUtils::IsSameRouterAp(connectedApBssid_, candidateRelationApInfo_.apInfo.bssid);
    if (isSameRouterAp && candidateRelationApInfo_.apInfo.rssi >= handover5gSignalRssi) {
        return true;
    }
    WIFI_LOGI("SameAp5gFilter: isSameRouterAp: %{public}d, tarRssi: %{public}d", isSameRouterAp,
        candidateRelationApInfo_.apInfo.rssi);
    return false;
}

// Ap5gScoreGreater24gSelectionStrategy
Ap5gScoreGreater24gSelectionStrategy::Ap5gScoreGreater24gSelectionStrategy(
    CandidateRelationApInfo &candidateRelationApInfo, ScoreResult &currentApScoreResult)
    : DualBandSelectionStrategy(candidateRelationApInfo, SelectStrategyName::AP_5G_SCORE_GREATER_24G),
    currentApScoreResult_(currentApScoreResult)
{}
Ap5gScoreGreater24gSelectionStrategy::~Ap5gScoreGreater24gSelectionStrategy()
{}
bool Ap5gScoreGreater24gSelectionStrategy::IsSelected()
{
    int candidateApCalibScore = candidateRelationApInfo_.scoreResult.GetCalibrateScore(currentApScoreResult_);
    int currentApCalibScore = currentApScoreResult_.GetCalibrateScore(candidateRelationApInfo_.scoreResult);
    int handover5gDiffrenceScore = 5;
    if (candidateApCalibScore > currentApCalibScore + handover5gDiffrenceScore) {
        return true;
    }
    WIFI_LOGI("Ap5gScoreGreater24gFilter: candidateAp: %{public}d, currentApScore: %{public}d",
        candidateApCalibScore, currentApCalibScore);
    return false;
}

//LearningAlgSelectionStrategy
LearningAlgSelectionStrategy::LearningAlgSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo)
    : DualBandSelectionStrategy(candidateRelationApInfo, SelectStrategyName::LEARNING_ALG)
{}
LearningAlgSelectionStrategy::~LearningAlgSelectionStrategy()
{}
bool LearningAlgSelectionStrategy::IsSelected()
{
    return DualBandLearningAlgService::Selected(
        candidateRelationApInfo_.meanP, candidateRelationApInfo_.apInfo.rssi);
}
}  // namespace Wifi
}  // namespace OHOS