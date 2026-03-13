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

#ifndef OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_SELECTOR_H
#define OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_SELECTOR_H

#include <vector>
#include <memory>
#include "connected_ap.h"
#include "candidate_relation_ap_info.h"
#include "score_service.h"
namespace OHOS {
namespace Wifi {

class DualBandSelectionStrategy {
public:
    DualBandSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo, std::string selectionStrategyName);
    virtual ~DualBandSelectionStrategy() = 0;
    virtual bool IsSelected() = 0;
    std::string GetName();
protected:
    std::string selectionStrategyName_;
    CandidateRelationApInfo candidateRelationApInfo_;
};

class Ap5gScoreSelectionStrategy : public DualBandSelectionStrategy {
public:
    explicit Ap5gScoreSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo);
    ~Ap5gScoreSelectionStrategy() override;
    bool IsSelected() override;
};
class SameAp5gSelectionStrategy : public DualBandSelectionStrategy {
public:
    SameAp5gSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo, std::string connectedApBssid);
    ~SameAp5gSelectionStrategy() override;
    bool IsSelected() override;
private:
    std::string connectedApBssid_;
};
class Ap5gScoreGreater24gSelectionStrategy : public DualBandSelectionStrategy {
public:
    Ap5gScoreGreater24gSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo,
        ScoreResult &currentApScoreResult);
    ~Ap5gScoreGreater24gSelectionStrategy() override;
    bool IsSelected() override;
private:
    ScoreResult currentApScoreResult_;
};
class LearningAlgSelectionStrategy : public DualBandSelectionStrategy {
public:
    explicit LearningAlgSelectionStrategy(CandidateRelationApInfo &candidateRelationApInfo);
    ~LearningAlgSelectionStrategy() override;
    bool IsSelected() override;
};

class DualBandSelector {
public:
    static std::shared_ptr<CandidateRelationApInfo> Select(ApInfo &currentApInfo,
        std::vector<CandidateRelationApInfo> &candidateRelationApInfos);
private:
    static CandidateRelationApInfo* GetBestCandidateRelationApInfo(
        std::vector<CandidateRelationApInfo> &candidateRelationApInfos, std::string connectedApBssid);
    static void CalculateScore(ScoreResult &currentApScoreResult, ApInfo &currentApInfo,
        std::vector<CandidateRelationApInfo> &candidateRelationApInfos);
    static void MakeSelectionStrategy(std::string connectedApBssid,
        std::vector<DualBandSelectionStrategy *> &dualBandSelectionStrategys,
        CandidateRelationApInfo &bestCandidateRelationApInfo, ScoreResult &currentApScoreResult);
    static void MakeScoreCalculators(std::vector<IScoreCalculator *> &scoreCalculators,
        std::string connectedApBssid);
};
namespace SelectStrategyName {
    inline const std::string AP_5G_SCORE = "AP_5G_SCORE";
    inline const std::string SAME_AP_5G = "SAME_AP_5G";
    inline const std::string AP_5G_SCORE_GREATER_24G = "AP_5G_SCORE_GREATER_24G";
    inline const std::string LEARNING_ALG = "LEARNING_ALG";
}
}  // namespace Wifi
}  // namespace OHOS
#endif