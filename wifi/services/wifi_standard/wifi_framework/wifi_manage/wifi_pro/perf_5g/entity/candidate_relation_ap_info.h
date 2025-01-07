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
 
#ifndef OHOS_WIFI_PRO_PERF_5G_CANDIDATE_RELATION_AP_INFO_H
#define OHOS_WIFI_PRO_PERF_5G_CANDIDATE_RELATION_AP_INFO_H
#include "connected_ap.h"
#include <string>
#include "relation_ap.h"
namespace OHOS {
namespace Wifi {
constexpr int INVALID_SCORE = -200;
struct ScoreResult {
    int totalScore = 0;
    int rttScore = INVALID_SCORE;
    int lostRateScore = INVALID_SCORE;
    int GetCalibrateScore(ScoreResult &scoreResult)
    {
        int calibrateScore = totalScore;
        if (!scoreResult.ExsitRttScore() && ExsitRttScore()) {
            calibrateScore -= rttScore;
        }
        if (!scoreResult.ExsitLostRateScore() && ExsitLostRateScore()) {
            calibrateScore -= lostRateScore;
        }
        return calibrateScore;
    }
    bool ExsitRttScore()
    {
        return rttScore != INVALID_SCORE;
    }
    bool ExsitLostRateScore()
    {
        return lostRateScore != INVALID_SCORE;
    }
};
struct CandidateRelationApInfo {
    ApInfo apInfo;
    std::string meanP;
    std::string selectStrategyName;
    ScoreResult scoreResult;
};
}  // namespace Wifi
}  // namespace OHOS
#endif