/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "external_wifi_score_builder_manager.h"
#include "wifi_logger.h"
#include "wifi_scorer_impl.h"


namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("WifiScoreBuilderManager")

ExternalWifiScoreBuildManager &ExternalWifiScoreBuildManager::GetInstance()
{
    static ExternalWifiScoreBuildManager gNetworkSelectorScoreBuilderManager;
    return gNetworkSelectorScoreBuilderManager;
}

void ExternalWifiScoreBuildManager::RegisterScorerBuilder(const ScoreTag &scoreTag,
                                                          const std::string &scoreName,
                                                          const ScoreBuilder &scoreBuilder)
{
    if (!scoreBuilder) {
        WIFI_LOGE("the scoreBuilder for scoreTag: %{public}d, filterName: %{public}s is empty",
                  static_cast<int>(scoreTag),
                  scoreName.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("RegisterScoreBuilder for scoreTag: %{public}d, filterName: %{public}s",
              static_cast<int>(scoreTag),
              scoreName.c_str());
    scoreBuilders.insert_or_assign({scoreTag, scoreName}, scoreBuilder);
}

void ExternalWifiScoreBuildManager::DeregisterScorerBuilder(const ScoreTag &scoreTag, const std::string &scoreName)
{
    std::lock_guard<std::mutex> lock(mutex);
    WIFI_LOGI("DeregisterScorerBuilder for scoreTag: %{public}d, filterName: %{public}s",
              static_cast<int>(scoreTag),
              scoreName.c_str());
    scoreBuilders.erase({scoreTag, scoreName});
}

void ExternalWifiScoreBuildManager::BuildScore(const ScoreTag &scoreTag,
                                               NetworkSelection::CompositeWifiScorer &compositeScore)
{
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto &scorerBuilderPair : scoreBuilders) {
        /* find the builder which match the filterTag  */
        if (scorerBuilderPair.first.first != scoreTag) {
            continue;
        }
        scorerBuilderPair.second.operator()(compositeScore);
    }
}
}
