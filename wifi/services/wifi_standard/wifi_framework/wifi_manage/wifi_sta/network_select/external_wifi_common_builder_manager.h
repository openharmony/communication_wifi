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

#ifndef OHOS_WIFI_EXTERNAL_NETWORK_SCORE_BUILDER_MANAGER_H_
#define OHOS_WIFI_EXTERNAL_NETWORK_SCORE_BUILDER_MANAGER_H_

#include <mutex>
#include "network_selection.h"

namespace OHOS::Wifi {
class ExternalWifiScoreBuildManager {
public:
    static ExternalWifiScoreBuildManager &GetInstance();

    ExternalWifiScoreBuildManager(const ExternalWifiScoreBuildManager &) = delete;

    const ExternalWifiScoreBuildManager &operator=(const ExternalWifiScoreBuildManager &) = delete;

    /**
     * Register the score builder function
     *
     * @param scoreTag scoreTag which define where the score should be inserted.
     * @param scoreName the score name.
     * @param scoreBuilder scoreBuilder function.
     */
    void RegisterScorerBuilder(const ScoreTag &scoreTag, const std::string &scoreName,
                               const ScoreBuilder &scoreBuilder);
    /**
     * Deregister the score builder function
     *
     * @param scoreTag scoreTag which define where the score should be inserted.
     * @param scoreName the score name.
     */
    void DeregisterScorerBuilder(const ScoreTag &scoreTag, const std::string &scoreName);

    /**
     * build the compositeScore
     *
     * @param scoreTag scoreTag which define where the compositeScore should be inserted.
     * @param compositeScore the target score to build.
     */
    void BuildScore(const ScoreTag &scoreTag, NetworkSelection::CompositeWifiScorer &compositeScore);
private:
    ExternalWifiScoreBuildManager() = default;

    ~ExternalWifiScoreBuildManager() = default;

    std::map<std::pair<ScoreTag, std::string>, ScoreBuilder> scoreBuilders;
    std::mutex mutex;
};
}

#endif