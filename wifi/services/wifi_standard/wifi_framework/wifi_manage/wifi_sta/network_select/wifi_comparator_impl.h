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

#ifndef OHOS_WIFI_WIFI_COMPARATOR_H
#define OHOS_WIFI_WIFI_COMPARATOR_H

#include <memory>
#include <functional>
#include "network_selection.h"

namespace OHOS::Wifi::NetworkSelection  {

class WifiScorerComparator : public IWifiComparator {
public:
    explicit WifiScorerComparator(const std::string &comparatorName);
    /**
     * AddScorer
     *
     * @param scorer the score for candidate network.
     */
    void AddScorer(const std::shared_ptr<IWifiScorer> &scorer);

    void GetBestCandidates(const std::vector<NetworkCandidate *> &candidates,
                           std::vector<NetworkCandidate *> &selectedCandidates) override;
private:
    void LogSelectedCandidates(std::vector<NetworkCandidate *> &selectedCandidates,
                               std::vector<ScoreResult> &scoreResults);
    void LogWorseSelectedCandidates(std::vector<NetworkCandidate *> &worseNetworkCandidates,
                                    NetworkCandidate &betterNetworkCandidate,
                                    std::vector<ScoreResult> &scoreResults);
    void LogWorseCandidate(NetworkCandidate &worseNetworkCandidates,
                           NetworkCandidate &selectedNetworkCandidate,
                           ScoreResult &scoreResults);
    std::vector<std::shared_ptr<IWifiScorer>> scorers;
    std::string comparatorName;
};
}
#endif
