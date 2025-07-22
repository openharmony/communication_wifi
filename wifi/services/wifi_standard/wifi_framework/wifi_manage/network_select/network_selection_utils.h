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

#ifndef OHOS_WIFI_NETWORK_SELECTION_UTILS_H_
#define OHOS_WIFI_NETWORK_SELECTION_UTILS_H_

#include "network_selection.h"

namespace OHOS::Wifi::NetworkSelection  {
class NetworkSelectionUtils {
public:

    /**
     * the function to determine whether the network is Open
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is Open
     */
    static bool IsOpenNetwork(const NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is Open and maybe portal.
     *
     * @param networkCandidate candidate network.
     * @param filterName wififilter name
     * @return return ture if the candidate network is Open and maybe portal.
     */
    static bool IsOpenAndMaybePortal(NetworkCandidate &networkCandidate, const std::string &filterName = "");

    /**
     * the function to determine whether the network is owe network.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is owe network.
     */
    static bool IsScanResultForOweNetwork(const NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is low-priority .
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is low-priority .
     */
    static bool IsBlackListNetwork(const NetworkCandidate &networkCandidate);

    /**
     * transfer the info of candidate networks to json format string.
     *
     * @param networkCandidates candidate network
     * @param filterName wififilter Name
     * @return json format string
     */
    static std::string GetNetworkCandidatesInfo(const std::vector<NetworkCandidate*> &networkCandidates,
        const std::string &filterName = "");

    /**
     * transfer the info of candidate networks to json format string.
     *
     * @param scoreResults scoreResults
     * @return json format string
     */
    static std::string GetScoreResultsInfo(const std::vector<ScoreResult> &scoreResults);

    /**
     * check if wifi is open.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is Open, else false.
     */
    static bool IsConfigOpenType(const NetworkCandidate &networkCandidate);
 
    /**
     * check if wifi is Is enterprise.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is enterprise, else false.
     */
    static bool IsEnterprise(const NetworkCandidate &networkCandidate);
 
    /**
     * check if wifi is open or enterprise.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is enterprise, else false.
     */
    static bool IsConfigOpenOrEapType(const NetworkCandidate &networkCandidate);
 
    /**
     * check if wifi has web keys.
     *
     * @param networkCandidate candidate network.
     * @return return ture if wifi device config has web keys, else false.
     */
    static bool HasWepKeys(const WifiDeviceConfig &wifiConfig);
 
    static bool IsSameFreqAsP2p(const NetworkCandidate &networkCandidate);
};
}
#endif
