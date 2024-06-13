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
     * @return return ture if the candidate network is Open and maybe portal.
     */
    static bool IsOpenAndMaybePortal(const NetworkCandidate &networkCandidate);

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
     * @return json format string
     */
    static std::string GetNetworkCandidatesInfo(const std::vector<NetworkCandidate*> &networkCandidates);

    /**
     * transfer the info of candidate networks to json format string.
     *
     * @param scoreResults scoreResults
     * @return json format string
     */
    static std::string GetScoreResultsInfo(const std::vector<ScoreResult> &scoreResults);

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
    /**
     * Get vendor country from param to determine it is ItDevice.
     * @param non
     * @return return true if the vendor country is ItDevice
     */
    static bool CheckDeviceTypeByVendorCountry();
#endif
};
}
#endif
