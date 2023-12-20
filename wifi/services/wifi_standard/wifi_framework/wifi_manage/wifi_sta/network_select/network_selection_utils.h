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

#include "network_selection_msg.h"
#include "network_selector_scorer.h"

namespace OHOS {
namespace Wifi {
class NetworkSelectionUtils {
public:

    /**
     * the function to determine whether the network is Open
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is Open
     */
    static bool isOpenNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is Open and maybe portal.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is Open and maybe portal.
     */
    static bool isOpenAndMaybePortal(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is owe network.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is owe network.
     */
    static bool isScanResultForOweNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is recovery.
     *
     * @param networkCandidate
     * @return  return ture if the candidate network is recovery.
     */
    static bool IsRecoveryNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network has internet.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network has internet.
     */
    static bool IsHasInternetNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is low-priority .
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is low-priority .
     */
    static bool IsBlackListNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network may be portal.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network may be portal.
     */
    static bool MayBePortalNetwork(NetworkCandidate &networkCandidate);
    /**
     * the function to determine whether the network is portal.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is portal.
     */
    static bool IsPortalNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is no internet.
     *
     * @param networkCandidate candidate network.
     * @return  return ture if the candidate network is no internet.
     */
    static bool IsNoInternetNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is saved.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the candidate network is saved.
     */
    static bool IsSavedNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the signal strength of candidate network is too weak.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the signal strength of candidate network is too weak.
     */
    static bool IsSignalTooWeak(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is hidden.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the  candidate network is hidden.
     */
    static bool IsHiddenNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is passPoint.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the  candidate network is passPoint.
     */
    static bool IsPassPointNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is ephemeral.
     *
     * @param networkCandidate candidate network.
     * @return return ture if the  candidate network is ephemeral.
     */
    static bool IsEphemeralNetwork(NetworkCandidate &networkCandidate);

    /**
     * the function to determine whether the network is enabled.
     *
     * @param networkCandidate candidate network
     * @return  return ture if the candidate network is enabled.
     */
    static bool IsNetworkEnabled(NetworkCandidate &networkCandidate);

    /**
     *  the function to determine whether the network match user selected.
     *
     * @param networkCandidate candidate network
     * @return  return ture if the candidate network match user selected
     */
    static bool IsMatchUserSelected(NetworkCandidate &networkCandidate);

    /**
     *  the function to determine whether the portal network is poor.
     * @param networkCandidate  candidate portal network
     * @return return ture if the candidate portal network is poor
     */
    static bool IsPoorPortalNetwork(NetworkCandidate &networkCandidate);

    /**
     * transfer the info of candidate network to json format string.
     * @param networkCandidate  candidate network
     * @return json format string
     */
    static std::string GetNetworkCandidateInfo(NetworkCandidate &networkCandidate);

    /**
     * transfer the info of score result to json format string.
     * @param scoreResult scoreResult
     * @return json format string
     */
    static std::string GetScoreMsg(ScoreResult &scoreResult);
};
}
}
#endif
