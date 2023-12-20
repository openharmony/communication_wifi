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


#ifndef OHOS_WIFI_NETWORK_SELECTION_MANAGER_H
#define OHOS_WIFI_NETWORK_SELECTION_MANAGER_H

#include "network_selection_msg.h"
#include "network_selector.h"
#include "network_selector_factory.h"

namespace OHOS {
namespace Wifi {
struct NetworkSelectionResult {
    InterScanInfo interScanInfo;
    WifiDeviceConfig wifiDeviceConfig;
};

class NetworkSelectionManager {
public:
    NetworkSelectionManager();
    ~NetworkSelectionManager();
    ErrCode InitNetworkSelectionService();
    /**
     * the function to select network.
     *
     * @param networkSelectionResult Network selection result
     * @param type the type of networkSelection
     * @param scanInfos scanInfos
     * @return whether network selection is successful.
     */
    bool SelectNetwork(NetworkSelectionResult &networkSelectionResult,
                       NetworkSelectType type,
                       const std::vector<InterScanInfo> &scanInfos);
private:
    NetworkSelectorFactory *pNetworkSelectorFactory;

    /**
     * get the saved deviceConfig associated with scanInfo
     *
     * @param networkCandidates  Candidate network
     * @param scanInfos scanInfos
     */
    static void GetAllDeviceConfigs(std::vector<NetworkCandidate> &networkCandidates,
                                    const std::vector<InterScanInfo> &scanInfos);

    /**
     * Try nominator the candidate network.
     *
     * @param networkCandidates candidate networks
     * @param networkSelector networkSelector
     */
    static void TryNominator(std::vector<NetworkCandidate> &networkCandidates,
                             const std::unique_ptr<INetworkSelector> &networkSelector);

    /**
     * the function to log the networkSelection nominate result.
     *
     * @param networkCandidate candidate network
     */
    static void LogNominateResult(NetworkCandidate &networkCandidate);

    static std::string VectorToJson(std::vector<std::string> &strings);
};
}
}
#endif
