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

#include <sstream>
#include "network_selection_manager.h"
#include "wifi_settings.h"
#include "wifi_logger.h"
#include "network_selection_utils.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("networkSelectionManager")

ErrCode NetworkSelectionManager::InitNetworkSelectionService()
{
    pNetworkSelectorFactory = std::make_unique<NetworkSelectorFactory>();
    return WIFI_OPT_SUCCESS;
}

bool NetworkSelectionManager::SelectNetwork(NetworkSelectionResult &networkSelectionResult,
                                            NetworkSelectType type,
                                            const std::vector<InterScanInfo> &scanInfos)
{
    auto networkSelectorOptional = pNetworkSelectorFactory->GetNetworkSelector(type);
    if (!(networkSelectorOptional.has_value())) {
        WIFI_LOGE("Get NetworkSelector failed for type %{public}d", static_cast<int>(type));
        return false;
    }
    auto &networkSelector = networkSelectorOptional.value();
    WIFI_LOGI("NetworkSelector: %{public}s", networkSelector->GetNetworkSelectorMsg().c_str());
    std::vector<NetworkCandidate> networkCandidates;

    /* Get the device config for each scanInfo, then create networkCandidate and put it into networkCandidates */
    GetAllDeviceConfigs(networkCandidates, scanInfos);

    /* Traverse networkCandidates and reserve qualified networkCandidate */
    TryNominate(networkCandidates, networkSelector);

    /* Get best networkCandidate from the reserved networkCandidates */
    std::vector<NetworkCandidate *> bestNetworkCandidates;
    networkSelector->GetBestCandidates(bestNetworkCandidates);
    if (bestNetworkCandidates.empty()) {
        return false;
    }

    /* if bestNetworkCandidates is not empty, assign the value of first bestNetworkCandidate
     * to the network selection result, and return true which means the network selection is successful */
    networkSelectionResult.wifiDeviceConfig = bestNetworkCandidates.at(0)->wifiDeviceConfig;
    networkSelectionResult.interScanInfo = bestNetworkCandidates.at(0)->interScanInfo;
    return true;
}

void NetworkSelectionManager::GetAllDeviceConfigs(std::vector<NetworkCandidate> &networkCandidates,
                                                  const std::vector<InterScanInfo> &scanInfos)
{
    for (auto &scanInfo : scanInfos) {
        networkCandidates.emplace_back(scanInfo);
        std::string deviceKeyMgmt;
        scanInfo.GetDeviceMgmt(deviceKeyMgmt);
        WifiSettings::GetInstance().GetDeviceConfig(scanInfo.ssid,
                                                    deviceKeyMgmt,
                                                    networkCandidates.back().wifiDeviceConfig);
    }
}

void NetworkSelectionManager::TryNominate(std::vector<NetworkCandidate> &networkCandidates,
                                          const std::unique_ptr<INetworkSelector> &networkSelector)
{
    std::for_each(networkCandidates.begin(), networkCandidates.end(), [&networkSelector](auto &networkCandidate) {
        networkSelector->TryNominate(networkCandidate);
        /* log the nominate result for current networkCandidate */
        LogNominateResult(networkCandidate);
    });
}

std::string NetworkSelectionManager::VectorToJson(std::vector<std::string> &strings)
{
    std::stringstream ss;
    ss << "[";
    for (int i = 0; i < strings.size(); ++i) {
        ss << strings[i];
        if (i < strings.size() - 1) {
            ss << " ,";
        }
    }
    ss << "]";
    return ss.str();
}

void NetworkSelectionManager::LogNominateResult(NetworkCandidate &networkCandidate)
{
    WIFI_LOGD("NetworkCandidate %{public}s is filtered by  %{public}s, is nominated by %{public}s",
        NetworkSelectionUtils::GetNetworkCandidateInfo(networkCandidate).c_str(),
        VectorToJson(networkCandidate.filteredMsg).c_str(),
        VectorToJson(networkCandidate.nominateMsg).c_str());
}
}
}