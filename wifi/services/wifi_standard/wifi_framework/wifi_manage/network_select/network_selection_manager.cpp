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
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"

namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("networkSelectionManager")

NetworkSelectionManager::NetworkSelectionManager()
{
    pNetworkSelectorFactory = std::make_unique<NetworkSelectorFactory>();
}

bool NetworkSelectionManager::SelectNetwork(NetworkSelectionResult &networkSelectionResult,
                                            NetworkSelectType type,
                                            const std::vector<InterScanInfo> &scanInfos)
{
    if (scanInfos.empty()) {
        WIFI_LOGI("scanInfos is empty, ignore this selection");
        return false;
    }

    /* networkCandidates must be declared before networkSelector,
     * so it can be accessed in the destruct of networkSelector and wifiFilter */
    std::vector<NetworkSelection::NetworkCandidate> networkCandidates;
    auto networkSelectorOptional = pNetworkSelectorFactory->GetNetworkSelector(type);
    if (!(networkSelectorOptional.has_value())) {
        WIFI_LOGE("Get NetworkSelector failed for type %{public}d", static_cast<int>(type));
        return false;
    }
    auto &networkSelector = networkSelectorOptional.value();
    WIFI_LOGI("NetworkSelector: %{public}s", networkSelector->GetNetworkSelectorMsg().c_str());

    /* Get the device config for each scanInfo, then create networkCandidate and put it into networkCandidates */
    GetAllDeviceConfigs(networkCandidates, scanInfos);

    /* Traverse networkCandidates and reserve qualified networkCandidate */
    TryNominate(networkCandidates, networkSelector);

    std::stringstream savedResult = GetSavedNetInfoForChr(networkCandidates);
    std::stringstream filteredReason = GetFilteredReasonForChr(networkCandidates);
    std::stringstream selectedInfo;

    /* Get best networkCandidate from the reserved networkCandidates */
    std::vector<NetworkSelection::NetworkCandidate *> bestNetworkCandidates;
    networkSelector->GetBestCandidates(bestNetworkCandidates);
    if (bestNetworkCandidates.empty()) {
        WriteAutoSelectHiSysEvent(static_cast<int>(type), selectedInfo.str(), filteredReason.str(), savedResult.str());
        return false;
    } else {
        WifiDeviceConfig selectedConfig;
        selectedConfig = bestNetworkCandidates.at(0)->wifiDeviceConfig;
        selectedInfo << selectedConfig.networkId << "_" << SsidAnonymize(selectedConfig.ssid) << "_"
            << MacAnonymize(selectedConfig.bssid) << selectedConfig.keyMgmt;
        WriteAutoSelectHiSysEvent(static_cast<int>(type), selectedInfo.str(), filteredReason.str(), savedResult.str());
    }

    /* if bestNetworkCandidates is not empty, assign the value of first bestNetworkCandidate
     * to the network selection result, and return true which means the network selection is successful */
    networkSelectionResult.wifiDeviceConfig = bestNetworkCandidates.at(0)->wifiDeviceConfig;
    networkSelectionResult.interScanInfo = bestNetworkCandidates.at(0)->interScanInfo;
    return true;
}

void NetworkSelectionManager::GetAllDeviceConfigs(std::vector<NetworkSelection::NetworkCandidate> &networkCandidates,
                                                  const std::vector<InterScanInfo> &scanInfos)
{
    std::map<int, std::size_t> wifiDeviceConfigs;
    std::map<int, std::size_t> wifiCandidateConfigs;
    for (auto &scanInfo : scanInfos) {
        auto& networkCandidate = networkCandidates.emplace_back(scanInfo);
        std::string deviceKeyMgmt;
        scanInfo.GetDeviceMgmt(deviceKeyMgmt);
        WifiSettings::GetInstance().GetDeviceConfig(scanInfo.ssid, deviceKeyMgmt, networkCandidate.wifiDeviceConfig);

        // save the indexes of saved network candidate in networkCandidates;
        if (networkCandidates.back().wifiDeviceConfig.networkId != INVALID_NETWORK_ID) {
            wifiDeviceConfigs.insert({networkCandidate.wifiDeviceConfig.networkId, networkCandidates.size() - 1});
            WifiSettings::GetInstance().SetNetworkCandidateScanResult(networkCandidate.wifiDeviceConfig.networkId);
            continue;
        }

        // add suggesion network
        WifiSettings::GetInstance().GetCandidateConfigWithoutUid(scanInfo.ssid, deviceKeyMgmt,
            networkCandidate.wifiDeviceConfig);
        if (networkCandidates.back().wifiDeviceConfig.networkId != INVALID_NETWORK_ID &&
            networkCandidates.back().wifiDeviceConfig.uid != WIFI_INVALID_UID &&
            networkCandidates.back().wifiDeviceConfig.isShared == false) {
            wifiCandidateConfigs.insert({networkCandidate.wifiDeviceConfig.networkId, networkCandidates.size() - 1});
        }
    }

    std::stringstream wifiDevicesInfo;
    for (auto &pair: wifiDeviceConfigs) {
        if (wifiDevicesInfo.rdbuf() ->in_avail() != 0) {
            wifiDevicesInfo << ",";
        }
        wifiDevicesInfo << "\"" << pair.first << "_" <<
            SsidAnonymize(networkCandidates.at(pair.second).wifiDeviceConfig.ssid) << "_" <<
            networkCandidates.at(pair.second).wifiDeviceConfig.keyMgmt << "\"";
    }
    WIFI_LOGI("Find savedNetworks in scanInfos: [%{public}s]", wifiDevicesInfo.str().c_str());

    std::stringstream wifiCandidateInfos;
    for (auto &pair: wifiCandidateConfigs) {
        if (wifiCandidateInfos.rdbuf() ->in_avail() != 0) {
            wifiCandidateInfos << ",";
        }
        wifiCandidateInfos << "\"" << pair.first << "_" <<
            SsidAnonymize(networkCandidates.at(pair.second).wifiDeviceConfig.ssid) << "\"";
    }
    WIFI_LOGI("Find suggestion networks in scanInfos: [%{public}s]", wifiCandidateInfos.str().c_str());
}

void NetworkSelectionManager::TryNominate(std::vector<NetworkSelection::NetworkCandidate> &networkCandidates,
                                          const std::unique_ptr<NetworkSelection::INetworkSelector> &networkSelector)
{
    std::for_each(networkCandidates.begin(), networkCandidates.end(), [&networkSelector](auto &networkCandidate) {
        networkSelector->TryNominate(networkCandidate);
    });
}

std::stringstream NetworkSelectionManager::GetSavedNetInfoForChr(
    std::vector<NetworkSelection::NetworkCandidate> &networkCandidates)
{
    std::map<int, WifiDeviceConfig> wifiDeviceConfigs;
    for (size_t i = 0; i < networkCandidates.size(); i++) {
        if (networkCandidates.at(i).wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
            continue;
        }
        wifiDeviceConfigs.insert({networkCandidates.at(i).wifiDeviceConfig.networkId,
            networkCandidates.at(i).wifiDeviceConfig});
    }
    std::stringstream savedResult;
    savedResult << "[";
    for (auto pair : wifiDeviceConfigs) {
        savedResult << "[";
        savedResult << pair.first << "_" << SsidAnonymize(pair.second.ssid) << pair.second.keyMgmt;
        savedResult << "]";
    }
    savedResult << "]";
    return savedResult;
}

std::stringstream NetworkSelectionManager::GetFilteredReasonForChr(
    std::vector<NetworkSelection::NetworkCandidate> &networkCandidates)\
{
    std::stringstream filteredReason;
    filteredReason << "[";
    for (size_t i = 0; i < networkCandidates.size(); i++) {
        if (networkCandidates.at(i).wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
            continue;
        }
        std::map<std::string, std::set<FiltedReason,
            FiltedReasonComparator, std::allocator<FiltedReason>>> filtedReason;
        filtedReason = networkCandidates.at(i).filtedReason;
        if (filtedReason.size() == 0) {
            continue;
        }
        filteredReason << "[";
        for (const auto& pair : filteredReason) {
            std::string filterName = pair.first;
            filteredReason << filterName << "_" << networkCandidates.at(i).ToString(filterName);
        }
        filteredReason << "]";
        if (i < networkCandidates.size() - 1) {
            filteredReason << ", ";
        }
    }
    filteredReason << "]";
    return filteredReason;
}
}