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
#include "wifi_sensor_scene.h"
#include "wifi_channel_helper.h"
#include "wifi_service_manager.h"

namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("networkSelectionManager")

const int OUTDOOR_NETWORK_SELECT_THRES = 3;

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
    bool isSavedNetEmpty = false;
    std::string savedResult = GetSavedNetInfoForChr(networkCandidates, isSavedNetEmpty);

    /* Traverse networkCandidates and reserve qualified networkCandidate */
    TryNominate(networkCandidates, networkSelector);

    std::string filteredReason = GetFilteredReasonForChr(networkCandidates);

    /* Get best networkCandidate from the reserved networkCandidates */
    std::vector<NetworkSelection::NetworkCandidate *> bestNetworkCandidates;
    networkSelector->GetBestCandidates(bestNetworkCandidates);

    std::string selectedInfo;
    if (bestNetworkCandidates.empty()) {
        if (!isSavedNetEmpty) {
            WriteAutoSelectHiSysEvent(static_cast<int>(type), selectedInfo, filteredReason, savedResult);
        }
        return false;
    } else {
        selectedInfo = GetSelectedInfoForChr(bestNetworkCandidates.at(0));
        WriteAutoSelectHiSysEvent(static_cast<int>(type), selectedInfo, filteredReason, savedResult);
    }

    /* Determine whether to select bestNetworkCandidates in outdoor scene */
    IodStatisticInfo iodStatisticInfo;
    iodStatisticInfo.outdoorAutoSelectCnt++;
    if (IsOutdoorFilter(bestNetworkCandidates.at(0))) {
        WIFI_LOGI("bestNetworkCandidates do not satisfy outdoor select condition");
        iodStatisticInfo.outdoorFilterCnt++;
        WriteIodHiSysEvent(iodStatisticInfo);
        return false;
    }
    WriteIodHiSysEvent(iodStatisticInfo);

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

    std::stringstream wifiCandidateInfos;
    for (auto &pair: wifiCandidateConfigs) {
        if (wifiCandidateInfos.rdbuf() ->in_avail() != 0) {
            wifiCandidateInfos << ",";
        }
        wifiCandidateInfos << "\"" << pair.first << "_" <<
            SsidAnonymize(networkCandidates.at(pair.second).wifiDeviceConfig.ssid) << "\"";
    }
    WIFI_LOGI("Find savedNetworks in scanInfos: [%{public}s]\n"
        "Find suggestion networks in scanInfos: [%{public}s]",
        wifiDevicesInfo.str().c_str(), wifiCandidateInfos.str().c_str());
}

void NetworkSelectionManager::TryNominate(std::vector<NetworkSelection::NetworkCandidate> &networkCandidates,
                                          const std::unique_ptr<NetworkSelection::INetworkSelector> &networkSelector)
{
    std::for_each(networkCandidates.begin(), networkCandidates.end(), [&networkSelector](auto &networkCandidate) {
        networkSelector->TryNominate(networkCandidate);
    });
}

std::string NetworkSelectionManager::GetSavedNetInfoForChr(
    std::vector<NetworkSelection::NetworkCandidate> &networkCandidates, bool &isSavedNetEmpty)
{
    std::map<int, NetworkSelection::NetworkCandidate> savedCandidates;
    for (size_t i = 0; i < networkCandidates.size(); i++) {
        if (networkCandidates.at(i).wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
            continue;
        }
        savedCandidates.insert({networkCandidates.at(i).wifiDeviceConfig.networkId,
            networkCandidates.at(i)});
    }
    if (savedCandidates.empty()) {
        isSavedNetEmpty = true;
    }
    std::string savedResult;
    savedResult += "[";
    for (auto pair : savedCandidates) {
        savedResult += "[";
        savedResult += std::to_string(pair.first);
        savedResult += "_";
        savedResult += SsidAnonymize(pair.second.wifiDeviceConfig.ssid);
        savedResult += "_";
        savedResult += pair.second.wifiDeviceConfig.keyMgmt;
        savedResult += "]";
    }
    savedResult += "]";
    return savedResult;
}

std::string NetworkSelectionManager::GetFilteredReasonForChr(
    std::vector<NetworkSelection::NetworkCandidate> &networkCandidates)
{
    std::string filteredReasons;
    filteredReasons += "[";
    for (size_t i = 0; i < networkCandidates.size(); i++) {
        if (networkCandidates.at(i).wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
            continue;
        }
        std::map<std::string, std::set<NetworkSelection::FiltedReason,
            NetworkSelection::FiltedReasonComparator, std::allocator<NetworkSelection::FiltedReason>>> filtedReason;
        filtedReason = networkCandidates.at(i).filtedReason;
        if (filtedReason.size() == 0) {
            continue;
        }
        filteredReasons += "[";
        for (const auto& pair : filtedReason) {
            std::string filterName = pair.first;
            filteredReasons += filterName;
            filteredReasons += "_";
            filteredReasons += networkCandidates.at(i).ToString(filterName);
        }
        filteredReasons += "]";
        if (i < networkCandidates.size() - 1) {
            filteredReasons += ", ";
        }
    }
    filteredReasons += "]";
    return filteredReasons;
}

std::string NetworkSelectionManager::GetSelectedInfoForChr(NetworkSelection::NetworkCandidate *networkCandidate)
{
    std::string selectedInfo;
    WifiDeviceConfig selectedConfig;
    selectedConfig = networkCandidate->wifiDeviceConfig;
    selectedInfo += std::to_string(selectedConfig.networkId);
    selectedInfo += "_";
    selectedInfo += SsidAnonymize(selectedConfig.ssid);
    selectedInfo += "_";
    selectedInfo += MacAnonymize(selectedConfig.bssid);
    selectedInfo += "_";
    selectedInfo += selectedConfig.keyMgmt;
    selectedInfo += "_";
    selectedInfo += std::to_string(networkCandidate->interScanInfo.frequency);
    selectedInfo += "_";
    selectedInfo += std::to_string(networkCandidate->interScanInfo.rssi);
    return selectedInfo;
}

bool NetworkSelectionManager::IsOutdoorFilter(NetworkSelection::NetworkCandidate *networkCandidate)
{
    std::lock_guard<std::mutex> lock(rssiCntMutex_);
    if (!WifiSensorScene::GetInstance().IsOutdoorScene()) {
        WIFI_LOGI("IsOutdoorFilter indoor scene do not filter");
        rssiCntMap_.clear();
        return false;
    }
    if ((WifiChannelHelper::GetInstance().IsValid5GHz(networkCandidate->interScanInfo.frequency) &&
            networkCandidate->interScanInfo.rssi >= RSSI_LEVEL_4_5G) ||
        (WifiChannelHelper::GetInstance().IsValid24GHz(networkCandidate->interScanInfo.frequency) &&
            networkCandidate->interScanInfo.rssi >= RSSI_LEVEL_4_2G)) {
        WIFI_LOGI("IsOutdoorFilter outdoor strong signal do not filter");
        rssiCntMap_.clear();
        return false;
    }
    if ((WifiChannelHelper::GetInstance().IsValid5GHz(networkCandidate->interScanInfo.frequency) &&
            networkCandidate->interScanInfo.rssi < RSSI_LEVEL_3_5G) ||
        (WifiChannelHelper::GetInstance().IsValid24GHz(networkCandidate->interScanInfo.frequency) &&
            networkCandidate->interScanInfo.rssi < RSSI_LEVEL_3_2G)) {
        rssiCntMap_.clear();
        return true;
    }
    if (rssiCntMap_[networkCandidate->interScanInfo.bssid] < OUTDOOR_NETWORK_SELECT_THRES) {
        rssiCntMap_[networkCandidate->interScanInfo.bssid]++;
        int instId = 0;
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
        if (pScanService == nullptr || pScanService->ResetScanInterval() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("IsOutdoorFilter ResetScanInterval failed");
            rssiCntMap_.clear();
            return false;
        }
        return true;
    }
    WIFI_LOGI("IsOutdoorFilter signal satisfy outdoor select condition");
    rssiCntMap_.clear();
    return false;
}
}