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

#include "network_selection_utils.h"
#include "network_status_history_manager.h"
#include "wifi_settings.h"
#include "wifi_common_util.h"
#include "wifi_logger.h"



namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("NetworkSelectionUtils")

constexpr int RECHECK_DELAYED_SECONDS = 1 * 60 * 60;
constexpr int MAX_RETRY_COUNT = 3;
constexpr int MIN_5GHZ_BAND_FREQUENCY = 5000;
constexpr int MIN_RSSI_VALUE_24G = -77;
constexpr int MIN_RSSI_VALUE_5G = -80;
constexpr int SIGNAL_LEVEL_TWO = 2;
constexpr int POOR_PORTAL_RECHECK_DELAYED_SECONDS = 2 * RECHECK_DELAYED_SECONDS;
constexpr int SCORE_PRECISION = 2;

bool NetworkSelectionUtils::isOpenNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_NONE;
};

bool NetworkSelectionUtils::isOpenAndMaybePortal(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    return isOpenNetwork(networkCandidate) && !wifiDeviceConfig.noInternetAccess
        && NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory);
}

bool NetworkSelectionUtils::isScanResultForOweNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.interScanInfo.capabilities.find("OWE") != std::string::npos;
}

bool NetworkSelectionUtils::IsRecoveryNetwork(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    return wifiDeviceConfig.noInternetAccess && !wifiDeviceConfig.isPortal
        && NetworkStatusHistoryManager::IsAllowRecoveryByHistory(wifiDeviceConfig.networkStatusHistory);
}

bool NetworkSelectionUtils::IsHasInternetNetwork(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (wifiDeviceConfig.noInternetAccess || wifiDeviceConfig.isPortal) {
        return false;
    }
    if (NetworkStatusHistoryManager::IsInternetAccessByHistory(wifiDeviceConfig.networkStatusHistory)) {
        return true;
    }
    if (NetworkSelectionUtils::isOpenNetwork(networkCandidate)) {
        return false;
    }
    return NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory);
}

bool NetworkSelectionUtils::IsBlackListNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.connFailedCount >= MAX_RETRY_COUNT;
}

bool NetworkSelectionUtils::MayBePortalNetwork(NetworkCandidate &networkCandidate)
{
    return !NetworkSelectionUtils::isScanResultForOweNetwork(networkCandidate)
        && NetworkSelectionUtils::isOpenAndMaybePortal(networkCandidate);
}

bool NetworkSelectionUtils::IsPortalNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.isPortal;
}

bool NetworkSelectionUtils::IsNoInternetNetwork(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    return wifiDeviceConfig.noInternetAccess
        && !NetworkStatusHistoryManager::IsAllowRecoveryByHistory(wifiDeviceConfig.networkStatusHistory);
}

bool NetworkSelectionUtils::IsSavedNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.networkId != INVALID_NETWORK_ID;
}

bool NetworkSelectionUtils::IsNetworkEnabled(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.status == static_cast<int>(WifiDeviceConfigStatus::ENABLED);
}

bool NetworkSelectionUtils::IsEphemeralNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.isEphemeral;
}

bool NetworkSelectionUtils::IsHiddenNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.interScanInfo.ssid.empty();
}

bool NetworkSelectionUtils::IsSignalTooWeak(NetworkCandidate &networkCandidate)
{
    auto &scanInfo = networkCandidate.interScanInfo;
    auto rssiThreshold = scanInfo.frequency < MIN_5GHZ_BAND_FREQUENCY ? MIN_RSSI_VALUE_24G : MIN_RSSI_VALUE_5G;
    return scanInfo.rssi < rssiThreshold;
}

bool NetworkSelectionUtils::IsPoorPortalNetwork(NetworkCandidate &networkCandidate)
{
    auto &interScanInfo = networkCandidate.interScanInfo;
    int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(interScanInfo.rssi, interScanInfo.band);
    if (currentSignalLevel > SIGNAL_LEVEL_TWO) {
        return false;
    }
    if (currentSignalLevel < SIGNAL_LEVEL_TWO) {
        return true;
    }
    auto lastHasInternetTime = networkCandidate.wifiDeviceConfig.lastHasInternetTime;
    auto now = time(nullptr);
    if (now < 0) {
        WIFI_LOGW("time return invalid!\n.");
        return true;
    }
    return (now - lastHasInternetTime) > POOR_PORTAL_RECHECK_DELAYED_SECONDS;
}

bool NetworkSelectionUtils::IsMatchUserSelected(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.userSelectBssid.empty()) {
        return true;
    }
    return networkCandidate.interScanInfo.bssid == networkCandidate.wifiDeviceConfig.userSelectBssid;
}

bool NetworkSelectionUtils::IsPassPointNetwork(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.isPasspoint;
}

std::string NetworkSelectionUtils::GetNetworkCandidateInfo(NetworkCandidate &networkCandidate)
{
    std::stringstream networkCandidateInfo;
    networkCandidateInfo << R"({ "ssid" : ")" << SsidAnonymize(networkCandidate.interScanInfo.ssid)
                         << R"(", "bssid" : ")"
                         << MacAnonymize(networkCandidate.interScanInfo.bssid) << R"(" })";
    return networkCandidateInfo.str();
}

std::string NetworkSelectionUtils::GetScoreMsg(ScoreResult &scoreResult)
{
    std::stringstream scoreMsg;
    scoreMsg << scoreResult.scorerName << " : " << std::fixed << std::setprecision(SCORE_PRECISION) <<
    scoreResult.score;
    if (scoreResult.scoreDetails.empty()) {
        return scoreMsg.str();
    }
    scoreMsg << "{ ";
    for (auto i = 0; i < scoreResult.scoreDetails.size(); i++) {
        scoreMsg << NetworkSelectionUtils::GetScoreMsg(scoreResult.scoreDetails.at(i));
        if (i < (scoreResult.scoreDetails.size() - 1)) {
            scoreMsg << ", ";
        }
    }
    scoreMsg << " }";
    return scoreMsg.str();
}
}
}