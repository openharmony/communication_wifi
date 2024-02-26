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

#include <iostream>
#include "wifi_scorer_impl.h"
#include "wifi_settings.h"
#include "network_status_history_manager.h"
#include "wifi_logger.h"

namespace OHOS::Wifi::NetworkSelection {
DEFINE_WIFILOG_LABEL("WifiScorerImpl")

constexpr int SUFFICIENT_RSSI_5G = -70;
constexpr int SUFFICIENT_RSSI_2G = -73;
constexpr int RSSI_SCORE_OFFSET = 85;
constexpr int RSSI_SCORE_SLOPE_IS_4 = 4;
constexpr int TOP_TIME_BASE_SCORE = 1000000;
constexpr int MAX_RECENT_SELECTION_SECONDS = 8 * 60 * 60;
constexpr int MIN_5G_FREQUENCY = 5160;
constexpr int MAX_5G_FREQUENCY = 5865;
constexpr int WIFI_5G_BAND_SCORE = 50;
constexpr int WIFI_2G_BAND_SCORE = 20;
constexpr int SECURITY_BONUS_SCORE = 5;
constexpr int RSSI_LEVEL_FOUR_SCORE = 80;
constexpr int RSSI_LEVEL_THREE_SCORE = 60;
constexpr int RSSI_LEVEL_TWO_SCORE = 20;
constexpr int SIGNAL_LEVEL_TWO = 2;
constexpr int SIGNAL_LEVEL_THREE = 3;
constexpr int SIGNAL_LEVEL_FOUR = 4;
constexpr int MIN_RSSI = -128;
constexpr int INTERNET_ACCESS_AWARD = 2;
constexpr int EMPTY_NETWORK_STATUS_HISTORY_AWARD = 1;

RssiScorer::RssiScorer() : SimpleWifiScorer("rssiScorer") {}

double RssiScorer::Score(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.interScanInfo.rssi < MIN_RSSI) {
        return MIN_RSSI;
    } else if (networkCandidate.interScanInfo.rssi > 0) {
        return 0;
    }
    return networkCandidate.interScanInfo.rssi;
}

LastHaveInternetTimeScorer::LastHaveInternetTimeScorer() : SimpleWifiScorer("lastHaveInternetTimeScorer") {}

double LastHaveInternetTimeScorer::Score(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.lastHasInternetTime > 0) {
        return static_cast<double>(networkCandidate.wifiDeviceConfig.lastHasInternetTime);
    }
    return 0;
}

NetworkStatusHistoryScorer::NetworkStatusHistoryScorer() : SimpleWifiScorer("networkStatusHistoryScorer") {}

double NetworkStatusHistoryScorer::Score(NetworkCandidate &networkCandidate)
{
    auto networkStatusHistory = networkCandidate.wifiDeviceConfig.networkStatusHistory;
    if (NetworkStatusHistoryManager::IsInternetAccessByHistory(networkStatusHistory)) {
        return INTERNET_ACCESS_AWARD;
    } else if (NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(networkStatusHistory)) {
        return EMPTY_NETWORK_STATUS_HISTORY_AWARD;
    }
    return 0;
}

double ThroughputScorer::GetRssiBaseScore(NetworkCandidate &networkCandidate)
{
    int rssi = networkCandidate.interScanInfo.rssi;
    if (networkCandidate.interScanInfo.band == static_cast<int>(BandType::BAND_2GHZ)) {
        rssi = rssi > SUFFICIENT_RSSI_2G ? SUFFICIENT_RSSI_2G : rssi;
    } else {
        rssi = rssi > SUFFICIENT_RSSI_5G ? SUFFICIENT_RSSI_5G : rssi;
    }
    return (rssi + RSSI_SCORE_OFFSET) * RSSI_SCORE_SLOPE_IS_4;
}

double ThroughputScorer::GetSavedNetworkAward(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.isEphemeral ? 0 : SAVED_NETWORK_AWARD_SCORE;
}

bool ThroughputScorer::IsRecentUserSelected(NetworkCandidate &networkCandidate) const
{
    auto userLastSelectedNetworkId = WifiSettings::GetInstance().GetUserLastSelectedNetworkId();
    if (userLastSelectedNetworkId != INVALID_NETWORK_ID
        && userLastSelectedNetworkId == networkCandidate.wifiDeviceConfig.networkId) {
        time_t userLastSelectedNetworkTimeVal = WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal();
        auto now = time(nullptr);
        if (now < 0) {
            WIFI_LOGW("time return invalid!\n.");
            return false;
        }
        return (now - userLastSelectedNetworkTimeVal) < MAX_RECENT_SELECTION_SECONDS;
    }
    return false;
}

bool ThroughputScorer::IsSecurityNetwork(NetworkCandidate &networkCandidate) const
{
    return networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_WEP
        || networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_WPA_PSK
        || networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_SAE
        || networkCandidate.wifiDeviceConfig.keyMgmt == KEY_MGMT_EAP;
}

void ThroughputScorer::DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult)
{
    double rssiBaseScore = GetRssiBaseScore(networkCandidate);
    double savedNetworkAward = GetSavedNetworkAward(networkCandidate);
    scoreResult.scorerName = "ThroughputScorer";
    if (IsRecentUserSelected(networkCandidate)) {
        scoreResult.score = TOP_TIME_BASE_SCORE + rssiBaseScore + savedNetworkAward;
        return;
    }
    scoreResult.score = rssiBaseScore + savedNetworkAward;
    if (IsSecurityNetwork(networkCandidate)) {
        scoreResult.score += SECURITY_AWARD_SCORE;
    }
}

SecurityBonusScorer::SecurityBonusScorer() : SimpleWifiScorer("securityScore") {}

bool SecurityBonusScorer::IsHigherSecurityTypeFromScanResult(const InterScanInfo &interScanInfo)
{
    return IsEncryptionSae(interScanInfo) || IsEncryptionPskSaeTransition(interScanInfo)
        || IsEncryptionOwe(interScanInfo) || IsEncryptionOweTransition(interScanInfo)
        || IsWpa3EnterpriseOnlyNetwork(interScanInfo) || IsWpa3EnterpriseTransitionNetwork(interScanInfo);
}

bool SecurityBonusScorer::IsEncryptionSae(const InterScanInfo &interScanInfo)
{
    return ExistSecurityType(interScanInfo, "SAE");
}

bool SecurityBonusScorer::IsEncryptionPskSaeTransition(const InterScanInfo &interScanInfo)
{
    return ExistSecurityType(interScanInfo, "PSK") && ExistSecurityType(interScanInfo, "SAE");
}

bool SecurityBonusScorer::IsEncryptionOwe(const InterScanInfo &interScanInfo)
{
    return ExistSecurityType(interScanInfo, "OWE");
}

bool SecurityBonusScorer::IsEncryptionOweTransition(const InterScanInfo &interScanInfo)
{
    return ExistSecurityType(interScanInfo, "OWE_TRANSITION");
}

bool SecurityBonusScorer::IsWpa3EnterpriseOnlyNetwork(const InterScanInfo &interScanInfo)
{
    return ExistSecurityType(interScanInfo, "EAP/SHA256") && !ExistSecurityType(interScanInfo, "EAP/SHA1")
        && ExistSecurityType(interScanInfo, "RSN") && !ExistSecurityType(interScanInfo, "WEP")
        && !ExistSecurityType(interScanInfo, "TKIP")
        && (ExistSecurityType(interScanInfo, "[MFPR]") || ExistSecurityType(interScanInfo, "[PMFR]"))
        && (ExistSecurityType(interScanInfo, "[MFPC]") || ExistSecurityType(interScanInfo, "[PMFC]"));
}

bool SecurityBonusScorer::IsWpa3EnterpriseTransitionNetwork(const InterScanInfo &interScanInfo)
{
    return ExistSecurityType(interScanInfo, "EAP/SHA1") && ExistSecurityType(interScanInfo, "EAP/SHA256")
        && ExistSecurityType(interScanInfo, "RSN") && !ExistSecurityType(interScanInfo, "WEP")
        && !ExistSecurityType(interScanInfo, "TKIP")
        && !(ExistSecurityType(interScanInfo, "[MFPR]") || ExistSecurityType(interScanInfo, "[PMFR]"))
        && (ExistSecurityType(interScanInfo, "[MFPC]") || ExistSecurityType(interScanInfo, "[PMFC]"));
}

bool SecurityBonusScorer::ExistSecurityType(const InterScanInfo &interScanInfo, const std::string &securityType)
{
    return interScanInfo.capabilities.find(securityType) != std::string::npos;
}

double SecurityBonusScorer::Score(NetworkCandidate &networkCandidate)
{
    return IsHigherSecurityTypeFromScanResult(networkCandidate.interScanInfo) ? SECURITY_BONUS_SCORE : 0;
}

RssiLevelBonusScorer::RssiLevelBonusScorer() : SimpleWifiScorer("rssiLevelScore") {}

double RssiLevelBonusScorer::Score(NetworkCandidate &networkCandidate)
{
    auto &scanInfo = networkCandidate.interScanInfo;
    int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(scanInfo.rssi, scanInfo.band);
    if (currentSignalLevel == SIGNAL_LEVEL_FOUR) {
        return RSSI_LEVEL_FOUR_SCORE;
    }
    if (currentSignalLevel == SIGNAL_LEVEL_THREE) {
        return RSSI_LEVEL_THREE_SCORE;
    }
    if (currentSignalLevel == SIGNAL_LEVEL_TWO) {
        return RSSI_LEVEL_TWO_SCORE;
    }
    return 0;
}

Network5gBonusScorer::Network5gBonusScorer() : SimpleWifiScorer("5gBonusScore") {}

double Network5gBonusScorer::Score(NetworkCandidate &networkCandidate)
{
    int frequency = networkCandidate.interScanInfo.frequency;
    return frequency >= MIN_5G_FREQUENCY && frequency <= MAX_5G_FREQUENCY ? WIFI_5G_BAND_SCORE : WIFI_2G_BAND_SCORE;
}

SavedNetworkScorer::SavedNetworkScorer(const std::string &scorerName) : CompositeWifiScorer(scorerName)
{
    AddScorer(std::make_shared<RssiLevelBonusScorer>());
    AddScorer(std::make_shared<SecurityBonusScorer>());
    AddScorer(std::make_shared<Network5gBonusScorer>());
}
}
