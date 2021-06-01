/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sta_saved_network_evaluator.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_SAVED_NETWORK_EVALUATOR"
#define BARS 5
#define BINARY_CODE 0001
#define LAST_SELECTION_SCORE_DECAY_S (5 * 60)
#define MAX(A, B) (((A) >= (B)) ? (A) : (B))
namespace OHOS {
namespace Wifi {
StaSavedNetworkEvaluator::StaSavedNetworkEvaluator(const StaConnectivityHelper *connectivityHelper)
    : ScoreSlope(WifiSettings::GetInstance().GetscoretacticsScoreSlope()),
      InitScore(WifiSettings::GetInstance().GetscoretacticsInitScore()),
      SameBssidScore(WifiSettings::GetInstance().GetscoretacticsSameBssidScore()),
      SameNetworkScore(WifiSettings::GetInstance().GetscoretacticsSameNetworkScore()),
      Frequency5GHzScore(WifiSettings::GetInstance().GetscoretacticsFrequency5GHzScore()),
      LastSelectionScore(WifiSettings::GetInstance().GetscoretacticsLastSelectionScore()),
      SecurityScore(WifiSettings::GetInstance().GetscoretacticsSecurityScore()),
      iSignalBars(BARS),
      pConnectivityHelper(connectivityHelper)
{}
StaSavedNetworkEvaluator::~StaSavedNetworkEvaluator()
{
    LOGI("Enter StaSavedNetworkEvaluator::~StaSavedNetworkEvaluator.\n");
}

void StaSavedNetworkEvaluator::Update(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaSavedNetworkEvaluator::Update.[%s]\n", scanResults[0].bssid.c_str());
}

ErrCode StaSavedNetworkEvaluator::NetworkEvaluators(
    WifiDeviceConfig &candidate, std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info)
{
    LOGI("Enter StaSavedNetworkEvaluator::NetworkEvaluators.\n");
    int highestScore = 0;
    int sign = 0;
    WifiScanInfo scanResultCandidate;
    scanResultCandidate.level = MIN_RSSI;

    for (auto scanInfo : scanResults) {
        if (scanInfo.bssid.size() == 0) {
            continue;
        }

        WifiDeviceConfig network;
        if (WifiSettings::GetInstance().GetDeviceConfig(scanInfo.bssid, DEVICE_CONFIG_INDEX_BSSID, network) == -1) {
            LOGI("Skip unsaved Network %s.", scanInfo.ssid.c_str()); /* Skipping Unsaved Networks */
            continue;
        }

        if (!SkipNetwork(network)) {
            continue;
        }

        int score = 0;
        CalculateNetworkScore(score, scanInfo, network, info);
        LOGI("The network %s score is %{public}d.rssi is %{public}d.\n", scanInfo.ssid.c_str(), score, scanInfo.level);

        if (score > highestScore || (score == highestScore && scanInfo.level > scanResultCandidate.level)) {
            highestScore = score;
            scanResultCandidate.level = scanInfo.level;
            candidate = network;
            sign = 1;
        }
    }
    if (sign == 1) {
        if (info.connState == ConnState::CONNECTED && candidate.networkId == info.networkId) {
            WifiDeviceConfig networkInfo;
            candidate = networkInfo;
            LOGI("The candidate network is the current connected network. Skip the network selection.");
            return WIFI_OPT_FAILED;
        } else {
            LOGI("The network is selected successfully.\n");
            return WIFI_OPT_SUCCESS;
        }
    } else {
        LOGI("Skip all scan results.\n");
        return WIFI_OPT_FAILED;
    }
}

bool StaSavedNetworkEvaluator::SkipNetwork(WifiDeviceConfig &network)
{
    /* Skip this type of network and evaluate it by other evaluators */
    if (network.isPasspoint || network.isEphemeral) {
        LOGI("Skip isPasspoint or isEphemeral Network %s.", network.ssid.c_str());
        return false;
    }

    if ((network.status != static_cast<int>(WifiDeviceConfigStatus::ENABLED)) &&
        (network.status != static_cast<int>(WifiDeviceConfigStatus::CURRENT))) {
        LOGI("Skip disable Network %s.NetworkId is %{public}d", network.ssid.c_str(), network.networkId);
        return false;
    }
    /*
     * Skip the network that does not support encryption.
     * There are two cases where encryption is supported but encryption is not
     * supported.
     */
    if ((network.allowedKeyManagement & 1) == BINARY_CODE) {
        return false;
    }
    return true;
}
void StaSavedNetworkEvaluator::CalculateNetworkScore(
    int &score, WifiScanInfo &scanInfo, WifiDeviceConfig &network, WifiLinkedInfo &info)
{
    LOGI("Enter StaSavedNetworkEvaluator::CalculateNetworkScore.\n");
    int rssi = scanInfo.level;
    /* Converts a signal to a grid number */
    int signalStrength = CalculateSignalBars(rssi, iSignalBars);
    /* Signal strength score */
    score += InitScore + signalStrength * ScoreSlope;
    LOGI("signalstrength score is %{public}d.\n", score);

    /* 5 GHz frequency band: bonus point */
    if (Is5GNetwork(scanInfo.frequency)) {
        score += Frequency5GHzScore;
        LOGI("5G score is %{public}d.\n", Frequency5GHzScore);
    }

    /* Bonus points for last user selection */
    int userLastSelectedNetworkId = WifiSettings::GetInstance().GetUserLastSelectedNetworkId();
    if (userLastSelectedNetworkId != INVALID_NETWORK_ID && userLastSelectedNetworkId == network.networkId) {
        time_t userLastSelectedNetworkTimeVal = WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal();
        time_t now = time(NULL);
        time_t timeDifference = now - userLastSelectedNetworkTimeVal;
        /*
         * Basic score of the network selected by the user: 120.
         * One point is deducted from every 5 points since the time when the user
         * selects the network.
         */
        if (timeDifference > 0) {
            int decay = (int)(timeDifference / LAST_SELECTION_SCORE_DECAY_S);
            int bonus = MAX((LastSelectionScore - decay), (0));
            score += bonus;
            LOGI("lastselected score is %{public}d.\n", bonus);
        }
    }
    /*
     * If the current network is the same as the candidate network, bonus points
     * are added.
     */
    if (info.detailedState == DetailedState::WORKING && scanInfo.ssid == info.ssid) {
        score += SameNetworkScore;
        LOGI("samenetwork score is %{public}d.\n", SameNetworkScore);
        /*
         * When firmware roaming is supported, the same BSSID is added to different
         * BSSIDs.
         */
        if (pConnectivityHelper->WhetherFirmwareRoamingIsSupported() && scanInfo.bssid != info.bssid) {
            score += SameBssidScore;
            LOGI("roamingsupport score is %{public}d.\n", SameBssidScore);
        }
    }

    if (info.detailedState == DetailedState::WORKING && info.bssid == scanInfo.bssid) {
        score += SameBssidScore;
        LOGI("SameBssid score is %{public}d.\n", SameBssidScore);
    }

    if (network.keyMgmt != "NONE" && network.keyMgmt.size() != 0) {
        score += SecurityScore;
        LOGI("security score is %{public}d.\n", SecurityScore);
    }
}

bool StaSavedNetworkEvaluator::Is5GNetwork(int frequency)
{
    if (frequency > MIN_5_FREQUENCY && frequency < MAX_5_FREQUENCY) {
        return true;
    } else {
        return false;
    }
}

int StaSavedNetworkEvaluator::CalculateSignalBars(int rssi, int signalBars)
{
    LOGI("Enter StaSavedNetworkEvaluator CalculateSignalBars");
    if (rssi <= MIN_RSSI) {
        return 0;
    } else if (rssi >= MAX_RSSI) {
        return signalBars - 1;
    } else {
        float inputRange = (MAX_RSSI - MIN_RSSI);
        float outputRange = (signalBars - 1);
        return static_cast<int>(static_cast<float>(rssi - MIN_RSSI) * outputRange / inputRange);
    }
}
}  // namespace Wifi
}  // namespace OHOS