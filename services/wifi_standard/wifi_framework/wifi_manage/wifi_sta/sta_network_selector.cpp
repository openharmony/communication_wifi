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
#include "sta_network_selector.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_NETWORK_SELECTOR"
namespace OHOS {
namespace Wifi {
StaNetworkSelector::StaNetworkSelector()
    : LastNetworkSelectionTimeStamp(0), pEvaluators {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}
{}
StaNetworkSelector::~StaNetworkSelector()
{
    LOGI("Enter StaNetworkSelector::~StaNetworkSelector.\n");
}

bool StaNetworkSelector::RegisterNetworkEvaluator(StaNetworkEvaluator *evaluator, int priority)
{
    LOGI("Enter StaNetworkSelector::RegisterNetworkEvaluator.\n");
    if (priority < 0 || priority >= EVALUATOR_MIN_PRIORITY) {
        LOGE("Out of array range.\n");
        return false;
    }
    if (pEvaluators[priority] != nullptr) {
        LOGE("Evaluators is not empty.\n");
        return false;
    }
    pEvaluators[priority] = evaluator;
    return true;
}

ErrCode StaNetworkSelector::SelectNetwork(WifiDeviceConfig &candidate, const std::vector<WifiScanInfo> &scanResults,
    std::vector<std::string> &blocklistedBssids, WifiLinkedInfo &info)
{
    LOGI("Enter StaNetworkSelector::SelectNetwork.\n");
    if (scanResults.empty()) {
        LOGE("No scanResult.\n");
        return WIFI_OPT_FAILED;
    }

    /* Whether network selection handover is required */
    if (!IsNetworkSelectionRequired(scanResults, info)) {
        LOGE("Network switching is not required.\n");
        return WIFI_OPT_FAILED;
    }

    /* Before initiating network selection, update all configured networks. */
    UpdateConfigNetworks();

    for (auto registeredEvaluator : pEvaluators) {
        if (registeredEvaluator != nullptr) {
            registeredEvaluator->Update(scanResults);
        }
    }

    std::vector<WifiScanInfo> filteredscanResults;
    /* Filter out unnecessary networks. */
    FilterscanResults(filteredscanResults, scanResults, blocklistedBssids, info);
    if (filteredscanResults.empty()) {
        LOGE("No scanResult available.\n");
        return WIFI_OPT_FAILED;
    }
    /*
     * Check the registered network evaluator from highest priority to lowest
     * priority until the selected network
     */
    for (auto registeredEvaluator : pEvaluators) {
        if (registeredEvaluator != nullptr) {
            ErrCode code = registeredEvaluator->NetworkEvaluators(candidate, filteredscanResults, info);
            if (code == WIFI_OPT_SUCCESS) {
                time_t now = time(NULL);
                LastNetworkSelectionTimeStamp = (int)now;
                LOGI("candidate network generation.\n");
                return WIFI_OPT_SUCCESS;
            }
        }
    }

    if (RoamingSelection(candidate, filteredscanResults, info)) {
        LOGI("Roaming network generation.\n");
        return WIFI_OPT_SUCCESS;
    }
    LOGE("No candidate network.\n");
    return WIFI_OPT_FAILED;
}

bool StaNetworkSelector::RoamingSelection(
    WifiDeviceConfig &candidate, std::vector<WifiScanInfo> &filteredscanResults, WifiLinkedInfo &info)
{
    for (auto scanInfo : filteredscanResults) {
        if (info.connState == ConnState::CONNECTED && scanInfo.ssid == info.ssid && scanInfo.bssid != info.bssid) {
            LOGI("Discover roaming networks.\n");
            if (RoamingEncryptionModeCheck(candidate, scanInfo, info)) {
                return true;
            }
        }
    }
    return false;
}

bool StaNetworkSelector::RoamingEncryptionModeCheck(
    WifiDeviceConfig &candidate, WifiScanInfo scanInfo, WifiLinkedInfo &info)
{
    WifiDeviceConfig network;
    if (WifiSettings::GetInstance().GetDeviceConfig(scanInfo.ssid, DEVICE_CONFIG_INDEX_SSID, network) == 0) {
        std::string mgmt = scanInfo.capabilities;
        if (mgmt.find("WPA-PSK") != std::string::npos || mgmt.find("WPA2-PSK") != std::string::npos) {
            mgmt = "WPA-PSK";
        } else if (mgmt.find("EAP") != std::string::npos) {
            mgmt = "WPA-EAP";
        } else if (mgmt.find("SAE") != std::string::npos) {
            mgmt = "SAE";
        } else {
            if (mgmt.find("WEP") != std::string::npos && network.wepTxKeyIndex == 0) {
                LOGE("The roaming network is a WEP network, but the connected network is not a WEP network.\n");
                return false;
            } else if (mgmt.find("WEP") == std::string::npos && network.wepTxKeyIndex != 0) {
                LOGE("The connected network is a WEP network, but the roaming network is not a WEP network.\n");
                return false;
            }
            mgmt = "NONE";
        }
        if (mgmt == network.keyMgmt) {
            LOGI("The Current network bssid %s signal strength is %{public}d", info.bssid.c_str(), info.rssi);
            LOGI("The Roaming network bssid %s signal strength is %{public}d", scanInfo.bssid.c_str(), scanInfo.level);
            int level = scanInfo.level - info.rssi;
            if (level > LEVEL) {
                LOGI("Roming network rssi - Current network rssi > 6.");
                candidate.ssid = scanInfo.ssid;
                candidate.bssid = scanInfo.bssid;
                return true;
            } else {
                LOGE("Roming network rssi - Current network rssi < 6.");
            }
        } else {
            LOGE("The encryption mode does not match.\n");
        }
    }
    return false;
}

bool StaNetworkSelector::IsNetworkSelectionRequired(const std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info)
{
    LOGI("Enter StaNetworkSelector::IsNetworkSelectionRequired.\n");
    if (scanResults.empty()) {
        LOGE("No network,skip network selection.\n");
        return false;
    }

    /* Connected to the network */
    if (info.detailedState == DetailedState::WORKING) {
        LOGI("The current connection status is Connected and working.\n");

        /* Configure whether to automatically switch the network. */
        if (!WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover()) {
            LOGE("Automatic network switching is not allowed in user "
                 "configuration.\n");
            return false;
        }
        /*
         * Indicates whether the minimum interval is the minimum interval since the
         * last network selection.
         */
        if (LastNetworkSelectionTimeStamp != 0) {
            int gap = (int)time(0) - LastNetworkSelectionTimeStamp;
            if (gap < MINIMUM_NETWORK_SELECTION_INTERVAL_S) {
                LOGE("%ds time before we selected the network(30s).\n", gap);
                return false;
            }
        }

        if (IsCurrentNetworkSuffice(scanResults, info)) {
            LOGE("The current network is suffice.\n");
            return false;
        } else {
            LOGI("The current network is insuffice.\n");
            return true;
        }
    } else if (info.detailedState == DetailedState::DISCONNECTED) {
        LOGI("The current connection status is Disconnected.\n");
        return true;
    } else if (info.detailedState == DetailedState::NOTWORKING) {
        LOGI("The current network cannot access the Internet.\n");

        /* Configure whether to automatically switch the network. */
        if (!WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover()) {
            LOGE("Automatic network switching is not allowed in user "
                 "configuration.\n");
            return false;
        } else {
            return true;
        }
    } else {
        LOGE("The current connection status is %{public}d.\n", info.detailedState);
        return false;
    }
}

bool StaNetworkSelector::IsCurrentNetworkSuffice(const std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info)
{
    LOGI("Enter StaNetworkSelector::IsCurrentNetworkSuffice.\n");

    WifiDeviceConfig network;

    /* The network is deleted */
    if (WifiSettings::GetInstance().GetDeviceConfig(info.networkId, network) == -1) {
        LOGE("The network is deleted.\n");
        return false;
    }

    int userLastSelectedNetworkId = WifiSettings::GetInstance().GetUserLastSelectedNetworkId();
    if (userLastSelectedNetworkId != INVALID_NETWORK_ID && userLastSelectedNetworkId == network.networkId) {
        time_t userLastSelectedNetworkTimeVal = WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal();
        time_t now = time(NULL);
        int interval = (int)(now - userLastSelectedNetworkTimeVal);
        if (interval <= LAST_USER_SELECTION_SUFFICIENT_S) {
            LOGI("(60s)Current user recent selections time is %ds.\n", interval);
            return true;
        }
    }

    /* Temporary network unqualified */
    if (network.isEphemeral) {
        LOGE("The network is isEphemeral.\n");
        return false;
    }

    if (network.keyMgmt == "NONE" || network.keyMgmt.size() == 0) {
        LOGE("This network No keyMgmt.\n");
        return false;
    }

    /* The signal strength on the live network does not meet requirements. */
    if (info.rssi < RSSI_DELIMITING_VALUE) {
        LOGE("Signal strength insuffice %{public}d < -65.\n", info.rssi);
        return false;
    }
    /*
     * The network is a 2.4 GHz network and is not qualified when the 5G network
     * is available.
     */
    if (Is24GNetwork(info.frequency)) {
        if (Is5GHzNetworkAvailable(scanResults)) {
            LOGE("5 GHz is available when the current frequency band is 2.4 GHz.\n");
            return false;
        }
    }
    return true;
}

bool StaNetworkSelector::Is5GHzNetworkAvailable(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaNetworkSelector::is5GHzNetworkAvailable.\n");
    for (auto scaninfo : scanResults) {
        if (Is5GNetwork(scaninfo.frequency)) {
            return true;
        }
    }
    return false;
}

bool StaNetworkSelector::Is24GNetwork(int frequency)
{
    if (frequency > MIN_24_FREQUENCY && frequency < MAX_24_FREQUENCY) {
        return true;
    } else {
        return false;
    }
}

bool StaNetworkSelector::Is5GNetwork(int frequency)
{
    if (frequency > MIN_5_FREQUENCY && frequency < MAX_5_FREQUENCY) {
        return true;
    } else {
        return false;
    }
}

void StaNetworkSelector::UpdateConfigNetworks()
{
    LOGI("Enter StaNetworkSelector::UpdateConfigNetworks.\n");
    std::vector<WifiDeviceConfig> configs;
    WifiSettings::GetInstance().GetDeviceConfig(configs);
    if (configs.empty()) {
        LOGE("No config networks.\n");
        return;
    }
    for (auto network : configs) {
        if (network.status == 1) {
            LOGI("The network is disable.networkId is %{public}d.", network.networkId);
        }
    }
    return;
}

void StaNetworkSelector::FilterscanResults(std::vector<WifiScanInfo> &filteredscanResults,
    const std::vector<WifiScanInfo> &scanResults, std::vector<std::string> &blocklistedBssids, WifiLinkedInfo &info)
{
    LOGI("Enter StaNetworkSelector::FilterscanResults.\n");
    if (scanResults.empty()) {
        return;
    }
    bool scanResultsHaveCurrentBssid = false;

    for (auto scanInfo : scanResults) {
        if (scanInfo.ssid.size() == 0) {
            continue;
        }

        /* Check whether the scanning result contains the current BSSID. */
        if (info.connState == ConnState::CONNECTED && scanInfo.bssid == info.bssid) {
            scanResultsHaveCurrentBssid = true;
        }

        auto itr = find(blocklistedBssids.begin(), blocklistedBssids.end(), scanInfo.bssid);
        if (itr != blocklistedBssids.end()) { /* Skip Blocklist Network */
            LOGI("Skip blocklistedBssid network %s.\n", scanInfo.ssid.c_str());
            continue;
        }

        /* Skipping networks with weak signals */
        if (scanInfo.frequency < MINIMUM_5_GHZ_BAND_FREQUENCY_IN_MEGAHERTZ) {
            if (scanInfo.level <= MINIMUM_RSSI24) {
                LOGI("Skip network %s with low 2.4G signals %{public}d.\n", scanInfo.ssid.c_str(), scanInfo.level);
                continue;
            }
        } else {
            if (scanInfo.level <= MINIMUM_RSSI5) {
                LOGI("Skip network %s with low 5G signals %{public}d.\n", scanInfo.ssid.c_str(), scanInfo.level);
                continue;
            }
        }
        filteredscanResults.push_back(scanInfo);
    }
    /*
     * Some scan requests may not include channels for the currently connected
     * network, so the currently connected network will not appear in the scan
     * results. We will not act on these scans to avoid network switching that may
     * trigger disconnections.
     */
    if (info.connState == ConnState::CONNECTED && !scanResultsHaveCurrentBssid) {
        LOGI("scanResult is be cleared.\n");
        filteredscanResults.clear();
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS