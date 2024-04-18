/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_filter_impl.h"
#include "network_selection_utils.h"
#include "network_status_history_manager.h"
#include "wifi_logger.h"
#include "wifi_settings.h"

namespace OHOS::Wifi::NetworkSelection {
DEFINE_WIFILOG_LABEL("WifiFilter")

constexpr int RECHECK_DELAYED_SECONDS = 1 * 60 * 60;
constexpr int MIN_5GHZ_BAND_FREQUENCY = 5000;
constexpr int MIN_RSSI_VALUE_24G = -77;
constexpr int MIN_RSSI_VALUE_5G = -80;
constexpr int SIGNAL_LEVEL_TWO = 2;
constexpr int POOR_PORTAL_RECHECK_DELAYED_SECONDS = 2 * RECHECK_DELAYED_SECONDS;

HiddenWifiFilter::HiddenWifiFilter() : SimpleWifiFilter("notHidden") {}

HiddenWifiFilter::~HiddenWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGD("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool HiddenWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return !networkCandidate.interScanInfo.ssid.empty();
}


SignalStrengthWifiFilter::SignalStrengthWifiFilter(): SimpleWifiFilter("notSignalWooWeak") {}

SignalStrengthWifiFilter::~SignalStrengthWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGD("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool SignalStrengthWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &scanInfo = networkCandidate.interScanInfo;
    auto rssiThreshold = scanInfo.frequency < MIN_5GHZ_BAND_FREQUENCY ? MIN_RSSI_VALUE_24G : MIN_RSSI_VALUE_5G;
    return scanInfo.rssi >= rssiThreshold;
}

SavedWifiFilter::SavedWifiFilter() : SimpleWifiFilter("savedWifiFilter") {}

SavedWifiFilter::~SavedWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool SavedWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.networkId != INVALID_NETWORK_ID;
}


EphemeralWifiFilter::EphemeralWifiFilter() : SimpleWifiFilter("notEphemeral") {}

EphemeralWifiFilter::~EphemeralWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool EphemeralWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return !networkCandidate.wifiDeviceConfig.isEphemeral;
}

PassPointWifiFilter::PassPointWifiFilter() : SimpleWifiFilter("notPassPoint") {}

PassPointWifiFilter::~PassPointWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool PassPointWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return !networkCandidate.wifiDeviceConfig.isPasspoint;
}


DisableWifiFilter::DisableWifiFilter() : SimpleWifiFilter("enableWifi") {}

DisableWifiFilter::~DisableWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool DisableWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.status == static_cast<int>(WifiDeviceConfigStatus::ENABLED);
}

MatchedUserSelectBssidWifiFilter::MatchedUserSelectBssidWifiFilter() : SimpleWifiFilter("matchUserSelect") {}

MatchedUserSelectBssidWifiFilter::~MatchedUserSelectBssidWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool MatchedUserSelectBssidWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.userSelectBssid.empty()) {
        return true;
    }
    return networkCandidate.interScanInfo.bssid == networkCandidate.wifiDeviceConfig.userSelectBssid;
}

HasInternetWifiFilter::HasInternetWifiFilter() : SimpleWifiFilter("hasInternet") {}

HasInternetWifiFilter::~HasInternetWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool HasInternetWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (wifiDeviceConfig.noInternetAccess || wifiDeviceConfig.isPortal) {
        return false;
    }
    if (NetworkStatusHistoryManager::IsInternetAccessByHistory(wifiDeviceConfig.networkStatusHistory)) {
        return true;
    }
    if (NetworkSelectionUtils::IsOpenNetwork(networkCandidate)) {
        return false;
    }
    return NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory);
}

RecoveryWifiFilter::RecoveryWifiFilter() : SimpleWifiFilter("recovery") {}

RecoveryWifiFilter::~RecoveryWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool RecoveryWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    return wifiDeviceConfig.noInternetAccess && !wifiDeviceConfig.isPortal &&
        NetworkStatusHistoryManager::IsAllowRecoveryByHistory(wifiDeviceConfig.networkStatusHistory);
}

PoorPortalWifiFilter::PoorPortalWifiFilter() : SimpleWifiFilter("notPoorPortal") {}

PoorPortalWifiFilter::~PoorPortalWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool PoorPortalWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &interScanInfo = networkCandidate.interScanInfo;
    int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(interScanInfo.rssi, interScanInfo.band);
    if (currentSignalLevel > SIGNAL_LEVEL_TWO) {
        return true;
    }
    if (currentSignalLevel < SIGNAL_LEVEL_TWO) {
        return false;
    }
    auto lastHasInternetTime = networkCandidate.wifiDeviceConfig.lastHasInternetTime;
    auto now = time(nullptr);
    if (now < 0) {
        WIFI_LOGW("time return invalid!\n.");
        return false;
    }
    return (now - lastHasInternetTime) <= POOR_PORTAL_RECHECK_DELAYED_SECONDS;
}

PortalWifiFilter::PortalWifiFilter() : SimpleWifiFilter("portalWifiFilter") {}

PortalWifiFilter::~PortalWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool PortalWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.isPortal;
}


MaybePortalWifiFilter::MaybePortalWifiFilter() : SimpleWifiFilter("maybePortal") {}

MaybePortalWifiFilter::~MaybePortalWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool MaybePortalWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return !NetworkSelectionUtils::IsScanResultForOweNetwork(networkCandidate) &&
        NetworkSelectionUtils::IsOpenAndMaybePortal(networkCandidate);
}


NoInternetWifiFilter::NoInternetWifiFilter() : SimpleWifiFilter("noInternet") {}

NoInternetWifiFilter::~NoInternetWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool NoInternetWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    return wifiDeviceConfig.noInternetAccess
        && !NetworkStatusHistoryManager::IsAllowRecoveryByHistory(wifiDeviceConfig.networkStatusHistory);
}


WeakAlgorithmWifiFilter::WeakAlgorithmWifiFilter() : SimpleWifiFilter("noWeakAlgorithm") {}

WeakAlgorithmWifiFilter::~WeakAlgorithmWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool WeakAlgorithmWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &scanInfo = networkCandidate.interScanInfo;
    if (scanInfo.securityType == WifiSecurity::WEP) {
        WIFI_LOGD("WeakAlgorithm: WEP AP(%{public}s) is ignored", networkCandidate.ToString().c_str());
        return false;
    } else if (scanInfo.securityType == WifiSecurity::OPEN) {
        WIFI_LOGD("WeakAlgorithm: OPEN AP(%{public}s) is ignored", networkCandidate.ToString().c_str());
        return false;
    } else if (scanInfo.securityType == WifiSecurity::PSK
        && scanInfo.capabilities.find("TKIP") != std::string::npos) {
        WIFI_LOGD("WeakAlgorithm: WPA AP(%{public}s) is ignored", networkCandidate.ToString().c_str());
        return false;
    }
    return true;
}
}
