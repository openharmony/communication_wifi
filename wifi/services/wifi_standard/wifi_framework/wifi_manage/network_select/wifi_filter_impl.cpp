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
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_settings.h"
#include "network_black_list_manager.h"
#include "wifi_ap_msg.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_app_state_aware.h"
#include "wifi_sensor_scene.h"
#endif
namespace OHOS::Wifi::NetworkSelection {
DEFINE_WIFILOG_LABEL("WifiFilter")
namespace {
constexpr int RECHECK_DELAYED_SECONDS = 1 * 60 * 60;
constexpr int SIGNAL_LEVEL_TWO = 2;
constexpr int POOR_PORTAL_RECHECK_DELAYED_SECONDS = 2 * RECHECK_DELAYED_SECONDS;
constexpr int32_t MIN_SIGNAL_LEVEL_INTERVAL = 2;
constexpr int32_t SIGNAL_LEVEL_THREE = 3;
constexpr int32_t MIN_RSSI_INTERVAL = 8;
}

HiddenWifiFilter::HiddenWifiFilter() : SimpleWifiFilter("notHidden") {}

HiddenWifiFilter::~HiddenWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool HiddenWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.interScanInfo.ssid.empty()) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::HIDDEN_NETWORK);
        return false;
    }
    return true;
}


SignalStrengthWifiFilter::SignalStrengthWifiFilter(): SimpleWifiFilter("notSignalWooWeak") {}

SignalStrengthWifiFilter::~SignalStrengthWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool SignalStrengthWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &scanInfo = networkCandidate.interScanInfo;
#ifndef OHOS_ARCH_LITE
    int rssiThreshold = WifiSensorScene::GetInstance().GetMinRssiThres(scanInfo.frequency);
#else
    auto rssiThreshold = scanInfo.frequency < MIN_5GHZ_BAND_FREQUENCY ? MIN_RSSI_VALUE_24G : MIN_RSSI_VALUE_5G;
#endif
    if (scanInfo.rssi < rssiThreshold) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::POOR_SIGNAL);
        return false;
    }
    return true;
}

SavedWifiFilter::SavedWifiFilter() : SimpleWifiFilter("savedWifiFilter") {}

SavedWifiFilter::~SavedWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool SavedWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.networkId == INVALID_NETWORK_ID) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NETWORK_ID_INVALID);
        return false;
    }
    if (networkCandidate.wifiDeviceConfig.uid != -1 && networkCandidate.wifiDeviceConfig.isShared == false) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NOT_SYSTEM_NETWORK);
        return false;
    }
    return true;
}


EphemeralWifiFilter::EphemeralWifiFilter() : SimpleWifiFilter("notEphemeral") {}

EphemeralWifiFilter::~EphemeralWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool EphemeralWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.isEphemeral) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::EPHEMERAL_NETWORK);
        return false;
    }
    return true;
}

PassPointWifiFilter::PassPointWifiFilter() : SimpleWifiFilter("notPassPoint") {}

PassPointWifiFilter::~PassPointWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool PassPointWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.isPasspoint) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::PASSPOINT_NETWORK);
        return false;
    }
    return true;
}


DisableWifiFilter::DisableWifiFilter() : SimpleWifiFilter("enableWifi") {}

DisableWifiFilter::~DisableWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool DisableWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.networkSelectionStatus.status != WifiDeviceConfigStatus::ENABLED) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NETWORK_STATUS_DISABLE);
        return false;
    }
    if (!networkCandidate.wifiDeviceConfig.isAllowAutoConnect) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NOT_ALLOW_AUTO_CONNECT);
        return false;
    }
    return true;
}

MatchedUserSelectBssidWifiFilter::MatchedUserSelectBssidWifiFilter() : SimpleWifiFilter("matchUserSelect") {}

MatchedUserSelectBssidWifiFilter::~MatchedUserSelectBssidWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool MatchedUserSelectBssidWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.userSelectBssid.empty()) {
        return true;
    }
    if (networkCandidate.interScanInfo.bssid != networkCandidate.wifiDeviceConfig.userSelectBssid) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::UNEXPECTED_NETWORK_BY_USER);
        return false;
    }
    return true;
}

HasInternetWifiFilter::HasInternetWifiFilter() : SimpleWifiFilter("hasInternet") {}

HasInternetWifiFilter::~HasInternetWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool HasInternetWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (wifiDeviceConfig.noInternetAccess) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NO_INTERNET);
        return false;
    }
    if (wifiDeviceConfig.isPortal) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::PORTAL_NETWORK);
        return false;
    }
    if (NetworkStatusHistoryManager::IsInternetAccessByHistory(wifiDeviceConfig.networkStatusHistory)) {
        return true;
    }
    if (NetworkSelectionUtils::IsOpenNetwork(networkCandidate)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::OPEN_NETWORK);
        return false;
    }
    if (!NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::HAS_NETWORK_HISTORY);
        return false;
    }
    return true;
}

RecoveryWifiFilter::RecoveryWifiFilter() : SimpleWifiFilter("recovery") {}

RecoveryWifiFilter::~RecoveryWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool RecoveryWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory)) {
        InterScanInfo interScanInfo = networkCandidate.interScanInfo;
        WIFI_LOGI("RecoveryWifiFilter, network history is 0, try reconnect, add candidate network, bssid=%{public}s",
            MacAnonymize(interScanInfo.bssid).c_str());
        return true;
    }
    if (!wifiDeviceConfig.noInternetAccess) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::HAS_INTERNET);
        return false;
    }
    if (wifiDeviceConfig.isPortal) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::PORTAL_NETWORK);
        return false;
    }
    if (!NetworkStatusHistoryManager::IsAllowRecoveryByHistory(wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::UNRECOVERABLE_NETWORK);
        return false;
    }
    return true;
}

PoorPortalWifiFilter::PoorPortalWifiFilter() : SimpleWifiFilter("notPoorPortal") {}

PoorPortalWifiFilter::~PoorPortalWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool PoorPortalWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &interScanInfo = networkCandidate.interScanInfo;
    if (networkCandidate.wifiDeviceConfig.isPortal &&
        networkCandidate.wifiDeviceConfig.noInternetAccess &&
        !NetworkStatusHistoryManager::IsAllowRecoveryByHistory(
            networkCandidate.wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert({FiltedReason::PORTAL_NETWORK, FiltedReason::NO_INTERNET,
            FiltedReason::UNRECOVERABLE_NETWORK});
        return false;
    }
    int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(interScanInfo.rssi, interScanInfo.band);
    if (currentSignalLevel > SIGNAL_LEVEL_TWO) {
        return true;
    }
    if (currentSignalLevel < SIGNAL_LEVEL_TWO) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::POOR_SIGNAL);
        return false;
    }
    auto lastHasInternetTime = networkCandidate.wifiDeviceConfig.lastHasInternetTime;
    auto now = time(nullptr);
    if (now < 0) {
        WIFI_LOGW("time return invalid!\n.");
        networkCandidate.filtedReason[filterName].insert(FiltedReason::TIME_INVALID);
        return false;
    }
    if ((now - lastHasInternetTime) > POOR_PORTAL_RECHECK_DELAYED_SECONDS) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::TIMEOUT_AND_NEED_RECHECK);
        return false;
    }
    return true;
}

PortalWifiFilter::PortalWifiFilter() : SimpleWifiFilter("portalWifiFilter") {}

PortalWifiFilter::~PortalWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool PortalWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.isPortal &&
        networkCandidate.wifiDeviceConfig.noInternetAccess &&
        !NetworkStatusHistoryManager::IsAllowRecoveryByHistory(
            networkCandidate.wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert({FiltedReason::PORTAL_NETWORK, FiltedReason::NO_INTERNET,
            FiltedReason::UNRECOVERABLE_NETWORK});
        return false;
    }
    if (!networkCandidate.wifiDeviceConfig.isPortal) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NOT_PORTAL_NETWORK);
        return false;
    }
    return true;
}

MaybePortalWifiFilter::MaybePortalWifiFilter() : SimpleWifiFilter("maybePortal") {}

MaybePortalWifiFilter::~MaybePortalWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool MaybePortalWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (NetworkSelectionUtils::IsScanResultForOweNetwork(networkCandidate)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::OWE_NETWORK);
        return false;
    }
    if (!NetworkSelectionUtils::IsOpenAndMaybePortal(networkCandidate, filterName)) {
        //The filtering reason has been added to this IsOpenAndMaybePortal interface.
        return false;
    }
    if (networkCandidate.wifiDeviceConfig.noInternetAccess &&
        !NetworkStatusHistoryManager::IsAllowRecoveryByHistory(
            networkCandidate.wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert({FiltedReason::NO_INTERNET,
            FiltedReason::UNRECOVERABLE_NETWORK});
        return false;
    }
    return true;
}


NoInternetWifiFilter::NoInternetWifiFilter() : SimpleWifiFilter("noInternet") {}

NoInternetWifiFilter::~NoInternetWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool NoInternetWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (!NetworkStatusHistoryManager::HasInternetEverByHistory(wifiDeviceConfig.networkStatusHistory)) {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NO_INTERNET);
        return false;
    }
    return true;
}

WeakAlgorithmWifiFilter::WeakAlgorithmWifiFilter() : SimpleWifiFilter("noWeakAlgorithm") {}

WeakAlgorithmWifiFilter::~WeakAlgorithmWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("%{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates, filterName).c_str());
    }
}

bool WeakAlgorithmWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &scanInfo = networkCandidate.interScanInfo;
    if (scanInfo.securityType == WifiSecurity::WEP) {
        WIFI_LOGD("WeakAlgorithm: WEP AP(%{public}s) is ignored", networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::WEAK_ALGORITHM_WEP_SECURITY);
        return false;
    } else if (scanInfo.securityType == WifiSecurity::OPEN) {
        WIFI_LOGD("WeakAlgorithm: OPEN AP(%{public}s) is ignored", networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::OPEN_NETWORK);
        return false;
    } else if (scanInfo.securityType == WifiSecurity::PSK
        && scanInfo.capabilities.find("TKIP") != std::string::npos) {
        if (scanInfo.capabilities.find("CCMP") != std::string::npos) {
            return true;
        }
        WIFI_LOGD("WeakAlgorithm: WPA AP(%{public}s) is ignored", networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::WEAK_ALGORITHM_WPA_SECURITY);
        return false;
    }
    return true;
}

NotCurrentNetworkFilter::NotCurrentNetworkFilter() : SimpleWifiFilter("NotCurrentNetwork") {}

NotCurrentNetworkFilter::~NotCurrentNetworkFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool NotCurrentNetworkFilter::Filter(NetworkCandidate &networkCandidate)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (networkCandidate.interScanInfo.bssid == linkedInfo.bssid) {
        WIFI_LOGI("NotCurrentNetworkFilter, same bssid:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::SAME_BSSID);
        return false;
    }

    if ((networkCandidate.interScanInfo.ssid == linkedInfo.ssid) &&
        NetworkSelectionUtils::IsConfigOpenOrEapType(networkCandidate)) {
        WIFI_LOGI("NotCurrentNetworkFilter, same ssid and open or eap type:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::SAME_SSID_OPENOREAP);
        return false;
    }
    return true;
}

SignalLevelFilter::SignalLevelFilter() : SimpleWifiFilter("SignalLevel") {}

SignalLevelFilter::~SignalLevelFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool SignalLevelFilter::Filter(NetworkCandidate &networkCandidate)
{
    auto &interScanInfo = networkCandidate.interScanInfo;
    int32_t signalLevel = WifiSettings::GetInstance().GetSignalLevel(interScanInfo.rssi, interScanInfo.band);
    if (signalLevel > SIGNAL_LEVEL_TWO) {
        return true;
    }
    networkCandidate.filtedReason[filterName].insert(FiltedReason::POOR_SIGNAL);
    return false;
}

ValidNetworkIdFilter::ValidNetworkIdFilter() : SimpleWifiFilter("ValidNetworkId") {}
 
ValidNetworkIdFilter::~ValidNetworkIdFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}
 
bool ValidNetworkIdFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.wifiDeviceConfig.networkId != INVALID_NETWORK_ID) {
        return true;
    } else {
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NETWORK_ID_INVALID);
        return false;
    }
}

NotNetworkBlackListFilter::NotNetworkBlackListFilter() : SimpleWifiFilter("NotNetworkBlackList") {}

NotNetworkBlackListFilter::~NotNetworkBlackListFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool NotNetworkBlackListFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (NetworkBlockListManager::GetInstance().IsInAbnormalWifiBlocklist(networkCandidate.interScanInfo.bssid)) {
        WIFI_LOGI("NotNetworkBlockListFilter, in abnormal wifi blocklist, skip candidate:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NETWORK_STATUS_DISABLE);
        return false;
    }

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int32_t curSignalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band);
    auto scanInfo = networkCandidate.interScanInfo;
    int32_t targetSignalLevel = WifiSettings::GetInstance().GetSignalLevel(scanInfo.rssi, scanInfo.band);
    if (NetworkBlockListManager::GetInstance().IsInWifiBlocklist(networkCandidate.interScanInfo.bssid) &&
        (targetSignalLevel <= SIGNAL_LEVEL_THREE || targetSignalLevel - curSignalLevel < MIN_SIGNAL_LEVEL_INTERVAL)) {
        if (linkedInfo.detailedState == DetailedState::NOTWORKING && targetSignalLevel >= SIGNAL_LEVEL_THREE) {
            WIFI_LOGI("NotNetworkBlockListFilter, ignore blocklist, targetSignalLevel >= 3, candidate:%{public}s",
                networkCandidate.ToString().c_str());
            return true;
        }
        WIFI_LOGI("NotNetworkBlackListFilter, in wifi blocklist, targetSignalLevel:%{public}d, "
            "curSignalLevel:%{public}d, skip candidate:%{public}s",
            targetSignalLevel, curSignalLevel, networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::BLOCKLIST_AP);
        return false;
    }
    return true;
}

NotP2pFreqAt5gFilter::NotP2pFreqAt5gFilter() : SimpleWifiFilter("NotP2pFreqAt5g") {}

NotP2pFreqAt5gFilter::~NotP2pFreqAt5gFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool NotP2pFreqAt5gFilter::Filter(NetworkCandidate &networkCandidate)
{
    if (networkCandidate.interScanInfo.band == static_cast<int>(BandType::BAND_2GHZ)) {
        return true;
    }

    Hid2dUpperScene softbusScene;
    Hid2dUpperScene castScene;
    Hid2dUpperScene shareScene;
    Hid2dUpperScene mouseCrossScene;
    Hid2dUpperScene miracastScene;
    WifiP2pLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SOFT_BUS_SERVICE_UID, softbusScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(CAST_ENGINE_SERVICE_UID, castScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MIRACAST_SERVICE_UID, miracastScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SHARE_SERVICE_UID, shareScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MOUSE_CROSS_SERVICE_UID, mouseCrossScene);
    WifiConfigCenter::GetInstance().GetP2pInfo(linkedInfo);
    if (linkedInfo.GetConnectState() == P2pConnectedState::P2P_DISCONNECTED
        && WifiConfigCenter::GetInstance().GetP2pEnhanceState() == 0) {
        return true;
    }
    // scene bit 0-2 is valid, 0x01: video, 0x02: audio, 0x04: file,
    // scene & 0x07 > 0 means one of them takes effect.
    bool isCastScene = false;
    if ((softbusScene.scene & 0x07) > 0 || (castScene.scene & 0x07) > 0 || (shareScene.scene & 0x07) > 0 ||
        (mouseCrossScene.scene & 0x07) > 0 || (miracastScene.scene & 0x07) > 0) {
        isCastScene = true;
    }

    if (!isCastScene) {
        return true;
    }

    if (NetworkSelectionUtils::IsSameFreqAsP2p(networkCandidate)) {
        return true;
    }
    networkCandidate.filtedReason[filterName].insert(FiltedReason::NOT_P2P_FREQ_AT_5G);
    return false;
}

ValidConfigNetworkFilter::ValidConfigNetworkFilter() : SimpleWifiFilter("ValidConfigNetwork") {}

ValidConfigNetworkFilter::~ValidConfigNetworkFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool ValidConfigNetworkFilter::Filter(NetworkCandidate &networkCandidate)
{
    // no internet filtering
    auto &wifiDeviceConfig = networkCandidate.wifiDeviceConfig;
    if (wifiDeviceConfig.noInternetAccess) {
        WIFI_LOGI("ValidConfigNetworkFilter, no internet access, skip candidate:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NO_INTERNET);
        return false;
    }

    // status history < 80%
    if (!NetworkStatusHistoryManager::IsInternetAccessByHistory(wifiDeviceConfig.networkStatusHistory)) {
        WIFI_LOGI("ValidConfigNetworkFilter, current network status history is %{public}s., skip : %{public}s",
            NetworkStatusHistoryManager::ToString(wifiDeviceConfig.networkStatusHistory).c_str(),
            networkCandidate.ToString().c_str());
        return false;
    }

    // portal network filtering
    if (networkCandidate.wifiDeviceConfig.isPortal) {
        WIFI_LOGI("ValidConfigNetworkFilter, portal network, skip candidate:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::PORTAL_NETWORK);
        return false;
    }

    // disable network filtering
    auto &networkSelectionStatus = networkCandidate.wifiDeviceConfig.networkSelectionStatus;
    if (networkSelectionStatus.status != WifiDeviceConfigStatus::ENABLED ||
        !networkCandidate.wifiDeviceConfig.isAllowAutoConnect) {
        WIFI_LOGI("ValidConfigNetworkFilter, disable network, skip candidate:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::NETWORK_STATUS_DISABLE);
        return false;
    }

    // empty network status history
    if (NetworkStatusHistoryManager::IsEmptyNetworkStatusHistory(wifiDeviceConfig.networkStatusHistory)) {
        WIFI_LOGI("ValidConfigNetworkFilter, no network status history, skip candidate:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::EMPTY_HISTORY);
        return false;
    }

    // maybe portal network filtering
    if (NetworkSelectionUtils::IsScanResultForOweNetwork(networkCandidate) &&
        NetworkSelectionUtils::IsOpenAndMaybePortal(networkCandidate)) {
        WIFI_LOGI("ValidConfigNetworkFilter, maybe portal network, skip candidate:%{public}s",
            networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::MAYBE_PORTAL_NETWORK);
        return false;
    }

    return true;
}

WifiSwitchThresholdFilter::WifiSwitchThresholdFilter() : SimpleWifiFilter("WifiSwitchThreshold") {}

WifiSwitchThresholdFilter::~WifiSwitchThresholdFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

bool WifiSwitchThresholdFilter::Filter(NetworkCandidate &networkCandidate)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    auto &interScanInfo = networkCandidate.interScanInfo;

    if (interScanInfo.rssi - linkedInfo.rssi < MIN_RSSI_INTERVAL) {
        WIFI_LOGI("WifiSwitchThresholdFilter, scan rssi:%{public}d, cur rssi:%{public}d, skip candidate:%{public}s",
            interScanInfo.rssi, linkedInfo.rssi, networkCandidate.ToString().c_str());
        networkCandidate.filtedReason[filterName].insert(FiltedReason::LESS_THAN_8RSSI);
        return false;
    }

    return true;
}

SuggestionNetworkWifiFilter::SuggestionNetworkWifiFilter() : SimpleWifiFilter("suggestionNetworkWifiFilter") {}
 
SuggestionNetworkWifiFilter::~SuggestionNetworkWifiFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}
 
bool SuggestionNetworkWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return networkCandidate.wifiDeviceConfig.uid != WIFI_INVALID_UID &&
        networkCandidate.wifiDeviceConfig.isShared == false;
}

WifiSwitchThresholdQoeFilter::WifiSwitchThresholdQoeFilter() : SimpleWifiFilter("WifiSwitchThresholdQoeFilter") {}
 
WifiSwitchThresholdQoeFilter::~WifiSwitchThresholdQoeFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}
 
bool WifiSwitchThresholdQoeFilter::Filter(NetworkCandidate &networkCandidate)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    auto &interScanInfo = networkCandidate.interScanInfo;
 
    if (interScanInfo.rssi < linkedInfo.rssi) {
        WIFI_LOGI("WifiSwitchThresholdFilter, scan info rssi:%{public}d,"
            "cur rssi:%{public}d, skip candidate:%{public}s",
            interScanInfo.rssi, linkedInfo.rssi, networkCandidate.ToString().c_str());
        return false;
    }
 
    return true;
}

WifiSwitch5GNot2GFilter::WifiSwitch5GNot2GFilter() : SimpleWifiFilter("WifiSwitch5GNot2GFilter") {}
 
WifiSwitch5GNot2GFilter::~WifiSwitch5GNot2GFilter()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  filterName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}
 
bool WifiSwitch5GNot2GFilter::Filter(NetworkCandidate &networkCandidate)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    auto &interScanInfo = networkCandidate.interScanInfo;
 
    if (linkedInfo.band == static_cast<int>(BandType::BAND_5GHZ) &&
        interScanInfo.band == static_cast<int>(BandType::BAND_2GHZ)) {
        return false;
    }
 
    return true;
}
}