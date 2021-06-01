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
#include "sta_connectivity_manager.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_CONNECTIVITY_MANAGER"
namespace OHOS {
namespace Wifi {
StaConnectivityManager::StaConnectivityManager(StaStateMachine *staStateMachine)
    : pStaStateMachine(staStateMachine),
      pSavedNetworkEvaluator(nullptr),
      pScoredNetworkEvaluator(nullptr),
      pPasspointNetworkEvaluator(nullptr),
      pNetworkSelector(nullptr),
      pConnectivityHelper(nullptr)
{}
StaConnectivityManager::~StaConnectivityManager()
{
    LOGI("Enter StaConnectivityManager::~StaConnectivityManager.\n");
    if (pSavedNetworkEvaluator != nullptr) {
        delete pSavedNetworkEvaluator;
        pSavedNetworkEvaluator = nullptr;
    }
    if (pScoredNetworkEvaluator != nullptr) {
        delete pScoredNetworkEvaluator;
        pScoredNetworkEvaluator = nullptr;
    }
    if (pPasspointNetworkEvaluator != nullptr) {
        delete pPasspointNetworkEvaluator;
        pPasspointNetworkEvaluator = nullptr;
    }
    if (pNetworkSelector != nullptr) {
        delete pNetworkSelector;
        pNetworkSelector = nullptr;
    }
    if (pConnectivityHelper != nullptr) {
        delete pConnectivityHelper;
        pConnectivityHelper = nullptr;
    }
}

void StaConnectivityManager::OnScanResultsReadyHandler(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaConnectivityManager::OnScanResultsReadyHandler.\n");
    RefreshBssidBlocklist(); /* Refreshing the BSSID Blocklist */

    WifiLinkedInfo info;
    WifiSettings::GetInstance().GetLinkedInfo(info);
    if (info.supplicantState == SupplicantState::ASSOCIATING ||
        info.supplicantState == SupplicantState::AUTHENTICATING ||
        info.supplicantState == SupplicantState::FOUR_WAY_HANDSHAKE ||
        info.supplicantState == SupplicantState::GROUP_HANDSHAKE) {
        LOGE("Supplicant is under transient state.\n");
        return;
    }

    std::vector<std::string> blocklistedBssids;
    CreatBlocklist(blocklistedBssids);

    WifiDeviceConfig candidate;
    if (pNetworkSelector->SelectNetwork(candidate, scanResults, blocklistedBssids, info) == WIFI_OPT_SUCCESS) {
        LOGI("SelectNetwork succeed.\n");
        ConnectToNetwork(candidate);
    } else {
        LOGI("Exit network selection.\n");
        return;
    }
}

ErrCode StaConnectivityManager::InitConnectivityManager()
{
    LOGI("Enter StaConnectivityManager::InitConnectivityManager.\n");
    pConnectivityHelper = new (std::nothrow) StaConnectivityHelper();
    if (pConnectivityHelper == nullptr) {
        LOGE("pConnectivityHelper is null\n");
        return WIFI_OPT_FAILED;
    }

    if (pConnectivityHelper->ObtainingFirmwareRoamingInfo()) {
        LOGI("Succeeded in obtaining firmware roaming information.\n");
    }

    UpdateFirmwareRoamingConfig();

    pNetworkSelector = new (std::nothrow) StaNetworkSelector();
    if (pNetworkSelector == nullptr) {
        LOGE("pNetworkSelector is null\n");
        return WIFI_OPT_FAILED;
    }

    pSavedNetworkEvaluator = new (std::nothrow) StaSavedNetworkEvaluator(pConnectivityHelper);
    if (pSavedNetworkEvaluator == nullptr) {
        LOGE("savedNetworkEvaluator is null\n");
        return WIFI_OPT_FAILED;
    }

    pScoredNetworkEvaluator = new (std::nothrow) StaScoredNetworkEvaluator();
    if (pScoredNetworkEvaluator == nullptr) {
        LOGE("scoredNetworkEvaluator is null.\n");
        return WIFI_OPT_FAILED;
    }

    pPasspointNetworkEvaluator = new (std::nothrow) StaPasspointNetworkEvaluator();
    if (pPasspointNetworkEvaluator == nullptr) {
        LOGE("PasspointNetworkEvaluator is null.\n");
        return WIFI_OPT_FAILED;
    }

    int savedPriority = WifiSettings::GetInstance().GetsavedNetworkEvaluatorPriority();
    if (pNetworkSelector->RegisterNetworkEvaluator(pSavedNetworkEvaluator, savedPriority)) {
        LOGI("RegisterSavedNetworkEvaluator succeeded.\n");
    }

    int scoredPriority = WifiSettings::GetInstance().GetscoredNetworkEvaluatorPriority();
    if (pNetworkSelector->RegisterNetworkEvaluator(pScoredNetworkEvaluator, scoredPriority)) {
        LOGI("RegisterScoredNetworkEvaluator succeeded.\n");
    }

    int passpointPriority = WifiSettings::GetInstance().GetpasspointNetworkEvaluatorPriority();
    if (pNetworkSelector->RegisterNetworkEvaluator(pPasspointNetworkEvaluator, passpointPriority)) {
        LOGI("RegisterPasspointNetworkEvaluator succeeded.\n");
    }
    return WIFI_OPT_SUCCESS;
}

bool StaConnectivityManager::TrackBlockBssid(std::string bssid, bool enable, int reasonCode)
{
    LOGI("Enter StaConnectivityManager::TrackBlockBssid.\n");
    if (bssid.empty()) {
        LOGI("bssid is empty.\n");
        return false;
    }

    /* Updating the BSSID Blocklist */
    if (!UpdateBssidBlocklist(bssid, enable, reasonCode)) {
        LOGI("The blocklist is not updated.\n");
        return false;
    }

    /* The blocklist has been updated, so update the firmware roaming */
    /* configuration */
    UpdateFirmwareRoamingConfig();
    return true;
}

bool StaConnectivityManager::UpdateBssidBlocklist(std::string bssid, bool enable, int reasonCode)
{
    LOGI("Enter StaConnectivityManager::UpdateBssidBlocklist.\n");
    if (enable) {
        if (bssidBlocklist.count(bssid) != 0) {
            /* Removed the BSSID from the blocklist When the BSSID is enabled. */
            bssidBlocklist.erase(bssid);
            return true;
        }
        return false;
    }

    BssidBlocklistStatus status;
    auto iter = bssidBlocklist.find(bssid);
    if (iter == bssidBlocklist.end()) {
        bssidBlocklist.emplace(bssid, status);
    }
    auto iterator = bssidBlocklist.find(bssid);
    if (iterator == bssidBlocklist.end()) {
        return false;
    }
    iterator->second.counter++;
    time_t now = time(NULL);
    iterator->second.blocklistedTimeStamp = (int)now;
    if (!iterator->second.isBlocklisted) {
        if (iterator->second.counter >= BSSID_BLOCKLIST_THRESHOLD ||
            reasonCode == REASON_CODE_AP_UNABLE_TO_HANDLE_NEW_STA) {
            iterator->second.isBlocklisted = true;
            return true;
        }
    }
    return false;
}

void StaConnectivityManager::UpdateFirmwareRoamingConfig()
{
    LOGI("Enter StaConnectivityManager::UpdateFirmwareRoamingConfig.\n");
    if (!pConnectivityHelper->WhetherFirmwareRoamingIsSupported()) {
        return;
    }

    int maxBlocklistSize = pConnectivityHelper->GetMaxNumBssidBlocklist();
    if (maxBlocklistSize <= 0) {
        return;
    }
    std::vector<std::string> blocklistedBssids;
    CreatBlocklist(blocklistedBssids);

    if (static_cast<int>(blocklistedBssids.size()) > maxBlocklistSize) {
        blocklistedBssids.resize(maxBlocklistSize);
    }

    if (pConnectivityHelper->SetFirmwareRoamingConfig(blocklistedBssids)) {
        LOGE("Set firmware roaming configuration succeeded.\n");
    } else {
        LOGI("Set firmware roaming configuration failed.\n");
    }
    return;
}

void StaConnectivityManager::RefreshBssidBlocklist()
{
    LOGI("Enter StaConnectivityManager::RefreshBssidBlocklist.\n");
    if (bssidBlocklist.empty()) {
        return;
    }
    bool updated = false;
    for (auto iter = bssidBlocklist.begin(); iter != bssidBlocklist.end();) {
        BssidBlocklistStatus status = iter->second;
        time_t now = time(NULL);
        int currentTimeStap = (int)now;
        if (status.isBlocklisted &&
            ((currentTimeStap - status.blocklistedTimeStamp) >= BSSID_BLOCKLIST_EXPIRE_TIME_S)) {
            bssidBlocklist.erase(iter++);
            updated = true;
        } else {
            iter++;
        }
    }
    if (updated) {
        UpdateFirmwareRoamingConfig();
    }
    return;
}

void StaConnectivityManager::CreatBlocklist(std::vector<std::string> &blocklistedBssids)
{
    LOGI("Enter StaConnectivityManager::CreatBlocklist.\n");

    for (auto iter = bssidBlocklist.begin(); iter != bssidBlocklist.end(); ++iter) {
        blocklistedBssids.push_back(iter->first);
    }
    return;
}

void StaConnectivityManager::ConnectToNetwork(WifiDeviceConfig &candidate)
{
    LOGI("Enter StaConnectivityManager::ConnectToNetwork.\n");
    if (candidate.bssid.empty()) {
        LOGE("candidate is null.\n");
        return;
    }

    WifiLinkedInfo currentConnectedNetwork;
    WifiSettings::GetInstance().GetLinkedInfo(currentConnectedNetwork);
    if (currentConnectedNetwork.connState == ConnState::CONNECTED && candidate.networkId == INVALID_NETWORK_ID &&
        currentConnectedNetwork.ssid == candidate.ssid && currentConnectedNetwork.bssid != candidate.bssid) {
        /* Frameworks start roaming only when firmware is not supported */
        if (!pConnectivityHelper->WhetherFirmwareRoamingIsSupported()) {
            LOGI("Roaming connectTo.\n");
            pStaStateMachine->StartRoamToNetwork(candidate.bssid);
            LOGI("connecTo network bssid is %s", candidate.bssid.c_str());
        }
    } else if (currentConnectedNetwork.detailedState == DetailedState::DISCONNECTED) {
        LOGI("connecTo save network.\n");
        pStaStateMachine->SendMessage(
            WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, candidate.networkId, NETWORK_SELECTED_FOR_CONNECTION_MANAGEMENT);
        LOGI("connecTo networkId is %{public}d", candidate.networkId);
        LOGI("connecTo bssid is %s", candidate.bssid.c_str());
        LOGI("connecTo preShareKey is %s", candidate.preSharedKey.c_str());
    } else {
        LOGE("The current connection status is %{public}d.\n", currentConnectedNetwork.detailedState);
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS