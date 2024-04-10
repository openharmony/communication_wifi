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
#include "sta_auto_connect_service.h"
#include "wifi_logger.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_settings.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("StaAutoConnectService");

namespace OHOS {
namespace Wifi {
StaAutoConnectService::StaAutoConnectService(StaStateMachine *staStateMachine, int instId)
    : pStaStateMachine(staStateMachine),
      pSavedDeviceAppraisal(nullptr),
      firmwareRoamFlag(true),
      maxBlockedBssidNum(BLOCKLIST_INVALID_SIZE),
      selectDeviceLastTime(0),
      pAppraisals {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr},
      m_instId(instId)
{}

StaAutoConnectService::~StaAutoConnectService()
{
    WIFI_LOGI("Enter ~StaAutoConnectService.\n");
    if (pSavedDeviceAppraisal != nullptr) {
        delete pSavedDeviceAppraisal;
        pSavedDeviceAppraisal = nullptr;
    }
}

ErrCode StaAutoConnectService::InitAutoConnectService()
{
    WIFI_LOGI("Enter InitAutoConnectService.\n");

    if (ObtainRoamCapFromFirmware()) {
        WIFI_LOGI("Succeeded in obtaining firmware roaming information.\n");
    }
    SyncBlockedSsidFirmware();

    pSavedDeviceAppraisal = new (std::nothrow) StaSavedDeviceAppraisal(firmwareRoamFlag);
    if (pSavedDeviceAppraisal == nullptr) {
        WIFI_LOGE("savedDeviceAppraisal is null\n");
        return WIFI_OPT_FAILED;
    }
    pNetworkSelectionManager = std::make_unique<NetworkSelectionManager>();
    int savedPriority = WifiSettings::GetInstance().GetSavedDeviceAppraisalPriority(m_instId);
    if (RegisterDeviceAppraisal(pSavedDeviceAppraisal, savedPriority)) {
        WIFI_LOGI("RegisterSavedDeviceAppraisal succeeded.\n");
    }
    return WIFI_OPT_SUCCESS;
}

void StaAutoConnectService::OnScanInfosReadyHandler(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter OnScanInfosReadyHandler.\n");
    ClearOvertimeBlockedBssid(); /* Refreshing the BSSID Blocklist */

    WifiLinkedInfo info;
    WifiSettings::GetInstance().GetLinkedInfo(info, m_instId);
    if (info.supplicantState == SupplicantState::ASSOCIATING ||
        info.supplicantState == SupplicantState::AUTHENTICATING ||
        info.supplicantState == SupplicantState::FOUR_WAY_HANDSHAKE ||
        info.supplicantState == SupplicantState::GROUP_HANDSHAKE) {
        WIFI_LOGE("Supplicant is under transient state.\n");
        return;
    }

    if (info.connState == ConnState::CONNECTED) {
        ClearAllBlockedBssids();
    }
    std::vector<std::string> blockedBssids;
    GetBlockedBssids(blockedBssids);
    if (!AllowAutoSelectDevice(info) || !IsAllowAutoJoin()) {
        return;
    }
    NetworkSelectionResult networkSelectionResult;
    if (pNetworkSelectionManager->SelectNetwork(networkSelectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos)) {
        int networkId = networkSelectionResult.wifiDeviceConfig.networkId;
        std::string &bssid = networkSelectionResult.interScanInfo.bssid;
        std::string &ssid = networkSelectionResult.interScanInfo.ssid;
        WIFI_LOGI("AutoSelectDevice networkId: %{public}d, ssid: %{public}s, bssid: %{public}s.", networkId,
                  SsidAnonymize(ssid).c_str(), MacAnonymize(bssid).c_str());
        auto message = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK);
        message->SetParam1(networkId);
        message->SetParam2(NETWORK_SELECTED_BY_AUTO);
        message->AddStringMessageBody(bssid);
        pStaStateMachine->SendMessage(message);
    } else {
        WIFI_LOGI("AutoSelectDevice return fail.");
        return;
    }
}

bool StaAutoConnectService::EnableOrDisableBssid(std::string bssid, bool enable, int reason)
{
    WIFI_LOGI("Enter EnableOrDisableBssid.\n");
    if (bssid.empty()) {
        WIFI_LOGI("bssid is empty.\n");
        return false;
    }

    /* Updating the BSSID Blocklist */
    if (!AddOrDelBlockedBssids(bssid, enable, reason)) {
        WIFI_LOGI("The blocklist is not updated.\n");
        return false;
    }

    /* The blocklist has been updated, so update the firmware roaming */
    /* configuration */
    SyncBlockedSsidFirmware();
    return true;
}

bool StaAutoConnectService::AddOrDelBlockedBssids(std::string bssid, bool enable, int reason)
{
    std::lock_guard<std::mutex> lock(m_blockBssidMapMutex);
    WIFI_LOGI("Enter AddOrDelBlockedBssids.\n");
    if (enable) {
        if (blockedBssidMap.count(bssid) != 0) {
            /* Removed the BSSID from the blocklist When the BSSID is enabled. */
            blockedBssidMap.erase(bssid);
            return true;
        }
        return false;
    }

    BlockedBssidInfo status;
    auto iter = blockedBssidMap.find(bssid);
    if (iter == blockedBssidMap.end()) {
        blockedBssidMap.emplace(bssid, status);
    }
    auto iterator = blockedBssidMap.find(bssid);
    if (iterator == blockedBssidMap.end()) {
        return false;
    }
    iterator->second.count++;
    time_t now = time(0);
    iterator->second.blockedTime = (int)now;
    if (!iterator->second.blockedFlag) {
        if (iterator->second.count >= MAX_BSSID_BLOCKLIST_COUNT ||
            reason == AP_CANNOT_HANDLE_NEW_STA) {
            iterator->second.blockedFlag = true;
            return true;
        }
    }
    return false;
}

void StaAutoConnectService::GetBlockedBssids(std::vector<std::string> &blockedBssids)
{
    std::lock_guard<std::mutex> lock(m_blockBssidMapMutex);
    for (auto iter = blockedBssidMap.begin(); iter != blockedBssidMap.end(); ++iter) {
        blockedBssids.push_back(iter->first);
    }
    WIFI_LOGD("GetBlockedBssids, blockedBssids count: %{public}d.", (int)blockedBssids.size());
    return;
}

void StaAutoConnectService::ClearAllBlockedBssids()
{
    std::lock_guard<std::mutex> lock(m_blockBssidMapMutex);
    WIFI_LOGI("Enter ClearAllBlockedBssids.\n");
    blockedBssidMap.clear();
    return;
}

void StaAutoConnectService::ClearOvertimeBlockedBssid()
{
    std::lock_guard<std::mutex> lock(m_blockBssidMapMutex);
    WIFI_LOGI("Enter ClearOvertimeBlockedBssid.\n");
    if (blockedBssidMap.empty()) {
        WIFI_LOGI("blockedBssidMap is empty !\n");
        return;
    }
    bool updated = false;
    auto iter = blockedBssidMap.begin();
    while (iter != blockedBssidMap.end()) {
        BlockedBssidInfo status = iter->second;
        time_t now = time(0);
        int currentTimeStap = (int)now;
        WIFI_LOGI("blockedFlag:%{public}d, currentTimeStap:%{public}d, blockedTime:%{public}d.\n",
            status.blockedFlag, currentTimeStap, status.blockedTime);
        if (status.blockedFlag && ((currentTimeStap - status.blockedTime) >= MAX_BSSID_BLOCKLIST_TIME)) {
            blockedBssidMap.erase(iter++);
            updated = true;
        } else {
            ++iter;
        }
    }
    if (updated) {
        SyncBlockedSsidFirmware();
    }
    return;
}

void StaAutoConnectService::ConnectElectedDevice(WifiDeviceConfig &electedDevice)
{
    WIFI_LOGI("Enter ConnectElectedDevice.\n");
    if (electedDevice.bssid.empty()) {
        WIFI_LOGE("electedDevice bssid is empty.");
        return;
    }

    WifiLinkedInfo currentConnectedNetwork;
    WifiSettings::GetInstance().GetLinkedInfo(currentConnectedNetwork, m_instId);
    if (currentConnectedNetwork.connState == ConnState::CONNECTED && electedDevice.networkId == INVALID_NETWORK_ID &&
        currentConnectedNetwork.ssid == electedDevice.ssid && currentConnectedNetwork.bssid != electedDevice.bssid) {
        /* Frameworks start roaming only when firmware is not supported */
        if (!firmwareRoamFlag) {
            WIFI_LOGI("Roaming connectTo, networkId: %{public}d.\n", electedDevice.networkId);
            pStaStateMachine->StartRoamToNetwork(electedDevice.bssid);
        }
    } else if (currentConnectedNetwork.detailedState == DetailedState::DISCONNECTED ||
        currentConnectedNetwork.detailedState == DetailedState::CONNECTION_TIMEOUT ||
        currentConnectedNetwork.detailedState == DetailedState::FAILED ||
        currentConnectedNetwork.detailedState == DetailedState::PASSWORD_ERROR ||
        currentConnectedNetwork.detailedState == DetailedState::CONNECTION_FULL ||
        currentConnectedNetwork.detailedState == DetailedState::CONNECTION_REJECT) {
        pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK,
            electedDevice.networkId,
            NETWORK_SELECTED_BY_AUTO);
        WIFI_LOGI("connectTo save networkId: %{public}d, preShareKey len: %{public}d.\n",
            electedDevice.networkId, (int)electedDevice.preSharedKey.length());
    } else {
        WIFI_LOGE("The current connection status is %{public}d.\n", currentConnectedNetwork.detailedState);
    }
    return;
}

void StaAutoConnectService::SyncBlockedSsidFirmware()
{
    WIFI_LOGI("Enter SyncBlockedSsidFirmware.\n");
    if (!firmwareRoamFlag) {
        return;
    }
    if (maxBlockedBssidNum <= 0) {
        return;
    }
    std::vector<std::string> blockedBssids;
    GetBlockedBssids(blockedBssids);

    if (static_cast<int>(blockedBssids.size()) > maxBlockedBssidNum) {
        blockedBssids.resize(maxBlockedBssidNum);
    }

    if (SetRoamBlockedBssidFirmware(blockedBssids)) {
        WIFI_LOGE("Set firmware roaming configuration succeeded.\n");
    } else {
        WIFI_LOGI("Set firmware roaming configuration failed.\n");
    }
    return;
}

bool StaAutoConnectService::ObtainRoamCapFromFirmware()
{
    WIFI_LOGI("Enter ObtainRoamCapFromFirmware.\n");

    unsigned int capabilities;
    if (WifiStaHalInterface::GetInstance().GetStaCapabilities(capabilities) == WIFI_IDL_OPT_OK) {
        if ((capabilities & STA_CAP_ROAMING) == 0) {
            WIFI_LOGE("Firmware roaming is not supported.\n");
            return false;
        }
    }

    WifiIdlRoamCapability capability;
    if (WifiStaHalInterface::GetInstance().GetRoamingCapabilities(capability) == WIFI_IDL_OPT_OK) {
        if (capability.maxBlocklistSize > 0) {
            firmwareRoamFlag = true;
            maxBlockedBssidNum = capability.maxBlocklistSize;
            WIFI_LOGI("Get firmware roaming capabilities succeeded.\n");
            return true;
        }
        WIFI_LOGE("Invalid firmware roaming capabilities.\n");
    }

    WIFI_LOGE("Get firmware roaming capabilities failed.\n");
    return false;
}

bool StaAutoConnectService::SetRoamBlockedBssidFirmware(const std::vector<std::string> &blocklistBssids) const
{
    WIFI_LOGI("Enter SetRoamBlockedBssidFirmware.\n");
    if (!firmwareRoamFlag) {
        return false;
    }

    if (blocklistBssids.empty()) {
        return false;
    }

    if (static_cast<int>(blocklistBssids.size()) > maxBlockedBssidNum) {
        return false;
    }

    WifiIdlRoamConfig capability;
    capability.blocklistBssids = blocklistBssids;
    if (WifiStaHalInterface::GetInstance().SetRoamConfig(capability) == WIFI_IDL_OPT_OK) {
        return true;
    }
    return false;
}

bool StaAutoConnectService::RegisterDeviceAppraisal(StaDeviceAppraisal *appraisal, int priority)
{
    WIFI_LOGI("Enter RegisterDeviceAppraisal.\n");
    if (priority < 0 || priority >= MIN_APPRAISAL_PRIORITY) {
        WIFI_LOGE("Out of array range.\n");
        return false;
    }
    if (pAppraisals[priority] != nullptr) {
        WIFI_LOGE("Appraisals is not empty.\n");
        return false;
    }
    pAppraisals[priority] = appraisal;
    return true;
}

ErrCode StaAutoConnectService::AutoSelectDevice(WifiDeviceConfig &electedDevice,
    const std::vector<InterScanInfo> &scanInfos, std::vector<std::string> &blockedBssids, WifiLinkedInfo &info)
{
    WIFI_LOGI("Enter SelectNetwork.\n");
    if (scanInfos.empty()) {
        WIFI_LOGE("scanInfo is empty.");
        return WIFI_OPT_FAILED;
    }

    /* Whether network selection handover is required */
    if (!AllowAutoSelectDevice(scanInfos, info)) {
        WIFI_LOGE("Network switching is not required.\n");
        return WIFI_OPT_FAILED;
    }

    std::vector<InterScanInfo> availableScanInfos;
    /* Filter out unnecessary networks. */
    GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
    if (availableScanInfos.empty()) {
        WIFI_LOGE("No scanInfo available.\n");
        return WIFI_OPT_FAILED;
    }
    /*
     * Check the registered network appraisal from highest priority to lowest
     * priority until the selected network
     */
    for (auto registeredAppraisal : pAppraisals) {
        if (registeredAppraisal != nullptr) {
            ErrCode code = registeredAppraisal->DeviceAppraisals(electedDevice, availableScanInfos, info);
            if (code == WIFI_OPT_SUCCESS) {
                time_t now = time(0);
                selectDeviceLastTime = static_cast<int>(now);
                WIFI_LOGI("electedDevice generation.\n");
                return WIFI_OPT_SUCCESS;
            }
        }
    }

    if (RoamingSelection(electedDevice, availableScanInfos, info)) {
        WIFI_LOGI("Roaming network generation.\n");
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGE("No electedDevice.\n");
    return WIFI_OPT_FAILED;
}

bool StaAutoConnectService::RoamingSelection(
    WifiDeviceConfig &electedDevice, std::vector<InterScanInfo> &availableScanInfos, WifiLinkedInfo &info)
{
    for (auto scanInfo : availableScanInfos) {
        if (info.connState == ConnState::CONNECTED && scanInfo.ssid == info.ssid && scanInfo.bssid != info.bssid) {
            WIFI_LOGD("Discover roaming networks.\n");
            if (RoamingEncryptionModeCheck(electedDevice, scanInfo, info)) {
                return true;
            }
        }
    }
    return false;
}

bool StaAutoConnectService::RoamingEncryptionModeCheck(
    WifiDeviceConfig &electedDevice, InterScanInfo scanInfo, WifiLinkedInfo &info)
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
                WIFI_LOGE("The roaming network is a WEP network, but the connected network is not a WEP network.\n");
                return false;
            } else if (mgmt.find("WEP") == std::string::npos && network.wepTxKeyIndex != 0) {
                WIFI_LOGE("The connected network is a WEP network, but the roaming network is not a WEP network.\n");
                return false;
            }
            mgmt = "NONE";
        }
        if (mgmt == network.keyMgmt) {
            WIFI_LOGD("The Current network bssid %{public}s signal strength is %{public}d",
                MacAnonymize(info.bssid).c_str(), info.rssi);
            WIFI_LOGD("The Roaming network bssid %{public}s signal strength is %{public}d",
                MacAnonymize(scanInfo.bssid).c_str(), scanInfo.rssi);
            int rssi = scanInfo.rssi - info.rssi;
            if (rssi > MIN_ROAM_RSSI_DIFF) {
                WIFI_LOGD("Roming network rssi - Current network rssi > 6.");
                electedDevice.ssid = scanInfo.ssid;
                electedDevice.bssid = scanInfo.bssid;
                return true;
            } else {
                WIFI_LOGD("Roming network rssi - Current network rssi < 6.");
            }
        } else {
            WIFI_LOGE("The encryption mode does not match.\n");
        }
    }
    return false;
}

bool StaAutoConnectService::AllowAutoSelectDevice(OHOS::Wifi::WifiLinkedInfo &info)
{
    if (info.connState == DISCONNECTED || info.connState == UNKNOWN) {
        return true;
    }
    WIFI_LOGI("Current linkInfo is not in DISCONNECTED state, skip network selection.");
    return false;
}

bool StaAutoConnectService::AllowAutoSelectDevice(const std::vector<InterScanInfo> &scanInfos, WifiLinkedInfo &info)
{
    WIFI_LOGI("Allow auto select device, connState=%{public}d, detailedState=%{public}d\n",
        info.connState, info.detailedState);
    if (scanInfos.empty()) {
        WIFI_LOGE("No network,skip network selection.\n");
        return false;
    }

    switch (info.detailedState) {
        case DetailedState::WORKING:
            /* Configure whether to automatically switch the network. */
            if (!WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover(m_instId)) {
                WIFI_LOGE("Automatic network switching is not allowed in user configuration.\n");
                return false;
            }
            /* Indicates whether the minimum interval is the minimum interval since the last network selection. */
            if (selectDeviceLastTime != 0) {
                int gap = static_cast<int>(time(0)) - selectDeviceLastTime;
                if (gap < MIN_SELECT_NETWORK_TIME) {
                    WIFI_LOGE("%ds time before we selected the network(30s).\n", gap);
                    return false;
                }
            }

            if (!CurrentDeviceGoodEnough(scanInfos, info)) {
                WIFI_LOGI("The current network is insuffice.\n");
                return true;
            }
            return false;

        case DetailedState::DISCONNECTED:
        case DetailedState::CONNECTION_TIMEOUT:
        case DetailedState::FAILED:
        case DetailedState::CONNECTION_REJECT:
        case DetailedState::CONNECTION_FULL:
            WIFI_LOGI("Auto Select is allowed, detailedState: %{public}d\n", info.detailedState);
            return true;
        case DetailedState::PASSWORD_ERROR:
            WIFI_LOGI("Password error, clear blocked bssids, auto connect to ap quickly.\n");
            ClearAllBlockedBssids();
            return true;

        case DetailedState::NOTWORKING:
            WIFI_LOGI("The current network cannot access the Internet.\n");
            /* Configure whether to automatically switch the network. */
            if (!WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover(m_instId)) {
                WIFI_LOGE("Automatic network switching is not allowed in user configuration.\n");
                return false;
            }
            return true;

        default:
            WIFI_LOGE("not allowed auto select!\n");
            return false;
    }
    return false;
}

bool StaAutoConnectService::CurrentDeviceGoodEnough(const std::vector<InterScanInfo> &scanInfos, WifiLinkedInfo &info)
{
    WIFI_LOGI("Enter CurrentDeviceGoodEnough.\n");

    WifiDeviceConfig network;

    /* The network is deleted */
    if (WifiSettings::GetInstance().GetDeviceConfig(info.networkId, network) == -1) {
        WIFI_LOGE("The network is deleted.\n");
        return false;
    }

    int userLastSelectedNetworkId = WifiSettings::GetInstance().GetUserLastSelectedNetworkId(m_instId);
    if (userLastSelectedNetworkId != INVALID_NETWORK_ID && userLastSelectedNetworkId == network.networkId) {
        time_t userLastSelectedNetworkTimeVal = WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal(m_instId);
        time_t now = time(0);
        int interval = static_cast<int>(now - userLastSelectedNetworkTimeVal);
        if (interval <= TIME_FROM_LAST_SELECTION) {
            WIFI_LOGI("(60s)Current user recent selections time is %ds.\n", interval);
            return true;
        }
    }

    /* Temporary network unqualified */
    if (network.isEphemeral) {
        WIFI_LOGE("The network is isEphemeral.\n");
        return false;
    }

    if (network.keyMgmt == "NONE" || network.keyMgmt.size() == 0) {
        WIFI_LOGE("This network No keyMgmt.\n");
        return false;
    }

    /* The signal strength on the live network does not meet requirements. */
    if (info.rssi < RSSI_DELIMITING_VALUE) {
        WIFI_LOGE("Signal strength insuffice %{public}d < -65.\n", info.rssi);
        return false;
    }
    /*
     * The network is a 2.4 GHz network and is not qualified when the 5G network
     * is available.
     */
    if (Whether24GDevice(info.frequency)) {
        if (WhetherDevice5GAvailable(scanInfos)) {
            WIFI_LOGE("5 GHz is available when the current frequency band is 2.4 GHz.\n");
            return false;
        }
    }
    return true;
}

bool StaAutoConnectService::WhetherDevice5GAvailable(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter WhetherDevice5GAvailable.\n");
    for (auto scaninfo : scanInfos) {
        if (Whether5GDevice(scaninfo.frequency)) {
            return true;
        }
    }
    return false;
}

bool StaAutoConnectService::Whether24GDevice(int frequency)
{
    if (frequency > MIN_24_FREQUENCY && frequency < MAX_24_FREQUENCY) {
        return true;
    } else {
        return false;
    }
}

bool StaAutoConnectService::Whether5GDevice(int frequency)
{
    if (frequency > MIN_5_FREQUENCY && frequency < MAX_5_FREQUENCY) {
        return true;
    } else {
        return false;
    }
}

void StaAutoConnectService::GetAvailableScanInfos(std::vector<InterScanInfo> &availableScanInfos,
    const std::vector<InterScanInfo> &scanInfos, std::vector<std::string> &blockedBssids, WifiLinkedInfo &info)
{
    WIFI_LOGI("Enter GetAvailableScanInfos.\n");
    if (scanInfos.empty()) {
        return;
    }
    bool scanInfosContainCurrentBssid = false;

    for (auto scanInfo : scanInfos) {
        if (scanInfo.ssid.size() == 0) {
            continue;
        }

        /* Check whether the scanning result contains the current BSSID. */
        if (info.connState == ConnState::CONNECTED && scanInfo.bssid == info.bssid) {
            scanInfosContainCurrentBssid = true;
        }

        auto itr = find(blockedBssids.begin(), blockedBssids.end(), scanInfo.bssid);
        if (itr != blockedBssids.end()) { /* Skip Blocklist Network */
            WIFI_LOGD("Skip blocklistedBssid network, ssid: %{public}s.\n", SsidAnonymize(scanInfo.ssid).c_str());
            continue;
        }

        /* Skipping networks with weak signals */
        if (scanInfo.frequency < MIN_5GHZ_BAND_FREQUENCY) {
            if (scanInfo.rssi <= MIN_RSSI_VALUE_24G) {
                WIFI_LOGD("Skip network %{public}s with low 2.4G signals %{public}d.\n",
                    SsidAnonymize(scanInfo.ssid).c_str(), scanInfo.rssi);
                continue;
            }
        } else {
            if (scanInfo.rssi <= MIN_RSSI_VALUE_5G) {
                WIFI_LOGD("Skip network %{public}s with low 5G signals %{public}d.\n",
                    SsidAnonymize(scanInfo.ssid).c_str(), scanInfo.rssi);
                continue;
            }
        }
        availableScanInfos.push_back(scanInfo);
    }
    /*
     * Some scan requests may not include channels for the currently connected
     * network, so the currently connected network will not appear in the scan
     * results. We will not act on these scans to avoid network switching that may
     * trigger disconnections.
     */
    if (info.connState == ConnState::CONNECTED && !scanInfosContainCurrentBssid) {
        WIFI_LOGI("scanInfo is be cleared.\n");
        availableScanInfos.clear();
    }
    return;
}

void StaAutoConnectService::DisableAutoJoin(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(autoJoinMutex);
    WIFI_LOGI("Auto Join is disabled by %{public}s.", conditionName.c_str());
    autoJoinConditionsMap.insert_or_assign(conditionName, []() { return false; });
}

void StaAutoConnectService::EnableAutoJoin(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(autoJoinMutex);
    WIFI_LOGI("Auto Join disabled by %{public}s is released.", conditionName.c_str());
    autoJoinConditionsMap.erase(conditionName);
}

void StaAutoConnectService::RegisterAutoJoinCondition(const std::string &conditionName,
                                                      const std::function<bool()> &autoJoinCondition)
{
    if (!autoJoinCondition) {
        WIFI_LOGE("the condition of %{public}s is empty.", conditionName.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(autoJoinMutex);
    WIFI_LOGI("Auto Join condition of %{public}s is registered.", conditionName.c_str());
    autoJoinConditionsMap.insert_or_assign(conditionName, autoJoinCondition);
}

void StaAutoConnectService::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(autoJoinMutex);
    WIFI_LOGI("Auto Join condition of %{public}s is deregistered.", conditionName.c_str());
    autoJoinConditionsMap.erase(conditionName);
}

bool StaAutoConnectService::IsAllowAutoJoin()
{
    std::lock_guard<std::mutex> lock(autoJoinMutex);
    for (auto condition = autoJoinConditionsMap.rbegin(); condition != autoJoinConditionsMap.rend(); ++condition) {
        if (!condition->second.operator()()) {
            WIFI_LOGI("Auto Join is not allowed because of %{public}s.", condition->first.c_str());
            return false;
        }
    }
    return true;
}
}  // namespace Wifi
}  // namespace OHOS
