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

#include "wifi_settings.h"
#include "define.h"
#include "wifi_cert_utils.h"
#include "wifi_global_func.h"
#include "wifi_log.h"
#include "wifi_config_country_freqs.h"
#include "mac_address.h"
#ifndef OHOS_ARCH_LITE
#include <sys/sendfile.h>
#include "wifi_country_code_define.h"
#include "network_parser.h"
#include "softap_parser.h"
#include "package_parser.h"
#include "wifi_backup_config.h"
#include "json/json.h"
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
#include "wifi_asset_manager.h"
#endif
#ifdef INIT_LIB_ENABLE
#include "parameter.h"
#endif
#if defined(FEATURE_ENCRYPTION_SUPPORT) || defined(SUPPORT_LOCAL_RANDOM_MAC)
#include "wifi_encryption_util.h"
#endif
#include "wifi_config_center.h"

namespace OHOS {
namespace Wifi {
#ifdef DTFUZZ_TEST
static WifiSettings* gWifiSettings = nullptr;
#endif

WifiSettings &WifiSettings::GetInstance()
{
#ifndef DTFUZZ_TEST
    static WifiSettings gWifiSettings;
    return gWifiSettings;
#else
    if (gWifiSettings == nullptr) {
        gWifiSettings = new (std::nothrow) WifiSettings();
    }
    return *gWifiSettings;
#endif
}

WifiSettings::WifiSettings()
    : mNetworkId(0),
      mApMaxConnNum(MAX_AP_CONN),
      mMaxNumConfigs(MAX_CONFIGS_NUM)
{
}

WifiSettings::~WifiSettings()
{
    SyncDeviceConfig();
    SyncHotspotConfig();
    {
        std::unique_lock<std::mutex> lock(mApMutex);
        SyncBlockList();
    }
    SyncWifiP2pGroupInfoConfig();
    SyncP2pVendorConfig();
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    SyncWifiConfig();
}

int WifiSettings::Init()
{
    /* read ini config */
    mSavedDeviceConfig.SetConfigFilePath(DEVICE_CONFIG_FILE_PATH);
    mSavedHotspotConfig.SetConfigFilePath(HOTSPOT_CONFIG_FILE_PATH);
    mSavedBlockInfo.SetConfigFilePath(BLOCK_LIST_FILE_PATH);
    mSavedWifiConfig.SetConfigFilePath(WIFI_CONFIG_FILE_PATH);
    mSavedWifiP2pGroupInfo.SetConfigFilePath(WIFI_P2P_GROUP_INFO_FILE_PATH);
    mSavedWifiP2pVendorConfig.SetConfigFilePath(WIFI_P2P_VENDOR_CONFIG_FILE_PATH);
    mTrustListPolicies.SetConfigFilePath(WIFI_TRUST_LIST_POLICY_FILE_PATH);
    mMovingFreezePolicy.SetConfigFilePath(WIFI_MOVING_FREEZE_POLICY_FILE_PATH);
    mSavedWifiStoreRandomMac.SetConfigFilePath(WIFI_STA_RANDOM_MAC_FILE_PATH);
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    wifiMdmRestrictedListConfig_.SetConfigFilePath(WIFI_MDM_RESTRICTED_LIST);
#endif
#ifndef OHOS_ARCH_LITE
    MergeWifiConfig();
    MergeSoftapConfig();
#endif
#if defined(FEATURE_ENCRYPTION_SUPPORT) || defined(SUPPORT_LOCAL_RANDOM_MAC)
    SetUpHks();
#endif
    InitWifiConfig();
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    InitWifiMdmRestrictedListConfig();
#endif
    ReloadDeviceConfig();
    InitHotspotConfig();
    InitP2pVendorConfig();
    ReloadWifiP2pGroupInfoConfig();
    ReloadTrustListPolicies();
    ReloadMovingFreezePolicy();
    ReloadStaRandomMac();
    InitPackageInfoConfig();
    IncreaseNumRebootsSinceLastUse();
    return 0;
}

int WifiSettings::AddDeviceConfig(const WifiDeviceConfig &config)
{
    if (config.ssid.empty() || (config.keyMgmt == KEY_MGMT_WPA_PSK && config.preSharedKey.length() == 0)) {
        LOGE("AddDeviceConfig fail, networkId:%{public}d, keyMgmt:%{public}s",
            config.networkId, config.keyMgmt.c_str());
        return -1;
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(config.networkId);
    if (iter != mWifiDeviceConfig.end()) {
#ifdef SUPPORT_ClOUD_WIFI_ASSET
        if (WifiAssetManager::GetInstance().IsWifiConfigChanged(config, iter->second)) {
            WifiAssetManager::GetInstance().WifiAssetUpdate(config);
        }
#endif
        iter->second = config;
    } else {
        mWifiDeviceConfig.emplace(std::make_pair(config.networkId, config));
#ifdef SUPPORT_ClOUD_WIFI_ASSET
        WifiAssetManager::GetInstance().WifiAssetAdd(config, USER_ID_DEFAULT, false);
#endif
        std::vector<WifiDeviceConfig> tempConfigs;
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            tempConfigs.push_back(iter->second);
        }
        std::vector<WifiDeviceConfig> removedConfigs = RemoveExcessDeviceConfigs(tempConfigs);
        for (auto iter = removedConfigs.begin(); iter != removedConfigs.end(); iter++) {
            mWifiDeviceConfig.erase(iter->networkId);
        }
    }
    return config.networkId;
}

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
ErrCode WifiSettings::AddWifiRestrictedListConfig(int uid, const WifiRestrictedInfo& wifiListInfo)
{
    if ((wifiListInfo.ssid.empty() && wifiListInfo.wifiRestrictedType == MDM_BLOCKLIST) ||
    (wifiListInfo.wifiRestrictedType == MDM_WHITELIST && (wifiListInfo.bssid.empty() || wifiListInfo.ssid.empty()))) {
        return WIFI_OPT_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (wifiRestrictedList_.size() > WIFI_MDM_RESTRICTED_MAX_NUM) {
        LOGE("Add WifiRestrictedInfo exceeding the maximum value!");
        return WIFI_OPT_MDM_WHITELIST_OUT_MAX_NUM;
    }
    wifiRestrictedList_.push_back(wifiListInfo);
    return WIFI_OPT_SUCCESS;
}

int WifiSettings::GetMdmRestrictedBlockDeviceConfig(std::vector<WifiDeviceConfig> &results, int instId)
{
    LOGI("Enter GetMdmRestrictedBlockDeviceConfig");
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::map<std::string, std::string> blockSsids;
    std::map<std::string, std::string> blockBssids;
    std::map<std::string, WifiRestrictedInfo> whiteBlocks;
    for (size_t i = 0; i < wifiRestrictedList_.size(); i++) {
        if (wifiRestrictedList_[i].wifiRestrictedType == MDM_BLOCKLIST) {
            if (!wifiRestrictedList_[i].ssid.empty()) {
                blockSsids.emplace(wifiRestrictedList_[i].ssid, wifiRestrictedList_[i].ssid);
            }
            if (!wifiRestrictedList_[i].bssid.empty()) {
                blockBssids.emplace(wifiRestrictedList_[i].bssid, wifiRestrictedList_[i].bssid);
            }
        }
        if (wifiRestrictedList_[i].wifiRestrictedType == MDM_WHITELIST) {
            whiteBlocks.emplace(wifiRestrictedList_[i].ssid + wifiRestrictedList_[i].bssid, wifiRestrictedList_[i]);
        }
    }
    if (blockSsids.size() <= 0 && blockBssids.size() <= 0 && whiteBlocks.size() <= 0) {
        return 0;
    }
    
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.instanceId == instId && ((blockSsids.find(iter->second.ssid) != blockSsids.end() ||
            blockBssids.find(iter->second.bssid) != blockBssids.end()) ||
            whiteBlocks.find(iter->second.ssid + iter->second.bssid) == whiteBlocks.end())) {
            results.push_back(iter->second);
        }
    }
    return 0;
}

ErrCode WifiSettings::CheckWifiMdmRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList)
{
    if (wifiRestrictedInfoList.size() > WIFI_MDM_RESTRICTED_MAX_NUM) {
        LOGE("Add WifiRestrictedInfo exceeding the maximum value!");
        return WIFI_OPT_MDM_BLOCKLIST_OUT_MAX_NUM;
    }
    ErrCode code = WIFI_OPT_SUCCESS;
    for (size_t i = 0; i < wifiRestrictedInfoList.size(); i++) {
        if ((wifiRestrictedInfoList[i].ssid.empty() && wifiRestrictedInfoList[i].wifiRestrictedType == MDM_BLOCKLIST) ||
        (wifiRestrictedInfoList[i].wifiRestrictedType == MDM_WHITELIST &&
        (wifiRestrictedInfoList[i].ssid.empty() || wifiRestrictedInfoList[i].bssid.empty()))) {
            code = WIFI_OPT_INVALID_PARAM;
            break;
        }
    }
    return code;
}
 
ErrCode WifiSettings::ClearWifiRestrictedListConfig(int uid)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    LOGI("Clear wifi Restricted List ");
    wifiRestrictedList_.clear();
    return WIFI_OPT_SUCCESS;
}
 
bool WifiSettings::FindWifiBlockListConfig(const std::string &ssid, const std::string &bssid, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (size_t i = 0; i < wifiRestrictedList_.size(); i++) {
        if (wifiRestrictedList_[i].wifiRestrictedType == MDM_BLOCKLIST &&
            (wifiRestrictedList_[i].ssid == ssid ||
            (!wifiRestrictedList_[i].bssid.empty() && wifiRestrictedList_[i].bssid == bssid))) {
            LOGI("find wifi block list info successful!");
            return true;
        }
    }
    return false;
}
 
bool WifiSettings::WhetherSetWhiteListConfig()
{
    bool setWhiteList = false;
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (size_t i = 0; i < wifiRestrictedList_.size(); i++) {
        if (wifiRestrictedList_[i].wifiRestrictedType == MDM_WHITELIST) {
            setWhiteList = true;
            break;
        }
    }
    return setWhiteList;
}
 
bool WifiSettings::FindWifiWhiteListConfig(const std::string &ssid,
    const std::string &bssid, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (size_t i = 0; i < wifiRestrictedList_.size(); i++) {
        if (wifiRestrictedList_[i].wifiRestrictedType == MDM_WHITELIST && wifiRestrictedList_[i].ssid == ssid &&
            wifiRestrictedList_[i].bssid == bssid) {
            LOGI("find wifi white list info successful!");
            return true;
        }
    }
    return false;
}
#endif

void WifiSettings::SyncAfterDecryped(WifiDeviceConfig &config)
{
#ifdef FEATURE_ENCRYPTION_SUPPORT
    if (IsWifiDeviceConfigDeciphered(config)) {
        return;
    }
    DecryptionDeviceConfig(config);
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    WifiAssetManager::GetInstance().WifiAssetAdd(config);
#endif
#endif
}

int WifiSettings::RemoveDevice(int networkId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter != mWifiDeviceConfig.end()) {
        if (!iter->second.wifiEapConfig.clientCert.empty()) {
            if (WifiCertUtils::UninstallCert(iter->second.wifiEapConfig.clientCert) != 0) {
                LOGE("uninstall cert %{public}s fail", iter->second.wifiEapConfig.clientCert.c_str());
            } else {
                LOGD("uninstall cert %{public}s success", iter->second.wifiEapConfig.clientCert.c_str());
            }
        }
#ifdef SUPPORT_ClOUD_WIFI_ASSET
        WifiAssetManager::GetInstance().WifiAssetRemove(iter->second);
#endif
        mWifiDeviceConfig.erase(iter);
    }
    return 0;
}

void WifiSettings::ClearDeviceConfig(void)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.wifiEapConfig.clientCert.empty()) {
            continue;
        }
        if (WifiCertUtils::UninstallCert(iter->second.wifiEapConfig.clientCert) != 0) {
            LOGE("uninstall cert %{public}s fail", iter->second.wifiEapConfig.clientCert.c_str());
        } else {
            LOGD("uninstall cert %{public}s success", iter->second.wifiEapConfig.clientCert.c_str());
        }
    }
    mWifiDeviceConfig.clear();
    return;
}

int WifiSettings::GetDeviceConfig(std::vector<WifiDeviceConfig> &results, int instId)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        // -1: Connect by system, use default uid.
        if ((iter->second.uid == -1 || iter->second.isShared) && iter->second.instanceId == instId) {
            results.push_back(iter->second);
        }
    }
    return 0;
}

int WifiSettings::GetDeviceConfig(const int &networkId, WifiDeviceConfig &config, int instId)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.networkId == networkId && iter->second.instanceId == instId) {
            SyncAfterDecryped(iter->second);
            config = iter->second;
            return 0;
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &index, const int &indexType,
    WifiDeviceConfig &config, int instId)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index && iter->second.instanceId == instId) {
                SyncAfterDecryped(iter->second);
                config = iter->second;
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index && iter->second.instanceId == instId) {
                SyncAfterDecryped(iter->second);
                config = iter->second;
                return 0;
            }
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &ssid, const std::string &keymgmt,
    WifiDeviceConfig &config, int instId)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }

    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if ((iter->second.ssid == ssid) && (InKeyMgmtBitset(iter->second, keymgmt))
            && (iter->second.uid == -1 || iter->second.isShared) && iter->second.instanceId == instId) {
            SyncAfterDecryped(iter->second);
            config = iter->second;
            return 0;
        }
    }

    return -1;
}

void WifiSettings::SetUserConnectChoice(int networkId)
{
    WifiDeviceConfig selectConfig;
    if (GetDeviceConfig(networkId, selectConfig) != 0 || selectConfig.ssid.empty()) {
        LOGE("%{public}s, not find networkId:%{public}d", __FUNCTION__, networkId);
        return;
    }
    LOGI("%{public}s enter, networkId:%{public}d, ssid: %{public}s", __FUNCTION__, networkId,
        SsidAnonymize(selectConfig.ssid).c_str());
    if (selectConfig.networkSelectionStatus.status != WifiDeviceConfigStatus::ENABLED) {
        selectConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::ENABLED;
    }
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    long currentTime = static_cast<int64_t>(times.tv_sec) * MSEC + times.tv_nsec / (MSEC * MSEC);
    std::vector<WifiDeviceConfig> savedNetwork;
    GetDeviceConfig(savedNetwork);
    for (const auto &config : savedNetwork) {
        if (config.networkId == selectConfig.networkId) {
            if (config.networkSelectionStatus.connectChoice != INVALID_NETWORK_ID) {
                LOGI("%{public}s remove user select preference of %{public}d,"
                    "set time %{public}ld from %{public}s, networkId: %{public}d", __FUNCTION__,
                    config.networkSelectionStatus.connectChoice, currentTime, SsidAnonymize(config.ssid).c_str(),
                    config.networkId);
                ClearNetworkConnectChoice(config.networkId);
            }
            continue;
        }
        if (config.networkSelectionStatus.seenInLastQualifiedNetworkSelection || config.hiddenSSID) {
            LOGI("%{public}s add select net:%{public}d set time:%{public}ld to net:%{public}d with ssid:%{public}s",
                __FUNCTION__, selectConfig.networkId, currentTime, config.networkId,
                SsidAnonymize(config.ssid).c_str());
            SetNetworkConnectChoice(config.networkId, selectConfig.networkId, currentTime);
        }
    }
}

void WifiSettings::ClearAllNetworkConnectChoice()
{
    std::vector<WifiDeviceConfig> savedNetwork;
    if (GetDeviceConfig(savedNetwork) != 0) {
        LOGI("%{public}s GetDeviceConfig fail", __FUNCTION__);
        return;
    }
    for (auto &config : savedNetwork) {
        if (config.networkSelectionStatus.connectChoice != INVALID_NETWORK_ID) {
            config.networkSelectionStatus.connectChoice = INVALID_NETWORK_ID;
            config.networkSelectionStatus.connectChoiceTimestamp = INVALID_NETWORK_SELECTION_DISABLE_TIMESTAMP;
            AddDeviceConfig(config);
        }
    }
}

bool WifiSettings::ClearNetworkConnectChoice(int networkId)
{
    WifiDeviceConfig config;
    if (GetDeviceConfig(networkId, config) != 0) {
        LOGI("%{public}s, cannot find networkId %{public}d", __FUNCTION__, networkId);
        return false;
    }
    config.networkSelectionStatus.connectChoice = INVALID_NETWORK_ID;
    config.networkSelectionStatus.connectChoiceTimestamp = INVALID_NETWORK_SELECTION_DISABLE_TIMESTAMP;
    AddDeviceConfig(config);
    return true;
}

void WifiSettings::RemoveConnectChoiceFromAllNetwork(int networkId)
{
    if (networkId == INVALID_NETWORK_ID) {
        LOGE("%{public}s network is invalid %{public}d", __FUNCTION__, networkId);
        return;
    }
    std::vector<WifiDeviceConfig> savedConfig;
    if (GetDeviceConfig(savedConfig) != 0) {
        LOGI("%{public}s GetDeviceConfig fail", __FUNCTION__);
        return;
    }
    for (auto &config : savedConfig) {
        if (config.networkSelectionStatus.connectChoice == networkId) {
            ClearNetworkConnectChoice(config.networkId);
        }
    }
}

bool WifiSettings::SetNetworkConnectChoice(int networkId, int selectNetworkId, long timestamp)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGI("%{public}s, not find networkId %{public}d", __FUNCTION__, networkId);
        return false;
    }
    config.networkSelectionStatus.connectChoice = selectNetworkId;
    config.networkSelectionStatus.connectChoiceTimestamp = timestamp;
    AddDeviceConfig(config);
    return true;
}

bool WifiSettings::ClearNetworkCandidateScanResult(int networkId)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGI("%{public}s, not find networkId %{public}d", __FUNCTION__, networkId);
        return false;
    }
    config.networkSelectionStatus.seenInLastQualifiedNetworkSelection = false;
    AddDeviceConfig(config);
    return true;
}

bool WifiSettings::SetNetworkCandidateScanResult(int networkId)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGI("%{public}s, not find networkId %{public}d", __FUNCTION__, networkId);
        return false;
    }
    config.networkSelectionStatus.seenInLastQualifiedNetworkSelection = true;
    AddDeviceConfig(config);
    return true;
}

int WifiSettings::SetDeviceEphemeral(int networkId, bool isEphemeral)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    iter->second.isEphemeral = isEphemeral;
    return 0;
}

int WifiSettings::SetDeviceAfterConnect(int networkId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    LOGD("Set Device After Connect");
    iter->second.lastConnectTime = time(0);
    iter->second.numRebootsSinceLastUse = 0;
    iter->second.numAssociation++;
    iter->second.networkSelectionStatus.networkDisableCount = 0;
    return 0;
}

int WifiSettings::SetDeviceRandomizedMacSuccessEver(int networkId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    iter->second.randomizedMacSuccessEver = true;
    return 0;
}

int WifiSettings::SetDeviceEverConnected(int networkId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    iter->second.everConnected = true;
    return 0;
}

int WifiSettings::SetAcceptUnvalidated(int networkId, bool state)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    iter->second.acceptUnvalidated = state;
    return 0;
}

bool WifiSettings::GetDeviceEverConnected(int networkId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return false;
    }
    return iter->second.everConnected;
}

bool WifiSettings::GetAcceptUnvalidated(int networkId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return false;
    }
    return iter->second.acceptUnvalidated;
}

int WifiSettings::GetCandidateConfigWithoutUid(const std::string &ssid, const std::string &keymgmt,
    WifiDeviceConfig &config)
{
    std::vector<WifiDeviceConfig> configs;
    if (GetAllCandidateConfigWithoutUid(configs) != 0) {
        return -1;
    }
    for (const auto &it : configs) {
        // -1: Connect by system, use default uid.
        if (it.uid != -1 && !(it.isShared) && it.ssid == ssid && it.keyMgmt == keymgmt) {
            config = it;
            return it.networkId;
        }
    }
    return -1;
}

int WifiSettings::GetCandidateConfig(const int uid, const std::string &ssid, const std::string &keymgmt,
    WifiDeviceConfig &config)
{
    std::vector<WifiDeviceConfig> configs;
    if (GetAllCandidateConfig(uid, configs) != 0) {
        return -1;
    }

    for (const auto &it : configs) {
        if (it.ssid == ssid && it.keyMgmt == keymgmt) {
            config = it;
            return it.networkId;
        }
    }
    return -1;
}

int WifiSettings::GetCandidateConfig(const int uid, const int &networkId, WifiDeviceConfig &config)
{
    std::vector<WifiDeviceConfig> configs;
    if (GetAllCandidateConfig(uid, configs) != 0) {
        return -1;
    }

    for (const auto &it : configs) {
        if (it.networkId == networkId) {
            config = it;
            return it.networkId;
        }
    }
    return -1;
}

int WifiSettings::GetAllCandidateConfigWithoutUid(std::vector<WifiDeviceConfig> &configs)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
 
    std::unique_lock<std::mutex> lock(mStaMutex);
    bool found = false;
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.uid != -1 && !iter->second.isShared) {
            configs.push_back(iter->second);
            found = true;
        }
    }
    return found ? 0 : -1;
}

int WifiSettings::GetAllCandidateConfig(const int uid, std::vector<WifiDeviceConfig> &configs)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }

    std::unique_lock<std::mutex> lock(mStaMutex);
    bool found = false;
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.uid == uid) {
            configs.push_back(iter->second);
            found = true;
        }
    }
    return found ? 0 : -1;
}

int WifiSettings::IncreaseDeviceConnFailedCount(const std::string &index, const int &indexType, int count)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index) {
                iter->second.connFailedCount += count;
                LOGI("WifiSettings::IncreaseDeviceConnFailedCount ssid=%{public}s,connFailedCount=%{public}d,"
                    "count=%{public}d",
                     SsidAnonymize(index).c_str(), iter->second.connFailedCount, count);
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index) {
                iter->second.connFailedCount += count;
                LOGI("WifiSettings::IncreaseDeviceConnFailedCount bssid=%{public}s,connFailedCount=%{public}d,"
                    "count=%{public}d",
                     SsidAnonymize(index).c_str(), iter->second.connFailedCount, count);
                return 0;
            }
        }
    }
    LOGE("WifiSettings::IncreaseDeviceConnFailedCount failed %{public}s,count=%{public}d",
        SsidAnonymize(index).c_str(), count);
    return -1;
}

int WifiSettings::SetDeviceConnFailedCount(const std::string &index, const int &indexType, int count)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index) {
                iter->second.connFailedCount = count;
                LOGI("WifiSettings::SetDeviceConnFailedCount bssid=%{public}s,connFailedCount=%{public}d,"
                    "count=%{public}d",
                     SsidAnonymize(index).c_str(), iter->second.connFailedCount, count);
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index) {
                iter->second.connFailedCount = count;
                LOGI("WifiSettings::SetDeviceConnFailedCount bssid=%{public}s,connFailedCount=%{public}d,"
                    "count=%{public}d",
                     SsidAnonymize(index).c_str(), iter->second.connFailedCount, count);
                return 0;
            }
        }
    }
    LOGE("WifiSettings::SetDeviceConnFailedCount failed %{public}s,count=%{public}d",
        SsidAnonymize(index).c_str(), count);
    return -1;
}

int WifiSettings::SyncDeviceConfig()
{
#ifndef CONFIG_NO_CONFIG_WRITE
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::vector<WifiDeviceConfig> tmp;
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); ++iter) {
        if (!iter->second.isEphemeral && iter->second.instanceId == 0) {
            tmp.push_back(iter->second);
        }
    }
    RemoveExcessDeviceConfigs(tmp);
    mSavedDeviceConfig.SetValue(tmp);
    return mSavedDeviceConfig.SaveConfig();
#else
    return 0;
#endif
}

static int FindKeyMgmtPosition(const std::string& keyMgmt)
{
    for (int index = 0; index < KEY_MGMT_TOTAL_NUM; ++index) {
        if (KEY_MGMT_ARRAY[index] == keyMgmt) {
            return index;
        }
    }
    return -1;
}

bool WifiSettings::InKeyMgmtBitset(const WifiDeviceConfig& config, const std::string& keyMgmt)
{
    if (keyMgmt != "WPA-PSK+SAE") {
        int index = FindKeyMgmtPosition(keyMgmt);
        if (index < 0) {
            return false;
        }
        return (config.keyMgmtBitset & (1 << index)) != 0;
    } else {
        return InKeyMgmtBitset(config, KEY_MGMT_WPA_PSK) || InKeyMgmtBitset(config, KEY_MGMT_SAE);
    }
}

void WifiSettings::SetKeyMgmtBitset(WifiDeviceConfig &config)
{
    // Currently only set when keyMgmtBitset does not match keyMgmt
    if (InKeyMgmtBitset(config, config.keyMgmt)) {
        return;
    }
    int index = FindKeyMgmtPosition(config.keyMgmt);
    // Invalid keyMgmt
    if (index < 0) {
        return;
    }
    config.keyMgmtBitset |= (1 << index);
    if (config.keyMgmt == KEY_MGMT_WPA_PSK) {
        index = FindKeyMgmtPosition(KEY_MGMT_SAE);
        config.keyMgmtBitset |= (1 << index);
    }
}

void WifiSettings::GetAllSuitableEncryption(const WifiDeviceConfig &config,
    const std::string &keyMgmt, std::vector<std::string> &candidateKeyMgmtList)
{
    if (keyMgmt == "WPA-PSK+SAE") {
        if (InKeyMgmtBitset(config, KEY_MGMT_WPA_PSK)) {
            candidateKeyMgmtList.emplace_back(KEY_MGMT_WPA_PSK);
        }
        if (InKeyMgmtBitset(config, KEY_MGMT_SAE)) {
            candidateKeyMgmtList.emplace_back(KEY_MGMT_SAE);
        }
    } else {
        if (InKeyMgmtBitset(config, keyMgmt)) {
            candidateKeyMgmtList.emplace_back(keyMgmt);
        }
    }
}

int WifiSettings::ReloadDeviceConfig()
{
#ifndef CONFIG_NO_CONFIG_WRITE
    std::unique_lock<std::mutex> lock(mStaMutex);
    int ret = mSavedDeviceConfig.LoadConfig();
    if (ret < 0) {
        deviceConfigLoadFlag.clear();
        LOGD("Loading device config failed: %{public}d", ret);
        return -1;
    }
    deviceConfigLoadFlag.test_and_set();
    std::vector<WifiDeviceConfig> tmp;
    mSavedDeviceConfig.GetValue(tmp);
    mNetworkId = 0;
    mWifiDeviceConfig.clear();
    for (std::size_t i = 0; i < tmp.size(); ++i) {
        WifiDeviceConfig &item = tmp[i];
        SetKeyMgmtBitset(item);
        item.networkId = mNetworkId++;
        mWifiDeviceConfig.emplace(item.networkId, item);
    }
    LOGI("ReloadDeviceConfig load deviceConfig size: %{public}d", static_cast<int>(mWifiDeviceConfig.size()));
    if (!mEncryptionOnBootFalg.test_and_set()) {
        mWifiEncryptionThread = std::make_unique<WifiEventHandler>("WifiEncryptionThread");
        mWifiEncryptionThread->PostAsyncTask([this]() {
            LOGI("ReloadDeviceConfig EncryptionWifiDeviceConfigOnBoot start.");
            EncryptionWifiDeviceConfigOnBoot();
        });
    }
    return 0;
#else
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiDeviceConfig.clear();
    return 0;
#endif
}

int WifiSettings::GetNextNetworkId()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    return mNetworkId++;
}

int WifiSettings::AddWpsDeviceConfig(const WifiDeviceConfig &config)
{
    int ret = mSavedDeviceConfig.LoadConfig();
    if (ret < 0) {
        LOGE("Add Wps config loading config failed: %{public}d", ret);
        return -1;
    }
    std::vector<WifiDeviceConfig> tmp;
    mSavedDeviceConfig.GetValue(tmp);
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiDeviceConfig.clear();
    mNetworkId = 0;
    mWifiDeviceConfig.emplace(mNetworkId++, config);
    for (std::size_t i = 0; i < tmp.size(); ++i) {
        WifiDeviceConfig &item = tmp[i];
        item.networkId = mNetworkId++;
        mWifiDeviceConfig.emplace(item.networkId, item);
    }
    return 0;
}

#ifndef OHOS_ARCH_LITE
int WifiSettings::OnRestore(UniqueFd &fd, const std::string &restoreInfo)
{
    LOGI("OnRestore enter.");
    const std::string versionForXml = "9";
    std::string key;
    std::string iv;
    std::string version;
    ParseBackupJson(restoreInfo, key, iv, version);

    std::vector<WifiDeviceConfig> deviceConfigs;
    int ret = 0;
    if (version == versionForXml) {
        ret = GetConfigbyBackupXml(deviceConfigs, fd);
    } else {
        ret = GetConfigbyBackupFile(deviceConfigs, fd, key, iv);
    }
    std::fill(key.begin(), key.end(), 0);
    if (ret < 0) {
        LOGE("OnRestore fail to get config from backup.");
        return ret;
    }

    LOGI("OnRestore end. Restore count: %{public}d", static_cast<int>(deviceConfigs.size()));
    ConfigsDeduplicateAndSave(deviceConfigs);
    return 0;
}

int WifiSettings::OnBackup(UniqueFd &fd, const std::string &backupInfo)
{
    LOGI("OnBackup enter.");
    std::string key;
    std::string iv;
    std::string version;
    ParseBackupJson(backupInfo, key, iv, version);
    if (key.size() == 0 || iv.size() == 0) {
        LOGE("OnBackup key or iv is empty.");
        return -1;
    }
    mSavedDeviceConfig.LoadConfig();
    std::vector<WifiDeviceConfig> localConfigs;
    mSavedDeviceConfig.GetValue(localConfigs);

    std::vector<WifiBackupConfig> backupConfigs;
    for (auto &config : localConfigs) {
        if (config.wifiEapConfig.eap.length() != 0 || config.isPasspoint == true) {
            continue;
        }
#ifdef FEATURE_ENCRYPTION_SUPPORT
        DecryptionDeviceConfig(config);
#endif
        WifiBackupConfig backupConfig;
        ConvertDeviceCfgToBackupCfg(config, backupConfig);
        backupConfigs.push_back(backupConfig);
    }
    std::vector<WifiDeviceConfig>().swap(localConfigs);

    WifiConfigFileImpl<WifiBackupConfig> wifiBackupConfig;
    wifiBackupConfig.SetConfigFilePath(BACKUP_CONFIG_FILE_PATH);
    wifiBackupConfig.SetEncryptionInfo(key, iv);
    wifiBackupConfig.SetValue(backupConfigs);
    wifiBackupConfig.SaveConfig();
    wifiBackupConfig.UnsetEncryptionInfo();
    std::fill(key.begin(), key.end(), 0);

    fd = UniqueFd(open(BACKUP_CONFIG_FILE_PATH, O_RDONLY));
    if (fd.Get() < 0) {
        LOGE("OnBackup open fail.");
        return -1;
    }
    LOGI("OnBackup end. Backup count: %{public}d, fd: %{public}d.", static_cast<int>(backupConfigs.size()), fd.Get());
    return 0;
}

std::string WifiSettings::SetBackupReplyCode(int replyCode)
{
    Json::Value root;
    Json::Value resultInfo;
    Json::Value errorInfo;

    errorInfo["type"] = "ErrorInfo";
    errorInfo["errorCode"] = std::to_string(replyCode);
    errorInfo["errorInfo"] = "";

    resultInfo.append(errorInfo);
    root["resultInfo"] = resultInfo;

    Json::FastWriter writer;
    return writer.write(root);
}

void WifiSettings::RemoveBackupFile()
{
    remove(BACKUP_CONFIG_FILE_PATH);
}
#endif

bool WifiSettings::AddRandomMac(WifiStoreRandomMac &randomMacInfo)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (!MacAddress::IsValidMac(randomMacInfo.randomMac)) {
        LOGE("%{public}s failed randomMac is inValid.", __func__);
        return false;
    }
    bool isAdded = false;
    std::string fuzzyBssid = "";
    if (IsPskEncryption(randomMacInfo.keyMgmt)) {
        fuzzyBssid = FuzzyBssid(randomMacInfo.peerBssid);
        if (fuzzyBssid.empty()) {
            LOGI("AddRandomMac fuzzyBssid is empty.");
            return false;
        }
    }
    
    for (auto &ele : mWifiStoreRandomMac) {
        if (IsPskEncryption(ele.keyMgmt)) {
            if (ele.randomMac != randomMacInfo.randomMac) {
                continue;
            }
            if (ele.fuzzyBssids.find(fuzzyBssid) != ele.fuzzyBssids.end()) {
                LOGI("AddRandomMac is contains fuzzyBssid:%{public}s", MacAnonymize(fuzzyBssid).c_str());
                return true;
            }
            if (ele.fuzzyBssids.size() <= FUZZY_BSSID_MAX_MATCH_CNT) {
                ele.fuzzyBssids.insert(fuzzyBssid);
                LOGI("AddRandomMac insert fuzzyBssid:%{public}s", MacAnonymize(fuzzyBssid).c_str());
                isAdded = true;
                break;
            } else {
                LOGI("AddRandomMac ele.fuzzyBssids.size is max count");
                return false;
            }
        }
        if (ele.ssid == randomMacInfo.ssid && ele.keyMgmt == randomMacInfo.keyMgmt) {
            return true;
        }
    }

    LOGI("AddRandomMac isAdded:%{public}d", isAdded);
    if (!isAdded) {
        if (IsPskEncryption(randomMacInfo.keyMgmt)) {
            randomMacInfo.fuzzyBssids.insert(fuzzyBssid);
        }
        mWifiStoreRandomMac.push_back(randomMacInfo);
    }

    mSavedWifiStoreRandomMac.SetValue(mWifiStoreRandomMac);
    mSavedWifiStoreRandomMac.SaveConfig();
    return isAdded;
}

bool WifiSettings::GetRandomMac(WifiStoreRandomMac &randomMacInfo)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::string fuzzyBssid = "";
    if (IsPskEncryption(randomMacInfo.keyMgmt)) {
        fuzzyBssid = FuzzyBssid(randomMacInfo.peerBssid);
        if (fuzzyBssid.empty()) {
            LOGI("GetStaRandomMac fuzzyBssid is empty.");
            return false;
        }
    }

    for (auto &item : mWifiStoreRandomMac) {
        if (!MacAddress::IsValidMac(item.randomMac)) {
            continue;
        }
        if (IsPskEncryption(item.keyMgmt)) {
            if (item.fuzzyBssids.find(fuzzyBssid) != item.fuzzyBssids.end()) {
                LOGI("GetStaRandomMac fuzzyBssids contains fuzzyBssid:%{public}s",
                    MacAnonymize(fuzzyBssid).c_str());
                randomMacInfo.randomMac = item.randomMac;
                break;
            }
        } else {
            if (item.ssid == randomMacInfo.ssid && item.keyMgmt == randomMacInfo.keyMgmt) {
                randomMacInfo.randomMac = item.randomMac;
                break;
            }
        }
    }
    return randomMacInfo.randomMac.empty();
}

const std::vector<TrustListPolicy> WifiSettings::ReloadTrustListPolicies()
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mTrustListPolicies.LoadConfig();
    if (mTrustListPolicies.GetValue().size() <= 0) {
        std::vector<TrustListPolicy> policies;
        TrustListPolicy policy;
        policies.push_back(policy);
        mTrustListPolicies.SetValue(policies);
        mTrustListPolicies.SaveConfig();
        mTrustListPolicies.LoadConfig();
    }

    return mTrustListPolicies.GetValue();
}

const MovingFreezePolicy WifiSettings::ReloadMovingFreezePolicy()
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mMovingFreezePolicy.LoadConfig();

    if (mMovingFreezePolicy.GetValue().size() <= 0) {
        std::vector<MovingFreezePolicy> policies;
        MovingFreezePolicy policy;
        policies.push_back(policy);
        mMovingFreezePolicy.SetValue(policies);
        mMovingFreezePolicy.SaveConfig();
        mMovingFreezePolicy.LoadConfig();
    }

    if (mMovingFreezePolicy.GetValue().size() <= 0) {
        return MovingFreezePolicy();
    }
    return mMovingFreezePolicy.GetValue()[0];
}

int WifiSettings::GetPackageInfoMap(std::map<std::string, std::vector<PackageInfo>> &packageInfoMap)
{
    std::unique_lock<std::mutex> lock(mPackageConfMutex);
    packageInfoMap = mPackageInfoMap;
    return 0;
}

int WifiSettings::GetPackageInfoByName(std::string name, std::vector<PackageInfo> &packageInfo)
{
    std::unique_lock<std::mutex> lock(mPackageConfMutex);
    auto iter = mPackageInfoMap.find(name);
    if (iter != mPackageInfoMap.end()) {
        packageInfo = iter->second;
        return 0;
    }
    return -1;
}

int WifiSettings::SyncHotspotConfig()
{
    std::unique_lock<std::mutex> lock(mApMutex);
    std::vector<HotspotConfig> tmp;

    for (int i = 0; i < AP_INSTANCE_MAX_NUM; i++) {
        auto iter = mHotspotConfig.find(i);
        if (iter != mHotspotConfig.end()) {
            tmp.push_back(iter->second);
        }
    }
    mSavedHotspotConfig.SetValue(tmp);
    mSavedHotspotConfig.SaveConfig();

    return 0;
}

int WifiSettings::SetHotspotConfig(const HotspotConfig &config, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    if (id < 0 || id >= AP_INSTANCE_MAX_NUM) {
        LOGE("SetHotspotConfig id is out of range");
        return -1;
    }
    mHotspotConfig[id] = config;
    return 0;
}

int WifiSettings::GetHotspotConfig(HotspotConfig &config, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mHotspotConfig.find(id);
    if (iter != mHotspotConfig.end()) {
        config = iter->second;
        return 0;
    }
    return -1;
}

void WifiSettings::ClearHotspotConfig()
{
    std::unique_lock<std::mutex> lock(mApMutex);
    mHotspotConfig.clear();
    HotspotConfig config;
    config.SetSecurityType(KeyMgmt::WPA2_PSK);
    config.SetBand(BandType::BAND_2GHZ);
    config.SetChannel(AP_CHANNEL_DEFAULT);
    config.SetMaxConn(GetApMaxConnNum());
    config.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    config.SetSsid(GetDefaultApSsid());
    config.SetPreSharedKey(GetRandomStr(RANDOM_PASSWD_LEN));
    auto ret = mHotspotConfig.emplace(0, config);
    if (!ret.second) {
        mHotspotConfig[0] = config;
    }
    LOGI("%{public}s, ApConfig ssid is %{public}s, preSharedKey_len is %{public}d", __FUNCTION__,
        SsidAnonymize(config.GetSsid()).c_str(), config.GetPreSharedKey().length());
}

int WifiSettings::GetBlockList(std::vector<StationInfo> &results, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    for (auto iter = mBlockListInfo.begin(); iter != mBlockListInfo.end(); iter++) {
        results.push_back(iter->second);
    }
    return 0;
}

int WifiSettings::ManageBlockList(const StationInfo &info, int mode, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mBlockListInfo.find(info.bssid);
    if (MODE_ADD == mode || MODE_UPDATE == mode) {
        if (iter != mBlockListInfo.end()) {
            iter->second = info;
        } else {
            mBlockListInfo.emplace(std::make_pair(info.bssid, info));
        }
    } else if (MODE_DEL == mode) {
        if (iter != mBlockListInfo.end()) {
            mBlockListInfo.erase(iter);
        }
    } else {
        return -1;
    }
    SyncBlockList();
    return 0;
}

int WifiSettings::SyncWifiP2pGroupInfoConfig()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mSavedWifiP2pGroupInfo.SetValue(mGroupInfoList);
    return mSavedWifiP2pGroupInfo.SaveConfig();
}

int WifiSettings::SetWifiP2pGroupInfo(const std::vector<WifiP2pGroupInfo> &groups)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mGroupInfoList = groups;
    return 0;
}

int WifiSettings::RemoveWifiP2pGroupInfo()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mGroupInfoList.clear();
    return 0;
}

int WifiSettings::RemoveWifiP2pSupplicantGroupInfo()
{
    std::filesystem::path pathName = P2P_SUPPLICANT_CONFIG_FILE;
    std::error_code code;
    if (!std::filesystem::exists(pathName, code)) {
        LOGE("p2p_supplicant file do not exists!, file:%{public}s", P2P_SUPPLICANT_CONFIG_FILE);
        return -1;
    }
    std::error_code ec;
    int retval = std::filesystem::remove(P2P_SUPPLICANT_CONFIG_FILE, ec);
    if (!ec) { // successful
        LOGI("p2p_supplicant file removed successful, retval:%{public}d value:%{public}d message:%{public}s",
            retval, ec.value(), ec.message().c_str());
        return 0;
    } // unsuccessful
    LOGE("p2p_supplicant file removed unsuccessful, value:%{public}d value:%{public}d message:%{public}s",
        retval, ec.value(), ec.message().c_str());
    return -1;
}

int WifiSettings::GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    groups = mGroupInfoList;
    return 0;
}

int WifiSettings::SyncP2pVendorConfig()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    std::vector<P2pVendorConfig> tmp;
    tmp.push_back(mP2pVendorConfig);
    mSavedWifiP2pVendorConfig.SetValue(tmp);
    return mSavedWifiP2pVendorConfig.SaveConfig();
}

int WifiSettings::SetP2pDeviceName(const std::string &deviceName)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mP2pVendorConfig.SetDeviceName(deviceName);
    std::vector<P2pVendorConfig> tmp;
    tmp.push_back(mP2pVendorConfig);
    mSavedWifiP2pVendorConfig.SetValue(tmp);
    return mSavedWifiP2pVendorConfig.SaveConfig();
}

int WifiSettings::SetP2pVendorConfig(const P2pVendorConfig &config)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mP2pVendorConfig = config;
    return 0;
}

int WifiSettings::GetP2pVendorConfig(P2pVendorConfig &config)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    config = mP2pVendorConfig;
    return 0;
}

bool WifiSettings::GetScanAlwaysState(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scanAlwaysSwitch;
    }
    return mWifiConfig[0].scanAlwaysSwitch;
}

int WifiSettings::GetSignalLevel(const int &rssi, const int &band, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    int level = 0;
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        do {
            if (band == static_cast<int>(BandType::BAND_5GHZ)) {
                if (rssi < iter->second.firstRssiLevel5G) {
                    break;
                }
                ++level;
                if (rssi < iter->second.secondRssiLevel5G) {
                    break;
                }
                ++level;
                if (rssi < iter->second.thirdRssiLevel5G) {
                    break;
                }
                ++level;
                if (rssi < iter->second.fourthRssiLevel5G) {
                    break;
                }
                ++level;
            } else {
                if (rssi < iter->second.firstRssiLevel2G) {
                    break;
                }
                ++level;
                if (rssi < iter->second.secondRssiLevel2G) {
                    break;
                }
                ++level;
                if (rssi < iter->second.thirdRssiLevel2G) {
                    break;
                }
                ++level;
                if (rssi < iter->second.fourthRssiLevel2G) {
                    break;
                }
                ++level;
            }
        } while (0);
    }
    return level;
}

int WifiSettings::GetOperatorWifiType(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.staAirplaneMode;
    }
    return mWifiConfig[0].staAirplaneMode;
}

int WifiSettings::SetOperatorWifiType(int type, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].staAirplaneMode = type;
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_REALTIME, &times);
    int64_t curTimeMs = static_cast<int64_t>(times.tv_sec) * MSEC + times.tv_nsec / (MSEC * MSEC);
    LOGI("set persist wifi state, current time is:%{public}" PRId64, curTimeMs);
    mWifiConfig[instId].persistWifiTime = curTimeMs;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetLastAirplaneMode(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.lastAirplaneMode;
    }
    return mWifiConfig[0].lastAirplaneMode;
}

int WifiSettings::SetLastAirplaneMode(int mode, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].lastAirplaneMode = mode;
    SyncWifiConfig();
    return 0;
}

#ifndef OHOS_ARCH_LITE
int WifiSettings::SetWifiToggleCaller(int callerPid, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].toggleWifiCaller = callerPid;
    SyncWifiConfig();
    return 0;
}
#endif

bool WifiSettings::GetCanOpenStaWhenAirplaneMode(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.canOpenStaWhenAirplane;
    }
    return mWifiConfig[0].canOpenStaWhenAirplane;
}

int WifiSettings::SetWifiFlagOnAirplaneMode(bool ifOpen, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].openWifiWhenAirplane = ifOpen;
    SyncWifiConfig();
    return 0;
}

bool WifiSettings::GetWifiFlagOnAirplaneMode(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.openWifiWhenAirplane;
    }
    return mWifiConfig[0].openWifiWhenAirplane;
}

int WifiSettings::SetWifiDisabledByAirplane(bool disabledByAirplane, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].wifiDisabledByAirplane = disabledByAirplane;
    SyncWifiConfig();
    return 0;
}

bool WifiSettings::GetWifiDisabledByAirplane(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.wifiDisabledByAirplane;
    }
    return mWifiConfig[0].wifiDisabledByAirplane;
}

int WifiSettings::GetStaLastRunState(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.staLastState;
    }
    return mWifiConfig[0].staLastState;
}

int WifiSettings::SetStaLastRunState(int bRun, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].staLastState = bRun;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetDhcpIpType(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.dhcpIpType;
    }
    return mWifiConfig[0].dhcpIpType;
}

bool WifiSettings::GetWhetherToAllowNetworkSwitchover(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.whetherToAllowNetworkSwitchover;
    }
    return mWifiConfig[0].whetherToAllowNetworkSwitchover;
}

int WifiSettings::GetScoretacticsScoreSlope(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsScoreSlope;
    }
    return mWifiConfig[0].scoretacticsScoreSlope;
}

int WifiSettings::GetScoretacticsInitScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsInitScore;
    }
    return mWifiConfig[0].scoretacticsInitScore;
}

int WifiSettings::GetScoretacticsSameBssidScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsSameBssidScore;
    }
    return mWifiConfig[0].scoretacticsSameBssidScore;
}

int WifiSettings::GetScoretacticsSameNetworkScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsSameNetworkScore;
    }
    return mWifiConfig[0].scoretacticsSameNetworkScore;
}

int WifiSettings::GetScoretacticsFrequency5GHzScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsFrequency5GHzScore;
    }
    return mWifiConfig[0].scoretacticsFrequency5GHzScore;
}

int WifiSettings::GetScoretacticsLastSelectionScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsLastSelectionScore;
    }
    return mWifiConfig[0].scoretacticsLastSelectionScore;
}

int WifiSettings::GetScoretacticsSecurityScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsSecurityScore;
    }
    return mWifiConfig[0].scoretacticsSecurityScore;
}

int WifiSettings::GetScoretacticsNormalScore(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scoretacticsNormalScore;
    }
    return mWifiConfig[0].scoretacticsNormalScore;
}

int WifiSettings::GetSavedDeviceAppraisalPriority(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.savedDeviceAppraisalPriority;
    }
    return mWifiConfig[0].savedDeviceAppraisalPriority;
}

bool WifiSettings::IsModulePreLoad(const std::string &name)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    if (name == WIFI_SERVICE_STA) {
        return mWifiConfig[0].preLoadSta;
    } else if (name == WIFI_SERVICE_SCAN) {
        return mWifiConfig[0].preLoadScan;
    } else if (name == WIFI_SERVICE_AP) {
        return mWifiConfig[0].preLoadAp;
    } else if (name == WIFI_SERVICE_P2P) {
        return mWifiConfig[0].preLoadP2p;
    } else if (name == WIFI_SERVICE_AWARE) {
        return mWifiConfig[0].preLoadAware;
    } else if (name == WIFI_SERVICE_ENHANCE) {
        return mWifiConfig[0].preLoadEnhance;
    } else {
        return false;
    }
}

bool WifiSettings::GetSupportHwPnoFlag(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.supportHwPnoFlag;
    }
    return mWifiConfig[0].supportHwPnoFlag;
}

int WifiSettings::GetMinRssi2Dot4Ghz(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.minRssi2Dot4Ghz;
    }
    return mWifiConfig[0].minRssi2Dot4Ghz;
}

int WifiSettings::GetMinRssi5Ghz(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.minRssi5Ghz;
    }
    return mWifiConfig[0].minRssi5Ghz;
}

int WifiSettings::SetRealMacAddress(const std::string &macAddress, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].realMacAddress = macAddress;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetRealMacAddress(std::string &macAddress, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        macAddress = iter->second.realMacAddress;
        return 0;
    }
    macAddress = mWifiConfig[0].realMacAddress;
    return 0;
}

void WifiSettings::SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies, int instId)
{
    for (auto& item : g_countryDefaultFreqs) {
        if (item.band == band) {
            frequencies = item.freqs;
        }
    }
}

void WifiSettings::SetScanOnlySwitchState(const int &state, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scanOnlySwitch = state;
    SyncWifiConfig();
}

int WifiSettings::GetScanOnlySwitchState(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE) {
        LOGI("factory mode, not allow scan only.");
        return 0;
    }
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scanOnlySwitch;
    }
    return mWifiConfig[0].scanOnlySwitch;
}

bool WifiSettings::EncryptionDeviceConfig(WifiDeviceConfig &config) const
{
#ifdef FEATURE_ENCRYPTION_SUPPORT
    if (config.version == 1) {
        return true;
    }
    WifiEncryptionInfo mWifiEncryptionInfo;
    mWifiEncryptionInfo.SetFile(GetTClassName<WifiDeviceConfig>());

    config.encryptedData = "";
    config.IV = "";
    if (!config.preSharedKey.empty()) {
        EncryptedData encry;
        if (WifiEncryption(mWifiEncryptionInfo, config.preSharedKey, encry) == HKS_SUCCESS) {
            config.encryptedData = encry.encryptedPassword;
            config.IV = encry.IV;
        } else {
            LOGE("EncryptionDeviceConfig WifiEncryption preSharedKey failed");
            WriteWifiEncryptionFailHiSysEvent(ENCRYPTION_EVENT,
                SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
            return false;
        }
    }

    if (config.wepTxKeyIndex < 0 || config.wepTxKeyIndex >= WEPKEYS_SIZE) {
        config.wepTxKeyIndex = 0;
    }
    config.encryWepKeys[config.wepTxKeyIndex] = "";
    config.IVWep = "";
    if (!config.wepKeys[config.wepTxKeyIndex].empty()) {
        EncryptedData encryWep;
        if (WifiEncryption(mWifiEncryptionInfo, config.wepKeys[config.wepTxKeyIndex], encryWep) == HKS_SUCCESS) {
            config.encryWepKeys[config.wepTxKeyIndex] = encryWep.encryptedPassword;
            config.IVWep = encryWep.IV;
        } else {
            LOGE("EncryptionDeviceConfig WifiEncryption wepKeys failed");
            WriteWifiEncryptionFailHiSysEvent(ENCRYPTION_EVENT,
                SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
            return false;
        }
    }

    config.wifiEapConfig.encryptedData = "";
    config.wifiEapConfig.IV = "";
    if (!config.wifiEapConfig.eap.empty()) {
        EncryptedData encryEap;
        if (WifiEncryption(mWifiEncryptionInfo, config.wifiEapConfig.password, encryEap) == HKS_SUCCESS) {
            config.wifiEapConfig.encryptedData = encryEap.encryptedPassword;
            config.wifiEapConfig.IV = encryEap.IV;
        } else {
            LOGE("EncryptionDeviceConfig WifiEncryption eap failed");
            WriteWifiEncryptionFailHiSysEvent(ENCRYPTION_EVENT,
                SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
            return false;
        }
    }
    if (!EncryptionWapiConfig(mWifiEncryptionInfo, config)) {
        return false;
    }
    config.version = 1;
#endif
    return true;
}

int WifiSettings::IncreaseNumRebootsSinceLastUse()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        iter->second.numRebootsSinceLastUse++;
    }
    return 0;
}

void WifiSettings::EncryptionWifiDeviceConfigOnBoot()
{
#ifdef FEATURE_ENCRYPTION_SUPPORT
    std::unique_lock<std::mutex> lock(mConfigOnBootMutex);
    if (mSavedDeviceConfig.LoadConfig() < 0) {
        return;
    }
    std::vector<WifiDeviceConfig> tmp;
    mSavedDeviceConfig.GetValue(tmp);
    int count = 0;

    for (std::size_t i = 0; i < tmp.size(); ++i) {
        WifiDeviceConfig &item = tmp[i];
        if (item.version == -1 && EncryptionDeviceConfig(item)) {
            count ++;
        }
    }
    if (count > 0) {
        mSavedDeviceConfig.SetValue(tmp);
        mSavedDeviceConfig.SaveConfig();
        ReloadDeviceConfig();
    }
    LOGI("EncryptionWifiDeviceConfigOnBoot end count:%{public}d", count);
#endif
}

int WifiSettings::ReloadStaRandomMac()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mSavedWifiStoreRandomMac.LoadConfig()) {
        return -1;
    }
    mWifiStoreRandomMac.clear();
    mSavedWifiStoreRandomMac.GetValue(mWifiStoreRandomMac);
    bool shouldReset = false;
    for (const auto &item: mWifiStoreRandomMac) {
        if (item.version == -1) {
            shouldReset = true;
            break;
        }
    }
    LOGI("%{public}s shouldReset:%{public}s", __func__, shouldReset ? "true" : "false");
    if (shouldReset) {
        for (auto &item: mWifiStoreRandomMac) {
            item.version = 0;
        }
        mSavedWifiStoreRandomMac.SetValue(mWifiStoreRandomMac);
        mSavedWifiStoreRandomMac.SaveConfig();
    }
    return 0;
}

void WifiSettings::InitPackageInfoConfig()
{
#ifndef OHOS_ARCH_LITE
    std::unique_ptr<PackageXmlParser> xmlParser = std::make_unique<PackageXmlParser>();
    bool ret = xmlParser->LoadConfiguration(PACKAGE_FILTER_CONFIG_FILE_PATH);
    if (!ret) {
        LOGE("PackageXmlParser load fail");
        return;
    }
    ret = xmlParser->Parse();
    if (!ret) {
        LOGE("PackageXmlParser Parse fail");
        return;
    }
    std::map<std::string, std::vector<PackageInfo>> scanControlPackageMap;
    std::vector<PackageInfo> candidateList;
    std::map<std::string, std::vector<PackageInfo>> variableMap;
    std::vector<PackageInfo> permissionTrustList;
    std::vector<PackageInfo> scanLimitPackage;
    xmlParser->GetScanControlPackages(scanControlPackageMap);
    xmlParser->GetCandidateFilterPackages(candidateList);
    xmlParser->GetCorePackages(variableMap);
    xmlParser->GetAclAuthPackages(permissionTrustList);
    xmlParser->GetScanLimitPackages(scanLimitPackage);
    
    std::unique_lock<std::mutex> lock(mPackageConfMutex);
    mPackageInfoMap.insert(scanControlPackageMap.begin(), scanControlPackageMap.end());
    mPackageInfoMap.insert_or_assign("CandidateFilterPackages", candidateList);
    mPackageInfoMap.insert(variableMap.begin(), variableMap.end());
    mPackageInfoMap.insert_or_assign("AclAuthPackages", permissionTrustList);
    mPackageInfoMap.insert_or_assign("ScanLimitPackages", scanLimitPackage);
#endif
}

std::string WifiSettings::GetPackageName(std::string tag)
{
    std::unique_lock<std::mutex> lock(mPackageConfMutex);
    for (auto iter = mPackageInfoMap.begin(); iter != mPackageInfoMap.end(); iter++) {
        if (iter->first == tag && !iter->second.empty()) {
            return iter->second[0].name;
        }
    }
    return "";
}

void WifiSettings::InitDefaultHotspotConfig()
{
    HotspotConfig cfg;
    cfg.SetSecurityType(KeyMgmt::WPA2_PSK);
    cfg.SetBand(BandType::BAND_2GHZ);
    cfg.SetChannel(AP_CHANNEL_DEFAULT);
    cfg.SetMaxConn(GetApMaxConnNum());
    cfg.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    cfg.SetSsid(GetDefaultApSsid());
    cfg.SetPreSharedKey(GetRandomStr(RANDOM_PASSWD_LEN));
    auto ret = mHotspotConfig.emplace(0, cfg);
    if (!ret.second) {
        mHotspotConfig[0] = cfg;
    }
}

void WifiSettings::InitHotspotConfig()
{
    /* init hotspot config */
    if (mSavedHotspotConfig.LoadConfig() >= 0) {
        std::vector<HotspotConfig> tmp;
        mSavedHotspotConfig.GetValue(tmp);
        if (tmp.size() > 0) {
            for (size_t i = 0; i < tmp.size(); i++) {
                mHotspotConfig[i] = tmp[i];
            }
        } else {
            LOGI("load hotspot config success, but tmp.size() = 0, use default config");
            InitDefaultHotspotConfig();
        }
    } else {
        LOGI("load hotspot config fail, use default config");
        InitDefaultHotspotConfig();
    }
    LOGI("%{public}s, ApConfig ssid is %{public}s, preSharedKey_len is %{public}d", __FUNCTION__,
        SsidAnonymize(mHotspotConfig[0].GetSsid()).c_str(),
        PassWordAnonymize(mHotspotConfig[0].GetPreSharedKey()).length());

    /* init block list info */
    if (mSavedBlockInfo.LoadConfig() >= 0) {
        std::vector<StationInfo> tmp;
        mSavedBlockInfo.GetValue(tmp);
        for (std::size_t i = 0; i < tmp.size(); ++i) {
            StationInfo &item = tmp[i];
            mBlockListInfo.emplace(item.bssid, item);
        }
    }
    return;
}

int WifiSettings::SyncBlockList()
{
    std::vector<StationInfo> tmp;
    for (auto iter = mBlockListInfo.begin(); iter != mBlockListInfo.end(); ++iter) {
        tmp.push_back(iter->second);
    }
    mSavedBlockInfo.SetValue(tmp);
    return mSavedBlockInfo.SaveConfig();
}

int WifiSettings::ReloadWifiP2pGroupInfoConfig()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    bool invalidGroupExist = false;
    if (mSavedWifiP2pGroupInfo.LoadConfig()) {
        return -1;
    }
    mSavedWifiP2pGroupInfo.GetValue(mGroupInfoList);
    for (auto iter = mGroupInfoList.begin(); iter != mGroupInfoList.end();) {
        int networkId = iter->GetNetworkId();
        std::string passPhrase = iter->GetPassphrase();
        if (passPhrase.empty()) {
            LOGI("ReloadWifiP2pGroupInfoConfig erase invalid networkId:%{public}d", networkId);
            iter = mGroupInfoList.erase(iter);
            invalidGroupExist = true;
        } else {
            ++iter;
        }
    }
    if (invalidGroupExist) {
        mSavedWifiP2pGroupInfo.SetValue(mGroupInfoList);
        mSavedWifiP2pGroupInfo.SaveConfig();
    }
    return 0;
}

void WifiSettings::InitDefaultP2pVendorConfig()
{
    mP2pVendorConfig.SetRandomMacSupport(false);
    mP2pVendorConfig.SetIsAutoListen(false);
    mP2pVendorConfig.SetDeviceName("");
    mP2pVendorConfig.SetPrimaryDeviceType("");
    mP2pVendorConfig.SetSecondaryDeviceType("");
}

void WifiSettings::InitP2pVendorConfig()
{
    if (mSavedWifiP2pVendorConfig.LoadConfig() >= 0) {
        std::vector<P2pVendorConfig> tmp;
        mSavedWifiP2pVendorConfig.GetValue(tmp);
        if (tmp.size() > 0) {
            mP2pVendorConfig = tmp[0];
        } else {
            InitDefaultP2pVendorConfig();
        }
    } else {
        InitDefaultP2pVendorConfig();
    }
    return;
}

int WifiSettings::GetApMaxConnNum()
{
    return mApMaxConnNum;
}

void WifiSettings::InitDefaultWifiConfig()
{
    WifiConfig wifiConfig;
    mWifiConfig[0] = wifiConfig;
}

void WifiSettings::InitWifiConfig()
{
    if (mSavedWifiConfig.LoadConfig() < 0) {
        return;
    }
    std::vector<WifiConfig> tmp;
    mSavedWifiConfig.GetValue(tmp);
    if (tmp.size() > 0) {
        for (size_t i = 0; i < tmp.size(); ++i) {
            mWifiConfig[i] = tmp[i];
        }
    } else {
        InitDefaultWifiConfig();
    }
    return;
}

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
void WifiSettings::InitWifiMdmRestrictedListConfig()
{
    if (wifiMdmRestrictedListConfig_.LoadConfig() < 0) {
        LOGI("the mdmRestrictedList loadConfig() return value < 0");
        return;
    }
    std::vector<WifiRestrictedInfo> tmp;
    wifiMdmRestrictedListConfig_.GetValue(tmp);
    if (tmp.size() > 0) {
        for (size_t i = 0; i < tmp.size(); i++) {
            wifiRestrictedList_.push_back(tmp[i]);
        }
    }
}

int WifiSettings::SyncWifiRestrictedListConfig()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::vector<WifiRestrictedInfo> tmp;

    for (size_t i = 0; i < wifiRestrictedList_.size(); i++) {
        tmp.push_back(wifiRestrictedList_[i]);
    }
    wifiMdmRestrictedListConfig_.SetValue(tmp);
    wifiMdmRestrictedListConfig_.SaveConfig();
    return 0;
}
#endif

int WifiSettings::SyncWifiConfig()
{
    std::unique_lock<std::mutex> lock(mSyncWifiConfigMutex);
    std::vector<WifiConfig> tmp;
    for (auto &item : mWifiConfig) {
        tmp.push_back(item.second);
    }
    mSavedWifiConfig.SetValue(tmp);
    return mSavedWifiConfig.SaveConfig();
}

std::vector<WifiDeviceConfig> WifiSettings::RemoveExcessDeviceConfigs(std::vector<WifiDeviceConfig> &configs) const
{
    std::vector<WifiDeviceConfig> removeVec;
    int maxNumConfigs = mMaxNumConfigs;
    if (maxNumConfigs < 0) {
        return removeVec;
    }
    int numExcessNetworks = static_cast<int>(configs.size()) - maxNumConfigs;
    if (numExcessNetworks <= 0) {
        return removeVec;
    }
    sort(configs.begin(), configs.end(), [](WifiDeviceConfig a, WifiDeviceConfig b) {
        if (std::max(a.lastConnectTime, a.lastUpdateTime) != std::max(b.lastConnectTime, b.lastUpdateTime)) {
            return std::max(a.lastConnectTime, a.lastUpdateTime) < std::max(b.lastConnectTime, b.lastUpdateTime);
        } else if (a.numRebootsSinceLastUse != b.numRebootsSinceLastUse) {
            return a.numRebootsSinceLastUse > b.numRebootsSinceLastUse;
        } else if (a.numAssociation != b.numAssociation) {
            return a.numAssociation < b.numAssociation;
        } else {
            return a.networkId < b.networkId;
        }
    });
    std::stringstream removeConfig;
    int maxIndex = numExcessNetworks > MAX_CONFIGS_NUM ? MAX_CONFIGS_NUM : numExcessNetworks;
    for (int i = 0; i < maxIndex; i++) {
        removeConfig << SsidAnonymize(configs[i].ssid) << ",";
    }
    LOGI("saved config size greater than %{public}d, remove ssid(print up to 1000)=%{public}s",
        maxNumConfigs, removeConfig.str().c_str());
    std::vector<WifiDeviceConfig> newVec(configs.begin(), configs.begin() + numExcessNetworks);
    removeVec.swap(newVec);
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    WifiAssetManager::GetInstance().WifiAssetRemovePack(removeVec);
#endif
    configs.erase(configs.begin(), configs.begin() + numExcessNetworks);
    return removeVec;
}

std::string WifiSettings::FuzzyBssid(const std::string bssid)
{
    if (bssid.empty() || bssid.length() != MAC_STRING_SIZE) {
        return "";
    }
    return "xx" + bssid.substr(COMPARE_MAC_OFFSET, COMPARE_MAC_LENGTH) + "xx";
}

#ifndef OHOS_ARCH_LITE
void WifiSettings::MergeWifiConfig()
{
    std::filesystem::path wifiPathNmae = WIFI_CONFIG_FILE_PATH;
    std::filesystem::path devicePathName = DEVICE_CONFIG_FILE_PATH;
    std::filesystem::path randomMacPathName = WIFI_STA_RANDOM_MAC_FILE_PATH;
    std::filesystem::path dualWifiPathName = DUAL_WIFI_CONFIG_FILE_PATH;
    std::error_code wifiConfigCode;
    std::error_code deviceConfigCode;
    std::error_code randomMacCode;
    std::error_code dualWifiCode;
    if (std::filesystem::exists(wifiPathNmae, wifiConfigCode)
        || std::filesystem::exists(devicePathName, deviceConfigCode)
        || std::filesystem::exists(randomMacPathName, randomMacCode)) {
        LOGI("file exists don't need to merge");
        return;
    }
    if (!std::filesystem::exists(dualWifiPathName, dualWifiCode)) {
        LOGI("dual frame file do not exists, don't need to merge");
        return;
    }
    std::unique_ptr<NetworkXmlParser> xmlParser = std::make_unique<NetworkXmlParser>();
    bool ret = xmlParser->LoadConfiguration(DUAL_WIFI_CONFIG_FILE_PATH);
    if (!ret) {
        LOGE("MergeWifiConfig load fail");
        return;
    }
    ret = xmlParser->Parse();
    if (!ret) {
        LOGE("MergeWifiConfig Parse fail");
        return;
    }
    std::vector<WifiDeviceConfig> wifideviceConfig = xmlParser->GetNetworks();
    if (wifideviceConfig.size() == 0) {
        LOGE("MergeWifiConfig wifideviceConfig empty");
        return;
    }
    mSavedDeviceConfig.SetValue(wifideviceConfig);
    mSavedDeviceConfig.SaveConfig();
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::vector<WifiStoreRandomMac> wifiStoreRandomMac = xmlParser->GetRandomMacmap();
    mSavedWifiStoreRandomMac.SetValue(wifiStoreRandomMac);
    mSavedWifiStoreRandomMac.SaveConfig();
}

void WifiSettings::MergeSoftapConfig()
{
    LOGI("Enter mergeSoftapConfig");
    std::filesystem::path wifiPathNmae = WIFI_CONFIG_FILE_PATH;
    std::filesystem::path hostapdPathName = HOTSPOT_CONFIG_FILE_PATH;
    std::filesystem::path dualApPathName = DUAL_SOFTAP_CONFIG_FILE_PATH;
    std::error_code wifiConfigCode;
    std::error_code hotspotConfigCode;
    std::error_code dualApCode;
    if (std::filesystem::exists(wifiPathNmae, wifiConfigCode)
        || std::filesystem::exists(hostapdPathName, hotspotConfigCode)) {
        LOGI("MergeSoftapConfig file exists don't need to merge");
        return;
    }
    if (!std::filesystem::exists(dualApPathName, dualApCode)) {
        LOGI("MergeSoftapConfig dual frame file do not exists, don't need to merge");
        return;
    }
    std::unique_ptr<SoftapXmlParser> xmlParser = std::make_unique<SoftapXmlParser>();
    bool ret = xmlParser->LoadConfiguration(DUAL_SOFTAP_CONFIG_FILE_PATH);
    if (!ret) {
        LOGE("MergeSoftapConfig fail");
        return;
    }
    ret = xmlParser->Parse();
    if (!ret) {
        LOGE("MergeSoftapConfig Parse fail");
        return;
    }
    std::vector<HotspotConfig> hotspotConfig = xmlParser->GetSoftapConfigs();
    if (hotspotConfig.size() == 0) {
        LOGE("MergeSoftapConfig hotspotConfig empty");
        return;
    }
    mSavedHotspotConfig.SetValue(hotspotConfig);
    mSavedHotspotConfig.SaveConfig();
}

void WifiSettings::ConfigsDeduplicateAndSave(std::vector<WifiDeviceConfig> &newConfigs)
{
    if (newConfigs.size() == 0) {
        LOGE("NewConfigs is empty!");
        return;
    }
    mSavedDeviceConfig.LoadConfig();
    std::vector<WifiDeviceConfig> localConfigs;
    mSavedDeviceConfig.GetValue(localConfigs);

    std::set<std::string> tmp;
    for (const auto &localConfig : localConfigs) {
        std::string configKey = localConfig.ssid + localConfig.keyMgmt;
        tmp.insert(configKey);
    }
    std::vector<WifiDeviceConfig> addConfigs;
    for (auto &config : newConfigs) {
        std::string configKey = config.ssid + config.keyMgmt;
        auto iter = tmp.find(configKey);
        if (iter == tmp.end()) {
            tmp.insert(configKey);
#ifdef FEATURE_ENCRYPTION_SUPPORT
            EncryptionDeviceConfig(config);
#endif
            localConfigs.push_back(config);
            addConfigs.push_back(config);
        }
    }
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    LOGD("WifiAsset ConfigsDeduplicateAndSave");
    WifiAssetManager::GetInstance().WifiAssetAddPack(addConfigs);
#endif
    std::vector<WifiDeviceConfig>().swap(newConfigs);
    mSavedDeviceConfig.SetValue(localConfigs);
    mSavedDeviceConfig.SaveConfig();
    ReloadDeviceConfig();
}

void WifiSettings::ParseBackupJson(const std::string &backupInfo, std::string &key, std::string &iv,
    std::string &version)
{
    const std::string type = "detail";
    const std::string encryptionSymkey = "encryption_symkey";
    const std::string gcmParamsIv = "gcmParams_iv";
    const std::string apiVersion = "api_version";
    std::string keyStr;
    std::string ivStr;

    ParseJson(backupInfo, type, encryptionSymkey, keyStr);
    ParseJson(backupInfo, type, gcmParamsIv, ivStr);
    ParseJson(backupInfo, type, apiVersion, version);
    LOGI("ParseBackupJson version: %{public}s.", version.c_str());
    ConvertDecStrToHexStr(keyStr, key);
    std::fill(keyStr.begin(), keyStr.end(), 0);
    LOGI("ParseBackupJson key.size: %{public}d.", static_cast<int>(key.size()));
    ConvertDecStrToHexStr(ivStr, iv);
    LOGI("ParseBackupJson iv.size: %{public}d.", static_cast<int>(iv.size()));
}

int WifiSettings::GetConfigbyBackupXml(std::vector<WifiDeviceConfig> &deviceConfigs, UniqueFd &fd)
{
    const std::string wifiBackupXmlBegin = "<WifiBackupData>";
    const std::string wifiBackupXmlEnd = "</WifiBackupData>";
    struct stat statBuf;
    if (fd.Get() < 0 || fstat(fd.Get(), &statBuf) < 0) {
        LOGE("GetConfigbyBackupXml fstat fd fail.");
        return -1;
    }
    char *buffer = (char *)malloc(statBuf.st_size);
    if (buffer == nullptr) {
        LOGE("GetConfigbyBackupXml malloc fail.");
        return -1;
    }
    ssize_t bufferLen = read(fd.Get(), buffer, statBuf.st_size);
    if (bufferLen < 0) {
        LOGE("GetConfigbyBackupXml read fail.");
        free(buffer);
        buffer = nullptr;
        return -1;
    }
    std::string backupData = std::string(buffer, buffer + bufferLen);
    if (memset_s(buffer, statBuf.st_size, 0, statBuf.st_size) != EOK) {
        LOGE("GetConfigbyBackupXml memset_s fail.");
        free(buffer);
        buffer = nullptr;
        return -1;
    }
    free(buffer);
    buffer = nullptr;

    std::string wifiBackupXml;
    SplitStringBySubstring(backupData, wifiBackupXml, wifiBackupXmlBegin, wifiBackupXmlEnd);
    std::fill(backupData.begin(), backupData.end(), 0);
    std::unique_ptr<NetworkXmlParser> xmlParser = std::make_unique<NetworkXmlParser>();
    bool ret = xmlParser->LoadConfigurationMemory(wifiBackupXml.c_str());
    if (!ret) {
        LOGE("GetConfigbyBackupXml load fail");
        return -1;
    }
    ret = xmlParser->Parse();
    if (!ret) {
        LOGE("GetConfigbyBackupXml Parse fail");
        return -1;
    }
    deviceConfigs = xmlParser->GetNetworks();
    std::fill(wifiBackupXml.begin(), wifiBackupXml.end(), 0);
    return 0;
}

int WifiSettings::GetConfigbyBackupFile(std::vector<WifiDeviceConfig> &deviceConfigs, UniqueFd &fd,
    const std::string &key, const std::string &iv)
{
    if (key.size() == 0 || iv.size() == 0) {
        LOGE("GetConfigbyBackupFile key or iv is empty.");
        return -1;
    }
    struct stat statBuf;
    if (fd.Get() < 0 || fstat(fd.Get(), &statBuf) < 0) {
        LOGE("GetConfigbyBackupFile fstat fd fail.");
        return -1;
    }
    int destFd = open(BACKUP_CONFIG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (destFd < 0) {
        LOGE("GetConfigbyBackupFile open file fail.");
        return -1;
    }
    if (sendfile(destFd, fd.Get(), nullptr, statBuf.st_size) < 0) {
        LOGE("GetConfigbyBackupFile fd sendfile(size: %{public}d) to destFd fail.", static_cast<int>(statBuf.st_size));
        close(destFd);
        return -1;
    }
    close(destFd);

    WifiConfigFileImpl<WifiBackupConfig> wifiBackupConfig;
    wifiBackupConfig.SetConfigFilePath(BACKUP_CONFIG_FILE_PATH);
    wifiBackupConfig.SetEncryptionInfo(key, iv);
    wifiBackupConfig.LoadConfig();
    std::vector<WifiBackupConfig> backupConfigs;
    wifiBackupConfig.GetValue(backupConfigs);
    wifiBackupConfig.UnsetEncryptionInfo();

    for (const auto &backupCfg : backupConfigs) {
        WifiDeviceConfig config;
        ConvertBackupCfgToDeviceCfg(backupCfg, config);
        deviceConfigs.push_back(config);
    }
    return 0;
}
#endif
#ifdef FEATURE_ENCRYPTION_SUPPORT
bool WifiSettings::IsWifiDeviceConfigDeciphered(const WifiDeviceConfig &config) const
{
    int keyIndex = (config.wepTxKeyIndex < 0 || config.wepTxKeyIndex >= WEPKEYS_SIZE) ? 0 : config.wepTxKeyIndex;
    if (!config.preSharedKey.empty() || !config.wepKeys[keyIndex].empty() || !config.wifiEapConfig.password.empty()) {
        return true;
    }
    if (config.keyMgmt == KEY_MGMT_NONE) {
        return true;
    }
    return false;
}

void WifiSettings::DecryptionWapiConfig(const WifiEncryptionInfo &wifiEncryptionInfo, WifiDeviceConfig &config) const
{
    if (config.keyMgmt != KEY_MGMT_WAPI_CERT) {
        return;
    }
 
    EncryptedData *encryWapiAs = new EncryptedData(config.wifiWapiConfig.encryptedAsCertData,
        config.wifiWapiConfig.asCertDataIV);
    std::string decryWapiAs = "";
    if (WifiDecryption(wifiEncryptionInfo, *encryWapiAs, decryWapiAs) == HKS_SUCCESS) {
        config.wifiWapiConfig.wapiAsCertData = decryWapiAs;
    } else {
        WriteWifiEncryptionFailHiSysEvent(DECRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        config.wifiWapiConfig.wapiAsCertData = "";
    }
    delete encryWapiAs;
    encryWapiAs = nullptr;

    EncryptedData *encryWapiUser = new EncryptedData(config.wifiWapiConfig.encryptedUserCertData,
        config.wifiWapiConfig.userCertDataIV);
    std::string decryWapiUser = "";
    if (WifiDecryption(wifiEncryptionInfo, *encryWapiUser, decryWapiUser) == HKS_SUCCESS) {
        config.wifiWapiConfig.wapiUserCertData = decryWapiUser;
    } else {
        WriteWifiEncryptionFailHiSysEvent(DECRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        config.wifiWapiConfig.wapiUserCertData = "";
    }
    delete encryWapiUser;
    encryWapiUser = nullptr;
}

int WifiSettings::DecryptionDeviceConfig(WifiDeviceConfig &config)
{
    if (IsWifiDeviceConfigDeciphered(config)) {
        LOGD("DecryptionDeviceConfig IsWifiDeviceConfigDeciphered true");
        return 0;
    }
    WifiEncryptionInfo mWifiEncryptionInfo;
    mWifiEncryptionInfo.SetFile(GetTClassName<WifiDeviceConfig>());
    EncryptedData *encry = new EncryptedData(config.encryptedData, config.IV);
    std::string decry = "";
    if (WifiDecryption(mWifiEncryptionInfo, *encry, decry) == HKS_SUCCESS) {
        config.preSharedKey = decry;
    } else {
        WriteWifiEncryptionFailHiSysEvent(DECRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        config.preSharedKey = "";
        std::string().swap(config.preSharedKey);
    }
    delete encry;

    if (config.wepTxKeyIndex < 0 || config.wepTxKeyIndex >= WEPKEYS_SIZE) {
        config.wepTxKeyIndex = 0;
    }
    EncryptedData *encryWep = new EncryptedData(config.encryWepKeys[config.wepTxKeyIndex], config.IVWep);
    std::string decryWep = "";
    if (WifiDecryption(mWifiEncryptionInfo, *encryWep, decryWep) == HKS_SUCCESS) {
        config.wepKeys[config.wepTxKeyIndex] = decryWep;
    } else {
        WriteWifiEncryptionFailHiSysEvent(DECRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        config.wepKeys[config.wepTxKeyIndex] = "";
    }
    delete encryWep;
    encryWep = nullptr;

    EncryptedData *encryEap = new EncryptedData(config.wifiEapConfig.encryptedData, config.wifiEapConfig.IV);
    std::string decryEap = "";
    if (WifiDecryption(mWifiEncryptionInfo, *encryEap, decryEap) == HKS_SUCCESS) {
        config.wifiEapConfig.password = decryEap;
    } else {
        WriteWifiEncryptionFailHiSysEvent(DECRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        config.wifiEapConfig.password = "";
    }
    delete encryEap;
    encryEap = nullptr;
    DecryptionWapiConfig(mWifiEncryptionInfo, config);
    LOGD("DecryptionDeviceConfig end");
    return 0;
}

bool WifiSettings::EncryptionWapiConfig(const WifiEncryptionInfo &wifiEncryptionInfo, WifiDeviceConfig &config) const
{
    if (config.keyMgmt != KEY_MGMT_WAPI_CERT) {
        return true;
    }

    if (config.wifiWapiConfig.wapiAsCertData.empty() || config.wifiWapiConfig.wapiUserCertData.empty()) {
        LOGE("EncryptionDeviceConfig wapiCertData empty");
        return false;
    }

    config.wifiWapiConfig.encryptedAsCertData = "";
    config.wifiWapiConfig.asCertDataIV = "";

    EncryptedData encryWapiAs;
    if (WifiEncryption(wifiEncryptionInfo, config.wifiWapiConfig.wapiAsCertData, encryWapiAs) == HKS_SUCCESS) {
        config.wifiWapiConfig.encryptedAsCertData = encryWapiAs.encryptedPassword;
        config.wifiWapiConfig.asCertDataIV = encryWapiAs.IV;
    } else {
        LOGE("EncryptionDeviceConfig WifiEncryption wapiAsCertData failed");
        WriteWifiEncryptionFailHiSysEvent(ENCRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        return false;
    }

    config.wifiWapiConfig.encryptedUserCertData = "";
    config.wifiWapiConfig.userCertDataIV = "";

    EncryptedData encryWapiUser;
    if (WifiEncryption(wifiEncryptionInfo, config.wifiWapiConfig.wapiUserCertData, encryWapiUser) == HKS_SUCCESS) {
        config.wifiWapiConfig.encryptedUserCertData = encryWapiUser.encryptedPassword;
        config.wifiWapiConfig.userCertDataIV = encryWapiUser.IV;
    } else {
        LOGE("EncryptionDeviceConfig WifiEncryption wapiUserCertData failed");
        WriteWifiEncryptionFailHiSysEvent(ENCRYPTION_EVENT,
            SsidAnonymize(config.ssid), config.keyMgmt, STA_MOUDLE_EVENT);
        return false;
    }
    return true;
}

#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
void WifiSettings::ApplyCloudWifiConfig(const std::vector<WifiDeviceConfig> &newWifiDeviceConfigs,
    const std::set<int> &wifiLinkedNetworkIds, std::map<int, WifiDeviceConfig> &tempConfigs)
{
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (wifiLinkedNetworkIds.count(iter->second.networkId) != 0) {
            tempConfigs.emplace(std::make_pair(iter->second.networkId, iter->second));
            LOGI("UpdateWifiConfigFromCloud, connected network %{public}s", SsidAnonymize(iter->second.ssid).c_str());
            continue;
        }
        if (WifiAssetManager::GetInstance().IsWifiConfigUpdated(newWifiDeviceConfigs, iter->second)) {
#ifdef FEATURE_ENCRYPTION_SUPPORT
            EncryptionDeviceConfig(iter->second);
#endif
            LOGI("UpdateWifiConfigFromCloud, modify network %{public}s", SsidAnonymize(iter->second.ssid).c_str());
            tempConfigs.emplace(std::make_pair(iter->second.networkId, iter->second));
            continue;
        }
#ifdef FEATURE_ENCRYPTION_SUPPORT
        if (!IsWifiDeviceConfigDeciphered(iter->second)) {
            LOGI("UpdateWifiConfigFromCloud, encrypted network %{public}s", SsidAnonymize(iter->second.ssid).c_str());
            tempConfigs.emplace(std::make_pair(iter->second.networkId, iter->second));
            continue;
        }
#endif
        LOGI("UpdateWifiConfigFromCloud remove from cloud %{public}s", SsidAnonymize(iter->second.ssid).c_str());
    }
}

void WifiSettings::UpdateWifiConfigFromCloud(const std::vector<WifiDeviceConfig> &newWifiDeviceConfigs,
    const std::set<int> &wifiLinkedNetworkIds)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::map<int, WifiDeviceConfig> tempConfigs;
    ApplyCloudWifiConfig(newWifiDeviceConfigs, wifiLinkedNetworkIds, tempConfigs);
    for (auto iter : newWifiDeviceConfigs) {
        bool find = false;
        for (auto oriIter = mWifiDeviceConfig.begin(); oriIter != mWifiDeviceConfig.end(); oriIter++) {
            if (oriIter->second.ssid == iter.ssid && oriIter->second.keyMgmt == iter.keyMgmt) {
                find = true;
                break;
            }
        }
        if (find) {
            continue;
        }
        iter.networkId = mNetworkId;
        iter.version = 0;
#ifdef FEATURE_ENCRYPTION_SUPPORT
        EncryptionDeviceConfig(iter);
#endif
        LOGI("%{public}s networkId: %{public}d, ssid: %{public}s, keyMgmt: %{public}s, psksize: %{public}d",
            __FUNCTION__, iter.networkId, SsidAnonymize(iter.ssid).c_str(), iter.keyMgmt.c_str(),
            static_cast<int>((iter.preSharedKey).length()));
        tempConfigs.emplace(std::make_pair(iter.networkId, iter));
        mNetworkId++;
    }
    for (auto& iter : tempConfigs) {
        SetKeyMgmtBitset(iter.second);
    }
    mWifiDeviceConfig.swap(tempConfigs);
}

void WifiSettings::UpLoadLocalDeviceConfigToCloud()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    LOGI("UpLoadLocalDeviceConfigToCloud enter");
    std::vector<WifiDeviceConfig> tmp;
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
#ifdef FEATURE_ENCRYPTION_SUPPORT
        if (IsWifiDeviceConfigDeciphered(iter->second)) {
            tmp.push_back(iter->second);
        }
#else
        tmp.push_back(iter->second);
#endif
    }
    WifiAssetManager::GetInstance().WifiAssetAddPack(tmp, USER_ID_DEFAULT, true, true);
}
#endif

std::string WifiSettings::GetDefaultApSsid()
{
    std::string ssid;
#ifdef INIT_LIB_ENABLE
    std::string marketName = GetMarketName();
    std::string brandName = GetBrand();
    if (marketName.empty() || brandName.empty()) {
        LOGE("Get market name or brand name is empty");
        ssid = "OHOS_" + GetRandomStr(RANDOM_STR_LEN);
        return ssid;
    }
    brandName += " ";
    size_t pos = marketName.find(brandName);
    if (pos != std::string::npos) {
        ssid = marketName.substr(pos + brandName.length());
    } else {
        ssid = marketName;
    }

    if (ssid.empty()) {
        LOGE("ssid is empty and use random generation");
        ssid = "OHOS_" + GetRandomStr(RANDOM_STR_LEN);
        return ssid;
    }

    const std::string ellipsis = "...";
    if (ssid.length() > MAX_SSID_LEN) {
        LOGE("ssid is larger than 32, use ellipsis");
        ssid = ssid.substr(0, MAX_SSID_LEN - ellipsis.length()) + ellipsis;
    }
#else
    ssid = "OHOS_" + GetRandomStr(RANDOM_STR_LEN);
#endif
    return ssid;
}
}  // namespace Wifi
}  // namespace OHOS
