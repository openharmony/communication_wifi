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
#include "wifi_settings.h"
#include <algorithm>
#include <chrono>
#include "define.h"
#include "wifi_cert_utils.h"
#include "wifi_global_func.h"
#include "wifi_log.h"
#include "wifi_config_country_freqs.h"
#include <random>
#ifdef FEATURE_ENCRYPTION_SUPPORT
#include "wifi_encryption_util.h"
#endif
namespace OHOS {
namespace Wifi {
WifiSettings &WifiSettings::GetInstance()
{
    static WifiSettings gWifiSettings;
    return gWifiSettings;
}

WifiSettings::WifiSettings()
    : mWifiStaCapabilities(0),
      mWifiState(0),
      mScanAlwaysActive(false),
      mP2pState(static_cast<int>(P2pState::P2P_STATE_CLOSED)),
      mP2pDiscoverState(0),
      mP2pConnectState(0),
      mApMaxConnNum(0),
      mMaxNumConfigs(0),
      mLastSelectedNetworkId(-1),
      mLastSelectedTimeVal(0),
      mScreenState(MODE_STATE_OPEN),
      mAirplaneModeState(MODE_STATE_CLOSE),
      mAppRunningModeState(ScanMode::SYS_FOREGROUND_SCAN),
      mPowerSavingModeState(MODE_STATE_CLOSE),
      mFreezeModeState(MODE_STATE_CLOSE),
      mNoChargerPlugModeState(MODE_STATE_CLOSE),
      mHotspotIdleTimeout(HOTSPOT_IDLE_TIMEOUT_INTERVAL_MS),
      mLastDiscReason(DisconnectedReason::DISC_REASON_DEFAULT),
      explicitGroup(false)
{
    mHotspotState[0] = static_cast<int>(ApState::AP_STATE_CLOSED);
    powerModel[0] = PowerModel::GENERAL;
    mThermalLevel = static_cast<int>(ThermalLevel::NORMAL);
    mValidChannels.clear();
}

WifiSettings::~WifiSettings()
{
    SyncDeviceConfig();
    SyncHotspotConfig();
    SyncBlockList();
    SyncWifiP2pGroupInfoConfig();
    SyncP2pVendorConfig();
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    SyncWifiConfig();
}

void WifiSettings::InitWifiConfig()
{
    if (mSavedWifiConfig.LoadConfig() < 0) {
        return;
    }
    std::vector<WifiConfig> tmp;
    mSavedWifiConfig.GetValue(tmp);
    if (tmp.size() > 0) {
        mWifiConfig = tmp[0];
        mScanAlwaysActive = mWifiConfig.scanAlwaysSwitch;
    }
    return;
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
            InitDefaultHotspotConfig();
        }
    } else {
        InitDefaultHotspotConfig();
    }
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

int WifiSettings::Init()
{
    mCountryCode = "CN";
    InitSettingsNum();

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
    InitWifiConfig();
    ReloadDeviceConfig();
    InitHotspotConfig();
    InitP2pVendorConfig();
    ReloadWifiP2pGroupInfoConfig();
    InitScanControlInfo();
    ReloadTrustListPolicies();
    ReloadMovingFreezePolicy();
    ReloadStaRandomMac();
#ifdef FEATURE_ENCRYPTION_SUPPORT
    SetUpHks();
#endif
    IncreaseNumRebootsSinceLastUse();
    return 0;
}

int WifiSettings::GetWifiStaCapabilities() const
{
    return mWifiStaCapabilities;
}

int WifiSettings::SetWifiStaCapabilities(int capabilities)
{
    mWifiStaCapabilities = capabilities;
    return 0;
}

int WifiSettings::GetWifiState() const
{
    return mWifiState.load();
}

int WifiSettings::SetWifiState(int state)
{
    mWifiState = state;
    return 0;
}

bool WifiSettings::GetScanAlwaysState() const
{
    return mScanAlwaysActive.load();
}

int WifiSettings::SetScanAlwaysState(bool isActive)
{
    mScanAlwaysActive = isActive;
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scanAlwaysSwitch = isActive;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::SaveScanInfoList(const std::vector<WifiScanInfo> &results)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiScanInfoList = results;
    return 0;
}

int WifiSettings::GetScanInfoList(std::vector<WifiScanInfo> &results)
{
    struct timespec clkTime = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &clkTime);
    int64_t curr = static_cast<int64_t>(clkTime.tv_sec) * MSEC * MSEC + clkTime.tv_nsec / MSEC; /* us */
    std::unique_lock<std::mutex> lock(mInfoMutex);
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end(); ++iter) {
        if (iter->timestamp + WIFI_GET_SCAN_INFO_VALID_TIMESTAMP * MSEC * MSEC < curr) {
            continue;
        }
        results.push_back(*iter);
    }
    return 0;
}

int WifiSettings::SetWifiLinkedStandardAndMaxSpeed(WifiLinkedInfo &linkInfo)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end(); ++iter) {
        if (iter->bssid == linkInfo.bssid) {
            linkInfo.wifiStandard = iter->wifiStandard;
            linkInfo.maxSupportedRxLinkSpeed = iter->maxSupportedRxLinkSpeed;
            linkInfo.maxSupportedTxLinkSpeed = iter->maxSupportedTxLinkSpeed;
            break;
        }
    }
    return 0;
}

int WifiSettings::GetScanControlInfo(ScanControlInfo &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    info = mScanControlInfo;
    return 0;
}

int WifiSettings::GetP2pInfo(WifiP2pLinkedInfo &linkedInfo)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    linkedInfo = mWifiP2pInfo;
    return 0;
}

int WifiSettings::SaveP2pInfo(WifiP2pLinkedInfo &linkedInfo)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiP2pInfo = linkedInfo;
    return 0;
}

int WifiSettings::SetScanControlInfo(const ScanControlInfo &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mScanControlInfo = info;
    return 0;
}

int WifiSettings::AddDeviceConfig(const WifiDeviceConfig &config)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    auto iter = mWifiDeviceConfig.find(config.networkId);
    if (iter != mWifiDeviceConfig.end()) {
        iter->second = config;
    } else {
        mWifiDeviceConfig.emplace(std::make_pair(config.networkId, config));
    }
    return config.networkId;
}

int WifiSettings::RemoveDevice(int networkId)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter != mWifiDeviceConfig.end()) {
        if (!iter->second.wifiEapConfig.clientCert.empty()) {
            if (WifiCertUtils::UninstallCert(iter->second.wifiEapConfig.clientCert) != 0) {
                LOGE("uninstall cert %{public}s fail", iter->second.wifiEapConfig.clientCert.c_str());
            } else {
                LOGD("uninstall cert %{public}s success", iter->second.wifiEapConfig.clientCert.c_str());
            }
        }
        mWifiDeviceConfig.erase(iter);
    }
    return 0;
}

void WifiSettings::ClearDeviceConfig(void)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
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

int WifiSettings::GetDeviceConfig(std::vector<WifiDeviceConfig> &results)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGE("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        results.push_back(iter->second);
    }
    return 0;
}

int WifiSettings::GetDeviceConfig(const int &networkId, WifiDeviceConfig &config)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGE("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.networkId == networkId) {
            config = iter->second;
            return 0;
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &index, const int &indexType, WifiDeviceConfig &config)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGE("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index) {
                config = iter->second;
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index) {
                config = iter->second;
                return 0;
            }
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGE("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if ((iter->second.ssid == ssid) && (iter->second.keyMgmt == keymgmt)) {
            config = iter->second;
            return 0;
        }
    }
    return -1;
}

int WifiSettings::GetHiddenDeviceConfig(std::vector<WifiDeviceConfig> &results)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGE("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.hiddenSSID) {
            results.push_back(iter->second);
        }
    }
    return 0;
}

int WifiSettings::SetDeviceState(int networkId, int state, bool bSetOther)
{
    if (state < 0 || state >= (int)WifiDeviceConfigStatus::UNKNOWN) {
        return -1;
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    iter->second.status = state;
    if (bSetOther && state == (int)WifiDeviceConfigStatus::ENABLED) {
        for (iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); ++iter) {
            if (iter->first != networkId && iter->second.status == state) {
                iter->second.status = 1;
            }
        }
    }
    return 0;
}

int WifiSettings::SetDeviceAfterConnect(int networkId)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    LOGI("Set Device After Connect");
    iter->second.lastConnectTime = time(0);
    iter->second.numRebootsSinceLastUse = 0;
    iter->second.numAssociation++;
    return 0;
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

int WifiSettings::GetAllCandidateConfig(const int uid, std::vector<WifiDeviceConfig> &configs)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGE("Reload wifi config");
        ReloadDeviceConfig();
    }

    std::unique_lock<std::mutex> lock(mConfigMutex);
    bool found = false;
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.uid == uid) {
            configs.push_back(iter->second);
            found = true;
        }
    }
    return found ? 0 : -1;
}

int WifiSettings::SyncWifiP2pGroupInfoConfig()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mSavedWifiP2pGroupInfo.SetValue(mGroupInfoList);
    return mSavedWifiP2pGroupInfo.SaveConfig();
}

int WifiSettings::ReloadWifiP2pGroupInfoConfig()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (mSavedWifiP2pGroupInfo.LoadConfig()) {
        return -1;
    }
    mSavedWifiP2pGroupInfo.GetValue(mGroupInfoList);
    return 0;
}

int WifiSettings::SetWifiP2pGroupInfo(const std::vector<WifiP2pGroupInfo> &groups)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mGroupInfoList = groups;
    return 0;
}

int WifiSettings::IncreaseDeviceConnFailedCount(const std::string &index, const int &indexType, int count)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index) {
                iter->second.connFailedCount += count;
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index) {
                iter->second.connFailedCount += count;
                return 0;
            }
        }
    }
    return -1;
}

int WifiSettings::SetDeviceConnFailedCount(const std::string &index, const int &indexType, int count)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index) {
                iter->second.connFailedCount = count;
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index) {
                iter->second.connFailedCount = count;
                return 0;
            }
        }
    }
    return -1;
}

int WifiSettings::RemoveWifiP2pGroupInfo()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mGroupInfoList.clear();
    return 0;
}

int WifiSettings::GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    groups = mGroupInfoList;
    return 0;
}

int WifiSettings::IncreaseNumRebootsSinceLastUse()
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        iter->second.numRebootsSinceLastUse++;
    }
    return 0;
}

int WifiSettings::RemoveExcessDeviceConfigs(std::vector<WifiDeviceConfig> &configs) const
{
    int maxNumConfigs = mMaxNumConfigs;
    if (maxNumConfigs < 0) {
        return 1;
    }
    int numExcessNetworks = static_cast<int>(configs.size()) - maxNumConfigs;
    if (numExcessNetworks <= 0) {
        return 1;
    }
    LOGI("Remove %d configs", numExcessNetworks);
    sort(configs.begin(), configs.end(), [](WifiDeviceConfig a, WifiDeviceConfig b) {
        if (a.status != b.status) {
            return (a.status == 0) < (b.status == 0);
        } else if (a.lastConnectTime != b.lastConnectTime) {
            return a.lastConnectTime < b.lastConnectTime;
        } else if (a.numRebootsSinceLastUse != b.numRebootsSinceLastUse) {
            return a.numRebootsSinceLastUse > b.numRebootsSinceLastUse;
        } else if (a.numAssociation != b.numAssociation) {
            return a.numAssociation < b.numAssociation;
        } else {
            return a.networkId < b.networkId;
        }
    });
    configs.erase(configs.begin(), configs.begin() + numExcessNetworks);
    return 0;
}

int WifiSettings::SyncDeviceConfig()
{
#ifndef CONFIG_NO_CONFIG_WRITE
    std::unique_lock<std::mutex> lock(mConfigMutex);
    std::vector<WifiDeviceConfig> tmp;
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); ++iter) {
        if (!iter->second.isEphemeral) {
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

int WifiSettings::ReloadDeviceConfig()
{
#ifndef CONFIG_NO_CONFIG_WRITE
    int ret = mSavedDeviceConfig.LoadConfig();
    if (ret < 0) {
        deviceConfigLoadFlag.clear();
        LOGE("Loading device config failed: %{public}d", ret);
        return -1;
    }
    deviceConfigLoadFlag.test_and_set();
    std::vector<WifiDeviceConfig> tmp;
    mSavedDeviceConfig.GetValue(tmp);
    std::unique_lock<std::mutex> lock(mConfigMutex);
    mWifiDeviceConfig.clear();
    for (std::size_t i = 0; i < tmp.size(); ++i) {
        WifiDeviceConfig &item = tmp[i];
        item.networkId = i;
        mWifiDeviceConfig.emplace(item.networkId, item);
    }
    return 0;
#else
    std::unique_lock<std::mutex> lock(mConfigMutex);
    mWifiDeviceConfig.clear();
    return 0;
#endif
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
    std::unique_lock<std::mutex> lock(mConfigMutex);
    mWifiDeviceConfig.clear();
    mWifiDeviceConfig.emplace(0, config);
    for (std::size_t i = 0; i < tmp.size(); ++i) {
        WifiDeviceConfig &item = tmp[i];
        item.networkId = i + 1;
        mWifiDeviceConfig.emplace(item.networkId, item);
    }
    return 0;
}

int WifiSettings::GetIpInfo(IpInfo &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    info = mWifiIpInfo;
    return 0;
}

int WifiSettings::SaveIpInfo(const IpInfo &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiIpInfo = info;
    return 0;
}

int WifiSettings::GetIpv6Info(IpV6Info &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    info = mWifiIpV6Info;
    return 0;
}

int WifiSettings::SaveIpV6Info(const IpV6Info &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiIpV6Info = info;
    return 0;
}

int WifiSettings::GetLinkedInfo(WifiLinkedInfo &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    if (mWifiLinkedInfo.channelWidth == WifiChannelWidth::WIDTH_INVALID) {
        GetLinkedChannelWidth();
    }
    info = mWifiLinkedInfo;
    return 0;
}

int WifiSettings::SaveLinkedInfo(const WifiLinkedInfo &info)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    WifiChannelWidth channelWidth = mWifiLinkedInfo.channelWidth;
    std::string bssid = mWifiLinkedInfo.bssid;
    mWifiLinkedInfo = info;
    if (bssid == info.bssid) {
        mWifiLinkedInfo.channelWidth = channelWidth;
    }
    
    return 0;
}

int WifiSettings::SetMacAddress(const std::string &macAddress)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mMacAddress = macAddress;
    return 0;
}

int WifiSettings::GetMacAddress(std::string &macAddress)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    macAddress = mMacAddress;
    return 0;
}

int WifiSettings::ReloadStaRandomMac()
{
    if (mSavedWifiStoreRandomMac.LoadConfig()) {
        return -1;
    }
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiStoreRandomMac.clear();
    mSavedWifiStoreRandomMac.GetValue(mWifiStoreRandomMac);
    return 0;
}

const static uint32_t COMPARE_MAC_OFFSET = 2;
const static uint32_t COMPARE_MAC_LENGTH = 17 - 4;

bool CompareMac(const std::string &mac1, const std::string &mac2)
{
    return memcmp(mac1.c_str() + COMPARE_MAC_OFFSET, mac2.c_str() + COMPARE_MAC_OFFSET, COMPARE_MAC_LENGTH) == 0;
}

bool WifiSettings::AddRandomMac(WifiStoreRandomMac &randomMacInfo)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    bool isConnected = false;

    for (auto &ele : mWifiStoreRandomMac) {
        if ((randomMacInfo.ssid == ele.ssid) && (randomMacInfo.keyMgmt == ele.keyMgmt)) {
            ele.peerBssid = randomMacInfo.peerBssid;
            randomMacInfo.randomMac = ele.randomMac;
            isConnected = true;
            break;
        } else if (CompareMac(randomMacInfo.peerBssid, ele.peerBssid) && (randomMacInfo.keyMgmt == ele.keyMgmt) &&
                   (randomMacInfo.keyMgmt == "NONE")) {
            isConnected = false;
        } else if (CompareMac(randomMacInfo.peerBssid, ele.peerBssid) && (randomMacInfo.keyMgmt == ele.keyMgmt) &&
                   (randomMacInfo.keyMgmt != "NONE")) {
            ele.ssid = randomMacInfo.ssid;
            randomMacInfo.randomMac = ele.randomMac;
            isConnected = true;
        } else {
            isConnected = false;
        }
    }

    if (!isConnected) {
        mWifiStoreRandomMac.push_back(randomMacInfo);
    }

    mSavedWifiStoreRandomMac.SetValue(mWifiStoreRandomMac);
    mSavedWifiStoreRandomMac.SaveConfig();
    return isConnected;
}

bool WifiSettings::GetRandomMac(WifiStoreRandomMac &randomMacInfo)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto &item : mWifiStoreRandomMac) {
        if (CompareMac(item.peerBssid, randomMacInfo.peerBssid) && item.ssid == randomMacInfo.ssid) {
            randomMacInfo.randomMac = item.randomMac;
            return true;
        }
    }
    return false;
}

bool WifiSettings::RemoveRandomMac(const std::string &bssid, const std::string &randomMac)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto it = mWifiStoreRandomMac.begin(); it != mWifiStoreRandomMac.end(); it++) {
        if (CompareMac(it->peerBssid, bssid) && it->randomMac == randomMac) {
            mWifiStoreRandomMac.erase(it);
            mSavedWifiStoreRandomMac.SetValue(mWifiStoreRandomMac);
            mSavedWifiStoreRandomMac.SaveConfig();
            return true;
        }
    }
    return false;
}

int WifiSettings::SetCountryCode(const std::string &countryCode)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    std::string tmpCode = countryCode;
    std::transform(countryCode.begin(), countryCode.end(), tmpCode.begin(), ::toupper);
    mCountryCode = tmpCode;
    return 0;
}

int WifiSettings::GetCountryCode(std::string &countryCode)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    countryCode = mCountryCode;
    return 0;
}

int WifiSettings::GetHotspotState(int id)
{
    auto iter = mHotspotState.find(id);
    if (iter != mHotspotState.end()) {
        return iter->second.load();
    }
    mHotspotState[id] = static_cast<int>(ApState::AP_STATE_CLOSED);
    return mHotspotState[id].load();
}

int WifiSettings::SetHotspotState(int state, int id)
{
    mHotspotState[id] = state;
    return 0;
}

int WifiSettings::SetHotspotConfig(const HotspotConfig &config, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    mHotspotConfig[id] = config;
    return 0;
}

int WifiSettings::GetHotspotConfig(HotspotConfig &config, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mHotspotConfig.find(id);
    if (iter != mHotspotConfig.end()) {
        config = iter->second;
    }
    return 0;
}

int WifiSettings::SetHotspotIdleTimeout(int time)
{
    mHotspotIdleTimeout = time;
    return 0;
}

int WifiSettings::GetHotspotIdleTimeout() const
{
    return mHotspotIdleTimeout;
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

int WifiSettings::SyncP2pVendorConfig()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    std::vector<P2pVendorConfig> tmp;
    tmp.push_back(mP2pVendorConfig);
    mSavedWifiP2pVendorConfig.SetValue(tmp);
    return mSavedWifiP2pVendorConfig.SaveConfig();
}

int WifiSettings::GetStationList(std::vector<StationInfo> &results, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    for (auto iter = mConnectStationInfo.begin(); iter != mConnectStationInfo.end(); iter++) {
        results.push_back(iter->second);
    }
    return 0;
}

int WifiSettings::ManageStation(const StationInfo &info, int mode, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mConnectStationInfo.find(info.bssid);
    if (MODE_ADD == mode || MODE_UPDATE == mode) {
        if (iter != mConnectStationInfo.end()) {
            iter->second = info;
        } else {
            mConnectStationInfo.emplace(std::make_pair(info.bssid, info));
        }
    #ifdef SUPPORT_RANDOM_MAC_ADDR
        WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, info.bssid);
    #endif
    } else if (MODE_DEL == mode) {
        if (iter != mConnectStationInfo.end()) {
            mConnectStationInfo.erase(iter);
        }
    #ifdef SUPPORT_RANDOM_MAC_ADDR
        WifiMacAddrInfo randomMacAddrInfo;
        randomMacAddrInfo.bssid = info.bssid;
        randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
        WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, randomMacAddrInfo);

        WifiMacAddrInfo realMacAddrInfo;
        realMacAddrInfo.bssid = info.bssid;
        realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
        WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, realMacAddrInfo);
    #endif
    } else {
        return -1;
    }
    return 0;
}

int WifiSettings::FindConnStation(const StationInfo &info, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mConnectStationInfo.find(info.bssid);
    if (iter == mConnectStationInfo.end()) {
        return -1;
    }
    return 0;
}

int WifiSettings::ClearStationList(int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mConnectStationInfo.clear();
    return 0;
}

int WifiSettings::GetBlockList(std::vector<StationInfo> &results, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    for (auto iter = mBlockListInfo.begin(); iter != mBlockListInfo.end(); iter++) {
        results.push_back(iter->second);
    }
    return 0;
}

int WifiSettings::ManageBlockList(const StationInfo &info, int mode, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
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
    return 0;
}

int WifiSettings::SyncBlockList()
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    std::vector<StationInfo> tmp;
    for (auto iter = mBlockListInfo.begin(); iter != mBlockListInfo.end(); ++iter) {
        tmp.push_back(iter->second);
    }
    mSavedBlockInfo.SetValue(tmp);
    return mSavedBlockInfo.SaveConfig();
}

int WifiSettings::GetValidBands(std::vector<BandType> &bands)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);

    auto it = mValidChannels.find(BandType::BAND_2GHZ);
    if (it != mValidChannels.end() && it->second.size() > 0) {
        bands.push_back(BandType::BAND_2GHZ);
    }
    it = mValidChannels.find(BandType::BAND_5GHZ);
    if (it != mValidChannels.end() && it->second.size() > 0) {
        bands.push_back(BandType::BAND_5GHZ);
    }
    return 0;
}

int WifiSettings::SetValidChannels(const ChannelsTable &channelsInfo)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mValidChannels = channelsInfo;

    return 0;
}

int WifiSettings::GetValidChannels(ChannelsTable &channelsInfo)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    channelsInfo = mValidChannels;

    return 0;
}

int WifiSettings::ClearValidChannels()
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mValidChannels.clear();
    return 0;
}

int WifiSettings::SetPowerModel(const PowerModel& model, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto ret = powerModel.emplace(id, model);
    if (!ret.second) {
        powerModel[id] = model;
    }
    return 0;
}

int WifiSettings::GetPowerModel(PowerModel& model, int id)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = powerModel.find(id);
    if (iter != powerModel.end()) {
        model = iter->second;
    } else {
        powerModel[id] = PowerModel::GENERAL;
        model = powerModel[id];
    }
    return 0;
}

int WifiSettings::SetP2pState(int state)
{
    mP2pState = state;
    return 0;
}

int WifiSettings::GetP2pState()
{
    return mP2pState.load();
}

int WifiSettings::SetP2pDiscoverState(int state)
{
    mP2pDiscoverState = state;
    return 0;
}

int WifiSettings::GetP2pDiscoverState()
{
    return mP2pDiscoverState.load();
}

int WifiSettings::SetP2pConnectedState(int state)
{
    mP2pConnectState = state;
    return 0;
}

int WifiSettings::GetP2pConnectedState()
{
    return mP2pConnectState.load();
}

int WifiSettings::GetSignalLevel(const int &rssi, const int &band)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    int level = 0;
    do {
        if (band == static_cast<int>(BandType::BAND_2GHZ)) {
            if (rssi < mWifiConfig.firstRssiLevel2G) {
                break;
            }
            ++level;
            if (rssi < mWifiConfig.secondRssiLevel2G) {
                break;
            }
            ++level;
            if (rssi < mWifiConfig.thirdRssiLevel2G) {
                break;
            }
            ++level;
            if (rssi < mWifiConfig.fourthRssiLevel2G) {
                break;
            }
            ++level;
        }
        if (band == static_cast<int>(BandType::BAND_5GHZ)) {
            if (rssi < mWifiConfig.firstRssiLevel5G) {
                break;
            }
            ++level;
            if (rssi < mWifiConfig.secondRssiLevel5G) {
                break;
            }
            ++level;
            if (rssi < mWifiConfig.thirdRssiLevel5G) {
                break;
            }
            ++level;
            if (rssi < mWifiConfig.fourthRssiLevel5G) {
                break;
            }
            ++level;
        }
    } while (0);
    return level;
}

int WifiSettings::GetApMaxConnNum()
{
    return mApMaxConnNum;
}

void WifiSettings::InitDefaultHotspotConfig()
{
    HotspotConfig cfg;
    cfg.SetSecurityType(KeyMgmt::WPA_PSK);
    cfg.SetBand(BandType::BAND_2GHZ);
    cfg.SetChannel(AP_CHANNEL_DEFAULT);
    cfg.SetMaxConn(GetApMaxConnNum());
    cfg.SetSsid("OHOS_" + GetRandomStr(RANDOM_STR_LEN));
    cfg.SetPreSharedKey("12345678");
    auto ret = mHotspotConfig.emplace(0, cfg);
    if (!ret.second) {
        mHotspotConfig[0] = cfg;
    }
}

void WifiSettings::InitDefaultP2pVendorConfig()
{
    mP2pVendorConfig.SetRandomMacSupport(false);
    mP2pVendorConfig.SetIsAutoListen(false);
    mP2pVendorConfig.SetDeviceName("");
    mP2pVendorConfig.SetPrimaryDeviceType("");
    mP2pVendorConfig.SetSecondaryDeviceType("");
}

void WifiSettings::InitSettingsNum()
{
    /* query drivers capability, support max connection num. */
    mApMaxConnNum = MAX_AP_CONN;
    mMaxNumConfigs = MAX_CONFIGS_NUM;
}

void WifiSettings::InitScanControlForbidList(void)
{
    /* Disable external scanning during scanning. */
    ScanForbidMode forbidMode;
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_SCANNING;
    mScanControlInfo.scanForbidList.push_back(forbidMode);

    /* Disable external scanning when the screen is shut down. */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_SCREEN_OFF;
    mScanControlInfo.scanForbidList.push_back(forbidMode);

    /* Disable all scans in connection */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanControlInfo.scanForbidList.push_back(forbidMode);

    /* Deep sleep disables all scans. */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanControlInfo.scanForbidList.push_back(forbidMode);

    /* PNO scanning disabled */
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTED;
    mScanControlInfo.scanForbidList.push_back(forbidMode);
    return;
}

void WifiSettings::InitScanControlIntervalList(void)
{
    /* Foreground app: 4 times in 2 minutes for a single application */
    ScanIntervalMode scanIntervalMode;
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_ORIGIN;
    scanIntervalMode.scanMode = ScanMode::APP_FOREGROUND_SCAN;
    scanIntervalMode.isSingle = true;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = FOREGROUND_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = FOREGROUND_SCAN_CONTROL_TIMES;
    mScanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* Backend apps: once every 30 minutes */
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_ORIGIN;
    scanIntervalMode.scanMode = ScanMode::APP_BACKGROUND_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = BACKGROUND_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = BACKGROUND_SCAN_CONTROL_TIMES;
    mScanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* no charger plug */
    /* All app: If the scanning interval is less than 5s for five  */
    /* consecutive times, the scanning can be performed only after */
    /* the scanning interval is greater than 5s. */
    const int frequencyContinueInterval = 5;
    const int frequencyContinueCount = 5;
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_CUSTOM;
    scanIntervalMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_CONTINUE;
    scanIntervalMode.interval = frequencyContinueInterval;
    scanIntervalMode.count = frequencyContinueCount;
    mScanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* no charger plug */
    /* Single app: If all scanning interval in 10 times is less than */
    /* the threshold (20s), the app is added to the blocklist and  */
    /* cannot initiate scanning. */
    const int frequencyBlocklistInterval = 20;
    const int frequencyBlocklistCount = 10;
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_CUSTOM;
    scanIntervalMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    scanIntervalMode.isSingle = true;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_BLOCKLIST;
    scanIntervalMode.interval = frequencyBlocklistInterval;
    scanIntervalMode.count = frequencyBlocklistCount;
    mScanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* PNO scanning every 20 seconds */
    scanIntervalMode.scanScene = SCAN_SCENE_ALL;
    scanIntervalMode.scanMode = ScanMode::PNO_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = PNO_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = PNO_SCAN_CONTROL_TIMES;
    mScanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /*
     * The system scans for 20 seconds, multiplies 2 each time,
     * and performs scanning every 160 seconds.
     */
    scanIntervalMode.scanScene = SCAN_SCENE_ALL;
    scanIntervalMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_EXP;
    scanIntervalMode.interval = SYSTEM_TIMER_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = SYSTEM_TIMER_SCAN_CONTROL_TIMES;
    mScanControlInfo.scanIntervalList.push_back(scanIntervalMode);
    return;
}

void WifiSettings::InitScanControlInfo()
{
    InitScanControlForbidList();
    InitScanControlIntervalList();
}

void WifiSettings::GetLinkedChannelWidth()
{
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end(); ++iter) {
        if (iter->bssid == mWifiLinkedInfo.bssid) {
            mWifiLinkedInfo.channelWidth = iter->channelWidth;
            return;
        }
    }
    LOGE("WifiSettings GetLinkedChannelWidth failed.");
}

void WifiSettings::UpdateLinkedChannelWidth(const std::string bssid, WifiChannelWidth channelWidth)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    if (bssid == mWifiLinkedInfo.bssid) {
        mWifiLinkedInfo.channelWidth = channelWidth;
    }
}

bool WifiSettings::EnableNetwork(int networkId, bool disableOthers)
{
    if (disableOthers) {
        SetUserLastSelectedNetworkId(networkId);
    }
    return true;
}

void WifiSettings::SetUserLastSelectedNetworkId(int networkId)
{
    mLastSelectedNetworkId = networkId;
    mLastSelectedTimeVal = time(NULL);
}

int WifiSettings::GetUserLastSelectedNetworkId()
{
    return mLastSelectedNetworkId;
}

time_t WifiSettings::GetUserLastSelectedNetworkTimeVal()
{
    return mLastSelectedTimeVal;
}

int WifiSettings::SyncWifiConfig()
{
    std::vector<WifiConfig> tmp;
    tmp.push_back(mWifiConfig);
    mSavedWifiConfig.SetValue(tmp);
    return mSavedWifiConfig.SaveConfig();
}

int WifiSettings::GetOperatorWifiType()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.staAirplaneMode;
}

int WifiSettings::SetOperatorWifiType(int type)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.staAirplaneMode = type;
    SyncWifiConfig();
    return 0;
}

bool WifiSettings::GetCanOpenStaWhenAirplaneMode()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.canOpenStaWhenAirplane;
}

bool WifiSettings::GetStaLastRunState()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.staLastState;
}

int WifiSettings::SetStaLastRunState(bool bRun)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.staLastState = bRun;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetDhcpIpType()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.dhcpIpType;
}

int WifiSettings::SetDhcpIpType(int dhcpIpType)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.dhcpIpType = dhcpIpType;
    SyncWifiConfig();
    return 0;
}

std::string WifiSettings::GetDefaultWifiInterface()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.defaultWifiInterface;
}

void WifiSettings::SetScreenState(const int &state)
{
    mScreenState = state;
}

int WifiSettings::GetScreenState() const
{
    return mScreenState;
}

void WifiSettings::SetAirplaneModeState(const int &state)
{
    mAirplaneModeState = state;
}

int WifiSettings::GetAirplaneModeState() const
{
    return mAirplaneModeState.load();
}

void WifiSettings::SetAppRunningState(ScanMode appRunMode)
{
    if (static_cast<int>(appRunMode) < static_cast<int>(ScanMode::APP_FOREGROUND_SCAN) ||
        static_cast<int>(appRunMode) > static_cast<int>(ScanMode::SYS_BACKGROUND_SCAN)) {
        return;
    }
    mAppRunningModeState = appRunMode;
}

ScanMode WifiSettings::GetAppRunningState() const
{
    return mAppRunningModeState;
}

void WifiSettings::SetPowerSavingModeState(const int &state)
{
    mPowerSavingModeState = state;
}

int WifiSettings::GetPowerSavingModeState() const
{
    return mPowerSavingModeState;
}

void WifiSettings::SetAppPackageName(const std::string &appPackageName)
{
    mAppPackageName = appPackageName;
}

const std::string WifiSettings::GetAppPackageName() const
{
    return mAppPackageName;
}

void WifiSettings::SetFreezeModeState(int state)
{
    mFreezeModeState = state;
}

int WifiSettings::GetFreezeModeState() const
{
    return mFreezeModeState;
}

void WifiSettings::SetNoChargerPlugModeState(int state)
{
    mNoChargerPlugModeState = state;
}

int WifiSettings::GetNoChargerPlugModeState() const
{
    return mNoChargerPlugModeState;
}

int WifiSettings::SetWhetherToAllowNetworkSwitchover(bool bSwitch)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.whetherToAllowNetworkSwitchover = bSwitch;
    SyncWifiConfig();
    return 0;
}

bool WifiSettings::GetWhetherToAllowNetworkSwitchover()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.whetherToAllowNetworkSwitchover;
}

int WifiSettings::SetScoretacticsScoreSlope(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsScoreSlope = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsScoreSlope()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsScoreSlope;
}

int WifiSettings::SetScoretacticsInitScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsInitScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsInitScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsInitScore;
}

int WifiSettings::SetScoretacticsSameBssidScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsSameBssidScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsSameBssidScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsSameBssidScore;
}

int WifiSettings::SetScoretacticsSameNetworkScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsSameNetworkScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsSameNetworkScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsSameNetworkScore;
}

int WifiSettings::SetScoretacticsFrequency5GHzScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsFrequency5GHzScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsFrequency5GHzScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsFrequency5GHzScore;
}

int WifiSettings::SetScoretacticsLastSelectionScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsLastSelectionScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsLastSelectionScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsLastSelectionScore;
}

int WifiSettings::SetScoretacticsSecurityScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsSecurityScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsSecurityScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsSecurityScore;
}

int WifiSettings::SetScoretacticsNormalScore(const int &score)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scoretacticsNormalScore = score;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetScoretacticsNormalScore()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scoretacticsNormalScore;
}

int WifiSettings::SetSavedDeviceAppraisalPriority(const int &priority)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.savedDeviceAppraisalPriority = priority;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetSavedDeviceAppraisalPriority()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.savedDeviceAppraisalPriority;
}

bool WifiSettings::IsModulePreLoad(const std::string &name)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    if (name == WIFI_SERVICE_STA) {
        return mWifiConfig.preLoadSta;
    } else if (name == WIFI_SERVICE_SCAN) {
        return mWifiConfig.preLoadScan;
    } else if (name == WIFI_SERVICE_AP) {
        return mWifiConfig.preLoadAp;
    } else if (name == WIFI_SERVICE_P2P) {
        return mWifiConfig.preLoadP2p;
    } else if (name == WIFI_SERVICE_AWARE) {
        return mWifiConfig.preLoadAware;
    } else if (name == WIFI_SERVICE_ENHANCE) {
        return mWifiConfig.preLoadEnhance;
    } else {
        return false;
    }
}

bool WifiSettings::GetSupportHwPnoFlag()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.supportHwPnoFlag;
}

int WifiSettings::GetMinRssi2Dot4Ghz()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.minRssi2Dot4Ghz;
}

int WifiSettings::GetMinRssi5Ghz()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.minRssi5Ghz;
}

std::string WifiSettings::GetStrDnsBak()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.strDnsBak;
}

bool WifiSettings::IsLoadStabak()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.isLoadStabak;
}

int WifiSettings::SetRealMacAddress(const std::string &macAddress)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.realMacAddress = macAddress;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::GetRealMacAddress(std::string &macAddress)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    macAddress = mWifiConfig.realMacAddress;
    return 0;
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

const std::vector<TrustListPolicy> WifiSettings::ReloadTrustListPolicies()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
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
    std::unique_lock<std::mutex> lock(mStaMutex);
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
        return mFPolicy;
    }
    return mMovingFreezePolicy.GetValue()[0];
}

std::string WifiSettings::GetConnectTimeoutBssid()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    const int timeout = 30; // 30s
    if (mBssidToTimeoutTime.second - static_cast<int>(time(0)) > timeout) {
        return "";
    }
    return mBssidToTimeoutTime.first;
}

int WifiSettings::SetConnectTimeoutBssid(std::string &bssid)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    time_t now = time(0);
    mBssidToTimeoutTime = std::make_pair(bssid, static_cast<int>(now));
    return 0;
}

void WifiSettings::SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies)
{
    std::string countryCode;
    if (GetCountryCode(countryCode)) {
        return;
    }

    for (auto& item : g_countryDefaultFreqs) {
        if (item.countryCode == countryCode && item.band == band) {
            frequencies = item.freqs;
        }
    }
}

void WifiSettings::SetExplicitGroup(bool isExplicit)
{
    explicitGroup = isExplicit;
}

bool WifiSettings::IsExplicitGroup(void)
{
    return explicitGroup;
}

void WifiSettings::SetThermalLevel(const int &level)
{
    mThermalLevel = level;
}

int WifiSettings::GetThermalLevel() const
{
    return mThermalLevel;
}

void WifiSettings::SetThreadStatusFlag(bool state)
{
    if (state) {
        mThreadStartTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    mThreadStatusFlag_ = state;
}

bool WifiSettings::GetThreadStatusFlag(void) const
{
    return mThreadStatusFlag_;
}

uint64_t WifiSettings::GetThreadStartTime(void) const
{
    return mThreadStartTime;
}

void WifiSettings::SaveDisconnectedReason(DisconnectedReason discReason)
{
    mLastDiscReason = discReason;
}

int WifiSettings::GetDisconnectedReason(DisconnectedReason &discReason) const
{
    discReason = mLastDiscReason;
    return 0;
}

void WifiSettings::SetScanOnlySwitchState(const int &state)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.scanOnlySwitch = state;
    SyncWifiConfig();
}

int WifiSettings::GetScanOnlySwitchState()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scanOnlySwitch;
}

bool WifiSettings::CheckScanOnlyAvailable()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.scanOnlySwitch && (MODE_STATE_CLOSE == mAirplaneModeState);
}

int WifiSettings::GetStaApExclusionType()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig.staApExclusionType;
}

int WifiSettings::SetStaApExclusionType(int type)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig.staApExclusionType = type;
    SyncWifiConfig();
    return 0;
}
#ifdef SUPPORT_RANDOM_MAC_ADDR
static std::string GetPairMacAddress(std::map<WifiMacAddrInfo,
    std::string>& macAddrInfoMap, const WifiMacAddrInfo &macAddrInfo)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        LOGI("find the record, realMacAddr:%{public}s, bssidType:%{public}d, randomMacAddr:%{public}s",
            macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        return iter->second;
    }
    return "";
}

static void InsertMacAddrPairs(std::map<WifiMacAddrInfo,
    std::string>& macAddrInfoMap, const WifiMacAddrInfo &macAddrInfo, std::string& randomMacAddr)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        LOGI("find the record, realMacAddr:%{public}s, bssidType:%{public}d, randomMacAddr:%{public}s",
            macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, randomMacAddr.c_str());
        return;
    } else {
        macAddrInfoMap.insert(std::make_pair(macAddrInfo, randomMacAddr));
    }
}

static void DelMacAddrPairs(std::map<WifiMacAddrInfo, std::string>& macAddrInfoMap, const WifiMacAddrInfo &macAddrInfo)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        if (iter->second.empty()) {
            LOGI("invalid record, bssid:%{public}s, bssidType:%{public}d",
                iter->first.bssid.c_str(), iter->first.bssidType);
        } else {
            LOGI("find the record, realMacAddr:%{public}s, bssidType:%{public}d, randomMacAddr:%{public}s",
                macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        }
        macAddrInfoMap.erase(iter);
    }
}

void WifiSettings::GenerateRandomMacAddress(std::string peerBssid, std::string &randomMacAddr)
{
    LOGI("enter GenerateRandomMacAddress");
    constexpr int arraySize = 4;
    constexpr int macBitSize = 12;
    constexpr int firstBit = 1;
    constexpr int lastBit = 11;
    constexpr int two = 2;
    constexpr int hexBase = 16;
    constexpr int octBase = 8;
    int ret = 0;
    char strMacTmp[arraySize] = {0};
    std::mt19937_64 gen(std::chrono::high_resolution_clock::now().time_since_epoch().count()
        + std::hash<std::string>{}(peerBssid));
    for (int i = 0; i < macBitSize; i++) {
        if (i != firstBit) {
            std::uniform_int_distribution<> distribution(0, hexBase - 1);
            ret = sprintf_s(strMacTmp, arraySize, "%x", distribution(gen));
        } else {
            std::uniform_int_distribution<> distribution(0, octBase - 1);
            ret = sprintf_s(strMacTmp, arraySize, "%x", two * distribution(gen));
        }
        if (ret == -1) {
            LOGE("GenerateRandomMacAddress failed, sprintf_s return -1!");
        }
        randomMacAddr += strMacTmp;
        if ((i % two) != 0 && (i != lastBit)) {
            randomMacAddr.append(":");
        }
    }
    LOGI("exit GenerateRandomMacAddress, randomMacAddr:%{public}s", randomMacAddr.c_str());
}

bool WifiSettings::StoreWifiMacAddrPairInfo(WifiMacAddrInfoType type, const std::string &realMacAddr)
{
    if (realMacAddr.empty()) {
        LOGE("invalid mac address");
        return false;
    }

    if (type >= WifiMacAddrInfoType::INVALID_MACADDR_INFO) {
        LOGE("invalid mac address");
        return false;
    }
    std::string randomMacAddr;
    WifiSettings::GetInstance().GenerateRandomMacAddress(realMacAddr, randomMacAddr);
    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = realMacAddr;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
    WifiSettings::GetInstance().AddMacAddrPairs(type, realMacAddrInfo, randomMacAddr);

    WifiMacAddrInfo randomMacAddrInfo;
    randomMacAddrInfo.bssid = randomMacAddr;
    randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
    WifiSettings::GetInstance().AddMacAddrPairs(type, randomMacAddrInfo, realMacAddr);
    return true;
}

int WifiSettings::AddMacAddrPairs(WifiMacAddrInfoType type,
    const WifiMacAddrInfo &macAddrInfo, std::string randomMacAddr)
{
    if ((type >= WifiMacAddrInfoType::INVALID_MACADDR_INFO) || macAddrInfo.bssid.empty()) {
        LOGE("invalid parameter, type:%{public}d, bssid:%{public}s", type, macAddrInfo.bssid.c_str());
        return -1;
    }
    LOGI("add a mac address pair, type:%{public}d, bssid:%{public}s, bssidType:%{public}d, randomMacAddr:%{public}s",
        type, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, randomMacAddr.c_str());
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            InsertMacAddrPairs(mWifiScanMacAddrPair, macAddrInfo, randomMacAddr);
            break;
        case WifiMacAddrInfoType::WIFI_DEVICE_CONFIG_MACADDR_INFO:
            InsertMacAddrPairs(mDeviceConfigMacAddrPair, macAddrInfo, randomMacAddr);
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            InsertMacAddrPairs(mHotspotMacAddrPair, macAddrInfo, randomMacAddr);
            break;
        case WifiMacAddrInfoType::P2P_MACADDR_INFO:
            InsertMacAddrPairs(mP2pMacAddrPair, macAddrInfo, randomMacAddr);
            break;
        default:
            LOGE("invalid mac address type, type:%{public}d", type);
            return -1;
    }
    return 0;
}

int WifiSettings::RemoveMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo)
{
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            DelMacAddrPairs(mWifiScanMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::WIFI_DEVICE_CONFIG_MACADDR_INFO:
            DelMacAddrPairs(mDeviceConfigMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            DelMacAddrPairs(mHotspotMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_MACADDR_INFO:
            DelMacAddrPairs(mP2pMacAddrPair, macAddrInfo);
            break;
        default:
            LOGE("invalid mac address type, type:%{public}d", type);
            return -1;
    }
    return 0;
}

std::string WifiSettings::GetMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo)
{
    LOGI("AddMacAddrPairs, type:%{public}d, bssid:%{public}s, bssidType:%{public}d",
        type, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            return GetPairMacAddress(mWifiScanMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::WIFI_DEVICE_CONFIG_MACADDR_INFO:
            return GetPairMacAddress(mDeviceConfigMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            return GetPairMacAddress(mHotspotMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_MACADDR_INFO:
            return GetPairMacAddress(mP2pMacAddrPair, macAddrInfo);
        default:
            LOGE("invalid mac address type, type:%{public}d", type);
            return "";
    }
    return "";
}
#endif
}  // namespace Wifi
}  // namespace OHOS
