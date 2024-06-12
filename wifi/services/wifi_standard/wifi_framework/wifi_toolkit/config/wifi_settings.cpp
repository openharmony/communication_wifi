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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "wifi_settings.h"
#include <algorithm>
#include <chrono>
#include "define.h"
#include "wifi_cert_utils.h"
#include "wifi_common_util.h"
#include "wifi_global_func.h"
#include "wifi_log.h"
#include "wifi_config_country_freqs.h"
#include <random>
#ifdef FEATURE_ENCRYPTION_SUPPORT
#include "wifi_encryption_util.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "wifi_country_code_define.h"
#include "network_parser.h"
#include "softap_parser.h"
#endif
#ifdef INIT_LIB_ENABLE
#include "parameter.h"
#endif

namespace OHOS {
namespace Wifi {
WifiSettings &WifiSettings::GetInstance()
{
    static WifiSettings gWifiSettings;
    return gWifiSettings;
}

WifiSettings::WifiSettings()
    : mNetworkId(0),
      mWifiStaCapabilities(0),
      mWifiStoping(false),
      mSoftapToggled(false),
      mIsSupportCoex(false),
      mStaIfaceName("wlan0"),
#ifdef HDI_CHIP_INTERFACE_SUPPORT
      mP2pIfaceName("p2p0"),
#else
      mP2pIfaceName("p2p-dev-wlan0"),
#endif
      mApIfaceName("wlan0"),
      mP2pState(static_cast<int>(P2pState::P2P_STATE_CLOSED)),
      mP2pDiscoverState(0),
      mP2pConnectState(0),
      mApMaxConnNum(0),
      mMaxNumConfigs(0),
      mScreenState(MODE_STATE_DEFAULT),
      mScanGenieState(MODE_STATE_OPEN),
      mAirplaneModeState(MODE_STATE_CLOSE),
      mPowerSleepState(MODE_STATE_CLOSE),
      mAppRunningModeState(ScanMode::SYS_FOREGROUND_SCAN),
      mPowerSavingModeState(MODE_STATE_CLOSE),
      mFreezeModeState(MODE_STATE_CLOSE),
      mNoChargerPlugModeState(MODE_STATE_CLOSE),
      mHotspotIdleTimeout(HOTSPOT_IDLE_TIMEOUT_INTERVAL_MS),
      explicitGroup(false)
{
    mWifiState[0] = static_cast<int>(WifiState::DISABLED);
    IpInfo ipInfo;
    mWifiIpInfo[0] = ipInfo;
    IpV6Info ipv6Info;
    mWifiIpV6Info[0] = ipv6Info;
    WifiLinkedInfo wifiLinkedInfo;
    mWifiLinkedInfo[0] = wifiLinkedInfo;
    mMacAddress[0] = "";
    mHotspotState[0] = static_cast<int>(ApState::AP_STATE_CLOSED);
    mLastSelectedNetworkId[0] = -1;
    mLastSelectedTimeVal[0] = 0;
    powerModel[0] = PowerModel::GENERAL;
    mBssidToTimeoutTime[0] = std::make_pair("", 0);
    mLastDiscReason[0] = DisconnectedReason::DISC_REASON_DEFAULT;
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
    /* init block list info */
    if (mSavedBlockInfo.LoadConfig() >= 0) {
        std::vector<StationInfo> tmp;
        mSavedBlockInfo.GetValue(tmp);
        for (std::size_t i = 0; i < tmp.size(); ++i) {
            StationInfo &item = tmp[i];
            mBlockListInfo.emplace(item.bssid, item);
        }
    }

    /* init softap random mac info */
    if (mSavedApRandomMac.LoadConfig() >= 0) {
        std::vector<SoftApRandomMac> tmp;
        mSavedApRandomMac.GetValue(tmp);
        if (tmp.size() > 0) {
            for (std::size_t i = 0; i < tmp.size(); i++) {
                mApRandomMac[i] = tmp[i];
            }
        }
    }
    return;
}

int WifiSettings::GetApRandomMac(SoftApRandomMac &randomMac, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApRandomMac.find(id);
    if (iter != mApRandomMac.end()) {
        randomMac = iter->second;
    }
    return 0;
}

int WifiSettings::SetApRandomMac(const SoftApRandomMac &randomMac, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    if (id > AP_INSTANCE_MAX_NUM) {
        LOGE("Id is larger than AP_INSTANCE_MAX_NUM");
        return -1;
    }

    mApRandomMac[id] =  randomMac;

    std::vector<SoftApRandomMac> tmp;
    for (auto iter : mApRandomMac) {
        tmp.push_back(iter.second);
    }

    mSavedApRandomMac.SetValue(tmp);
    mSavedApRandomMac.SaveConfig();
    return 0;
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

void WifiSettings::InitPackageFilterConfig()
{
    if (mPackageFilterConfig.LoadConfig() >= 0) {
        std::vector<PackageFilterConf> tmp;
        mPackageFilterConfig.GetValue(tmp);
        for (int i = 0; i < tmp.size(); i++) {
            mFilterMap.insert(std::make_pair(tmp[i].filterName, tmp[i].packageList));
        }
    }
    return;
}

int WifiSettings::ReloadPortalconf()
{
    if (mSavedPortal.LoadConfig() >= 0) {
        std::vector<WifiPortalConf> tmp;
        mSavedPortal.GetValue(tmp);
        if (tmp.size() > 0) {
            mPortalUri = tmp[0];
        } else {
            mPortalUri.portalHttpUrl = "test";
        }
    } else {
        mPortalUri.portalHttpUrl = "test";
    }
    return 0;
}

int WifiSettings::Init()
{
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
    mSavedPortal.SetConfigFilePath(PORTAL_CONFIG_FILE_PATH);
    mPackageFilterConfig.SetConfigFilePath(PACKAGE_FILTER_CONFIG_FILE_PATH);
    mSavedApRandomMac.SetConfigFilePath(WIFI_SOFTAP_RANDOM_MAC_FILE_PATH);
#ifndef OHOS_ARCH_LITE
    MergeWifiConfig();
    MergeSoftapConfig();
#endif
#ifdef FEATURE_ENCRYPTION_SUPPORT
    SetUpHks();
#endif
    InitWifiConfig();
    ReloadDeviceConfig();
    InitHotspotConfig();
    InitP2pVendorConfig();
    ReloadWifiP2pGroupInfoConfig();
    InitScanControlInfo();
    ReloadTrustListPolicies();
    ReloadMovingFreezePolicy();
    ReloadStaRandomMac();
    ReloadPortalconf();
    InitPackageFilterConfig();
    ClearLocalHid2dInfo();
    IncreaseNumRebootsSinceLastUse();
    mPersistWifiState = GetPersistWifiState();
    mAirplaneModeState.store(GetLastAirplaneMode());
    return 0;
}

#ifndef OHOS_ARCH_LITE
void WifiSettings::MergeWifiConfig()
{
    if (std::filesystem::exists(WIFI_CONFIG_FILE_PATH) || std::filesystem::exists(DEVICE_CONFIG_FILE_PATH)
        || std::filesystem::exists(WIFI_STA_RANDOM_MAC_FILE_PATH)) {
        LOGI("file exists don't need to merge");
        return;
    }
    if (!std::filesystem::exists(DUAL_WIFI_CONFIG_FILE_PATH)) {
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
    std::vector<WifiStoreRandomMac> wifiStoreRandomMac = xmlParser->GetRandomMacmap();
    mSavedWifiStoreRandomMac.SetValue(wifiStoreRandomMac);
    mSavedWifiStoreRandomMac.SaveConfig();
}

void WifiSettings::MergeSoftapConfig()
{
    if (std::filesystem::exists(WIFI_CONFIG_FILE_PATH) || std::filesystem::exists(HOTSPOT_CONFIG_FILE_PATH)) {
        LOGI("MergeSoftapConfig file exists don't need to merge");
        return;
    }
    if (!std::filesystem::exists(DUAL_SOFTAP_CONFIG_FILE_PATH)) {
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

void WifiSettings::MergeWifiCloneConfig(std::string &cloneData)
{
    LOGI("MergeWifiCloneConfig enter");
    std::unique_ptr<NetworkXmlParser> xmlParser = std::make_unique<NetworkXmlParser>();
    bool ret = xmlParser->LoadConfigurationMemory(cloneData.c_str());
    if (!ret) {
        LOGE("MergeWifiCloneConfig load fail");
        return;
    }
    ret = xmlParser->Parse();
    if (!ret) {
        LOGE("MergeWifiCloneConfig Parse fail");
        return;
    }
    std::vector<WifiDeviceConfig> cloneConfigs = xmlParser->GetNetworks();
    if (cloneConfigs.empty()) {
        return;
    }
    ConfigsDeduplicateAndSave(cloneConfigs);
}

void WifiSettings::ConfigsDeduplicateAndSave(std::vector<WifiDeviceConfig> &newConfigs)
{
    if (newConfigs.size() == 0) {
        LOGE("NewConfigs is empty!");
        return;
    }

#ifdef FEATURE_ENCRYPTION_SUPPORT
    for (auto &config : newConfigs) {
        EncryptionDeviceConfig(config);
    }
#endif

    mSavedDeviceConfig.LoadConfig();
    std::vector<WifiDeviceConfig> localConfigs;
    mSavedDeviceConfig.GetValue(localConfigs);

    std::set<std::string> tmp;
    for (const auto &localConfig : localConfigs) {
        std::string configKey = localConfig.ssid + localConfig.keyMgmt;
        tmp.insert(configKey);
    }
    for (auto &config : newConfigs) {
        std::string configKey = config.ssid + config.keyMgmt;
        auto iter = tmp.find(configKey);
        if (iter == tmp.end()) {
            tmp.insert(configKey);
            localConfigs.push_back(config);
        }
    }

    mSavedDeviceConfig.SetValue(localConfigs);
    mSavedDeviceConfig.SaveConfig();
    ReloadDeviceConfig();
}
#endif

int WifiSettings::GetWifiStaCapabilities() const
{
    return mWifiStaCapabilities;
}

int WifiSettings::SetWifiStaCapabilities(int capabilities)
{
    mWifiStaCapabilities = capabilities;
    return 0;
}

int WifiSettings::GetWifiState(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiState.find(instId);
    if (iter != mWifiState.end()) {
        return iter->second.load();
    }
    mWifiState[instId] = static_cast<int>(WifiState::DISABLED);
    return mWifiState[instId].load();
}

int WifiSettings::SetWifiState(int state, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiState[instId] = state;
    return 0;
}

bool WifiSettings::HasWifiActive()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    for (auto &item : mWifiState) {
        int state = item.second.load();
        if (state == static_cast<int>(WifiState::ENABLING) || state == static_cast<int>(WifiState::ENABLED)) {
            LOGD("HasWifiActive: one wifi is active! instId:%{public}d", item.first);
            return true;
        }
    }
    LOGD("HasWifiActive: No wifi is active!");
    return false;
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

int WifiSettings::SetScanAlwaysState(bool isActive, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scanAlwaysSwitch = isActive;
    SyncWifiConfig();
    return 0;
}

int WifiSettings::SaveScanInfoList(const std::vector<WifiScanInfo> &results)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiScanInfoList = results;
    return 0;
}

int WifiSettings::ClearScanInfoList()
{
    if (HasWifiActive()) {
        return 0;
    }
    std::unique_lock<std::mutex> lock(mInfoMutex);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO);
#endif
    mWifiScanInfoList.clear();
    return 0;
}

void WifiSettings::InsertWifi6BlackListCache(const std::string currentBssid,
    const Wifi6BlackListInfo wifi6BlackListInfo)
{
    std::unique_lock<std::mutex> lock(mWifiSelfcureMutex);
    auto iter = wifi6BlackListCache.find(currentBssid);
    if (iter != wifi6BlackListCache.end()) {
        iter->second = wifi6BlackListInfo;
    } else {
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));
    }
}

void WifiSettings::RemoveWifi6BlackListCache(const std::string bssid)
{
    std::unique_lock<std::mutex> lock(mWifiSelfcureMutex);
    if (wifi6BlackListCache.find(bssid) != wifi6BlackListCache.end()) {
        wifi6BlackListCache.erase(bssid);
    } else {
        LOGE("%{public}s: don't exist wifi bla list, bssid: %{public}s", __func__, MacAnonymize(bssid).c_str());
        return;
    }
}

int WifiSettings::GetWifi6BlackListCache(std::map<std::string, Wifi6BlackListInfo> &blackListCache) const
{
    blackListCache = wifi6BlackListCache;
    return 0;
}

void WifiSettings::SetWifiToggledState(bool state)
{
    std::unique_lock<std::mutex> lock(mWifiToggledMutex);

    if (state) {
        if (GetAirplaneModeState() == MODE_STATE_OPEN) {
            SetWifiFlagOnAirplaneMode(true);
            PersistWifiState(WIFI_STATE_ENABLED_AIRPLANEMODE_OVERRIDE);
        } else {
            PersistWifiState(WIFI_STATE_ENABLED);
        }
    } else {
        if (GetAirplaneModeState() == MODE_STATE_OPEN) {
            SetWifiFlagOnAirplaneMode(false);
        }
        PersistWifiState(WIFI_STATE_DISABLED);
    }
}

void WifiSettings::PersistWifiState(int state)
{
    mPersistWifiState = state;
    SetOperatorWifiType(state);
    LOGI("persist wifi state is %{public}d", state);
}

int WifiSettings::GetPersistWifiState()
{
    return GetOperatorWifiType();
}

bool WifiSettings::IsWifiToggledEnable()
{
    if (GetAirplaneModeState() == MODE_STATE_OPEN) {
        return mPersistWifiState == WIFI_STATE_ENABLED_AIRPLANEMODE_OVERRIDE;
    } else {
        return mPersistWifiState != WIFI_STATE_DISABLED;
    }
}

void WifiSettings::SetSoftapToggledState(bool state)
{
    std::unique_lock<std::mutex> lock(mSoftapToggledMutex);
    mSoftapToggled = state;
}

bool WifiSettings::GetSoftapToggledState() const
{
    return mSoftapToggled;
}

void WifiSettings::SetWifiStopState(bool state)
{
    std::unique_lock<std::mutex> lock(mWifiStopMutex);
    mWifiStoping = state;
}

bool WifiSettings::GetWifiStopState() const
{
    return mWifiStoping;
}

void WifiSettings::SetCoexSupport(bool isSupport)
{
    mIsSupportCoex = isSupport;
}

bool WifiSettings::GetCoexSupport() const
{
    return mIsSupportCoex;
}

void WifiSettings::SetStaIfaceName(const std::string &ifaceName)
{
    std::unique_lock<std::mutex> lock(mWifiToggledMutex);
    mStaIfaceName = ifaceName;
}

std::string WifiSettings::GetStaIfaceName()
{
    std::unique_lock<std::mutex> lock(mWifiToggledMutex);
    return mStaIfaceName;
}

void WifiSettings::SetP2pIfaceName(const std::string &ifaceName)
{
    std::unique_lock<std::mutex> lock(mWifiToggledMutex);
    mP2pIfaceName = ifaceName;
}

std::string WifiSettings::GetP2pIfaceName()
{
    std::unique_lock<std::mutex> lock(mWifiToggledMutex);
    return mP2pIfaceName;
}

void WifiSettings::SetApIfaceName(const std::string &ifaceName)
{
    std::unique_lock<std::mutex> lock(mSoftapToggledMutex);
    mApIfaceName = ifaceName;
}

std::string WifiSettings::GetApIfaceName()
{
    std::unique_lock<std::mutex> lock(mSoftapToggledMutex);
    return mApIfaceName;
}

int WifiSettings::GetScanInfoList(std::vector<WifiScanInfo> &results)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end(); ) {
        if (iter->disappearCount >= WIFI_DISAPPEAR_TIMES) {
        #ifdef SUPPORT_RANDOM_MAC_ADDR
            WifiSettings::GetInstance().RemoveMacAddrPairInfo(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
                iter->bssid);
        #endif
            LOGI("ScanInfo remove ssid=%{public}s bssid=%{public}s.\n",
                SsidAnonymize(iter->ssid).c_str(), MacAnonymize(iter->bssid).c_str());
            iter = mWifiScanInfoList.erase(iter);
            continue;
        }
        results.push_back(*iter);
        ++iter;
    }
    LOGI("WifiSettings::GetScanInfoList size = %{public}zu", results.size());
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

int WifiSettings::GetScanControlInfo(ScanControlInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mScanControlInfo.find(instId);
    if (iter != mScanControlInfo.end()) {
        info = iter->second;
    }
    return 0;
}

int WifiSettings::GetPackageFilterMap(std::map<std::string, std::vector<std::string>> &filterMap)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    filterMap = mFilterMap;
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

int WifiSettings::SetScanControlInfo(const ScanControlInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mScanControlInfo[instId] = info;
    return 0;
}

#ifdef FEATURE_ENCRYPTION_SUPPORT
bool WifiSettings::IsWifiDeviceConfigDeciphered(const WifiDeviceConfig &config) const
{
    
    int keyIndex = (config.wepTxKeyIndex < 0 || config.wepTxKeyIndex >= WEPKEYS_SIZE) ? 0 : config.wepTxKeyIndex;
    if (!config.preSharedKey.empty() || !config.wepKeys[keyIndex].empty() || !config.wifiEapConfig.password.empty()) {
        return true;
    }

    return false;
}

int WifiSettings::DecryptionDeviceConfig(WifiDeviceConfig &config)
{
    if (IsWifiDeviceConfigDeciphered(config)) {
        LOGI("DecryptionDeviceConfig IsWifiDeviceConfigDeciphered true");
        return 0;
    }
    LOGI("DecryptionDeviceConfig start");
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
    LOGI("DecryptionDeviceConfig end");
    return 0;
}
#endif

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
    config.version = 1;
#endif
    return true;
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
        LOGD("Reload wifi config");
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
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if (iter->second.networkId == networkId) {
            config = iter->second;
#ifdef FEATURE_ENCRYPTION_SUPPORT
            DecryptionDeviceConfig(config);
#endif
            return 0;
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &index, const int &indexType, WifiDeviceConfig &config)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    if (indexType == DEVICE_CONFIG_INDEX_SSID) {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.ssid == index) {
                config = iter->second;
#ifdef FEATURE_ENCRYPTION_SUPPORT
                DecryptionDeviceConfig(config);
#endif
                return 0;
            }
        }
    } else {
        for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
            if (iter->second.bssid == index) {
                config = iter->second;
#ifdef FEATURE_ENCRYPTION_SUPPORT
                DecryptionDeviceConfig(config);
#endif
                return 0;
            }
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if ((iter->second.ssid == ssid) && (iter->second.keyMgmt == keymgmt)) {
            config = iter->second;
#ifdef FEATURE_ENCRYPTION_SUPPORT
            DecryptionDeviceConfig(config);
#endif
            return 0;
        }
    }
    return -1;
}

int WifiSettings::GetDeviceConfig(const std::string &ancoCallProcessName, const std::string &ssid,
    const std::string &keymgmt, WifiDeviceConfig &config)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
        ReloadDeviceConfig();
    }
    if (ancoCallProcessName.empty()) {
        LOGD("anco do not deal with");
        return -1;
    }
    std::unique_lock<std::mutex> lock(mConfigMutex);
    for (auto iter = mWifiDeviceConfig.begin(); iter != mWifiDeviceConfig.end(); iter++) {
        if ((iter->second.ssid == ssid) && (iter->second.keyMgmt == keymgmt) &&
            iter->second.ancoCallProcessName == ancoCallProcessName) {
            config = iter->second;
#ifdef FEATURE_ENCRYPTION_SUPPORT
            DecryptionDeviceConfig(config);
#endif
            return 0;
        }
    }
    return -1;
}

int WifiSettings::GetHiddenDeviceConfig(std::vector<WifiDeviceConfig> &results)
{
    if (!deviceConfigLoadFlag.test_and_set()) {
        LOGD("Reload wifi config");
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
    LOGD("Set Device After Connect");
    iter->second.lastConnectTime = time(0);
    iter->second.numRebootsSinceLastUse = 0;
    iter->second.numAssociation++;
    return 0;
}

int WifiSettings::SetDeviceRandomizedMacSuccessEver(int networkId)
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
    auto iter = mWifiDeviceConfig.find(networkId);
    if (iter == mWifiDeviceConfig.end()) {
        return -1;
    }
    iter->second.randomizedMacSuccessEver = true;
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
        LOGD("Reload wifi config");
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

void WifiSettings::SetCurrentP2pGroupInfo(const WifiP2pGroupInfo &group)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    m_P2pGroupInfo = group;
}

WifiP2pGroupInfo WifiSettings::GetCurrentP2pGroupInfo()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    return m_P2pGroupInfo;
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

int WifiSettings::RemoveWifiP2pSupplicantGroupInfo()
{
    if (!std::filesystem::exists(P2P_SUPPLICANT_CONFIG_FILE)) {
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
    std::stringstream removeConfig;
    int maxIndex = numExcessNetworks > MAX_CONFIGS_NUM ? MAX_CONFIGS_NUM : numExcessNetworks;
    for (int i = 0; i < maxIndex; i++) {
        removeConfig << SsidAnonymize(configs[i].ssid) << ",";
    }
    LOGI("saved config size greater than %{public}d, remove ssid(print up to 1000)=%{public}s",
        maxNumConfigs, removeConfig.str().c_str());
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

void WifiSettings::EncryptionWifiDeviceConfigOnBoot()
{
#ifdef FEATURE_ENCRYPTION_SUPPORT
    std::unique_lock<std::mutex> lock(mConfigOnBootMutex);
    mSavedDeviceConfig.LoadConfig();
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

int WifiSettings::ReloadDeviceConfig()
{
#ifndef CONFIG_NO_CONFIG_WRITE
    int ret = mSavedDeviceConfig.LoadConfig();
    if (ret < 0) {
        deviceConfigLoadFlag.clear();
        LOGD("Loading device config failed: %{public}d", ret);
        return -1;
    }
    deviceConfigLoadFlag.test_and_set();
    std::vector<WifiDeviceConfig> tmp;
    mSavedDeviceConfig.GetValue(tmp);
    std::unique_lock<std::mutex> lock(mConfigMutex);
    mNetworkId = 0;
    mWifiDeviceConfig.clear();
    for (std::size_t i = 0; i < tmp.size(); ++i) {
        WifiDeviceConfig &item = tmp[i];
        item.networkId = mNetworkId++;
        mWifiDeviceConfig.emplace(item.networkId, item);
    }
    if (!mEncryptionOnBootFalg.test_and_set()) {
        mWifiEncryptionThread = std::make_unique<WifiEventHandler>("WifiEncryptionThread");
        mWifiEncryptionThread->PostAsyncTask([this]() {
            LOGI("ReloadDeviceConfig EncryptionWifiDeviceConfigOnBoot start.");
            EncryptionWifiDeviceConfigOnBoot();
        });
    }
    return 0;
#else
    std::unique_lock<std::mutex> lock(mConfigMutex);
    mWifiDeviceConfig.clear();
    return 0;
#endif
}

int WifiSettings::GetNextNetworkId()
{
    std::unique_lock<std::mutex> lock(mConfigMutex);
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
    std::unique_lock<std::mutex> lock(mConfigMutex);
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

int WifiSettings::GetIpInfo(IpInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mWifiIpInfo.find(instId);
    if (iter != mWifiIpInfo.end()) {
        info = iter->second;
    }
    return 0;
}

int WifiSettings::SaveIpInfo(const IpInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiIpInfo[instId] = info;
    return 0;
}

int WifiSettings::GetIpv6Info(IpV6Info &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mWifiIpV6Info.find(instId);
    if (iter != mWifiIpV6Info.end()) {
        info = iter->second;
    }
    return 0;
}

int WifiSettings::SaveIpV6Info(const IpV6Info &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    mWifiIpV6Info[instId] = info;
    return 0;
}

std::map<int, WifiLinkedInfo> WifiSettings::GetAllWifiLinkedInfo()
{
    return mWifiLinkedInfo;
}

int WifiSettings::GetLinkedInfo(WifiLinkedInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mWifiLinkedInfo.find(instId);
    if (iter != mWifiLinkedInfo.end()) {
        UpdateLinkedInfo(instId);
        info = iter->second;
    }
    return 0;
}

int WifiSettings::SaveLinkedInfo(const WifiLinkedInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mWifiLinkedInfo.find(instId);
    if (iter != mWifiLinkedInfo.end()) {
        WifiChannelWidth channelWidth = iter->second.channelWidth;
        std::string bssid = iter->second.bssid;
        iter->second = info;
        if (bssid == info.bssid) {
            iter->second.channelWidth = channelWidth;
        }
    }

    return 0;
}

int WifiSettings::SetMacAddress(const std::string &macAddress, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mMacAddress[instId] = macAddress;
    return 0;
}

int WifiSettings::GetMacAddress(std::string &macAddress, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mMacAddress.find(instId);
    if (iter != mMacAddress.end()) {
        macAddress = iter->second;
    }
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

void WifiSettings::ClearRandomMacConfig()
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiStoreRandomMac.clear();
    mSavedWifiStoreRandomMac.SetValue(mWifiStoreRandomMac);
    mSavedWifiStoreRandomMac.SaveConfig();
    LOGI("Clear RandomMacConfig");
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
                   (randomMacInfo.keyMgmt == KEY_MGMT_WPA_PSK)) {
            ele.ssid = randomMacInfo.ssid;
            randomMacInfo.randomMac = ele.randomMac;
            isConnected = true;
            break;
        } else if (randomMacInfo.peerBssid == ele.peerBssid && (randomMacInfo.keyMgmt == ele.keyMgmt) &&
                   (randomMacInfo.keyMgmt != KEY_MGMT_WPA_PSK)) {
            isConnected = true;
            break;
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
        if (item.ssid != randomMacInfo.ssid || randomMacInfo.keyMgmt != item.keyMgmt) {
            continue;
        }
        if (randomMacInfo.keyMgmt == KEY_MGMT_WPA_PSK && CompareMac(item.peerBssid, randomMacInfo.peerBssid)) {
            randomMacInfo.randomMac = item.randomMac;
            return true;
        }
        if (item.peerBssid == randomMacInfo.peerBssid) {
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
        WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO,
            info.bssid, "");
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
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO);
#endif
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

int WifiSettings::SetHid2dUpperScene(const std::string& ifName, const Hid2dUpperScene &scene)
{
    LOGD("SetHid2dUpperScene ifName: %{public}s", ifName.c_str());
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mUpperIfName = ifName;
    mUpperScene = scene;
    return 0;
}

int WifiSettings::GetHid2dUpperScene(std::string& ifName, Hid2dUpperScene &scene)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    scene = mUpperScene;
    ifName = mUpperIfName;
    return 0;
}

int WifiSettings::SetP2pBusinessType(const P2pBusinessType &type)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    mP2pBusinessType = type;
    return 0;
}

int WifiSettings::GetP2pBusinessType(P2pBusinessType &type)
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    type = mP2pBusinessType;
    return 0;
}

void WifiSettings::ClearLocalHid2dInfo()
{
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (strstr(mUpperIfName.c_str(), "chba") == NULL) {
        mUpperScene.mac = "";
        mUpperScene.scene = 0;
        mUpperScene.fps = 0;
        mUpperScene.bw = 0;
        mUpperIfName = "";
    }

    mP2pBusinessType = P2pBusinessType::INVALID;
}

void WifiSettings::SetPowerIdelState(const int &state)
{
    mIdelState = state;
}

int WifiSettings::GetPowerIdelState() const
{
    return mIdelState;
}

void WifiSettings::SetGnssFixState(const int &state)
{
    mGnssFixState = state;
}

int WifiSettings::GetGnssFixState() const
{
    return mGnssFixState;
}

void WifiSettings::SetAbnormalApps(const std::vector<std::string> &abnormalAppList)
{
    mAbnormalAppList = abnormalAppList;
}

int WifiSettings::GetAbnormalApps(std::vector<std::string> &abnormalAppList)
{
    abnormalAppList = mAbnormalAppList;
    return 0;
}

void WifiSettings::SetScanGenieState(const int &state)
{
    mScanGenieState = state;
}

int WifiSettings::GetScanGenieState() const
{
    return mScanGenieState;
}

int WifiSettings::GetSignalLevel(const int &rssi, const int &band, int instId)
{
    LOGI("GetSignalLevel wifi settings start...");
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
    LOGI("GetSignalLevel wifi settings end...");
    return level;
}

int WifiSettings::GetApMaxConnNum()
{
    return mApMaxConnNum;
}

void WifiSettings::InitDefaultHotspotConfig()
{
    HotspotConfig cfg;
#ifdef INIT_LIB_ENABLE
    std::string ssid = GetMarketName();
#endif
    cfg.SetSecurityType(KeyMgmt::WPA2_PSK);
    cfg.SetBand(BandType::BAND_2GHZ);
    cfg.SetChannel(AP_CHANNEL_DEFAULT);
    cfg.SetMaxConn(GetApMaxConnNum());
    cfg.SetBandWidth(AP_BANDWIDTH_DEFAULT);
#ifdef INIT_LIB_ENABLE
    cfg.SetSsid(ssid);
#else
    cfg.SetSsid("OHOS_" + GetRandomStr(RANDOM_STR_LEN));
#endif
    cfg.SetPreSharedKey(GetRandomStr(RANDOM_PASSWD_LEN));
    auto ret = mHotspotConfig.emplace(0, cfg);
    if (!ret.second) {
        mHotspotConfig[0] = cfg;
    }
}

void WifiSettings::ClearHotspotConfig()
{
    mHotspotConfig.clear();
    HotspotConfig config;
#ifdef INIT_LIB_ENABLE
    std::string ssid = GetMarketName();
#endif
    config.SetSecurityType(KeyMgmt::WPA2_PSK);
    config.SetBand(BandType::BAND_2GHZ);
    config.SetChannel(AP_CHANNEL_DEFAULT);
    config.SetMaxConn(GetApMaxConnNum());
    config.SetBandWidth(AP_BANDWIDTH_DEFAULT);
#ifdef INIT_LIB_ENABLE
    config.SetSsid(ssid);
#else
    config.SetSsid("OHOS_" + GetRandomStr(RANDOM_STR_LEN));
#endif
    config.SetPreSharedKey(GetRandomStr(RANDOM_PASSWD_LEN));
    auto ret = mHotspotConfig.emplace(0, config);
    if (!ret.second) {
        mHotspotConfig[0] = config;
    }
}

std::string WifiSettings::GetConnectedBssid(int instId)
{
    WifiLinkedInfo linkedInfo;
    GetLinkedInfo(linkedInfo, instId);
    if (linkedInfo.connState == ConnState::CONNECTED) {
        return linkedInfo.bssid;
    }
    return "";
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
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);

    /* Disable external scanning when the screen is shut down. */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_SCREEN_OFF;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);

    /* Disable all scans in connection */
#ifdef SUPPORT_SCAN_CONTROL
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_ASSOCIATING;
    forbidMode.forbidTime = ASSOCIATING_SCAN_CONTROL_INTERVAL;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_ASSOCIATED;
    forbidMode.forbidTime = ASSOCIATED_SCAN_CONTROL_INTERVAL;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_OBTAINING_IP;
    forbidMode.forbidCount = OBTAINING_IP_SCAN_CONTROL_TIMES;
    forbidMode.forbidTime = OBTAINING_IP_SCAN_CONTROL_INTERVAL;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
#else
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
#endif
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);

    /* Deep sleep disables all scans. */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);

    /* PNO scanning disabled */
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTED;
    mScanControlInfo[0].scanForbidList.push_back(forbidMode);
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
    mScanControlInfo[0].scanIntervalList.push_back(scanIntervalMode);

    /* Backend apps: once every 30 minutes */
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_ORIGIN;
    scanIntervalMode.scanMode = ScanMode::APP_BACKGROUND_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = BACKGROUND_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = BACKGROUND_SCAN_CONTROL_TIMES;
    mScanControlInfo[0].scanIntervalList.push_back(scanIntervalMode);

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
    mScanControlInfo[0].scanIntervalList.push_back(scanIntervalMode);

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
    mScanControlInfo[0].scanIntervalList.push_back(scanIntervalMode);

    /* PNO scanning every 20 seconds */
    scanIntervalMode.scanScene = SCAN_SCENE_ALL;
    scanIntervalMode.scanMode = ScanMode::PNO_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = PNO_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = PNO_SCAN_CONTROL_TIMES;
    mScanControlInfo[0].scanIntervalList.push_back(scanIntervalMode);

    /*
     * The system scans for 20 seconds, multiplies 2 each time,
     * and performs scanning every 160 seconds.
     */
    scanIntervalMode.scanScene = SCAN_SCENE_ALL;
    scanIntervalMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_EXP;
    scanIntervalMode.interval = SYSTEM_TIMER_SCAN_CONTROL_INTERVAL;
#ifdef SUPPORT_SCAN_CONTROL
    scanIntervalMode.count = 0;
#else
    scanIntervalMode.count = SYSTEM_TIMER_SCAN_CONTROL_TIMES;
#endif
    mScanControlInfo[0].scanIntervalList.push_back(scanIntervalMode);
    return;
}

void WifiSettings::InitScanControlInfo()
{
    InitScanControlForbidList();
    InitScanControlIntervalList();
}

void WifiSettings::GetLinkedChannelWidth(int instId)
{
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end(); ++iter) {
        if (iter->bssid == mWifiLinkedInfo[instId].bssid) {
            mWifiLinkedInfo[instId].channelWidth = iter->channelWidth;
            return;
        }
    }
    LOGD("WifiSettings GetLinkedChannelWidth failed.");
}

void WifiSettings::UpdateLinkedChannelWidth(const std::string bssid, WifiChannelWidth channelWidth, int instId)
{
    std::unique_lock<std::mutex> lock(mInfoMutex);
    auto iter = mWifiLinkedInfo.find(instId);
    if (iter != mWifiLinkedInfo.end()) {
        if (bssid == iter->second.bssid) {
            iter->second.channelWidth = channelWidth;
        }
    }
}

void WifiSettings::UpdateLinkedInfo(int instId)
{
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end(); ++iter) {
        if (iter->bssid == mWifiLinkedInfo[instId].bssid) {
            if (mWifiLinkedInfo[instId].channelWidth == WifiChannelWidth::WIDTH_INVALID) {
                mWifiLinkedInfo[instId].channelWidth = iter->channelWidth;
            }
            mWifiLinkedInfo[instId].supportedWifiCategory = iter->supportedWifiCategory;
            mWifiLinkedInfo[instId].isHiLinkNetwork = iter->isHiLinkNetwork;
            return;
        }
    }
    LOGD("WifiSettings UpdateLinkedInfo failed.");
}

bool WifiSettings::EnableNetwork(int networkId, bool disableOthers, int instId)
{
    if (disableOthers) {
        SetUserLastSelectedNetworkId(networkId, instId);
    }
    return true;
}

void WifiSettings::SetUserLastSelectedNetworkId(int networkId, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mLastSelectedNetworkId[instId] = networkId;
    mLastSelectedTimeVal[instId] = time(NULL);
}

int WifiSettings::GetUserLastSelectedNetworkId(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mLastSelectedNetworkId.find(instId);
    if (iter != mLastSelectedNetworkId.end()) {
        return iter->second;
    }
    return -1;
}

time_t WifiSettings::GetUserLastSelectedNetworkTimeVal(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mLastSelectedTimeVal.find(instId);
    if (iter != mLastSelectedTimeVal.end()) {
        return iter->second;
    }
    return 0;
}

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

bool WifiSettings::GetStaLastRunState(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.staLastState;
    }
    return mWifiConfig[0].staLastState;
}

int WifiSettings::SetStaLastRunState(bool bRun, int instId)
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

int WifiSettings::SetDhcpIpType(int dhcpIpType, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].dhcpIpType = dhcpIpType;
    SyncWifiConfig();
    return 0;
}

std::string WifiSettings::GetDefaultWifiInterface(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.defaultWifiInterface;
    }
    return mWifiConfig[0].defaultWifiInterface;
}

void WifiSettings::SetScreenState(const int &state)
{
    mScreenState = state;
}

int WifiSettings::GetScreenState() const
{
    return mScreenState;
}

bool WifiSettings::SetWifiStateOnAirplaneChanged(const int &state)
{
    mAirplaneModeState = state;
    SetLastAirplaneMode(state);
    if (GetWifiFlagOnAirplaneMode()) {
        if (state == MODE_STATE_OPEN && mPersistWifiState == WIFI_STATE_ENABLED) {
            PersistWifiState(WIFI_STATE_ENABLED_AIRPLANEMODE_OVERRIDE);
        } else if (state == MODE_STATE_CLOSE && mPersistWifiState == WIFI_STATE_ENABLED_AIRPLANEMODE_OVERRIDE) {
            PersistWifiState(WIFI_STATE_ENABLED);
        }
        if (mPersistWifiState == WIFI_STATE_DISABLED || mPersistWifiState ==  WIFI_STATE_DISABLED_AIRPLANEMODE_ON) {
            return true;
        }
        return false;
    }
    if (state == MODE_STATE_OPEN) {
        if (mPersistWifiState == WIFI_STATE_ENABLED) {
            PersistWifiState(WIFI_STATE_DISABLED_AIRPLANEMODE_ON);
        }
    } else {
        if (mPersistWifiState == WIFI_STATE_DISABLED_AIRPLANEMODE_ON
            || mPersistWifiState == WIFI_STATE_ENABLED_AIRPLANEMODE_OVERRIDE) {
            PersistWifiState(WIFI_STATE_ENABLED);
        }
    }
    return true;
}

int WifiSettings::GetAirplaneModeState() const
{
    return mAirplaneModeState.load();
}

void WifiSettings::SetPowerSleepState(const int &state)
{
    mPowerSleepState = state;
}

int WifiSettings::GetPowerSleepState() const
{
    return mPowerSleepState.load();
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

int WifiSettings::SetWhetherToAllowNetworkSwitchover(bool bSwitch, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].whetherToAllowNetworkSwitchover = bSwitch;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsScoreSlope(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsScoreSlope = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsInitScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsInitScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsSameBssidScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsSameBssidScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsSameNetworkScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsSameNetworkScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsFrequency5GHzScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsFrequency5GHzScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsLastSelectionScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsLastSelectionScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsSecurityScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsSecurityScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetScoretacticsNormalScore(const int &score, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[instId].scoretacticsNormalScore = score;
    SyncWifiConfig();
    return 0;
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

int WifiSettings::SetSavedDeviceAppraisalPriority(const int &priority, int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[0].savedDeviceAppraisalPriority = priority;
    SyncWifiConfig();
    return 0;
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

std::string WifiSettings::GetStrDnsBak(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.strDnsBak;
    }
    return mWifiConfig[0].strDnsBak;
}

bool WifiSettings::IsLoadStabak(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.isLoadStabak;
    }
    return mWifiConfig[0].isLoadStabak;
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

std::string WifiSettings::GetConnectTimeoutBssid(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mBssidToTimeoutTime.find(instId);
    if (iter != mBssidToTimeoutTime.end()) {
        const int timeout = 30; // 30s
        if (iter->second.second - static_cast<int>(time(0)) > timeout) {
            return "";
        }
        return iter->second.first;
    }
    return "";
}

int WifiSettings::SetConnectTimeoutBssid(std::string &bssid, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    time_t now = time(0);
    mBssidToTimeoutTime[instId] = std::make_pair(bssid, static_cast<int>(now));
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

void WifiSettings::SaveDisconnectedReason(DisconnectedReason discReason, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mLastDiscReason[instId] = discReason;
}

int WifiSettings::GetDisconnectedReason(DisconnectedReason &discReason, int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mLastDiscReason.find(instId);
    if (iter != mLastDiscReason.end()) {
        discReason = iter->second;
    }
    return 0;
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
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scanOnlySwitch;
    }
    return mWifiConfig[0].scanOnlySwitch;
}

bool WifiSettings::CheckScanOnlyAvailable(int instId)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    auto iter = mWifiConfig.find(instId);
    if (iter != mWifiConfig.end()) {
        return iter->second.scanOnlySwitch && (MODE_STATE_CLOSE == mAirplaneModeState);
    }
    return mWifiConfig[0].scanOnlySwitch && (MODE_STATE_CLOSE == mAirplaneModeState);
}

int WifiSettings::GetStaApExclusionType()
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    return mWifiConfig[0].staApExclusionType;
}

void WifiSettings::GetPortalUri(WifiPortalConf &urlInfo)
{
    urlInfo.portalHttpUrl = mPortalUri.portalHttpUrl;
    urlInfo.portalHttpsUrl = mPortalUri.portalHttpsUrl;
    urlInfo.portalBakHttpUrl = mPortalUri.portalBakHttpUrl;
    urlInfo.portalBakHttpsUrl = mPortalUri.portalBakHttpsUrl;
}

int WifiSettings::SetStaApExclusionType(int type)
{
    std::unique_lock<std::mutex> lock(mWifiConfigMutex);
    mWifiConfig[0].staApExclusionType = type;
    SyncWifiConfig();
    return 0;
}

long int WifiSettings::GetRandom()
{
    long random = 0;
    do {
        int fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
        ssize_t length = 0;
        if (fd >= 0) {
            length = read(fd, &random, sizeof(random));
            close(fd);
        } else {
            LOGW("%{public}s: failed to open, try again", __func__);
        }
        if (random == 0) {
            fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
            if (fd >= 0) {
                length = read(fd, &random, sizeof(random));
                close(fd);
            } else {
                LOGE("%{public}s: retry failed", __func__);
            }
        }
    } while (0);
    return (random >= 0 ? random : -random);
}

void WifiSettings::GenerateRandomMacAddress(std::string &randomMacAddr)
{
    constexpr unsigned long long high1stByteMask = 0xFF00000000000000;
    constexpr unsigned long long high2rdByteMask = 0x00FF000000000000;
    constexpr unsigned long long high3thByteMask = 0x0000FF0000000000;
    constexpr unsigned long long high4thByteMask = 0x000000FF00000000;
    constexpr unsigned long long high5thByteMask = 0x00000000FF000000;
    constexpr unsigned long long high6thByteMask = 0x0000000000FF0000;
    unsigned long long macAddressValidLongMask = (1ULL << 48) - 1;
    unsigned long long macAddressSaiAssignedMask = 1ULL << 43;
    unsigned long long macAddressEliAssignedMask = 1ULL << 42;
    unsigned long long macAddressLocallyAssignedMask = 1ULL << 41;
    unsigned long long macAddressMulticastMask = 1ULL << 40;
    constexpr int maxMacSize = 18;
    char strMac[maxMacSize] = { 0 };
    int ret = 0;

    unsigned long long random = GetRandom();
    if (random == 0) {
        LOGE("%{public}s: random is invalid!", __func__);
        return;
    }
    LOGD("%{public}s: random is 0x%{public}llx==%{public}lld", __func__, random, random);
    random &= macAddressValidLongMask;
    random &= ~macAddressSaiAssignedMask;
    random &= ~macAddressEliAssignedMask;
    random |= macAddressLocallyAssignedMask;
    random &= ~macAddressMulticastMask;

    LOGD("mac:0x%{public}02llx:0x%{public}02llx:0x%{public}02llx:0x%{public}02llx:0x%{public}02llx:0x%{public}02llx",
        (random & high1stByteMask) >> 56, (random & high2rdByteMask) >> 48, (random & high3thByteMask) >> 40,
        (random & high4thByteMask) >> 32, (random & high5thByteMask) >> 24, (random & high6thByteMask) >> 16);
    ret = sprintf_s(strMac, maxMacSize, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
        (random & high1stByteMask) >> 56, (random & high2rdByteMask) >> 48, (random & high3thByteMask) >> 40,
        (random & high4thByteMask) >> 32, (random & high5thByteMask) >> 24, (random & high6thByteMask) >> 16);
    if (ret < 0) {
        LOGW("%{public}s: failed to sprintf_s", __func__);
    }
    randomMacAddr = strMac;
    LOGD("%{public}s: randomMacAddr: %{private}s", __func__, randomMacAddr.c_str());
}

#ifdef SUPPORT_RANDOM_MAC_ADDR
static std::string GetPairMacAddress(std::map<WifiMacAddrInfo,
    std::string>& macAddrInfoMap, const WifiMacAddrInfo &macAddrInfo)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        LOGD("%{public}s: find the record, realMacAddr:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
            __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        return iter->second;
    } else {
        LOGD("%{public}s: record not found.", __func__);
    }
    return "";
}

static WifiMacAddrErrCode InsertMacAddrPairs(std::map<WifiMacAddrInfo,
    std::string>& macAddrInfoMap, const WifiMacAddrInfo &macAddrInfo, std::string& randomMacAddr)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        LOGD("%{public}s: the record is existed, macAddr:%{private}s, bssidType:%{public}d, value:%{private}s",
            __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        return WIFI_MACADDR_HAS_EXISTED;
    } else {
        macAddrInfoMap.insert(std::make_pair(macAddrInfo, randomMacAddr));
        LOGD("%{public}s: add a mac address pair, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
            __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, randomMacAddr.c_str());
        return WIFI_MACADDR_OPER_SUCCESS;
    }
}

static void DelMacAddrPairs(std::map<WifiMacAddrInfo, std::string>& macAddrInfoMap, const WifiMacAddrInfo &macAddrInfo)
{
    auto iter = macAddrInfoMap.find(macAddrInfo);
    if (iter != macAddrInfoMap.end()) {
        if (iter->second.empty()) {
            LOGI("%{public}s: invalid record, bssid:%{private}s, bssidType:%{public}d",
                __func__, iter->first.bssid.c_str(), iter->first.bssidType);
        } else {
            LOGD("%{public}s: find the record, realMacAddr:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
                __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, iter->second.c_str());
        }
        macAddrInfoMap.erase(iter);
    }
}

static void PrintPairMacAddress(std::map<WifiMacAddrInfo, std::string>& result)
{
    LOGI("total records: %{public}d", (int)result.size());
    int idx = 0;
    for (auto iter = result.begin(); iter != result.end(); iter++) {
        LOGI("Index:%{public}d, bssid:%{private}s, bssidType:%{public}d, value:%{private}s",
            ++idx, iter->first.bssid.c_str(), iter->first.bssidType, iter->second.c_str());
    }
}

void WifiSettings::GenerateRandomMacAddress(std::string peerBssid, std::string &randomMacAddr)
{
    LOGD("enter GenerateRandomMacAddress");
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
    LOGD("exit GenerateRandomMacAddress, randomMacAddr:%{private}s", randomMacAddr.c_str());
}

bool WifiSettings::StoreWifiMacAddrPairInfo(WifiMacAddrInfoType type, const std::string &realMacAddr,
    const std::string &randomAddr)
{
    if (realMacAddr.empty()) {
        LOGE("StoreWifiMacAddrPairInfo: address is empty");
        return false;
    }

    if (type >= WifiMacAddrInfoType::INVALID_MACADDR_INFO) {
        LOGE("StoreWifiMacAddrPairInfo: invalid type[%{public}d]", type);
        return false;
    }

    std::string randomMacAddr;
    if (randomAddr.empty()) {
        WifiSettings::GetInstance().GenerateRandomMacAddress(realMacAddr, randomMacAddr);
    } else {
        randomMacAddr = randomAddr;
    }
    LOGD("%{public}s: type:%{public}d, address:%{private}s, randomAddr:%{private}s, randomMacAddr:%{private}s",
        __func__, type, realMacAddr.c_str(), randomAddr.c_str(), randomMacAddr.c_str());
    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = realMacAddr;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
    WifiMacAddrErrCode ret = WifiSettings::GetInstance().AddMacAddrPairs(type, realMacAddrInfo, randomMacAddr);
    if (ret == WIFI_MACADDR_OPER_SUCCESS) {
        WifiMacAddrInfo randomMacAddrInfo;
        randomMacAddrInfo.bssid = randomMacAddr;
        randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
        WifiSettings::GetInstance().AddMacAddrPairs(type, randomMacAddrInfo, realMacAddr);
    }
    return true;
}
std::string WifiSettings::GetRandomMacAddr(WifiMacAddrInfoType type, std::string bssid)
{
    LOGD("%{public}s: query a random mac address, type:%{public}d, bssid:%{private}s",
        __func__, type, bssid.c_str());
    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = bssid;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
    std::string randomMacAddr = WifiSettings::GetInstance().GetMacAddrPairs(type, realMacAddrInfo);
    if (!randomMacAddr.empty()) {
        LOGD("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
            __func__, realMacAddrInfo.bssid.c_str(), realMacAddrInfo.bssidType, randomMacAddr.c_str());
        return randomMacAddr;
    } else {
        WifiMacAddrInfo randomMacAddrInfo;
        randomMacAddrInfo.bssid = bssid;
        randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
        randomMacAddr = WifiSettings::GetInstance().GetMacAddrPairs(type, realMacAddrInfo);
        if (!randomMacAddr.empty()) {
            LOGD("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
                __func__, randomMacAddrInfo.bssid.c_str(), randomMacAddrInfo.bssidType, randomMacAddr.c_str());
            return randomMacAddr;
        }
    }
    return "";
}
void WifiSettings::RemoveMacAddrPairInfo(WifiMacAddrInfoType type, std::string bssid)
{
    LOGD("%{public}s: remove a mac address pair, type:%{public}d, bssid:%{private}s",
        __func__, type, bssid.c_str());
    WifiMacAddrInfo realMacAddrInfo;
    realMacAddrInfo.bssid = bssid;
    realMacAddrInfo.bssidType = REAL_DEVICE_ADDRESS;
    WifiSettings::GetInstance().RemoveMacAddrPairs(type, realMacAddrInfo);

    WifiMacAddrInfo randomMacAddrInfo;
    randomMacAddrInfo.bssid = bssid;
    randomMacAddrInfo.bssidType = RANDOM_DEVICE_ADDRESS;
    WifiSettings::GetInstance().RemoveMacAddrPairs(type, randomMacAddrInfo);
}
WifiMacAddrErrCode WifiSettings::AddMacAddrPairs(WifiMacAddrInfoType type,
    const WifiMacAddrInfo &macAddrInfo, std::string randomMacAddr)
{
    if ((type >= WifiMacAddrInfoType::INVALID_MACADDR_INFO) || macAddrInfo.bssid.empty()) {
        LOGE("%{public}s: invalid parameter, type:%{public}d, bssid:%{private}s",
            __func__, type, macAddrInfo.bssid.c_str());
        return WIFI_MACADDR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            return InsertMacAddrPairs(mWifiScanMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            return InsertMacAddrPairs(mHotspotMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            return InsertMacAddrPairs(mP2pDeviceMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            return InsertMacAddrPairs(mP2pGroupsInfoMacAddrPair, macAddrInfo, randomMacAddr);
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            return InsertMacAddrPairs(mP2pCurrentgroupMacAddrPair, macAddrInfo, randomMacAddr);
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            break;
    }
    return WIFI_MACADDR_INVALID_PARAM;
}

int WifiSettings::RemoveMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo)
{
    LOGD("remove a mac address pair, type:%{public}d, bssid:%{private}s, bssidType:%{public}d",
        type, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            DelMacAddrPairs(mWifiScanMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            DelMacAddrPairs(mHotspotMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            DelMacAddrPairs(mP2pDeviceMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            DelMacAddrPairs(mP2pGroupsInfoMacAddrPair, macAddrInfo);
            break;
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            DelMacAddrPairs(mP2pCurrentgroupMacAddrPair, macAddrInfo);
            break;
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            return -1;
    }
    return 0;
}

std::string WifiSettings::GetMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo)
{
    LOGD("get a mac address pair, type:%{public}d, bssid:%{private}s, bssidType:%{public}d",
        type, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            return GetPairMacAddress(mWifiScanMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            return GetPairMacAddress(mHotspotMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            return GetPairMacAddress(mP2pDeviceMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            return GetPairMacAddress(mP2pGroupsInfoMacAddrPair, macAddrInfo);
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            return GetPairMacAddress(mP2pCurrentgroupMacAddrPair, macAddrInfo);
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            return "";
    }
    return "";
}

void WifiSettings::PrintMacAddrPairs(WifiMacAddrInfoType type)
{
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            PrintPairMacAddress(mWifiScanMacAddrPair);
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            PrintPairMacAddress(mHotspotMacAddrPair);
            break;
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            PrintPairMacAddress(mP2pDeviceMacAddrPair);
            break;
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            PrintPairMacAddress(mP2pGroupsInfoMacAddrPair);
            break;
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            PrintPairMacAddress(mP2pCurrentgroupMacAddrPair);
            break;
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
            break;
    }
}

void WifiSettings::ClearMacAddrPairs(WifiMacAddrInfoType type)
{
    LOGI("%{public}s type:%{public}d", __func__, type);
    std::unique_lock<std::mutex> lock(mMacAddrPairMutex);
    switch (type) {
        case WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO:
            mWifiScanMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO:
            mHotspotMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO:
            mP2pDeviceMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO:
            mP2pGroupsInfoMacAddrPair.clear();
            break;
        case WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO:
            mP2pCurrentgroupMacAddrPair.clear();
            break;
        default:
            LOGE("%{public}s: invalid mac address type, type:%{public}d", __func__, type);
    }
    return;
}
#endif
}  // namespace Wifi
}  // namespace OHOS
