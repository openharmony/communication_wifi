/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_SETTINGS_H
#define OHOS_WIFI_SETTINGS_H

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <memory>
#include <mutex>
#include <algorithm>
#ifndef OHOS_ARCH_LITE
#include "unique_fd.h"
#endif
#include "wifi_common_def.h"
#include "wifi_common_msg.h"
#include "wifi_config_file_impl.h"
#include "wifi_event_handler.h"
#include "wifi_hisysevent.h"
#include "wifi_common_util.h"

constexpr int RANDOM_STR_LEN = 6;
constexpr int RANDOM_PASSWD_LEN = 8;
constexpr int MSEC = 1000;
constexpr int FOREGROUND_SCAN_CONTROL_TIMES = 4;
constexpr int FOREGROUND_SCAN_CONTROL_INTERVAL = 2 * 60;
constexpr int BACKGROUND_SCAN_CONTROL_TIMES = 1;
constexpr int BACKGROUND_SCAN_CONTROL_INTERVAL = 30 * 60;
constexpr int FREQUENCY_CONTINUE_INTERVAL = 5;
constexpr int FREQUENCY_CONTINUE_COUNT = 5;
constexpr int FREQUENCY_BLOCKLIST_INTERVAL = 20;
constexpr int FREQUENCY_BLOCKLIST_COUNT = 10;
constexpr int PNO_SCAN_CONTROL_TIMES = 1;
constexpr int PNO_SCAN_CONTROL_INTERVAL = 20;
constexpr int SYSTEM_TIMER_SCAN_CONTROL_TIMES = 4;
constexpr int SYSTEM_TIMER_SCAN_CONTROL_INTERVAL = 10;
constexpr int MODE_ADD = 0;
constexpr int MODE_DEL = 1;
constexpr int MODE_UPDATE = 2;
constexpr int ASSOCIATING_SCAN_CONTROL_INTERVAL = 2;
constexpr int ASSOCIATED_SCAN_CONTROL_INTERVAL = 5;
constexpr int OBTAINING_IP_SCAN_CONTROL_INTERVAL = 5;
constexpr int OBTAINING_IP_SCAN_CONTROL_TIMES = 1;
/* Obtain the scanning result that is valid within 30s. */
constexpr int WIFI_GET_SCAN_INFO_VALID_TIMESTAMP = 30 * 1000 * 1000;
/* Hotspot idle status auto close timeout 10min. */
constexpr int HOTSPOT_IDLE_TIMEOUT_INTERVAL_MS = 10 * 60 * 1000;
constexpr int WIFI_DISAPPEAR_TIMES = 3;
constexpr int WIFI_DEVICE_CONFIG_MAX_MUN = 1000;
constexpr uint32_t COMPARE_MAC_OFFSET = 2;
/* Plaintext string length */
constexpr uint32_t COMPARE_MAC_LENGTH = 17 - 4;

inline constexpr char DEVICE_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/device_config.conf";
inline constexpr char BACKUP_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/backup_config.conf";
inline constexpr char HOTSPOT_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/hotspot_config.conf";
inline constexpr char BLOCK_LIST_FILE_PATH[] = CONFIG_ROOR_DIR"/block_list.conf";
inline constexpr char WIFI_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/wifi_config.conf";
inline constexpr char WIFI_P2P_GROUP_INFO_FILE_PATH[] = CONFIG_ROOR_DIR"/p2p_groups.conf";
inline constexpr char WIFI_P2P_VENDOR_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/p2p_vendor_config.conf";
inline constexpr char WIFI_TRUST_LIST_POLICY_FILE_PATH[] = CONFIG_ROOR_DIR"/trust_list_polices.conf";
inline constexpr char WIFI_MOVING_FREEZE_POLICY_FILE_PATH[] = CONFIG_ROOR_DIR"/moving_freeze_policy.conf";
inline constexpr char WIFI_STA_RANDOM_MAC_FILE_PATH[] = CONFIG_ROOR_DIR"/sta_randomMac.conf";
inline constexpr char DUAL_WIFI_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/WifiConfigStore.xml";
inline constexpr char DUAL_SOFTAP_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/WifiConfigStoreSoftAp.xml";
inline constexpr char PACKAGE_FILTER_CONFIG_FILE_PATH[] = "/system/etc/wifi/wifi_package_filter.xml";
inline constexpr char P2P_SUPPLICANT_CONFIG_FILE[] = CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf";

namespace OHOS {
namespace Wifi {
enum class ThermalLevel {
    COOL = 0,
    NORMAL = 1,
    WARM = 2,
    HOT = 3,
    OVERHEATED = 4,
    WARNING = 5,
    EMERGENCY = 6,
};

enum WifiMacAddrErrCode {
    WIFI_MACADDR_OPER_SUCCESS = 0,
    WIFI_MACADDR_HAS_EXISTED = 1,
    WIFI_MACADDR_INVALID_PARAM = 2,
    WIFI_MACADDR_BUTT
};

class WifiSettings {
public:
    static WifiSettings &GetInstance();
    ~WifiSettings();

    int Init();

    int AddDeviceConfig(const WifiDeviceConfig &config);

    int RemoveDevice(int networkId);

    void ClearDeviceConfig(void);

    int GetDeviceConfig(std::vector<WifiDeviceConfig> &results, int instId = 0);

    int GetDeviceConfig(const int &networkId, WifiDeviceConfig &config, int instId = 0);

    int GetDeviceConfig(const std::string &index, const int &indexType, WifiDeviceConfig &config, int instId = 0);

    int GetDeviceConfig(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config, int instId = 0);

    void SetUserConnectChoice(int networkId);

    void ClearAllNetworkConnectChoice();

    bool ClearNetworkConnectChoice(int networkId);

    /**
     * @Description Iterate through all the saved networks and remove the provided config from the connectChoice.
     * This is invoked when a network is removed from records
     *
     * @param networkId - deviceConfig's networkId corresponding to the network that is being removed
     */
    void RemoveConnectChoiceFromAllNetwork(int networkId);

    bool SetNetworkConnectChoice(int networkId, int selectNetworkId, long timestamp);

    /**
     * @Description this invoked by network selector at the start of every selection procedure to clear all candidate
     * seen flag
     *
     * @param networkId - deviceConfig's networkId
     * @Return true if the network was found, false otherwise
     */
    bool ClearNetworkCandidateScanResult(int networkId);

    /**
     * @Description this invoked by network selector when match deviceconfig from scanresults to update if deviceconfig
     * can be seen for user
     *
     * @param networkId - deviceConfig's networkId
     * @Return true if the network was found, false otherwise
     */
    bool SetNetworkCandidateScanResult(int networkId);

    int SetDeviceEphemeral(int networkId, bool isEphemeral);

    int SetDeviceAfterConnect(int networkId);

    int SetDeviceRandomizedMacSuccessEver(int networkId);

    int SetDeviceEverConnected(int networkId);
 
    int SetAcceptUnvalidated(int networkId, bool state);
 
    bool GetDeviceEverConnected(int networkId);
 
    bool GetAcceptUnvalidated(int networkId);

    int GetCandidateConfigWithoutUid(const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config);

    int GetCandidateConfig(const int uid, const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config);

    int GetCandidateConfig(const int uid, const int &networkId, WifiDeviceConfig &config);

    int GetAllCandidateConfig(const int uid, std::vector<WifiDeviceConfig> &configs);

    int IncreaseDeviceConnFailedCount(const std::string &index, const int &indexType, int count);

    int SetDeviceConnFailedCount(const std::string &index, const int &indexType, int count);

    int SyncDeviceConfig();

    bool InKeyMgmtBitset(const WifiDeviceConfig& config, const std::string& keyMgmt);

    void SetKeyMgmtBitset(WifiDeviceConfig &config);

    void GetAllSuitableEncryption(const WifiDeviceConfig &config, const std::string &keyMgmt,
        std::vector<std::string> &candidateKeyMgmtList);

    int ReloadDeviceConfig();

    int GetNextNetworkId();

    int AddWpsDeviceConfig(const WifiDeviceConfig &config);

#ifndef OHOS_ARCH_LITE
    int OnRestore(UniqueFd &fd, const std::string &restoreInfo);

    int OnBackup(UniqueFd &fd, const std::string &backupInfo);

    std::string SetBackupReplyCode(int replyCode);

    void RemoveBackupFile();

    int SetWifiToggleCaller(int callerPid, int instId = 0);
#endif

    bool AddRandomMac(WifiStoreRandomMac &randomMacInfo);

    bool GetRandomMac(WifiStoreRandomMac &randomMacInfo);

    const std::vector<TrustListPolicy> ReloadTrustListPolicies();

    const MovingFreezePolicy ReloadMovingFreezePolicy();

    int GetPackageInfoMap(std::map<std::string, std::vector<PackageInfo>> &packageInfoMap);

    std::string GetPackageName(std::string tag);

    int SyncHotspotConfig();

    int SetHotspotConfig(const HotspotConfig &config, int id = 0);

    int GetHotspotConfig(HotspotConfig &config, int id = 0);

    void ClearHotspotConfig();

    int GetBlockList(std::vector<StationInfo> &results, int id = 0);

    int ManageBlockList(const StationInfo &info, int mode, int id = 0);

    int SyncWifiP2pGroupInfoConfig();

    int SetWifiP2pGroupInfo(const std::vector<WifiP2pGroupInfo> &groups);

    int RemoveWifiP2pGroupInfo();

    int RemoveWifiP2pSupplicantGroupInfo();

    int GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups);

    int SyncP2pVendorConfig();

    int SetP2pDeviceName(const std::string &deviceName);

    int SetP2pVendorConfig(const P2pVendorConfig &config);

    int GetP2pVendorConfig(P2pVendorConfig &config);

    bool GetScanAlwaysState(int instId = 0);

    int GetSignalLevel(const int &rssi, const int &band, int instId = 0);

    int GetOperatorWifiType(int instId = 0);

    int SetOperatorWifiType(int type, int instId = 0);

    int GetLastAirplaneMode(int instId = 0);

    int SetLastAirplaneMode(int mode, int instId = 0);

    bool GetCanOpenStaWhenAirplaneMode(int instId = 0);

    int SetWifiFlagOnAirplaneMode(bool ifOpen, int instId = 0);

    bool GetWifiFlagOnAirplaneMode(int instId = 0);

    bool GetWifiDisabledByAirplane(int instId = 0);

    int SetWifiDisabledByAirplane(bool disabledByAirplane, int instId = 0);

    int GetStaLastRunState(int instId = 0);

    int SetStaLastRunState(int bRun, int instId = 0);

    int GetDhcpIpType(int instId = 0);

    bool GetWhetherToAllowNetworkSwitchover(int instId = 0);

    int GetScoretacticsScoreSlope(int instId = 0);

    int GetScoretacticsInitScore(int instId = 0);

    int GetScoretacticsSameBssidScore(int instId = 0);

    int GetScoretacticsSameNetworkScore(int instId = 0);

    int GetScoretacticsFrequency5GHzScore(int instId = 0);

    int GetScoretacticsLastSelectionScore(int instId = 0);

    int GetScoretacticsSecurityScore(int instId = 0);

    int GetScoretacticsNormalScore(int instId = 0);

    int GetSavedDeviceAppraisalPriority(int instId = 0);

    bool IsModulePreLoad(const std::string &name);

    bool GetSupportHwPnoFlag(int instId = 0);

    int GetMinRssi2Dot4Ghz(int instId = 0);

    int GetMinRssi5Ghz(int instId = 0);

    int SetRealMacAddress(const std::string &macAddress, int instId = 0);

    int GetRealMacAddress(std::string &macAddress, int instId = 0);

    void SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies, int instId = 0);

    void SetScanOnlySwitchState(const int &state, int instId = 0);

    int GetScanOnlySwitchState(int instId = 0);

    bool EncryptionDeviceConfig(WifiDeviceConfig &config) const;

#ifdef SUPPORT_ClOUD_WIFI_ASSET
    void ApplyCloudWifiConfig(const std::vector<WifiDeviceConfig> &newWifiDeviceConfigs,
        const std::set<int> &wifiLinkedNetworkIds, std::map<int, WifiDeviceConfig> &tempConfigs);

    void UpdateWifiConfigFromCloud(const std::vector<WifiDeviceConfig> &newWifiDeviceConfigs,
        const std::set<int> &wifiLinkedNetworkIds);

    void UpLoadLocalDeviceConfigToCloud();
#endif

private:
    WifiSettings();
    int IncreaseNumRebootsSinceLastUse();
    void EncryptionWifiDeviceConfigOnBoot();
    int ReloadStaRandomMac();
    void InitPackageInfoConfig();
    void InitDefaultHotspotConfig();
    void InitHotspotConfig();
    int SyncBlockList();
    int ReloadWifiP2pGroupInfoConfig();
    void InitDefaultP2pVendorConfig();
    void InitP2pVendorConfig();
    int GetApMaxConnNum();
    void InitDefaultWifiConfig();
    void InitWifiConfig();
    int SyncWifiConfig();
    int RemoveExcessDeviceConfigs(std::vector<WifiDeviceConfig> &configs) const;
    std::string FuzzyBssid(const std::string bssid);
#ifndef OHOS_ARCH_LITE
    void MergeWifiConfig();
    void MergeSoftapConfig();
    void ConfigsDeduplicateAndSave(std::vector<WifiDeviceConfig> &newConfigs);
    void ParseBackupJson(const std::string &backupInfo, std::string &key, std::string &iv, std::string &version);
    int GetConfigbyBackupXml(std::vector<WifiDeviceConfig> &deviceConfigs, UniqueFd &fd);
    int GetConfigbyBackupFile(std::vector<WifiDeviceConfig> &deviceConfigs, UniqueFd &fd, const std::string &key,
        const std::string &iv);
#endif
#ifdef FEATURE_ENCRYPTION_SUPPORT
    bool IsWifiDeviceConfigDeciphered(const WifiDeviceConfig &config) const;
    void DecryptionWapiConfig(const WifiEncryptionInfo &wifiEncryptionInfo, WifiDeviceConfig &config) const;
    int DecryptionDeviceConfig(WifiDeviceConfig &config);
    bool EncryptionWapiConfig(const WifiEncryptionInfo &wifiEncryptionInfo, WifiDeviceConfig &config) const;
#endif
    void SyncAfterDecryped(WifiDeviceConfig &config);
    int GetAllCandidateConfigWithoutUid(std::vector<WifiDeviceConfig> &configs);
private:
    // STA
    std::mutex mStaMutex;
    std::mutex mConfigOnBootMutex;
    int mNetworkId;
    std::atomic_flag deviceConfigLoadFlag = ATOMIC_FLAG_INIT;
    std::atomic_flag mEncryptionOnBootFalg = ATOMIC_FLAG_INIT;
    std::map<int, WifiDeviceConfig> mWifiDeviceConfig;
    WifiConfigFileImpl<WifiDeviceConfig> mSavedDeviceConfig;
    std::vector<WifiStoreRandomMac> mWifiStoreRandomMac;
    WifiConfigFileImpl<WifiStoreRandomMac> mSavedWifiStoreRandomMac;
    std::unique_ptr<WifiEventHandler> mWifiEncryptionThread = nullptr;

    // SCAN
    std::mutex mScanMutex;
    WifiConfigFileImpl<TrustListPolicy> mTrustListPolicies;
    WifiConfigFileImpl<MovingFreezePolicy> mMovingFreezePolicy;
    std::map<std::string, std::vector<std::string>> mFilterMap;

    // AP
    std::mutex mApMutex;
    std::map<int, HotspotConfig> mHotspotConfig;
    WifiConfigFileImpl<HotspotConfig> mSavedHotspotConfig;
    std::map<std::string, StationInfo> mBlockListInfo;
    WifiConfigFileImpl<StationInfo> mSavedBlockInfo;

    // P2P
    std::mutex mP2pMutex;
    std::vector<WifiP2pGroupInfo> mGroupInfoList;
    WifiConfigFileImpl<WifiP2pGroupInfo> mSavedWifiP2pGroupInfo;
    P2pVendorConfig mP2pVendorConfig;
    WifiConfigFileImpl<P2pVendorConfig> mSavedWifiP2pVendorConfig;

    // COMMON
    std::mutex mWifiConfigMutex;
    std::mutex mSyncWifiConfigMutex;
    std::mutex mPackageConfMutex;
    std::atomic<int> mApMaxConnNum;
    std::atomic<int> mMaxNumConfigs;
    std::map<int, WifiConfig> mWifiConfig;
    WifiConfigFileImpl<WifiConfig> mSavedWifiConfig;
    std::map<std::string, std::vector<PackageInfo>> mPackageInfoMap;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
