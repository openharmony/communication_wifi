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

#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <memory>
#include <mutex>
#include <algorithm>
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
/* Obtain the scanning result that is valid within 180s. */
constexpr int WIFI_GET_SCAN_INFO_VALID_TIMESTAMP = 180;
/* Hotspot idle status auto close timeout 10min. */
constexpr int HOTSPOT_IDLE_TIMEOUT_INTERVAL_MS = 10 * 60 * 1000;
constexpr int WIFI_DISAPPEAR_TIMES = 3;

constexpr char DEVICE_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/device_config.conf";
constexpr char HOTSPOT_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/hotspot_config.conf";
constexpr char BLOCK_LIST_FILE_PATH[] = CONFIG_ROOR_DIR"/block_list.conf";
constexpr char WIFI_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/wifi_config.conf";
constexpr char WIFI_P2P_GROUP_INFO_FILE_PATH[] = CONFIG_ROOR_DIR"/p2p_groups.conf";
constexpr char WIFI_P2P_VENDOR_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/p2p_vendor_config.conf";
const std::string WIFI_TRUST_LIST_POLICY_FILE_PATH = CONFIG_ROOR_DIR"/trust_list_polices.conf";
const std::string WIFI_MOVING_FREEZE_POLICY_FILE_PATH = CONFIG_ROOR_DIR"/moving_freeze_policy.conf";
constexpr char WIFI_STA_RANDOM_MAC_FILE_PATH[] = CONFIG_ROOR_DIR"/sta_randomMac.conf";
constexpr char PORTAL_CONFIG_FILE_PATH[] = "/system/etc/wifi/wifi_portal.conf";
constexpr char DUAL_WIFI_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/WifiConfigStore.xml";
constexpr char DUAL_SOFTAP_CONFIG_FILE_PATH[] = CONFIG_ROOR_DIR"/WifiConfigStoreSoftAp.xml";
constexpr char PACKAGE_FILTER_CONFIG_FILE_PATH[] = "/system/etc/wifi/wifi_package_filter.cfg";
constexpr char P2P_SUPPLICANT_CONFIG_FILE[] = CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf";
constexpr char WIFI_SOFTAP_RANDOM_MAC_FILE_PATH[] = CONFIG_ROOR_DIR"/ap_randomMac.conf";

namespace OHOS {
namespace Wifi {
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

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
    ~WifiSettings();
    static WifiSettings &GetInstance();

    /**
     * @Description Init the WifiSettings object
     *
     * @return int - init result, when 0 means success, other means some fails happened
     */
    int Init();

    /**
     * @Description Get the Wifi Sta Capabilities
     *
     * @return int - mWifiStaCapabilities
     */
    int GetWifiStaCapabilities() const;

    /**
     * @Description Save the Wifi Sta Capabilities
     *
     * @param capabilities - input capability
     * @return int - 0 success
     */
    int SetWifiStaCapabilities(int capabilities);

    /**
     * @Description Get current STA service state
     *
     * @return int - the wifi state, DISABLING/DISABLED/ENABLING/ENABLED/UNKNOWN
     */
    int GetWifiState(int instId = 0);

    /**
     * @Description Save STA service state
     *
     * @param state - the wifi state
     * @return int - 0 success
     */
    int SetWifiState(int state, int instId = 0);

    void PersistWifiState(int state);
    int GetPersistWifiState();
    bool IsWifiToggledEnable();
    void SetWifiToggledState(bool state);
    bool GetWifiToggledState() const;
    void InsertWifi6BlackListCache(const std::string currentBssid,
        const Wifi6BlackListInfo wifi6BlackListInfo);
    void RemoveWifi6BlackListCache(const std::string bssid);
    int GetWifi6BlackListCache(std::map<std::string, Wifi6BlackListInfo> &blackListCache) const;
    void SetSoftapToggledState(bool state);
    bool GetSoftapToggledState() const;
    void SetWifiStopState(bool state);
    bool GetWifiStopState() const;
    void SetCoexSupport(bool isSupport);
    bool GetCoexSupport() const;
    void SetStaIfaceName(const std::string &ifaceName);
    std::string GetStaIfaceName();
    void SetP2pIfaceName(const std::string &ifaceName);
    std::string GetP2pIfaceName();
    void SetApIfaceName(const std::string &ifaceName);
    std::string GetApIfaceName();

    /**
     * @Description Has STA service running
     *
     * @return bool - true
     */
    bool HasWifiActive();

    /**
     * @Description Get the ScanAlways switch state
     *
     * @return true - ScanAlways on, false - ScanAlways off
     */
    bool GetScanAlwaysState(int instId = 0);

    /**
     * @Description Set the ScanAlways switch state
     *
     * @param isActive - ScanAlways on/off
     * @return int - 0 success
     */
    int SetScanAlwaysState(bool isActive, int instId = 0);

    /**
     * @Description Save scan results
     *
     * @param results - vector scan results
     * @return int - 0 success
     */
    int SaveScanInfoList(const std::vector<WifiScanInfo> &results);
    /**
     * @Description Clear scan results
     *
     * @return int - 0 success
     */
    int ClearScanInfoList();
    /**
     * @Description UpdateLinkedChannelWidth
     *
     * @param bssid ap ssid
     * @param channelWidth ap channelwidth
     * @return void
     */
    void UpdateLinkedChannelWidth(std::string bssid, WifiChannelWidth channelWidth, int instId = 0);

    /**
     * @Description Get scan results
     *
     * @param results - output vector of scan results
     * @return int - 0 success
     */
    int GetScanInfoList(std::vector<WifiScanInfo> &results);

    /**
     * @Description Get scan result by bssid
     *
     * @param results - output scan result
     * @return int - 0 success
     */
    int SetWifiLinkedStandardAndMaxSpeed(WifiLinkedInfo &linkInfo);
    /**
     * @Description save the p2p connected info
     *
     * @param linkedInfo - WifiP2pLinkedInfo object
     * @return int - 0 success
     */
    int SaveP2pInfo(WifiP2pLinkedInfo &linkedInfo);

    /**
     * @Description Get the p2p connected info
     *
     * @param linkedInfo - output the p2p connected info
     * @return int - 0 success
     */
    int GetP2pInfo(WifiP2pLinkedInfo &linkedInfo);

    /**
     * @Description Get the scan control policy info
     *
     * @param info - output ScanControlInfo struct
     * @return int - 0 success
     */
    int GetScanControlInfo(ScanControlInfo &info, int instId = 0);

    /**
     * @Description Save the scan control policy info
     *
     * @param info - input ScanControlInfo struct
     * @return int - 0 success
     */
    int SetScanControlInfo(const ScanControlInfo &info, int instId = 0);

    /**
     * @Description Get the filter info
     *
     * @param filterMap - output package map
     * @return int - 0 success
     */
    int GetPackageFilterMap(std::map<std::string, std::vector<std::string>> &filterMap);

    /**
     * @Description Add Device Configuration
     *
     * @param config - WifiDeviceConfig object
     * @return int - network id
     */
    int AddDeviceConfig(const WifiDeviceConfig &config);

    /**
     * @Description Remove a wifi device config who's networkId equals input networkId
     *
     * @param networkId - a networkId that is to be removed
     * @return int - 0 success ,other is failed
     */
    int RemoveDevice(int networkId);

    /**
     * @Description Remove all saved wifi device config
     *
     */
    void ClearDeviceConfig(void);

    /**
     * @Description Get all saved wifi device config
     *
     * @param results - output wifi device config results
     * @return int - 0 success
     */
    int GetDeviceConfig(std::vector<WifiDeviceConfig> &results);

    /**
     * @Description Get the specify networkId's wifi device config
     *
     * @param networkId - network id
     * @param config - output WifiDeviceConfig struct
     * @return int - 0 success; -1 not find the device config
     */
    int GetDeviceConfig(const int &networkId, WifiDeviceConfig &config);

    /**
     * @brief Get the specify wifi device config which bssid is equal to input bssid
     *
     * @param index - bssid string or ssid string
     * @param indexType - index type 0:ssid 1:bssid
     * @param config - output WifiDeviceConfig struct
     * @return int - 0 success; -1 not find the device config
     */
    int GetDeviceConfig(const std::string &index, const int &indexType, WifiDeviceConfig &config);

    /**
     * @Description Get the specify wifi device config which ssid is equal to input ssid and keymgmt is equal to input
     * keymgmt
     *
     * @param ssid - ssid string
     * @param keymgmt - keymgmt string
     * @param config - output WifiDeviceConfig struct
     * @return int - 0 success; -1 not find the device config
     */
    int GetDeviceConfig(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config);

    /**
     * @Description Get the specify wifi device config which ssid is equal to input ssid and keymgmt is equal to input
     * keymgmt
     *@param networkId - network id
     * @param ssid - ssid string
     * @param keymgmt - keymgmt string
     * @param config - output WifiDeviceConfig struct
     * @return int - 0 success; -1 not find the device config
     */
    int GetDeviceConfig(const std::string &ancoCallProcessName, const std::string &ssid,
            const std::string &keymgmt, WifiDeviceConfig &config);

    /**
     * @Description Get the wifi device configs which hiddenSSID is true
     *
     * @param results - output WifiDeviceConfig structs
     * @return int - 0 success
     */
    int GetHiddenDeviceConfig(std::vector<WifiDeviceConfig> &results);

    /**
     * @Description Set a wifi device's state who's networkId equals input networkId;
     * when the param bSetOther is true and the state is ENABLED, that means we need
     * to set other wifi device DISABLED
     * @param networkId - the wifi device's id
     * @param state - WifiDeviceConfigStatus DISABLED/ENABLED/UNKNOWN
     * @param bSetOther - whether set other device config disabled
     * @return int - when 0 means success, other means some fails happened,
     *               Input state invalid or not find the wifi device config
     */
    int SetDeviceState(int networkId, int state, bool bSetOther = false);

    /**
     * @Description Set a wifi device's attributes who's networkId equals input networkId after connect;
     *
     * @param networkId - the wifi device's id
     * @return int - when 0 means success, other means some fails happened,
     *               Input state invalid or not find the wifi device config
     */
    int SetDeviceAfterConnect(int networkId);

    /**
     * @Description Get the candidate device configuration
     *
     * @param uid - call app uid
     * @param networkId - a networkId that is to be get
     * @param config - WifiDeviceConfig object
     * @return int - network id
     */
    int GetCandidateConfig(const int uid, const int &networkId, WifiDeviceConfig &config);

    /**
     * @Description  Get all the Candidate Device Configurations set key uuid
     *
     * @param uid - call app uid
     * @param configs - WifiDeviceConfig objects
     * @return int - 0 success
     */
    int GetAllCandidateConfig(const int uid, std::vector<WifiDeviceConfig> &configs);

    /**
     * @Description Synchronizing saved the wifi device config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncDeviceConfig();

    /**
     * @Description Increments the number of reboots since last use for each configuration
     *
     * @return int - 0 success; -1 save file failed
     */
    int IncreaseNumRebootsSinceLastUse();
    /**
     * @Description Remove excess networks in case the number of saved networks exceeds the mas limit
     *
     * @param configs - WifiDeviceConfig objects
     * @return int - 0 if networks were removed, 1 otherwise.
     */
    int RemoveExcessDeviceConfigs(std::vector<WifiDeviceConfig> &configs) const;

    /**
     * @Description Reload wifi device config from config file
     *
     * @return int - 0 success; -1 read config file failed
     */
    int ReloadDeviceConfig();

    /**
     * @Description Encryption WifiDeviceConfig for old data
     */
    void EncryptionWifiDeviceConfigOnBoot();

    /**
     * @Description Synchronizing saved the wifi WifiP2pGroupInfo config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncWifiP2pGroupInfoConfig();

    /**
     * @Description Reload wifi WifiP2pGroupInfo config from config file
     *
     * @return int - 0 success; -1 read config file failed
     */
    int ReloadWifiP2pGroupInfoConfig();

    /**
     * @Description Save WifiP2pGroupInfo
     *
     * @param groups - input wifi p2p groups config results
     * @return int - 0 success
     */
    int SetWifiP2pGroupInfo(const std::vector<WifiP2pGroupInfo> &groups);

    /**
     * @Description set current WifiP2pGroupInfo
     *
     * @param group - input wifi p2p group config
     */
    void SetCurrentP2pGroupInfo(const WifiP2pGroupInfo &group);

    /**
     * @Description get current WifiP2pGroupInfo
     *
     * @return WifiP2pGroupInfo - WifiP2pGroupInfo result
     */
    WifiP2pGroupInfo GetCurrentP2pGroupInfo();

    /**
     * @brief increase sta connected failed count
     *
     * @param index - bssid string or ssid string
     * @param indexType - index type 0:ssid 1:bssid
     * @param count - the increase count to set
     * @return int - 0 success; -1 not find the device config
     */
    int IncreaseDeviceConnFailedCount(const std::string &index, const int &indexType, int count);

    /**
     * @brief set sta connected failed count
     *
     * @param index - bssid string or ssid string
     * @param indexType - index type 0:ssid 1:bssid
     * @param count - the count to set
     * @return int - 0 success; -1 not find the device config
     */
    int SetDeviceConnFailedCount(const std::string &index, const int &indexType, int count);

    /**
     * @Description Delete a WifiP2pGroupInfo node
     *
     * @return int
     */
    int RemoveWifiP2pGroupInfo();

    /**
     * @Description Delete a WifiP2pSupplicantGroupInfo conf
     *
     * @return int
     */
    int RemoveWifiP2pSupplicantGroupInfo();

    /**
     * @Description Get all saved wifi p2p groups config
     *
     * @param results - output wifi p2p groups config results
     * @return int - 0 success
     */
    int GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups);

    /**
     * @Description Get the dhcp info
     *
     * @param info - output IpInfo struct
     * @return int - 0 success
     */
    int GetIpInfo(IpInfo &info, int instId = 0);

    /**
     * @Description Save dhcp info
     *
     * @param info - input IpInfo struct
     * @return int - 0 success
     */
    int SaveIpInfo(const IpInfo &info, int instId = 0);

    /**
     * @Description Get the dhcp ipv6info
     *
     * @param info - output IpV6Info struct
     * @return int - 0 success
     */
    int GetIpv6Info(IpV6Info &info, int instId = 0);

    /**
     * @Description Save dhcp inV6fo
     *
     * @param info - input IpV6Info struct
     * @return int - 0 success
     */
    int SaveIpV6Info(const IpV6Info &info, int instId = 0);

    /**
     * @Description Get all wifi linked info
     *
     * @return map - all wifi linked info
     */
    std::map<int, WifiLinkedInfo> GetAllWifiLinkedInfo();

    /**
     * @Description Get current link info
     *
     * @param info - output WifiLinkedInfo struct
     * @return int - 0 success
     */
    int GetLinkedInfo(WifiLinkedInfo &info, int instId = 0);

    /**
     * @Description getConnectedBssid
     *
     * @param connectedBssid connectedBssid
     * @param instId target wlan id
     */
    std::string GetConnectedBssid(int instId = 0);

    /**
     * @Description Save link info
     *
     * @param info - input WifiLinkedInfo struct
     * @return int - 0 success
     */
    int SaveLinkedInfo(const WifiLinkedInfo &info, int instId = 0);

    /**
     * @Description Save mac address
     *
     * @param macAddress - mac address info
     * @return int - 0 success
     */
    int SetMacAddress(const std::string &macAddress, int instId = 0);

    /**
     * @Description Get the mac address
     *
     * @param macAddress - output mac address info
     * @return int - 0 success
     */
    int GetMacAddress(std::string &macAddress, int instId = 0);

    /**
     * @Description reload mac address
     *
     * @return int - 0 success
     */
    int ReloadStaRandomMac();

    /**
     * @Description reload portal conf
     *
     * @return int - 0 success
     */
    int ReloadPortalconf();

    /**
     * @Description clear random mac conf
     *
     * @return int - 0 success
     */
    void ClearRandomMacConfig();

    /**
     * @Description Get portal uri
     *
     * @param portalUri - portal uri
     * @return int - 0 success
     */
    void GetPortalUri(WifiPortalConf &urlInfo);

    /**
     * @Description add random mac address
     *
     * @param randomMacInfo - randmon mac address info
     * @return int - 0 success
     */
    bool AddRandomMac(WifiStoreRandomMac &randomMacInfo);

    /**
     * @Description Get random mac address
     *
     * @param randomMacInfo - randmon mac address info
     * @return int - 0 success
     */
    bool GetRandomMac(WifiStoreRandomMac &randomMacInfo);

    /**
     * @Description remove random mac address
     *
     * @param bssid - bssid string
     * @param randomMac - randmon mac address string
     * @return int - 1 success
     */
    bool RemoveRandomMac(const std::string &bssid, const std::string &randomMac);

    /**
     * @Description Get current hotspot state
     *
     * @return int - the hotspot state, IDLE/STARTING/STARTED/CLOSING/CLOSED
     */
    int GetHotspotState(int id = 0);

    /**
     * @Description Save current hotspot state
     *
     * @param state - hotspot state
     * @return int - 0 success
     */
    int SetHotspotState(int state, int id = 0);

    /**
     * @Description Set the hotspot config
     *
     * @param config - input HotspotConfig struct
     * @return int - 0 success
     */
    int SetHotspotConfig(const HotspotConfig &config, int id = 0);

    /**
     * @Description Get the hotspot config
     *
     * @param config - output HotspotConfig struct
     * @return int - 0 success
     */
    int GetHotspotConfig(HotspotConfig &config, int id = 0);

    /**
     * @Description Set the idel timeout of Hotspot
     *
     * @return int - 0 success
     */
    int SetHotspotIdleTimeout(int time);

    /**
     * @Description Get the idel timeout of Hotspot
     *
     * @param time -input time,
     * @return int - the hotspot idle timeout
     */
    int GetHotspotIdleTimeout() const;

    /**
     * @Description Synchronizing saved the Hotspot config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncHotspotConfig();

    /**
     * @Description Set the p2p vendor config
     *
     * @param config - input P2pVendorConfig struct
     * @return int - 0 success
     */
    int SetP2pVendorConfig(const P2pVendorConfig &config);

    /**
     * @Description Get the p2p vendor config
     *
     * @param config - output P2pVendorConfig struct
     * @return int - 0 success
     */
    int GetP2pVendorConfig(P2pVendorConfig &config);

    /**
     * @Description Synchronizing saved the P2p Vendor config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncP2pVendorConfig();

    /**
     * @Description Get current hotspot accept linked stations
     *
     * @param results - output StationInfo results
     * @return int - 0 success
     */
    int GetStationList(std::vector<StationInfo> &results, int id = 0);

    /**
     * @Description Management (add/update/delete) connected station list
     *
     * @param info - input StationInfo struct
     * @param mode - mode of MODE_ADD MODE_UPDATE MODE_DEL
     * @return int - 0 success; -1 mode not correct
     */
    int ManageStation(const StationInfo &info, int mode, int id = 0); /* add / update / remove */

    /**
     * @Description Clear connected station list
     *
     * @return int - 0 success
     */
    int ClearStationList(int id = 0);

    /**
     * @Description Get the block list
     *
     * @param results - output StationInfo results
     * @return int - 0 success
     */
    int GetBlockList(std::vector<StationInfo> &results, int id = 0);

    /**
     * @Description Manager (add/update/delete) station connect Blocklist
     *
     * @param info - input StationInfo struct
     * @param mode - mode of MODE_ADD MODE_DEL MODE_UPDATE
     * @return int - 0 success; -1 mode not correct
     */
    int ManageBlockList(const StationInfo &info, int mode, int id = 0); /* add / remove */

    /**
     * @Description Judge whether the station is in current linked station list
     *
     * @param info - input StationInfo struct
     * @return int - 0 find the station, exist; -1 not find, not exist
     */
    int FindConnStation(const StationInfo &info, int id = 0);

    /**
     * @Description Synchronizing saved the block list config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncBlockList();

    /**
     * @Description Get the Valid Bands object
     *
     * @param bands - output vector for BandType
     * @return int - 0 success
     */
    int GetValidBands(std::vector<BandType> &bands);

    /**
     * @Description Set the Valid Channels object
     *
     * @param channelsInfo - input ChannelsTable struct
     * @return int - 0 success
     */
    int SetValidChannels(const ChannelsTable &channelsInfo);

    /**
     * @Description Get the Valid Channels object
     *
     * @param channelsInfo - output ChannelsTable struct
     * @return int - 0 success
     */
    int GetValidChannels(ChannelsTable &channelsInfo);

    /**
     * @Description Clear the number of valid channels
     *
     * @return int - 0 success
     */
    int ClearValidChannels();

    /**
     * @Description Get supported power model list
     *
     * @param model - the model to be set
     * @return ErrCode - operation result
     */
    int SetPowerModel(const PowerModel& model, int id = 0);

    /**
     * @Description Get power model
     *
     * @param model - current power model
     * @return ErrCode - operation result
     */
    int GetPowerModel(PowerModel& model, int id = 0);

    /**
     * @Description set the p2p state
     *
     * @param state - the p2p state
     * @return int - 0 success
     */
    int SetP2pState(int state);

    /**
     * @Description Get current p2p state
     *
     * @return int - the p2p state, NONE/IDLE/STARTING/STARTED/CLOSING/CLOSED
     */
    int GetP2pState();

    /**
     * @Description set the p2p discover state
     *
     * @param state - the p2p discover state
     * @return int - 0 success
     */
    int SetP2pDiscoverState(int state);

    /**
     * @Description Get current p2p discover state
     *
     * @return int -the p2p discover state, P2P_DISCOVER_NONE/P2P_DISCOVER_STARTING/P2P_DISCOVER_CLOSED
     */
    int GetP2pDiscoverState();

    /**
     * @Description set the p2p connected state
     *
     * @param state - the p2p connected state
     * @return int - 0 success
     */
    int SetP2pConnectedState(int state);

    /**
     * @Description Get current p2p connected state
     *
     * @return int - the connected state, P2P_CONNECTED_NONE/P2P_CONNECTED_STARTING/P2P_CONNECTED_CLOSED
     */
    int GetP2pConnectedState();

    /**
     * @Description Set the hid2d upper scene
     *
     * @param state - the hid2d upper scene
     * @return int - 0 success
     */
    int SetHid2dUpperScene(const std::string& ifName, const Hid2dUpperScene &scene);

    /**
     * @Description Get the hid2d upper scene
     *
     * @param state - the hid2d upper scene
     * @return int - 0 success
     */
    int GetHid2dUpperScene(std::string& ifName, Hid2dUpperScene &scene);

    /**
     * @Description Set p2p type
     *
     * @param type - the p2p type
     * @return int - 0 success
     */
    int SetP2pBusinessType(const P2pBusinessType &type);

    /**
     * @Description Get p2p type
     *
     * @param state - p2p type
     * @return int - 0 success
     */
    int GetP2pBusinessType(P2pBusinessType &type);

    /**
     * @Description Clear the hid2d info
     */
    void ClearLocalHid2dInfo();

    /**
     * @Description Get signal level about given rssi and band
     *
     * @param rssi - rssi info
     * @param band - band info
     * @return int - level
     */
    int GetSignalLevel(const int &rssi, const int &band, int instId = 0);

    /**
     * @Description Get the Ap Max Conn Num
     *
     * @return int - number
     */
    int GetApMaxConnNum();

    /**
     * @Description Enable Network
     *
     * @param networkId - enable network id
     * @param disableOthers - when set, save this network id, and can use next time
     * @return true
     * @return false
     */
    bool EnableNetwork(int networkId, bool disableOthers, int instId = 0);

    /**
     * @Description Set the User Last Selected Network Id
     *
     * @param networkId - network id
     */
    void SetUserLastSelectedNetworkId(int networkId, int instId = 0);

    /**
     * @Description Get the User Last Selected Network Id
     *
     * @return int - network id
     */
    int GetUserLastSelectedNetworkId(int instId = 0);

    /**
     * @Description Get the User Last Selected Network time
     *
     * @return time_t - timestamp
     */
    time_t GetUserLastSelectedNetworkTimeVal(int instId = 0);

    /**
     * @Description Synchronizing saved the WifiConfig into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncWifiConfig();

    /**
     * @Description Get operator wifi state
     *
     * @return type - enum OperatorWifiType
     */
    int GetOperatorWifiType(int instId = 0);

    /**
     * @Description Set operator wifi state
     *
     * @param type - enum OperatorWifiType
     * @return int - 0 success
     */
    int SetOperatorWifiType(int type, int instId = 0);

    /**
     * @Description Get last airplane mode
     *
     * @return type - enum aiprlane mode
     */
    int GetLastAirplaneMode(int instId = 0);

    /**
     * @Description Set last airplane mode
     *
     * @return type - 0 success
     */
    int SetLastAirplaneMode(int mode, int instId = 0);

    /**
     * @Description Get the config whether can open sta when airplane mode opened
     *
     * @return true - can open
     * @return false - can't open
     */
    bool GetCanOpenStaWhenAirplaneMode(int instId = 0);

    /**
     * @Description Get the config whether open wifi when airplane mode opened
     *
     * @return true - open
     * @return false - can't open
     */
    bool GetWifiFlagOnAirplaneMode(int instId = 0);

    /**
     * @Description Set the config whether open wifi when airplane mode opened
     *
     * @param ifOpen - user want to open wifi
     * @return int - 0 success
     */
    int SetWifiFlagOnAirplaneMode(bool ifOpen, int instId = 0);

    /**
     * @Description Get the STA service last running state
     *
     * @return true - running
     * @return false - not running
     */
    bool GetStaLastRunState(int instId = 0);

    /**
     * @Description Set the STA service running state
     *
     * @param bRun - running or not
     * @return int - 0 success
     */
    int SetStaLastRunState(bool bRun, int instId = 0);

    /**
     * @Description Get the Dhcp Ip Type
     *
     * @return int - dhcp ip type, ipv4/ipv6/double
     */
    int GetDhcpIpType(int instId = 0);

    /**
     * @Description Set the Dhcp Ip Type
     *
     * @param dhcpIpType - ipv4/ipv6/double
     * @return int - 0 success
     */
    int SetDhcpIpType(int dhcpIpType, int instId = 0);

    /**
     * @Description Get the Default Wifi Interface
     *
     * @return std::string - interface name
     */
    std::string GetDefaultWifiInterface(int instId = 0);

    /**
     * @Description Set the Screen State
     *
     * @param state - 1 on; 2 off
     */
    void SetScreenState(const int &state);

    /**
     * @Description Get the Screen State
     *
     * @return int - 1 on; 2 off
     */
    int GetScreenState() const;

    /**
     * @Description Set the Idel State
     *
     * @param state - 1 on; 2 off
     */
    void SetPowerIdelState(const int &state);

    /**
     * @Description Get the Idel State
     *
     * @return int - 1 on; 2 off
     */
    int GetPowerIdelState() const;

    /**
     * @Description Set the Battery Charge State
     *
     * @param state - 1 on; 2 off
     */
    void SetBatteryChargeState(const int &state);

    /**
     * @Description Set the Gnss Fix State
     *
     * @param state - 1 on; 2 off
     */
    void SetGnssFixState(const int &state);

    /**
     * @Description Get the Gnss Fix State
     *
     * @return int - 1 on; 2 off
     */
    int GetGnssFixState() const;

    /**
     * @Description Set the abnormal apps
     *
     * @param abnormalAppList - abnormal app list
     */
    void SetAbnormalApps(const std::vector<std::string> &abnormalAppList);

    /**
     * @Description Get the abnormal apps
     *
     * @param abnormalAppList - abnormal app list
     * @return int - 0 success
     */
    int GetAbnormalApps(std::vector<std::string> &abnormalAppList);

    /**
     * @Description Set the scan genie state
     *
     * @param state - 1 on; 2 off
     */
    void SetScanGenieState(const int &state);

    /**
     * @Description Get the scan genie state
     *
     * @return int - 1 on; 2 off
     */
    int GetScanGenieState() const;

    /**
     * @Description Set the Airplane Mode State
     *
     * @param state - 1 open; 2 close
     * @return bool - true airplane mode toggled, false airplane mode not toggled
     */
    bool SetWifiStateOnAirplaneChanged(const int &state);

    /**
     * @Description Get the Airplane Mode State
     *
     * @return int - 1 open; 2 close
     */
    int GetAirplaneModeState() const;

    /**
     * @Description Set the Power Sleep State
     *
     * @param state - 1 open; 2 close
     */
    void SetPowerSleepState(const int &state);

    /**
     * @Description Get the Power Sleep State
     *
     * @return int - 1 open; 2 close
     */
    int GetPowerSleepState() const;

    /**
     * @Description Set the App Running State
     *
     * @param appRunMode - app run mode
     */
    void SetAppRunningState(ScanMode appRunMode);

    /**
     * @Description Get the App Running State
     *
     * @return ScanMode
     */
    ScanMode GetAppRunningState() const;

    /**
     * @Description Set the Power Saving Mode State
     *
     * @param state - 1 open; 2 close
     */
    void SetPowerSavingModeState(const int &state);

    /**
     * @Description Get the Power Saving Mode State
     *
     * @return int - 1 open; 2 close
     */
    int GetPowerSavingModeState() const;

    /**
     * @Description Set app package name.
     *
     * @param appPackageName - app package name
     */
    void SetAppPackageName(const std::string &appPackageName);

    /**
     * @Description Get app package name.
     *
     * @return const std::string - app package name.
     */
    const std::string GetAppPackageName() const;

    /**
     * @Description Set freeze mode state.
     *
     * @param state - 1 freeze mode; 2 moving mode
     */
    void SetFreezeModeState(int state);

    /**
     * @Description Get freeze mode state.
     *
     * @return freeze mode.
     */
    int GetFreezeModeState() const;

    /**
     * @Description Set no charger plugged in mode.
     *
     * @param state - 1 no charger plugged in mode; 2 charger plugged in mode
     */
    void SetNoChargerPlugModeState(int state);

    /**
     * @Description Get no charger plugged in mode.
     *
     * @return no charger plugged in mode.
     */
    int GetNoChargerPlugModeState() const;

    /**
     * @Description Set enable/disable Whether to allow network switchover
     *
     * @param bSwitch - enable/disable
     * @return int - 0 success
     */
    int SetWhetherToAllowNetworkSwitchover(bool bSwitch, int instId = 0);

    /**
     * @Description Check whether enable network switchover
     *
     * @return true - enable
     * @return false - disable
     */
    bool GetWhetherToAllowNetworkSwitchover(int instId = 0);

    /**
     * @Description Set the policy score slope
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsScoreSlope(const int &score, int instId = 0);

    /**
     * @Description Get the policy score slope
     *
     * @return int - score
     */
    int GetScoretacticsScoreSlope(int instId = 0);

    /**
     * @Description Initial score of the set strategy
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsInitScore(const int &score, int instId = 0);

    /**
     * @Description Obtain the initial score of the tactic
     *
     * @return int - score
     */
    int GetScoretacticsInitScore(int instId = 0);

    /**
     * @Description Set the scoring policy to the same BSSID score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsSameBssidScore(const int &score, int instId = 0);

    /**
     * @Description Get the scoring policy to the same BSSID score
     *
     * @return int - score
     */
    int GetScoretacticsSameBssidScore(int instId = 0);

    /**
     * @Description Set the score policy for the same network
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsSameNetworkScore(const int &score, int instId = 0);

    /**
     * @Description Get the score policy for the same network
     *
     * @return int - score
     */
    int GetScoretacticsSameNetworkScore(int instId = 0);

    /**
     * @Description Set the 5 GHz score of the policy frequency
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsFrequency5GHzScore(const int &score, int instId = 0);

    /**
     * @Description Get the 5 GHz score of the policy frequency
     *
     * @return int - score
     */
    int GetScoretacticsFrequency5GHzScore(int instId = 0);

    /**
     * @Description Set the score policy. last select score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsLastSelectionScore(const int &score, int instId = 0);

    /**
     * @Description Get the score policy, last select score
     *
     * @return int - score
     */
    int GetScoretacticsLastSelectionScore(int instId = 0);

    /**
     * @Description Setting the Score Policy Security Score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsSecurityScore(const int &score, int instId = 0);

    /**
     * @Description Get the Score Policy Security Score
     *
     * @return int - priority
     */
    int GetScoretacticsSecurityScore(int instId = 0);

    /**
     * @Description Setting the Score Policy Candidate Score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetScoretacticsNormalScore(const int &score, int instId = 0);

    /**
     * @Description Get the Score Policy Candidate Score
     *
     * @return int - score
     */
    int GetScoretacticsNormalScore(int instId = 0);

    /**
     * @Description Set the saved device appraisal priority
     *
     * @param priority - priority
     * @return int - 0 success
     */
    int SetSavedDeviceAppraisalPriority(const int &priority, int instId = 0);

    /**
     * @Description Get the saved device appraisal priority
     *
     * @return int - priority
     */
    int GetSavedDeviceAppraisalPriority(int instId = 0);

    /**
     * @Description Judge the Module need preloaded or not
     *
     * @param name - module name
     * @return true - need preload
     * @return false - no need preload
     */
    bool IsModulePreLoad(const std::string &name);

    /**
     * @Description Save wps connection device config
     *
     * @param config - input WifiDeviceConfig struct
     * @return int - 0 success; -1 load the device config file failed
     */
    int AddWpsDeviceConfig(const WifiDeviceConfig &config);
    /**
     * @Description Get the Support HwPno Flag object
     *
     * @return true - support HwPno scan
     * @return false - not support HwPno scan
     */
    bool GetSupportHwPnoFlag(int instId = 0);
    /**
     * @Description Get the Min 2.4G strength object
     *
     * @return int Min 2.4G strength
     */
    int GetMinRssi2Dot4Ghz(int instId = 0);
    /**
     * @Description Get the Min 5G strength object
     *
     * @return int Min 5G strength
     */
    int GetMinRssi5Ghz(int instId = 0);

    /**
     * @Description Get the Alternate dns.
     *
     * @return string - dns
     */
    std::string GetStrDnsBak(int instId = 0);
    /**
     * @Description Obtaining Whether to Load the Configuration of the Standby STA.
     *
     * @return bool - Indicates whether to load the configuration of the standby STA.
     */
    bool IsLoadStabak(int instId = 0);

    /**
     * @Description Set the real mac address
     *
     * @param macAddress - the real mac address
     * @return int - 0 success
     */
    int SetRealMacAddress(const std::string &macAddress, int instId = 0);

    /**
     * @Description Get the real mac address
     *
     * @param macAddress - the real mac address
     * @return int - 0 success
     */
    int GetRealMacAddress(std::string &macAddress, int instId = 0);

    /**
     * @Description set the device name
     *
     * @param deviceName - device name
     * @return int - result
     */
    int SetP2pDeviceName(const std::string &deviceName);

    /**
     * @Description get trustlist policies.
     *
     * @return const std::vector<TrustListPolicy> - trustlist policies.
     */
    const std::vector<TrustListPolicy> ReloadTrustListPolicies();

    /**
     * @Description get moving freeze state trustlist.
     *
     * @return const MovingFreezePolicy - moving freeze policy.
     */
    const MovingFreezePolicy ReloadMovingFreezePolicy();

    /**
     * @Description get bssid of connection timeout for last time.
     *
     * @return bssid.
     */
    std::string GetConnectTimeoutBssid(int instId = 0);

    /**
     * @Description set bssid of connection timeout for last time.
     *
     * @return int - result
     */
    int SetConnectTimeoutBssid(std::string &bssid, int instId = 0);

    /**
     * @Description set default frequencies for specify country band.
     *
     */
    void SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies, int instId = 0);

    /**
     * @Description set type of GO group
     *
     * @param isExplicit true: created by user; false: created by auto negotiation
     */
    void SetExplicitGroup(bool isExplicit);

    /**
     * @Description get type of Go group
     *
     * @return true: created by user; false: created by auto negotiation
     */
    bool IsExplicitGroup(void);

    /**
     * @Description Set the thermal level
     *
     * @param level 0 COOL, 1 NORMAL, 2 WARM, 3 HOT, 4 OVERHEATED, 5 WARNING, 6 EMERGENCY
     */
    void SetThermalLevel(const int &level);

    /**
     * @Description Get the thermal level
     *
     * @return int 0 COOL, 1 NORMAL, 2 WARM, 3 HOT, 4 OVERHEATED, 5 WARNING, 6 EMERGENCY
     */
    int GetThermalLevel() const;

    /**
     * @Description SetThreadStatusFlag
     *
     * @param state true thread start, false thread end
     */
    void SetThreadStatusFlag(bool state);

    /**
     * @Description GetThreadStatusFlag
     *
     * @return ThreadStatusFlag
     */
    bool GetThreadStatusFlag(void) const;

    /**
     * @Description GetThreadStartTime
     *
     * @return StartTime
     */
    uint64_t GetThreadStartTime(void) const;

    /**
     * @Description Save the last disconnected reason
     *
     * @param discReason - discReason
     */
    void SaveDisconnectedReason(DisconnectedReason discReason, int instId = 0);

    /**
     * @Description Get the last disconnected reason
     *
     * @param discReason - discReason
     * @return int - 0 success
     */
    int GetDisconnectedReason(DisconnectedReason &discReason, int instId = 0);

    /**
     * @Description Set the Scan Only Switch State
     *
     * @param state - 1 on; 2 off
     */
    void SetScanOnlySwitchState(const int &state, int instId = 0);

    /**
     * @Description Get the Scan Only Switch State
     *
     * @return int - 1 on; 2 off
     */
    int GetScanOnlySwitchState(int instId = 0);
    /**
     * @Description Get the Scan Only Whether Available
     *
     * @return int - 1 on; 2 off
     */
    bool CheckScanOnlyAvailable(int instId = 0);

    /**
     * @Description Get sta ap exclusion type
     *
     * @return type - enum StaApExclusionType
     */
    int GetStaApExclusionType();

    /**
     * @Description Set sta ap exclusion type
     *
     * @param type - enum StaApExclusionType
     * @return int - 0 success
     */
    int SetStaApExclusionType(int type);

    /**
     * @Description Generate random number
     *
     * @return long int
     */
    long int GetRandom();
    /**
     * @Description generate a MAC address
     *
     * @param randomMacAddr - random MAC address[out]
     */
    void GenerateRandomMacAddress(std::string &randomMacAddr);
    /**
     * @Description Clear Hotspot config
     *
     * @return void
     */
    void ClearHotspotConfig();
    /**
     * @Description Encryption wifi device config
     *
     * @param config - Encryption wifiDeviceConfig
     */
    bool EncryptionDeviceConfig(WifiDeviceConfig &config) const;

    /**
     * @Description Set WifiDeviceConfig by randomizedMacSuccess
     *
     * @param networkId - networkId[in]
     * @return int - when 0 means success, other means some fails happened,
     *               Input state invalid or not find the wifi device config
     */
    int SetDeviceRandomizedMacSuccessEver(int networkId);
#ifdef FEATURE_ENCRYPTION_SUPPORT

    /**
     * @Description Decryption wifi device config
     *
     * @param config - Decryption wifiDeviceConfig
     */
    int DecryptionDeviceConfig(WifiDeviceConfig &config);

    /**
     * @Description Check WifiDeviceConfig is deciphered
     *
     * @param config - wifiDeviceConfig
     * @return bool - true: deciphered
     */
    bool IsWifiDeviceConfigDeciphered(const WifiDeviceConfig &config) const;
#endif
#ifdef SUPPORT_RANDOM_MAC_ADDR
    /**
     * @Description generate a MAC address
     *
     * @param peerBssid - real MAC address[in]
     * @param randomMacAddr - random MAC address[out]
     */
    void GenerateRandomMacAddress(std::string peerBssid, std::string &randomMacAddr);
    /**
     * @Description save a MAC address pair
     *
     * @param type - MAC address type[in]
     * @param realMacAddr - real MAC address[in]
     * @param randomAddr - random MAC address[in]
     * @return bool - false fail to save the MAC address, true success to save the MAC address
     */
    bool StoreWifiMacAddrPairInfo(WifiMacAddrInfoType type, const std::string &realMacAddr,
        const std::string &randomAddr);
    /**
     * @Description get random MAC address
     *
     * @param type - MAC address type[in]
     * @param bssid - MAC address
     * @return std::string - random MAC address
     */
    std::string GetRandomMacAddr(WifiMacAddrInfoType type, std::string bssid);
    /**
     * @Description remove MAC address pair
     *
     * @param type - MAC address type[in]
     * @param bssid - MAC address
     */
    void RemoveMacAddrPairInfo(WifiMacAddrInfoType type, std::string bssid);
    /**
     * @Description add a MAC address pair
     *
     * @param type - MAC address type[in]
     * @param macAddrInfo - MAC address info[in]
     * @param randomMacAddr - random MAC address[out]
     * @return WifiMacAddrErrCode - 0 success
     */
    WifiMacAddrErrCode AddMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo,
        std::string randomMacAddr);
    /**
     * @Description remove a MAC address pair
     *
     * @param type - MAC address type[in]
     * @param macAddrInfo - MAC address info[in]
     * @return int - 0 success
     */
    int RemoveMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo);
    /**
     * @Description query a MAC address pair
     *
     * @param type - MAC address type[in]
     * @param macAddrInfo - MAC address info[in]
     * @return std::string - an empty string indicates failure
     */
    std::string GetMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo);
    /**
     * @Description print MAC address pair
     *
     * @param type - MAC address type[in]
     */
    void PrintMacAddrPairs(WifiMacAddrInfoType type);
    /**
     * @Description Clear MAC address pair
     *
     * @param type - MAC address type[in]
     * @return std::string - an empty string indicates failure
     */
    void ClearMacAddrPairs(WifiMacAddrInfoType type);
#endif

    /**
     * @Description get softap random mac address
     *
     * @param randomMac - MAC address info[in]
     * @return int - 0 success
     */
    int GetApRandomMac(SoftApRandomMac &randomMac, int id);
    /**
     * @Description set softap random mac address
     *
     * @param randomMac - MAC address info[in]
     * @return int - 0 success
     */
    int SetApRandomMac(const SoftApRandomMac &randomMac, int id);

    /**
     * @Description Get next networkId
     *
     * @return int - next network id
     */
    int GetNextNetworkId();

#ifndef OHOS_ARCH_LITE
    /**
     * @Description Merge Localconfigs with cloneConfigs
     *
     * @param cloneData - wifi xml config
     */
    void MergeWifiCloneConfig(std::string &cloneData);
#endif

private:
    WifiSettings();
    void InitDefaultWifiConfig();
    void InitWifiConfig();
    void InitDefaultHotspotConfig();
    void InitHotspotConfig();
    void InitDefaultP2pVendorConfig();
    void InitP2pVendorConfig();
    void InitSettingsNum();
    void InitScanControlForbidList();
    void InitScanControlIntervalList();
    void InitScanControlInfo();
    void GetLinkedChannelWidth(int instId = 0);
    void UpdateLinkedInfo(int instId = 0);
#ifndef OHOS_ARCH_LITE
    void MergeSoftapConfig();
    void MergeWifiConfig();
    void ConfigsDeduplicateAndSave(std::vector<WifiDeviceConfig> &newConfigs);
#endif
    void InitPackageFilterConfig();

private:
    int mNetworkId;
    int mWifiStaCapabilities;            /* Sta capability */
    std::map <int, std::atomic<int>> mWifiState;         /* Sta service state */
    bool mWifiStoping;
    bool mSoftapToggled;
    bool mIsSupportCoex;
    std::string mStaIfaceName;
    std::string mP2pIfaceName;
    std::string mApIfaceName;
    std::vector<WifiScanInfo> mWifiScanInfoList;
    std::vector<WifiP2pGroupInfo> mGroupInfoList;
    std::vector<WifiStoreRandomMac> mWifiStoreRandomMac;
    std::map <int, ScanControlInfo> mScanControlInfo;
    WifiP2pLinkedInfo mWifiP2pInfo;
    WifiP2pGroupInfo m_P2pGroupInfo;
    std::map<int, WifiDeviceConfig> mWifiDeviceConfig;
    std::map <int, IpInfo> mWifiIpInfo;
    std::map <int, IpV6Info> mWifiIpV6Info;
    std::map <int, WifiLinkedInfo> mWifiLinkedInfo;
    std::map <int, std::string> mMacAddress;
    WifiPortalConf mPortalUri;
    std::map <int, std::atomic<int>> mHotspotState;
    std::map <int, HotspotConfig> mHotspotConfig;
    std::map <int, SoftApRandomMac> mApRandomMac;
    P2pVendorConfig mP2pVendorConfig;
    std::map<std::string, StationInfo> mConnectStationInfo;
    std::map<std::string, StationInfo> mBlockListInfo;
    ChannelsTable mValidChannels;
    std::atomic<int> mP2pState;
    std::atomic<int> mP2pDiscoverState;
    std::atomic<int> mP2pConnectState;
    int mApMaxConnNum;           /* ap support max sta numbers */
    int mMaxNumConfigs;          /* max saved configs numbers */
    std::map <int, int> mLastSelectedNetworkId;  /* last selected networkid */
    std::map <int, time_t> mLastSelectedTimeVal; /* last selected time */
    int mScreenState;            /* -1 MODE_STATE_DEFAULT 1 MODE_STATE_OPEN, 2 MODE_STATE_CLOSE */
    int mThermalLevel;           /* 1 COOL, 2 NORMAL, 3 WARM, 4 HOT, 5 OVERHEATED, 6 WARNING, 7 EMERGENCY */
    int mIdelState;              /* 1 MODE_STATE_OPEN, 2 MODE_STATE_CLOSE */
    int mBatteryChargeState;     /* 1 MODE_STATE_OPEN, 2 MODE_STATE_CLOSE */
    int mGnssFixState;           /* 1 MODE_STATE_OPEN, 2 MODE_STATE_CLOSE */
    int mScanGenieState;         /* 1 MODE_STATE_OPEN, 2 MODE_STATE_CLOSE */
    std::atomic<int> mAirplaneModeState;      /* 1 on 2 off */
    std::atomic<int> mPowerSleepState;        /* 1 on 2 off */
    ScanMode mAppRunningModeState; /* 0 app for 1 app back 2 sys for 3 sys back */
    int mPowerSavingModeState;   /* 1 on 2 off */
    std::string mAppPackageName;
    int mFreezeModeState;        /* 1 on 2 off */
    int mNoChargerPlugModeState;  /* 1 on 2 off */
    std::map <int, WifiConfig> mWifiConfig;
    std::map <int, std::pair<std::string, int>> mBssidToTimeoutTime;
    std::map<int, PowerModel> powerModel;
    int mHotspotIdleTimeout;
    std::map <int, DisconnectedReason> mLastDiscReason;
    std::string mUpperIfName;
    Hid2dUpperScene mUpperScene;
    P2pBusinessType mP2pBusinessType;
    int mPersistWifiState;

    std::map<WifiMacAddrInfo, std::string> mWifiScanMacAddrPair;
    std::map<WifiMacAddrInfo, std::string> mDeviceConfigMacAddrPair;
    std::map<WifiMacAddrInfo, std::string> mHotspotMacAddrPair;
    std::map<WifiMacAddrInfo, std::string> mP2pDeviceMacAddrPair;
    std::map<WifiMacAddrInfo, std::string> mP2pGroupsInfoMacAddrPair;
    std::map<WifiMacAddrInfo, std::string> mP2pCurrentgroupMacAddrPair;

    std::mutex mMacAddrPairMutex;
    std::mutex mStaMutex;
    std::mutex mApMutex;
    std::mutex mConfigMutex;
    std::mutex mConfigOnBootMutex;
    std::mutex mInfoMutex;
    std::mutex mP2pMutex;
    std::mutex mWifiConfigMutex;
    std::mutex mWifiToggledMutex;
    std::mutex mWifiSelfcureMutex;
    std::mutex mWifiStopMutex;
    std::mutex mSoftapToggledMutex;
    std::mutex mSyncWifiConfigMutex;

    std::atomic_flag deviceConfigLoadFlag = ATOMIC_FLAG_INIT;
    std::atomic_flag mEncryptionOnBootFalg = ATOMIC_FLAG_INIT;

    WifiConfigFileImpl<WifiDeviceConfig> mSavedDeviceConfig; /* Persistence device config */
    WifiConfigFileImpl<HotspotConfig> mSavedHotspotConfig;
    WifiConfigFileImpl<SoftApRandomMac> mSavedApRandomMac;
    WifiConfigFileImpl<StationInfo> mSavedBlockInfo;
    WifiConfigFileImpl<WifiConfig> mSavedWifiConfig;
    WifiConfigFileImpl<WifiP2pGroupInfo> mSavedWifiP2pGroupInfo;
    WifiConfigFileImpl<P2pVendorConfig> mSavedWifiP2pVendorConfig;
    WifiConfigFileImpl<TrustListPolicy> mTrustListPolicies;
    WifiConfigFileImpl<MovingFreezePolicy> mMovingFreezePolicy;
    MovingFreezePolicy mFPolicy;
    WifiConfigFileImpl<WifiStoreRandomMac> mSavedWifiStoreRandomMac;
    WifiConfigFileImpl<WifiPortalConf> mSavedPortal;
    WifiConfigFileImpl<PackageFilterConf> mPackageFilterConfig;
    bool explicitGroup;
    std::atomic_bool mThreadStatusFlag_ { false };
    std::atomic_uint64_t mThreadStartTime { 0 };
    std::map<std::string, std::vector<std::string>> mFilterMap;
    std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
    std::vector<std::string> mAbnormalAppList;

    std::unique_ptr<WifiEventHandler> mWifiEncryptionThread = nullptr;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
