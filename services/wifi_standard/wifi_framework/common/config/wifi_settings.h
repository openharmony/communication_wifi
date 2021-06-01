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

#ifndef OHOS_WIFI_SETTINGS_H
#define OHOS_WIFI_SETTINGS_H

#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <memory>
#include <mutex>
#include <algorithm>
#include "wifi_config_file_impl.h"

constexpr int MODE_STATE_OPEN = 1;
constexpr int MODE_STATE_CLOSE = 2;

constexpr int RANDOM_STR_LEN = 6;
constexpr int MSEC = 1000;
constexpr int FOREGROUND_SCAN_CONTROL_TIMES = 4;
constexpr int FOREGROUND_SCAN_CONTROL_INTERVAL = 2 * 60;
constexpr int BACKGROUND_SCAN_CONTROL_TIMES = 1;
constexpr int BACKGROUND_SCAN_CONTROL_INTERVAL = 30 * 60;
constexpr int PNO_SCAN_CONTROL_TIMES = 1;
constexpr int PNO_SCAN_CONTROL_INTERVAL = 20;
constexpr int SYSTEM_TIMER_SCAN_CONTROL_TIMES = 4;
constexpr int SYSTEM_TIMER_SCAN_CONTROL_INTERVAL = 20;
constexpr int MODE_ADD = 0;
constexpr int MODE_DEL = 1;
constexpr int MODE_UPDATE = 2;
/* Obtain the scanning result that is valid within 180s. */
constexpr int WIFI_GET_SCAN_RESULT_VALID_TIMESTAMP = 180;

constexpr char DEVICE_CONFIG_FILE_PATH[] = "./device_config.conf";
constexpr char HOTSPOT_CONFIG_FILE_PATH[] = "./hotspot_config.conf";
constexpr char BLOCK_LIST_FILE_PATH[] = "./block_list.conf";
constexpr char WIFI_CONFIG_FILE_PATH[] = "./wifi_config.conf";

namespace OHOS {
namespace Wifi {
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

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
    int GetWifiState() const;

    /**
     * @Description Save STA service state
     *
     * @param state - the wifi state
     * @return int - 0 success
     */
    int SetWifiState(int state);

    /**
     * @Description Get the ScanAlways switch state
     *
     * @return true - ScanAlways on, false - ScanAlways off
     */
    bool GetScanAlwaysState() const;

    /**
     * @Description Set the ScanAlways switch state
     *
     * @param isActive - ScanAlways on/off
     * @return int - 0 success
     */
    int SetScanAlwaysState(bool isActive);

    /**
     * @Description Save scan results
     *
     * @param results - vector scan results
     * @return int - 0 success
     */
    int SaveScanInfoList(const std::vector<WifiScanInfo> &results);

    /**
     * @Description Get scan results
     *
     * @param results - output vector of scan results
     * @return int - 0 success
     */
    int GetScanInfoList(std::vector<WifiScanInfo> &results);

    /**
     * @Description Get the scan control policy info
     *
     * @param info - output ScanControlInfo struct
     * @return int - 0 success
     */
    int GetScanControlInfo(ScanControlInfo &info);

    /**
     * @Description Save the scan control policy info
     *
     * @param info - input ScanControlInfo struct
     * @return int - 0 success
     */
    int SetScanControlInfo(const ScanControlInfo &info);

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
    int RemoveDeviceConfig(int networkId);

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
     * @param state - WifiDeviceConfigStatus INVALID/CURRENT/DISABLED/ENABLED/UNKNOWN
     * @param bSetOther - whether set other device config disabled
     * @return int - when 0 means success, other means some fails happened,
     *               Input state invalid or not find the wifi device config
     */
    int SetDeviceState(int networkId, int state, bool bSetOther = false);

    /**
     * @Description Synchronizing saved the wifi device config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncDeviceConfig();

    /**
     * @Description Reload wifi device config from config file
     *
     * @return int - 0 success; -1 read config file failed
     */
    int ReloadDeviceConfig();

    /**
     * @Description Get the dhcp info
     *
     * @param info - output DhcpInfo struct
     * @return int - 0 success
     */
    int GetDhcpInfo(DhcpInfo &info);

    /**
     * @Description Save dhcp info
     *
     * @param info - input DhcpInfo struct
     * @return int - 0 success
     */
    int SaveDhcpInfo(const DhcpInfo &info);

    /**
     * @Description Get current link info
     *
     * @param info - output WifiLinkedInfo struct
     * @return int - 0 success
     */
    int GetLinkedInfo(WifiLinkedInfo &info);

    /**
     * @Description Save link info
     *
     * @param info - input WifiLinkedInfo struct
     * @return int - 0 success
     */
    int SaveLinkedInfo(const WifiLinkedInfo &info);

    /**
     * @Description Save mac address
     *
     * @param macAddress - mac address info
     * @return int - 0 success
     */
    int SetMacAddress(const std::string &macAddress);

    /**
     * @Description Get the mac address
     *
     * @param macAddress - output mac address info
     * @return int - 0 success
     */
    int GetMacAddress(std::string &macAddress);

    /**
     * @Description Save the country code
     *
     * @param countryCode - input country code
     * @return int - 0 success
     */
    int SetCountryCode(const std::string &countryCode);

    /**
     * @Description Get the country code
     *
     * @param countryCode - output country code
     * @return int - 0 success
     */
    int GetCountryCode(std::string &countryCode);

    /**
     * @Description Get current hotspot state
     *
     * @return int - the hotspot state, IDLE/STARTING/STARTED/CLOSING/CLOSED
     */
    int GetHotspotState();

    /**
     * @Description Save current hotspot state
     *
     * @param state - hotspot state
     * @return int - 0 success
     */
    int SetHotspotState(int state);

    /**
     * @Description Set the hotspot config
     *
     * @param config - input HotspotConfig struct
     * @return int - 0 success
     */
    int SetHotspotConfig(const HotspotConfig &config);

    /**
     * @Description Get the hotspot config
     *
     * @param config - output HotspotConfig struct
     * @return int - 0 success
     */
    int GetHotspotConfig(HotspotConfig &config);

    /**
     * @Description Synchronizing saved the Hotspot config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncHotspotConfig();

    /**
     * @Description Get current hotspot accept linked stations
     *
     * @param results - output StationInfo results
     * @return int - 0 success
     */
    int GetStationList(std::vector<StationInfo> &results);

    /**
     * @Description Management (add/update/delete) connected station list
     *
     * @param info - input StationInfo struct
     * @param mode - mode of MODE_ADD MODE_UPDATE MODE_DEL
     * @return int - 0 success; -1 mode not correct
     */
    int ManageStation(const StationInfo &info, int mode); /* add / update / remove */

    /**
     * @Description Clear connected station list
     *
     * @return int - 0 success
     */
    int ClearStationList();

    /**
     * @Description Get the block list
     *
     * @param results - output StationInfo results
     * @return int - 0 success
     */
    int GetBlockList(std::vector<StationInfo> &results);

    /**
     * @Description Manager (add/update/delete) station connect Blocklist
     *
     * @param info - input StationInfo struct
     * @param mode - mode of MODE_ADD MODE_DEL MODE_UPDATE
     * @return int - 0 success; -1 mode not correct
     */
    int ManageBlockList(const StationInfo &info, int mode); /* add / remove */

    /**
     * @Description Judge whether the station is in current linked station list
     *
     * @param info - input StationInfo struct
     * @return int - 0 find the station, exist; -1 not find, not exist
     */
    int FindConnStation(const StationInfo &info);

    /**
     * @Description Synchronizing saved the block list config into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncBlockList();

    /**
     * @Description Get the Valid Bands object
     *
     * @param bands - output vector fo BandType
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
     * @Description Get signal level about given rssi and band
     *
     * @param rssi - rssi info
     * @param band - band info
     * @return int - level
     */
    int GetSignalLevel(const int &rssi, const int &band);

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
    bool EnableNetwork(int networkId, bool disableOthers);

    /**
     * @Description Set the User Last Selected Network Id
     *
     * @param networkId - network id
     */
    void SetUserLastSelectedNetworkId(int networkId);

    /**
     * @Description Get the User Last Selected Network Id
     *
     * @return int - network id
     */
    int GetUserLastSelectedNetworkId();

    /**
     * @Description Get the User Last Selected Network time
     *
     * @return time_t - timestamp
     */
    time_t GetUserLastSelectedNetworkTimeVal();

    /**
     * @Description Synchronizing saved the WifiConfig into config file
     *
     * @return int - 0 success; -1 save file failed
     */
    int SyncWifiConfig();

    /**
     * @Description Get the config whether permit to use wifi when airplane mode opened
     *
     * @return true - can use
     * @return false - cannot use
     */
    bool GetCanUseStaWhenAirplaneMode();

    /**
     * @Description Set the config whether permit to use wifi when airplane mode opened
     *
     * @param bCan - true / false
     * @return int - 0 success
     */
    int SetCanUseStaWhenAirplaneMode(bool bCan);

    /**
     * @Description Get the STA service last running state
     *
     * @return true - running
     * @return false - not running
     */
    bool GetStaLastRunState();

    /**
     * @Description Set the STA service running state
     *
     * @param bRun - running or not
     * @return int - 0 success
     */
    int SetStaLastRunState(bool bRun);

    /**
     * @Description Get the Dhcp Ip Type
     *
     * @return int - dhcp ip type, ipv4/ipv6/double
     */
    int GetDhcpIpType();

    /**
     * @Description Set the Dhcp Ip Type
     *
     * @param dhcpIpType - ipv4/ipv6/double
     * @return int - 0 success
     */
    int SetDhcpIpType(int dhcpIpType);

    /**
     * @Description Get the Default Wifi Interface
     *
     * @return std::string - interface name
     */
    std::string GetDefaultWifiInterface();

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
    int GetScreenState();

    /**
     * @Description Set the Airplane Mode State
     *
     * @param state - 1 open; 2 close
     */
    void SetAirplaneModeState(const int &state);

    /**
     * @Description Get the Airplane Mode State
     *
     * @return int - 1 open; 2 close
     */
    int GetAirplaneModeState();

    /**
     * @Description Set the App Running State
     *
     * @param state - 1 front; 2 backend
     */
    void SetAppRunningState(const int &state);

    /**
     * @Description Get the App Running State
     *
     * @return int - 1 front; 2 backend
     */
    int GetAppRunningState();

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
    int GetPowerSavingModeState();

    /**
     * @Description Set enable/disable Whether to allow network switchover
     *
     * @param bSwitch - enable/disable
     * @return int - 0 success
     */
    int SetWhetherToAllowNetworkSwitchover(bool bSwitch);

    /**
     * @Description Check whether enable network switchover
     *
     * @return true - enable
     * @return false - disable
     */
    bool GetWhetherToAllowNetworkSwitchover();

    /**
     * @Description Set the policy score slope
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsScoreSlope(const int &score);

    /**
     * @Description Get the policy score slope
     *
     * @return int - score
     */
    int GetscoretacticsScoreSlope();

    /**
     * @Description Initial score of the set strategy
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsInitScore(const int &score);

    /**
     * @Description Obtain the initial score of the tactic
     *
     * @return int - score
     */
    int GetscoretacticsInitScore();

    /**
     * @Description Set the scoring policy to the same BSSID score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsSameBssidScore(const int &score);

    /**
     * @Description Get the scoring policy to the same BSSID score
     *
     * @return int - score
     */
    int GetscoretacticsSameBssidScore();

    /**
     * @Description Set the score policy for the same network
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsSameNetworkScore(const int &score);

    /**
     * @Description Get the score policy for the same network
     *
     * @return int - score
     */
    int GetscoretacticsSameNetworkScore();

    /**
     * @Description Set the 5 GHz score of the policy frequency
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsFrequency5GHzScore(const int &score);

    /**
     * @Description Get the 5 GHz score of the policy frequency
     *
     * @return int - score
     */
    int GetscoretacticsFrequency5GHzScore();

    /**
     * @Description Set the score policy. last select score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsLastSelectionScore(const int &score);

    /**
     * @Description Get the score policy, last select score
     *
     * @return int - score
     */
    int GetscoretacticsLastSelectionScore();

    /**
     * @Description Setting the Score Policy Security Score
     *
     * @param score - score
     * @return int - 0 success
     */
    int SetscoretacticsSecurityScore(const int &score);

    /**
     * @Description Get the Score Policy Security Score
     *
     * @return int - priority
     */
    int GetscoretacticsSecurityScore();

    /**
     * @Description Set the saved network evaluator priority
     *
     * @param priority - priority
     * @return int - 0 success
     */
    int SetsavedNetworkEvaluatorPriority(const int &priority);

    /**
     * @Description Get the saved network evaluator priority
     *
     * @return int - priority
     */
    int GetsavedNetworkEvaluatorPriority();

    /**
     * @Description Set the priority of the network evaluator for the score.
     *
     * @param priority - priority
     * @return int - 0 success
     */
    int SetscoredNetworkEvaluatorPriority(const int &priority);

    /**
     * @Description Get the priority of the network evaluator for the score
     *
     * @return int - priority
     */
    int GetscoredNetworkEvaluatorPriority();

    /**
     * @Description Set Pass Network Evaluator Priority
     *
     * @param priority - priority
     * @return int - 0 success
     */
    int SetpasspointNetworkEvaluatorPriority(const int &priority);

    /**
     * @Description Get Pass Network Evaluator Priority
     *
     * @return int - priority
     */
    int GetpasspointNetworkEvaluatorPriority();

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
    bool GetSupportHwPnoFlag();
    /**
     * @Description Get the Min 2.4G strength object
     *
     * @return int Min 2.4G strength
     */
    int GetMinRssi2Dot4Ghz();
    /**
     * @Description Get the Min 5G strength object
     *
     * @return int Min 5G strength
     */
    int GetMinRssi5Ghz();

private:
    WifiSettings();

    /**
     * @Description Initial default Hotspot configuration
     *
     */
    void InitDefaultHotspotConfig();

    /**
     * @Description Init maximum number of connections
     *
     */
    void InitGetApMaxConnNum();
    /**
     * @Description:Preset Scanning Control Policy
     *
     */
    void InitScanControlInfo();

private:
    int mWifiStaCapabilities;            /* Sta capability */
    std::atomic<int> mWifiState;         /* Sta service state */
    std::atomic<bool> mScanAlwaysActive; /* if scan always */
    std::vector<WifiScanInfo> mWifiScanInfoList;
    ScanControlInfo mScanControlInfo;
    std::map<int, WifiDeviceConfig> mWifiDeviceConfig;
    DhcpInfo mWifiDhcpInfo;
    WifiLinkedInfo mWifiLinkedInfo;
    std::string mMacAddress;
    std::string mCountryCode;
    std::atomic<int> mHotspotState;
    HotspotConfig mHotspotConfig;
    std::map<std::string, StationInfo> mConnectStationInfo;
    std::map<std::string, StationInfo> mBlockListInfo;
    ChannelsTable mValidChannels;
    int mApMaxConnNum;           /* ap support max sta numbers */
    int mLastSelectedNetworkId;  /* last selected networkid */
    time_t mLastSelectedTimeVal; /* last selected time */
    int mScreenState;            /* 1 on 2 off */
    int mAirplaneModeState;      /* 1 on 2 off */
    int mAppRunningModeState;    /* 1 front 2 backend */
    int mPowerSavingModeState;   /* 1 on 2 off */
    WifiConfig mWifiConfig;

    std::mutex mStaMutex;
    std::mutex mApMutex;
    std::mutex mConfigMutex;
    std::mutex mInfoMutex;

    WifiConfigFileImpl<WifiDeviceConfig> mSavedDeviceConfig; /* Persistence device config */
    WifiConfigFileImpl<HotspotConfig> mSavedHotspotConfig;
    WifiConfigFileImpl<StationInfo> mSavedBlockInfo;
    WifiConfigFileImpl<WifiConfig> mSavedWifiConfig;
};
}  // namespace Wifi
}  // namespace OHOS
#endif