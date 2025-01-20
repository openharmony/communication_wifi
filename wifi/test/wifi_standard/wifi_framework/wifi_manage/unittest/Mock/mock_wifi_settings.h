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

#ifndef OHOS_MOCK_WIFISETTINGS_H
#define OHOS_MOCK_WIFISETTINGS_H

#include <gmock/gmock.h>
#include <map>
#include <string>
#include <vector>
#include "wifi_p2p_msg.h"
#include "wifi_scan_msg.h"
#include "wifi_msg.h"
#include "wifi_internal_msg.h"
#include "wifi_ap_msg.h"

namespace OHOS {
namespace Wifi {
inline const int MODE_ADD = 0;
inline const int MODE_DEL = 1;
inline const int MODE_UPDATE = 2;
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int SetWifiState(int state, int instId = 0) = 0;
    virtual int AddDeviceConfig(const WifiDeviceConfig &config) = 0;
    virtual int RemoveDevice(int networkId) = 0;
    virtual void ClearDeviceConfig() = 0;
    virtual int GetDeviceConfig(std::vector<WifiDeviceConfig> &results, int instId = 0) = 0;
    virtual int GetDeviceConfig(const int &networkId, WifiDeviceConfig &config, int instId = 0) = 0;
    virtual int GetDeviceConfig(
        const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config, int instId = 0) = 0;
    virtual int GetDeviceConfig(
        const std::string &index, const int &indexType, WifiDeviceConfig &config, int instId = 0) = 0;
    virtual void SetUserConnectChoice(int networkId) = 0;
    virtual void ClearAllNetworkConnectChoice() = 0;
    virtual bool ClearNetworkConnectChoice(int networkId) = 0;
    virtual void RemoveConnectChoiceFromAllNetwork(int networkId) = 0;
    virtual bool SetNetworkConnectChoice(int networkId, int selectNetworkId, long timestamp) = 0;
    virtual bool ClearNetworkCandidateScanResult(int networkId) = 0;
    virtual bool SetNetworkCandidateScanResult(int networkId) = 0;
    virtual int GetCandidateConfigWithoutUid(const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config) = 0;
    virtual int SyncDeviceConfig() = 0;
    virtual int ReloadDeviceConfig() = 0;
    virtual int GetIpInfo(IpInfo &info, int instId = 0) = 0;
    virtual int SaveIpInfo(const IpInfo &info, int instId = 0) = 0;
    virtual int GetLinkedInfo(WifiLinkedInfo &info, int instId = 0) = 0;
    virtual int SaveLinkedInfo(const WifiLinkedInfo &info, int instId = 0) = 0;
    virtual int SetMacAddress(const std::string &macAddress, int instId = 0) = 0;
    virtual int GetMacAddress(std::string &macAddress, int instId = 0) = 0;
    virtual int SetCountryCode(const std::string &countryCode) = 0;
    virtual int GetCountryCode(std::string &countryCode) = 0;
    virtual int GetSignalLevel(const int &rssi, const int &band, int instId = 0) = 0;
    virtual bool EnableNetwork(int networkId, bool disableOthers, int instId = 0) = 0;
    virtual void SetUserLastSelectedNetworkId(int networkId, int instId = 0) = 0;
    virtual int GetUserLastSelectedNetworkId(int instId = 0) = 0;
    virtual time_t GetUserLastSelectedNetworkTimeVal(int instId = 0) = 0;
    virtual int GetDhcpIpType(int instId = 0) = 0;
    virtual int SetDhcpIpType(int dhcpIpType, int instId = 0) = 0;
    virtual int SetWhetherToAllowNetworkSwitchover(bool bSwitch, int instId = 0) = 0;
    virtual bool GetWhetherToAllowNetworkSwitchover(int instId = 0) = 0;
    virtual int GetSavedDeviceAppraisalPriority(int instId = 0) = 0;
    virtual int GetExternDeviceAppraisalPriority() = 0;
    virtual int GetScoretacticsScoreSlope(int instId = 0) = 0;
    virtual int GetScoretacticsInitScore(int instId = 0) = 0;
    virtual int GetScoretacticsSameBssidScore(int instId = 0) = 0;
    virtual int GetScoretacticsSameNetworkScore(int instId = 0) = 0;
    virtual int GetScoretacticsFrequency5GHzScore(int instId = 0) = 0;
    virtual int GetScoretacticsLastSelectionScore(int instId = 0) = 0;
    virtual int GetScoretacticsSecurityScore(int instId = 0) = 0;
    virtual std::string GetStrDnsBak(int instId = 0) = 0;
    virtual int GetScanInfoList(std::vector<WifiScanInfo> &results) = 0;
    virtual std::string GetConnectTimeoutBssid(int instId = 0) = 0;
    virtual int SetConnectTimeoutBssid(std::string &bssid, int instId = 0) = 0;
    virtual int SetDeviceAfterConnect(int networkId) = 0;
    virtual int GetCandidateConfig(const int uid, const int &networkId, WifiDeviceConfig &config) = 0;
    virtual int GetAllCandidateConfig(const int uid, std::vector<WifiDeviceConfig> &configs) = 0;
    virtual int GetValidChannels(ChannelsTable &channelsInfo) = 0;
    virtual int GetWifiState(int instId = 0) = 0;
    virtual int SetDeviceConnFailedCount(const std::string &index, const int &indexType, int count) = 0;
    virtual int IncreaseDeviceConnFailedCount(const std::string &index, const int &indexType, int count) = 0;
    virtual int SaveIpV6Info(const IpV6Info &info, int instId = 0) = 0;
    virtual int GetIpv6Info(IpV6Info &info, int instId = 0) = 0;
    virtual int SetRealMacAddress(const std::string &macAddress, int instId = 0) = 0;
    virtual int GetRealMacAddress(std::string &macAddress, int instId = 0) = 0;
    virtual int GetScoretacticsNormalScore(int instId = 0) = 0;
    virtual int SetWifiLinkedStandardAndMaxSpeed(WifiLinkedInfo &linkInfo) = 0;
    virtual void SaveDisconnectedReason(DisconnectedReason discReason, int instId = 0) = 0;
    virtual void InsertWifiCategoryBlackListCache(int blacklistType, const std::string currentBssid,
        const WifiCategoryBlackListInfo wifi6BlackListInfo) = 0;
    virtual void RemoveWifiCategoryBlackListCache(int blacklistType, const std::string bssid) = 0;
    virtual int GetWifiCategoryBlackListCache(int blacklistType,
        std::map<std::string, WifiCategoryBlackListInfo> &blackListCache) const = 0;
    virtual void UpdateWifiConnectFailListCache(int blacklistType, const std::string bssid,
        const WifiCategoryConnectFailInfo wifiConnectFailInfo) = 0;
    virtual void RemoveWifiConnectFailListCache(const std::string bssid) = 0;
    virtual int GetWifiConnectFailListCache(
        std::map<std::string, WifiCategoryConnectFailInfo> &connectFailCache) const = 0;
    virtual std::string GetStaIfaceName() = 0;
    virtual void SetWifiSelfcureReset(const bool isReset) = 0;
    virtual bool GetWifiSelfcureReset() const = 0;
    virtual void SetLastNetworkId(const int networkId) = 0;
    virtual int GetLastNetworkId() const = 0;
    virtual int GetP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual void SetWifiToggledState(int state) = 0;
    virtual int GetScreenState() const = 0;
    virtual int SetDeviceRandomizedMacSuccessEver(int networkId) = 0;
    virtual bool StoreWifiMacAddrPairInfo(WifiMacAddrInfoType type, const std::string &realMacAddr,
        const std::string &randomAddr) = 0;
    virtual void UpdateLinkedChannelWidth(std::string bssid, WifiChannelWidth channelWidth, int instId = 0) = 0;
    virtual int GetNoChargerPlugModeState() const = 0  ;
    virtual int GetPackageInfoMap(std::map<std::string, std::vector<PackageInfo>> &filterMap) = 0;
    virtual int GetPowerIdelState()  const = 0 ;
    virtual int GetGnssFixState() const = 0;
    virtual int GetAbnormalApps(std::vector<std::string> &abnormalAppList) = 0;
    virtual int GetScanGenieState() const = 0;
    virtual int ClearScanInfoList() = 0;
    virtual int SetValidChannels(const ChannelsTable &channelsInfo) = 0;
    virtual int SaveScanInfoList(const std::vector<WifiScanInfo> &results) = 0;
    virtual int GetMinRssi2Dot4Ghz(int instId = 0) = 0;
    virtual int GetMinRssi5Ghz(int instId = 0) = 0;
    virtual ScanMode GetAppRunningState() = 0;
    virtual int GetFreezeModeState() const = 0;
    virtual const std::string GetAppPackageName() const = 0;
    virtual const std::vector<TrustListPolicy> ReloadTrustListPolicies() = 0;
    virtual const MovingFreezePolicy ReloadMovingFreezePolicy() = 0;
    virtual int GetThermalLevel() const = 0;
    virtual int GetHid2dUpperScene(int uid, Hid2dUpperScene &scene) = 0;
    virtual int64_t GetHid2dSceneLastSetTime() const = 0;
    virtual int SetHid2dSceneLastSetTime(int64_t setTime) = 0;
    virtual int GetP2pBusinessType(P2pBusinessType &type) = 0;
    virtual int SetHid2dUpperScene(int uid, const Hid2dUpperScene &scene) = 0;
    virtual int SetWifiDetailState(WifiDetailState state, int instId) = 0;
    virtual bool EncryptionDeviceConfig(WifiDeviceConfig &config) const = 0;
    virtual bool GetRandomMac(WifiStoreRandomMac &randomMacInfo) = 0;
    virtual void GenerateRandomMacAddress(std::string &randomMacAddr) = 0;
    virtual void GenerateRandomMacAddress(std::string peerBssid, std::string &randomMacAddr) = 0;
    virtual bool AddRandomMac(WifiStoreRandomMac &randomMacInfo) = 0;
    virtual int AddWpsDeviceConfig(const WifiDeviceConfig &config) = 0;
    virtual void SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies,
        int instId = 0) = 0;
    virtual int GetNextNetworkId() = 0;
    virtual  int GetWifiStaCapabilities() const = 0;
    virtual int SetWifiStaCapabilities(int capabilities) = 0;
    virtual WifiDetailState GetWifiDetailState(int instId = 0) = 0;
    virtual void SetWifiAllowSemiActive(bool isAllowed) = 0;
    virtual bool GetWifiAllowSemiActive() const = 0;
    virtual void SetPersistWifiState(int state) = 0;
    virtual int GetPersistWifiState() = 0;
    virtual int GetWifiToggledEnable() = 0;
    virtual void SetWifiStopState(bool state) = 0;
    virtual bool GetWifiStopState() const= 0;
    virtual void SetCoexSupport(bool isSupport) = 0;
    virtual bool GetCoexSupport() const = 0;
    virtual void SetStaIfaceName(const std::string &ifaceName) = 0;
    virtual int GetHiddenDeviceConfig(std::vector<WifiDeviceConfig> &results) = 0;
    virtual int IncreaseNumRebootsSinceLastUse()= 0;
    virtual int RemoveExcessDeviceConfigs(std::vector<WifiDeviceConfig> &configs) const = 0;
    virtual void EncryptionWifiDeviceConfigOnBoot()= 0;
    virtual int GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups) = 0;
    virtual std::map<int, WifiLinkedInfo> GetAllWifiLinkedInfo() = 0;
    virtual std::string GetConnectedBssid(int instId = 0) = 0;
    virtual int ReloadStaRandomMac() = 0;
    virtual int ReloadPortalconf() = 0;
    virtual void ClearRandomMacConfig() = 0;
    virtual std::string FuzzyBssid(const std::string bssid) = 0;
    virtual bool RemoveRandomMac(const std::string &bssid, const std::string &randomMac) = 0;
    virtual int GetStationList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageStation(const StationInfo &info, int mode, int id = 0) = 0;
    virtual int ClearStationList(int id = 0)= 0;
    virtual int GetBlockList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageBlockList(const StationInfo &info, int mode, int id = 0) = 0;
    virtual int FindConnStation(const StationInfo &info, int id = 0) = 0;
    virtual int SyncBlockList()= 0;
    virtual int GetValidBands(std::vector<BandType> &bands)= 0;
    virtual int ClearValidChannels()= 0;
    virtual int SetPowerModel(const PowerModel& model, int id = 0)= 0;
    virtual int GetPowerModel(PowerModel& model, int id = 0) = 0;
    virtual int GetOperatorWifiType(int instId = 0) = 0;
    virtual int SetOperatorWifiType(int type, int instId = 0) = 0;
    virtual int GetLastAirplaneMode(int instId = 0) = 0;
    virtual int SetLastAirplaneMode(int mode, int instId = 0) = 0;
    virtual bool GetCanOpenStaWhenAirplaneMode(int instId = 0) = 0;
    virtual bool GetWifiFlagOnAirplaneMode(int instId = 0) = 0;
    virtual int SetWifiFlagOnAirplaneMode(bool ifOpen, int instId = 0) = 0;
    virtual int SetWifiDisabledByAirplane(bool disabledByAirplane, int instId = 0) = 0;
    virtual bool GetWifiDisabledByAirplane(int instId = 0) = 0;
    virtual int GetStaLastRunState(int instId = 0) = 0;
    virtual int SetStaLastRunState(int bRun, int instId = 0) = 0;
    virtual std::string GetDefaultWifiInterface(int instId = 0) = 0;
    virtual bool IsLoadStabak(int instId = 0) = 0;
    virtual int GetDisconnectedReason(DisconnectedReason &discReason, int instId = 0) = 0;
    virtual void SetScanOnlySwitchState(const int &state, int instId = 0) = 0;
    virtual  bool IsModulePreLoad(const std::string &name) = 0;
    virtual WifiP2pGroupInfo GetCurrentP2pGroupInfo() = 0;
    virtual int GetHotspotState(int id = 0) = 0;
    virtual bool SetWifiStateOnAirplaneChanged(const int &state);
    virtual int GetScanControlInfo(ScanControlInfo &info, int instId = 0) = 0;
    virtual bool GetScanAlwaysState(int instId) = 0;
    virtual bool GetSupportHwPnoFlag(int instId = 0) = 0;
    virtual int SetAcceptUnvalidated(int networkId, bool state) = 0;
    virtual int GetHotspotConfig(HotspotConfig &hotspotConfig, int id) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    static WifiSettings &GetInstance(void);
    MOCK_METHOD2(SetWifiState, int(int state, int));
    MOCK_METHOD1(AddDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_METHOD1(RemoveDevice, int(int networkId));
    MOCK_METHOD0(ClearDeviceConfig, void());
    MOCK_METHOD2(GetDeviceConfig, int(std::vector<WifiDeviceConfig> &results, int));
    MOCK_METHOD3(GetDeviceConfig, int(const int &networkId, WifiDeviceConfig &config, int));
    MOCK_METHOD4(
        GetDeviceConfig, int(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config, int));
    MOCK_METHOD4(
        GetDeviceConfig, int(const std::string &index, const int &indexType, WifiDeviceConfig &config, int));
    MOCK_METHOD1(SetUserConnectChoice, void(int networkId));
    MOCK_METHOD0(ClearAllNetworkConnectChoice, void());
    MOCK_METHOD1(ClearNetworkConnectChoice, bool(int networkId));
    MOCK_METHOD1(RemoveConnectChoiceFromAllNetwork, void(int networkId));
    MOCK_METHOD3(SetNetworkConnectChoice, bool(int networkId, int selectNetworkId, long timestamp));
    MOCK_METHOD1(ClearNetworkCandidateScanResult, bool(int networkId));
    MOCK_METHOD1(SetNetworkCandidateScanResult, bool(int networkId));
    MOCK_METHOD3(GetCandidateConfigWithoutUid, int(const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config));
    MOCK_METHOD0(SyncDeviceConfig, int());
    MOCK_METHOD0(ReloadDeviceConfig, int());
    MOCK_METHOD2(GetIpInfo, int(IpInfo &info, int));
    MOCK_METHOD2(SaveIpInfo, int(const IpInfo &info, int));
    MOCK_METHOD2(GetLinkedInfo, int(WifiLinkedInfo &info, int));
    MOCK_METHOD2(SaveLinkedInfo, int(const WifiLinkedInfo &info, int));
    MOCK_METHOD2(SetMacAddress, int(const std::string &macAddress, int));
    MOCK_METHOD2(GetMacAddress, int(std::string &macAddress, int));
    MOCK_METHOD1(SetCountryCode, int(const std::string &countryCode));
    MOCK_METHOD1(GetCountryCode, int(std::string &countryCode));
    MOCK_METHOD3(GetSignalLevel, int(const int &rssi, const int &band, int));
    MOCK_METHOD3(EnableNetwork, bool(int networkId, bool disableOthers, int));
    MOCK_METHOD2(SetUserLastSelectedNetworkId, void(int networkId, int));
    MOCK_METHOD1(GetUserLastSelectedNetworkId, int(int));
    MOCK_METHOD1(GetUserLastSelectedNetworkTimeVal, time_t(int));
    MOCK_METHOD1(GetDhcpIpType, int(int));
    MOCK_METHOD2(SetDhcpIpType, int(int dhcpIpType, int));
    MOCK_METHOD2(SetWhetherToAllowNetworkSwitchover, int(bool bSwitch, int));
    MOCK_METHOD1(GetWhetherToAllowNetworkSwitchover, bool(int));
    MOCK_METHOD1(GetSavedDeviceAppraisalPriority, int(int));
    MOCK_METHOD0(GetExternDeviceAppraisalPriority, int());
    MOCK_METHOD1(GetScoretacticsScoreSlope, int(int));
    MOCK_METHOD1(GetScoretacticsInitScore, int(int));
    MOCK_METHOD1(GetScoretacticsSameBssidScore, int(int));
    MOCK_METHOD1(GetScoretacticsSameNetworkScore, int(int));
    MOCK_METHOD1(GetScoretacticsFrequency5GHzScore, int(int));
    MOCK_METHOD1(GetScoretacticsLastSelectionScore, int(int));
    MOCK_METHOD1(GetScoretacticsSecurityScore, int(int));
    MOCK_METHOD1(GetStrDnsBak, std::string(int));
    MOCK_METHOD1(GetScanInfoList, int(std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(GetConnectTimeoutBssid, std::string(int));
    MOCK_METHOD2(SetConnectTimeoutBssid, int(std::string &bssid, int));
    MOCK_METHOD1(SetDeviceAfterConnect, int(int networkId));
    MOCK_METHOD3(GetCandidateConfig, int(const int uid, const int &networkId, WifiDeviceConfig &config));
    MOCK_METHOD2(GetAllCandidateConfig, int(const int uid, std::vector<WifiDeviceConfig> &configs));
    MOCK_METHOD1(GetValidChannels, int(ChannelsTable &channelsInfo));
    MOCK_METHOD1(GetWifiState, int(int));
    MOCK_METHOD3(SetDeviceConnFailedCount, int(const std::string &index, const int &indexType, int count));
    MOCK_METHOD3(IncreaseDeviceConnFailedCount, int(const std::string &index, const int &indexType, int count));
    MOCK_METHOD2(SaveIpV6Info, int(const IpV6Info &info, int));
    MOCK_METHOD2(GetIpv6Info, int(IpV6Info &info, int));
    MOCK_METHOD2(SetRealMacAddress, int(const std::string &macAddress, int));
    MOCK_METHOD2(GetRealMacAddress, int(std::string &macAddress, int));
    MOCK_METHOD1(GetScoretacticsNormalScore, int(int));
    MOCK_METHOD1(SetWifiLinkedStandardAndMaxSpeed, int(WifiLinkedInfo &linkInfo));
    MOCK_METHOD2(SaveDisconnectedReason, void(DisconnectedReason discReason, int));
    MOCK_METHOD3(InsertWifiCategoryBlackListCache, void(int blacklistType, const std::string currentBssid,
        const WifiCategoryBlackListInfo wifi6BlackListInfo));
    MOCK_METHOD2(RemoveWifiCategoryBlackListCache, void(int blacklistType, const std::string bssid));
    MOCK_CONST_METHOD2(GetWifiCategoryBlackListCache, int(int blacklistType,
        std::map<std::string, WifiCategoryBlackListInfo> &blackListCache));
    MOCK_METHOD3(UpdateWifiConnectFailListCache, void(int blacklistType, const std::string bssid,
        const WifiCategoryConnectFailInfo wifiConnectFailInfo));
    MOCK_METHOD1(RemoveWifiConnectFailListCache, void(const std::string bssid));
    MOCK_CONST_METHOD1(GetWifiConnectFailListCache, int(
        std::map<std::string, WifiCategoryConnectFailInfo> &connectFailCache));
    MOCK_METHOD0(GetStaIfaceName, std::string());
    MOCK_METHOD1(SetWifiSelfcureReset, void(const bool isReset));
    MOCK_CONST_METHOD0(GetWifiSelfcureReset, bool());
    MOCK_METHOD1(SetLastNetworkId, void(const int networkId));
    MOCK_CONST_METHOD0(GetLastNetworkId, int());
    MOCK_METHOD1(GetP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD1(SetWifiToggledState, void(int state));
    MOCK_CONST_METHOD0(GetScreenState, int());
    MOCK_METHOD1(SetDeviceRandomizedMacSuccessEver, int(int networkId));
    MOCK_METHOD1(SetValidChannels, int(const ChannelsTable &channelsInfo));
    MOCK_METHOD1(GetPackageInfoMap,  int(std::map<std::string, std::vector<PackageInfo>> &filterMap));
    MOCK_METHOD1(GetAbnormalApps,  int (std::vector<std::string> &abnormalAppList));
    MOCK_METHOD0(ClearScanInfoList, int());
    MOCK_METHOD3(StoreWifiMacAddrPairInfo, bool(WifiMacAddrInfoType type, const std::string &realMacAddr,
        const std::string &randomAddr));
    MOCK_METHOD3(UpdateLinkedChannelWidth, void(std::string bssid, WifiChannelWidth channelWidth, int instId));
    MOCK_CONST_METHOD0(GetNoChargerPlugModeState, int());
    MOCK_CONST_METHOD0(GetPowerIdelState, int());
    MOCK_CONST_METHOD0(GetGnssFixState, int());
    MOCK_METHOD1(SaveScanInfoList, int(const std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(GetMinRssi2Dot4Ghz, int(int));
    MOCK_METHOD1(GetMinRssi5Ghz, int(int));
    MOCK_METHOD0(GetAppRunningState, ScanMode());
    MOCK_CONST_METHOD0(GetFreezeModeState, int());
    MOCK_CONST_METHOD0(GetAppPackageName, const std::string());
    MOCK_METHOD0(ReloadMovingFreezePolicy, const MovingFreezePolicy());
    MOCK_CONST_METHOD0(GetThermalLevel, int());
    MOCK_METHOD2(GetHid2dUpperScene, int(int uid, Hid2dUpperScene &scene));
    MOCK_CONST_METHOD0(GetHid2dSceneLastSetTime, int64_t());
    MOCK_METHOD1(SetHid2dSceneLastSetTime, int(int64_t setTime));
    MOCK_METHOD1(GetP2pBusinessType, int(P2pBusinessType &type));
    MOCK_METHOD2(SetHid2dUpperScene, int(int uid, const Hid2dUpperScene &scene));
    MOCK_METHOD2(SetWifiDetailState, int(WifiDetailState state, int instId));
    MOCK_CONST_METHOD1(EncryptionDeviceConfig, bool(WifiDeviceConfig &config));
    MOCK_METHOD1(GetRandomMac, bool(WifiStoreRandomMac &randomMacInfo));
    MOCK_METHOD1(GenerateRandomMacAddress, void(std::string &randomMacAddr));
    MOCK_METHOD2(GenerateRandomMacAddress, void (std::string peerBssid, std::string &randomMacAddr));
    MOCK_METHOD1(AddRandomMac, bool(WifiStoreRandomMac &randomMacInfo));
    MOCK_METHOD1(AddWpsDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_CONST_METHOD0(GetScanGenieState, int());
    MOCK_METHOD3(SetDefaultFrequenciesByCountryBand, void(const BandType band, std::vector<int> &frequencies, int));
    MOCK_METHOD0(GetNextNetworkId, int());
    MOCK_CONST_METHOD0(GetWifiStaCapabilities, int());
    MOCK_METHOD1(SetWifiStaCapabilities, int(int capabilities));
    MOCK_METHOD1(GetWifiDetailState, WifiDetailState(int instId));
    MOCK_METHOD1(SetWifiAllowSemiActive, void(bool isAllowed));
    MOCK_CONST_METHOD0(GetWifiAllowSemiActive, bool());
    MOCK_METHOD1(SetPersistWifiState, void(int state));
    MOCK_METHOD0(GetPersistWifiState, int());
    MOCK_METHOD0(GetWifiToggledEnable, int());
    MOCK_METHOD1(SetWifiStopState, void(bool state));
    MOCK_CONST_METHOD0(GetWifiStopState, bool());
    MOCK_METHOD1(SetCoexSupport, void(bool isSupport));
    MOCK_CONST_METHOD0(GetCoexSupport, bool());
    MOCK_METHOD1(SetStaIfaceName, void(const std::string &ifaceName));
    MOCK_METHOD1(GetHiddenDeviceConfig, int(std::vector<WifiDeviceConfig> &results));
    MOCK_METHOD0(IncreaseNumRebootsSinceLastUse, int());
    MOCK_CONST_METHOD1(RemoveExcessDeviceConfigs, int(std::vector<WifiDeviceConfig> &configs));
    MOCK_METHOD0(EncryptionWifiDeviceConfigOnBoot, void());
    MOCK_METHOD1(GetWifiP2pGroupInfo, int(std::vector<WifiP2pGroupInfo> &groups));
    MOCK_METHOD0(GetAllWifiLinkedInfo, std::map<int, WifiLinkedInfo> ());
    MOCK_METHOD1(GetConnectedBssid, std::string (int instId));
    MOCK_METHOD0(ReloadStaRandomMac, int());
    MOCK_METHOD0(ReloadPortalconf, int());
    MOCK_METHOD0(ClearRandomMacConfig, void());
    MOCK_METHOD1(FuzzyBssid, std::string(const std::string bssid));
    MOCK_METHOD2(RemoveRandomMac, bool(const std::string &bssid, const std::string &randomMac));
    MOCK_METHOD2(GetStationList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageStation, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD1(ClearStationList, int(int id));
    MOCK_METHOD2(GetBlockList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageBlockList, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD2(FindConnStation, int(const StationInfo &info, int id));
    MOCK_METHOD0(SyncBlockList, int());
    MOCK_METHOD1(GetValidBands, int(std::vector<BandType> &bands));
    MOCK_METHOD0(ClearValidChannels, int());
    MOCK_METHOD2(SetPowerModel, int(const PowerModel& model, int id));
    MOCK_METHOD2(GetPowerModel, int(PowerModel& model, int id));
    MOCK_METHOD1(GetOperatorWifiType, int(int instId));
    MOCK_METHOD2(SetOperatorWifiType, int(int type, int instId));
    MOCK_METHOD1(GetLastAirplaneMode, int(int instId));
    MOCK_METHOD2(SetLastAirplaneMode, int(int mode, int instId));
    MOCK_METHOD1(GetCanOpenStaWhenAirplaneMode, bool(int instId));
    MOCK_METHOD1(GetWifiFlagOnAirplaneMode, bool(int instId));
    MOCK_METHOD2(SetWifiFlagOnAirplaneMode, int(bool ifOpen, int instId));
    MOCK_METHOD1(GetWifiDisabledByAirplane, bool(int instId));
    MOCK_METHOD2(SetWifiDisabledByAirplane, int(bool disabledByAirplane, int instId));
    MOCK_METHOD1(GetStaLastRunState, int(int instId));
    MOCK_METHOD2(SetStaLastRunState, int(int bRun, int instId));
    MOCK_METHOD1(GetDefaultWifiInterface, std::string(int instId));
    MOCK_METHOD1(IsLoadStabak, bool(int instId));
    MOCK_METHOD2(GetDisconnectedReason, int(DisconnectedReason &discReason, int instId));
    MOCK_METHOD2(SetScanOnlySwitchState, void(const int &state, int instId));
    MOCK_METHOD0(ReloadTrustListPolicies, const std::vector<TrustListPolicy>());
    MOCK_METHOD1(IsModulePreLoad,  bool(const std::string &name));
    MOCK_METHOD0(GetCurrentP2pGroupInfo, WifiP2pGroupInfo());
    MOCK_METHOD1(GetHotspotState, int(int id));
    MOCK_METHOD1(SetWifiStateOnAirplaneChanged, bool(const int &state));
    MOCK_METHOD2(GetScanControlInfo, int(ScanControlInfo &info, int));
    MOCK_METHOD1(GetScanAlwaysState, bool(int instId));
    MOCK_METHOD1(GetSupportHwPnoFlag, bool(int instId));
    MOCK_METHOD2(SetAcceptUnvalidated, int(int networkId, bool state));
    MOCK_METHOD2(GetHotspotConfig, int(HotspotConfig &hotspotConfig, int id));
};
}  // namespace Wifi
}  // namespace OHOS
#endif