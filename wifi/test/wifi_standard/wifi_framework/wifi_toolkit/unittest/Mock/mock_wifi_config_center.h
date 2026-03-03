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

#ifndef OHOS_MOCK_WIFI_CONFIG_CENTER_H
#define OHOS_MOCK_WIFI_CONFIG_CENTER_H

#include <gmock/gmock.h>
#include "wifi_internal_msg.h"
#include "mock_wifi_scan_config.h"

namespace OHOS {
namespace Wifi {
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

class MockWifiConfigCenter {
public:
    virtual ~MockWifiConfigCenter() = default;
    virtual void SetWifiSelfcureReset(const bool isReset) = 0;
    virtual bool GetWifiSelfcureReset() const = 0;
    virtual void SetWifiSelfcureResetEntered(const bool isReset) = 0;
    virtual bool GetWifiSelfcureResetEntered() = 0;
    virtual void SetLastNetworkId(const int networkId) = 0;
    virtual int GetLastNetworkId() const = 0;
    virtual void SetWifiAllowSemiActive(bool isAllowed) = 0;
    virtual bool GetWifiAllowSemiActive() const = 0;
    virtual void SetWifiStopState(bool state) = 0;
    virtual bool GetWifiStopState() const= 0;
    virtual void SetStaIfaceName(const std::string &ifaceName, int instId = 0) = 0;
    virtual std::string GetStaIfaceName(int instId = 0) = 0;
    virtual int GetWifiState(int instId = 0) = 0;
    virtual int SetWifiState(int state, int instId = 0) = 0;
    virtual WifiDetailState GetWifiDetailState(int instId = 0) = 0;
    virtual int SetWifiDetailState(WifiDetailState state, int instId) = 0;
    virtual int GetIpInfo(IpInfo &info, int instId = 0) = 0;
    virtual int SaveIpInfo(const IpInfo &info, int instId = 0) = 0;
    virtual int GetIpv6Info(IpV6Info &info, int instId = 0) = 0;
    virtual int SaveIpV6Info(const IpV6Info &info, int instId = 0) = 0;
    virtual std::map<int, WifiLinkedInfo> GetAllWifiLinkedInfo() = 0;
    virtual int GetLinkedInfo(WifiLinkedInfo &info, int instId = 0) = 0;
    virtual int SaveLinkedInfo(const WifiLinkedInfo &info, int instId = 0) = 0;
    virtual int GetMloLinkedInfo(std::vector<WifiLinkedInfo> &info, int instId = 0) = 0;
    virtual int SaveMloLinkedInfo(const std::vector<WifiLinkedInfo> &info, int instId = 0) = 0;
    virtual void UpdateLinkedChannelWidth(std::string bssid, WifiChannelWidth channelWidth, int instId = 0) = 0;
    virtual int SetMacAddress(const std::string &macAddress, int instId = 0) = 0;
    virtual int GetMacAddress(std::string &macAddress, int instId = 0) = 0;
    virtual void SetUserLastSelectedNetworkId(int networkId, int instId = 0) = 0;
    virtual int GetUserLastSelectedNetworkId(int instId = 0) = 0;
    virtual time_t GetUserLastSelectedNetworkTimeVal(int instId = 0) = 0;
    virtual std::string GetConnectTimeoutBssid(int instId = 0) = 0;
    virtual int SetConnectTimeoutBssid(std::string &bssid, int instId = 0) = 0;
    virtual void SaveDisconnectedReason(DisconnectedReason discReason, int instId = 0) = 0;
    virtual int GetDisconnectedReason(DisconnectedReason &discReason, int instId = 0) = 0;
    virtual void InsertWifiCategoryBlackListCache(int blacklistType, const std::string currentBssid,
        const WifiCategoryBlackListInfo wifiBlackListInfo) = 0;
    virtual void RemoveWifiCategoryBlackListCache(int blacklistType, const std::string bssid) = 0;
    virtual int GetWifiCategoryBlackListCache(int blacklistType,
	    std::map<std::string, WifiCategoryBlackListInfo> &blackListCache) = 0;
    virtual void UpdateWifiConnectFailListCache(int blacklistType, const std::string bssid,
        const WifiCategoryConnectFailInfo connectFailInfo) = 0;
    virtual void RemoveWifiConnectFailListCache(const std::string bssid) = 0;
    virtual int GetWifiConnectFailListCache(
	    std::map<std::string, WifiCategoryConnectFailInfo> &connectFailCache) = 0;
    virtual bool EnableNetwork(int networkId, bool disableOthers, int instId = 0) = 0;
    virtual void SetAppPackageName(const std::string &name) = 0;
    virtual const std::string GetAppPackageName() = 0;
    virtual void SetAppRunningState(ScanMode appRunMode) = 0;
    virtual ScanMode GetAppRunningState() const = 0;
    virtual int GetScanControlInfo(ScanControlInfo &info, int instId = 0) = 0;
    virtual int SetScanControlInfo(const ScanControlInfo &info, int instId = 0) = 0;
    virtual int GetAbnormalApps(std::vector<std::string> &abnormalAppList) = 0;
    virtual int SaveScanInfoList(const std::vector<WifiScanInfo> &results) = 0;
    virtual int ClearScanInfoList() = 0;
    virtual int GetScanInfoList(std::vector<WifiScanInfo> &results) = 0;
    virtual int SetWifiLinkedStandardAndMaxSpeed(WifiLinkedInfo &linkInfo) = 0;
    virtual void SetMloWifiLinkedMaxSpeed(int instId = 0) = 0;
    virtual std::string GetConnectedBssid(int instId = 0) = 0;
    virtual std::string GetApIfaceName() = 0;
    virtual int SetHotspotState(int state, int id = 0) = 0;
    virtual int SetPowerModel(const PowerModel& model, int id = 0)= 0;
    virtual int GetPowerModel(PowerModel& model, int id = 0) = 0;
    virtual int GetStationList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageStation(const StationInfo &info, int mode, int id = 0) = 0;
    virtual int ClearStationList(int id = 0)= 0;
    virtual int GetHid2dUpperScene(int uid, Hid2dUpperScene &scene) = 0;
    virtual int SetP2pBusinessType(const P2pBusinessType &type) = 0;
    virtual int GetP2pBusinessType(P2pBusinessType &type) = 0;
    virtual int SaveP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual int GetP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual WifiP2pGroupInfo GetCurrentP2pGroupInfo() = 0;
    virtual void SetCoexSupport(bool isSupport) = 0;
    virtual bool GetCoexSupport() const = 0;
    virtual void SetScreenState(const int &state) = 0;
    virtual int GetScreenState() const = 0;
    virtual void SetBrowserState(bool browser) = 0;
    virtual bool GetBrowserState() = 0;
    virtual int SetHid2dUpperScene(int uid, const Hid2dUpperScene &scene) = 0;
    virtual void SetWlanPage(bool isWlanPage) = 0;
    virtual bool IsWlanPage() const = 0;
    virtual void SetThermalLevel(const int &level) = 0;
    virtual int GetThermalLevel() const = 0;
    virtual bool SetWifiStateOnAirplaneChanged(const int &state);
    virtual void SetWifiToggledState(int state, int id = 0) = 0;
    virtual int SetLastConnStaFreq(int freq) = 0;
    virtual int GetFreezeModeState() const = 0;
    virtual void SetScanStyle(int scanStyle) = 0;
    virtual int GetScanStyle() const = 0;
    virtual void SetThreadStatusFlag(bool state) = 0;
    virtual int SetChangeDeviceConfig(ConfigChange value, const WifiDeviceConfig &config) = 0;
    virtual void SetWifiConnectedMode(bool isContainerConnected, int instId = 0) = 0;
    virtual bool GetWifiConnectedMode(int instId = 0) = 0;
    virtual WifiOprMidState GetScanMidState(int instId = 0) = 0;
    virtual void SetScanMidState(WifiOprMidState state, int instId = 0) = 0;
    virtual bool SetScanMidState(WifiOprMidState expState, WifiOprMidState state, int instId = 0) = 0;
    virtual WifiOprMidState GetWifiMidState(int instId = 0) = 0;
    virtual void SetWifiMidState(WifiOprMidState state, int instId = 0) = 0;
    virtual bool SetWifiMidState(WifiOprMidState expState, WifiOprMidState state, int instId = 0) = 0;
    virtual WifiOprMidState GetP2pMidState() = 0;
    virtual void SetP2pMidState(WifiOprMidState state) = 0;
    virtual bool SetP2pMidState(WifiOprMidState expState, WifiOprMidState state) = 0;
    virtual WifiOprMidState GetWifiScanOnlyMidState(int instId = 0) = 0;
    virtual bool SetWifiScanOnlyMidState(WifiOprMidState expState, WifiOprMidState state, int instId = 0) = 0;
    virtual void SetWifiScanOnlyMidState(WifiOprMidState state, int instId = 0) = 0;
    virtual WifiOprMidState GetApMidState(int id = 0) = 0;
    virtual bool SetApMidState(WifiOprMidState expState, WifiOprMidState state, int id = 0) = 0;
    virtual void SetApMidState(WifiOprMidState state, int id = 0) = 0;
    virtual int GetAirplaneModeState() const = 0;
    virtual int GetHotspotState(int id = 0) = 0;
    virtual int SetP2pEnhanceState(int state = 0) = 0;
    virtual int GetP2pEnhanceState() = 0;
    virtual void ClearLocalHid2dInfo(int uid = 0) = 0;
    virtual std::string GetMacAddrPairs(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo) = 0;
    virtual int GetHotspotIdleTimeout() const = 0;
    virtual void SetSoftapToggledState(bool state) = 0;
    virtual void SetNoChargerPlugModeState(int state) = 0;
    virtual void SetPowerIdelState(const int &state) = 0;
    virtual void SetApIfaceName(const std::string &ifaceName) = 0;
    virtual int GetWifiToggledEnable(int id = 0) = 0;
    virtual bool GetSoftapToggledState() const = 0;
    virtual bool CheckScanOnlyAvailable(int instId) = 0;
    virtual int GetSelectedCandidateNetworkId() const = 0;
    virtual void SetSelectedCandidateNetworkId(const int networkId) = 0;
    virtual void SetP2pIfaceName(const std::string &ifaceName) = 0;
    virtual int SetP2pState(int state) = 0;
    virtual int GetPowerSavingModeState() const = 0;
    virtual void CleanWifiCategoryRecord() = 0;
    virtual void SetPersistWifiState(int state, int instId) = 0;
    virtual int GetPersistWifiState(int instId) = 0;
    virtual void UpdateLinkedInfo(int instId) = 0;
    virtual int GetNoChargerPlugModeState() const = 0;
    virtual bool StoreWifiMacAddrPairInfo(WifiMacAddrInfoType type, const std::string &realMacAddr,
        const std::string &randomAddr) = 0;
    virtual std::string GetP2pIfaceName() = 0;
    virtual int GetScanGenieState() const = 0;
    virtual int Init() = 0;
    virtual void SetFreezeModeState(int state) = 0;
    virtual void SetSystemMode(int systemMode) = 0;
    virtual int GetSystemMode() = 0;
    virtual bool GetWifiSelfcureResetEntered() const = 0;
    virtual int SetHotspotIdleTimeout(int time) = 0;
    virtual bool IsAllowPopUp() = 0;
    virtual bool IsAllowPcPopUp() = 0;
    virtual void SetDeviceType(int deviceType) = 0;
    virtual int GetDeviceType() = 0;
    virtual int64_t GetHid2dSceneLastSetTime() = 0;
    virtual int SetHid2dSceneLastSetTime(int64_t setTime) = 0;
    virtual int GetP2pEnhanceFreq() = 0;
    virtual bool IsNeedFastScan(void) = 0;
    virtual void SetFastScan(bool fastScan) = 0;
    virtual HotspotMode GetHotspotMode() = 0;
    virtual void SetHotspotMode(const HotspotMode &mode) = 0;
    virtual int GetLocalOnlyHotspotConfig(HotspotConfig &hotspotConfig) = 0;
    virtual void SetLocalOnlyHotspotConfig(const HotspotConfig &hotspotConfig) = 0;
    virtual bool IsScreenLandscape() = 0;
    virtual void SetScreenDispalyState(int32_t orientation) = 0;
    virtual void SetNetworkControlInfo(const WifiNetworkControlInfo& networkControlInfo) = 0;
    virtual WifiNetworkControlInfo GetNetworkControlInfo() = 0;
    virtual void SetDfsControlData(DfsControlData dfsControlData) = 0;
    virtual DfsControlData GetDfsControlData() = 0;
    virtual bool IsSameKeyMgmt(std::string scanKeyMgmt, std::string keyMgmt);
};

class WifiConfigCenter : public MockWifiConfigCenter {
public:
    static WifiConfigCenter &GetInstance();
    std::unique_ptr<WifiScanConfig>& GetWifiScanConfig();

    MOCK_METHOD1(SetWifiSelfcureReset, void(const bool isReset));
    MOCK_CONST_METHOD0(GetWifiSelfcureReset, bool());
    MOCK_METHOD1(SetWifiSelfcureResetEntered, void(const bool isReset));
    MOCK_METHOD0(GetWifiSelfcureResetEntered, bool());
    MOCK_METHOD1(SetLastNetworkId, void(const int networkId));
    MOCK_CONST_METHOD0(GetLastNetworkId, int());
    MOCK_METHOD1(SetWifiAllowSemiActive, void(bool isAllowed));
    MOCK_CONST_METHOD0(GetWifiAllowSemiActive, bool());
    MOCK_METHOD1(SetWifiStopState, void(bool state));
    MOCK_CONST_METHOD0(GetWifiStopState, bool());
    MOCK_METHOD2(SetStaIfaceName, void(const std::string &ifaceName, int));
    MOCK_METHOD1(GetStaIfaceName, std::string(int));
    MOCK_METHOD1(GetWifiState, int(int));
    MOCK_METHOD2(SetWifiState, int(int state, int));
    MOCK_METHOD1(GetWifiDetailState, WifiDetailState(int instId));
    MOCK_METHOD2(SetWifiDetailState, int(WifiDetailState state, int instId));
    MOCK_METHOD2(GetIpInfo, int(IpInfo &info, int));
    MOCK_METHOD2(SaveIpInfo, int(const IpInfo &info, int));
    MOCK_METHOD2(GetIpv6Info, int(IpV6Info &info, int));
    MOCK_METHOD2(SaveIpV6Info, int(const IpV6Info &info, int));
    MOCK_METHOD0(GetAllWifiLinkedInfo, std::map<int, WifiLinkedInfo> ());
    MOCK_METHOD2(GetLinkedInfo, int(WifiLinkedInfo &info, int));
    MOCK_METHOD2(SaveLinkedInfo, int(const WifiLinkedInfo &info, int));
    MOCK_METHOD2(GetMloLinkedInfo, int(std::vector<WifiLinkedInfo> &info, int));
    MOCK_METHOD2(SaveMloLinkedInfo, int(const std::vector<WifiLinkedInfo> &info, int));
    MOCK_METHOD3(UpdateLinkedChannelWidth, void(std::string bssid, WifiChannelWidth channelWidth, int instId));
    MOCK_METHOD2(SetMacAddress, int(const std::string &macAddress, int));
    MOCK_METHOD2(GetMacAddress, int(std::string &macAddress, int));
    MOCK_METHOD2(SetUserLastSelectedNetworkId, void(int networkId, int));
    MOCK_METHOD1(GetUserLastSelectedNetworkId, int(int));
    MOCK_METHOD1(GetUserLastSelectedNetworkTimeVal, time_t(int));
    MOCK_METHOD1(GetConnectTimeoutBssid, std::string(int));
    MOCK_METHOD2(SetConnectTimeoutBssid, int(std::string &bssid, int));
    MOCK_METHOD2(SaveDisconnectedReason, void(DisconnectedReason discReason, int));
    MOCK_METHOD2(GetDisconnectedReason, int(DisconnectedReason &discReason, int instId));
    MOCK_METHOD3(InsertWifiCategoryBlackListCache, void(int blacklistType, const std::string currentBssid,
        const WifiCategoryBlackListInfo wifiBlackListInfo));
    MOCK_METHOD2(RemoveWifiCategoryBlackListCache, void(int blacklistType, const std::string bssid));
    MOCK_METHOD2(GetWifiCategoryBlackListCache, int(
	    int blacklistType, std::map<std::string, WifiCategoryBlackListInfo> &blackListCache));
	MOCK_METHOD3(UpdateWifiConnectFailListCache, void(int blacklistType, const std::string currentBssid,
        const WifiCategoryConnectFailInfo connectFailInfo));
    MOCK_METHOD1(RemoveWifiConnectFailListCache, void(const std::string bssid));
    MOCK_METHOD1(GetWifiConnectFailListCache, int(
	    std::map<std::string, WifiCategoryConnectFailInfo> &connectFailCache));
    MOCK_METHOD3(EnableNetwork, bool(int networkId, bool disableOthers, int));
    MOCK_METHOD1(SetAppPackageName, void(const std::string &name));
    MOCK_METHOD0(GetAppPackageName, const std::string());
    MOCK_METHOD1(SetAppRunningState, void(ScanMode appRunMode));
    MOCK_CONST_METHOD0(GetAppRunningState, ScanMode());
    MOCK_METHOD2(GetScanControlInfo, int(ScanControlInfo &info, int));
    MOCK_METHOD2(SetScanControlInfo, int(const ScanControlInfo &info, int));
    MOCK_METHOD1(GetAbnormalApps,  int (std::vector<std::string> &abnormalAppList));
    MOCK_METHOD1(SaveScanInfoList, int(const std::vector<WifiScanInfo> &results));
    MOCK_METHOD0(ClearScanInfoList, int());
    MOCK_METHOD1(GetScanInfoList, int(std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(SetWifiLinkedStandardAndMaxSpeed, int(WifiLinkedInfo &linkInfo));
    MOCK_METHOD1(SetMloWifiLinkedMaxSpeed, void(int instId));
    MOCK_METHOD1(GetConnectedBssid, std::string (int instId));
    MOCK_METHOD0(GetApIfaceName, std::string());
    MOCK_METHOD2(SetHotspotState, int(int state, int id));
    MOCK_METHOD2(SetPowerModel, int(const PowerModel& model, int id));
    MOCK_METHOD2(GetPowerModel, int(PowerModel& model, int id));
    MOCK_METHOD2(GetStationList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageStation, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD1(ClearStationList, int(int id));
    MOCK_METHOD2(GetHid2dUpperScene, int(int uid, Hid2dUpperScene &scene));
    MOCK_METHOD1(SetP2pBusinessType, int(const P2pBusinessType &type));
    MOCK_METHOD1(GetP2pBusinessType, int(P2pBusinessType &type));
    MOCK_METHOD1(SaveP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD1(GetP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD0(GetCurrentP2pGroupInfo, WifiP2pGroupInfo());
    MOCK_METHOD1(SetCoexSupport, void(bool isSupport));
    MOCK_CONST_METHOD0(GetCoexSupport, bool());
    MOCK_METHOD1(SetScreenState, void(const int &state));
    MOCK_METHOD1(SetBrowserState, void(bool));
    MOCK_METHOD0(GetBrowserState, bool());
    MOCK_METHOD2(SetHid2dUpperScene, int(int, const Hid2dUpperScene &));
    MOCK_CONST_METHOD0(GetScreenState, int());
    MOCK_METHOD1(SetWlanPage, void(bool isWlanPage));
    MOCK_CONST_METHOD0(IsWlanPage, bool());
    MOCK_METHOD1(SetThermalLevel, void(const int &level));
    MOCK_CONST_METHOD0(GetThermalLevel, int());
    MOCK_METHOD1(SetWifiStateOnAirplaneChanged, bool(const int &state));
    MOCK_METHOD2(SetWifiToggledState, void(int state, int));
    MOCK_METHOD1(SetLastConnStaFreq, int(int freq));
    MOCK_CONST_METHOD0(GetFreezeModeState, int());
    MOCK_METHOD1(SetScanStyle, void(int scanStyle));
    MOCK_CONST_METHOD0(GetScanStyle, int());
    MOCK_METHOD1(SetThreadStatusFlag, void(bool state));
    MOCK_METHOD2(SetChangeDeviceConfig, int(ConfigChange value, const WifiDeviceConfig &config));
    MOCK_METHOD2(SetWifiConnectedMode, void(bool isContainerConnected, int instId));
    MOCK_METHOD1(GetWifiConnectedMode, bool(int instId));
    MOCK_METHOD1(GetScanMidState, WifiOprMidState(int instId));
    MOCK_METHOD2(SetScanMidState, void(WifiOprMidState state, int instId));
    MOCK_METHOD3(SetScanMidState, bool(WifiOprMidState expState, WifiOprMidState state, int instId));
    MOCK_METHOD1(GetWifiMidState, WifiOprMidState(int instId));
    MOCK_METHOD2(SetWifiMidState, void(WifiOprMidState state, int instId));
    MOCK_METHOD3(SetWifiMidState, bool(WifiOprMidState expState, WifiOprMidState state, int instId));
    MOCK_METHOD0(GetP2pMidState, WifiOprMidState(void));
    MOCK_METHOD1(SetP2pMidState, void(WifiOprMidState state));
    MOCK_METHOD2(SetP2pMidState, bool(WifiOprMidState expState, WifiOprMidState state));
    MOCK_METHOD1(GetWifiScanOnlyMidState, WifiOprMidState(int instId));
    MOCK_METHOD3(SetWifiScanOnlyMidState, bool(WifiOprMidState expState, WifiOprMidState state, int instId));
    MOCK_METHOD2(SetWifiScanOnlyMidState, void(WifiOprMidState state, int instId));
    MOCK_METHOD1(GetApMidState, WifiOprMidState(int id));
    MOCK_METHOD3(SetApMidState, bool(WifiOprMidState expState, WifiOprMidState state, int id));
    MOCK_METHOD2(SetApMidState, void(WifiOprMidState state, int id));
    MOCK_CONST_METHOD0(GetAirplaneModeState, int(void));
    MOCK_METHOD1(GetHotspotState, int(int id));
    MOCK_METHOD1(SetP2pEnhanceState, int(int state));
    MOCK_METHOD0(GetP2pEnhanceState, int());
    MOCK_METHOD1(ClearLocalHid2dInfo, void(int uid));
    MOCK_METHOD2(GetMacAddrPairs, std::string(WifiMacAddrInfoType type, const WifiMacAddrInfo &macAddrInfo));
    MOCK_CONST_METHOD0(GetHotspotIdleTimeout, int());
    MOCK_METHOD1(SetSoftapToggledState, void(bool state));
    MOCK_METHOD1(SetNoChargerPlugModeState, void(int state));
    MOCK_METHOD1(SetPowerIdelState, void(const int &state));
    MOCK_METHOD1(SetApIfaceName, void(const std::string &ifaceName));
    MOCK_METHOD1(GetWifiToggledEnable, int(int));
    MOCK_CONST_METHOD0(GetSoftapToggledState, bool());
    MOCK_METHOD1(CheckScanOnlyAvailable, bool(int instId));
    MOCK_CONST_METHOD0(GetSelectedCandidateNetworkId, int());
    MOCK_METHOD1(SetSelectedCandidateNetworkId, void(const int networkId));
    MOCK_METHOD1(SetP2pIfaceName, void(const std::string &ifaceName));
    MOCK_METHOD1(SetP2pState, int(int state));
    MOCK_CONST_METHOD0(GetPowerSavingModeState, int());
    MOCK_METHOD0(CleanWifiCategoryRecord, void());
    MOCK_METHOD2(SetPersistWifiState, void(int state, int instId));
    MOCK_METHOD1(GetPersistWifiState, int(int instId));
    MOCK_METHOD1(UpdateLinkedInfo, void(int instId));
    MOCK_CONST_METHOD0(GetNoChargerPlugModeState, int());
    MOCK_METHOD3(StoreWifiMacAddrPairInfo, bool(WifiMacAddrInfoType type, const std::string &realMacAddr,
        const std::string &randomAddr));
    MOCK_METHOD0(GetP2pIfaceName, std::string());
    MOCK_CONST_METHOD0(GetScanGenieState, int());
    MOCK_METHOD0(Init, int());
    MOCK_METHOD1(SetFreezeModeState, void(int state));
    MOCK_METHOD1(SetSystemMode, void(int));
    MOCK_METHOD0(GetSystemMode, int());
    MOCK_METHOD0(GetHid2dSceneLastSetTime, int64_t());
    MOCK_METHOD1(SetHid2dSceneLastSetTime, int(int64_t setTime));
    MOCK_METHOD0(IsAllowPopUp, bool());
    MOCK_METHOD0(IsAllowPcPopUp, bool());
    MOCK_METHOD1(SetDeviceType, void(int deviceType));
    MOCK_METHOD0(GetDeviceType, int());
    MOCK_METHOD1(SetHotspotIdleTimeout, int(int time));
    MOCK_METHOD0(GetP2pEnhanceFreq, int());
    MOCK_CONST_METHOD0(GetWifiSelfcureResetEntered, bool());
    MOCK_METHOD0(IsNeedFastScan, bool());
    MOCK_METHOD1(SetFastScan, void(bool fastScan));
    MOCK_METHOD0(GetHotspotMode, HotspotMode());
    MOCK_METHOD1(SetHotspotMode, void(const HotspotMode &mode));
    MOCK_METHOD1(GetLocalOnlyHotspotConfig, int(HotspotConfig &hotspotConfig));
    MOCK_METHOD1(SetLocalOnlyHotspotConfig, void(const HotspotConfig &hotspotConfig));
    MOCK_METHOD0(IsScreenLandscape, bool());
    MOCK_METHOD1(SetScreenDispalyState, void(int32_t orientation));
    MOCK_METHOD1(SetNetworkControlInfo, void(const WifiNetworkControlInfo& networkControlInfo));
    MOCK_METHOD0(GetNetworkControlInfo, WifiNetworkControlInfo());
    MOCK_METHOD1(SetDfsControlData, void(DfsControlData dfsControlData));
    MOCK_METHOD0(GetDfsControlData, DfsControlData());
    MOCK_METHOD2(IsSameKeyMgmt, bool(std::string scanKeyMgmt, std::string keyMgmt));
private:
    WifiConfigCenter();
    std::unique_ptr<WifiScanConfig> wifiScanConfig = nullptr;
};
}  // namespace OHOS
}  // namespace Wifi
#endif