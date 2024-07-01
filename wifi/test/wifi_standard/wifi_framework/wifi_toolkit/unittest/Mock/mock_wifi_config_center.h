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

namespace OHOS {
namespace Wifi {
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

class MockWifiConfigCenter {
public:
    virtual ~MockWifiConfigCenter() = default;
    virtual void SetWifiSelfcureReset(const bool isReset) = 0;
    virtual bool GetWifiSelfcureReset() = 0;
    virtual void SetLastNetworkId(const int networkId) = 0;
    virtual int GetLastNetworkId() const = 0;
    virtual void SetWifiAllowSemiActive(bool isAllowed) = 0;
    virtual bool GetWifiAllowSemiActive() const = 0;
    virtual void SetWifiStopState(bool state) = 0;
    virtual bool GetWifiStopState() const= 0;
    virtual void SetStaIfaceName(const std::string &ifaceName) = 0;
    virtual std::string GetStaIfaceName() = 0;
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
    virtual void InsertWifi6BlackListCache(const std::string currentBssid,
        const Wifi6BlackListInfo wifi6BlackListInfo) = 0;
    virtual void RemoveWifi6BlackListCache(const std::string bssid) = 0;
    virtual int GetWifi6BlackListCache(std::map<std::string, Wifi6BlackListInfo> &blackListCache) = 0;
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
    virtual std::string GetConnectedBssid(int instId = 0) = 0;
    virtual std::string GetApIfaceName() = 0;
    virtual int GetValidBands(std::vector<BandType> &bands)= 0;
    virtual int SetValidChannels(const ChannelsTable &channelsInfo) = 0;
    virtual int GetValidChannels(ChannelsTable &channelsInfo) = 0;
    virtual int SetHotspotState(int state, int id = 0) = 0;
    virtual int SetPowerModel(const PowerModel& model, int id = 0)= 0;
    virtual int GetPowerModel(PowerModel& model, int id = 0) = 0;
    virtual int GetStationList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageStation(const StationInfo &info, int mode, int id = 0) = 0;
    virtual int ClearStationList(int id = 0)= 0;
    virtual int GetHid2dUpperScene(std::string& ifName, Hid2dUpperScene &scene) = 0;
    virtual int SetP2pBusinessType(const P2pBusinessType &type) = 0;
    virtual int GetP2pBusinessType(P2pBusinessType &type) = 0;
    virtual int SaveP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual int GetP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual WifiP2pGroupInfo GetCurrentP2pGroupInfo() = 0;
    virtual void SetCoexSupport(bool isSupport) = 0;
    virtual bool GetCoexSupport() const = 0;
    virtual void SetScreenState(const int &state) = 0;
    virtual int GetScreenState() const = 0;
    virtual void SetThermalLevel(const int &level) = 0;
    virtual int GetThermalLevel() const = 0;
    virtual bool SetWifiStateOnAirplaneChanged(const int &state);
    virtual void SetWifiToggledState(bool state) = 0;
    virtual int GetFreezeModeState() const = 0;
    virtual void SetThreadStatusFlag(bool state) = 0;
};

class WifiConfigCenter : public MockWifiConfigCenter {
public:
    static WifiConfigCenter &GetInstance();

    MOCK_METHOD1(SetWifiSelfcureReset, void(const bool isReset));
    MOCK_METHOD0(GetWifiSelfcureReset, bool());
    MOCK_METHOD1(SetLastNetworkId, void(const int networkId));
    MOCK_CONST_METHOD0(GetLastNetworkId, int());
    MOCK_METHOD1(SetWifiAllowSemiActive, void(bool isAllowed));
    MOCK_CONST_METHOD0(GetWifiAllowSemiActive, bool());
    MOCK_METHOD1(SetWifiStopState, void(bool state));
    MOCK_CONST_METHOD0(GetWifiStopState, bool());
    MOCK_METHOD1(SetStaIfaceName, void(const std::string &ifaceName));
    MOCK_METHOD0(GetStaIfaceName, std::string());
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
    MOCK_METHOD2(InsertWifi6BlackListCache, void(const std::string currentBssid,
        const Wifi6BlackListInfo wifi6BlackListInfo));
    MOCK_METHOD1(RemoveWifi6BlackListCache, void(const std::string bssid));
    MOCK_METHOD1(GetWifi6BlackListCache, int(std::map<std::string, Wifi6BlackListInfo> &blackListCache));
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
    MOCK_METHOD1(GetConnectedBssid, std::string (int instId));
    MOCK_METHOD0(GetApIfaceName, std::string());
    MOCK_METHOD1(GetValidBands, int(std::vector<BandType> &bands));
    MOCK_METHOD1(SetValidChannels, int(const ChannelsTable &channelsInfo));
    MOCK_METHOD1(GetValidChannels, int(ChannelsTable &channelsInfo));
    MOCK_METHOD2(SetHotspotState, int(int state, int id));
    MOCK_METHOD2(SetPowerModel, int(const PowerModel& model, int id));
    MOCK_METHOD2(GetPowerModel, int(PowerModel& model, int id));
    MOCK_METHOD2(GetStationList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageStation, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD1(ClearStationList, int(int id));
    MOCK_METHOD2(GetHid2dUpperScene, int(std::string& ifName, Hid2dUpperScene &scene));
    MOCK_METHOD1(SetP2pBusinessType, int(const P2pBusinessType &type));
    MOCK_METHOD1(GetP2pBusinessType, int(P2pBusinessType &type));
    MOCK_METHOD1(SaveP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD1(GetP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD0(GetCurrentP2pGroupInfo, WifiP2pGroupInfo());
    MOCK_METHOD1(SetCoexSupport, void(bool isSupport));
    MOCK_CONST_METHOD0(GetCoexSupport, bool());
    MOCK_METHOD1(SetScreenState, void(const int &state));
    MOCK_CONST_METHOD0(GetScreenState, int());
    MOCK_METHOD1(SetThermalLevel, void(const int &level));
    MOCK_CONST_METHOD0(GetThermalLevel, int());
    MOCK_METHOD1(SetWifiStateOnAirplaneChanged, bool(const int &state));
    MOCK_METHOD1(SetWifiToggledState, void(bool state));
    MOCK_CONST_METHOD0(GetFreezeModeState, int());
    MOCK_METHOD1(SetThreadStatusFlag, void(bool state));
};
}  // namespace OHOS
}  // namespace Wifi
#endif