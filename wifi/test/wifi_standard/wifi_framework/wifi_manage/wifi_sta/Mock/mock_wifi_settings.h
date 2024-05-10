/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "wifi_ap_msg.h"
#include "wifi_msg.h"
#include <gmock/gmock.h>
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;
class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int SetWifiState(int state, int instId = 0) = 0;
    virtual int AddDeviceConfig(const WifiDeviceConfig &config) = 0;
    virtual int RemoveDevice(int networkId) = 0;
    virtual void ClearDeviceConfig() = 0;
    virtual int GetDeviceConfig(std::vector<WifiDeviceConfig> &results) = 0;
    virtual int GetDeviceConfig(const int &networkId, WifiDeviceConfig &config) = 0;
    virtual int GetDeviceConfig(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config) = 0;
    virtual int GetDeviceConfig(const std::string &index, const int &indexType, WifiDeviceConfig &config) = 0;
    virtual int SetDeviceState(int networkId, int state, bool bSetOther = false) = 0;
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
    virtual void GetPortalUri(WifiPortalConf &urlInfo) = 0;
    virtual void InsertWifi6BlackListCache(const std::string currentBssid,
        const Wifi6BlackListInfo wifi6BlackListInfo) = 0;
    virtual void RemoveWifi6BlackListCache(const std::string bssid) = 0;
    virtual int GetWifi6BlackListCache(std::map<std::string, Wifi6BlackListInfo> &blackListCache) const = 0;
    virtual std::string GetStaIfaceName() = 0;
    virtual int GetScreenState() const = 0;
    virtual int SetDeviceRandomizedMacSuccessEver(int networkId) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    WifiSettings() = default;
    ~WifiSettings() = default;
    static WifiSettings &GetInstance(void);

    MOCK_METHOD2(SetWifiState, int(int state, int));
    MOCK_METHOD1(AddDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_METHOD1(RemoveDevice, int(int networkId));
    MOCK_METHOD0(ClearDeviceConfig, void());
    MOCK_METHOD1(GetDeviceConfig, int(std::vector<WifiDeviceConfig> &results));
    MOCK_METHOD2(GetDeviceConfig, int(const int &networkId, WifiDeviceConfig &config));
    MOCK_METHOD3(GetDeviceConfig, int(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config));
    MOCK_METHOD3(GetDeviceConfig, int(const std::string &index, const int &indexType, WifiDeviceConfig &config));
    MOCK_METHOD3(SetDeviceState, int(int networkId, int state, bool bSetOther));
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
    MOCK_METHOD1(GetPortalUri, void(WifiPortalConf &urlInfo));
    MOCK_METHOD2(InsertWifi6BlackListCache, void(const std::string currentBssid,
        const Wifi6BlackListInfo wifi6BlackListInfo));
    MOCK_METHOD1(RemoveWifi6BlackListCache, void(const std::string bssid));
    MOCK_CONST_METHOD1(GetWifi6BlackListCache, int(std::map<std::string, Wifi6BlackListInfo> &blackListCache));
    MOCK_METHOD0(GetStaIfaceName, std::string());
    MOCK_CONST_METHOD0(GetScreenState, int());
    MOCK_METHOD1(SetDeviceRandomizedMacSuccessEver, int(int networkId));
};
}  // namespace OHOS
}  // namespace Wifi
#endif