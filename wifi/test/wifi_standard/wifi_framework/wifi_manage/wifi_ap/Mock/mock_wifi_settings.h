/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MOCK_WIFI_SETTINGS_H
#define OHOS_MOCK_WIFI_SETTINGS_H

#include <map>
#include <string>
#include <vector>
#include "wifi_ap_msg.h"
#include <gmock/gmock.h>
#include "wifi_p2p_msg.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {

const int MODE_ADD = 0;
const int MODE_DEL = 1;
const int MODE_UPDATE = 2;

using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int SetCountryCode(const std::string &countryCode) = 0;
    virtual int GetCountryCode(std::string &countryCode) = 0;
    virtual int GetHotspotState(int id = 0) = 0;
    virtual int SetHotspotState(int state, int id = 0) = 0;
    virtual int SetHotspotConfig(const HotspotConfig &config, int id = 0) = 0;
    virtual int GetHotspotConfig(HotspotConfig &config, int id = 0) = 0;
    virtual int GetStationList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageStation(const StationInfo &info, int mode, int id = 0) = 0; /* add / update / remove */
    virtual int ClearStationList(int id = 0) = 0;
    virtual int GetBlockList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageBlockList(const StationInfo &info, int mode, int id = 0) = 0; /* add / remove */
    virtual int FindConnStation(const StationInfo &info, int id = 0) = 0;
    virtual int GetValidBands(std::vector<BandType> &bands) = 0;
    virtual int SetValidChannels(const ChannelsTable &channelsInfo) = 0;
    virtual int GetValidChannels(ChannelsTable &channelsInfo) = 0;
    virtual int ClearValidChannels() = 0;
    virtual int GetApMaxConnNum() = 0;
    virtual void SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies,
        int instId = 0) = 0;
    virtual std::string GetConnectTimeoutBssid(int instId = 0) = 0;
    virtual int SetConnectTimeoutBssid(std::string &bssid, int instId = 0) = 0;
    virtual int SyncHotspotConfig() = 0;
    virtual int SetPowerModel(const PowerModel& model, int id = 0) = 0;
    virtual int GetPowerModel(PowerModel& model, int id = 0) = 0;
    virtual void SetThreadStatusFlag(bool state) = 0;
    virtual int GetLinkedInfo(WifiLinkedInfo &info, int instId) = 0;
    virtual int GetP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual WifiP2pGroupInfo GetCurrentP2pGroupInfo() = 0;
    virtual int GetIpInfo(IpInfo &info, int instId = 0) = 0;
    virtual std::string GetApIfaceName() = 0;
    virtual int GetHotspotIdleTimeout() const = 0;
    virtual int SetHotspotIdleTimeout(int time) = 0;
    virtual void GenerateRandomMacAddress(std::string &randomMacAddr) = 0;
    virtual void GenerateRandomMacAddress(std::string peerBssid, std::string &randomMacAddr) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    WifiSettings() = default;
    ~WifiSettings() = default;
    static WifiSettings &GetInstance(void);
    MOCK_METHOD1(SetCountryCode, int(const std::string &countryCode));
    MOCK_METHOD1(GetCountryCode, int(std::string &countryCode));
    MOCK_METHOD1(GetHotspotState, int(int id));
    MOCK_METHOD2(SetHotspotState, int(int state, int id));
    MOCK_METHOD2(SetHotspotConfig, int(const HotspotConfig &config, int id));
    MOCK_METHOD2(GetHotspotConfig, int(HotspotConfig &config, int id));
    MOCK_METHOD2(GetStationList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageStation, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD1(ClearStationList, int(int id));
    MOCK_METHOD2(GetBlockList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageBlockList, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD2(FindConnStation, int(const StationInfo &info, int id));
    MOCK_METHOD1(GetValidBands, int(std::vector<BandType> &bands));
    MOCK_METHOD1(SetValidChannels, int(const ChannelsTable &channelsInfo));
    MOCK_METHOD1(GetValidChannels, int(ChannelsTable &channelsInfo));
    MOCK_METHOD0(ClearValidChannels, int());
    MOCK_METHOD0(GetApMaxConnNum, int());
    MOCK_METHOD3(SetDefaultFrequenciesByCountryBand, void(const BandType band, std::vector<int> &frequencies, int));
    MOCK_METHOD1(GetConnectTimeoutBssid, std::string(int));
    MOCK_METHOD2(SetConnectTimeoutBssid, int(std::string &bssid, int));
    MOCK_METHOD0(SyncHotspotConfig, int());
    MOCK_METHOD2(SetPowerModel, int(const PowerModel& model, int id));
    MOCK_METHOD2(GetPowerModel, int(PowerModel& model, int id));
    MOCK_METHOD1(SetThreadStatusFlag, void(bool state));
    MOCK_METHOD2(GetLinkedInfo, int(WifiLinkedInfo &info, int instId));
    MOCK_METHOD1(GetP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD0(GetCurrentP2pGroupInfo, WifiP2pGroupInfo());
    MOCK_METHOD2(GetIpInfo, int(IpInfo &info, int));
    MOCK_METHOD0(GetApIfaceName, std::string());
    MOCK_CONST_METHOD0(GetHotspotIdleTimeout, int());
    MOCK_METHOD1(SetHotspotIdleTimeout, int(int));
    MOCK_METHOD1(GenerateRandomMacAddress, void(std::string &randomMacAddr));
    MOCK_METHOD2(GenerateRandomMacAddress, void(std::string peerBssid, std::string &randomMacAddr));
};
} /* namespace Wifi */
} /* namespace OHOS */
#endif
