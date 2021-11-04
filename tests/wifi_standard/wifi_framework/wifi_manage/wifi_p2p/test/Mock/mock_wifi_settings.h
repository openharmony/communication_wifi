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

#ifndef OHOS_MOCK_WIFISETTINGS_H
#define OHOS_MOCK_WIFISETTINGS_H

#include <map>
#include <string>
#include <vector>
#include "wifi_msg.h"
#include <gmock/gmock.h>

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
    virtual int GetHotspotState() = 0;
    virtual int SetHotspotState(int state) = 0;
    virtual int SetHotspotConfig(const HotspotConfig &config) = 0;
    virtual int GetHotspotConfig(HotspotConfig &config) = 0;
    virtual int GetStationList(std::vector<StationInfo> &results) = 0;
    virtual int ManageStation(const StationInfo &info, int mode) = 0; /* add / update / remove */
    virtual int ClearStationList() = 0;
    virtual int GetBlockList(std::vector<StationInfo> &results) = 0;
    virtual int ManageBlockList(const StationInfo &info, int mode) = 0; /* add / remove */
    virtual int FindConnStation(const StationInfo &info) = 0;
    virtual int GetValidBands(std::vector<BandType> &bands) = 0;
    virtual int SetValidChannels(const ChannelsTable &channelsInfo) = 0;
    virtual int GetValidChannels(ChannelsTable &channelsInfo) = 0;
    virtual int ClearValidChannels() = 0;
    virtual int GetApMaxConnNum() = 0;
    virtual int SetWifiP2pGroupInfo(const std::vector<WifiP2pGroupInfo> &groups) = 0;
    virtual int SetP2pVendorConfig(const P2pVendorConfig &config) = 0;
    virtual int GetP2pVendorConfig(P2pVendorConfig &config) = 0;
    virtual int GetP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual int SaveP2pInfo(WifiP2pLinkedInfo &linkedInfo) = 0;
    virtual int GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    WifiSettings() = default;
    ~WifiSettings() = default;
    static WifiSettings &GetInstance(void);
    MOCK_METHOD1(GetWifiP2pGroupInfo, int(std::vector<WifiP2pGroupInfo> &groups));
    MOCK_METHOD1(SaveP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD1(GetP2pInfo, int(WifiP2pLinkedInfo &linkedInfo));
    MOCK_METHOD1(SetP2pVendorConfig, int(const P2pVendorConfig &config));
    MOCK_METHOD1(GetP2pVendorConfig, int(P2pVendorConfig &config));
    MOCK_METHOD1(SetWifiP2pGroupInfo, int(const std::vector<WifiP2pGroupInfo> &groups));
    MOCK_METHOD1(SetCountryCode, int(const std::string &countryCode));
    MOCK_METHOD1(GetCountryCode, int(std::string &countryCode));
    MOCK_METHOD0(GetHotspotState, int());
    MOCK_METHOD1(SetHotspotState, int(int));
    MOCK_METHOD1(SetHotspotConfig, int(const HotspotConfig &config));
    MOCK_METHOD1(GetHotspotConfig, int(HotspotConfig &config));
    MOCK_METHOD1(GetStationList, int(std::vector<StationInfo> &results));
    MOCK_METHOD2(ManageStation, int(const StationInfo &info, int mode));
    MOCK_METHOD0(ClearStationList, int());
    MOCK_METHOD1(GetBlockList, int(std::vector<StationInfo> &results));
    MOCK_METHOD2(ManageBlockList, int(const StationInfo &info, int mode));
    MOCK_METHOD1(FindConnStation, int(const StationInfo &info));
    MOCK_METHOD1(GetValidBands, int(std::vector<BandType> &bands));
    MOCK_METHOD1(SetValidChannels, int(const ChannelsTable &channelsInfo));
    MOCK_METHOD1(GetValidChannels, int(ChannelsTable &channelsInfo));
    MOCK_METHOD0(ClearValidChannels, int());
    MOCK_METHOD0(GetApMaxConnNum, int());
};
}  // namespace Wifi
}  // namespace OHOS
#endif