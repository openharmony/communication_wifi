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

class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int SetCountryCode(const std::string &countryCode) = 0;
    virtual int GetCountryCode(std::string &countryCode) = 0;
    virtual int SetHotspotConfig(const HotspotConfig &config, int id = 0) = 0;
    virtual int GetHotspotConfig(HotspotConfig &config, int id = 0) = 0;
    virtual int GetBlockList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageBlockList(const StationInfo &info, int mode, int id = 0) = 0; /* add / remove */
    virtual int GetApMaxConnNum() = 0;
    virtual void SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies,
        int instId = 0) = 0;
    virtual int SyncHotspotConfig() = 0;
    virtual std::string GetPackageName(std::string tag) = 0;
    virtual int GetDeviceConfig(const int &networkId, WifiDeviceConfig &config, int instId) = 0;
    virtual int GetPackageInfoByName(std::string name, std::vector<PackageInfo> &packageInfo) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    WifiSettings() = default;
    ~WifiSettings() override = default;
    static WifiSettings &GetInstance(void);
    MOCK_METHOD1(SetCountryCode, int(const std::string &countryCode));
    MOCK_METHOD1(GetCountryCode, int(std::string &countryCode));
    MOCK_METHOD2(SetHotspotConfig, int(const HotspotConfig &config, int id));
    MOCK_METHOD2(GetHotspotConfig, int(HotspotConfig &config, int id));
    MOCK_METHOD2(GetBlockList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageBlockList, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD0(GetApMaxConnNum, int());
    MOCK_METHOD3(SetDefaultFrequenciesByCountryBand, void(const BandType band, std::vector<int> &frequencies, int));
    MOCK_METHOD0(SyncHotspotConfig, int());
    MOCK_METHOD1(GetPackageName, std::string(std::string tag));
    MOCK_METHOD3(GetDeviceConfig, int(const int &networkId, WifiDeviceConfig &config, int instId));
    MOCK_METHOD2(GetPackageInfoByName, int(std::string name, std::vector<PackageInfo> &packageInfo));
};
} /* namespace Wifi */
} /* namespace OHOS */
#endif
