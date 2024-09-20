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
#ifndef OHOS_MOCK_WIFI_SETTINGS_H
#define OHOS_MOCK_WIFI_SETTINGS_H

#include "wifi_ap_msg.h"
#include "wifi_msg.h"
#include "wifi_internal_msg.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Wifi {
class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual void SetSupportHwPnoFlag(bool supportHwPnoFlag) = 0;
    virtual bool GetSupportHwPnoFlag(int instId = 0) = 0;
    virtual int GetMinRssi2Dot4Ghz(int instId = 0) = 0;
    virtual int GetMinRssi5Ghz(int instId = 0) = 0;
    virtual bool GetWhetherToAllowNetworkSwitchover(int instId = 0) = 0;
    virtual int GetDeviceConfig(std::vector<WifiDeviceConfig> &results, int instId = 0) = 0;
    virtual int GetDeviceConfig(
        const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config, int instId = 0) = 0;
    virtual const std::vector<TrustListPolicy> ReloadTrustListPolicies() = 0;
    virtual const MovingFreezePolicy ReloadMovingFreezePolicy() = 0;
    virtual int GetPackageFilterMap(std::map<std::string, std::vector<std::string>> &filterMap) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    static WifiSettings &GetInstance(void);

    MOCK_METHOD1(SetSupportHwPnoFlag, void(bool supportHwPnoFlag));
    MOCK_METHOD1(GetSupportHwPnoFlag, bool(int));
    MOCK_METHOD1(GetMinRssi2Dot4Ghz, int(int));
    MOCK_METHOD1(GetMinRssi5Ghz, int(int));
    MOCK_METHOD1(GetWhetherToAllowNetworkSwitchover, bool(int));
    MOCK_METHOD2(GetDeviceConfig, int(std::vector<WifiDeviceConfig> &results, int));
    MOCK_METHOD4(GetDeviceConfig, int(const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config, int));
    MOCK_METHOD0(ReloadTrustListPolicies, const std::vector<TrustListPolicy>());
    MOCK_METHOD0(ReloadMovingFreezePolicy, const MovingFreezePolicy());
    MOCK_METHOD1(GetPackageFilterMap,  int(std::map<std::string, std::vector<std::string>> &filterMap));
};
}  // namespace Wifi
}  // namespace OHOS
#endif
