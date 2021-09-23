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

#include "wifi_msg.h"
#include <gmock/gmock.h>

namespace OHOS {
namespace Wifi {
class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int SaveScanInfoList(const std::vector<WifiScanInfo> &results) = 0;
    virtual int GetScanInfoList(std::vector<WifiScanInfo> &results) = 0;
    virtual int GetScanControlInfo(ScanControlInfo &info) = 0;
    virtual int SetScanControlInfo(const ScanControlInfo &info) = 0;
    virtual void SetScreenState(const int &state) = 0;
    virtual int GetScreenState() = 0;
    virtual bool GetSupportHwPnoFlag() = 0;
    virtual int GetMinRssi2Dot4Ghz() = 0;
    virtual int GetMinRssi5Ghz() = 0;
    virtual bool GetWhetherToAllowNetworkSwitchover() = 0;
    virtual int GetDeviceConfig(std::vector<WifiDeviceConfig> &results) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    static WifiSettings &GetInstance(void);

    MOCK_METHOD1(SaveScanInfoList, int(const std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(GetScanInfoList, int(std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(GetScanControlInfo, int(ScanControlInfo &info));
    MOCK_METHOD1(SetScanControlInfo, int(const ScanControlInfo &info));
    MOCK_METHOD1(SetScreenState, void(const int &state));
    MOCK_METHOD0(GetScreenState, int());
    MOCK_METHOD0(GetSupportHwPnoFlag, bool());
    MOCK_METHOD0(GetMinRssi2Dot4Ghz, int());
    MOCK_METHOD0(GetMinRssi5Ghz, int());
    MOCK_METHOD0(GetWhetherToAllowNetworkSwitchover, bool());
    MOCK_METHOD1(GetDeviceConfig, int(std::vector<WifiDeviceConfig> &results));
};
}  // namespace Wifi
}  // namespace OHOS

#endif