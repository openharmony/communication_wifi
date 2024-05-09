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
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;

class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int SaveScanInfoList(const std::vector<WifiScanInfo> &results) = 0;
    virtual int GetScanInfoList(std::vector<WifiScanInfo> &results) = 0;
    virtual int GetScanControlInfo(ScanControlInfo &info, int instId = 0) = 0;
    virtual int SetScanControlInfo(const ScanControlInfo &info, int instId = 0) = 0;
    virtual void SetScreenState(const int &state) = 0;
    virtual int GetScreenState() const = 0;
    virtual ScanMode GetAppRunningState() const = 0;
    virtual const std::string GetAppPackageName() const = 0;
    virtual int GetFreezeModeState() const = 0;
    virtual void SetSupportHwPnoFlag(bool supportHwPnoFlag) = 0;
    virtual bool GetSupportHwPnoFlag(int instId = 0) = 0;
    virtual int GetMinRssi2Dot4Ghz(int instId = 0) = 0;
    virtual int GetMinRssi5Ghz(int instId = 0) = 0;
    virtual bool GetWhetherToAllowNetworkSwitchover(int instId = 0) = 0;
    virtual int GetDeviceConfig(std::vector<WifiDeviceConfig> &results) = 0;
    virtual const std::vector<TrustListPolicy> ReloadTrustListPolicies() = 0;
    virtual const MovingFreezePolicy ReloadMovingFreezePolicy() = 0;
    virtual int GetThermalLevel() const = 0;
    virtual void SetThermalLevel(const int &level) = 0;
    virtual void SetAppRunningState(ScanMode appRunMode) = 0;
    virtual int SetWhetherToAllowNetworkSwitchover(bool bSwitch, int instId = 0) = 0;
    virtual int ClearScanInfoList() = 0;
    virtual void SetAppPackageName(const std::string &name) = 0;
    virtual int SetP2pBusinessType(const P2pBusinessType &type) = 0;
    virtual int GetHid2dUpperScene(std::string& ifName, Hid2dUpperScene &scene) = 0;
    virtual int GetP2pBusinessType(P2pBusinessType &type) = 0;
    virtual int SetHid2dUpperScene(const std::string& ifName, const Hid2dUpperScene &scene) = 0;
    virtual std::string GetStaIfaceName() = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    static WifiSettings &GetInstance(void);

    MOCK_METHOD1(SaveScanInfoList, int(const std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(GetScanInfoList, int(std::vector<WifiScanInfo> &results));
    MOCK_METHOD2(GetScanControlInfo, int(ScanControlInfo &info, int));
    MOCK_METHOD2(SetScanControlInfo, int(const ScanControlInfo &info, int));
    MOCK_METHOD1(SetScreenState, void(const int &state));
    MOCK_CONST_METHOD0(GetScreenState, int());
    MOCK_CONST_METHOD0(GetAppRunningState, ScanMode());
    MOCK_CONST_METHOD0(GetAppPackageName, const std::string());
    MOCK_CONST_METHOD0(GetFreezeModeState, int());
    MOCK_METHOD1(SetSupportHwPnoFlag, void(bool supportHwPnoFlag));
    MOCK_METHOD1(GetSupportHwPnoFlag, bool(int));
    MOCK_METHOD1(GetMinRssi2Dot4Ghz, int(int));
    MOCK_METHOD1(GetMinRssi5Ghz, int(int));
    MOCK_METHOD1(GetWhetherToAllowNetworkSwitchover, bool(int));
    MOCK_METHOD1(GetDeviceConfig, int(std::vector<WifiDeviceConfig> &results));
    MOCK_METHOD0(ReloadTrustListPolicies, const std::vector<TrustListPolicy>());
    MOCK_METHOD0(ReloadMovingFreezePolicy, const MovingFreezePolicy());
    MOCK_CONST_METHOD0(GetThermalLevel, int());
    MOCK_METHOD1(SetThermalLevel, void(const int &level));
    MOCK_METHOD1(SetAppRunningState, void(ScanMode appRunMode));
    MOCK_METHOD2(SetWhetherToAllowNetworkSwitchover, int(bool bSwitch, int));
    MOCK_METHOD0(ClearScanInfoList, int());
    MOCK_METHOD1(SetAppPackageName, void(const std::string &name));
    MOCK_METHOD1(SetP2pBusinessType, int(const P2pBusinessType &type));
    MOCK_METHOD2(GetHid2dUpperScene, int(std::string& ifName, Hid2dUpperScene &scene));
    MOCK_METHOD1(GetP2pBusinessType, int(P2pBusinessType &type));
    MOCK_METHOD2(SetHid2dUpperScene, int(const std::string& ifName, const Hid2dUpperScene &scene));
    MOCK_METHOD0(GetStaIfaceName, std::string());
};
}  // namespace Wifi
}  // namespace OHOS
#endif
