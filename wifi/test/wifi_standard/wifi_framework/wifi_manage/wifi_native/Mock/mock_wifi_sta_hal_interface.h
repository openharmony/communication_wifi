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

#ifndef OHOS_MOCK_WIFI_STA_HAL_INTERFACE_H
#define OHOS_MOCK_WIFI_STA_HAL_INTERFACE_H
#include <string>
#include <vector>
#include "wifi_event_callback.h"
#include "wifi_native_struct.h"
#include "wifi_error_no.h"
#include "wifi_msg.h"
#include "inter_scan_info.h"

namespace OHOS {
namespace Wifi {
class MockWifiStaHalInterface {
public:
    static MockWifiStaHalInterface &GetInstance(void);
    void SetRetResult(WifiErrorNo retResult);
    WifiErrorNo GetRetResult();
    void SetStaCapabilities(WifiErrorNo retResult);
    void SetChipsetFeatureCapability(int chipsetFeatureCapability);
private:
    MockWifiStaHalInterface();
    WifiErrorNo mRetResult;
    WifiErrorNo mGetStaCapabilities;
    int chipsetFeatureCapability_;
};

class WifiStaHalInterface {
public:
    static WifiStaHalInterface &GetInstance(void);
    WifiErrorNo StartWifi(const std::string &ifaceName = "wlan0", int instId = 0);
    WifiErrorNo StopWifi(int instId = 0);
    WifiErrorNo Connect(int networkId);
    WifiErrorNo Reconnect(void);
    WifiErrorNo Reassociate(void);
    WifiErrorNo Disconnect(const std::string &ifaceName);
    WifiErrorNo GetStaCapabilities(unsigned int &capabilities);
    WifiErrorNo GetStaDeviceMacAddress(std::string &mac, const std::string &ifaceName, int macSrc);
    WifiErrorNo SetWifiCountryCode(const std::string &ifaceName, const std::string &code);
    WifiErrorNo GetSupportFrequencies(const std::string &ifaceName, int band, std::vector<int> &frequencies);
    WifiErrorNo SetConnectMacAddr(const std::string &ifaceName, const std::string &mac);
    WifiErrorNo SetScanMacAddress(const std::string &mac);
    WifiErrorNo DisconnectLastRoamingBssid(const std::string &mac);
    WifiErrorNo GetSupportFeature(long &feature);
    WifiErrorNo SetTxPower(const std::string &ifaceName, int power);
    WifiErrorNo Scan(const std::string &ifaceName, const WifiHalScanParam &scanParam);
    WifiErrorNo QueryScanInfos(const std::string &ifaceName, std::vector<InterScanInfo> &scanInfos);
    WifiErrorNo StartPnoScan(const std::string &ifaceName, const WifiHalPnoScanParam &scanParam);
    WifiErrorNo StopPnoScan(const std::string &ifaceName);
    WifiErrorNo RemoveDevice(int networkId);
    WifiErrorNo ClearDeviceConfig(const std::string &ifaceName) const;
    WifiErrorNo GetNextNetworkId(int &networkId, const std::string &ifaceName);
    WifiErrorNo EnableNetwork(int networkId, const std::string &ifaceName);
    WifiErrorNo DisableNetwork(int networkId, const std::string &ifaceName);
    WifiErrorNo SetDeviceConfig(int networkId, const WifiHalDeviceConfig &config, const std::string &ifaceName);
    WifiErrorNo GetDeviceConfig(WifiHalGetDeviceConfig &config, const std::string &ifaceName);
    WifiErrorNo SaveDeviceConfig(void);
    WifiErrorNo RegisterStaEventCallback(const WifiEventCallback &callback, const std::string &ifaceName);
    WifiErrorNo StartWpsPbcMode(const WifiHalWpsConfig &config);
    WifiErrorNo StartWpsPinMode(const WifiHalWpsConfig &config, int &pinCode);
    WifiErrorNo StopWps(void);
    WifiErrorNo GetRoamingCapabilities(WifiHalRoamCapability &capability);
    WifiErrorNo SetBssid(int networkId, const std::string &bssid, const std::string &ifaceName);
    WifiErrorNo SetRoamConfig(const WifiHalRoamConfig &config);
    WifiErrorNo WpaAutoConnect(int enable);
    WifiErrorNo WpaBlocklistClear();
    WifiErrorNo GetNetworkList(std::vector<WifiHalWpaNetworkInfo> &networkList);
    WifiErrorNo GetConnectSignalInfo(const std::string &ifaceName, const std::string &endBssid,
        WifiSignalPollInfo &info);
    WifiErrorNo SetPmMode(const std::string &ifaceName, int frequency, int mode);
    WifiErrorNo SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable);
    WifiErrorNo ShellCmd(const std::string &ifName, const std::string &cmd);
    WifiErrorNo GetPskPassphrase(const std::string &ifName, std::string &psk);
    WifiErrorNo GetChipsetCategory(const std::string &ifaceName, int& chipsetCategory);
    WifiErrorNo GetChipsetWifiFeatrureCapability(const std::string &ifaceName, int& chipsetFeatrureCapability);
    WifiErrorNo SetNetworkInterfaceUpDown(const std::string &ifaceName, bool upDown);
    const WifiEventCallback &GetCallbackInst(const std::string &ifaceName) const;
    const std::function<void(int)> &GetDeathCallbackInst(void) const;
    WifiErrorNo RegisterNativeProcessCallback(const std::function<void(int)> &callback);
public:
    WifiSignalPollInfo mInfo;
private:
    WifiEventCallback mStaCallback;
    std::function<void(int)> mDeathCallback;
    WifiHalRoamCapability mCapability;
};
}  // namespace Wifi
}  // namespace OHOS

#endif