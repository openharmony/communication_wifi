/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_WIFI_STA_INTERFACE_H
#define OHOS_MOCK_WIFI_STA_INTERFACE_H

#include <string>
#include "wifi_error_no.h"
#include "i_wifi_struct.h"

namespace OHOS {
namespace Wifi {

struct WifiStaHalInfo {
    bool startWifi = true;
    bool stopWifi = true;
    bool connect = true;
    bool reconnect = true;
    bool reassociate = true;
    bool disconnect = true;
    bool getCapabilities = true;
    bool getDeviceAddress = true;
    bool getSupportFre = true;
    bool setConnectMac = true;
    bool setScanMac = true;
    bool disconnectLast = true;
    bool getSupportFeature = true;
    bool sendRequest = true;
    bool setTxPower = true;
    bool removeDevice = true;
    bool clearDeviceConfig = true;
    bool getNextNetworkId = true;
    bool enableNetwork = true;
    bool getDeviceConfig = true;
    bool setDeviceConfig = true;
    bool disableNetwork = true;
    bool saveDeviceConfig = true;
    bool callback = true;
    bool stopWps = true;
    bool startWpsPbcMode = true;
    bool startWpsPinMode = true;
    bool getRoamingCapabilities = true;
    bool setRoamConfig = true;
    bool wpaAutoConnect = true;
    bool wpaBlocklistClear = true;
    bool getNetworkList = true;
    bool getConnectSignalInfo = true;
    bool setBssid = true;
}

struct SupplicantHalInfo {
    bool startSipplicant = true;
    bool setCountrycode = true;
    bool setSuspend = true;
    bool setPower = true;
}

class MockWifiStaInterface {
public:
    MockWifiStaInterface() = default;
    virtual ~MockWifiStaInterface() = default;
    static MockWifiStaInterface &GetInstance(void);
public:
    WifiStaHalInfo pWifiStaHalInfo;
    SupplicantHalInfo pSupplicant;
};

}  // namespace OHOS
}  // namespace OHOS
#endif
