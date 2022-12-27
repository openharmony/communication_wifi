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

#ifndef OHOS_MOCK_WIFI_AP_HAL_INTERFACE_H
#define OHOS_MOCK_WIFI_AP_HAL_INTERFACE_H

#include <gmock/gmock.h>
#include <map>
#include <string>
#include <vector>

#include "i_wifi_struct.h"
#include "wifi_error_no.h"
#include "wifi_ap_msg.h"
#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace Wifi {
typedef struct IWifiApMonitorEventCallback {
    std::function<void(CStationInfo *)> onStaJoinOrLeave;
    std::function<void(int)> onApEnableOrDisable;
} IWifiApMonitorEventCallback;
class MockWifiApHalInterface {
public:
    virtual ~MockWifiApHalInterface() = default;
    virtual WifiErrorNo StartAp(int id = 0) = 0;
    virtual WifiErrorNo StopAp(int id = 0) = 0;
    virtual WifiErrorNo SetSoftApConfig(const HotspotConfig &config, int id = 0) = 0;
    virtual WifiErrorNo GetStationList(std::vector<std::string> &result, int id = 0) = 0;
    virtual WifiErrorNo AddBlockByMac(const std::string &mac, int id = 0) = 0;
    virtual WifiErrorNo DelBlockByMac(const std::string &mac, int id = 0) = 0;
    virtual WifiErrorNo RemoveStation(const std::string &mac, int id = 0) = 0;
    virtual WifiErrorNo GetFrequenciesByBand(int band, std::vector<int> &frequencies) = 0;
    virtual WifiErrorNo GetFrequenciesByBand(int band, std::vector<int> &frequencies, int id = 0) = 0;
    virtual WifiErrorNo RegisterApEvent(IWifiApMonitorEventCallback callback, int id = 0) = 0;
    virtual WifiErrorNo SetWifiCountryCode(const std::string &code, int id = 0) = 0;
    virtual WifiErrorNo DisconnectStaByMac(const std::string &mac, int id = 0) = 0;
    virtual const IWifiApMonitorEventCallback &GetApCallbackInst(int id = 0) const = 0;
    virtual WifiErrorNo GetPowerModel(int& model, int id = 0) const = 0;
    virtual WifiErrorNo SetPowerModel(const int& model, int id = 0) const = 0;
};

class WifiApHalInterface : public MockWifiApHalInterface {
public:
    static WifiApHalInterface &GetInstance(void);
    MOCK_METHOD1(StartAp, WifiErrorNo(int id));
    MOCK_METHOD1(StopAp, WifiErrorNo(int id));
    MOCK_METHOD2(SetSoftApConfig, WifiErrorNo(const HotspotConfig &config, int id));
    MOCK_METHOD2(GetStationList, WifiErrorNo(std::vector<std::string> &result, int id));
    MOCK_METHOD2(AddBlockByMac, WifiErrorNo(const std::string &mac, int id));
    MOCK_METHOD2(DelBlockByMac, WifiErrorNo(const std::string &mac, int id));
    MOCK_METHOD2(RemoveStation, WifiErrorNo(const std::string &mac, int id));
    MOCK_METHOD2(GetFrequenciesByBand, WifiErrorNo(int band, std::vector<int> &frequencies));
    MOCK_METHOD3(GetFrequenciesByBand, WifiErrorNo(int band, std::vector<int> &frequencies, int id));
    MOCK_METHOD2(RegisterApEvent, WifiErrorNo(IWifiApMonitorEventCallback callback, int id));
    MOCK_METHOD2(SetWifiCountryCode, WifiErrorNo(const std::string &code, int id));
    MOCK_METHOD2(DisconnectStaByMac, WifiErrorNo(const std::string &mac, int id));
    MOCK_CONST_METHOD1(GetApCallbackInst, IWifiApMonitorEventCallback &(int id));
    MOCK_CONST_METHOD2(GetPowerModel, WifiErrorNo(int& model, int id));
    MOCK_CONST_METHOD2(SetPowerModel, WifiErrorNo(const int& model, int id));
};
} // namespace Wifi
} // namespace OHOS
#endif