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

#ifndef OHOS_WIFIDEVICEMANAGER_H
#define OHOS_WIFIDEVICEMANAGER_H

#include <string>
#include <vector>
#include <map>
#include "i_wifi_struct.h"

namespace OHOS {
namespace Wifi {
class WifiIfaceInfo {
public:
    std::string name;
    IWifiIface iface;
};

class WifiChipInfo {
public:
    IWifiChip chip;
    int chipId;
    std::vector<int> chipModes;
    int currentModeId;
    std::map<int, std::vector<WifiIfaceInfo>> wifiInterfaces;
};

class WifiInterfaceCreateInfo {
public:
    WifiInterfaceCreateInfo();
    ~WifiInterfaceCreateInfo();
    WifiChipInfo chipInfo;
    int chipModde;
    std::vector<WifiIfaceInfo> toBeRemovedInterfaces;
};

class WifiDeviceManager {
public:
    /**
     * @Description Create a Sta Interface object.
     *
     * @param ifaceName
     * @return IWifiClientIface*
     */
    IWifiClientIface *CreateStaInterface(const std::string &ifaceName);
    /**
     * @Description Remove Sta Interface.
     *
     * @param iface
     * @return true
     * @return false
     */
    bool RemoveStaInterface(const IWifiIface &iface);
    /**
     * @Description Create a Ap Interface object.
     *
     * @param ifaceName
     * @return IWifiApIface*
     */
    IWifiApIface *CreateApInterface(const std::string &ifaceName);
    /**
     * @Description Remove Ap Interface.
     *
     * @param iface
     * @return true
     * @return false
     */
    bool RemoveApInterface(const IWifiIface &iface);
    /**
     * @Description Check is supported.
     *
     * @return true
     * @return false
     */
    bool IsSupported();
    /**
     * @Description Check is Started.
     *
     * @return true
     * @return false
     */
    bool IsStarted();
    /**
     * @Description Get the Supported Iface Types.
     *
     * @param ifaceTypes
     */
    void GetSupportedIfaceTypes(std::vector<int> &ifaceTypes);

private:
    IWifiIface *CreateInterface(const int &ifaceType);
    IWifiIface *TryToCreateInterface(const std::vector<WifiChipInfo> &chipInfos, const int &ifaceType);
    IWifiIface *ReConfigChip(WifiInterfaceCreateInfo &ifaceCreateInfo, const int &ifaceType);
    bool RemoveInterface(const IWifiIface &iface);
    void GetChipInfos(std::vector<WifiChipInfo> &chipInfos);
    bool StartWifi();
    void InitWifi();
    void StopWifi();
};
}  // namespace Wifi
}  // namespace OHOS
#endif