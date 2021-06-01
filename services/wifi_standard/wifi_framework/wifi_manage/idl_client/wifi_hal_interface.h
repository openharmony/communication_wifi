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

#ifndef OHOS_WIFIHALINTERFACE_H
#define OHOS_WIFIHALINTERFACE_H

#include <string>
#include "wifi_interface_manager.h"
#include "wifi_vendor_interface.h"

namespace OHOS {
namespace Wifi {
class WifiHalInterface {
public:
    /**
     * @Description Get the Instance object.
     *
     * @return WifiHalInterface&
     */
    static WifiHalInterface &GetInstance(void);
    /**
     * @Description Create a Sta Interface object.
     *
     * @param type
     * @param iface
     * @return int
     */
    int CreateStaInterface(InterfaceType type, WifiInterfaceInfo *iface);
    /**
     * @Description Create a Ap Interface object.
     *
     * @param iface
     * @return int
     */
    int CreateApInterface(WifiInterfaceInfo *iface);
    /**
     * @Description Remove Sta Interface.
     *
     * @param iface
     * @return true
     * @return false
     */
    bool RemoveStaInterface(const WifiInterfaceInfo *iface);
    /**
     * @Description Remove Ap Interface.
     *
     * @param iface
     * @return true
     * @return false
     */
    bool RemoveApInterface(const WifiInterfaceInfo *iface);
    /**
     * @Description Shut Down Interface.
     *
     * @param ifaceName
     * @return true
     * @return false
     */
    bool ShutDownInterface(const std::string &ifaceName);
    /**
     * @Description Is Wifi Interface Up.
     *
     * @param ifaceName
     * @return true
     * @return false
     */
    bool IsWifiInterfaceUp(const std::string &ifaceName);

private:
    void OnInterfaceStateChanged(WifiInterfaceInfo &iface, bool bIsUp);
    void OnInterfaceDestroyed(const WifiInterfaceInfo &iface);
    void OnStaInterfaceForScanDestroyed(const WifiInterfaceInfo &iface);
    void OnStaInterfaceForConnectivityDestroyed(const WifiInterfaceInfo &iface);
    void OnApInterfaceForConnectivityDestroyed(const WifiInterfaceInfo &iface);

private:
    WifiInterfaceManager mIfaceMgr;
    WifiVendorInterface mVendorInterface;
};
}  // namespace Wifi
}  // namespace OHOS

#endif