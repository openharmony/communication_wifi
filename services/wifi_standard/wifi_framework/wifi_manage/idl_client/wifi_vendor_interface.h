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

#ifndef OHOS_WIFIVENDORINTERFACE_H
#define OHOS_WIFIVENDORINTERFACE_H

#include <string>
#include "wifi_device_manager.h"
#include "i_wifi_struct.h"

namespace OHOS {
namespace Wifi {
class WifiVendorInterface {
public:
    /**
     * @Description Create a Sta Interface object.
     *
     * @param ifaceName
     * @return int - 0 Success, -1 Failed.
     */
    int CreateStaInterface(std::string &ifaceName);
    /**
     * @Description Remove Sta Interface.
     *
     * @param ifaceName
     * @return true
     * @return false
     */
    bool RemoveStaInterface(const std::string &ifaceName);
    /**
     * @Description Create an Ap Interface object.
     *
     * @param ifaceName
     * @return int - 0 Success, -1 Failed.
     */
    int CreateApInterface(std::string &ifaceName);
    /**
     * @Description Remove Ap Interface.
     *
     * @param ifaceName
     * @return true
     * @return false
     */
    bool RemoveApInterface(const std::string &ifaceName);
    /**
     * @Description Check is vendor hal supported.
     *
     * @return true
     * @return false
     */
    bool IsVendorHalSupported();
    /**
     * @Description Get the Supported Feature Set object.
     *
     * @param ifaceName
     * @return long
     */
    long GetSupportedFeatureSet(const std::string &ifaceName);

private:
    void GetWifiStaIface(const std::string &ifaceName, IWifiClientIface *iface);
    void GetWifiApIface(const std::string &ifaceName, IWifiApIface *iface);

private:
    WifiDeviceManager mDeviceManager;
    std::map<std::string, IWifiClientIface *> mWifiStaIfaces;
    std::map<std::string, IWifiApIface *> mWifiApIfaces;
};
}  // namespace Wifi
}  // namespace OHOS

#endif