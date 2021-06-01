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
#include "wifi_vendor_interface.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_WIFI_VENDOR_INTERFACE"

namespace OHOS {
namespace Wifi {
int WifiVendorInterface::CreateStaInterface(std::string &ifaceName)
{
    mDeviceManager.CreateStaInterface(ifaceName);
    if (ifaceName.empty()) {
        LOGE("CreateStaInterface: failed!");
        return -1;
    }
    return 0;
}

bool WifiVendorInterface::RemoveStaInterface(const std::string &ifaceName)
{
    IWifiClientIface *staIface = nullptr;
    GetWifiStaIface(ifaceName, staIface);
    IWifiIface *iface = (IWifiIface *)staIface;
    if (iface == nullptr) {
        return false;
    }
    return mDeviceManager.RemoveStaInterface(*iface);
}

int WifiVendorInterface::CreateApInterface(std::string &ifaceName)
{
    mDeviceManager.CreateStaInterface(ifaceName);
    if (ifaceName.empty()) {
        LOGE("CreateStaInterface: failed!");
        return -1;
    }
    return 0;
}

bool WifiVendorInterface::RemoveApInterface(const std::string &ifaceName)
{
    IWifiApIface *apIface = nullptr;
    GetWifiApIface(ifaceName, apIface);
    IWifiIface *iface = (IWifiIface *)apIface;
    if (iface == nullptr) {
        return false;
    }
    return mDeviceManager.RemoveApInterface(*iface);
}

bool WifiVendorInterface::IsVendorHalSupported()
{
    return mDeviceManager.IsSupported();
}

long WifiVendorInterface::GetSupportedFeatureSet(const std::string &ifaceName)
{
    LOGD("GetSupportedFeatureSet iface %s", ifaceName.c_str());
    long featureSet = 0;
    if (!mDeviceManager.IsStarted()) {
        return featureSet;
    }
    return featureSet;
}

void WifiVendorInterface::GetWifiStaIface(const std::string &ifaceName, IWifiClientIface *iface)
{
    std::map<std::string, IWifiClientIface *>::iterator itor = mWifiStaIfaces.find(ifaceName);
    if (itor != mWifiStaIfaces.end()) {
        iface = itor->second;
    }
}

void WifiVendorInterface::GetWifiApIface(const std::string &ifaceName, IWifiApIface *iface)
{
    std::map<std::string, IWifiApIface *>::iterator itor = mWifiApIfaces.find(ifaceName);
    if (itor != mWifiApIfaces.end()) {
        iface = itor->second;
    }
}
}  // namespace Wifi
}  // namespace OHOS