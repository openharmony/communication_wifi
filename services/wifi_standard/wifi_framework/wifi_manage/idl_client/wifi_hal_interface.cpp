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

#include "wifi_hal_interface.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_WIFI_HAL_INTERFACE"

namespace OHOS {
namespace Wifi {
WifiHalInterface &WifiHalInterface::GetInstance(void)
{
    static WifiHalInterface instance;
    return instance;
}

int WifiHalInterface::CreateStaInterface(InterfaceType type, WifiInterfaceInfo *iface)
{
    iface = mIfaceMgr.AllocInteface(type);
    if (iface == nullptr) {
        LOGE("CreateStaInterface:alloc interface error!");
        return -1;
    }

    if (mVendorInterface.IsVendorHalSupported()) {
        mVendorInterface.CreateStaInterface(iface->name);
    } else {
        LOGW("CreateStaInterface:Vendor Hal is not supported.");
        iface->name = "wlan0";
    }

    if (iface->name.empty()) {
        LOGE("Create STA iface Failed in vendor HAL.");
        mIfaceMgr.RemoveInterface(iface->id);
        return -1;
    }

    LOGD("CreateStaInterface Successfully,and name is %s", iface->name.c_str());
    OnInterfaceStateChanged(*iface, IsWifiInterfaceUp(iface->name));

    /* get wifi insterface support feature */
    iface->featureSet = mVendorInterface.GetSupportedFeatureSet(iface->name);
    return 0;
}

int WifiHalInterface::CreateApInterface(WifiInterfaceInfo *iface)
{
    iface = mIfaceMgr.AllocInteface(IFACE_TYPE_AP);
    if (iface == nullptr) {
        LOGE("CreateApInterface:alloc interface error!");
        return -1;
    }

    if (mVendorInterface.IsVendorHalSupported()) {
        mVendorInterface.CreateStaInterface(iface->name);
    } else {
        LOGW("CreateApInterface:Vendor Hal is not supported.");
        iface->name = "wlan1";
    }

    if (iface->name.empty()) {
        LOGE("Create AP iface Failed in vendor HAL.");
        mIfaceMgr.RemoveInterface(iface->id);
        return -1;
    }

    LOGD("CreateApInterface Successfully,and name is %s", iface->name.c_str());
    OnInterfaceStateChanged(*iface, IsWifiInterfaceUp(iface->name));

    /* get wifi insterface support feature */
    iface->featureSet = mVendorInterface.GetSupportedFeatureSet(iface->name);
    return 0;
}

bool WifiHalInterface::RemoveStaInterface(const WifiInterfaceInfo *iface)
{
    if (mVendorInterface.IsVendorHalSupported()) {
        return mVendorInterface.RemoveStaInterface(iface->name);
    } else {
        LOGW("RemoveStaInterface:Vendor Hal is not supported.");
        if (mIfaceMgr.RemoveInterface(iface->id)) {
            OnInterfaceDestroyed(*iface);
            LOGI("remove interface name = %s,id = %{public}d  successfully!", iface->name.c_str(), iface->id);
            return true;
        }
    }

    return false;
}

bool WifiHalInterface::RemoveApInterface(const WifiInterfaceInfo *iface)
{
    if (mVendorInterface.IsVendorHalSupported()) {
        return mVendorInterface.RemoveApInterface(iface->name);
    } else {
        LOGW("RemoveApInterface:Vendor Hal is not supported.");
        if (mIfaceMgr.RemoveInterface(iface->id)) {
            OnInterfaceDestroyed(*iface);
            LOGI("remove interface name = %s,id = %{public}d  successfully!", iface->name.c_str(), iface->id);
            return true;
        }
    }

    return false;
}

bool WifiHalInterface::ShutDownInterface(const std::string &ifaceName)
{
    WifiInterfaceInfo *iface = mIfaceMgr.GetInterface(ifaceName);
    if (iface == nullptr) {
        return false;
    }
    if (iface->type == IFACE_TYPE_STA_FOR_CONNECTIVITY || iface->type == IFACE_TYPE_STA_FOR_SCAN) {
        return RemoveStaInterface(iface);
    } else if (iface->type == IFACE_TYPE_AP) {
        return RemoveApInterface(iface);
    }

    LOGI("interface %s is no need to remove!", ifaceName.c_str());
    return true;
}

bool WifiHalInterface::IsWifiInterfaceUp(const std::string &ifaceName)
{
    LOGD("IsWifiInterfaceUp iface %s", ifaceName.c_str());
    return false;
}

void WifiHalInterface::OnInterfaceStateChanged(WifiInterfaceInfo &iface, bool bIsUp)
{
    if (bIsUp == iface.isUp) {
        LOGD("interface status is unchanged on index %{public}d is %{public}d", iface.id, bIsUp);
        return;
    }

    LOGD("interface %s old status is %{public}d,new status is %{public}d", iface.name.c_str(), iface.isUp, bIsUp);
    iface.isUp = bIsUp;
}

void WifiHalInterface::OnInterfaceDestroyed(const WifiInterfaceInfo &iface)
{
    if (iface.type == IFACE_TYPE_STA_FOR_CONNECTIVITY) {
        OnStaInterfaceForConnectivityDestroyed(iface);
    } else if (iface.type == IFACE_TYPE_STA_FOR_SCAN) {
        OnStaInterfaceForScanDestroyed(iface);
    } else if (iface.type == IFACE_TYPE_AP) {
        OnApInterfaceForConnectivityDestroyed(iface);
    }
}
void WifiHalInterface::OnStaInterfaceForScanDestroyed(const WifiInterfaceInfo &iface)
{
    LOGD("OnStaInterfaceForScanDestroyed iface type %{public}d", iface.type);
    return;
}

void WifiHalInterface::OnStaInterfaceForConnectivityDestroyed(const WifiInterfaceInfo &iface)
{
    LOGD("OnStaInterfaceForConnectivityDestroyed iface type %{public}d", iface.type);
    return;
}

void WifiHalInterface::OnApInterfaceForConnectivityDestroyed(const WifiInterfaceInfo &iface)
{
    LOGD("OnApInterfaceForConnectivityDestroyed iface type %{public}d", iface.type);
    return;
}
}  // namespace Wifi
}  // namespace OHOS