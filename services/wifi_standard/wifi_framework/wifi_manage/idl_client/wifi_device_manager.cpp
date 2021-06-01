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

#include "wifi_device_manager.h"
#include "wifi_log.h"
#include "i_wifi.h"
#include "i_wifi_chip.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_WIFI_DEVICE_MANAGER"

namespace OHOS {
namespace Wifi {
WifiInterfaceCreateInfo::WifiInterfaceCreateInfo():chipModde(0)
{}

WifiInterfaceCreateInfo::~WifiInterfaceCreateInfo()
{}

IWifiClientIface *WifiDeviceManager::CreateStaInterface(const std::string &ifaceName)
{
    LOGD("CreateStaInterface iface %s", ifaceName.c_str());
    return (IWifiClientIface *)CreateInterface(TYPE_STA);
}

bool WifiDeviceManager::RemoveStaInterface(const IWifiIface &iface)
{
    return RemoveInterface(iface);
}

IWifiApIface *WifiDeviceManager::CreateApInterface(const std::string &ifaceName)
{
    LOGD("CreateApInterface iface %s", ifaceName.c_str());
    return (IWifiApIface *)CreateInterface(TYPE_AP);
}

bool WifiDeviceManager::RemoveApInterface(const IWifiIface &iface)
{
    return RemoveInterface(iface);
}

bool WifiDeviceManager::IsSupported()
{
    return true;
}

bool WifiDeviceManager::IsStarted()
{
    return false;
}

void WifiDeviceManager::GetSupportedIfaceTypes(std::vector<int> &ifaceTypes)
{
    LOGD("GetSupportedIfaceTypes begin size %{public}d", ifaceTypes.size());
    return;
}

IWifiIface *WifiDeviceManager::CreateInterface(const int &ifaceType)
{
    std::vector<WifiChipInfo> chipInfos;
    GetChipInfos(chipInfos);
    if (chipInfos.size() == 0) {
        StopWifi();
    }

    IWifiIface *iface = TryToCreateInterface(chipInfos, ifaceType);
    return iface;
}

IWifiIface *WifiDeviceManager::TryToCreateInterface(const std::vector<WifiChipInfo> &chipInfos, const int &ifaceType)
{
    LOGD("TryToCreateInterface chip size %{public}d", chipInfos.size());
    WifiInterfaceCreateInfo ifaceCreateInfo;
    IWifiIface *iface = ReConfigChip(ifaceCreateInfo, ifaceType);
    return iface;
}

IWifiIface *WifiDeviceManager::ReConfigChip(WifiInterfaceCreateInfo &ifaceCreateInfo, const int &ifaceType)
{
    bool isModeChange =
        !ifaceCreateInfo.chipInfo.currentModeId || ifaceCreateInfo.chipInfo.currentModeId == ifaceCreateInfo.chipModde;
    if (isModeChange) {
        std::vector<WifiIfaceInfo> wifiIfaceInfos;
        WifiIfaceInfo ifaceInfo;
        std::map<int, std::vector<WifiIfaceInfo>>::iterator itor = ifaceCreateInfo.chipInfo.wifiInterfaces.begin();
        while (itor != ifaceCreateInfo.chipInfo.wifiInterfaces.end()) {
            wifiIfaceInfos.clear();
            wifiIfaceInfos.swap(itor->second);

            std::vector<WifiIfaceInfo>::iterator iter = wifiIfaceInfos.begin();
            while (iter != wifiIfaceInfos.end()) {
                ifaceInfo = *iter;
                RemoveInterface(ifaceInfo.iface);
                iter++;
            }

            itor++;
        }
    } else {
        WifiIfaceInfo ifaceInfo;
        std::vector<WifiIfaceInfo>::iterator iter = ifaceCreateInfo.toBeRemovedInterfaces.begin();
        while (iter != ifaceCreateInfo.toBeRemovedInterfaces.end()) {
            ifaceInfo = *iter;
            RemoveInterface(ifaceInfo.iface);
            iter++;
        }
    }

    /* create new interface */
    IWifiIface *wifiIface = nullptr;
    WifiErrorNo errorNo = CreateIface(ifaceType, wifiIface);
    if (errorNo != WIFI_IDL_OPT_OK) {
        LOGE("create new interface failed!");
        return nullptr;
    }

    return wifiIface;
}

bool WifiDeviceManager::RemoveInterface(const IWifiIface &iface)
{
    std::string strName = std::string(iface.name);
    WifiErrorNo error = RemoveIface(strName.c_str());
    if (error != WIFI_IDL_OPT_OK) {
        LOGE("remove interface %s failed!", iface.name);
        return false;
    }

    return true;
}

void WifiDeviceManager::GetChipInfos(std::vector<WifiChipInfo> &chipInfos)
{
    LOGD("GetChipInfos chip size %{public}d", chipInfos.size());
    uint8_t ids[8] = {0};
    int32_t len = 0;
    WifiErrorNo error = GetWifiChipIds(ids, &len);
    if (error != WIFI_IDL_OPT_OK) {
        LOGE("GetWifiChipIds failed!");
        return;
    }
}

bool WifiDeviceManager::StartWifi()
{
    InitWifi();
    return false;
}

void WifiDeviceManager::InitWifi()
{
    StopWifi();
}

void WifiDeviceManager::StopWifi()
{
    return;
}
}  // namespace Wifi
}  // namespace OHOS