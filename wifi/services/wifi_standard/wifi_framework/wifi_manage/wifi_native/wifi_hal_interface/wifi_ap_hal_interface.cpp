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

#include <mutex>
#include "wifi_ap_hal_interface.h"
#include "hal_device_manage.h"
#include "wifi_log.h"
#include "wifi_error_no.h"

#undef LOG_TAG
#define LOG_TAG "WifiApHalInterface"

namespace OHOS {
namespace Wifi {
static IWifiApMonitorEventCallback g_cb = {nullptr, nullptr};
WifiApHalInterface &WifiApHalInterface::GetInstance(void)
{
    static WifiApHalInterface inst;
    static int initFlag = 0;
    static std::mutex initMutex;
    if (initFlag == 0) {
        std::unique_lock<std::mutex> lock(initMutex);
        if (initFlag == 0) {
#ifdef HDI_WPA_INTERFACE_SUPPORT
            if (inst.InitHdiWpaClient()) {
                initFlag = 1;
            }
#endif
        }
    }
    return inst;
}

WifiErrorNo WifiApHalInterface::StartAp(int id, const std::string &ifaceName)
{
    WifiErrorNo ret = WIFI_HAL_OPT_FAILED;
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    ret = mHdiWpaClient->StartAp(id, ifaceName);
#endif
    return ret;
}

WifiErrorNo WifiApHalInterface::StopAp(int id)
{
    WifiErrorNo ret = WIFI_HAL_OPT_FAILED;
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    ret = mHdiWpaClient->StopAp(id);
#endif
    return ret;
}

WifiErrorNo WifiApHalInterface::SetSoftApConfig(const std::string &ifName, const HotspotConfig &config, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetSoftApConfig(ifName, config, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::SetMaxConnectNum(const std::string &ifName, int32_t channel, int32_t maxConn)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetMaxConnectNum(ifName, channel, maxConn)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::EnableAp(int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->EnableAp(id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::SetApPasswd(const char *pass, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetApPasswd(pass, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::GetStationList(std::vector<std::string> &result, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetStationList(result, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::SetSoftApBlockList(const std::string &ifaceName,
    const std::vector<std::string> &blockList)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetBlockList(ifaceName, ifaceName, blockList)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::DisAssociateSta(const std::string &ifaceName, const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().DisAssociateSta(ifaceName, ifaceName, mac)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::AddBlockByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->AddBlockByMac(mac, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::DelBlockByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->DelBlockByMac(mac, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::RemoveStation(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->RemoveStation(mac, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::GetFrequenciesByBand(const std::string &ifaceName,  int band,
    std::vector<int> &frequencies)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, frequencies)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::RegisterApEvent(IWifiApMonitorEventCallback callback, int id)
{
    WifiErrorNo err = WIFI_HAL_OPT_FAILED;
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    err = mHdiWpaClient->RegisterApEvent(callback, id);
#endif
    if (err == WIFI_HAL_OPT_OK || callback.onStaJoinOrLeave == nullptr) {
        mApCallback[id] = callback;
    }
    return err;
}

WifiErrorNo WifiApHalInterface::SetWifiCountryCode(const std::string &ifaceName, const std::string &code)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetWifiCountryCode(ifaceName, code)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::DisconnectStaByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqDisconnectStaByMac(mac, id);
#endif
    return WIFI_HAL_OPT_FAILED;
}

const IWifiApMonitorEventCallback &WifiApHalInterface::GetApCallbackInst(int id) const
{
    auto iter = mApCallback.find(id);
    if (iter != mApCallback.end()) {
        return iter->second;
    }
    return g_cb;
}

WifiErrorNo WifiApHalInterface::GetPowerModel(const std::string &ifaceName, int& model)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetPowerModel(ifaceName, model)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::SetPowerModel(const std::string &ifaceName, int model)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetPowerModel(ifaceName, model)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiApHalInterface::SetConnectMacAddr(const std::string &ifaceName, const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetApMacAddress(ifaceName, mac)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}
}  // namespace Wifi
}  // namespace OHOS