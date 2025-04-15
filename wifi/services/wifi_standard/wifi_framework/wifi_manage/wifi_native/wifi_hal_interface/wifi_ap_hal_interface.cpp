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
#else
            if (inst.InitIdlClient()) {
                initFlag = 1;
            }
#endif
        }
    }
    return inst;
}

WifiErrorNo WifiApHalInterface::StartAp(int id, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    WifiErrorNo ret = mHdiWpaClient->StartAp(id, ifaceName);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    WifiErrorNo ret = mIdlClient->StartAp(id, ifaceName);
#endif
    return ret;
}

WifiErrorNo WifiApHalInterface::StopAp(int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    WifiErrorNo ret = mHdiWpaClient->StopAp(id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    WifiErrorNo ret = mIdlClient->StopAp(id);
#endif
    return ret;
}

WifiErrorNo WifiApHalInterface::SetSoftApConfig(const std::string &ifName, const HotspotConfig &config, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetSoftApConfig(ifName, config, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->SetSoftApConfig(config, id);
#endif
}

WifiErrorNo WifiApHalInterface::SetMaxConnectNum(const std::string &ifName, int32_t channel, int32_t maxConn)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetMaxConnectNum(ifName, channel, maxConn)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#else
    return WIFI_HAL_OPT_OK;
#endif
}

WifiErrorNo WifiApHalInterface::EnableAp(int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->EnableAp(id);
#else
    return WIFI_HAL_OPT_OK;
#endif
}

WifiErrorNo WifiApHalInterface::SetApPasswd(const char *pass, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetApPasswd(pass, id);
#else
    return WIFI_HAL_OPT_OK;
#endif
}

WifiErrorNo WifiApHalInterface::GetStationList(std::vector<std::string> &result, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetStationList(result, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->GetStationList(result, id);
#endif
}

WifiErrorNo WifiApHalInterface::SetSoftApBlockList(const std::string &ifaceName,
    const std::vector<std::string> &blockList)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetBlockList(ifaceName, ifaceName, blockList)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#else
    return WIFI_HAL_OPT_FAILED;
#endif
}

WifiErrorNo WifiApHalInterface::DisAssociateSta(const std::string &ifaceName, const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().DisAssociateSta(ifaceName, ifaceName, mac)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#else
    return WIFI_HAL_OPT_FAILED;
#endif
}

WifiErrorNo WifiApHalInterface::AddBlockByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->AddBlockByMac(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->AddBlockByMac(mac, id);
#endif
}

WifiErrorNo WifiApHalInterface::DelBlockByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->DelBlockByMac(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->DelBlockByMac(mac, id);
#endif
}

WifiErrorNo WifiApHalInterface::RemoveStation(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->RemoveStation(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->RemoveStation(mac, id);
#endif
}

WifiErrorNo WifiApHalInterface::GetFrequenciesByBand(const std::string &ifaceName,  int band,
    std::vector<int> &frequencies)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, frequencies)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->GetFrequenciesByBand(band, frequencies);
#endif
}

WifiErrorNo WifiApHalInterface::RegisterApEvent(IWifiApMonitorEventCallback callback, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    WifiErrorNo err = mHdiWpaClient->RegisterApEvent(callback, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->RegisterApEvent(callback, id);
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
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->SetWifiCountryCode(code);
#endif
}

WifiErrorNo WifiApHalInterface::DisconnectStaByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqDisconnectStaByMac(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->ReqDisconnectStaByMac(mac, id);
#endif
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
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->ReqGetPowerModel(model);
#endif
}

WifiErrorNo WifiApHalInterface::SetPowerModel(const std::string &ifaceName, int model)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetPowerModel(ifaceName, model)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->ReqSetPowerModel(model);
#endif
}

WifiErrorNo WifiApHalInterface::SetConnectMacAddr(const std::string &ifaceName, const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetApMacAddress(ifaceName, mac)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_HAL_OPT_FAILED);
    return mIdlClient->SetConnectMacAddr(mac, HAL_PORT_TYPE_AP);
#endif
}
}  // namespace Wifi
}  // namespace OHOS