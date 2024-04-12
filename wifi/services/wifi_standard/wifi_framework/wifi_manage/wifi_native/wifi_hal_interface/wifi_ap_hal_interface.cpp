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
#include "wifi_ap_hal_interface.h"
#include <mutex>
#include "wifi_log.h"
#include "wifi_error_no.h"
#include "wifi_idl_define.h"

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
#ifdef HDI_INTERFACE_SUPPORT
            if (inst.InitHdiClient()) {
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
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo ret = mHdiWpaClient->StartAp(id, ifaceName);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo ret = mIdlClient->StartAp(id, ifaceName);
#endif
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    ret = mHdiClient->StartAp(id);
#endif
    return ret;
}

WifiErrorNo WifiApHalInterface::StopAp(int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo ret = mHdiWpaClient->StopAp(id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo ret = mIdlClient->StopAp(id);
#endif
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    ret = mHdiClient->StopAp(id);
#endif
    return ret;
}

WifiErrorNo WifiApHalInterface::SetSoftApConfig(const HotspotConfig &config, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->SetSoftApConfig(config, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetSoftApConfig(config, id);
#endif
}

WifiErrorNo WifiApHalInterface::GetStationList(std::vector<std::string> &result, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetStationList(result, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStationList(result, id);
#endif
}

WifiErrorNo WifiApHalInterface::AddBlockByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->AddBlockByMac(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->AddBlockByMac(mac, id);
#endif
}

WifiErrorNo WifiApHalInterface::DelBlockByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->DelBlockByMac(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->DelBlockByMac(mac, id);
#endif
}

WifiErrorNo WifiApHalInterface::RemoveStation(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->RemoveStation(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RemoveStation(mac, id);
#endif
}

WifiErrorNo WifiApHalInterface::GetFrequenciesByBand(int band, std::vector<int> &frequencies, int id)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->GetFrequenciesByBand(band, frequencies, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetFrequenciesByBand(band, frequencies, id);
#endif
}

WifiErrorNo WifiApHalInterface::RegisterApEvent(IWifiApMonitorEventCallback callback, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mHdiWpaClient->RegisterApEvent(callback, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->RegisterApEvent(callback, id);
#endif
    if (err == WIFI_IDL_OPT_OK || callback.onStaJoinOrLeave == nullptr) {
        mApCallback[id] = callback;
    }
    return err;
}

WifiErrorNo WifiApHalInterface::SetWifiCountryCode(const std::string &code, int id)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->SetWifiCountryCode(code, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetWifiCountryCode(code, id);
#endif
}

WifiErrorNo WifiApHalInterface::DisconnectStaByMac(const std::string &mac, int id)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqDisconnectStaByMac(mac, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
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

WifiErrorNo WifiApHalInterface::GetPowerModel(int& model, int id) const
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqGetPowerModel(model, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetPowerModel(model, id);
#endif
}

WifiErrorNo WifiApHalInterface::SetPowerModel(const int& model, int id) const
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqSetPowerModel(model, id);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetPowerModel(model, id);
#endif
}

WifiErrorNo WifiApHalInterface::SetConnectMacAddr(const std::string &mac)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->SetConnectMacAddr(mac, WIFI_HAL_PORT_TYPE_AP);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetConnectMacAddr(mac, WIFI_HAL_PORT_TYPE_AP);
#endif
}
}  // namespace Wifi
}  // namespace OHOS