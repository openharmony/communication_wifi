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
            if (inst.InitIdlClient()) {
                initFlag = 1;
            }
        }
    }
    return inst;
}

WifiErrorNo WifiApHalInterface::StartAp(int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StartAp(id);
}

WifiErrorNo WifiApHalInterface::StopAp(int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StopAp(id);
}

WifiErrorNo WifiApHalInterface::SetSoftApConfig(const HotspotConfig &config, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetSoftApConfig(config, id);
}

WifiErrorNo WifiApHalInterface::GetStationList(std::vector<std::string> &result, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStationList(result, id);
}

WifiErrorNo WifiApHalInterface::AddBlockByMac(const std::string &mac, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->AddBlockByMac(mac, id);
}

WifiErrorNo WifiApHalInterface::DelBlockByMac(const std::string &mac, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->DelBlockByMac(mac, id);
}

WifiErrorNo WifiApHalInterface::RemoveStation(const std::string &mac, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RemoveStation(mac, id);
}

WifiErrorNo WifiApHalInterface::GetFrequenciesByBand(int band, std::vector<int> &frequencies, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetFrequenciesByBand(band, frequencies, id);
}

WifiErrorNo WifiApHalInterface::RegisterApEvent(IWifiApMonitorEventCallback callback, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->RegisterApEvent(callback, id);
    if (err == WIFI_IDL_OPT_OK || callback.onStaJoinOrLeave == nullptr) {
        mApCallback[id] = callback;
    }
    return err;
}

WifiErrorNo WifiApHalInterface::SetWifiCountryCode(const std::string &code, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetWifiCountryCode(code, id);
}

WifiErrorNo WifiApHalInterface::DisconnectStaByMac(const std::string &mac, int id)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqDisconnectStaByMac(mac, id);
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
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetPowerModel(model, id);
}

WifiErrorNo WifiApHalInterface::SetPowerModel(const int& model, int id) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetPowerModel(model, id);
}
}  // namespace Wifi
}  // namespace OHOS