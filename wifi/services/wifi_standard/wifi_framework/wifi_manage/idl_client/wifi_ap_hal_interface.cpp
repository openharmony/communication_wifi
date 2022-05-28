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

WifiErrorNo WifiApHalInterface::StartAp(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StartAp();
}

WifiErrorNo WifiApHalInterface::StopAp(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StopAp();
}

WifiErrorNo WifiApHalInterface::SetSoftApConfig(const HotspotConfig &config)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetSoftApConfig(config);
}

WifiErrorNo WifiApHalInterface::GetStationList(std::vector<std::string> &result)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStationList(result);
}

WifiErrorNo WifiApHalInterface::AddBlockByMac(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->AddBlockByMac(mac);
}

WifiErrorNo WifiApHalInterface::DelBlockByMac(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->DelBlockByMac(mac);
}

WifiErrorNo WifiApHalInterface::RemoveStation(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RemoveStation(mac);
}

WifiErrorNo WifiApHalInterface::GetFrequenciesByBand(int band, std::vector<int> &frequencies)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetFrequenciesByBand(band, frequencies);
}

WifiErrorNo WifiApHalInterface::RegisterApEvent(IWifiApMonitorEventCallback callback)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->RegisterApEvent(callback);
    if (err == WIFI_IDL_OPT_OK || callback.onStaJoinOrLeave == nullptr) {
        mApCallback = callback;
    }
    return err;
}

WifiErrorNo WifiApHalInterface::SetWifiCountryCode(const std::string &code)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetWifiCountryCode(code);
}

WifiErrorNo WifiApHalInterface::DisconnectStaByMac(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqDisconnectStaByMac(mac);
}

const IWifiApMonitorEventCallback &WifiApHalInterface::GetApCallbackInst(void) const
{
    return mApCallback;
}

WifiErrorNo WifiApHalInterface::GetPowerModel(int& model) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetPowerModel(model);
}

WifiErrorNo WifiApHalInterface::SetPowerModel(const int& model) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetPowerModel(model);
}
}  // namespace Wifi
}  // namespace OHOS