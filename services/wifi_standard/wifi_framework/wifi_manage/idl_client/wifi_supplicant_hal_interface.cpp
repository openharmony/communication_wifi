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
#include "wifi_supplicant_hal_interface.h"
#include <mutex>
#include "wifi_log.h"
#include "wifi_idl_inner_interface.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_WIFI_SUPPLICANT_HAL_INTERFACE"

RpcClient *GetSupplicantRpcClient(void)
{
    return OHOS::Wifi::WifiSupplicantHalInterface::GetInstance().mIdlClient->pRpcClient;
}

namespace OHOS {
namespace Wifi {
WifiSupplicantHalInterface &WifiSupplicantHalInterface::GetInstance(void)
{
    static WifiSupplicantHalInterface inst;
    static int initFlag = 0;
    static std::mutex initMutex;
    if (initFlag == 0) {
        std::unique_lock<std::mutex> lock(initMutex);
        if (initFlag == 0) {
            inst.InitIdlClient();
            initFlag = 1;
        }
    }
    return inst;
}

WifiErrorNo WifiSupplicantHalInterface::StartSupplicant(void)
{
    return mIdlClient->ReqStartSupplicant();
}

WifiErrorNo WifiSupplicantHalInterface::StopSupplicant(void)
{
    return mIdlClient->ReqStopSupplicant();
}

WifiErrorNo WifiSupplicantHalInterface::ConnectSupplicant(void)
{
    return mIdlClient->ReqConnectSupplicant();
}

WifiErrorNo WifiSupplicantHalInterface::DisconnectSupplicant(void)
{
    return mIdlClient->ReqDisconnectSupplicant();
}

WifiErrorNo WifiSupplicantHalInterface::RequestToSupplicant(const std::string &request)
{
    return mIdlClient->ReqRequestToSupplicant(request);
}

WifiErrorNo WifiSupplicantHalInterface::RigisterSupplicantEventCallback(SupplicantEventCallback &callback)
{
    return mIdlClient->ReqRigisterSupplicantEventCallback(callback);
}

WifiErrorNo WifiSupplicantHalInterface::UnRigisterSupplicantEventCallback(void)
{
    return mIdlClient->ReqUnRigisterSupplicantEventCallback();
}

WifiErrorNo WifiSupplicantHalInterface::SetPowerSave(bool enable)
{
    return mIdlClient->ReqSetPowerSave(enable);
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetCountryCode(const std::string &countryCode)
{
    if (countryCode.length() <= 0) {
        return WIFI_IDL_OPT_FAILED;
    }
    return mIdlClient->ReqWpaSetCountryCode(countryCode);
}

WifiErrorNo WifiSupplicantHalInterface::WpaGetCountryCode(std::string &countryCode)
{
    return mIdlClient->ReqWpaGetCountryCode(countryCode);
}
}  // namespace Wifi
}  // namespace OHOS