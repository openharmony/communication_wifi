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
#include "mock_wifi_supplicant_hal_interface.h"


namespace OHOS {
namespace Wifi {

MockWifiSupplicantHalInterface::MockWifiSupplicantHalInterface()
{
    mRetResult = WIFI_HAL_OPT_OK;
}

MockWifiSupplicantHalInterface &MockWifiSupplicantHalInterface::GetInstance(void)
{
    static MockWifiSupplicantHalInterface inst;
    return inst;
}
void MockWifiSupplicantHalInterface::SetRetResult(WifiErrorNo retResult)
{
    mRetResult = retResult;
}
WifiErrorNo MockWifiSupplicantHalInterface::GetRetResult()
{
    return mRetResult;
}

WifiSupplicantHalInterface &WifiSupplicantHalInterface::GetInstance(void)
{
    static WifiSupplicantHalInterface inst;
    return inst;
}

WifiErrorNo WifiSupplicantHalInterface::StartSupplicant(void) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::StopSupplicant(void) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::ConnectSupplicant(void) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::DisconnectSupplicant(void) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::RequestToSupplicant(const std::string &request) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::RegisterSupplicantEventCallback(SupplicantEventCallback &callback)
{
    mCallback = callback;
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::UnRegisterSupplicantEventCallback(void)
{
    mCallback.onScanNotify = nullptr;
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::SetPowerSave(bool enable) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetCountryCode(const std::string &countryCode) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::WpaGetCountryCode(std::string &countryCode) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

const SupplicantEventCallback &WifiSupplicantHalInterface::GetCallbackInst(void) const
{
    return mCallback;
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetSuspendMode(bool mode) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetPowerMode(bool mode, int instId) const
{
    return (MockWifiSupplicantHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

void WifiSupplicantHalInterface::NotifyScanResultEvent()
{
}
}  // namespace Wifi
}  // namespace OHOS
