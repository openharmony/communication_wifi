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
#include "wifi_supplicant_hal_interface.h"
#include "wifi_log.h"
#include "wifi_config_center.h"

#undef LOG_TAG
#define LOG_TAG "WifiSupplicantHalInterface"

namespace OHOS {
namespace Wifi {
std::mutex WifiSupplicantHalInterface::mSupplicantHalMutex;
WifiSupplicantHalInterface &WifiSupplicantHalInterface::GetInstance(void)
{
    static WifiSupplicantHalInterface inst;
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

WifiErrorNo WifiSupplicantHalInterface::StartSupplicant(void) const
{
    LOGI("call WifiSupplicantHalInterface::%{public}s!", __func__);
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::StopSupplicant(void) const
{
    LOGI("call WifiSupplicantHalInterface::%{public}s!", __func__);
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::ConnectSupplicant(void) const
{
    LOGI("call WifiSupplicantHalInterface::%{public}s!", __func__);
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::DisconnectSupplicant(void) const
{
    LOGI("call WifiSupplicantHalInterface::%{public}s!", __func__);
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::RequestToSupplicant(const std::string &request) const
{
    LOGI("call WifiSupplicantHalInterface::%{public}s!", __func__);
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::RegisterSupplicantEventCallback(SupplicantEventCallback &callback)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::lock_guard<std::mutex> lock(mSupplicantHalMutex);
    mCallback = callback;
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::UnRegisterSupplicantEventCallback(void)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::lock_guard<std::mutex> lock(mSupplicantHalMutex);
    mCallback.onScanNotify = nullptr;
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::SetPowerSave(bool enable) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqSetPowerSave(
        enable, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetCountryCode(const std::string &countryCode) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaSetCountryCode(
        countryCode, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::WpaGetCountryCode(std::string &countryCode) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaGetCountryCode(
        countryCode, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

const SupplicantEventCallback &WifiSupplicantHalInterface::GetCallbackInst(void) const
{
    return mCallback;
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetSuspendMode(bool mode) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaSetSuspendMode(
        mode, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiSupplicantHalInterface::WpaSetPowerMode(bool mode, int instId) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqSetPowerSave(mode, WifiConfigCenter::GetInstance().GetStaIfaceName(instId).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

void WifiSupplicantHalInterface::NotifyScanResultEvent(uint32_t event)
{
    std::lock_guard<std::mutex> lock(mSupplicantHalMutex);
    if (mCallback.onScanNotify) {
        if (event == HAL_CMD_SCAN_ABORTED) {
            mCallback.onScanNotify(HAL_SINGLE_SCAN_FAILED);
        } else {
            mCallback.onScanNotify(HAL_SINGLE_SCAN_OVER_OK);
        }
    }
}
}  // namespace Wifi
}  // namespace OHOS
