/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "oh_wifi.h"
#include "wifi_device.h"

std::shared_ptr<OHOS::Wifi::WifiDevice> g_WifiDevicePtr = OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);

static WifiResultCode WifiErrCodeToResultCode(OHOS::Wifi::ErrCode errCode)
{
    switch (errCode) {
        case OHOS::Wifi::WIFI_OPT_SUCCESS:
            return WIFI_SUCCESS;
        case OHOS::Wifi::WIFI_OPT_PERMISSION_DENIED:
            return WIFI_PERMISSION_DENIED;
        case OHOS::Wifi::WIFI_OPT_INVALID_PARAM:
            return WIFI_INVALID_PARAM;
        case OHOS::Wifi::WIFI_OPT_NOT_SUPPORTED:
            return WIFI_NOT_SUPPORTED;
        default:
            return WIFI_OPERATION_FAILED;
    }
}

WifiResultCode OH_Wifi_IsWifiEnabled(bool *enabled)
{
    if (enabled == nullptr) {
        return WIFI_INVALID_PARAM;
    }

    if (g_WifiDevicePtr == nullptr) {
        return WIFI_OPERATION_FAILED;
    }

    bool isEnabled = false;
    OHOS::Wifi::ErrCode ret = g_WifiDevicePtr->IsWifiActive(isEnabled);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        return WifiErrCodeToResultCode(ret);
    }

    *enabled = isEnabled;
    return WIFI_SUCCESS;
}