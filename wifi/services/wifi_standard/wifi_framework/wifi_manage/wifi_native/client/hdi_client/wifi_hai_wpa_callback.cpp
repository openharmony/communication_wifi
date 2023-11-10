/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_callback.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"

void OnEventDisconnected(HdiWpaDisconnectParam *disconnectParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(status, networkId, mac);
    }
}

void OnEventConnected(HdiWpaConnectParam *connectParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(status, networkId, mac);
    }
}

void OnEventBssidChanged(HdiWpaBssidChangedParam *bssidChangedParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onBssidChanged) {
        cbk.onBssidChanged(reason, bssid);
    }
}

void OnEventStateChanged(HdiWpaStateChangedParam *stateChangedParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaStateChanged) {
        cbk.onWpaStateChanged(reason, bssid);
    }
}

void OnEventTempDisabled(HdiWpaTempDisabledParam *tempDisabledParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaStateChanged) {
        cbk.onWpaStateChanged(status);
    }
}

void OnEventAssociateReject(HdiWpaAssociateRejectParam *associateRejectParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaConnectionReject) {
        cbk.onWpaConnectionReject(reason, bssid);
    }
}

void OnEventWpsOverlap(char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpsOverlap) {
        cbk.onWpsOverlap(reason, bssid);
    }
}

void OnEventWpsTimeout(char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpsTimeOut) {
        cbk.onWpsTimeOut(reason, bssid);
    }
}

void OnEventScanResult(HdiWpaRecvScanResultParam *recvScanResultParam, char *ifaceName)
{
    // 解析数据

    const OHOS::Wifi::SupplicantEventCallback &cbk =
        OHOS::Wifi::WifiSupplicantHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onScanNotify) {
        cbk.onScanNotify(status);
    }
}
#endif