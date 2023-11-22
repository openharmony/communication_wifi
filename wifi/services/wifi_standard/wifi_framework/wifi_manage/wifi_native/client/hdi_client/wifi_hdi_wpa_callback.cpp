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

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaCallback"

int32_t OnEventDisconnected(struct IWpaCallback *self,
    const struct HdiWpaDisconnectParam *disconectParam, const char* ifName)
{
    if (disconectParam == NULL) {
        LOGE("OnEventDisconnected: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(WPA_CB_DISCONNECTED, disconectParam->reasonCode, (const char *)disconectParam->bssid);
    }
    return 0;
}

int32_t OnEventConnected(struct IWpaCallback *self,
    const struct HdiWpaConnectParam *connectParam, const char* ifName)
{
    if (connectParam == NULL) {
        LOGE("OnEventConnected: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(WPA_CB_CONNECTED, connectParam->networkId, (const char *)connectParam->bssid);
    }
    return 0;
}

int32_t OnEventBssidChanged(struct IWpaCallback *self,
    const struct HdiWpaBssidChangedParam *bssidChangedParam, const char* ifName)
{
    if (bssidChangedParam == NULL) {
        LOGE("OnEventBssidChanged: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onBssidChanged) {
        cbk.onBssidChanged((const char *)bssidChangedParam->reason, (const char *)bssidChangedParam->bssid);
    }
    return 0;
}

int32_t OnEventStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char* ifName)
{
    if (statechangedParam == NULL) {
        LOGE("OnEventStateChanged: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaStateChanged) {
        cbk.onWpaStateChanged(statechangedParam->status);
    }
    return 0;
}

int32_t OnEventTempDisabled(struct IWpaCallback *self,
    const struct HdiWpaTempDisabledParam *tempDisabledParam, const char *ifName)
{
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaSsidWrongKey) {
        cbk.onWpaSsidWrongKey(1);
    }
    return 0;
}

int32_t OnEventAssociateReject(struct IWpaCallback *self,
    const struct HdiWpaAssociateRejectParam *associateRejectParam, const char *ifName)
{
    if (associateRejectParam == NULL) {
        LOGE("OnEventAssociateReject: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaConnectionReject) {
        cbk.onWpaConnectionReject(associateRejectParam->statusCode);
    }
    return 0;
}

int32_t OnEventWpsOverlap(struct IWpaCallback *self, const char *ifName)
{
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpsOverlap) {
        cbk.onWpsOverlap(1);
    }
    return 0;
}

int32_t OnEventWpsTimeout(struct IWpaCallback *self, const char *ifName)
{
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpsTimeOut) {
        cbk.onWpsTimeOut(1);
    }
    return 0;
}

int32_t OnEventScanResult(struct IWpaCallback *self,
    const struct HdiWpaRecvScanResultParam *recvScanResultParam, const char* ifName)
{
    if (recvScanResultParam == NULL) {
        LOGE("OnEventScanResult: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::SupplicantEventCallback &cbk =
        OHOS::Wifi::WifiSupplicantHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onScanNotify) {
        cbk.onScanNotify(SINGLE_SCAN_OVER_OK);
    }
    return 0;
}
#endif