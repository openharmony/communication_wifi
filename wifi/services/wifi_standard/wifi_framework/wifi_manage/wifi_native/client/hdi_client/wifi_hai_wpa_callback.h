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
#ifndef OHOS_WIFI_HDI_WPA_CALLBACK_H
#define OHOS_WIFI_HDI_WPA_CALLBACK_H

#inclide "wifi_hdi_wpa_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IWifiHdiWpaCallback {
    void (*OnEventDisconnected)(HdiWpaDisconnectParam *disconnectParam, char *ifaceName);
    void (*OnEventConnected)(HdiWpaConnectParam *connectParam, char *ifaceName);
    void (*OnEventBssidChanged)(HdiWpaBssidChangedParam *bssidChangedParam, char *ifaceName);
    void (*OnEventStateChanged)(HdiWpaStateChangedParam *stateChangedParam, char *ifaceName);
    void (*OnEventTempDisabled)(HdiWpaTempDisabledParam *tempDisabledParam, char *ifaceName);
    void (*OnEventAssociateReject)(HdiWpaAssociateRejectParam *associateRejectParam, char *ifaceName);
    void (*OnEventWpsOverlap)(char *ifaceName);
    void (*OnEventWpsTimeout)(char *ifaceName);
    void (*OnEventScanResult)(HdiWpaRecvScanResultParam *recvScanResultParam, char *ifaceName);
} IWifiHdiWpaCallback;

void OnEventDisconnected(HdiWpaDisconnectParam *disconnectParam, char *ifaceName);
void OnEventConnected(HdiWpaConnectParam *connectParam, char *ifaceName);
void OnEventBssidChanged(HdiWpaBssidChangedParam *bssidChangedParam, char *ifaceName);
void OnEventStateChanged(HdiWpaStateChangedParam *stateChangedParam, char *ifaceName);
void OnEventTempDisabled(HdiWpaTempDisabledParam *tempDisabledParam, char *ifaceName);
void OnEventAssociateReject(HdiWpaAssociateRejectParam *associateRejectParam, char *ifaceName);
void OnEventWpsOverlap(char *ifaceName);
void OnEventWpsTimeout(char *ifaceName);
void OnEventScanResult(HdiWpaRecvScanResultParam *recvScanResultParam, char *ifaceName);

#ifdef __cplusplus
}
#endif
#endif
#endif