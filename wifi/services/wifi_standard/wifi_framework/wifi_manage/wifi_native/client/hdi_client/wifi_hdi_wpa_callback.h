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

#include "wifi_hdi_wpa_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t OnEventDisconnected(struct IWpaCallback *self,
    const struct HdiWpaDisconnectParam *disconectParam, const char* ifName);
int32_t OnEventConnected(struct IWpaCallback *self,
    const struct HdiWpaConnectParam *connectParam, const char* ifName);
int32_t OnEventBssidChanged(struct IWpaCallback *self,
    const struct HdiWpaBssidChangedParam *bssidChangedParam, const char* ifName);
int32_t OnEventStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char* ifName);
int32_t OnEventTempDisabled(struct IWpaCallback *self,
    const struct HdiWpaTempDisabledParam *tempDisabledParam, const char *ifName);
int32_t OnEventAssociateReject(struct IWpaCallback *self,
    const struct HdiWpaAssociateRejectParam *associateRejectParam, const char *ifName);
int32_t OnEventWpsOverlap(struct IWpaCallback *self, const char *ifName);
int32_t OnEventWpsTimeout(struct IWpaCallback *self, const char *ifName);
int32_t OnEventScanResult(struct IWpaCallback *self,
    const struct HdiWpaRecvScanResultParam *recvScanResultParam, const char* ifName);
int32_t onEventStaJoin(struct IHostapdCallback *self, const struct HdiApCbParm *apCbParm, const char* ifName);
int32_t onEventApState(struct IHostapdCallback *self, const struct HdiApCbParm *apCbParm, const char* ifName);

#ifdef __cplusplus
}
#endif
#endif
#endif