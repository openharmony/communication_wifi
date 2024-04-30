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
typedef unsigned char u8;

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
int32_t OnEventStaNotify(struct IWpaCallback *self, const char *notifyParam, const char *ifName);
int32_t OnEventWpsOverlap(struct IWpaCallback *self, const char *ifName);
int32_t OnEventWpsTimeout(struct IWpaCallback *self, const char *ifName);
int32_t OnEventScanResult(struct IWpaCallback *self,
    const struct HdiWpaRecvScanResultParam *recvScanResultParam, const char* ifName);
int32_t onEventStaJoin(struct IHostapdCallback *self, const struct HdiApCbParm *apCbParm, const char* ifName);
int32_t onEventApState(struct IHostapdCallback *self, const struct HdiApCbParm *apCbParm, const char* ifName);
int32_t OnEventP2pStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char* ifName);
int32_t OnEventDeviceFound(struct IWpaCallback *self,
    const struct HdiP2pDeviceInfoParam *deviceInfoParam, const char* ifName);
int32_t OnEventDeviceLost(struct IWpaCallback *self,
    const struct HdiP2pDeviceLostParam *deviceLostParam, const char* ifName);
int32_t OnEventGoNegotiationRequest(struct IWpaCallback *self,
    const struct HdiP2pGoNegotiationRequestParam *goNegotiationRequestParam, const char* ifName);
int32_t OnEventGoNegotiationCompleted(struct IWpaCallback *self,
    const struct HdiP2pGoNegotiationCompletedParam *goNegotiationCompletedParam, const char* ifName);
int32_t OnEventInvitationReceived(struct IWpaCallback *self,
    const struct HdiP2pInvitationReceivedParam *invitationReceivedParam, const char *ifName);
int32_t OnEventInvitationResult(struct IWpaCallback *self,
    const struct HdiP2pInvitationResultParam *invitationResultParam, const char *ifName);
int32_t OnEventGroupFormationSuccess(struct IWpaCallback *self, const char *ifName);
int32_t OnEventGroupFormationFailure(struct IWpaCallback *self, const char *reason, const char *ifName);
int32_t OnEventGroupStarted(struct IWpaCallback *self,
    const struct HdiP2pGroupStartedParam *groupStartedParam, const char* ifName);
int32_t OnEventGroupRemoved(struct IWpaCallback *self,
    const struct HdiP2pGroupRemovedParam *groupRemovedParam, const char* ifName);
int32_t OnEventProvisionDiscoveryCompleted(struct IWpaCallback *self,
    const struct HdiP2pProvisionDiscoveryCompletedParam *provisionDiscoveryCompletedParam, const char* ifName);
int32_t OnEventFindStopped(struct IWpaCallback *self, const char* ifName);
int32_t OnEventServDiscReq(struct IWpaCallback *self,
    const struct HdiP2pServDiscReqInfoParam *servDiscReqInfoParam, const char* ifName);
int32_t OnEventServDiscResp(struct IWpaCallback *self,
    const struct HdiP2pServDiscRespParam *servDiscRespParam, const char* ifName);
int32_t OnEventStaConnectState(struct IWpaCallback *self,
    const struct HdiP2pStaConnectStateParam *staConnectStateParam, const char* ifName);
int32_t OnEventIfaceCreated(struct IWpaCallback *self,
    const struct HdiP2pIfaceCreatedParam *ifaceCreatedParam, const char* ifName);

size_t PrintfDecode(u8 *buf, size_t maxlen, const char *str);
#ifdef __cplusplus
}
#endif
#endif
#endif