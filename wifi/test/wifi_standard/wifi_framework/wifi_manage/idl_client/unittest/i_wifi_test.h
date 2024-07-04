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

#ifndef OHOS_IDL_IWIFI_TEST_H
#define OHOS_IDL_IWIFI_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

void IdlCbkAddRemoveIface(Context *context, int event);
void IdlCbkStaJoinLeave(Context *context);
void IdlCbkScanInfoNotify(Context *context);
void IdlCbkConnectChanged(Context *context);
void IdlCbkDisConnectReasonNotify(Context *context);
void IdlCbkBssidChanged(Context *context);
void IdlCbkApStateChange(Context *context, int event);
void IdlCbkWpaEventDeal(Context *context, int event);
int IdlDealStaApEvent(Context *context, int event);
void IdlCbP2pEventDeal(Context *context);
void IdlCbP2pSupConnFailedEvent();
void IdlCbP2pDeviceFoundEventDeal(Context *context);
void IdlCbP2pDeviceLostEventDeal(Context *context);
void IdlCbP2pGoNegotiationRequestEvent(Context *context);
void IdlCbP2pGoNegotiationSuccessEvent();
void IdlCbP2pGoNegotiationFailureEvent(Context *context);
void IdlCbP2pInvitationReceivedEvent(Context *context);
void IdlCbP2pInvitationResultEvent(Context *context);
void IdlCbP2pGroupFormationSuccessEvent();
void IdlCbP2pGroupFormationFailureEvent(Context *context);
void IdlCbP2pGroupStartedEvent(Context *context);
void IdlCbP2pGroupRemovedEvent(Context *context);
void IdlCbP2pProvDiscEvent(Context *context, int event);
void IdlCbP2pProDiscShowPinEvent(Context *context);
void IdlCbP2pFindStopEvent();
void IdlCbP2pServDiscRespEvent(Context *context);
void IdlCbP2pProvServDiscFailureEvent();
void IdlCbP2pApStaConnectEvent(Context *context, int event);
void IdlCbP2pServDiscReqEvent(Context *context);
void IdlCbP2pIfaceCreatedEvent(Context *context);
void IdlCbP2pConnectFailedEvent(Context *context);
void IdlCbP2pChannelSwitchEvent(Context *context);
int IdlDealP2pEventFirst(Context *context, int event);
int IdlDealP2pEventSecond(Context *context, int event);
int IdlDealP2pEvent(Context *context, int event);

#ifdef __cplusplus
}
#endif

#endif