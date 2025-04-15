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

#ifndef OHOS_HDI_WLAN_WPA_V1_2_IWPACALLBACK_H
#define OHOS_HDI_WLAN_WPA_V1_2_IWPACALLBACK_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>
#include "wlan/wpa/v2_0/wpa_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfRemoteService;

#define IWPACALLBACK_INTERFACE_DESC "ohos.hdi.wlan.wpa.v2_0.IWpaCallback"

#define IWPA_CALLBACK_MAJOR_VERSION 1
#define IWPA_CALLBACK_MINOR_VERSION 2

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

#ifndef HDI_CHECK_VALUE_RETURN
#define HDI_CHECK_VALUE_RETURN(lv, compare, rv, ret) do { \
    if ((lv) compare (rv)) { \
        return ret; \
    } \
} while (false)
#endif

#ifndef HDI_CHECK_VALUE_RET_GOTO
#define HDI_CHECK_VALUE_RET_GOTO(lv, compare, rv, ret, value, table) do { \
    if ((lv) compare (rv)) { \
        ret = value; \
        goto table; \
    } \
} while (false)
#endif

enum {
    CMD_WPA_CALLBACK_GET_VERSION = 0,
    CMD_WPA_CALLBACK_ON_EVENT_DISCONNECTED = 1,
    CMD_WPA_CALLBACK_ON_EVENT_CONNECTED = 2,
    CMD_WPA_CALLBACK_ON_EVENT_BSSID_CHANGED = 3,
    CMD_WPA_CALLBACK_ON_EVENT_STATE_CHANGED = 4,
    CMD_WPA_CALLBACK_ON_EVENT_TEMP_DISABLED = 5,
    CMD_WPA_CALLBACK_ON_EVENT_ASSOCIATE_REJECT = 6,
    CMD_WPA_CALLBACK_ON_EVENT_WPS_OVERLAP = 7,
    CMD_WPA_CALLBACK_ON_EVENT_WPS_TIMEOUT = 8,
    CMD_WPA_CALLBACK_ON_EVENT_SCAN_RESULT = 9,
    CMD_WPA_CALLBACK_ON_EVENT_DEVICE_FOUND = 10,
    CMD_WPA_CALLBACK_ON_EVENT_DEVICE_LOST = 11,
    CMD_WPA_CALLBACK_ON_EVENT_GO_NEGOTIATION_REQUEST = 12,
    CMD_WPA_CALLBACK_ON_EVENT_GO_NEGOTIATION_COMPLETED = 13,
    CMD_WPA_CALLBACK_ON_EVENT_INVITATION_RECEIVED = 14,
    CMD_WPA_CALLBACK_ON_EVENT_INVITATION_RESULT = 15,
    CMD_WPA_CALLBACK_ON_EVENT_GROUP_FORMATION_SUCCESS = 16,
    CMD_WPA_CALLBACK_ON_EVENT_GROUP_FORMATION_FAILURE = 17,
    CMD_WPA_CALLBACK_ON_EVENT_GROUP_STARTED = 18,
    CMD_WPA_CALLBACK_ON_EVENT_GROUP_REMOVED = 19,
    CMD_WPA_CALLBACK_ON_EVENT_PROVISION_DISCOVERY_COMPLETED = 20,
    CMD_WPA_CALLBACK_ON_EVENT_FIND_STOPPED = 21,
    CMD_WPA_CALLBACK_ON_EVENT_SERV_DISC_REQ = 22,
    CMD_WPA_CALLBACK_ON_EVENT_SERV_DISC_RESP = 23,
    CMD_WPA_CALLBACK_ON_EVENT_STA_CONNECT_STATE = 24,
    CMD_WPA_CALLBACK_ON_EVENT_IFACE_CREATED = 25,
    CMD_WPA_CALLBACK_ON_EVENT_AUTH_REJECT = 26,
    CMD_WPA_CALLBACK_ON_EVENT_STA_NOTIFY = 27,
    CMD_WPA_CALLBACK_ON_EVENT_VENDOR_CB = 28,
    CMD_WPA_CALLBACK_ON_EVENT_GROUP_INFO_STARTED = 29,
    CMD_WPA_CALLBACK_ON_EVENT_AUTH_TIMEOUT = 30,
};

struct IWpaCallback {
    int32_t (*OnEventDisconnected)(struct IWpaCallback *self, const struct HdiWpaDisconnectParam* disconnectParam,
         const char* ifName);

    int32_t (*OnEventConnected)(struct IWpaCallback *self, const struct HdiWpaConnectParam* connectParam,
         const char* ifName);

    int32_t (*OnEventBssidChanged)(struct IWpaCallback *self, const struct HdiWpaBssidChangedParam* bssidChangedParam,
         const char* ifName);

    int32_t (*OnEventStateChanged)(struct IWpaCallback *self, const struct HdiWpaStateChangedParam* statechangedParam,
         const char* ifName);

    int32_t (*OnEventTempDisabled)(struct IWpaCallback *self, const struct HdiWpaTempDisabledParam* tempDisabledParam,
         const char* ifName);

    int32_t (*OnEventAssociateReject)(struct IWpaCallback *self,
         const struct HdiWpaAssociateRejectParam* associateRejectParam, const char* ifName);

    int32_t (*OnEventWpsOverlap)(struct IWpaCallback *self, const char* ifName);

    int32_t (*OnEventWpsTimeout)(struct IWpaCallback *self, const char* ifName);

    int32_t (*OnEventScanResult)(struct IWpaCallback *self, const struct HdiWpaRecvScanResultParam* recvScanResultParam,
         const char* ifName);

    int32_t (*OnEventDeviceFound)(struct IWpaCallback *self, const struct HdiP2pDeviceInfoParam* deviceInfoParam,
         const char* ifName);

    int32_t (*OnEventDeviceLost)(struct IWpaCallback *self, const struct HdiP2pDeviceLostParam* deviceLostParam,
         const char* ifName);

    int32_t (*OnEventGoNegotiationRequest)(struct IWpaCallback *self,
         const struct HdiP2pGoNegotiationRequestParam* goNegotiationRequestParam, const char* ifName);

    int32_t (*OnEventGoNegotiationCompleted)(struct IWpaCallback *self,
         const struct HdiP2pGoNegotiationCompletedParam* goNegotiationCompletedParam, const char* ifName);

    int32_t (*OnEventInvitationReceived)(struct IWpaCallback *self,
         const struct HdiP2pInvitationReceivedParam* invitationReceivedParam, const char* ifName);

    int32_t (*OnEventInvitationResult)(struct IWpaCallback *self,
         const struct HdiP2pInvitationResultParam* invitationResultParam, const char* ifName);

    int32_t (*OnEventGroupFormationSuccess)(struct IWpaCallback *self, const char* ifName);

    int32_t (*OnEventGroupFormationFailure)(struct IWpaCallback *self, const char* reason, const char* ifName);

    int32_t (*OnEventGroupStarted)(struct IWpaCallback *self, const struct HdiP2pGroupStartedParam* groupStartedParam,
         const char* ifName);

    int32_t (*OnEventGroupRemoved)(struct IWpaCallback *self, const struct HdiP2pGroupRemovedParam* groupRemovedParam,
         const char* ifName);

    int32_t (*OnEventProvisionDiscoveryCompleted)(struct IWpaCallback *self,
         const struct HdiP2pProvisionDiscoveryCompletedParam* provisionDiscoveryCompletedParam, const char* ifName);

    int32_t (*OnEventFindStopped)(struct IWpaCallback *self, const char* ifName);

    int32_t (*OnEventServDiscReq)(struct IWpaCallback *self,
         const struct HdiP2pServDiscReqInfoParam* servDiscReqInfoParam, const char* ifName);

    int32_t (*OnEventServDiscResp)(struct IWpaCallback *self, const struct HdiP2pServDiscRespParam* servDiscRespParam,
         const char* ifName);

    int32_t (*OnEventStaConnectState)(struct IWpaCallback *self,
         const struct HdiP2pStaConnectStateParam* staConnectStateParam, const char* ifName);

    int32_t (*OnEventIfaceCreated)(struct IWpaCallback *self, const struct HdiP2pIfaceCreatedParam* ifaceCreatedParam,
         const char* ifName);

    int32_t (*OnEventAuthReject)(struct IWpaCallback *self, const struct HdiWpaAuthRejectParam* authRejectParam,
         const char* ifName);

    int32_t (*OnEventStaNotify)(struct IWpaCallback *self, const char* notifyParam, const char* ifName);

    int32_t (*OnEventVendorCb)(struct IWpaCallback *self, const struct WpaVendorInfo* wpaVendorInfo,
         const char* ifName);

    int32_t (*OnEventGroupInfoStarted)(struct IWpaCallback *self,
         const struct HdiP2pGroupInfoStartedParam* groupStartedParam, const char* ifName);

    int32_t (*OnEventAuthTimeout)(struct IWpaCallback *self, const char* ifName);

    int32_t (*GetVersion)(struct IWpaCallback *self, uint32_t* majorVer, uint32_t* minorVer);

    struct HdfRemoteService* (*AsObject)(struct IWpaCallback *self);
};

// no external method used to create client object, it only support ipc mode
struct IWpaCallback *IWpaCallbackGet(struct HdfRemoteService *remote);

// external method used to release client object, it support ipc and passthrought mode
void IWpaCallbackRelease(struct IWpaCallback *instance);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_WLAN_WPA_V1_1_IWPACALLBACK_H