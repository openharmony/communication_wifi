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

#include "wifi_hal_callback.h"
#include <securec.h>
#include "wifi_log.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_define.h"
#include "wifi_hal_common_func.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalCallback"
#define MAC_OFFSET 1

static void EmitEventCallbackMsg(WifiHalEventCallbackMsg *pCbkMsg, WifiHalEvent event)
{
    if (pCbkMsg == NULL) {
        return;
    }
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    if (PushBackCallbackMsg(event, pCbkMsg) != 0) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    if (EmitEvent(server, event) < 0) {
        PopBackCallbackMsg(event);
        free(pCbkMsg);
        pCbkMsg = NULL;
    }
    return;
}

void WifiHalCbNotifyScanEnd(int status)
{
    LOGI("Get Scan status: %{public}d, and begin push notify message", status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.scanStatus = status;
    EmitEventCallbackMsg(pCbkMsg, WIFI_SCAN_INFO_NOTIFY_EVENT);
    return;
}

void WifiHalCbNotifyConnectChanged(int status, int networkId, const char *pos)
{
    if (pos == NULL) {
        LOGI("Get connect state changed, pos is NULL");
        return;
    }
    LOGI("Get connect state changed, state: %{public}d, networkid = %{public}d", status, networkId);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = status;
    pCbkMsg->msg.connMsg.networkId = networkId;
    StrSafeCopy(pCbkMsg->msg.connMsg.bssid, WIFI_MAC_LENGTH + 1, pos);
    EmitEventCallbackMsg(pCbkMsg, WIFI_CONNECT_CHANGED_NOTIFY_EVENT);
    return;
}

void WifiHalCbNotifyDisConnectReason(int reason, const char *bssid)
{
    if (bssid == NULL) {
        LOGI("Get connect state changed, pos is NULL");
        return;
    }
    LOGI("Get disconnect state changed, reason: %{public}d", reason);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = reason;
    StrSafeCopy(pCbkMsg->msg.connMsg.bssid, WIFI_MAC_LENGTH + 1, bssid);
    EmitEventCallbackMsg(pCbkMsg, WIFI_STA_DISCONNECT_REASON_EVENT);
    return;
}

void WifiHalCbNotifyBssidChanged(const char *reasonPos, const char *bssidPos)
{
    char reason[WIFI_REASON_LENGTH] = {0};
    if (reasonPos == NULL || bssidPos == NULL) {
        LOGE("reasonPos or bssidPos is NULL");
        return;
    }
    char *reasonEnd = strchr(reasonPos, ' ');
    if (reasonEnd != NULL) {
        int reasonLen = reasonEnd - reasonPos;
        reasonLen = reasonLen > WIFI_REASON_LENGTH ? WIFI_REASON_LENGTH : reasonLen;
        if (memcpy_s(reason, sizeof(reason), reasonPos, reasonLen) != EOK) {
            LOGW("failed to copy the reason!");
        }
    }

    LOGI("bssid changed event, reason: %{public}s, bssid = %{private}s", reason, bssidPos);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (memcpy_s(pCbkMsg->msg.bssidChangedMsg.reason, WIFI_REASON_LENGTH, reason, WIFI_REASON_LENGTH) != EOK) {
        LOGW("failed to copy the reason!");
    }
    if (memcpy_s(pCbkMsg->msg.bssidChangedMsg.bssid, WIFI_MAC_LENGTH + 1, bssidPos, WIFI_MAC_LENGTH + 1) != EOK) {
        LOGW("failed to copy the bssid!");
    }
    EmitEventCallbackMsg(pCbkMsg, WIFI_BSSID_CHANGED_NOTIFY_EVENT);
}

void WifiHalCbNotifyWpaStateChange(int status)
{
    LOGI("wpa state changed, state: %{public}d, and begin push notify message", status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = status;
    EmitEventCallbackMsg(pCbkMsg, WIFI_WPA_STATE_EVENT);
    return;
}

void WifiHalCbNotifyWrongKey(int status)
{
    LOGI("wrong key, state: %{public}d, and begin push notify message", status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = status;
    EmitEventCallbackMsg(pCbkMsg, WIFI_SSID_WRONG_KEY);
    return;
}

void WifiHalCbNotifyConnectionFull(int status)
{
    LOGI("connection is full, state: %{public}d, and begin push notify message", status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }

    pCbkMsg->msg.connMsg.status = status;
    EmitEventCallbackMsg(pCbkMsg, WIFI_CONNECTION_FULL_EVENT);
    return;
}

void WifiHalCbNotifyConnectionReject(int status)
{
    LOGI("connection is eeject, state: %{public}d, and begin push notify message", status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }

    pCbkMsg->msg.connMsg.status = status;
    EmitEventCallbackMsg(pCbkMsg, WIFI_CONNECTION_REJECT_EVENT);
    return;
}

void WifiHalCbNotifyWpsOverlap(int event)
{
    LOGI("wps overlap, state: %{public}d, and begin push notify message", event);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = event;
    EmitEventCallbackMsg(pCbkMsg, WIFI_WPS_OVERLAP);
    return;
}

void WifiHalCbNotifyWpsTimeOut(int event)
{
    LOGI("wps time out, state: %{public}d, and begin push notify message", event);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = event;
    EmitEventCallbackMsg(pCbkMsg, WIFI_WPS_TIME_OUT);
    return;
}

void WifiHalCbStaJoin(const char *content, int id)
{
    if (content == NULL) {
        LOGD("Get hostapd Sta join content is NULL");
        return;
    }
    LOGD("Get hostapd Sta join, instance id:%{public}d", id);
    WifiHalEvent event;
    char tmpBuf[WIFI_BSSID_LENGTH] = {0};
    if (strncmp("AP-STA-CONNECTED", content, strlen("AP-STA-CONNECTED")) == 0) {
        event = WIFI_STA_JOIN_EVENT;
        StrSafeCopy(tmpBuf, sizeof(tmpBuf), content + strlen("AP-STA-CONNECTED") + MAC_OFFSET);
    } else if (strncmp("AP-STA-DISCONNECTED", content, strlen("AP-STA-DISCONNECTED")) == 0) {
        event = WIFI_STA_LEAVE_EVENT;
        StrSafeCopy(tmpBuf, sizeof(tmpBuf), content + strlen("AP-STA-DISCONNECTED") + MAC_OFFSET);
    } else {
        return;
    }
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("hostapd create callback message failed!");
        return;
    }
    pCbkMsg->msg.ifMsg.id = id;
    pCbkMsg->msg.ifMsg.type = event;
    StrSafeCopy(pCbkMsg->msg.ifMsg.ifname, sizeof(pCbkMsg->msg.ifMsg.ifname), tmpBuf);
    EmitEventCallbackMsg(pCbkMsg, event);
    return;
}

void WifiHalCbApState(const char *content, int id)
{
    if (content == NULL) {
        LOGD("Get hostapd status changed content is NULL");
        return;
    }
    LOGD("Get hostapd status changed, instance id:%{public}d", id);
    WifiHalEvent event;
    if (strncmp(content, "AP-ENABLED", strlen("AP-ENABLED")) == 0) {
        event = WIFI_AP_ENABLE_EVENT;
    } else if (strncmp(content, "AP-DISABLED", strlen("AP-DISABLED")) == 0 ||
               strncmp(content, "CTRL-EVENT-TERMINATING", strlen("CTRL-EVENT-TERMINATING")) == 0) {
        event = WIFI_AP_DISABLE_EVENT;
    } else if (strncmp(content, "AP-STA-POSSIBLE-PSK-MISMATCH ", strlen("AP-STA-POSSIBLE-PSK-MISMATCH ")) == 0) {
        event = AP_STA_PSK_MISMATH_EVENT;
    } else {
        return;
    }
    
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("hostapd create callback message failed!");
        return;
    }
    pCbkMsg->msg.ifMsg.type = event;
    pCbkMsg->msg.ifMsg.id = id;
    EmitEventCallbackMsg(pCbkMsg, event);
    return;
}

void WifiP2pHalCbNotifyConnectSupplicant(int state)
{
    LOGI("P2p supplicant connect even : %{public}d", state);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.scanStatus = state;
    EmitEventCallbackMsg(pCbkMsg, WIFI_P2P_SUP_CONNECTION_EVENT);
    return;
}

void P2pHalCbDeviceFound(const P2pDeviceInfo *device)
{
    if (device == NULL) {
        return;
    }
    ANONYMIZE_LOGI("P2p device found event deviceName: %{public}s", device->deviceName);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.deviceInfo = *device;
    EmitEventCallbackMsg(pCbkMsg, P2P_DEVICE_FOUND_EVENT);
    return;
}

void P2pHalCbDeviceLost(const char *p2pDeviceAddress)
{
    if (p2pDeviceAddress == NULL) {
        LOGI("P2p device lost event p2pDeviceAddress is NULL");
        return;
    }
    LOGI("P2p device lost event p2pDeviceAddress: %{private}s", p2pDeviceAddress);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.connMsg.bssid, sizeof(pCbkMsg->msg.connMsg.bssid), p2pDeviceAddress,
        sizeof(pCbkMsg->msg.connMsg.bssid) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_DEVICE_LOST_EVENT);
    return;
}

void P2pHalCbGoNegotiationRequest(const char *srcAddress, short passwordId)
{
    if (srcAddress == NULL) {
        LOGI("P2p go negotiation request event srcAddress is NULL");
        return;
    }
    LOGI("P2p go negotiation request event srcAddress: %{private}s, passwordId: %{private}d", srcAddress, passwordId);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = passwordId;
    if (strncpy_s(pCbkMsg->msg.connMsg.bssid, sizeof(pCbkMsg->msg.connMsg.bssid), srcAddress,
        sizeof(pCbkMsg->msg.connMsg.bssid) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_GO_NEGOTIATION_REQUEST_EVENT);
    return;
}

void P2pHalCbGoNegotiationSuccess()
{
    LOGI("P2p go negotiation success event");
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    EmitEvent(server, P2P_GO_NEGOTIATION_SUCCESS_EVENT);
    return;
}

void P2pHalCbGoNegotiationFailure(int status)
{
    LOGI("P2p go negotiation failure event status: %{public}d", status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.scanStatus = status;
    EmitEventCallbackMsg(pCbkMsg, P2P_GO_NEGOTIATION_FAILURE_EVENT);
    return;
}

void P2pHalCbP2pChannelSwitch(int freq)
{
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.serDiscReqInfo.freq = freq;
    EmitEventCallbackMsg(pCbkMsg, P2P_CHANNEL_SWITCH);
    return;
}

void P2pHalCbP2pConnectFailed(const char *bssid, int reason)
{
    if (bssid == NULL) {
        LOGE("P2p connect failed event bssid is NULL");
        return;
    }
    LOGI("P2p connect failed event bssid: %{private}s, reason: %{public}d", bssid, reason);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.connMsg.status = reason;
    if (strncpy_s(pCbkMsg->msg.connMsg.bssid, sizeof(pCbkMsg->msg.connMsg.bssid), bssid,
        sizeof(pCbkMsg->msg.connMsg.bssid) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_CONNECT_FAILED);
    return;
}

void P2pHalCbInvitationReceived(const P2pInvitationInfo *info)
{
    if (info == NULL) {
        return;
    }
    LOGI("P2p invitation received event srcAddress: %{private}s", info->srcAddress);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.invitaInfo = *info;
    EmitEventCallbackMsg(pCbkMsg, P2P_INVITATION_RECEIVED_EVENT);
    return;
}

void P2pHalCbInvitationResult(const char *bssid, int status)
{
    if (bssid == NULL) {
        LOGI("P2p invitation result event bssid is NULL");
        return;
    }
    LOGI("P2p invitation result event bssid: %{private}s, status: %{public}d", bssid, status);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.invitaInfo.persistentNetworkId = status;
    if (strncpy_s(pCbkMsg->msg.invitaInfo.bssid, sizeof(pCbkMsg->msg.invitaInfo.bssid), bssid,
        sizeof(pCbkMsg->msg.invitaInfo.bssid) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_INVITATION_RESULT_EVENT);
    return;
}

void P2pHalCbGroupFormationSuccess()
{
    LOGI("P2p group formation success event");
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    EmitEvent(server, P2P_GROUP_FORMATION_SUCCESS_EVENT);
    return;
}

void P2pHalCbGroupFormationFailure(const char *reason)
{
    if (reason == NULL) {
        LOGI("P2p group formation failure event reason is NULL");
        return;
    }
    LOGW("P2p group formation failure event reason: %{public}s", reason);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.invitaInfo.bssid, sizeof(pCbkMsg->msg.invitaInfo.bssid), reason,
        sizeof(pCbkMsg->msg.invitaInfo.bssid) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_GROUP_FORMATION_FAILURE_EVENT);
    return;
}

void P2pHalCbGroupStarted(const P2pGroupInfo *info)
{
    if (info == NULL) {
        return;
    }
    LOGI("P2p group started event groupIfName: %{public}s", info->groupIfName);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.groupInfo = *info;
    EmitEventCallbackMsg(pCbkMsg, P2P_GROUP_STARTED_EVENT);
    return;
}

void P2pHalCbGroupRemoved(const char *groupIfName, int isGo)
{
    if (groupIfName == NULL) {
        LOGI("P2p group removed event groupIfName is NULL");
        return;
    }
    LOGW("P2p group removed event groupIfName: %{public}s, isGo: %{public}d", groupIfName, isGo);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.groupInfo.isGo = isGo;
    if (strncpy_s(pCbkMsg->msg.groupInfo.groupIfName, sizeof(pCbkMsg->msg.groupInfo.groupIfName), groupIfName,
        sizeof(pCbkMsg->msg.groupInfo.groupIfName) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_GROUP_REMOVED_EVENT);
    return;
}

void P2pHalCbclientRemoved(const char *deviceMac)
{
    if (deviceMac == NULL) {
        LOGI("P2p group removed event deviceMac is NULL");
        return;
    }
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.p2pDeviceAddress, sizeof(pCbkMsg->msg.deviceInfo.p2pDeviceAddress),
        deviceMac, sizeof(pCbkMsg->msg.deviceInfo.p2pDeviceAddress) - 1) != EOK) {
        free(pCbkMsg);
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_CLIENT_REMOVED_EVENT);
    return;
}

void P2pHalCbProvisionDiscoveryPbcRequest(const char *address)
{
    if (address == NULL) {
        LOGI("P2p provision discovery pbc request event address is NULL");
        return;
    }
    LOGI("P2p provision discovery pbc request event address: %{private}s", address);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.srcAddress, sizeof(pCbkMsg->msg.deviceInfo.srcAddress), address,
        sizeof(pCbkMsg->msg.deviceInfo.srcAddress) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_PROV_DISC_PBC_REQ_EVENT);
    return;
}

void P2pHalCbProvisionDiscoveryPbcResponse(const char *address)
{
    if (address == NULL) {
        LOGI("P2p provision discovery pbc response event address is NULL");
        return;
    }
    LOGI("P2p provision discovery pbc response event address: %{private}s", address);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.srcAddress, sizeof(pCbkMsg->msg.deviceInfo.srcAddress), address,
        sizeof(pCbkMsg->msg.deviceInfo.srcAddress) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_PROV_DISC_PBC_RSP_EVENT);
    return;
}

void P2pHalCbProvisionDiscoveryEnterPin(const char *address)
{
    if (address == NULL) {
        LOGI("P2p provision discovery enter pin event address is NULL");
        return;
    }
    LOGI("P2p provision discovery enter pin event address: %{private}s", address);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.srcAddress, sizeof(pCbkMsg->msg.deviceInfo.srcAddress), address,
        sizeof(pCbkMsg->msg.deviceInfo.srcAddress) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_PROV_DISC_ENTER_PIN_EVENT);
    return;
}

void P2pHalCbProvisionDiscoveryShowPin(const char *address, const char *pin)
{
    if (address == NULL || pin == NULL) {
        LOGI("P2p provision discovery show pin event address or pin is NULL");
        return;
    }
    LOGI("P2p provision discovery show pin event address: %{private}s, pin: %{private}s", address, pin);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.srcAddress, sizeof(pCbkMsg->msg.deviceInfo.srcAddress), address,
        sizeof(pCbkMsg->msg.deviceInfo.srcAddress) - 1) != EOK ||
        strncpy_s(pCbkMsg->msg.deviceInfo.deviceName, sizeof(pCbkMsg->msg.deviceInfo.deviceName), pin,
        sizeof(pCbkMsg->msg.deviceInfo.deviceName) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_PROV_DISC_SHOW_PIN_EVENT);
    return;
}

void P2pHalCbProvisionDiscoveryFailure()
{
    LOGW("P2p provision discovery failure event");
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    EmitEvent(server, P2P_PROV_DISC_FAILURE_EVENT);
    return;
}

void P2pHalCbFindStopped()
{
    LOGW("P2p find stopped event");
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    EmitEvent(server, P2P_FIND_STOPPED_EVENT);
    return;
}

void P2pHalCbServiceDiscoveryResponse(const P2pServDiscRespInfo *info)
{
    if (info == NULL) {
        return;
    }
    LOGI("P2p service discovery response event srcAddress: %{private}s", info->srcAddress);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.serverInfo = *info;
    if (info->tlvs != NULL) { // deep copy
        unsigned len = strlen(info->tlvs) + 1;
        if (len == 0) {
            free(pCbkMsg);
            pCbkMsg = NULL;
            return;
        }
        pCbkMsg->msg.serverInfo.tlvs = (char *)calloc(len, sizeof(char));
        if (pCbkMsg->msg.serverInfo.tlvs == NULL) {
            free(pCbkMsg);
            pCbkMsg = NULL;
            return;
        }
        if (strncpy_s(pCbkMsg->msg.serverInfo.tlvs, len, info->tlvs, len - 1) != EOK) {
            free(pCbkMsg->msg.serverInfo.tlvs);
            pCbkMsg->msg.serverInfo.tlvs = NULL;
            free(pCbkMsg);
            pCbkMsg = NULL;
            return;
        }
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_SERV_DISC_RESP_EVENT);
    return;
}

void P2pHalCbStaConnectState(const char *p2pDeviceAddress, const char *p2pGroupAddress, int state)
{
    if (p2pDeviceAddress == NULL) {
        LOGI("P2p sta authorized/deauthorized event devAddress is NULL");
        return;
    }
    LOGI("P2p sta authorized/deauthorized event devAddress: %{private}s", p2pDeviceAddress);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.p2pDeviceAddress, sizeof(pCbkMsg->msg.deviceInfo.p2pDeviceAddress),
        p2pDeviceAddress, sizeof(pCbkMsg->msg.deviceInfo.p2pDeviceAddress) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    if (strncpy_s(pCbkMsg->msg.deviceInfo.p2pGroupAddress, sizeof(pCbkMsg->msg.deviceInfo.p2pGroupAddress),
        p2pGroupAddress, sizeof(pCbkMsg->msg.deviceInfo.p2pGroupAddress) - 1) != EOK) {
        free(pCbkMsg);
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, ((state == 0) ? AP_STA_DISCONNECTED_EVENT : AP_STA_CONNECTED_EVENT));
    return;
}

void P2pHalCbConnectSupplicantFailed()
{
    LOGW("P2p supplicant connect Failed event");
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    EmitEvent(server, SUP_CONN_FAILED_EVENT);
    return;
}

void P2pHalCbServDiscReq(const P2pServDiscReqInfo *info)
{
    LOGI("P2p service discovery request event");
    if (info == NULL) {
        return;
    }
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.serDiscReqInfo = *info;
    if (info->tlvs != NULL) { // deep copy
        unsigned len = strlen(info->tlvs) + 1;
        if (len == 0) {
            free(pCbkMsg);
            pCbkMsg = NULL;
            return;
        }
        pCbkMsg->msg.serDiscReqInfo.tlvs = (char *)calloc(len, sizeof(char));
        if (pCbkMsg->msg.serDiscReqInfo.tlvs == NULL) {
            free(pCbkMsg);
            pCbkMsg = NULL;
            return;
        }
        if (strncpy_s(pCbkMsg->msg.serDiscReqInfo.tlvs, len, info->tlvs, len - 1) != EOK) {
            free(pCbkMsg->msg.serDiscReqInfo.tlvs);
            pCbkMsg->msg.serDiscReqInfo.tlvs = NULL;
            free(pCbkMsg);
            pCbkMsg = NULL;
            return;
        }
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_SERV_DISC_REQ_EVENT);
    return;
}

void P2pHalCbP2pIfaceCreated(const char *ifName, int isGo)
{
    if (ifName == NULL) {
        LOGE("P2p interface created event ifName is NULL");
        return;
    }
    LOGI("P2p interface created event ifName: %{public}s, isGo: %{public}d", ifName, isGo);
    WifiHalEventCallbackMsg *pCbkMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbkMsg == NULL) {
        LOGE("create callback message failed!");
        return;
    }
    pCbkMsg->msg.ifMsg.type = isGo;
    if (strncpy_s(pCbkMsg->msg.ifMsg.ifname, sizeof(pCbkMsg->msg.ifMsg.ifname), ifName,
        sizeof(pCbkMsg->msg.ifMsg.ifname) - 1) != EOK) {
        free(pCbkMsg);
        pCbkMsg = NULL;
        return;
    }
    EmitEventCallbackMsg(pCbkMsg, P2P_IFACE_CREATED_EVENT);
}
