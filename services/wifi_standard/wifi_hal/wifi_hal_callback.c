/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "wifi_log.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_define.h"
#include "wifi_hal_common_func.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalCallback"

void WifiHalCbNotifyScanEnd(int status)
{
    LOGI("Get Scan result: %{public}d, and begin push notify message", status);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("create callback message failed!");
        return;
    }
    pCBTest->msg.scanResult = status;
    if (PushBackCallbackMsg(WIFI_SCAN_RESULT_NOTIFY_EVENT, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, WIFI_SCAN_RESULT_NOTIFY_EVENT) < 0) {
        PopBackCallbackMsg(WIFI_SCAN_RESULT_NOTIFY_EVENT);
        free(pCBTest);
    }
    return;
}

void WifiHalCbNotifyConnectChanged(int status, int networkId, const char *pos)
{
    LOGI("connect state changed, state: %{public}d, networkid = %{public}d,", status, networkId);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("create callback message failed!");
        return;
    }
    pCBTest->msg.connMsg.status = status;
    pCBTest->msg.connMsg.networkId = networkId;
    MySafeCopy(pCBTest->msg.connMsg.bssid, sizeof(pCBTest->msg.connMsg.bssid), pos);
    if (PushBackCallbackMsg(WIFI_CONNECT_CHANGED_NOTIFY_EVENT, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, WIFI_CONNECT_CHANGED_NOTIFY_EVENT) < 0) {
        PopBackCallbackMsg(WIFI_CONNECT_CHANGED_NOTIFY_EVENT);
        free(pCBTest);
    }
    return;
}
void WifiHalCbNotifyWpaStateChange(int status)
{
    LOGI("wpa state changed, state: %{public}d, and begin push notify message", status);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("create callback message failed!");
        return;
    }
    pCBTest->msg.scanResult = status;
    if (PushBackCallbackMsg(WIFI_WPA_STATE_EVENT, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, WIFI_WPA_STATE_EVENT) < 0) {
        PopBackCallbackMsg(WIFI_WPA_STATE_EVENT);
        free(pCBTest);
    }
    return;
}

void WifiHalCbNotifyWrongKey(int status)
{
    LOGI("wrong key, state: %{public}d, and begin push notify message", status);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("create callback message failed!");
        return;
    }
    pCBTest->msg.scanResult = status;
    if (PushBackCallbackMsg(WIFI_SSID_WRONG_KEY, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, WIFI_SSID_WRONG_KEY) < 0) {
        PopBackCallbackMsg(WIFI_SSID_WRONG_KEY);
        free(pCBTest);
    }
    return;
}
void WifiHalCbNotifyWpsOverlap(int event)
{
    LOGI("wps overlap, state: %{public}d, and begin push notify message", event);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server has exists!");
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("create callback message failed!");
        return;
    }
    pCBTest->msg.scanResult = event;
    if (PushBackCallbackMsg(WIFI_WPS_OVERLAP, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, WIFI_WPS_OVERLAP) < 0) {
        PopBackCallbackMsg(WIFI_WPS_OVERLAP);
        free(pCBTest);
    }
    return;
}

void WifiHalCbNotifyWpsTimeOut(int event)
{
    LOGI("wps time out, state: %{public}d, and begin push notify message", event);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server has exists!");
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("create callback message failed!");
        return;
    }
    pCBTest->msg.scanResult = event;
    if (PushBackCallbackMsg(WIFI_WPS_TIME_OUT, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, WIFI_WPS_TIME_OUT) < 0) {
        PopBackCallbackMsg(WIFI_WPS_TIME_OUT);
        free(pCBTest);
    }
    return;
}

void WifiHalCbSTAJoin(const char *content)
{
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    WifiHalEvent event;
    char tmpBuf[128] = "";
    if (strncmp("AP-STA-CONNECTED", content, strlen("AP-STA-CONNECTED")) == 0) {
        event = WIFI_STA_JOIN_EVENT;
        MySafeCopy(tmpBuf, sizeof(tmpBuf), content + strlen("AP-STA-CONNECTED") + 1);
    } else if (strncmp("AP-STA-DISCONNECTED", content, strlen("AP-STA-DISCONNECTED")) == 0) {
        event = WIFI_STA_LEAVE_EVENT;
        MySafeCopy(tmpBuf, sizeof(tmpBuf), content + strlen("AP-STA-DISCONNECTED") + 1);
    } else {
        return;
    }
    WifiHalEventCallbackMsg *pCBTest = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCBTest == NULL) {
        LOGD("hostapd create callback message failed!");
        return;
    }
    pCBTest->msg.ifMsg.type = event;
    MySafeCopy(pCBTest->msg.ifMsg.ifname, sizeof(pCBTest->msg.ifMsg.ifname), tmpBuf);
    if (PushBackCallbackMsg(event, pCBTest) != 0) {
        free(pCBTest);
        return;
    }
    if (EmitEvent(server, event) < 0) {
        PopBackCallbackMsg(event);
        free(pCBTest);
    }
    return;
}

void WifiHalCbAPState(const char *content)
{
    LOGI("Get hostapd AP State: %s", content);
    RpcServer *server = GetRpcServer();
    if (server == NULL) {
        LOGE("Rpc server not exists!");
        return;
    }
    WifiHalEvent event;
    if (strncmp(content, "AP-ENABLED", strlen("AP-ENABLED")) == 0) {
        event = WIFI_AP_ENABLE_EVENT;
    } else if (strncmp(content, "AP-DISABLED", strlen("AP-DISABLED")) == 0 ||
               strncmp(content, "CTRL-EVENT-TERMINATING", strlen("CTRL-EVENT-TERMINATING")) == 0) {
        event = WIFI_AP_DISABLE_EVENT;
    } else {
        return;
    }
    EmitEvent(server, event);
    return;
}
