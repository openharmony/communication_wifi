/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include "securec.h"
#include "wifi_common_hal.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_log.h"
#include "wifi_wpa_common.h"
#include "wifi_hal_common_func.h"

#undef LOG_TAG
#define LOG_TAG "WifiCommonHal"

WifiWpaChbaInterface *g_wpaChbaInterface = NULL;

#define WPA_CMD_BUF_LEN 400
#define WPA_CMD_REPLY_BUF_SMALL_LEN 64

int SendComCmd(const char* sendcmd)
{
    if (sendcmd == NULL) {
        return -1;
    }
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    char cmd[WPA_CMD_BUF_LEN] = {0};

    int ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", sendcmd);
    if (ret < 0) {
        LOGE("snprint err is %d", ret);
        return -1;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        LOGE("WpaCliCmd err");
        return -1;
    }
    size_t bufLen = strlen(buf);
    if (strncmp(cmd, "IFNAME=chba0 STATUS", strlen("IFNAME=chba0 STATUS")) == 0) {
        for (int i = 0; i < bufLen; i++) {
            buf[i] = buf[i] == '\n' ? '*' : buf[i];
        }
        char *sep = "*";
        char *retbuf = strtok(buf, sep);
        retbuf = strtok(NULL, sep);
        HalCallbackNotify(retbuf);
    }
    return 0;
}

static void HalEmitEventCallbackMsg(WifiHalEventCallbackMsg *pCbkMsg, WifiHalEvent event)
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

int HalCallbackNotify(const char* event)
{
    if (event == NULL) {
        LOGE("recv notify message is null");
        return -1;
    }
    WifiHalEventCallbackMsg *pCbMsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    if (pCbMsg == NULL) {
        LOGE("create callback message failed!");
        return -1;
    }
    strcpy_s(pCbMsg->msg.commsg.event, sizeof(pCbMsg->msg.commsg.event), event);
    HalEmitEventCallbackMsg(pCbMsg, WIFI_HAL_COMMON_EVENT);
    return 0;
}

WifiWpaChbaInterface *GetWifiWpaChbaInterface()
{
    if(g_wpaChbaInterface != NULL) {
        return g_wpaChbaInterface;
    }
    g_wpaChbaInterface = (WifiWpaChbaInterface *)calloc(1, sizeof(WifiWpaChbaInterface));
    if (g_wpaChbaInterface == NULL) {
        LOGE("alloc memory for chba interface failed!");
        return NULL;
    }
    strcpy_s(g_wpaChbaInterface->ifname, sizeof(g_wpaChbaInterface->ifname), "chba0");
    return g_wpaChbaInterface;
}

void ReleaseWpaChbaInterface(void)
{
    if (g_wpaChbaInterface != NULL) {
        free(g_wpaChbaInterface);
        g_wpaChbaInterface = NULL;
    }
}
