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

#include "i_wifi.h"
#include "client.h" /*/ RPC client.h */
#include "serial.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "wifi_idl_inner_interface.h"
#include "i_wifi_chip.h"
#include "i_wifi_chip_event_callback.h"
#include "i_wifi_event_callback.h"
#include "i_wifi_hotspot_iface.h"
#include "i_wifi_sta_iface.h"
#include "i_wifi_supplicant_iface.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_I_WIFI"
#define IDL_CONN_BSSID_LEN 32
#define IFACE_NAME_LENGTH 16

WifiErrorNo GetWifiChip(uint8_t id, IWifiChip *chip)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetWifiChip");
    WriteInt(context, id);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server GetWifiChip deal failed!");
    } else {
        /* read IWifiChip struct */
        ReadInt(context, &(chip->i));
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetWifiChipIds(uint8_t *ids, int32_t *size)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetWifiChipIds");
    WriteInt(context, *size);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server GetWifiChipIds deal failed!");
    } else {
        ReadInt(context, size);
        for (int i = 0; i < *size; ++i) {
            ReadInt(context, (int *)(ids + i));
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo Start(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "Start");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo Stop(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "Stop");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo NotifyClear(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "NotifyClear");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

/* Defines the callback processing function. */
static int IdlCbkAddRemoveIface(Context *context, int event)
{
    int type = 0;
    if (ReadInt(context, &type) < 0) {
        return -1;
    }
    char iface[IFACE_NAME_LENGTH] = {0};
    if (ReadStr(context, iface, sizeof(iface)) != 0) {
        return -1;
    }
    IWifiChipEventCallback *callback = GetWifiChipEventCallback();
    if (event == WIFI_IDL_CBK_CMD_ADD_IFACE && callback->onIfaceAdded != NULL) {
        callback->onIfaceAdded(type, iface);
    } else if (event == WIFI_IDL_CBK_CMD_REMOVE_IFACE && callback->onIfaceRemoved != NULL) {
        callback->onIfaceRemoved(type, iface);
    }
    return 0;
}

static int IdlCbkStaJoinLeave(Context *context)
{
    CStationInfo info = {0};
    if (ReadInt(context, &info.type) < 0) {
        return -1;
    }
    int len = ReadStr(context, NULL, 0);
    if (len < 0) {
        return -1;
    }
    char *reason = (char *)calloc(len + 1, sizeof(char));
    if (reason == NULL) {
        return -1;
    }
    if (ReadStr(context, reason, len + 1) < 0) {
        free(reason);
        return -1;
    }
    if (strncpy_s(info.mac, sizeof(info.mac), reason, sizeof(info.mac) - 1) != EOK) {
        free(reason);
        return -1;
    }
    IWifiApEventCallback *callback = GetWifiApEventCallback();
    if (callback->onStaJoinOrLeave != NULL) {
        callback->onStaJoinOrLeave(&info);
    }
    free(reason);
    return 0;
}

static int IdlCbkScanResultNotify(Context *context)
{
    int result = 0;
    if (ReadInt(context, &result) < 0) {
        return -1;
    }
    ISupplicantEventCallback *callback = GetSupplicantEventCallback();
    if (callback->onScanNotify != NULL) {
        callback->onScanNotify(result, callback->pInstance);
    }
    return 0;
}

static int IdlCbkConnectChanged(Context *context)
{
    int status = 0;
    if (ReadInt(context, &status) < 0) {
        return -1;
    }
    int networkId = 0;
    if (ReadInt(context, &networkId) < 0) {
        return -1;
    }
    char pMac[IDL_CONN_BSSID_LEN] = {0};
    if (ReadStr(context, pMac, IDL_CONN_BSSID_LEN) < 0) {
        return -1;
    }
    IWifiEventCallback *callback = GetWifiEventCallback();
    if (callback->onConnectChanged != NULL) {
        callback->onConnectChanged(status, networkId, pMac, callback->pInstance);
    }
    return 0;
}

static int IdlCbkApStateChange(int event)
{
    IWifiApEventCallback *callback = GetWifiApEventCallback();
    if (callback->onApEnableOrDisable != NULL) {
        callback->onApEnableOrDisable(event);
    }
    return 0;
}

static int IdlCbkWpaEventDeal(Context *context, int event)
{
    int status = 0;
    if (ReadInt(context, &status) < 0) {
        return -1;
    }
    IWifiEventCallback *callback = GetWifiEventCallback();
    if (event == WIFI_IDL_CBK_CMD_WPS_TIME_OUT && callback->onWpsTimeOut != NULL) {
        callback->onWpsTimeOut(status, callback->pInstance);
    }
    if (event == WIFI_IDL_CBK_CMD_WPS_OVERLAP && callback->onWpsOverlap != NULL) {
        callback->onWpsOverlap(status, callback->pInstance);
    }
    if (event == WIFI_IDL_CBK_CMD_SSID_WRONG_KEY && callback->onSsidWrongkey != NULL) {
        callback->onSsidWrongkey(status, callback->pInstance);
    }
    if (event == WIFI_IDL_CBK_CMD_WPA_STATE_CHANGEM && callback->onWpaStateChanged != NULL) {
        callback->onWpaStateChanged(status, callback->pInstance);
    }
    return 0;
}

int OnTransact(Context *context)
{
    int event = 0;
    if (ReadInt(context, &event) < 0) {
        return -1;
    }
    switch (event) {
        case WIFI_IDL_CBK_CMD_FAILURE: {
            break;
        }
        case WIFI_IDL_CBK_CMD_STARTED: {
            break;
        }
        case WIFI_IDL_CBK_CMD_STOPED: {
            break;
        }
        case WIFI_IDL_CBK_CMD_ADD_IFACE:
        case WIFI_IDL_CBK_CMD_REMOVE_IFACE: {
            return IdlCbkAddRemoveIface(context, event);
        }
        case WIFI_IDL_CBK_CMD_STA_JOIN:
        case WIFI_IDL_CBK_CMD_STA_LEAVE: {
            return IdlCbkStaJoinLeave(context);
        }
        case WIFI_IDL_CBK_CMD_SCAN_RESULT_NOTIFY: {
            return IdlCbkScanResultNotify(context);
        }
        case WIFI_IDL_CBK_CMD_CONNECT_CHANGED: {
            return IdlCbkConnectChanged(context);
        }
        case WIFI_IDL_CBK_CMD_AP_ENABLE:
        case WIFI_IDL_CBK_CMD_AP_DISABLE: {
            return IdlCbkApStateChange(event);
        }
        case WIFI_IDL_CBK_CMD_WPA_STATE_CHANGEM:
        case WIFI_IDL_CBK_CMD_SSID_WRONG_KEY:
        case WIFI_IDL_CBK_CMD_WPS_OVERLAP:
        case WIFI_IDL_CBK_CMD_WPS_TIME_OUT: {
            return IdlCbkWpaEventDeal(context, event);
        }
        default: {
            LOGI("unsupport call back events: %{public}d", event);
            break;
        }
    }
    return 0;
}
