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

#include "i_wifi_hotspot_iface.h"
#include <stddef.h>
#include "client.h"
#include "context.h"
#include "i_wifi_public_func.h"
#include "serial.h"
#include "wifi_idl_inner_interface.h"
#include "wifi_log.h"
#include "wifi_native_define.h"

#undef LOG_TAG
#define LOG_TAG "WifiIdlHotspotIface"

#define AP_EVENT_MAX_NUM 8

static IWifiApEventCallback g_wifiApEventCallback[AP_INSTANCE_MAX_NUM];
void SetWifiApEventCallback(IWifiApEventCallback callback, int id)
{
    if ((id >= AP_INSTANCE_MAX_NUM) || (id < 0)) {
        LOGE("SetWifiApEventCallback error");
        return;
    }
    g_wifiApEventCallback[id] = callback;
}

IWifiApEventCallback *GetWifiApEventCallback(int id)
{
    if ((id >= AP_INSTANCE_MAX_NUM) || (id < 0)) {
        LOGE("GetWifiApEventCallback error");
        return NULL;
    }
    return &g_wifiApEventCallback[id];
}

WifiErrorNo StartSoftAp(int id, const char *ifaceName)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartSoftAp");
    WriteInt(context, id);
    WriteStr(context, ifaceName);
    WriteEnd(context);

    if (RpcClientCall(client, "StartSoftAp") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }

    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StopSoftAp(int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StopSoftAp");
    WriteInt(context, id);
    WriteEnd(context);

    if (RpcClientCall(client, "StopSoftAp") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }

    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetHostapdConfig(HostapdConfig *config, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetHostapdConfig");
    WriteStr(context, config->ssid);
    WriteInt(context, config->ssidLen);
    WriteStr(context, config->preSharedKey);
    WriteInt(context, config->preSharedKeyLen);
    WriteInt(context, config->securityType);
    WriteInt(context, config->band);
    WriteInt(context, config->channel);
    WriteInt(context, config->maxConn);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "SetHostapdConfig") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetStaInfos(char *infos, int32_t *size, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetStaInfos");
    WriteInt(context, *size);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "GetStaInfos") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetStaInfos deal failed!");
    } else {
        ReadInt(context, size);
        ReadStr(context, infos, *size);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetMacFilter(unsigned char *mac, int lenMac, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetMacFilter");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "SetMacFilter") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo DelMacFilter(unsigned char *mac, int lenMac, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DelMacFilter");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "DelMacFilter") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo DisassociateSta(unsigned char *mac, int lenMac, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DisassociateSta");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "DisassociateSta") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetValidFrequenciesForBand");
    WriteInt(context, band);
    WriteInt(context, *size);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "GetValidFrequenciesForBand") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetValidFrequenciesForBand deal failed!");
    } else {
        ReadInt(context, size);
        for (int i = 0; i < *size; ++i) {
            ReadInt(context, frequencies + i);
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetCountryCode(const char *code, int id)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetCountryCode");
    WriteStr(context, code);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "SetCountryCode") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

static int GetApCallbackEvents(int *events, int size)
{
    int apEvents[] = {
        HAL_CBK_CMD_STA_JOIN,
        HAL_CBK_CMD_STA_LEAVE,
        HAL_CBK_CMD_AP_ENABLE,
        HAL_CBK_CMD_AP_DISABLE,
        HAL_CBK_CMD_AP_STA_PSK_MISMATCH_EVENT
    };
    int max = sizeof(apEvents) / sizeof(apEvents[0]);
    int num = 0;
    for (; num < max && num < size; ++num) {
        events[num] = apEvents[num];
    }
    return num;
}

WifiErrorNo RegisterAsscociatedEvent(IWifiApEventCallback callback, int id)
{
    int events[AP_EVENT_MAX_NUM];
    int num = GetApCallbackEvents(events, AP_EVENT_MAX_NUM);
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    if (callback.onStaJoinOrLeave == NULL) {
        WriteFunc(context, "UnRegisterEventCallback");
    } else {
        WriteFunc(context, "RegisterEventCallback");
    }
    WriteInt(context, num);
    for (int i = 0; i < num; ++i) {
        WriteInt(context, events[i]);
    }
    WriteEnd(context);
    if (RpcClientCall(client, "RegisterAsscociatedEvent") != WIFI_HAL_OPT_OK) {
        if (callback.onStaJoinOrLeave == NULL) {
            SetWifiApEventCallback(callback, id);
        }
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_HAL_OPT_OK || callback.onStaJoinOrLeave == NULL) {
        SetWifiApEventCallback(callback, id);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaSetPowerModel(const int model, int id)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaSetPowerModel");
    WriteInt(context, model);
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "WpaSetPowerModel") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaGetPowerModel(int* model, int id)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaGetPowerModel");
    WriteInt(context, id);
    WriteEnd(context);
    if (RpcClientCall(client, "WpaGetPowerModel") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_HAL_OPT_OK) {
        ReadInt(context, model);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}
