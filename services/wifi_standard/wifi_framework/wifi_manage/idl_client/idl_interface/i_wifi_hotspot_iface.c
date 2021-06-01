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
#include "i_wifi_hotspot_iface.h"
#include "client.h"
#include "serial.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "wifi_idl_inner_interface.h"


#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_I_WIFI_HOTSPOT_IFACE"

static IWifiApEventCallback g_wifiApEventCallback = {0};
void SetWifiApEventCallback(IWifiApEventCallback callback)
{
    g_wifiApEventCallback = callback;
}

IWifiApEventCallback *GetWifiApEventCallback(void)
{
    return &g_wifiApEventCallback;
}

WifiErrorNo StartSoftAp(void)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartSoftAp");
    WriteEnd(context);

    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StartSoftAp:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }

    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StopSoftAp(void)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StopSoftAp");
    WriteEnd(context);

    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StopSoftAp:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }

    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetHostapdConfig(HostsapdConfig *config)
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

WifiErrorNo GetStaInfos(char *infos, int32_t *size)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetStaInfos");
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
        LOGE("server GetStaInfos deal failed!");
    } else {
        ReadInt(context, size);
        ReadStr(context, infos, *size);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo ConfigHotspot(uint32_t chan, const char *mscb)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "ConfigHotspot");
    WriteInt(context, chan);
    WriteStr(context, mscb);
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

WifiErrorNo SetMacFilter(unsigned char *mac, int lenMac)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetMacFilter");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
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

WifiErrorNo DelMacFilter(unsigned char *mac, int lenMac)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DelMacFilter");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
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

WifiErrorNo DisassociateSta(unsigned char *mac, int lenMac)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DisassociateSta");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
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

WifiErrorNo GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetValidFrequenciesForBand");
    WriteInt(context, band);
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

WifiErrorNo SetCountryCode(const char *code)
{
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetCountryCode");
    WriteStr(context, code);
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

WifiErrorNo RegisterAsscociatedEvent(IWifiApEventCallback callback)
{
    int num = 0;
    if (callback.onStaJoinOrLeave != NULL) {
        num += EVENTS_STA_JOIN_LEAVE_NUM;
    }
    if (callback.onApEnableOrDisable != NULL) {
        num += EVENTS_STA_JOIN_LEAVE_NUM;
    }
    RpcClient *client = GetApRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    if (num == 0) {
        WriteFunc(context, "UnRegisterEventCallback");
        WriteInt(context, (EVENTS_STA_JOIN_LEAVE_NUM + EVENTS_AP_DISABLE_ENABLE_NUM));
        WriteInt(context, WIFI_IDL_CBK_CMD_STA_JOIN);
        WriteInt(context, WIFI_IDL_CBK_CMD_STA_LEAVE);
        WriteInt(context, WIFI_IDL_CBK_CMD_AP_ENABLE);
        WriteInt(context, WIFI_IDL_CBK_CMD_AP_DISABLE);
    } else {
        WriteFunc(context, "RegisterEventCallback");
        WriteInt(context, num);
        if (callback.onStaJoinOrLeave != NULL) {
            WriteInt(context, WIFI_IDL_CBK_CMD_STA_JOIN);
            WriteInt(context, WIFI_IDL_CBK_CMD_STA_LEAVE);
        }
        if (callback.onApEnableOrDisable != NULL) {
            WriteInt(context, WIFI_IDL_CBK_CMD_AP_ENABLE);
            WriteInt(context, WIFI_IDL_CBK_CMD_AP_DISABLE);
        }
    }

    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_IDL_OPT_OK) {
        SetWifiApEventCallback(callback);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}
