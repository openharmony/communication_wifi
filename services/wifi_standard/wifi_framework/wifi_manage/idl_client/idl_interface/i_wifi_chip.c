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
#include "i_wifi_chip.h"
#include "client.h"
#include "serial.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "wifi_idl_inner_interface.h"


#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_I_WIFI_CHIP"

/* Defines the global wifichipeventcallback variable. */
static IWifiChipEventCallback g_wifiChipEventCallback = {0};
void SetWifiChipEventCallback(IWifiChipEventCallback callback)
{
    g_wifiChipEventCallback = callback;
}

IWifiChipEventCallback *GetWifiChipEventCallback(void)
{
    return &g_wifiChipEventCallback;
}

WifiErrorNo GetChipId(int32_t *id)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetChipId");
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
        LOGE("server GetChipId deal failed!");
    } else {
        ReadInt(context, id);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo CreateIface(int32_t type, IWifiIface *iface)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "CreateIface");
    WriteInt(context, type);
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
        LOGE("server CreateIface deal failed!");
    } else {
        /* read IWifiIface struct */
        ReadInt(context, &(iface->index));
        ReadInt(context, &(iface->type));
        ReadStr(context, iface->name, sizeof(iface->name));
        ReadStr(context, iface->macAddr, sizeof(iface->macAddr));
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetIface(const char *ifname, IWifiIface *iface)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetIface");
    WriteStr(context, ifname);
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
        LOGE("server GetIface deal failed!");
    } else {
        /*  read IWifiIface struct */
        ReadInt(context, &(iface->index));
        ReadInt(context, &(iface->type));
        ReadStr(context, iface->name, sizeof(iface->name));
        ReadStr(context, iface->macAddr, sizeof(iface->macAddr));
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetIfaceNames(int32_t type, char *ifaces, int32_t size)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetIfaceNames");
    WriteInt(context, type);
    WriteInt(context, size);
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
        LOGE("server GetIfaceNames deal failed!");
    } else {
        ReadStr(context, ifaces, size);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RemoveIface(const char *ifname)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "RemoveIface");
    WriteStr(context, ifname);
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

WifiErrorNo GetCapabilities(uint32_t *capabilities)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetCapabilities");
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
        LOGE("server GetCapabilities deal failed!");
    } else {
        ReadInt(context, (int *)capabilities);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetSupportedComboModes(int32_t *modes, int32_t *size)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetSupportedComboModes");
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
        LOGE("server GetSupportedComboModes deal failed!");
    } else {
        ReadInt(context, size);
        for (int i = 0; i < *size; ++i) {
            ReadInt(context, modes + i);
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo ConfigComboModes(int32_t mode)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "ConfigComboModes");
    WriteInt(context, mode);
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

WifiErrorNo GetComboModes(int32_t *id)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetComboModes");
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
        LOGE("server GetComboModes deal failed!");
    } else {
        ReadInt(context, id);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RegisterEventCallback(IWifiChipEventCallback callback)
{
    int num = 0;
    if (callback.onIfaceAdded != NULL) {
        ++num;
    }
    if (callback.onIfaceRemoved != NULL) {
        ++num;
    }
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    if (num == 0) {
        WriteFunc(context, "UnRegisterEventCallback");
        WriteInt(context, EVENTS_IFACE_ADD_DEL_NUM);
        WriteInt(context, WIFI_IDL_CBK_CMD_ADD_IFACE);
        WriteInt(context, WIFI_IDL_CBK_CMD_REMOVE_IFACE);
    } else {
        WriteFunc(context, "RegisterEventCallback");
        WriteInt(context, num);
        if (callback.onIfaceAdded != NULL) {
            WriteInt(context, WIFI_IDL_CBK_CMD_ADD_IFACE);
        }
        if (callback.onIfaceRemoved != NULL) {
            WriteInt(context, WIFI_IDL_CBK_CMD_REMOVE_IFACE);
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
        SetWifiChipEventCallback(callback);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RequestFirmwareDebugDump(unsigned char *bytes, int32_t *size)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "RequestFirmwareDebugDump");
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
        LOGE("server RequestFirmwareDebugDump deal failed!");
    } else {
        ReadInt(context, size);
        ReadUStr(context, bytes, *size + 1);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetPowerMode(uint8_t mode)
{
    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetPowerMode");
    WriteInt(context, mode);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("SetPowerMode:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiStatus SetLatencyMode(LatencyMode mode)
{
    struct WifiStatus status;

    RpcClient *client = GetChipRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetLatencyMode");
    WriteInt(context, (int)mode);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("SetLatencyMode:remote call failed!");
        status.code = (int)WIFI_IDL_OPT_FAILED;
        UnlockRpcClient(client);
        return status;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);

    status.code = result;
    return status;
}