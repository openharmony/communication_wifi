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
#include "i_wifi_supplicant_iface.h"
#include "client.h"
#include "serial.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "wifi_idl_inner_interface.h"


#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_I_WIFI_SUPPLICANT_IFACE"
static ISupplicantEventCallback g_wifiSupplicantEventCallback = {0};
void SetSupplicantEventCallback(ISupplicantEventCallback callback)
{
    g_wifiSupplicantEventCallback = callback;
}

ISupplicantEventCallback *GetSupplicantEventCallback(void)
{
    return &g_wifiSupplicantEventCallback;
}

WifiErrorNo StartSupplicant(void)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartSupplicant");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StartSupplicant:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StopSupplicant(void)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StopSupplicant");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StopSupplicant:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo ConnectSupplicant(void)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "ConnectSupplicant");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("ConnectSupplicant:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo DisConnectSupplicant(void)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DisConnectSupplicant");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("DisConnectSupplicant:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RequestToSupplicant(unsigned char *buf, int32_t bufSize)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "RequestToSupplicant");
    WriteInt(context, bufSize);
    WriteUStr(context, buf, bufSize);
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

WifiErrorNo RigisterSupplicantEventCallback(ISupplicantEventCallback callback)
{
    int num = 0;
    if (callback.onScanNotify != NULL) {
        num += 1;
    }
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    if (num == 0) { /* UnRegisterEventCallback */
        WriteFunc(context, "UnRegisterEventCallback");
        WriteInt(context, 1); /* ISupplicantEventCallback event num */
        WriteInt(context, WIFI_IDL_CBK_CMD_SCAN_RESULT_NOTIFY);
    } else {
        WriteFunc(context, "RegisterEventCallback");
        WriteInt(context, num);
        if (callback.onScanNotify != NULL) {
            WriteInt(context, WIFI_IDL_CBK_CMD_SCAN_RESULT_NOTIFY);
        }
    }
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("RigisterSupplicantEventCallback: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_IDL_OPT_OK) {
        g_wifiSupplicantEventCallback = callback;
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo Connect(int networkId)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "Connect");
    WriteInt(context, networkId);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("Connect: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo Reconnect(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "Reconnect");
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

WifiErrorNo Reassociate(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "Reassociate");
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

WifiErrorNo Disconnect(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "Disconnect");
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
WifiErrorNo SetPowerSave(BOOL enable)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetPowerSave");
    WriteInt(context, (int)enable);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("SetPowerSave:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaSetCountryCode(const char *countryCode)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaSetCountryCode");
    WriteStr(context, countryCode);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("WpaSetCountryCode:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaGetCountryCode(char *countryCode, int codeSize)
{
    RpcClient *client = GetSupplicantRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaGetCountryCode");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("WpaSetCountryCode:remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_IDL_OPT_OK) {
        ReadStr(context, countryCode, codeSize);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    if (strlen(countryCode) <= 0) {
        return WIFI_IDL_OPT_FAILED;
    }
    return result;
}