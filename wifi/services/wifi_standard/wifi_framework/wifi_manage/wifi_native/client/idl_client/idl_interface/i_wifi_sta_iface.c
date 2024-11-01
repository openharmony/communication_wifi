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

#include "i_wifi_sta_iface.h"
#include <stdlib.h>
#include <sys/un.h>
#include "client.h"
#include "context.h"
#include "i_wifi_public_func.h"
#include "serial.h"
#include "wifi_idl_inner_interface.h"
#include "wifi_log.h"
#include "wifi_native_define.h"

#undef LOG_TAG
#define LOG_TAG "WifiIdlStaIface"

static int g_staCallbackEvents[] = {
    HAL_CBK_CMD_FAILURE,
    HAL_CBK_CMD_STARTED,
    HAL_CBK_CMD_STOPED,
    HAL_CBK_CMD_CONNECT_CHANGED,
    HAL_CBK_CMD_BSSID_CHANGED,
    HAL_CBK_CMD_WPA_STATE_CHANGEM,
    HAL_CBK_CMD_SSID_WRONG_KEY,
    HAL_CBK_CMD_WPS_OVERLAP,
    HAL_CBK_CMD_WPS_TIME_OUT,
    HAL_CBK_CMD_WPS_CONNECTION_FULL,
    HAL_CBK_CMD_WPS_CONNECTION_REJECT,
    HAL_CBK_CMD_STA_DISCONNECT_REASON_EVENT
};

static IWifiEventCallback g_wifiStaEventCallback = {0};
void SetWifiEventCallback(IWifiEventCallback callback)
{
    g_wifiStaEventCallback = callback;
}

IWifiEventCallback *GetWifiEventCallback(void)
{
    return &g_wifiStaEventCallback;
}

WifiErrorNo GetStaCapabilities(int32_t *capabilities)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetStaCapabilities");
    WriteEnd(context);
    if (RpcClientCall(client, "GetStaCapabilities") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetStaCapabilities deal failed!");
    } else {
        ReadInt(context, capabilities);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetDeviceMacAddress(unsigned char *mac, int *lenMac)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetDeviceMacAddress");
    WriteInt(context, *lenMac);
    WriteEnd(context);
    if (RpcClientCall(client, "GetDeviceMacAddress") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetDeviceMacAddress deal failed!");
    } else {
        ReadInt(context, lenMac);
        ReadUStr(context, mac, *lenMac + 1);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetFrequencies(int32_t band, int *frequencies, int32_t *size)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetFrequencies");
    WriteInt(context, band);
    WriteInt(context, *size);
    WriteEnd(context);
    if (RpcClientCall(client, "GetFrequencies") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetFrequencies deal failed!");
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

WifiErrorNo SetAssocMacAddr(unsigned char *mac, int lenMac, const int portType)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetAssocMacAddr");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
    WriteInt(context, portType);
    WriteEnd(context);
    if (RpcClientCall(client, "SetAssocMacAddr") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetScanningMacAddress(unsigned char *mac, int lenMac)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetScanningMacAddress");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
    WriteEnd(context);
    if (RpcClientCall(client, "SetScanningMacAddress") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo DeauthLastRoamingBssid(unsigned char *mac, int lenMac)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DeauthLastRoamingBssid");
    WriteInt(context, lenMac);
    WriteUStr(context, mac, lenMac);
    WriteEnd(context);
    if (RpcClientCall(client, "DeauthLastRoamingBssid") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetSupportFeature(long *feature)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetSupportFeature");
    WriteEnd(context);
    if (RpcClientCall(client, "GetSupportFeature") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_HAL_OPT_OK) {
        ReadLong(context, feature);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RunCmd(const char *ifname, int32_t cmdId, unsigned char *buf, int32_t bufSize)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "RunCmd");
    WriteStr(context, ifname);
    WriteInt(context, cmdId);
    WriteInt(context, bufSize);
    WriteUStr(context, buf, bufSize);
    WriteEnd(context);
    if (RpcClientCall(client, "RunCmd") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetWifiTxPower(int32_t power)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetWifiTxPower");
    WriteInt(context, power);
    WriteEnd(context);
    if (RpcClientCall(client, "SetWifiTxPower") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RemoveNetwork(int networkId)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "RemoveNetwork");
    WriteInt(context, networkId);
    WriteEnd(context);
    if (RpcClientCall(client, "RemoveNetwork") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo AddNetwork(int *networkId)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "AddNetwork");
    WriteEnd(context);
    if (RpcClientCall(client, "AddNetwork") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server AddNetwork deal failed!");
    } else {
        ReadInt(context, networkId);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo EnableNetwork(int networkId)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "EnableNetwork");
    WriteInt(context, networkId);
    WriteEnd(context);
    if (RpcClientCall(client, "EnableNetwork") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server EnableNetwork deal failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo DisableNetwork(int networkId)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "DisableNetwork");
    WriteInt(context, networkId);
    WriteEnd(context);
    if (RpcClientCall(client, "DisableNetwork") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server DisableNetwork deal failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetNetwork(int networkId, SetNetworkConfig *confs, int size)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetNetwork");
    WriteInt(context, networkId);
    WriteInt(context, size);
    for (int i = 0; i < size; ++i) {
        WriteInt(context, confs[i].cfgParam);
        WriteStr(context, confs[i].cfgValue);
    }
    WriteEnd(context);
    if (RpcClientCall(client, "SetNetwork") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server SetNetwork deal failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaGetNetwork(GetNetworkConfig *confs)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaGetNetwork");
    WriteInt(context, confs->networkId);
    WriteStr(context, confs->param);
    WriteEnd(context);
    if (RpcClientCall(client, "WpaGetNetwork") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server WpaGetNetwork deal failed!");
    } else {
        ReadStr(context, confs->value, WIFI_NETWORK_CONFIG_VALUE_LENGTH);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return (WifiErrorNo)result;
}

WifiErrorNo SaveNetworkConfig(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SaveNetworkConfig");
    WriteEnd(context);
    if (RpcClientCall(client, "SaveNetworkConfig") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartScan(const ScanSettings *settings)
{
    if (settings == NULL) {
        return WIFI_HAL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartScan");
    WriteInt(context, settings->hiddenSsidSize);
    for (int i = 0; i < settings->hiddenSsidSize; ++i) {
        WriteInt(context, strlen(settings->hiddenSsid[i]));
        WriteStr(context, settings->hiddenSsid[i]);
    }
    WriteInt(context, settings->freqSize);
    for (int i = 0; i < settings->freqSize; ++i) {
        WriteInt(context, settings->freqs[i]);
    }
    WriteInt(context, settings->scanStyle);
    WriteEnd(context);
    if (RpcClientCall(client, "StartScan") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetNetworkList(WifiNetworkInfo *infos, int *size)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetNetworkList");
    WriteInt(context, *size);
    WriteEnd(context);
    if (RpcClientCall(client, "GetNetworkList") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetNetworkList deal failed!");
    } else {
        ReadInt(context, size);
        for (int i = 0; i < *size; ++i) {
            ReadInt(context, &infos[i].id);
            ReadStr(context, infos[i].ssid, WIFI_SSID_LENGTH);
            ReadStr(context, infos[i].bssid, WIFI_BSSID_LENGTH);
            ReadStr(context, infos[i].flags, WIFI_NETWORK_FLAGS_LENGTH);
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

static void GetScanInfoElems(Context *context, ScanInfo* scanInfo)
{
    const int MAX_INFO_ELEMS_SIZE = 256;
    ReadInt(context, &scanInfo->ieSize);
    if (scanInfo->ieSize <= 0 || scanInfo->ieSize > MAX_INFO_ELEMS_SIZE) {
        return;
    }
    /* This pointer will be released in its client */
    scanInfo->infoElems = (ScanInfoElem *)calloc(scanInfo->ieSize, sizeof(ScanInfoElem));
    if (scanInfo->infoElems == NULL) {
        return;
    }
    for (int i = 0; i < scanInfo->ieSize; ++i) {
        ReadInt(context, (int *)&scanInfo->infoElems[i].id);
        ReadInt(context, &scanInfo->infoElems[i].size);
        if (scanInfo->infoElems[i].size <= 0) {
            continue;
        }
        /* This pointer will be released in its client */
        scanInfo->infoElems[i].content = calloc(scanInfo->infoElems[i].size + 1, sizeof(char));
        if (scanInfo->infoElems[i].content == NULL) {
            return;
        }
        ReadUStr(context, (unsigned char *)scanInfo->infoElems[i].content,
            scanInfo->infoElems[i].size + 1);
    }
}

ScanInfo* GetScanInfos(int *size)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetScanInfos");
    WriteInt(context, *size);
    WriteEnd(context);
    if (RpcClientCall(client, "GetScanInfos") != WIFI_HAL_OPT_OK) {
        return NULL;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ScanInfo* scanInfos = NULL;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("server GetScanInfos deal failed!");
    } else {
        ReadInt(context, size);
        LOGI("GetScanInfos size: %{public}d", *size);
        if (*size > 0) {
            scanInfos = (ScanInfo *)calloc(*size, sizeof(ScanInfo));
            if (scanInfos != NULL) {
                for (int i = 0; i < *size; ++i) {
                    ReadStr(context, scanInfos[i].bssid, WIFI_BSSID_LENGTH);
                    ReadInt(context, &scanInfos[i].freq);
                    ReadInt(context, &scanInfos[i].siglv);
                    ReadStr(context, scanInfos[i].flags, WIFI_SCAN_INFO_CAPABILITY_LENGTH);
                    ReadStr(context, scanInfos[i].ssid, WIFI_SSID_LENGTH);
                    ReadInt64(context, &scanInfos[i].timestamp);
                    ReadInt(context, &scanInfos[i].channelWidth);
                    ReadInt(context, &scanInfos[i].centerFrequency0);
                    ReadInt(context, &scanInfos[i].centerFrequency1);
                    ReadInt(context, &scanInfos[i].isVhtInfoExist);
                    ReadInt(context, &scanInfos[i].isHtInfoExist);
                    ReadInt(context, &scanInfos[i].isHeInfoExist);
                    ReadInt(context, &scanInfos[i].isErpExist);
                    ReadInt(context, &scanInfos[i].maxRates);
                    ReadInt(context, &scanInfos[i].extMaxRates);
                    GetScanInfoElems(context, &scanInfos[i]);
                }
            } else {
                LOGE("GetScanInfos alloc mem failed!");
            }
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return scanInfos;
}

WifiErrorNo StartPnoScan(const PnoScanSettings *settings)
{
    if (settings == NULL) {
        return WIFI_HAL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartPnoScan");
    WriteInt(context, settings->scanInterval);
    WriteInt(context, settings->minRssi2Dot4Ghz);
    WriteInt(context, settings->minRssi5Ghz);
    WriteInt(context, settings->hiddenSsidSize);
    for (int i = 0; i < settings->hiddenSsidSize; ++i) {
        WriteInt(context, strlen(settings->hiddenSsid[i]));
        WriteStr(context, settings->hiddenSsid[i]);
    }
    WriteInt(context, settings->savedSsidSize);
    for (int i = 0; i < settings->savedSsidSize; ++i) {
        WriteInt(context, strlen(settings->savedSsid[i]));
        WriteStr(context, settings->savedSsid[i]);
    }
    WriteInt(context, settings->freqSize);
    for (int i = 0; i < settings->freqSize; ++i) {
        WriteInt(context, settings->freqs[i]);
    }
    WriteEnd(context);
    if (RpcClientCall(client, "StartPnoScan") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StopPnoScan(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StopPnoScan");
    WriteEnd(context);
    if (RpcClientCall(client, "StopPnoScan") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo RegisterStaEventCallback(IWifiEventCallback callback)
{
    int num = sizeof(g_staCallbackEvents) / sizeof(g_staCallbackEvents[0]);
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    if (callback.onConnectChanged == NULL) {
        WriteFunc(context, "UnRegisterEventCallback");
    } else {
        WriteFunc(context, "RegisterEventCallback");
    }
    WriteInt(context, num);
    for (int i = 0; i < num; ++i) {
        WriteInt(context, g_staCallbackEvents[i]);
    }
    WriteEnd(context);
    if (RpcClientCall(client, "RegisterStaEventCallback") != WIFI_HAL_OPT_OK) {
        if (callback.onConnectChanged == NULL) {
            SetWifiEventCallback(callback);
        }
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_HAL_OPT_OK || callback.onConnectChanged == NULL) {
        SetWifiEventCallback(callback);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartWpsPbcMode(WifiWpsParam *param)
{
    if (param == NULL) {
        return WIFI_HAL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartWpsPbcMode");
    WriteInt(context, param->anyFlag);
    WriteInt(context, param->multiAp);
    WriteStr(context, param->bssid);
    WriteEnd(context);
    if (RpcClientCall(client, "StartWpsPbcMode") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartWpsPinMode(WifiWpsParam *param, int *pinCode)
{
    if (param == NULL || pinCode == NULL) {
        return WIFI_HAL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartWpsPinMode");
    WriteInt(context, param->anyFlag);
    WriteInt(context, param->multiAp);
    WriteStr(context, param->bssid);
    WriteStr(context, param->pinCode);
    WriteEnd(context);
    if (RpcClientCall(client, "StartWpsPinMode") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_HAL_OPT_OK) {
        ReadInt(context, pinCode);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StopWps(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StopWps");
    WriteEnd(context);
    if (RpcClientCall(client, "StopWps") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetRoamingCapabilities(WifiRoamCapability *capability)
{
    if (capability == NULL) {
        return WIFI_HAL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetRoamingCapabilities");
    WriteEnd(context);
    if (RpcClientCall(client, "GetRoamingCapabilities") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_HAL_OPT_OK) {
        ReadInt(context, &capability->maxBlocklistSize);
        ReadInt(context, &capability->maxTrustlistSize);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetRoamConfig(char **blocklist, int blocksize, char **trustlist, int trustsize)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetRoamConfig");
    WriteInt(context, blocksize);
    if (blocksize > 0 && blocklist != NULL) {
        for (int i = 0; i < blocksize; ++i) {
            WriteStr(context, blocklist[i]);
        }
    }
    WriteInt(context, trustsize);
    if (trustsize > 0 && trustlist != NULL) {
        for (int i = 0; i < trustsize; ++i) {
            WriteStr(context, trustlist[i]);
        }
    }
    WriteEnd(context);
    if (RpcClientCall(client, "SetRoamConfig") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaAutoConnect(int enable)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaAutoConnect");
    WriteInt(context, enable);
    WriteEnd(context);
    if (RpcClientCall(client, "WpaAutoConnect") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("WpaAutoConnect failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}


WifiErrorNo WpaBlocklistClear(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaBlocklistClear");
    WriteEnd(context);
    if (RpcClientCall(client, "WpaBlocklistClear") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("WpaBlocklistClear failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetConnectSignalInfo(const char *endBssid, WpaSignalInfo *info)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetConnectSignalInfo");
    WriteStr(context, endBssid);
    WriteEnd(context);
    if (RpcClientCall(client, "GetConnectSignalInfo") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_HAL_OPT_OK) {
        LOGE("GetConnectSignalInfo failed!");
    } else {
        ReadInt(context, &info->signal);
        ReadInt(context, &info->txrate);
        ReadInt(context, &info->rxrate);
        ReadInt(context, &info->noise);
        ReadInt(context, &info->frequency);
        ReadInt(context, &info->txPackets);
        ReadInt(context, &info->rxPackets);
        ReadInt(context, &info->snr);
        ReadInt(context, &info->chload);
        ReadInt(context, &info->ulDelay);
        ReadInt(context, &info->txBytes);
        ReadInt(context, &info->rxBytes);
        ReadInt(context, &info->txFailed);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetSuspendMode(bool mode)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetSuspendMode");
    WriteInt(context, mode);
    WriteEnd(context);
    if (RpcClientCall(client, "SetSuspendMode") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetPowerMode(bool mode)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetPowerMode");
    WriteInt(context, mode);
    WriteEnd(context);
    if (RpcClientCall(client, "SetPowerMode") != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int result = WIFI_HAL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

