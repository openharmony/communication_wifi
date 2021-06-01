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
#include "i_wifi_sta_iface.h"
#include "client.h"
#include "serial.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "wifi_idl_inner_interface.h"


#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_STA_IFACE"
#define EVENT_MAX_NUM 8

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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
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

WifiErrorNo SetAssocMacAddr(unsigned char *mac, int lenMac)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetAssocMacAddr");
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

WifiErrorNo GetSupportFeature(long *feature)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetSupportFeature");
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

WifiErrorNo SetWifiTxPower(int32_t power)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "SetWifiTxPower");
    WriteInt(context, power);
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

WifiErrorNo RemoveNetwork(int networkId)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "RemoveNetwork");
    WriteInt(context, networkId);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("RemoveNetwork: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("AddNetwork: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("EnableNetwork: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("DisableNetwork: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server DisableNetwork deal failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetNetwork(int networkId, NetWorkConfig *confs, int size)
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("SetNetwork: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server SetNetwork deal failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaGetNetwork(GetWpaNetWorkConfig *confs)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaGetNetwork");
    WriteInt(context, confs->networkId);
    WriteStr(context, confs->param);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("WpaGetNetwork: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server WpaGetNetwork deal failed!");
        return (WifiErrorNo)result;
    }
    ReadStr(context, confs->value, WIFI_NETWORK_CONFIG_VALUE_LENGTH);
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("SaveNetworkConfig: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartScan(const ScanSettings *settings)
{
    if (settings == NULL) {
        return WIFI_IDL_OPT_FAILED;
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StartScan: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}
WifiErrorNo GetNetworkList(NetworkList *networkList, int *size)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetNetworkList");
    WriteInt(context, *size);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("GetNetworkList: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server GetNetworkList deal failed!");
    } else {
        ReadInt(context, size);
        for (int i = 0; i < *size; ++i) {
            ReadInt(context, &networkList[i].id);
            ReadStr(context, networkList[i].ssid, WIFI_SSID_LENGTH);
            ReadStr(context, networkList[i].bssid, WIFI_BSSID_LENGTH);
            ReadStr(context, networkList[i].flags, WIFI_BSSID_LENGTH);
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetScanResults(ScanResult *results, int *size)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetScanResults");
    WriteInt(context, *size);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("GetScanResults: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("server GetScanResults deal failed!");
    } else {
        ReadInt(context, size);
        for (int i = 0; i < *size; ++i) {
            ReadStr(context, results[i].bssid, WIFI_BSSID_LENGTH);
            ReadInt(context, &results[i].frequency);
            ReadInt(context, &results[i].signalLevel);
            ReadStr(context, results[i].capability, WIFI_SCAN_RESULT_CAPABILITIES_LENGTH);
            ReadStr(context, results[i].ssid, WIFI_SSID_LENGTH);
            ReadLong(context, &results[i].timestamp);
        }
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartPnoScan(const PnoScanSettings *settings)
{
    if (settings == NULL) {
        return WIFI_IDL_OPT_FAILED;
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StartPnoScan: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StopPnoScan: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

static int CheckRegisterEvent(IWifiEventCallback callback, int *events, int size)
{
    LOGD("CheckRegisterEvent: size = %d.", size);
    int num = 0;
    if (callback.onStarted != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_STARTED;
    }
    if (callback.onStopped != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_STOPED;
    }
    if (callback.onFailure != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_FAILURE;
    }
    if (callback.onConnectChanged != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_CONNECT_CHANGED;
    }
    if (callback.onWpaStateChanged != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_WPA_STATE_CHANGEM;
    }
    if (callback.onSsidWrongkey != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_SSID_WRONG_KEY;
    }
    if (callback.onWpsOverlap != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_WPS_OVERLAP;
    }
    if (callback.onWpsTimeOut != NULL) {
        events[num++] = WIFI_IDL_CBK_CMD_WPS_TIME_OUT;
    }
    return num;
}

WifiErrorNo RegisterStaEventCallback(IWifiEventCallback callback)
{
    int events[EVENT_MAX_NUM] = {0}; /*  event max num */
    int num = CheckRegisterEvent(callback, events, EVENT_MAX_NUM);
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    if (num == 0) { /* UnRegisterEventCallback */
        WriteFunc(context, "UnRegisterEventCallback");
        WriteInt(context, EVENT_MAX_NUM); /* IWifiEventCallback event num */
        WriteInt(context, WIFI_IDL_CBK_CMD_FAILURE);
        WriteInt(context, WIFI_IDL_CBK_CMD_STARTED);
        WriteInt(context, WIFI_IDL_CBK_CMD_STOPED);
        WriteInt(context, WIFI_IDL_CBK_CMD_CONNECT_CHANGED);
        WriteInt(context, WIFI_IDL_CBK_CMD_WPA_STATE_CHANGEM);
        WriteInt(context, WIFI_IDL_CBK_CMD_SSID_WRONG_KEY);
        WriteInt(context, WIFI_IDL_CBK_CMD_WPS_OVERLAP);
        WriteInt(context, WIFI_IDL_CBK_CMD_WPS_TIME_OUT);
    } else {
        WriteFunc(context, "RegisterEventCallback");
        WriteInt(context, num);
        for (int i = 0; i < num; ++i) {
            WriteInt(context, events[i]);
        }
    }
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("RegisterStaEventCallback: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_IDL_OPT_OK) {
        SetWifiEventCallback(callback);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartWpsPbcMode(WifiWpsParam *param)
{
    if (param == NULL) {
        return WIFI_IDL_OPT_FAILED;
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StartWpsPbcMode: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo StartWpsPinMode(WifiWpsParam *param, int *pinCode)
{
    if (param == NULL || pinCode == NULL) {
        return WIFI_IDL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "StartWpsPinMode");
    WriteInt(context, param->anyFlag);
    WriteInt(context, param->multiAp);
    WriteStr(context, param->bssid);
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StartWpsPinMode: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_IDL_OPT_OK) {
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("StopWps: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo GetRoamingCapabilities(WifiRoamCapability *capability)
{
    if (capability == NULL) {
        return WIFI_IDL_OPT_FAILED;
    }
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "GetRoamingCapabilities");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("GetRoamingCapabilities: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result == WIFI_IDL_OPT_OK) {
        ReadInt(context, &capability->maxBlocklistSize);
        ReadInt(context, &capability->maxTrustlistSize);
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo SetRoamConfig(char **blocklist, int blocksize, char **trustlist, int size)
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
    WriteInt(context, size);
    if (size > 0 && trustlist != NULL) {
        for (int i = 0; i < size; ++i) {
            WriteStr(context, trustlist[i]);
        }
    }
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("SetRoamConfig: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("WpaAutoConnect: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("WpaAutoConnect failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}

WifiErrorNo WpaReconfigure(void)
{
    RpcClient *client = GetStaRpcClient();
    LockRpcClient(client);
    Context *context = client->context;
    WriteBegin(context, 0);
    WriteFunc(context, "WpaReconfigure");
    WriteEnd(context);
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("WpaAutoConnect: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("WpaReconfigure failed!");
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
    int ret = RemoteCall(client);
    if (ret < 0) {
        LOGE("WpaBlocklistClear: remote call failed!");
        UnlockRpcClient(client);
        return WIFI_IDL_OPT_FAILED;
    }
    int result = WIFI_IDL_OPT_FAILED;
    ReadInt(context, &result);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("WpaBlocklistClear failed!");
    }
    ReadClientEnd(client);
    UnlockRpcClient(client);
    return result;
}