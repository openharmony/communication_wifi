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
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_crpc_base.h"
#include "wifi_hal_crpc_chip.h"
#include "wifi_hal_crpc_supplicant.h"
#include "wifi_hal_crpc_sta.h"
#include "wifi_hal_crpc_ap.h"
#include "wifi_hal_crpc_common.h"
#include "securec.h"
#include "wifi_log.h"
#include "wifi_hal_common_func.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalCrpcServer"

/* Defines the mapping between global function names and functions. */
static WifiHalRpcFunc *g_rpcFuncHandle = NULL;
static RpcServer *g_rpcServer = NULL;

void SetRpcServerInited(RpcServer *server)
{
    g_rpcServer = server;
    return;
}

RpcServer *GetRpcServer(void)
{
    return g_rpcServer;
}

static int GetPos(const char *name)
{
    int total = 0;
    while (*name) {
        total += *name;
        ++name;
    }
    if (total < 0) {
        total *= -1;
    }
    return total % RPC_FUNC_NUM;
}

static int PushRpcFunc(const char *name, RPCFUNC func)
{
    int pos = GetPos(name);
    if (g_rpcFuncHandle[pos].func == NULL) {
        MySafeCopy(g_rpcFuncHandle[pos].funcname, sizeof(g_rpcFuncHandle[pos].funcname), name);
        g_rpcFuncHandle[pos].func = func;
    } else {
        WifiHalRpcFunc *p = g_rpcFuncHandle + pos;
        while (p->next) {
            p = p->next;
        }
        WifiHalRpcFunc *q = (WifiHalRpcFunc *)calloc(1, sizeof(WifiHalRpcFunc));
        if (q == NULL) {
            return -1;
        }
        MySafeCopy(q->funcname, sizeof(q->funcname), name);
        q->func = func;
        q->next = NULL;
        p->next = q;
    }
    return 0;
}

static int InitRpcFuncMapBase(void)
{
    int ret = 0;
    ret += PushRpcFunc("LoadDriver", RpcLoadDriver);
    ret += PushRpcFunc("UnloadDriver", RpcUnloadDriver);
    ret += PushRpcFunc("GetName", RpcGetName);
    ret += PushRpcFunc("GetType", RpcGetType);
    return ret;
}

static int InitRpcFuncMapChip(void)
{
    int ret = 0;
    ret += PushRpcFunc("GetWifiChip", RpcGetWifiChip);
    ret += PushRpcFunc("GetWifiChipIds", RpcGetWifiChipIds);
    ret += PushRpcFunc("GetChipId", RpcGetChipId);
    ret += PushRpcFunc("CreateIface", RpcCreateIface);
    ret += PushRpcFunc("GetIface", RpcGetIface);
    ret += PushRpcFunc("GetIfaceNames", RpcGetIfaceNames);
    ret += PushRpcFunc("RemoveIface", RpcRemoveIface);
    ret += PushRpcFunc("GetCapabilities", RpcGetCapabilities);
    ret += PushRpcFunc("GetSupportedComboModes", RpcGetSupportedComboModes);
    ret += PushRpcFunc("ConfigComboModes", RpcConfigComboModes);
    ret += PushRpcFunc("GetComboModes", RpcGetComboModes);
    ret += PushRpcFunc("RequestFirmwareDebugDump", RpcRequestFirmwareDebugDump);
    ret += PushRpcFunc("SetPowerMode", RpcSetPowerMode);
    ret += PushRpcFunc("SetLatencyMode", RpcSetLatencyMode);
    return ret;
}

static int InitRpcFuncMapSupplicant(void)
{
    int ret = 0;
    ret += PushRpcFunc("StartSupplicant", RpcStartSupplicant);
    ret += PushRpcFunc("StopSupplicant", RpcStopSupplicant);
    ret += PushRpcFunc("ConnectSupplicant", RpcConnectSupplicant);
    ret += PushRpcFunc("DisconnectSupplicant", RpcDisconnectSupplicant);
    ret += PushRpcFunc("RequestToSupplicant", RpcRequestToSupplicant);
    ret += PushRpcFunc("SetPowerSave", RpcSetPowerSave);
    ret += PushRpcFunc("WpaSetCountryCode", RpcWpaSetCountryCode);
    ret += PushRpcFunc("WpaGetCountryCode", RpcWpaGetCountryCode);
    return ret;
}

static int InitRpcFuncMapSta(void)
{
    int ret = 0;
    ret += PushRpcFunc("Start", RpcStart);
    ret += PushRpcFunc("Stop", RpcStop);
    ret += PushRpcFunc("StartScan", RpcStartScan);
    ret += PushRpcFunc("GetScanResults", RpcGetScanResults);
    ret += PushRpcFunc("StartPnoScan", RpcStartPnoScan);
    ret += PushRpcFunc("StopPnoScan", RpcStopPnoScan);
    ret += PushRpcFunc("Connect", RpcConnect);
    ret += PushRpcFunc("Reconnect", RpcReconnect);
    ret += PushRpcFunc("Reassociate", RpcReassociate);
    ret += PushRpcFunc("Disconnect", RpcDisconnect);
    ret += PushRpcFunc("SetExternalSim", RpcSetExternalSim);
    ret += PushRpcFunc("SetBluetoothCoexistenceScanMode", RpcSetBluetoothCoexistenceScanMode);
    ret += PushRpcFunc("StopFilteringMulticastV4Packets", RpcStopFilteringMulticastV4Packets);
    ret += PushRpcFunc("StopFilteringMulticastV6Packets", RpcStopFilteringMulticastV6Packets);
    ret += PushRpcFunc("EnableStaAutoReconnect", RpcEnableStaAutoReconnect);
    ret += PushRpcFunc("SetConcurrencyPriority", RpcSetConcurrencyPriority);
    ret += PushRpcFunc("SetSuspendModeEnabled", RpcSetSuspendModeEnabled);
    ret += PushRpcFunc("GetStaCapabilities", RpcGetStaCapabilities);
    ret += PushRpcFunc("GetDeviceMacAddress", RpcGetDeviceMacAddress);
    ret += PushRpcFunc("GetFrequencies", RpcGetFrequencies);
    ret += PushRpcFunc("SetAssocMacAddr", RpcSetAssocMacAddr);
    ret += PushRpcFunc("SetScanningMacAddress", RpcSetScanningMacAddress);
    ret += PushRpcFunc("DeauthLastRoamingBssid", RpcDeauthLastRoamingBssid);
    ret += PushRpcFunc("GetSupportFeature", RpcGetSupportFeature);
    ret += PushRpcFunc("RunCmd", RpcRunCmd);
    ret += PushRpcFunc("SetWifiTxPower", RpcSetWifiTxPower);
    ret += PushRpcFunc("RemoveNetwork", RpcRemoveNetwork);
    ret += PushRpcFunc("AddNetwork", RpcAddNetwork);
    ret += PushRpcFunc("EnableNetwork", RpcEnableNetwork);
    ret += PushRpcFunc("DisableNetwork", RpcDisableNetwork);
    ret += PushRpcFunc("SetNetwork", RpcSetNetwork);
    ret += PushRpcFunc("SaveNetworkConfig", RpcSaveNetworkConfig);
    ret += PushRpcFunc("StartWpsPbcMode", RpcStartWpsPbcMode);
    ret += PushRpcFunc("StartWpsPinMode", RpcStartWpsPinMode);
    ret += PushRpcFunc("StopWps", RpcStopWps);
    ret += PushRpcFunc("GetRoamingCapabilities", RpcGetRoamingCapabilities);
    ret += PushRpcFunc("SetRoamConfig", RpcSetRoamConfig);
    ret += PushRpcFunc("WpaGetNetwork", RpcWpaGetNetwork);
    ret += PushRpcFunc("WpaAutoConnect", RpcWpaAutoConnect);
    ret += PushRpcFunc("WpaReconfigure", RpcWpaReconfigure);
    ret += PushRpcFunc("WpaBlocklistClear", RpcWpaBlocklistClear);
    ret += PushRpcFunc("GetNetworkList", RpcGetNetworkList);
    return ret;
}

static int InitRpcFuncMapAp(void)
{
    int ret = 0;
    ret += PushRpcFunc("StartSoftAp", RpcStartSoftAp);
    ret += PushRpcFunc("StopSoftAp", RpcStopSoftAp);
    ret += PushRpcFunc("SetHostapdConfig", RpcSetHostapdConfig);
    ret += PushRpcFunc("GetStaInfos", RpcGetStaInfos);
    ret += PushRpcFunc("ConfigHotspot", RpcConfigHotspot);
    ret += PushRpcFunc("SetCountryCode", RpcSetCountryCode);
    ret += PushRpcFunc("SetMacFilter", RpcSetMacFilter);
    ret += PushRpcFunc("DelMacFilter", RpcDelMacFilter);
    ret += PushRpcFunc("DisassociateSta", RpcDisassociateSta);
    ret += PushRpcFunc("GetValidFrequenciesForBand", RpcGetValidFrequenciesForBand);
    return ret;
}

static int InitRpcFuncMapCommon(void)
{
    int ret = 0;
    ret += PushRpcFunc("RegisterEventCallback", RpcRegisterEventCallback);
    ret += PushRpcFunc("UnRegisterEventCallback", RpcUnRegisterEventCallback);
    ret += PushRpcFunc("NotifyClear", RpcNotifyClear);
    return ret;
}

int InitRpcFunc(void)
{
    g_rpcFuncHandle = (WifiHalRpcFunc *)calloc(RPC_FUNC_NUM, sizeof(WifiHalRpcFunc));
    if (g_rpcFuncHandle == NULL) {
        return -1;
    }

    int ret = 0;
    ret += InitRpcFuncMapBase();
    ret += InitRpcFuncMapChip();
    ret += InitRpcFuncMapSupplicant();
    ret += InitRpcFuncMapSta();
    ret += InitRpcFuncMapAp();
    ret += InitRpcFuncMapCommon();
    if (ret < 0) {
        return -1;
    }

    if (InitCallbackMsg() < 0) {
        return -1;
    }
    return 0;
}

void ReleaseRpcFunc(void)
{
    for (int i = 0; i < RPC_FUNC_NUM; ++i) {
        WifiHalRpcFunc *p = g_rpcFuncHandle[i].next;
        while (p) {
            WifiHalRpcFunc *q = p->next;
            free(p);
            p = q;
        }
    }
    free(g_rpcFuncHandle);
    g_rpcFuncHandle = NULL;
    ReleaseCallbackMsg();
    return;
}

RPCFUNC GetRpcFunc(const char *func)
{
    int pos = GetPos(func);
    WifiHalRpcFunc *p = g_rpcFuncHandle + pos;
    while (p && strcmp(p->funcname, func) != 0) {
        p = p->next;
    }
    if (p == NULL) {
        return NULL;
    }
    return p->func;
}

/* Processing client requests */
int OnTransact(RpcServer *server, Context *context)
{
    if ((server == NULL) || (context == NULL)) {
        return -1;
    }

    char func[RPC_FUNCNAME_MAX_LEN] = {0};
    int ret = ReadFunc(context, func, RPC_FUNCNAME_MAX_LEN);
    if (ret < 0) {
        return -1;
    }
    LOGI("run %{public}s", func);
    RPCFUNC pFunc = GetRpcFunc(func);
    if (pFunc == NULL) {
        LOGD("unsupport function[%{public}s]", func);
        WriteBegin(context, 0);
        WriteInt(context, WIFI_HAL_FAILED);
        WriteStr(context, "unsupport function");
        WriteEnd(context);
    } else {
        ret = pFunc(server, context);
        if (ret < 0) {
            WriteBegin(context, 0);
            WriteInt(context, WIFI_HAL_FAILED);
            WriteStr(context, "server deal failed!");
            WriteEnd(context);
        }
    }
    return 0;
}

/* Callback request */
int OnCallbackTransact(RpcServer *server, int event, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    WriteBegin(context, 1);
    WriteInt(context, event);
    /* Callback parameters are required based on the message ID. */
    if (event == WIFI_ADD_IFACE_EVENT) {
        WifiHalEventCallbackMsg *cbmsg = FrontCallbackMsg(event);
        if (cbmsg != NULL) {
            WriteInt(context, cbmsg->msg.ifMsg.type);
            WriteStr(context, cbmsg->msg.ifMsg.ifname);
        }
    } else if (event == WIFI_SCAN_RESULT_NOTIFY_EVENT) {
        WifiHalEventCallbackMsg *cbmsg = FrontCallbackMsg(event);
        if (cbmsg != NULL) {
            WriteInt(context, cbmsg->msg.scanResult);
        }
    } else if (event == WIFI_CONNECT_CHANGED_NOTIFY_EVENT) {
        WifiHalEventCallbackMsg *cbmsg = FrontCallbackMsg(event);
        if (cbmsg != NULL) {
            WriteInt(context, cbmsg->msg.connMsg.status);
            WriteInt(context, cbmsg->msg.connMsg.networkId);
            WriteStr(context, cbmsg->msg.connMsg.bssid);
        }
    } else if (event == WIFI_STA_JOIN_EVENT || event == WIFI_STA_LEAVE_EVENT) {
        WifiHalEventCallbackMsg *cbmsg = FrontCallbackMsg(event);
        if (cbmsg != NULL) {
            WriteInt(context, cbmsg->msg.ifMsg.type);
            WriteStr(context, cbmsg->msg.ifMsg.ifname);
        }
    } else if (event == WIFI_WPA_STATE_EVENT || event == WIFI_SSID_WRONG_KEY || event == WIFI_WPS_OVERLAP ||
               event == WIFI_WPS_TIME_OUT) {
        WifiHalEventCallbackMsg *cbmsg = FrontCallbackMsg(event);
        if (cbmsg != NULL) {
            WriteInt(context, cbmsg->msg.scanResult);
        }
    }
    WriteEnd(context);
    return 0;
}

int EndCallbackTransact(RpcServer *server, int event)
{
    if (server == NULL) {
        return -1;
    }
    return PopFrontCallbackMsg(event);
}

/* Defines the bidirectional list of global callback event parameters. */
static WifiHalEventCallback *g_wifiHalEventCallback = NULL;

int InitCallbackMsg(void)
{
    g_wifiHalEventCallback = (WifiHalEventCallback *)calloc(1, sizeof(WifiHalEventCallback));
    if (g_wifiHalEventCallback == NULL) {
        return -1;
    }
    pthread_mutex_init(&g_wifiHalEventCallback->mutex, NULL);
    for (int i = 0; i < WIFI_HAL_MAX_EVENT - WIFI_FAILURE_EVENT; ++i) {
        g_wifiHalEventCallback->cbmsgs[i].pre = g_wifiHalEventCallback->cbmsgs + i;
        g_wifiHalEventCallback->cbmsgs[i].next = g_wifiHalEventCallback->cbmsgs + i;
    }
    return 0;
}

void ReleaseCallbackMsg(void)
{
    for (int i = 0; i < WIFI_HAL_MAX_EVENT - WIFI_FAILURE_EVENT; ++i) {
        WifiHalEventCallbackMsg *head = g_wifiHalEventCallback->cbmsgs + i;
        WifiHalEventCallbackMsg *p = head->next;
        while (p != head) {
            WifiHalEventCallbackMsg *q = p->next;
            free(p);
            p = q;
        }
    }
    pthread_mutex_destroy(&g_wifiHalEventCallback->mutex);
    free(g_wifiHalEventCallback);
    g_wifiHalEventCallback = NULL;
    return;
}

int PushBackCallbackMsg(int event, WifiHalEventCallbackMsg *msg)
{
    if (event >= WIFI_HAL_MAX_EVENT || event < WIFI_FAILURE_EVENT) {
        return -1;
    }
    int pos = event - WIFI_FAILURE_EVENT;
    pthread_mutex_lock(&g_wifiHalEventCallback->mutex);
    WifiHalEventCallbackMsg *head = g_wifiHalEventCallback->cbmsgs + pos;
    if (head->next == head) { /* Empty Queue */
        msg->pre = head;
        head->next = msg;
        msg->next = head;
        head->pre = msg;
    } else {
        msg->pre = head->pre;
        head->pre->next = msg;
        msg->next = head;
        head->pre = msg;
    }
    pthread_mutex_unlock(&g_wifiHalEventCallback->mutex);
    return 0;
}

int PopBackCallbackMsg(int event)
{
    if (event >= WIFI_HAL_MAX_EVENT || event < WIFI_FAILURE_EVENT) {
        return -1;
    }
    int pos = event - WIFI_FAILURE_EVENT;
    pthread_mutex_lock(&g_wifiHalEventCallback->mutex);
    WifiHalEventCallbackMsg *head = g_wifiHalEventCallback->cbmsgs + pos;
    if (head->next != head) { /* The queue is not empty. */
        WifiHalEventCallbackMsg *tail = head->pre;
        head->pre = tail->pre;
        tail->pre->next = head;
    }
    pthread_mutex_unlock(&g_wifiHalEventCallback->mutex);
    return 0;
}

WifiHalEventCallbackMsg *FrontCallbackMsg(int event)
{
    if (event >= WIFI_HAL_MAX_EVENT || event < WIFI_FAILURE_EVENT) {
        return NULL;
    }
    int pos = event - WIFI_FAILURE_EVENT;
    WifiHalEventCallbackMsg *head = g_wifiHalEventCallback->cbmsgs + pos;
    if (head->next != head) { /* The queue is not empty. */
        return head->next;
    } else {
        return NULL;
    }
}

int PopFrontCallbackMsg(int event)
{
    if (event >= WIFI_HAL_MAX_EVENT || event < WIFI_FAILURE_EVENT) {
        return -1;
    }
    int pos = event - WIFI_FAILURE_EVENT;
    pthread_mutex_lock(&g_wifiHalEventCallback->mutex);
    WifiHalEventCallbackMsg *head = g_wifiHalEventCallback->cbmsgs + pos;
    if (head->next != head) { /* The queue is not empty. */
        WifiHalEventCallbackMsg *p = head->next;
        head->next = p->next;
        p->next->pre = head;
        free(p);
    }
    pthread_mutex_unlock(&g_wifiHalEventCallback->mutex);
    return 0;
}