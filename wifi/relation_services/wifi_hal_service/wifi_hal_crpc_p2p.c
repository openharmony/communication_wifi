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

#include "wifi_hal_crpc_p2p.h"
#include <securec.h>
#include "serial.h"
#include "wifi_hal_p2p_interface.h"
#include "wifi_hal_define.h"

#define WIFI_IDL_GET_MAX_BANDS 32
#define GROUP_CONFIG_END_POS 9

int RpcP2pStart(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pStart();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pStop(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pStop();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetRandomMac(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int enable = 0;
    if (ReadInt(context, &enable) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetRandomMac(enable);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetDeviceName(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char name[WIFI_P2P_WPS_NAME_LENGTH] = {0};
    if (ReadStr(context, name, sizeof(name)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetDeviceName(name);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetSsidPostfixName(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char name[WIFI_P2P_WPS_NAME_LENGTH] = {0};
    if (ReadStr(context, name, sizeof(name)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetSsidPostfixName(name);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetWpsDeviceType(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char type[WIFI_P2P_WPS_NAME_LENGTH] = {0};
    if (ReadStr(context, type, sizeof(type)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetWpsDeviceType(type);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetWpsSecondaryDeviceType(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char type[WIFI_P2P_WPS_NAME_LENGTH] = {0};
    if (ReadStr(context, type, sizeof(type)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetWpsSecondaryDeviceType(type);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetWpsConfigMethods(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char methods[WIFI_P2P_WPS_METHODS_LENGTH] = {0};
    if (ReadStr(context, methods, sizeof(methods)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetWpsConfigMethods(methods);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pGetDeviceAddress(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int size = 0;
    if (ReadInt(context, &size) < 0 || size <= 0) {
        return HAL_FAILURE;
    }
    char *address = (char *)calloc(size, sizeof(char));
    if (address == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pGetDeviceAddress(address, size);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteStr(context, address);
    }
    WriteEnd(context);
    free(address);
    address = NULL;
    return HAL_SUCCESS;
}

int RpcP2pFlush(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pFlush();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pFlushService(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pFlushService();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSaveConfig(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSaveConfig();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetupWpsPbc(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char interface[WIFI_P2P_GROUP_IFNAME_LENGTH] = {0};
    char bssid[WIFI_BSSID_LENGTH] = {0};
    if (ReadStr(context, interface, sizeof(interface)) != 0 || ReadStr(context, bssid, sizeof(bssid)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetupWpsPbc(interface, bssid);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetupWpsPin(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char interface[WIFI_P2P_GROUP_IFNAME_LENGTH] = {0};
    char address[WIFI_BSSID_LENGTH] = {0};
    char pinCode[WIFI_PIN_CODE_LENGTH + 1] = {0};
    int resultLen = 0;
    if (ReadStr(context, interface, sizeof(interface)) != 0 || ReadStr(context, address, sizeof(address)) != 0 ||
        ReadStr(context, pinCode, sizeof(pinCode)) != 0 || ReadInt(context, &resultLen) < 0) {
        return HAL_FAILURE;
    }
    if (resultLen <= 0) {
        return HAL_FAILURE;
    }
    char *pResult = (char *)calloc(resultLen, sizeof(char));
    if (pResult == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetupWpsPin(interface, address, pinCode, pResult, resultLen);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteStr(context, pResult);
    }
    WriteEnd(context);
    free(pResult);
    pResult = NULL;
    return HAL_SUCCESS;
}

int RpcP2pRemoveNetwork(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int networkId = 0;
    if (ReadInt(context, &networkId) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pRemoveNetwork(networkId);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pRemoveClient(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char deviceMac[WIFI_BSSID_LENGTH] = {0};
    if (ReadStr(context, deviceMac, sizeof(deviceMac)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pRemoveGroupClient(deviceMac);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pListNetworks(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    P2pNetworkList infoList;
    if (memset_s(&infoList, sizeof(infoList), 0, sizeof(infoList)) != EOK) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pListNetworks(&infoList);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, infoList.infoNum);
        for (int i = 0; i < infoList.infoNum; i++) {
            WriteInt(context, infoList.infos[i].id);
            WriteStr(context, infoList.infos[i].ssid);
            WriteStr(context, infoList.infos[i].bssid);
            WriteStr(context, infoList.infos[i].flags);
        }
    }
    WriteEnd(context);
    free(infoList.infos);
    infoList.infos = NULL;
    return HAL_SUCCESS;
}

int RpcP2pSetGroupMaxIdle(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char interface[WIFI_P2P_GROUP_IFNAME_LENGTH] = {0};
    int maxtime = 0;
    if (ReadStr(context, interface, sizeof(interface)) != 0 || ReadInt(context, &maxtime) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetGroupMaxIdle(interface, maxtime);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetPowerSave(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char interface[WIFI_P2P_GROUP_IFNAME_LENGTH] = {0};
    int enable = 0;
    if (ReadStr(context, interface, sizeof(interface)) != 0 || ReadInt(context, &enable) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetPowerSave(interface, enable);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetWfdEnable(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int enable = 0;
    if (ReadInt(context, &enable) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetWfdEnable(enable);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetWfdDeviceConfig(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char conf[WIFI_P2P_WFD_DEVICE_CONF_LENGTH] = {0};
    if (ReadStr(context, conf, sizeof(conf)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetWfdDeviceConfig(conf);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pStartFind(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int timeout = 0;
    if (ReadInt(context, &timeout) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pStartFind(timeout);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pStopFind(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pStopFind();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetExtListen(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int enable = 0;
    int period = 0;
    int interval = 0;
    if (ReadInt(context, &enable) < 0 || ReadInt(context, &period) < 0 || ReadInt(context, &interval) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetExtListen(enable, period, interval);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetListenChannel(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int channel = 0;
    int regClass = 0;
    if (ReadInt(context, &channel) < 0 || ReadInt(context, &regClass) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetListenChannel(channel, regClass);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pConnect(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    P2pConnectInfo info;
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return HAL_FAILURE;
    }
    if (ReadInt(context, &info.mode) < 0 || ReadInt(context, &info.provdisc) < 0 ||
        ReadInt(context, &info.goIntent) < 0 || ReadInt(context, &info.persistent) < 0 ||
        ReadStr(context, info.peerDevAddr, sizeof(info.peerDevAddr)) != 0 ||
        ReadStr(context, info.pin, sizeof(info.pin)) != 0) {
        return HAL_FAILURE;
    }
    int flag = 0;
    if (info.provdisc == HAL_WPS_METHOD_DISPLAY && strcmp(info.pin, "pin") == 0) {
        flag = 1;
    }
    WifiErrorNo err = P2pConnect(&info);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS && flag) {
        WriteStr(context, info.pin);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pCancelConnect(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pCancelConnect();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pProvisionDiscovery(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char bssid[WIFI_BSSID_LENGTH] = {0};
    int mode = 0;
    if (ReadStr(context, bssid, sizeof(bssid)) != 0 || ReadInt(context, &mode) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pProvisionDiscovery(bssid, mode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pAddGroup(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int isPersistent = 0;
    int networkId = 0;
    int freq = 0;
    if (ReadInt(context, &isPersistent) < 0 || ReadInt(context, &networkId) < 0 || ReadInt(context, &freq) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pAddGroup(isPersistent, networkId, freq);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pRemoveGroup(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char interface[WIFI_P2P_GROUP_IFNAME_LENGTH] = {0};
    if (ReadStr(context, interface, sizeof(interface)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pRemoveGroup(interface);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pInvite(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int persistent = 0;
    char peerBssid[WIFI_BSSID_LENGTH] = {0};
    char goBssid[WIFI_BSSID_LENGTH] = {0};
    char ifName[WIFI_IFACE_NAME_MAXLEN] = {0};
    if (ReadInt(context, &persistent) < 0 || ReadStr(context, peerBssid, sizeof(peerBssid)) != 0 ||
        ReadStr(context, goBssid, sizeof(goBssid)) != 0 || ReadStr(context, ifName, sizeof(ifName)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pInvite(persistent, peerBssid, goBssid, ifName);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pReinvoke(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int networkId = 0;
    char bssid[WIFI_BSSID_LENGTH] = {0};
    if (ReadInt(context, &networkId) < 0 || ReadStr(context, bssid, sizeof(bssid)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pReinvoke(networkId, bssid);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pGetGroupCapability(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char bssid[WIFI_BSSID_LENGTH] = {0};
    if (ReadStr(context, bssid, sizeof(bssid)) != 0) {
        return HAL_FAILURE;
    }
    int capacity = 0;
    WifiErrorNo err = P2pGetGroupCapability(bssid, &capacity);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, capacity);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pAddService(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    P2pServiceInfo argv;
    if (memset_s(&argv, sizeof(argv), 0, sizeof(argv)) != EOK) {
        return HAL_FAILURE;
    }
    if (ReadInt(context, &argv.mode) < 0) {
        return HAL_FAILURE;
    }
    if (!argv.mode) {
        if (ReadInt(context, &argv.version) < 0 || ReadStr(context, argv.name, sizeof(argv.name)) != 0) {
            return HAL_FAILURE;
        }
    } else {
        if (ReadStr(context, argv.query, sizeof(argv.query)) != 0 ||
            ReadStr(context, argv.resp, sizeof(argv.resp)) != 0) {
            return HAL_FAILURE;
        }
    }
    WifiErrorNo err = P2pAddService(&argv);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pRemoveService(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    P2pServiceInfo argv;
    if (memset_s(&argv, sizeof(argv), 0, sizeof(argv)) != EOK) {
        return HAL_FAILURE;
    }
    if (ReadInt(context, &argv.mode) < 0) {
        return HAL_FAILURE;
    }
    if (!argv.mode) {
        if (ReadInt(context, &argv.version) < 0 || ReadStr(context, argv.name, sizeof(argv.name)) != 0) {
            return HAL_FAILURE;
        }
    } else {
        if (ReadStr(context, argv.query, sizeof(argv.query)) != 0) {
            return HAL_FAILURE;
        }
    }
    WifiErrorNo err = P2pRemoveService(&argv);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pReqServiceDiscovery(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char bssid[WIFI_BSSID_LENGTH] = {0};
    if (ReadStr(context, bssid, sizeof(bssid)) != 0) {
        return HAL_FAILURE;
    }
    char discoverinfo[WIFI_P2P_SERVE_DISCOVER_MSG_LENGTH] = {0};
    char *pDiscoverInfo = NULL;
    int len = ReadStr(context, discoverinfo, sizeof(discoverinfo));
    if (len < 0) {
        return HAL_FAILURE;
    } else if (len > 0) {
        pDiscoverInfo = (char *)calloc(len + 1, sizeof(char));
        if (pDiscoverInfo == NULL) {
            return HAL_FAILURE;
        }
        if (ReadStr(context, pDiscoverInfo, len + 1) != 0) {
            free(pDiscoverInfo);
            pDiscoverInfo = NULL;
            return HAL_FAILURE;
        }
    }
    int retSize = 0;
    if (ReadInt(context, &retSize) < 0 || retSize <= 0) {
        free(pDiscoverInfo);
        pDiscoverInfo = NULL;
        return HAL_FAILURE;
    }
    char *pRetBuf = (char *)calloc(retSize, sizeof(char));
    if (pRetBuf == NULL) {
        free(pDiscoverInfo); /* free(NULL) is ok, so here no need to judge pDiscoverInfo != NULL */
        pDiscoverInfo = NULL;
        return HAL_FAILURE;
    }
    WifiErrorNo err =
        P2pReqServiceDiscovery(bssid, ((pDiscoverInfo == NULL) ? discoverinfo : pDiscoverInfo), pRetBuf, retSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteStr(context, pRetBuf);
    }
    WriteEnd(context);
    free(pRetBuf);
    pRetBuf = NULL;
    free(pDiscoverInfo);
    pDiscoverInfo = NULL;
    return HAL_SUCCESS;
}

int RpcP2pCancelServiceDiscovery(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char id[WIFI_P2P_SERVER_DISCOVERY_SEQUENCE_LENGTH] = {0};
    if (ReadStr(context, id, sizeof(id)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pCancelServiceDiscovery(id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetMiracastType(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int type = 0;
    if (ReadInt(context, &type) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetMiracastType(type);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pRespServerDiscovery(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    P2pServDiscReqInfo info;
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return HAL_FAILURE;
    }
    if (ReadInt(context, &info.freq) < 0 || ReadInt(context, &info.dialogToken) < 0 ||
        ReadStr(context, info.mac, sizeof(info.mac)) != 0) {
        return HAL_FAILURE;
    }
    int tlvsLen = ReadStr(context, NULL, 0);
    if (tlvsLen <= 0) {
        return HAL_FAILURE;
    }
    info.tlvs = (char *)calloc(tlvsLen + 1, sizeof(char));
    if (info.tlvs == NULL) {
        return HAL_FAILURE;
    }
    if (ReadStr(context, info.tlvs, tlvsLen + 1) != 0) {
        free(info.tlvs);
        info.tlvs = NULL;
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pRespServerDiscovery(&info);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(info.tlvs);
    info.tlvs = NULL;
    return HAL_SUCCESS;
}

int RpcP2pSetServDiscExternal(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = 0;
    if (ReadInt(context, &mode) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetServDiscExternal(mode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pSetPersistentReconnect(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = 0;
    if (ReadInt(context, &mode) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pSetPersistentReconnect(mode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pGetPeer(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char bssid[WIFI_BSSID_LENGTH] = {0};
    P2pDeviceInfo peerInfo;
    if (memset_s(&peerInfo, sizeof(peerInfo), 0, sizeof(peerInfo)) != EOK ||
        ReadStr(context, bssid, sizeof(bssid)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pGetPeer(bssid, &peerInfo);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteStr(context, peerInfo.p2pDeviceAddress);
        WriteStr(context, peerInfo.deviceName);
        WriteStr(context, peerInfo.primaryDeviceType);
        WriteInt(context, peerInfo.configMethods);
        WriteInt(context, peerInfo.deviceCapabilities);
        WriteInt(context, peerInfo.groupCapabilities);
        WriteStr(context, peerInfo.operSsid);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pGetChba0Freq(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int chba0Freq = 0;
    WifiErrorNo err = P2pGetChba0Freq(&chba0Freq);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, chba0Freq);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pGetFrequencies(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int band = 0;
    int maxSize = 0;
    if (ReadInt(context, &band) < 0 || ReadInt(context, &maxSize) < 0 || maxSize <= 0
        || maxSize > WIFI_IDL_GET_MAX_BANDS) {
        return HAL_FAILURE;
    }
    int *frequencies = (int *)calloc(maxSize, sizeof(int));
    if (frequencies == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pGetFrequencies(band, frequencies, &maxSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, maxSize);
        for (int i = 0; i < maxSize; ++i) {
            WriteInt(context, frequencies[i]);
        }
    }
    WriteEnd(context);
    free(frequencies);
    frequencies = NULL;
    return HAL_SUCCESS;
}

int RpcP2pSetGroupConfig(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int networkId = 0;
    int size = 0;
    if (ReadInt(context, &networkId) < 0 || ReadInt(context, &size) < 0 || size <= 0 || size > GROUP_CONFIG_END_POS) {
        return HAL_FAILURE;
    }
    P2pGroupConfig *confs = (P2pGroupConfig *)calloc(size, sizeof(P2pGroupConfig));
    if (confs == NULL) {
        return HAL_FAILURE;
    }
    int flag = 0;
    for (int i = 0; i < size; ++i) {
        if (ReadInt(context, (int *)&(confs[i].cfgParam)) < 0 ||
            ReadStr(context, confs[i].cfgValue, sizeof(confs[i].cfgValue)) != 0) {
            flag = 1;
            break;
        }
    }
    WifiErrorNo err = WIFI_HAL_FAILED;
    if (flag == 0) {
        err = P2pSetGroupConfig(networkId, confs, size);
    }
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(confs);
    confs = NULL;
    return HAL_SUCCESS;
}

int RpcP2pGetGroupConfig(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int networkId = 0;
    int size = 0;
    if (ReadInt(context, &networkId) < 0 || ReadInt(context, &size) < 0 || size <= 0 || size > GROUP_CONFIG_END_POS) {
        return HAL_FAILURE;
    }
    P2pGroupConfig *confs = (P2pGroupConfig *)calloc(size, sizeof(P2pGroupConfig));
    if (confs == NULL) {
        return HAL_FAILURE;
    }
    int flag = 0;
    for (int i = 0; i < size; ++i) {
        if (ReadInt(context, (int *)&(confs[i].cfgParam)) < 0) {
            flag = 1;
            break;
        }
    }
    WifiErrorNo err = WIFI_HAL_FAILED;
    if (flag == 0) {
        err = P2pGetGroupConfig(networkId, confs, size);
    }
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        for (int i = 0; i < size; i++) {
            WriteStr(context, confs[i].cfgValue);
        }
    }
    WriteEnd(context);
    free(confs);
    confs = NULL;
    return HAL_SUCCESS;
}

int RpcP2pAddNetwork(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int networkId = 0;
    WifiErrorNo err = P2pAddNetwork(&networkId);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, networkId);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcP2pHid2dConnect(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }

    Hid2dConnectInfo info;
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return HAL_FAILURE;
    }
    if (ReadStr(context, info.ssid, sizeof(info.ssid)) != 0 ||
        ReadStr(context, info.bssid, sizeof(info.bssid)) != 0 ||
        ReadStr(context, info.passphrase, sizeof(info.passphrase)) != 0 ||
        ReadInt(context, &info.frequency) < 0 ||
        ReadInt(context, &info.isLegacyGo) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = P2pHid2dConnect(&info);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}
