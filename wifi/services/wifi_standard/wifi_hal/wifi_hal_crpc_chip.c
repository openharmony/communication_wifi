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

#include "wifi_hal_crpc_chip.h"
#include <securec.h>
#include "serial.h"
#include "wifi_hal_chip_interface.h"
#include "wifi_hal_define.h"

int RpcGetWifiChip(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int chipId = 0;
    if (ReadInt(context, &chipId) < 0) {
        return HAL_FAILURE;
    }
    WifiChip wifiChip;
    if (memset_s(&wifiChip, sizeof(wifiChip), 0, sizeof(wifiChip)) != EOK) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = GetWifiChip(chipId, &wifiChip);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, wifiChip.chip);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcGetWifiChipIds(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int maxSize = 0;
    if (ReadInt(context, &maxSize) < 0) {
        return HAL_FAILURE;
    }
    if (maxSize <= 0) {
        return HAL_FAILURE;
    }
    uint8_t *chipIds = (uint8_t *)calloc(maxSize * sizeof(int), sizeof(uint8_t));
    if (chipIds == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = GetWifiChipIds(chipIds, &maxSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, maxSize);
        for (int i = 0; i < maxSize; ++i) {
            WriteInt(context, chipIds[i]);
        }
    }
    WriteEnd(context);
    free(chipIds);
    chipIds = NULL;
    return HAL_SUCCESS;
}

int RpcGetChipId(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int chipId = 0;
    WifiErrorNo err = GetChipId(&chipId);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, chipId);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcCreateIface(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int type = 0;
    if (ReadInt(context, &type) < 0) {
        return HAL_FAILURE;
    }
    WifiIface wifiIface;
    if (memset_s(&wifiIface, sizeof(wifiIface), 0, sizeof(wifiIface)) != EOK) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = CreateIface(type, &wifiIface);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, wifiIface.index);
        WriteInt(context, wifiIface.type);
        WriteStr(context, wifiIface.name);
        WriteStr(context, wifiIface.macAddr);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcGetIface(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiIface wifiIface;
    if (memset_s(&wifiIface, sizeof(wifiIface), 0, sizeof(wifiIface)) != EOK) {
        return HAL_FAILURE;
    }
    char ifname[WIFI_IFACE_NAME_MAXLEN] = {0};
    char *pstr = NULL;
    int ret = ReadStr(context, ifname, WIFI_IFACE_NAME_MAXLEN);
    if (ret < 0) {
        return HAL_FAILURE;
    } else if (ret > 0) {
        int len = ret + 1;
        pstr = (char *)calloc(len, sizeof(char));
        if (pstr == NULL) {
            return HAL_FAILURE;
        }
        ReadStr(context, pstr, len);
    }
    WifiErrorNo err = GetIface((pstr == NULL) ? ifname : pstr, &wifiIface);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, wifiIface.index);
        WriteInt(context, wifiIface.type);
        WriteStr(context, wifiIface.name);
        WriteStr(context, wifiIface.macAddr);
    }
    WriteEnd(context);
    if (pstr != NULL) {
        free(pstr);
        pstr = NULL;
    }
    return HAL_SUCCESS;
}

int RpcGetIfaceNames(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int type = 0;
    int size = 0;
    if (ReadInt(context, &type) < 0 || ReadInt(context, &size) < 0 || size <= 0) {
        return HAL_FAILURE;
    }
    char *ifname = (char *)calloc(size, sizeof(char));
    if (ifname == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = GetIfaceNames(type, ifname, size);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteStr(context, ifname);
    }
    WriteEnd(context);
    free(ifname);
    ifname = NULL;
    return HAL_SUCCESS;
}

int RpcRemoveIface(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char ifname[WIFI_IFACE_NAME_MAXLEN] = {0};
    char *pstr = NULL;
    int ret = ReadStr(context, ifname, WIFI_IFACE_NAME_MAXLEN);
    if (ret < 0) {
        return HAL_FAILURE;
    } else if (ret > 0) {
        int len = ret + 1;
        pstr = (char *)calloc(len, sizeof(char));
        if (pstr == NULL) {
            return HAL_FAILURE;
        }
        ReadStr(context, pstr, len);
    }
    WifiErrorNo err = RemoveIface((pstr == NULL) ? ifname : pstr);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    if (pstr != NULL) {
        free(pstr);
        pstr = NULL;
    }
    return HAL_SUCCESS;
}

int RpcGetCapabilities(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    uint32_t capabilities = 0;
    WifiErrorNo err = GetCapabilities(&capabilities);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, capabilities);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcGetSupportedComboModes(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int maxSize = 0;
    if (ReadInt(context, &maxSize) < 0 || maxSize <= 0) {
        return HAL_FAILURE;
    }
    int *modes = (int *)calloc(maxSize, sizeof(int));
    if (modes == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = GetSupportedComboModes(modes, &maxSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, maxSize);
        for (int i = 0; i < maxSize; ++i) {
            WriteInt(context, modes[i]);
        }
    }
    WriteEnd(context);
    free(modes);
    modes = NULL;
    return HAL_SUCCESS;
}

int RpcConfigComboModes(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = 0;
    if (ReadInt(context, &mode) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = ConfigComboModes(mode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcGetComboModes(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = 0;
    WifiErrorNo err = GetComboModes(&mode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, mode);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcRequestFirmwareDebugDump(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int maxSize = 0;
    if (ReadInt(context, &maxSize) < 0 || maxSize <= 0) {
        return HAL_FAILURE;
    }

    unsigned char *bytes = (unsigned char *)calloc(maxSize + 1, sizeof(unsigned char));
    if (bytes == NULL) {
        return HAL_FAILURE;
    }

    WifiErrorNo err = RequestFirmwareDebugDump(bytes, &maxSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, maxSize);
        WriteUStr(context, bytes, maxSize);
    }
    WriteEnd(context);
    free(bytes);
    bytes = NULL;
    return HAL_SUCCESS;
}

int RpcIsChipSupportDbdc(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int support = 0;
    WifiErrorNo err = GetIsChipSupportDbdc(&support);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, support);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcIsChipSupportCsa(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int support = 0;
    WifiErrorNo err = GetIsChipSupportCsa(&support);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, support);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcIsChipSupportRadarDetect(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int support = 0;
    WifiErrorNo err = GetIsChipSupportRadarDetect(&support);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, support);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcIsChipSupportDfsChannel(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int support = 0;
    WifiErrorNo err = GetIsChipSupportDfsChannel(&support);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, support);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcIsChipSupportIndoorChannel(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int support = 0;
    WifiErrorNo err = GetIsChipSupportIndoorChannel(&support);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, support);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}