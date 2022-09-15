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

#include "wifi_hal_crpc_ap.h"
#include <securec.h>
#include "serial.h"
#include "wifi_hdi_ap_impl.h"
#include "wifi_hal_ap_interface.h"
#include "wifi_hal_define.h"

int RpcStartSoftAp(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int id = 0;
    if (ReadInt(context, &id) < 0 || id < 0) {
        return HAL_FAILURE;
    }

    WifiErrorNo err = StartSoftAp(id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcStopSoftAp(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int id = 0;
    if (ReadInt(context, &id) < 0 || id < 0) {
        return HAL_FAILURE;
    }

    WifiErrorNo err = StopSoftAp(id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcSetHostapdConfig(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int id = 0;
    HostapdConfig config;
    if (memset_s(&config, sizeof(config), 0, sizeof(config)) != EOK) {
        return HAL_FAILURE;
    }

    if (ReadStr(context, config.ssid, sizeof(config.ssid)) != 0 || ReadInt(context, &config.ssidLen) < 0 ||
        ReadStr(context, config.preSharedKey, sizeof(config.preSharedKey)) != 0 ||
        ReadInt(context, &config.preSharedKeyLen) < 0 || ReadInt(context, &config.securityType) < 0 ||
        ReadInt(context, &config.band) < 0 || ReadInt(context, &config.channel) < 0 ||
        ReadInt(context, &config.maxConn) < 0 || ReadInt(context, &id) < 0 || id < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = SetHostapdConfig(&config, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcGetStaInfos(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int maxSize = 0;
    int id = 0;
    if (ReadInt(context, &maxSize) < 0 || maxSize <= 0 || ReadInt(context, &id) < 0 || id < 0) {
        return HAL_FAILURE;
    }
    char *infos = (char *)calloc(maxSize, sizeof(char));
    if (infos == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = GetStaInfos(infos, &maxSize, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, maxSize);
        WriteStr(context, infos);
    }
    WriteEnd(context);
    free(infos);
    infos = NULL;
    return HAL_SUCCESS;
}

int RpcSetCountryCode(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char countryCode[WIFI_COUNTRY_CODE_MAXLEN + 1] = {0};
    int id = 0;
    if (ReadStr(context, countryCode, sizeof(countryCode)) != 0 || ReadInt(context, &id) < 0 || id < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = SetCountryCode(countryCode, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcSetMacFilter(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int lenMac = 0;
    int id = 0;
    if (ReadInt(context, &lenMac) < 0 || lenMac <= 0) {
        return HAL_FAILURE;
    }
    int len = lenMac + 1;
    unsigned char *mac = (unsigned char *)calloc(len, sizeof(unsigned char));
    if (mac == NULL) {
        return HAL_FAILURE;
    }
    if (ReadUStr(context, mac, len) != 0 || ReadInt(context, &id) < 0 || id < 0) {
        free(mac);
        mac = NULL;
        return HAL_FAILURE;
    }
    WifiErrorNo err = SetMacFilter(mac, lenMac, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(mac);
    mac = NULL;
    return HAL_SUCCESS;
}

int RpcDelMacFilter(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int lenMac = 0;
    int id = 0;
    if (ReadInt(context, &lenMac) < 0 || lenMac <= 0) {
        return HAL_FAILURE;
    }
    int len = lenMac + 1;
    unsigned char *mac = (unsigned char *)calloc(len, sizeof(unsigned char));
    if (mac == NULL) {
        return HAL_FAILURE;
    }
    if (ReadUStr(context, mac, len) != 0 || ReadInt(context, &id) < 0 || id < 0) {
        free(mac);
        mac = NULL;
        return HAL_FAILURE;
    }
    WifiErrorNo err = DelMacFilter(mac, lenMac, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(mac);
    mac = NULL;
    return HAL_SUCCESS;
}

int RpcDisassociateSta(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int lenMac = 0;
    int id = 0;
    if (ReadInt(context, &lenMac) < 0 || lenMac <= 0) {
        return HAL_FAILURE;
    }
    int len = lenMac + 1;
    unsigned char *mac = (unsigned char *)calloc(len, sizeof(unsigned char));
    if (mac == NULL) {
        return HAL_FAILURE;
    }

    if (ReadUStr(context, mac, len) != 0 || ReadInt(context, &id) < 0 || id < 0) {
        free(mac);
        mac = NULL;
        return HAL_FAILURE;
    }
    WifiErrorNo err = DisassociateSta(mac, lenMac, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(mac);
    mac = NULL;
    return HAL_SUCCESS;
}

int RpcGetValidFrequenciesForBand(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int band = 0;
    int size = 0;
    int id = 0;
    if (ReadInt(context, &band) < 0 || ReadInt(context, &size) < 0  ||
        ReadInt(context, &id) < 0 || id < 0) {
        return HAL_FAILURE;
    }
    if (size <= 0) {
        return HAL_FAILURE;
    }
    int *frequencies = (int *)calloc(size, sizeof(int));
    if (frequencies == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = GetValidFrequenciesForBand(band, frequencies, &size, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, size);
        for (int i = 0; i < size; ++i) {
            WriteInt(context, frequencies[i]);
        }
    }
    WriteEnd(context);
    free(frequencies);
    frequencies = NULL;
    return HAL_SUCCESS;
}

int RpcSetPowerModel(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = -1;
    if (ReadInt(context, &mode) < 0) {
        return HAL_FAILURE;
    }
    int id = 0;
    if (ReadInt(context, &id) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = WifiSetPowerModel(mode, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcGetPowerModel(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = -1;
    int id = 0;
    if (ReadInt(context, &id) < 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = WifiGetPowerModel(&mode, id);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteInt(context, mode);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}
