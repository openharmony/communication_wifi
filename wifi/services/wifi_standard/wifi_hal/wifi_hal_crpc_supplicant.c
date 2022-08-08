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

#include "wifi_hal_crpc_supplicant.h"
#include "serial.h"
#include "wifi_hal_sta_interface.h"
#include "wifi_hal_define.h"

int RpcStartSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = StartSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcStopSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = StopSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcConnectSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = ConnectSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcDisconnectSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = DisconnectSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcRequestToSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int maxSize = 0;
    if (ReadInt(context, &maxSize) < 0 || maxSize < 0) {
        return HAL_FAILURE;
    }
    int len = maxSize + 1;
    unsigned char *buf = (unsigned char *)calloc(len, sizeof(unsigned char));
    if (buf == NULL) {
        return HAL_FAILURE;
    }
    if (ReadUStr(context, buf, len) != 0) {
        free(buf);
        buf = NULL;
        return HAL_FAILURE;
    }
    WifiErrorNo err = RequestToSupplicant(buf, maxSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(buf);
    buf = NULL;
    return HAL_SUCCESS;
}

int RpcSetPowerSave(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int mode = 0;
    if (ReadInt(context, &mode) < 0) {
        return HAL_FAILURE;
    }

    WifiErrorNo err = SetPowerSave(mode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcWpaSetCountryCode(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char countryCode[WIFI_COUNTRY_CODE_MAXLEN + 1] = {0};
    if (ReadStr(context, countryCode, sizeof(countryCode)) != 0) {
        return HAL_FAILURE;
    }
    WifiErrorNo err = WpaSetCountryCode(countryCode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return HAL_SUCCESS;
}

int RpcWpaGetCountryCode(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    char countryCode[WIFI_COUNTRY_CODE_MAXLEN + 1] = {0};
    WifiErrorNo err = WpaGetCountryCode(countryCode, WIFI_COUNTRY_CODE_MAXLEN + 1);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == WIFI_HAL_SUCCESS) {
        WriteStr(context, countryCode);
    }
    WriteEnd(context);
    return HAL_SUCCESS;
}
