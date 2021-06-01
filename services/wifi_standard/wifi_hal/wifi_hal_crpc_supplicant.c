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

#include "wifi_hal_crpc_supplicant.h"
#include "wifi_hal_sta_interface.h"
#include "wifi_hal_define.h"

int RpcStartSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    WifiErrorNo err = StartSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return 0;
}

int RpcStopSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    WifiErrorNo err = StopSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return 0;
}

int RpcConnectSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    WifiErrorNo err = ConnectSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return 0;
}

int RpcDisconnectSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    WifiErrorNo err = DisconnectSupplicant();
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return 0;
}

int RpcRequestToSupplicant(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    int maxSize = 0;
    if (ReadInt(context, &maxSize) < 0) {
        return -1;
    }
    int len = maxSize + 1;
    unsigned char *buf = (unsigned char *)calloc(len, sizeof(unsigned char));
    if (buf == NULL) {
        return -1;
    }
    if (ReadUStr(context, buf, len) != 0) {
        free(buf);
        return -1;
    }
    WifiErrorNo err = RequestToSupplicant(buf, maxSize);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    free(buf);
    return 0;
}

int RpcSetPowerSave(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    int mode = 0;
    if (ReadInt(context, &mode) < 0) {
        return -1;
    }

    WifiErrorNo statusCode = SetPowerSave(mode);
    WriteBegin(context, 0);
    WriteInt(context, (int)statusCode);
    WriteEnd(context);
    return 0;
}

int RpcWpaSetCountryCode(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    char countryCode[WIFI_COUNTRY_CODE_MAXLEN] = {0};
    int ret = ReadStr(context, countryCode, WIFI_COUNTRY_CODE_MAXLEN);
    int codeSize = 0;
    if (ret < 0) {
        return -1;
    } else if (ret >= 0) {
        codeSize = strlen(countryCode);
    }
    if (codeSize == 0) {
        return -1;
    }
    WifiErrorNo err = WpaSetCountryCode(countryCode);
    WriteBegin(context, 0);
    WriteInt(context, err);
    WriteEnd(context);
    return 0;
}

int RpcWpaGetCountryCode(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return -1;
    }
    char *countryCode = (char *)calloc(WIFI_COUNTRY_CODE_MAXLEN, sizeof(char));
    if (countryCode == NULL) {
        return -1;
    }
    WifiErrorNo err = WpaGetCountryCode(countryCode, WIFI_COUNTRY_CODE_MAXLEN);
    WriteBegin(context, 0);
    WriteInt(context, err);
    if (err == 0) {
        WriteStr(context, countryCode);
    }
    WriteEnd(context);
    free(countryCode);
    return 0;
}
