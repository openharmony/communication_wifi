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

#include "wifi_hal_crpc_common.h"
#include "serial.h"
#include "wifi_hal_crpc_base.h"
#include "wifi_hal_sta_interface.h"
#include "wifi_hal_ap_interface.h"
#include "wifi_hal_p2p_interface.h"
#include "wifi_hal_define.h"
#include "wifi_hostapd_hal.h"

int RpcRegisterEventCallback(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int num = 0;
    if (ReadInt(context, &num) < 0) {
        return HAL_FAILURE;
    }
    int *events = ReadIntArray(context, num);
    if (events == NULL) {
        return HAL_FAILURE;
    }
    for (int i = 0; i < num; ++i) {
        RegisterCallback(server, events[i], context);
    }
    WriteBegin(context, 0);
    WriteInt(context, WIFI_HAL_SUCCESS);
    WriteEnd(context);
    free(events);
    events = NULL;
    return HAL_SUCCESS;
}

int RpcUnRegisterEventCallback(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    int num = 0;
    if (ReadInt(context, &num) < 0) {
        return HAL_FAILURE;
    }
    int *events = ReadIntArray(context, num);
    if (events == NULL) {
        return HAL_FAILURE;
    }
    for (int i = 0; i < num; ++i) {
        UnRegisterCallback(server, events[i], context);
    }
    WriteBegin(context, 0);
    WriteInt(context, WIFI_HAL_SUCCESS);
    WriteEnd(context);
    free(events);
    events = NULL;
    return HAL_SUCCESS;
}

int RpcNotifyClear(RpcServer *server, Context *context)
{
    if (server == NULL || context == NULL) {
        return HAL_FAILURE;
    }
    ForceStop();
    for (int id = 0; id < AP_MAX_INSTANCE; id++) {
        StopSoftAp(id);
    }
    P2pForceStop();
    WriteBegin(context, 0);
    WriteInt(context, 0);
    WriteEnd(context);
    return HAL_SUCCESS;
}