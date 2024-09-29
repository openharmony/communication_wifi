/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_WLAN_HOSTAPD_V1_0_IHOSTAPDCALLBACK_H
#define OHOS_HDI_WLAN_HOSTAPD_V1_0_IHOSTAPDCALLBACK_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>
#include "wlan/hostapd/v1_0/hostapd_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfRemoteService;

#define IHOSTAPDCALLBACK_INTERFACE_DESC "ohos.hdi.wlan.hostapd.v1_0.IHostapdCallback"

#define IHOSTAPD_CALLBACK_MAJOR_VERSION 1
#define IHOSTAPD_CALLBACK_MINOR_VERSION 0

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

#ifndef HDI_CHECK_VALUE_RETURN
#define HDI_CHECK_VALUE_RETURN(lv, compare, rv, ret) do { \
    if ((lv) compare (rv)) { \
        return ret; \
    } \
} while (false)
#endif

#ifndef HDI_CHECK_VALUE_RET_GOTO
#define HDI_CHECK_VALUE_RET_GOTO(lv, compare, rv, ret, value, table) do { \
    if ((lv) compare (rv)) { \
        ret = value; \
        goto table; \
    } \
} while (false)
#endif

enum {
    CMD_HOSTAPD_CALLBACK_GET_VERSION = 0,
    CMD_HOSTAPD_CALLBACK_ON_EVENT_STA_JOIN = 1,
    CMD_HOSTAPD_CALLBACK_ON_EVENT_AP_STATE = 2,
    CMD_HOSTAPD_CALLBACK_ON_EVENT_HOST_APD_NOTIFY = 3,
};

struct IHostapdCallback {
    int32_t (*OnEventStaJoin)(struct IHostapdCallback *self, const struct HdiApCbParm* apCbParm, const char* ifName);

    int32_t (*OnEventApState)(struct IHostapdCallback *self, const struct HdiApCbParm* apCbParm, const char* ifName);

    int32_t (*OnEventHostApdNotify)(struct IHostapdCallback *self, const char* notifyParam, const char* ifName);

    int32_t (*GetVersion)(struct IHostapdCallback *self, uint32_t* majorVer, uint32_t* minorVer);

    struct HdfRemoteService* (*AsObject)(struct IHostapdCallback *self);
};

// no external method used to create client object, it only support ipc mode
struct IHostapdCallback *IHostapdCallbackGet(struct HdfRemoteService *remote);

// external method used to release client object, it support ipc and passthrought mode
void IHostapdCallbackRelease(struct IHostapdCallback *instance);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_WLAN_HOSTAPD_V1_0_IHOSTAPDCALLBACK_H