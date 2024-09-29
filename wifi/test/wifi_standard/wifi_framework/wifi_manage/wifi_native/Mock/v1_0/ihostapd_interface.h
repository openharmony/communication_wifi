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

#ifndef OHOS_HDI_WLAN_HOSTAPD_V1_0_IHOSTAPDINTERFACE_H
#define OHOS_HDI_WLAN_HOSTAPD_V1_0_IHOSTAPDINTERFACE_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>
#include "wlan/hostapd/v1_0/hostapd_types.h"
#include "wlan/hostapd/v1_0/ihostapd_callback.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HdfRemoteService;

#define IHOSTAPDINTERFACE_INTERFACE_DESC "ohos.hdi.wlan.hostapd.v1_0.IHostapdInterface"

#define IHOSTAPD_INTERFACE_MAJOR_VERSION 1
#define IHOSTAPD_INTERFACE_MINOR_VERSION 0

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
    CMD_HOSTAPD_INTERFACE_GET_VERSION = 0,
    CMD_HOSTAPD_INTERFACE_START_AP = 1,
    CMD_HOSTAPD_INTERFACE_START_AP_WITH_CMD = 2,
    CMD_HOSTAPD_INTERFACE_STOP_AP = 3,
    CMD_HOSTAPD_INTERFACE_ENABLE_AP = 4,
    CMD_HOSTAPD_INTERFACE_DISABLE_AP = 5,
    CMD_HOSTAPD_INTERFACE_SET_AP_PASSWD = 6,
    CMD_HOSTAPD_INTERFACE_SET_AP_NAME = 7,
    CMD_HOSTAPD_INTERFACE_SET_AP_WPA_VALUE = 8,
    CMD_HOSTAPD_INTERFACE_SET_AP_BAND = 9,
    CMD_HOSTAPD_INTERFACE_SET_AP80211N = 10,
    CMD_HOSTAPD_INTERFACE_SET_AP_WMM = 11,
    CMD_HOSTAPD_INTERFACE_SET_AP_CHANNEL = 12,
    CMD_HOSTAPD_INTERFACE_SET_AP_MAX_CONN = 13,
    CMD_HOSTAPD_INTERFACE_RELOAD_AP_CONFIG_INFO = 14,
    CMD_HOSTAPD_INTERFACE_SET_MAC_FILTER = 15,
    CMD_HOSTAPD_INTERFACE_DEL_MAC_FILTER = 16,
    CMD_HOSTAPD_INTERFACE_GET_STA_INFOS = 17,
    CMD_HOSTAPD_INTERFACE_DISASSOCIATE_STA = 18,
    CMD_HOSTAPD_INTERFACE_REGISTER_EVENT_CALLBACK = 19,
    CMD_HOSTAPD_INTERFACE_UNREGISTER_EVENT_CALLBACK = 20,
    CMD_HOSTAPD_INTERFACE_HOST_APD_SHELL_CMD = 21,
};

struct IHostapdInterface {
    int32_t (*StartAp)(struct IHostapdInterface *self);

    int32_t (*StartApWithCmd)(struct IHostapdInterface *self, const char* ifName, int32_t id);

    int32_t (*StopAp)(struct IHostapdInterface *self);

    int32_t (*EnableAp)(struct IHostapdInterface *self, const char* ifName, int32_t id);

    int32_t (*DisableAp)(struct IHostapdInterface *self, const char* ifName, int32_t id);

    int32_t (*SetApPasswd)(struct IHostapdInterface *self, const char* ifName, const char* pass, int32_t id);

    int32_t (*SetApName)(struct IHostapdInterface *self, const char* ifName, const char* name, int32_t id);

    int32_t (*SetApWpaValue)(struct IHostapdInterface *self, const char* ifName, int32_t securityType, int32_t id);

    int32_t (*SetApBand)(struct IHostapdInterface *self, const char* ifName, int32_t band, int32_t id);

    int32_t (*SetAp80211n)(struct IHostapdInterface *self, const char* ifName, int32_t value, int32_t id);

    int32_t (*SetApWmm)(struct IHostapdInterface *self, const char* ifName, int32_t value, int32_t id);

    int32_t (*SetApChannel)(struct IHostapdInterface *self, const char* ifName, int32_t channel, int32_t id);

    int32_t (*SetApMaxConn)(struct IHostapdInterface *self, const char* ifName, int32_t maxConn, int32_t id);

    int32_t (*ReloadApConfigInfo)(struct IHostapdInterface *self, const char* ifName, int32_t id);

    int32_t (*SetMacFilter)(struct IHostapdInterface *self, const char* ifName, const char* mac, int32_t id);

    int32_t (*DelMacFilter)(struct IHostapdInterface *self, const char* ifName, const char* mac, int32_t id);

    int32_t (*GetStaInfos)(struct IHostapdInterface *self, const char* ifName, char* buf, uint32_t bufLen, int32_t size,
         int32_t id);

    int32_t (*DisassociateSta)(struct IHostapdInterface *self, const char* ifName, const char* mac, int32_t id);

    int32_t (*RegisterEventCallback)(struct IHostapdInterface *self, struct IHostapdCallback* cbFunc,
         const char* ifName);

    int32_t (*UnregisterEventCallback)(struct IHostapdInterface *self, struct IHostapdCallback* cbFunc,
         const char* ifName);

    int32_t (*HostApdShellCmd)(struct IHostapdInterface *self, const char* ifName, const char* cmd);

    int32_t (*GetVersion)(struct IHostapdInterface *self, uint32_t* majorVer, uint32_t* minorVer);

    struct HdfRemoteService* (*AsObject)(struct IHostapdInterface *self);
};

// external method used to create client object, it support ipc and passthrought mode
struct IHostapdInterface *IHostapdInterfaceGet(bool isStub);
struct IHostapdInterface *IHostapdInterfaceGetInstance(const char *serviceName, bool isStub);

// external method used to create release object, it support ipc and passthrought mode
void IHostapdInterfaceRelease(struct IHostapdInterface *instance, bool isStub);
void IHostapdInterfaceReleaseInstance(const char *serviceName, struct IHostapdInterface *instance, bool isStub);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_WLAN_HOSTAPD_V1_0_IHOSTAPDINTERFACE_H