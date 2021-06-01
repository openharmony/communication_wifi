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
#include "wifi_hal_chip_interface.h"
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "wifi_log.h"
#include "wifi_hal_adapter.h"
#undef LOG_TAG
#define LOG_TAG "WifiHalChipInterface"

WifiIfaceArray *g_wifiIfaceArray = NULL;
unsigned g_kMaxWlanIfaces = 5;

WifiIfaceArray *CreateWifiIfaceArray(int maxIfaces)
{
    if (maxIfaces <= 0) {
        return NULL;
    }

    g_wifiIfaceArray = (WifiIfaceArray *)calloc(1, sizeof(WifiIfaceArray));
    if (g_wifiIfaceArray == NULL) {
        return NULL;
    }
    g_wifiIfaceArray->pos = 0;
    g_wifiIfaceArray->capacity = maxIfaces;
    g_wifiIfaceArray->ifaces = (WifiIface **)calloc(maxIfaces, sizeof(WifiIface *));
    if (g_wifiIfaceArray->ifaces == NULL) {
        free(g_wifiIfaceArray);
        g_wifiIfaceArray = NULL;
        return NULL;
    }
    return g_wifiIfaceArray;
}

void ReleaseWifiIfaceArray(void)
{
    if (g_wifiIfaceArray != NULL) {
        for (int i = 0; i < g_wifiIfaceArray->capacity; ++i) {
            free(g_wifiIfaceArray->ifaces[i]);
        }
        free(g_wifiIfaceArray->ifaces);
        free(g_wifiIfaceArray);
        g_wifiIfaceArray = NULL;
    }
    return;
}

int FindWifiIfaceFromArray(const char *ifname)
{
    if (g_wifiIfaceArray == NULL) {
        g_wifiIfaceArray = CreateWifiIfaceArray(g_kMaxWlanIfaces);
    }
    if (g_wifiIfaceArray == NULL) {
        return -1;
    }
    for (int i = 0; i < g_wifiIfaceArray->pos; ++i) {
        if (strcmp(g_wifiIfaceArray->ifaces[i]->name, ifname) == 0) {
            return i;
        }
    }
    return -1;
}

int PushWifiIfaceIntoArray(WifiIface *face)
{
    if (face == NULL) {
        return -1;
    }
    int pos = FindWifiIfaceFromArray(face->name);
    if (pos >= 0) {
        return 0;
    }
    if (g_wifiIfaceArray == NULL) {
        return -1;
    }
    if (g_wifiIfaceArray->pos >= g_wifiIfaceArray->capacity) {
        return ERROR_CODE_POS_OVERFLOW;
    }
    if (g_wifiIfaceArray->pos < 0) {
        return -1;
    }
    g_wifiIfaceArray->ifaces[g_wifiIfaceArray->pos] = face;
    g_wifiIfaceArray->pos += 1;
    return 0;
}

int RemoveWifiIfaceFromArray(const char *name)
{
    int pos = FindWifiIfaceFromArray(name);
    if (pos < 0) {
        return 0;
    }
    WifiIface *p = g_wifiIfaceArray->ifaces[pos];
    g_wifiIfaceArray->ifaces[pos] = g_wifiIfaceArray->ifaces[g_wifiIfaceArray->pos - 1];
    g_wifiIfaceArray->ifaces[g_wifiIfaceArray->pos - 1] = NULL;
    g_wifiIfaceArray->pos -= 1;
    free(p);
    return 0;
}

WifiErrorNo GetWifiChip(uint8_t id, WifiChip *chip)
{
    LOGI("GetWifiChip() id: %{public}u", id);
    if (chip != NULL) {
        chip->chip = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetWifiChipIds(uint8_t *ids, int32_t *size)
{
    LOGI("GetWifiChipIds()");
    if (ids != NULL && size != NULL) {
        LOGD("input size %{public}d", *size);
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetChipId(int32_t *id)
{
    LOGI("GetChipId()");
    if (id != NULL) {
        *id = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo CreateIface(int32_t type, WifiIface *iface)
{
    LOGI("CreateIface() type: %{public}d", type);
    const int bufferSize = 8;
    char name[bufferSize] = {0};
    if (strcpy_s(iface->name, sizeof(iface->name), name) != EOK) {
        return WIFI_HAL_FAILED;
    }

    iface->type = type;
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetIface(const char *ifname, WifiIface *iface)
{
    if ((NULL == ifname) || (NULL == iface)) {
        return WIFI_HAL_FAILED;
    }
    LOGI("GetIface() ifname: %s", ifname);

    WifiIface tmpIface;
    tmpIface.index = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    tmpIface.type = 0;
    tmpIface.name[0] = '\0';
    if (strcpy_s(tmpIface.macAddr, sizeof(tmpIface.macAddr), "00:00:00:00:00:00") != EOK) {
        return WIFI_HAL_FAILED;
    }

    iface = &tmpIface;
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetIfaceNames(int32_t type, char *ifaces, int32_t size)
{
    LOGI("GetIfaceNames() type: %{public}d size: %{public}d", type, size);
    if (ifaces != NULL) {
        ifaces[0] = '\0'; /* fixed compile error, -Werror,-Wunused-parameter */
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo RemoveIface(const char *ifname)
{
    LOGI("RemoveIface() ifname:%s", ifname);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetCapabilities(uint32_t *capabilities)
{
    LOGI("GetCapabilities()");
    if (capabilities != NULL) {
        *capabilities = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetSupportedComboModes(int32_t *modes, int32_t *size)
{
    LOGI("GetSupportedComboModes()");
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo ConfigComboModes(int32_t mode)
{
    LOGI("ConfigComboModes() mode: %{public}d", mode);
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiConfigComboModes(mode);
    return ConvertErrorCode(err);
}

WifiErrorNo GetComboModes(int32_t *id)
{
    LOGI("GetComboModes()");
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiGetComboModes(id);
    return ConvertErrorCode(err);
}

WifiErrorNo RequestFirmwareDebugDump(unsigned char *bytes, int32_t *size)
{
    LOGI("RequestFirmwareDebugDump()");
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiRequestFirmwareDebugDump(bytes, size);
    return ConvertErrorCode(err);
}

WifiErrorNo SetPowerMode(uint8_t mode)
{
    LOGI("SetPowerMode() %{public}u", mode);
    return WIFI_HAL_SUCCESS;
}

WifiStatus SetLatencyMode(LatencyMode mode)
{
    LOGI("SetLatencyMode is not supported! mode %{public}u", mode);
    struct WifiStatus status = {ERROR_NOT_SUPPORTED, "not supported"};
    return status;
}
