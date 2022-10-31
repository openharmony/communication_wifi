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

#include "wifi_hal_ap_interface.h"
#include <errno.h>
#include <securec.h>
#include "wifi_hal_adapter.h"
#include "wifi_hal_module_manage.h"
#include "wifi_hal_common_func.h"
#ifdef HDI_INTERFACE_SUPPORT
#include "wifi_hdi_proxy.h"
#endif
#include "wifi_log.h"
#include "wifi_wpa_hal.h"
#include "wifi_hostapd_hal.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalApInterface"

#define DISABLE_AP_WAIT_MS 50000
#define ABLE_AP_WAIT_MS 50000
#define WIFI_MULTI_CMD_MAX_LEN 1024
#define IFCAE_NAME_LEN 256
static const char *g_serviceName = "hostapd";

WifiErrorNo StartSoftAp(int id)
{
    LOGI("Ready to start hostapd: %{public}d!", id);
    char ifaceName[IFCAE_NAME_LEN] = {0};
    if (StartHostapd() != WIFI_HAL_SUCCESS) {
        LOGE("hostapd start failed!");
        return WIFI_HAL_OPEN_HOSTAPD_FAILED;
    }
    if (StartHostapdHal(id) != WIFI_HAL_SUCCESS) {
        LOGE("hostapd init failed!");
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        LOGE("hostapdHalDevice is NULL!");
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = sprintf_s(ifaceName, IFCAE_NAME_LEN, AP_INTF"%d", id);
    if (ret == -1) {
        LOGE("StartSoftAp failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    if (GetIfaceState(ifaceName) == 0 || id > 0) {
        ret = hostapdHalDevice->enableAp(id);
        if (ret != 0) {
            LOGE("enableAp failed! ret=%{public}d", ret);
            return WIFI_HAL_FAILED;
        }
    }
#ifdef HDI_INTERFACE_SUPPORT
    if (HdiStart() != WIFI_HAL_SUCCESS) {
        LOGE("[Ap] Start hdi failed!");
        return WIFI_HAL_FAILED;
    }
#endif
    LOGI("AP start successfully, id:%{public}d!", id);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartHostapd(void)
{
    char startCmd[WIFI_MULTI_CMD_MAX_LEN] = {0};
    char *p = startCmd;
    int onceMove = 0;
    int sumMove = 0;
    onceMove = snprintf_s(p, WIFI_MULTI_CMD_MAX_LEN - sumMove,
        WIFI_MULTI_CMD_MAX_LEN - sumMove -1, "%s", g_serviceName);
    if (onceMove < 0) {
        return WIFI_HAL_FAILED;
    }
    p = p + onceMove;
    sumMove = sumMove + onceMove;
    int num;
    WifiHostapdHalDeviceInfo *cfg = GetWifiCfg(&num);
    if (cfg == NULL) {
        return WIFI_HAL_FAILED;
    }
    for (int i = 0; i < num; i++) {
        if (CopyConfigFile(cfg[i].cfgName) != 0) {
            return WIFI_HAL_FAILED;
        }
        onceMove = snprintf_s(p, WIFI_MULTI_CMD_MAX_LEN - sumMove,
            WIFI_MULTI_CMD_MAX_LEN - sumMove -1, " %s", cfg[i].config);
        if (onceMove < 0) {
            return WIFI_HAL_FAILED;
        }
        p = p + onceMove;
        sumMove = sumMove + onceMove;
    }
    ModuleManageRetCode ret = StartModule(g_serviceName, startCmd);
    if (ret == MM_SUCCESS) {
        return WIFI_HAL_SUCCESS;
    }

    LOGE("start hostapd failed!");
    return WIFI_HAL_FAILED;
}

WifiErrorNo StartHostapdHal(int id)
{
    LOGD("Ready to init hostapd");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopSoftAp(int id)
{
#ifdef HDI_INTERFACE_SUPPORT
    if (HdiStop() != WIFI_HAL_SUCCESS) {
        LOGE("[Ap] Stop hdi failed!");
        return WIFI_HAL_FAILED;
    }
#endif
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice != NULL) {
        int ret = hostapdHalDevice->disableAp(id);
        if (ret != 0) {
            LOGE("disableAp failed! ret=%{public}d", ret);
        }
    } else {
        LOGE("cant not get hostapd dev");
    }
    if (StopHostapd() != WIFI_HAL_SUCCESS) {
        LOGE("hostapd stop failed!");
        return WIFI_HAL_FAILED;
    }
    if (StopHostapdHal(id) != WIFI_HAL_SUCCESS) {
        LOGE("hostapd_hal stop failed!");
        return WIFI_HAL_FAILED;
    }
    LOGI("AP stop successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopHostapd(void)
{
    ModuleManageRetCode ret;
    ret = StopModule(g_serviceName, true);
    if (ret == MM_FAILED) {
        LOGE("stop hostapd failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopHostapdHal(int id)
{
    ReleaseHostapdDev(id);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetStaInfos(char *infos, int32_t *size, int id)
{
    if (infos == NULL || size == NULL) {
        LOGE("GetStaInfos infos or size is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("GetStaInfos:Start");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    if (hostapdHalDevice->showConnectedDevList(infos, *size, id) != 0) {
        LOGE("ShowConnectedDevList failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetCountryCode(const char *code, int id)
{
    if (code == NULL || strlen(code) != WIFI_COUNTRY_CODE_MAXLEN) {
        LOGE("SetCountryCode code is invalid");
        return WIFI_HAL_INVALID_PARAM;
    }
    LOGD("SetCountryCode() code: %{public}s", code);
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    if (hostapdHalDevice->setCountryCode(code, id) != 0) {
        LOGE("SetCountryCode failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetHostapdConfig(HostapdConfig *config, int id)
{
    if (config == NULL) {
        LOGE("SetHostapdConfig config is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("SetHostapdConfig()");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->setApInfo(config, id);
    if (ret != 0) {
        LOGE("SetApInfo failed!");
        return WIFI_HAL_FAILED;
    }
    ret = hostapdHalDevice->reloadApConfigInfo(id);
    if (ret != 0) {
        LOGE("ReloadApConfigInfo failed!");
        return WIFI_HAL_FAILED;
    }
    ret = hostapdHalDevice->disableAp(id);
    if (ret != 0) {
        LOGE("DisableAp failed!");
        return WIFI_HAL_FAILED;
    }
    ret = hostapdHalDevice->enableAp(id);
    if (ret != 0) {
        LOGE("EnableAp failed!");
        return WIFI_HAL_FAILED;
    }
    LOGD("SetHostapdConfig successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetMacFilter(const unsigned char *mac, int lenMac, int id)
{
    if (mac == NULL) {
        LOGE("SetMacFilter is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("SetMacFilter:mac: %{private}s, len_mac: %{public}d", (const char *)mac, lenMac);
    if (strlen((const char *)mac) != WIFI_MAC_LENGTH || lenMac != WIFI_MAC_LENGTH) {
        LOGE("Mac size not correct! mac len %{public}zu, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }
    if (CheckMacIsValid((const char *)mac) != 0) {
        return WIFI_HAL_INPUT_MAC_INVALID;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    if (hostapdHalDevice->addBlocklist((const char *)mac, id) != 0) {
        LOGE("AddBlocklist failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DelMacFilter(const unsigned char *mac, int lenMac, int id)
{
    if (mac == NULL) {
        LOGE("DelMacFilter is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("DelMacFilter:mac: %{private}s, len_mac: %{public}d", (const char *)mac, lenMac);
    if (strlen((const char *)mac) != WIFI_MAC_LENGTH || lenMac != WIFI_MAC_LENGTH) {
        LOGE("Mac size not correct! mac len %{public}zu, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }
    if (CheckMacIsValid((const char *)mac) != 0) {
        return WIFI_HAL_INPUT_MAC_INVALID;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    if (hostapdHalDevice->delBlocklist((const char *)mac, id) != 0) {
        LOGE("DelBlocklist failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DisassociateSta(const unsigned char *mac, int lenMac, int id)
{
    if (mac == NULL) {
        LOGE("DisassociateSta is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("DisassociateSta:mac: %{private}s, len_mac: %{public}d", (const char *)mac, lenMac);
    if (strlen((const char *)mac) != WIFI_MAC_LENGTH || lenMac != WIFI_MAC_LENGTH) {
        LOGE("Mac size not correct! mac len %{public}zu, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }
    if (CheckMacIsValid((const char *)mac) != 0) {
        return WIFI_HAL_INPUT_MAC_INVALID;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    if (hostapdHalDevice->disConnectedDev((const char *)mac, id) != 0) {
        LOGE("DisConnectedDev failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id)
{
    if (frequencies == NULL || size == NULL) {
        LOGE("%{public}s frequencies or size is null.", __func__);
        return WIFI_HAL_FAILED;
    }
    LOGE("%{public}s func is not support!", __func__);
    return WIFI_HAL_FAILED;
}

WifiErrorNo WifiSetPowerModel(const int mode, int id)
{
    LOGE("%{public}s func is not support!", __func__);
    return WIFI_HAL_FAILED;
}

WifiErrorNo WifiGetPowerModel(int* mode, int id)
{
    LOGE("%{public}s func is not support!", __func__);
    return WIFI_HAL_FAILED;
}
