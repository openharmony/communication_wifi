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
#include "wifi_hal_ap_interface.h"
#include <errno.h>
#include "wifi_hal_callback.h"
#include "wifi_hal_module_manage.h"
#include "wifi_log.h"
#include "wifi_hostapd_hal.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalApInterface"

static const char *g_serviceName = "hostapd";
static const char *g_startCmd = "hostapd /data/misc/wifi/hostapd/hostapd.conf";

WifiErrorNo StartSoftAp(void)
{
    LOGI("Ready to start hostapd");
    int ret = StartHostapd();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGD("hostapd start failed!");
        return WIFI_HAL_OPEN_HOSTAPD_FAILED;
    }

    ret = StartHostapdHal();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGD("hostapd init failed!");
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }

    LOGD("AP start successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartHostapd(void)
{
    ModuleManageRetCode ret = StartModule(g_serviceName, g_startCmd);
    if (ret == MM_SUCCESS) {
        return WIFI_HAL_SUCCESS;
    }
    
    LOGE("start hostapd failed!");
    return WIFI_HAL_FAILED;
}

WifiErrorNo StartHostapdHal(void)
{
    LOGI("Ready to init hostapd");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopSoftAp(void)
{
    int ret = StopHostapd();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGD("hostapd stop failed!");
        return WIFI_HAL_FAILED;
    }

    ret = StopHostapdHal();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGD("hostapd_hal stop failed!");
        return WIFI_HAL_FAILED;
    }

    LOGI("AP stop successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopHostapd(void)
{
    ModuleManageRetCode ret = MM_FAILED;
    do {
        ret = StopModule(g_serviceName);
        if (ret == MM_FAILED) {
            LOGE("stop hostapd failed!");
            return WIFI_HAL_FAILED;
        }
    } while (ret == MM_REDUCE_REFERENCE);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopHostapdHal(void)
{
    ReleaseHostapdDev();
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetStaInfos(char *infos, int32_t *size)
{
    LOGI("GetStaInfos:Start");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->showConnectedDevList(infos, size);
    if (ret != 0) {
        LOGD("ShowConnectedDevList failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ConfigHotspot(uint32_t chan, const char *mscb)
{
    /* SetHostapdConfig This interface function is included. */
    LOGI("ConfigHotspot chan %{public}u, mscb %{public}s", chan, (mscb == NULL) ? "" : mscb);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetCountryCode(const char *code)
{
    LOGI("SetCountryCode() code: %{public}s", code);
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->setCountryCode(code);
    if (ret != 0) {
        LOGD("SetCountryCode failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetHostapdConfig(HostsapdConfig *config)
{
    LOGI("SetHostapdConfig()");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->setApInfo(config);
    if (ret != 0) {
        LOGD("SetApInfo failed!");
        return WIFI_HAL_FAILED;
    }
    ret = hostapdHalDevice->reloadApConfigInfo();
    if (ret != 0) {
        LOGD("ReloadApConfigInfo failed!");
        return WIFI_HAL_FAILED;
    }
    StatusInfo statusInfo;
    ret = hostapdHalDevice->status(&statusInfo); /* Obtains the current AP status. */
    if (ret != 0) {
        LOGD("GetStatus failed!");
        return WIFI_HAL_FAILED;
    } else if (strncmp(statusInfo.state, "ENABLE", strlen("ENABLE")) == 0) {
        /* If the command output is ENABLE, run the disable command. */
        ret = hostapdHalDevice->disableAp();
        if (ret != 0) {
            LOGD("DisableAp failed!");
            return WIFI_HAL_FAILED;
        }
    }
    ret = hostapdHalDevice->enableAp();
    if (ret != 0) {
        LOGD("EnableAp failed!");
        return WIFI_HAL_FAILED;
    }
    LOGE("SetHostapdConfig successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetMacFilter(const unsigned char *mac, int lenMac)
{
    LOGD("SetMacFilter:mac: %s, len_mac: %{public}d", (const char *)mac, lenMac);
    if (WIFI_MAC_LENGTH != strlen((const char *)mac) || WIFI_MAC_LENGTH != lenMac) {
        LOGD("Mac size not correct! mac len %{public}d, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->addBlocklist((const char *)mac);
    if (ret != 0) {
        LOGD("AddBlocklist failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DelMacFilter(const unsigned char *mac, int lenMac)
{
    LOGI("DelMacFilter:mac: %s, len_mac: %{public}d", (const char *)mac, lenMac);
    if (WIFI_MAC_LENGTH != strlen((const char *)mac) || WIFI_MAC_LENGTH != lenMac) {
        LOGD("Mac size not correct! mac len %{public}d, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->delBlocklist((const char *)mac);
    if (ret != 0) {
        LOGD("DelBlocklist failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DisassociateSta(const unsigned char *mac, int lenMac)
{
    LOGI("DisassociateSta:mac: %s, len_mac: %{public}d", (const char *)mac, lenMac);
    if (WIFI_MAC_LENGTH != strlen((const char *)mac) || WIFI_MAC_LENGTH != lenMac) {
        LOGD("Mac size not correct! mac len %{public}d, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev();
    if (hostapdHalDevice == NULL) {
        return WIFI_HAL_HOSTAPD_NOT_INIT;
    }
    int ret = hostapdHalDevice->disConnectedDev((const char *)mac);
    if (ret != 0) {
        LOGE("DisConnectedDev failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size)
{
    LOGI("GetValidFrequenciesForBand");
    return WIFI_HAL_NOT_SUPPORT;
}
