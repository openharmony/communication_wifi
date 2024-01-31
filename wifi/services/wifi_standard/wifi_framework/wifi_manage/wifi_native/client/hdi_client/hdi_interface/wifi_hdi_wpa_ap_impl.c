/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_ap_impl.h"
#include "wifi_hdi_util.h"
#include <unistd.h>

#undef LOG_TAG
#define LOG_TAG "wifiHdiWpaApImpl"

#define CTRL_LEN 128
#define IFACENAME_LEN 6
#define CFGNAME_LEN 30
#define AP_IFNAME "wlan0"
#define AP_IFNAME_COEX "wlan1"
#define WIFI_DEFAULT_CFG "hostapd.conf"
#define WIFI_COEX_CFG "hostapd_coex.conf"
#define HOSTAPD_DEFAULT_CFG CONFIG_ROOT_DIR"wap_supplicant"WIFI_DEFAULT_CFG
#define HOSTAPD_DEFAULT_CFG_COEX CONFIG_ROOT_DIR"wap_supplicant"WIFI_COEX_CFG
char g_hostapdCfg[CTRL_LEN] = {0};
char g_apIfaceName[IFACENAME_LEN] = {0};
char g_apCfgName[CFGNAME_LEN] = {0};

static pthread_mutex_t g_hdiCallbackMutex = PTHREAD_MUTEX_INITIALIZER;
static struct IHostapdCallback *g_hdiApCallbackObj = NULL;

static WifiErrorNo RegisterApEventCallback()
{
    LOGI("RegisterApEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiApCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterApEventCallback: g_hdiApCallbackObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterApEventCallback: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->RegisterEventCallback(apObj, g_hdiApCallbackObj, g_apIfaceName);
    if (result != HDF_SUCCESS) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterApEventCallback: RegisterApEventCallback failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("RegisterApEventCallback success.");
    return WIFI_IDL_OPT_OK;
}

static WifiErrorNo UnRegisterApEventCallback()
{
    LOGI("UnRegisterApEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiApCallbackObj != NULL) {
        struct IHostapdInterface *apObj = GetApInterface();
        if (apObj == NULL) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("UnRegisterApEventCallback: apObj is NULL");
            return WIFI_IDL_OPT_FAILED;
        }

        int32_t result = apObj->UnregisterEventCallback(apObj, g_hdiApCallbackObj, g_apIfaceName);
        if (result != HDF_SUCCESS) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("UnRegisterEventCallback: UnRegisterEventCallback failed result:%{public}d", result);
            return WIFI_IDL_OPT_FAILED;
        }

        free(g_hdiApCallbackObj);
        g_hdiApCallbackObj = NULL;
    }

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("UnRegisterApEventCallback success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiRegisterApEventCallback(struct IHostapdCallback *callback)
{
    LOGI("HdiRegisterApEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (callback == NULL || callback->OnEventStaJoin == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("HdiRegisterApEventCallback: invalid parameter");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_hdiApCallbackObj != NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("HdiRegisterApEventCallback: already register");
        return WIFI_IDL_OPT_OK;
    }

    g_hdiApCallbackObj = (struct IHostapdCallback *)malloc(sizeof(struct IHostapdCallback));
    if (g_hdiApCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("HdiRegisterApEventCallback: IWpaCallback malloc failed");
        return WIFI_IDL_OPT_FAILED;
    }

    g_hdiApCallbackObj->OnEventStaJoin = callback->OnEventStaJoin;
    g_hdiApCallbackObj->OnEventApState = callback->OnEventApState;
    g_hdiApCallbackObj->GetVersion = NULL;
    g_hdiApCallbackObj->AsObject = NULL;

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("HdiRegisterApEventCallback: success.");
    return WIFI_IDL_OPT_OK;
}

void InitCfg(char *ifaceName)
{
    if (strncmp(ifaceName, AP_IFNAME_COEX, IFACENAME_LEN -1) == 0) {
        if (memcpy_s(g_apCfgName, CFGNAME_LEN, WIFI_COEX_CFG, sizeof(WIFI_DEFAULT_CFG)) != EOK) {
            LOGE("memcpy cfg fail");
        }
        if (memcpy_s(g_apIfaceName, IFACENAME_LEN, AP_IFNAME_COEX, sizeof(AP_IFNAME)) != EOK) {
            LOGE("memcpy ap name fail");
        }
        if (memcpy_s(g_hostapdCfg, CTRL_LEN, HOSTAPD_DEFAULT_CFG_COEX, sizeof(HOSTAPD_DEFAULT_CFG_COEX)) != EOK) {
            LOGE("memcpy hostapdCfg fail");
        }
    } else {
        if (memcpy_s(g_apCfgName, CFGNAME_LEN, WIFI_DEFAULT_CFG, sizeof(WIFI_DEFAULT_CFG)) != EOK) {
            LOGE("memcpy cfg fail");
        }
        if (memcpy_s(g_apIfaceName, IFACENAME_LEN, AP_IFNAME, sizeof(AP_IFNAME)) != EOK) {
            LOGE("memcpy ap name fail");
        }
        if (memcpy_s(g_hostapdCfg, CTRL_LEN, HOSTAPD_DEFAULT_CFG, sizeof(HOSTAPD_DEFAULT_CFG)) != EOK) {
            LOGE("memcpy hostapdCfg fail");
        }
    }
}

WifiErrorNo HdiStartAp(char *ifaceName, int id)
{
    LOGI("Ready to start hostpad: %{public}d, %{public}s", id, ifaceName);

    InitCfg(ifaceName);
    if (CopyConfigFile(g_apCfgName) != WIFI_IDL_OPT_OK) {
        LOGE("HdiStartAp: CopyConfigFile failed.");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiApStart(id, g_hostapdCfg) != WIFI_IDL_OPT_OK) {
        LOGE("HdiStartAp: HdiApStart failed.");
        return WIFI_IDL_OPT_FAILED;
    }

    if (RegisterApEventCallback() != WIFI_IDL_OPT_OK) {
        LOGE("HdiStartAp: RegisterApEventCallback failed.");
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiStartAp: success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStopAp(int id)
{
    LOGI("HdiStopAp enter");
    if (UnRegisterApEventCallback() != WIFI_IDL_OPT_OK) {
        LOGE("HdiStopAp: UnRegisterApEventCallback failed.");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiApStop(id, g_apIfaceName) != WIFI_IDL_OPT_OK) {
        LOGE("HdiStopAp: HdiApStop failed.");
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiStopAp success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiEnableAp(int id)
{
    LOGI("HdiEnableAp enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiEnableAp: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->EnableAp(apObj, g_apIfaceName, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiEnableAp failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiEnableAp success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiDisableAp(int id)
{
    LOGI("HdiDisableAp enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiDisableAp: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->DisableAp(apObj, g_apIfaceName, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiDisableAp failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiDisableAp success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiReloadApConfigInfo(int id)
{
    LOGI("HdiReloadApConfigInfo enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiReloadApConfigInfo: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->ReloadApConfigInfo(apObj, g_apIfaceName, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiReloadApConfigInfo failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiReloadApConfigInfo success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApPasswd(const char *pass, int id)
{
    LOGI("HdiSetApPasswd enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApPasswd: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApPasswd(apObj, g_apIfaceName, pass, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApPasswd failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApPasswd success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApName(const char *name, int id)
{
    LOGI("HdiSetApName enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApName: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApName(apObj, g_apIfaceName, name, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApName failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApName success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApWpaValue(int securityType, int id)
{
    LOGI("HdiSetApWpaValue enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApWpaValue: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApWpaValue(apObj, g_apIfaceName, securityType, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApWpaValue failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApWpaValue success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApBand(int band, int id)
{
    LOGI("HdiSetApBand enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApBand: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApBand(apObj, g_apIfaceName, band, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApBand failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApBand success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetAp80211n(int value, int id)
{
    LOGI("HdiSetAp80211n enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetAp80211n: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetAp80211n(apObj, g_apIfaceName, value, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetAp80211n failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetAp80211n success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApWmm(int value, int id)
{
    LOGI("HdiSetApWmm enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApWmm: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApWmm(apObj, g_apIfaceName, value, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApWmm failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApWmm success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApChannel(int channel, int id)
{
    LOGI("HdiSetApChannel enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApChannel: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApChannel(apObj, g_apIfaceName, channel, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApChannel failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApChannel success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetApMaxConn(int maxConn, int id)
{
    LOGI("HdiSetApMaxConn enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetApMaxConn: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetApMaxConn(apObj, g_apIfaceName, maxConn, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetApMaxConn failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetApMaxConn success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetMacFilter(const char *mac, int id)
{
    LOGI("HdiSetMacFilter enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiSetMacFilter: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->SetMacFilter(apObj, g_apIfaceName, mac, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetMacFilter failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetMacFilter success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiDelMacFilter(const char *mac, int id)
{
    LOGI("HHdiDelMacFilter enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HHdiDelMacFilter: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->DelMacFilter(apObj, g_apIfaceName, mac, id);
    if (result != HDF_SUCCESS) {
        LOGE("HHdiDelMacFilter failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HHdiDelMacFilter success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiGetStaInfos(char *buf, int size, int id)
{
    LOGI("HdiGetStaInfos enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiGetStaInfos: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->GetStaInfos(apObj, g_apIfaceName, buf, size, size, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiGetStaInfos failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiGetStaInfos success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiDisassociateSta(const char *mac, int id);
{
    LOGI("HdiDisassociateSta enter");
    struct IHostapdInterface *apObj = GetApInterface();
    if (apObj == NULL) {
        LOGE("HdiDisassociateSta: apObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = apObj->DisassociateSta(apObj, g_apIfaceName, mac, id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiDisassociateSta failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiDisassociateSta success");
    return WIFI_IDL_OPT_OK;
}

#endif