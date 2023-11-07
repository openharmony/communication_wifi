/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <pthread.h>
#include "wifi_hdi_wpa_proxy.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaProxy"

const char *HDI_WPA_SERVICE_NAME = "wpa_interface_service";
static pthread_mutex_t g_wpaObjMutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_wpaRefCount = 0;
static struct IWpaInterface *g_wpaObj = NULL;

WifiErrorNo HdiWpaStart()
{
    LOGI("HdiWpaStart start...");
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaRefCount != 0) {
        ++g_wpaRefCount;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGI("%{public}s wpa ref count: %d", __func__, g_wpaRefCount);
        return WIFI_IDL_OPT_OK;
    }

    g_wpaObj = IWpaInterfaceGetInstance(HDI_WPA_SERVICE_NAME, false);
    if (g_wpaObj == NULL) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s WpaInterfaceGetInstance failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t ret = g_wpaObj->Start(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Start failed: %{public}d", __func__, ret);
        IWpaInterfaceReleaseInstance(HDI_WPA_SERVICE_NAME, g_wpaObj, false);
        g_wpaObj = NULL;
        pthread_mutex_unlock(&g_wpaObjMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    ++g_wpaRefCount;
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("HdiWpaStart is started");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStop()
{
    LOGI("HdiWpaStop stop...");
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaObj == NULL || g_wpaRefCount == 0) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    const unsigned int ONE_REF_COUNT = 1;
    if (g_wpaRefCount > ONE_REF_COUNT) {
        --g_wpaRefCount;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGI("%{public}s wlan ref count: %d", __func__, g_wpaRefCount);
        return WIFI_IDL_OPT_OK;
    }

    int32_t ret = g_wpaObj->Stop(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Stop failed: %{public}d", __func__, ret);
    }
    IWpaInterfaceReleaseInstance(HDI_WPA_SERVICE_NAME, g_wpaObj, false);
    --g_wpaRefCount;
    g_wpaObj = NULL;
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("HdiWpaStop is stopped");
    return (ret == HDF_SUCCESS) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

struct IWpaInterface* GetWlanInterface()
{
    struct IWpaInterface *wpaObj = NULL;
    pthread_mutex_lock(&g_wpaObjMutex);
    wpaObj = g_wpaObj;
    pthread_mutex_unlock(&g_wpaObjMutex);
    return wpaObj;
}
#endif