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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "wifi_hdi_wpa_proxy.h"
#include "servmgr_hdi.h"
#include "devmgr_hdi.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaProxy"
#define PATH_NUM 2
#define BUFF_SIZE 256

const char *HDI_WPA_SERVICE_NAME = "wpa_interface_service";
static pthread_mutex_t g_wpaObjMutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_wpaRefCount = 0;
static struct IWpaInterface *g_wpaObj = NULL;
static struct HDIDeviceManager *g_devMgr = NULL;

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

    g_devMgr = HDIDeviceManagerGet();
    if (g_devMgr == NULL) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s HDIDeviceManagerGet failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    if (g_devMgr->LoadDevice(g_devMgr, HDI_WPA_SERVICE_NAME) != HDF_SUCCESS) {
        g_devMgr = NULL;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s LoadDevice failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    g_wpaObj = IWpaInterfaceGetInstance(HDI_WPA_SERVICE_NAME, false);
    if (g_wpaObj == NULL) {
        g_devMgr->UnloadDevice(g_devMgr, HDI_WPA_SERVICE_NAME);
        g_devMgr = NULL;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s WpaInterfaceGetInstance failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t ret = g_wpaObj->Start(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Start failed: %{public}d", __func__, ret);
        IWpaInterfaceReleaseInstance(HDI_WPA_SERVICE_NAME, g_wpaObj, false);
        g_wpaObj = NULL;
        g_devMgr->UnloadDevice(g_devMgr, HDI_WPA_SERVICE_NAME);
        g_devMgr = NULL;
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
    g_wpaRefCount = 0;
    g_wpaObj = NULL;
    g_devMgr->UnloadDevice(g_devMgr, HDI_WPA_SERVICE_NAME);
    g_devMgr = NULL;
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("HdiWpaStop is stopped");
    return (ret == HDF_SUCCESS) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiAddWpaIface(const char *ifName, const char *confName)
{
    pthread_mutex_lock(&g_wpaObjMutex);
    if (ifName == NULL || confName == NULL) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("HdiAddWpaIface: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_wpaObj == NULL || g_wpaRefCount == 0) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiAddWpaIface ifName:%{public}s, confName:%{public}s", ifName, confName);
    int32_t ret = g_wpaObj->AddWpaIface(g_wpaObj, ifName, confName);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s AddWpaIface failed: %{public}d", __func__, ret);
        pthread_mutex_unlock(&g_wpaObjMutex);
        return WIFI_IDL_OPT_FAILED;
    }
    
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("%{public}s AddWpaIface success!", __func__);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiRemoveWpaIface(const char *ifName)
{
    pthread_mutex_lock(&g_wpaObjMutex);
    if (ifName == NULL) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("HdiRemoveWpaIface: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_wpaObj == NULL || g_wpaRefCount == 0) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiRemoveWpaIface ifName:%{public}s", ifName);
    int32_t ret = g_wpaObj->RemoveWpaIface(g_wpaObj, ifName);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s RemoveWpaIface failed: %{public}d", __func__, ret);
        pthread_mutex_unlock(&g_wpaObjMutex);
        return WIFI_IDL_OPT_FAILED;
    }
    
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("%{public}s RemoveWpaIface success!", __func__);
    return WIFI_IDL_OPT_OK;
}

struct IWpaInterface* GetWpaInterface()
{
    struct IWpaInterface *wpaObj = NULL;
    pthread_mutex_lock(&g_wpaObjMutex);
    wpaObj = g_wpaObj;
    pthread_mutex_unlock(&g_wpaObjMutex);
    return wpaObj;
}

WifiErrorNo ExcuteCmd(const char *szCmd)
{
    LOGI("Execute cmd: %{private}s", szCmd);
    int ret = system(szCmd);
    if (ret == -1) {
        LOGE("Execute system cmd %{private}s failed!", szCmd);
        return WIFI_IDL_OPT_FAILED;
    }
    if (WIFEXITED(ret) && (WEXITSTATUS(ret) == 0)) {
        return WIFI_IDL_OPT_OK;
    }
    LOGE("Execute system cmd %{private}s failed: %{private}d", szCmd, WEXITSTATUS(ret));
    return WIFI_IDL_OPT_FAILED;
}

WifiErrorNo CopyConfigFile(const char* configName)
{
    char buf[BUFF_SIZE] = {0};
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%s/wpa_supplicant/%s", CONFIG_ROOR_DIR, configName) < 0) {
        LOGE("snprintf_s dest dir failed.");
        return WIFI_IDL_OPT_FAILED;
    }
    char path[PATH_NUM][BUFF_SIZE] = {"/system/etc/wifi/", "/vendor/etc/wifi/"};
    for (int i = 0; i != PATH_NUM; ++i) {
        if (strcat_s(path[i], sizeof(path[i]), configName) != EOK) {
            LOGE("strcat_s failed.");
            return WIFI_IDL_OPT_FAILED;
        }
        if (access(path[i], F_OK) != -1) {
            char cmd[BUFF_SIZE] = {0};
            if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
                "cp %s %s/wpa_supplicant/", path[i], CONFIG_ROOR_DIR) < 0) {
                LOGE("snprintf_s cp cmd failed.");
                return WIFI_IDL_OPT_FAILED;
            }
            return ExcuteCmd(cmd);
        }
    }
    LOGE("Copy config file failed: %{public}s", configName);
    return WIFI_IDL_OPT_FAILED;
}
#endif