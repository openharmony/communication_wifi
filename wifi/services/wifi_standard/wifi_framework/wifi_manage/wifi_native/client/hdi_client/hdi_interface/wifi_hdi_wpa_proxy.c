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
#include <sys/stat.h>
#include <fcntl.h>
#include "wifi_hdi_wpa_proxy.h"
#include "servmgr_hdi.h"
#include "devmgr_hdi.h"
#include "hdf_remote_service.h"
#include "osal_mem.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaProxy"
#define PATH_NUM 2
#define BUFF_SIZE 256

#define MAX_READ_FILE_SIZE 1024
#define MAX_FILE_BLOCK_SIZE 1024
#define FILE_OPEN_PRIV 0666

const char *HDI_WPA_SERVICE_NAME = "wpa_interface_service";
static pthread_mutex_t g_wpaObjMutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_wpaRefCount = 0x0;
static struct IWpaInterface *g_wpaObj = NULL;
static struct HDIDeviceManager *g_devMgr = NULL;

const char *HDI_AP_SERVICE_NAME = "hostapd_interface_service";
static pthread_mutex_t g_apObjMutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_apRefCount = 0x0;
static struct IHostapdInterface *g_apObj = NULL;

static void ProxyOnRemoteDied(struct HdfDeathRecipient* recipient, struct HdfRemoteService* service)
{
    LOGI("%{public}s enter", __func__);
    if (recipient == NULL || service == NULL) {
        LOGE("%{public}s input param is null", __func__);
        HdiWpaResetGlobalObj();
        return;
    }
    HdfRemoteServiceRemoveDeathRecipient(service, recipient);
    HdfRemoteServiceRecycle(service);
    if (recipient == NULL) {
        LOGE("%{public}s param recipient is null", __func__);
        HdiWpaResetGlobalObj();
        return;
    }
    OsalMemFree(recipient);
    recipient = NULL;
    HdiWpaResetGlobalObj();
}

WifiErrorNo RegistHdfDeathCallBack()
{
    struct HDIServiceManager* serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        LOGE("%{public}s: failed to get HDIServiceManager", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    struct HdfRemoteService* remote = serviceMgr->GetService(serviceMgr, HDI_WPA_SERVICE_NAME);
    HDIServiceManagerRelease(serviceMgr);
    if (remote == NULL) {
        LOGE("%{public}s: failed to get HdfRemoteService", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("%{public}s: success to get HdfRemoteService", __func__);
    struct HdfDeathRecipient* recipient = (struct HdfDeathRecipient*)OsalMemCalloc(sizeof(struct HdfDeathRecipient));
    recipient->OnRemoteDied = ProxyOnRemoteDied;
    HdfRemoteServiceAddDeathRecipient(remote, recipient);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStart()
{
    LOGI("HdiWpaStart start...");
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaRefCount != 0 && g_wpaObj != NULL && g_devMgr != NULL) {
        ++g_wpaRefCount;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGI("%{public}s wpa ref count: %{public}d", __func__, g_wpaRefCount);
        return WIFI_IDL_OPT_OK;
    } else {
        g_wpaRefCount = 0x0;
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
    RegistHdfDeathCallBack();
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("HdiWpaStart is started");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStop()
{
    LOGI("HdiWpaStop stop...");
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaObj == NULL || g_wpaRefCount == 0) {
        g_wpaRefCount = 0x0;
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

WifiErrorNo HdiApStart(int id, char *hostapdCfg)
{
    LOGI("HdiApStart start...");
    pthread_mutex_lock(&g_apObjMutex);
    if (g_apRefCount != 0 && g_apObj != NULL && g_devMgr != NULL) {
        ++g_apRefCount;
        pthread_mutex_unlock(&g_apObjMutex);
        LOGI("%{public}s ap ref count: %{public}d", __func__, g_apRefCount);
        return WIFI_IDL_OPT_OK;
    } else {
        g_apRefCount = 0x0;
    }
    g_devMgr = HDIDeviceManagerGet();
    if (g_devMgr == NULL) {
        pthread_mutex_unlock(&g_apObjMutex);
        LOGE("%{public}s HDIDeviceManagerGet failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    if (g_devMgr->LoadDevice(g_devMgr, HDI_AP_SERVICE_NAME) != HDF_SUCCESS) {
        g_devMgr = NULL;
        pthread_mutex_unlock(&g_apObjMutex);
        LOGE("%{public}s LoadDevice failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    g_apObj = IHostapdInterfaceGetInstance(HDI_AP_SERVICE_NAME, false);
    if (g_apObj == NULL) {
        g_devMgr->UnloadDevice(g_devMgr, HDI_AP_SERVICE_NAME);
        g_devMgr = NULL;
        pthread_mutex_unlock(&g_apObjMutex);
        LOGE("%{public}s HostapdInterfaceGetInstance failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t ret = g_apObj->StartAp(g_apObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Start failed: %{public}d", __func__, ret);
        IHostapdInterfaceGetInstance(HDI_AP_SERVICE_NAME, g_apObj, false);
        g_apObj = NULL;
        g_devMgr->UnloadDevice(g_devMgr, HDI_AP_SERVICE_NAME);
        g_devMgr = NULL;
        pthread_mutex_unlock(&g_apObjMutex);
        return WIFI_IDL_OPT_FAILED;
    }
    ++g_apRefCount;
    pthread_mutex_unlock(&g_apObjMutex);
    LOGI("HdiApStart is started");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiApStop(int id, char *ifaceName)
{
    LOGI("HdiApStop stop...");
    pthread_mutex_lock(&g_apObjMutex);
    if (g_apObj == NULL || g_apRefCount == 0) {
        g_apRefCount = 0x0;
        pthread_mutex_unlock(&g_apObjMutex);
        LOGE("%{public}s g_apObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    const unsigned int ONE_REF_COUNT = 1;
    if (g_apRefCount > ONE_REF_COUNT) {
        --g_apRefCount;
        pthread_mutex_unlock(&g_apObjMutex);
        LOGI("%{public}s wlan ref count: %d", __func__, g_apRefCount);
        return WIFI_IDL_OPT_OK;
    }
    int32_t ret;
    ret = g_apObj->DisableAp(g_apObj, ifaceName, id);
    ret = g_apObj->StopAp(g_apObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Stop failed: %{public}d", __func__, ret);
    }
    IWpaInterfaceReleaseInstance(HDI_AP_SERVICE_NAME, g_apObj, false);
    g_apRefCount = 0;
    g_apObj = NULL;
    g_devMgr->UnloadDevice(g_devMgr, HDI_AP_SERVICE_NAME);
    g_devMgr = NULL;
    pthread_mutex_unlock(&g_apObjMutex);
    LOGI("HdiApStop is stopped");
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

struct IHostapdInterface* GetApInterface()
{
    struct IHostapdInterface *apObj = NULL;
    pthread_mutex_lock(&g_apObjMutex);
    apObj = g_apObj;
    pthread_mutex_unlock(&g_apObjMutex);
    return apObj;
}

WifiErrorNo CopyUserFile(const char *srcFilePath, const char* destFilePath)
{
    LOGI("Execute CopyUserFile enter");
    if (srcFilePath == NULL || destFilePath == NULL) {
        LOGE("CopyUserFile() srcFilePath or destFilePath is nullptr!");
        return WIFI_IDL_OPT_FAILED;
    }
    int srcFd = -1;
    int destFd = -1;
    do {
        if ((srcFd = open(srcFilePath, O_RDONLY)) < 0)  {
            LOGE("CopyUserFile() failed, open srcFilePath:%{public}s error!", srcFilePath);
            break;
        }
        if ((destFd = open(destFilePath, O_RDWR | O_CREAT | O_TRUNC, FILE_OPEN_PRIV))< 0)  {
            LOGE("CopyUserFile() failed, open destFilePath:%{public}s error!", destFilePath);
            break;
        }
        ssize_t bytes;
        lseek(srcFd, 0, SEEK_SET);
        char buf[MAX_READ_FILE_SIZE] = {0};
        for (int i = 0; i < MAX_FILE_BLOCK_SIZE; i++) {
            if (memset_s(buf, MAX_READ_FILE_SIZE, 0, MAX_READ_FILE_SIZE) != WIFI_IDL_OPT_OK) {
                break;
            }
            if ((bytes = read(srcFd, buf, MAX_READ_FILE_SIZE-1)) < 0) {
                LOGE("CopyUserFile() failed, read srcFilePath:%{public}s error!", srcFilePath);
                break;
            }
            if (write(destFd, buf, bytes) < 0) {
                LOGE("CopyUserFile() failed, write destFilePath:%{public}s error!", destFilePath);
            }
        }
    } while (0);
    if (srcFd>=0) {
        close(srcFd);
    }
    
    if (destFd>=0) {
        close(destFd);
    }
    LOGI("CopyUserFile() copy file succeed.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo CopyConfigFile(const char* configName)
{
    if (configName == NULL || strlen(configName) == 0) {
        LOGE("Copy config file failed:is null");
        return WIFI_IDL_OPT_FAILED;
    }
    char path[PATH_NUM][BUFF_SIZE] = {"/system/etc/wifi/", "/vendor/etc/wifi/"};
    for (int i = 0; i != PATH_NUM; ++i) {
        if (strcat_s(path[i], sizeof(path[i]), configName) != EOK) {
            LOGE("strcat_s failed.");
            return WIFI_IDL_OPT_FAILED;
        }
        if (access(path[i], F_OK) != -1) {
            char destFilePath[BUFF_SIZE] = {0};
            if (snprintf_s(destFilePath, sizeof(destFilePath), sizeof(destFilePath) - 1,
                "%s/wpa_supplicant/%s", CONFIG_ROOR_DIR, configName) < 0) {
                LOGE("snprintf_s destFilePath failed.");
                return WIFI_IDL_OPT_FAILED;
            }
            return CopyUserFile(path[i], destFilePath);
        }
    }
    LOGE("Copy config file failed: %{public}s", configName);
    return WIFI_IDL_OPT_FAILED;
}

void HdiWpaResetGlobalObj()
{
    g_wpaRefCount = 0;
    g_wpaObj = NULL;
    g_devMgr = NULL;
    LOGE("%{public}s reset wpa g_wpaObj", __func__);
    HdiWpaStart();
}
#endif