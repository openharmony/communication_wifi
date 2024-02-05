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

#define CTRL_LEN 128
#define IFACENAME_LEN 6
#define CFGNAME_LEN 30
#define WIFI_MULTI_CMD_MAX_LEN 1024
#define WPA_HOSTAPD_NAME "hostapd"
#define AP_IFNAME "wlan0"
#define AP_IFNAME_COEX "wlan1"
#define WIFI_DEFAULT_CFG "hostapd.conf"
#define WIFI_COEX_CFG "hostapd_coex.conf"
#define HOSTAPD_DEFAULT_CFG CONFIG_ROOT_DIR"wap_supplicant"WIFI_DEFAULT_CFG
#define HOSTAPD_DEFAULT_CFG_COEX CONFIG_ROOT_DIR"wap_supplicant"WIFI_COEX_CFG
static char g_hostapdCfg[CTRL_LEN] = {0};
static char g_apIfaceName[IFACENAME_LEN] = {0};
static char g_apCfgName[CFGNAME_LEN] = {0};
static int g_id;

const char *HDI_WPA_SERVICE_NAME = "wpa_interface_service";
static pthread_mutex_t g_wpaObjMutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_wpaStartSucceed = false;
static struct IWpaInterface *g_wpaObj = NULL;
static struct HDIDeviceManager *g_devMgr = NULL;

const char *HDI_AP_SERVICE_NAME = "hostapd_interface_service";
static pthread_mutex_t g_apObjMutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_apRefCount = 0x0;
static struct IHostapdInterface *g_apObj = NULL;
static struct HDIDeviceManager *g_apDevMgr = NULL;
struct HdiWpaIfaceInfo {
    char ifName[BUFF_SIZE];
    struct HdiWpaIfaceInfo* next;
};
struct HdiWpaIfaceInfo* g_HdiWpaIfaceInfoHead = NULL;

bool FindHdiWpaIface(const char* ifName)
{
    LOGI("%{public}s enter", __func__);
    if (ifName == NULL || strlen(ifName) == 0) {
        LOGI("%{public}s err1", __func__);
        return true;
    }
    struct HdiWpaIfaceInfo* currernt = g_HdiWpaIfaceInfoHead;
    while (currernt != NULL) {
        if (strncmp(currernt->ifName, ifName, strlen(ifName)) == 0 ) {
            LOGI("%{public}s out1", __func__);
            return true;
        }
        currernt = currernt->next;
    }
    LOGI("%{public}s out", __func__);
    return false;
}

void AddHdiWpaIface(const char* ifName)
{
    LOGI("%{public}s enter", __func__);
    if (ifName == NULL || strlen(ifName) == 0) {
        LOGI("%{public}s err", __func__);
        return;
    }
    struct HdiWpaIfaceInfo* pre = NULL;
    struct HdiWpaIfaceInfo* currernt = g_HdiWpaIfaceInfoHead;
    while (currernt != NULL) {
        pre = currernt;
        currernt = currernt->next;
    }
    currernt =(struct HdiWpaIfaceInfo*) malloc(sizeof(struct HdiWpaIfaceInfo));
    if (currernt == NULL) {
        LOGI("%{public}s err2", __func__);
        return;
    }
    memset_s(currernt->ifName, BUFF_SIZE, 0, strlen(ifName));
    currernt->next = NULL;
    if (strncpy_s(currernt->ifName, BUFF_SIZE, ifName, strlen(ifName)) != EOK) {
        free(currernt);
        LOGI("%{public}s err3", __func__);
        return;
    }
    if (pre != NULL) {
        pre->next = currernt;
    } else {
        g_HdiWpaIfaceInfoHead = currernt;
    }
    LOGI("%{public}s out", __func__);
    return;
}

void RemoveHdiWpaIface(const char* ifName)
{
    LOGI("%{public}s enter", __func__);
    if (ifName == NULL || strlen(ifName) == 0) {
        return;
    }
    struct HdiWpaIfaceInfo* pre = NULL;
    struct HdiWpaIfaceInfo* currernt = g_HdiWpaIfaceInfoHead;
    while (currernt != NULL) {
        if (strncmp(currernt->ifName, ifName, BUFF_SIZE) != 0) {
            pre = currernt;
            currernt = currernt->next;
            continue;
        }
        if (pre == NULL) {
            g_HdiWpaIfaceInfoHead = currernt->next;
        } else {
            pre->next = currernt->next;
        }
        free(currernt);
        currernt = NULL;
    }
    LOGI("%{public}s out", __func__);
    return;
}

int GetHdiWpaIfaceCount()
{
    int count = 0;
    struct HdiWpaIfaceInfo* currernt = g_HdiWpaIfaceInfoHead;
    while (currernt != NULL) {
        currernt = currernt->next;
        count++;
    }
    return count;
}
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
    if (g_wpaStartSucceed && g_wpaObj != NULL && g_devMgr != NULL) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGI("%{public}s wpa ref count: %{public}d", __func__, g_wpaStartSucceed);
        return WIFI_IDL_OPT_OK;
    } else {
        g_wpaStartSucceed = false;
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
    g_wpaStartSucceed = true;
    RegistHdfDeathCallBack();
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGI("HdiWpaStart is started");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStop()
{
    LOGI("HdiWpaStop stop...");
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaObj == NULL || g_wpaStartSucceed == false) {
        g_wpaStartSucceed = false;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    int count = GetHdiWpaIfaceCount();
    if (count > 0) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGI("%{public}s wlan count:%{public}d", __func__, count);
        return WIFI_IDL_OPT_OK;
    }

    int32_t ret = g_wpaObj->Stop(g_wpaObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Stop failed: %{public}d", __func__, ret);
    }
    IWpaInterfaceReleaseInstance(HDI_WPA_SERVICE_NAME, g_wpaObj, false);
    g_wpaStartSucceed = false;
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
    int count = GetHdiWpaIfaceCount();
    if (ifName == NULL || confName == NULL) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        (count == 0)?(g_wpaStartSucceed = false):(g_wpaStartSucceed = true);
        LOGE("HdiAddWpaIface: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_wpaObj == NULL || g_wpaStartSucceed == false) {
        g_wpaStartSucceed = false;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiAddWpaIface ifName:%{public}s, confName:%{public}s", ifName, confName);
    if (!FindHdiWpaIface(ifName)) {
        int32_t ret = g_wpaObj->AddWpaIface(g_wpaObj, ifName, confName);
        if (ret != HDF_SUCCESS) {
            (count == 0)?(g_wpaStartSucceed = false):(g_wpaStartSucceed = true);
            LOGE("%{public}s AddWpaIface failed: %{public}d", __func__, ret);
            pthread_mutex_unlock(&g_wpaObjMutex);
            return WIFI_IDL_OPT_FAILED;
        }
        AddHdiWpaIface(ifName);
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

    if (g_wpaObj == NULL || g_wpaStartSucceed == 0) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or ref count is 0", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiRemoveWpaIface ifName:%{public}s", ifName);
    if (FindHdiWpaIface(ifName)) {
        int32_t ret = g_wpaObj->RemoveWpaIface(g_wpaObj, ifName);
        if (ret != HDF_SUCCESS) {
            LOGE("%{public}s RemoveWpaIface failed: %{public}d", __func__, ret);
            pthread_mutex_unlock(&g_wpaObjMutex);
            return WIFI_IDL_OPT_FAILED;
        }
        RemoveHdiWpaIface(ifName);
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
    g_wpaStartSucceed = 0;
    g_wpaObj = NULL;
    g_devMgr = NULL;
    LOGE("%{public}s reset wpa g_wpaObj", __func__);
    HdiWpaStart();
}

void HdiApResetGlobalObj()
{
    g_apRefCount = 0;
    g_apObj = NULL;
    g_apDevMgr = NULL;
    LOGE("%{public}s reset ap g_apObj", __func__);
    HdiApStart(g_id);
}

static void ProxyOnApRemoteDied(struct HdfDeathRecipient* recipient, struct HdfRemoteService* service)
{
    LOGI("%{public}s enter", __func__);
    if (recipient == NULL || service == NULL) {
        LOGE("%{public}s input param is null", __func__);
        HdiApResetGlobalObj();
        return;
    }
    HdfRemoteServiceRemoveDeathRecipient(service, recipient);
    HdfRemoteServiceRecycle(service);
    if (recipient == NULL) {
        LOGE("%{public}s param recipient is null", __func__);
        HdiApResetGlobalObj();
        return;
    }
    OsalMemFree(recipient);
    recipient = NULL;
    HdiApResetGlobalObj();
}

WifiErrorNo RegistHdfApDeathCallBack()
{
    struct HDIServiceManager* serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        LOGE("%{public}s: failed to get HDIServiceManager", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    struct HdfRemoteService* remote = serviceMgr->GetService(serviceMgr, HDI_AP_SERVICE_NAME);
    HDIServiceManagerRelease(serviceMgr);
    if (remote == NULL) {
        LOGE("%{public}s: failed to get HdfRemoteService", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("%{public}s: success to get HdfRemoteService", __func__);
    struct HdfDeathRecipient* recipient = (struct HdfDeathRecipient*)OsalMemCalloc(sizeof(struct HdfDeathRecipient));
    recipient->OnRemoteDied = ProxyOnApRemoteDied;
    HdfRemoteServiceAddDeathRecipient(remote, recipient);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo GetApInstance()
{
    g_devMgr = HDIDeviceManagerGet();
    if (g_devMgr == NULL) {
        LOGE("%{public}s HDIDeviceManagerGet failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    if (g_devMgr->LoadDevice(g_devMgr, HDI_AP_SERVICE_NAME) != HDF_SUCCESS) {
        g_devMgr = NULL;
        LOGE("%{public}s LoadDevice failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    g_apObj = IHostapdInterfaceGetInstance(HDI_AP_SERVICE_NAME, false);
    if (g_apObj == NULL) {
        g_devMgr->UnloadDevice(g_devMgr, HDI_AP_SERVICE_NAME);
        g_devMgr = NULL;
        LOGE("%{public}s HostapdInterfaceGetInstance failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo StartAp()
{
    char startCmd[WIFI_MULTI_CMD_MAX_LEN] = {0};
    char *p = startCmd;
    int onceMove = 0;
    onceMove = snprintf_s(p, WIFI_MULTI_CMD_MAX_LEN - sumMove,
        WIFI_MULTI_CMD_MAX_LEN - sumMove -1, "%s", WPA_HOSTAPD_NAME);
    if (onceMove < 0) {
        return WIFI_IDL_OPT_FAILED;
    }
    p = p + onceMove;
    onceMove = snprintf_s(p, WIFI_MULTI_CMD_MAX_LEN - sumMove,
        WIFI_MULTI_CMD_MAX_LEN - sumMove -1, " %s", cfg[i].config);
    if (onceMove < 0) {
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t ret = g_apObj->StartApWithCmd(g_apObj, startCmd);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Start failed: %{public}d", __func__, ret);
        IHostapdInterfaceGetInstance(HDI_AP_SERVICE_NAME, g_apObj, false);
        g_apObj = NULL;
        g_devMgr->UnloadDevice(g_devMgr, HDI_AP_SERVICE_NAME);
        g_devMgr = NULL;
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiApStart(int id)
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

    g_id = id;
    WifiErrorNo result = WIFI_IDL_OPT_FAILED;
    result = CopyConfigFile(g_apCfgName);
    if (result != WIFI_IDL_OPT_OK) {
        LOGE("HdiApStart: CopyConfigFile failed.");
        pthread_mutex_unlock(&g_apObjMutex);
        return result;
    }

    result = GetApInstance();
    if (result != WIFI_IDL_OPT_OK) {
        pthread_mutex_unlock(&g_apObjMutex);
        return result;
    }

    result = StartAp();
    if (result != WIFI_IDL_OPT_OK) {
        pthread_mutex_unlock(&g_apObjMutex);
        return result;
    }

    ++g_apRefCount;
    RegistHdfApDeathCallBack();
    pthread_mutex_unlock(&g_apObjMutex);
    LOGI("HdiApStart is started");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiApStop(int id)
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
    ret = g_apObj->DisableAp(g_apObj, g_apIfaceName, id);
    ret = g_apObj->StopAp(g_apObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Stop failed: %{public}d", __func__, ret);
    }
    IWpaInterfaceReleaseInstance(HDI_AP_SERVICE_NAME, g_apObj, false);
    g_apRefCount = 0;
    g_apObj = NULL;
    g_apDevMgr->UnloadDevice(g_apDevMgr, HDI_AP_SERVICE_NAME);
    g_apDevMgr = NULL;
    pthread_mutex_unlock(&g_apObjMutex);
    LOGI("HdiApStop is stopped");
    return (ret == HDF_SUCCESS) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

struct IHostapdInterface* GetApInterface()
{
    struct IHostapdInterface *apObj = NULL;
    pthread_mutex_lock(&g_apObjMutex);
    apObj = g_apObj;
    pthread_mutex_unlock(&g_apObjMutex);
    return apObj;
}

char *GetApIfaceaName()
{
    return g_apIfaceName;
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

#endif