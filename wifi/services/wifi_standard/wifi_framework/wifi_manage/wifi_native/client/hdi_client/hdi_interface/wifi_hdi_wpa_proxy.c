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
#define IFACENAME_LEN 16
#define CFGNAME_LEN 30
#define WIFI_MULTI_CMD_MAX_LEN 1024

#if (AP_NUM > 1)
#define WIFI_5G_CFG "hostapd_0.conf"
#define WIFI_2G_CFG "hostapd_1.conf"
#else
#define WPA_HOSTAPD_NAME "hostapd"
#define AP_IFNAME "wlan0"
#define AP_IFNAME_COEX "wlan1"
#define WIFI_DEFAULT_CFG "hostapd.conf"
#define WIFI_COEX_CFG "hostapd_coex.conf"
#define HOSTAPD_DEFAULT_CFG CONFIG_ROOR_DIR"wap_supplicant"WIFI_DEFAULT_CFG
#define HOSTAPD_DEFAULT_CFG_COEX CONFIG_ROOR_DIR"wap_supplicant"WIFI_COEX_CFG
#endif

const char *HDI_WPA_SERVICE_NAME = "wpa_interface_service";
static pthread_mutex_t g_wpaObjMutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_wpaStartSucceed = false;
static struct IWpaInterface *g_wpaObj = NULL;
static struct HDIDeviceManager *g_devMgr = NULL;
static pthread_mutex_t g_ifaceNameMutex = PTHREAD_MUTEX_INITIALIZER;
static char g_staIfaceName[IFACENAME_LEN] = {0};
static char g_p2pIfaceName[IFACENAME_LEN] = {0};

const char *HDI_AP_SERVICE_NAME = "hostapd_interface_service";
static pthread_mutex_t g_apObjMutex = PTHREAD_MUTEX_INITIALIZER;
static struct IHostapdInterface *g_apObj = NULL;
static struct HDIDeviceManager *g_apDevMgr = NULL;
static pthread_mutex_t g_apIfaceNameMutex = PTHREAD_MUTEX_INITIALIZER;
static char g_apIfaceName[IFACENAME_LEN] = {0};
static char g_hostapdCfg[CTRL_LEN] = {0};
static char g_apCfgName[CFGNAME_LEN] = {0};
static int g_id;
static int g_execDisable;
static bool g_apIsRunning = false;

struct IfaceNameInfo {
    char ifName[BUFF_SIZE];
    struct IfaceNameInfo* next;
};
struct IfaceNameInfo* g_IfaceNameInfoHead = NULL;

static bool FindifaceName(const char* ifName)
{
    LOGI("%{public}s enter", __func__);
    if (ifName == NULL || strlen(ifName) == 0) {
        LOGI("%{public}s err1", __func__);
        return true;
    }
    struct IfaceNameInfo* current = g_IfaceNameInfoHead;
    while (current != NULL) {
        if (strncmp(current->ifName, ifName, strlen(ifName)) == 0) {
            LOGI("%{public}s out1", __func__);
            return true;
        }
        current = current->next;
    }
    LOGI("%{public}s out", __func__);
    return false;
}

static void AddIfaceName(const char* ifName)
{
    LOGI("%{public}s enter", __func__);
    if (ifName == NULL || strlen(ifName) == 0) {
        LOGI("%{public}s err", __func__);
        return;
    }
    struct IfaceNameInfo* pre = NULL;
    struct IfaceNameInfo* current = g_IfaceNameInfoHead;
    while (current != NULL) {
        pre = current;
        current = current->next;
    }
    current =(struct IfaceNameInfo*) malloc(sizeof(struct IfaceNameInfo));
    if (current == NULL) {
        LOGI("%{public}s err2", __func__);
        return;
    }
    memset_s(current->ifName, BUFF_SIZE, 0, strlen(ifName));
    current->next = NULL;
    if (strncpy_s(current->ifName, BUFF_SIZE, ifName, strlen(ifName)) != EOK) {
        free(current);
        LOGI("%{public}s err3", __func__);
        return;
    }
    if (pre != NULL) {
        pre->next = current;
    } else {
        g_IfaceNameInfoHead = current;
    }
    LOGI("%{public}s out", __func__);
    return;
}

static void RemoveIfaceName(const char* ifName)
{
    LOGI("%{public}s enter", __func__);
    if (ifName == NULL || strlen(ifName) == 0) {
        return;
    }
    struct IfaceNameInfo* pre = NULL;
    struct IfaceNameInfo* current = g_IfaceNameInfoHead;
    while (current != NULL) {
        if (strncmp(current->ifName, ifName, BUFF_SIZE) != 0) {
            pre = current;
            current = current->next;
            continue;
        }
        if (pre == NULL) {
            g_IfaceNameInfoHead = current->next;
        } else {
            pre->next = current->next;
        }
        free(current);
        current = NULL;
    }
    LOGI("%{public}s out", __func__);
    return;
}

static int GetIfaceCount()
{
    int count = 0;
    struct IfaceNameInfo* current = g_IfaceNameInfoHead;
    while (current != NULL) {
        current = current->next;
        count++;
    }
    return count;
}

static void HdiWpaResetGlobalObj()
{
    if (IsHdiWpaStopped() == WIFI_IDL_OPT_OK) {
        LOGE("%{public}s HdiWpa already stopped", __func__);
        return;
    }
    pthread_mutex_lock(&g_wpaObjMutex);
    g_wpaStartSucceed = false;
    g_wpaObj = NULL;
    g_devMgr = NULL;
    pthread_mutex_unlock(&g_wpaObjMutex);
    LOGE("%{public}s reset wpa g_wpaObj", __func__);
    HdiWpaStart();
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

static WifiErrorNo RegistHdfDeathCallBack()
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
    if (recipient == NULL) {
        LOGE("%{public}s: OsalMemCalloc is failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
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
        LOGI("%{public}s wpa hdi already started", __func__);
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
    LOGI("HdiWpaStart start success!");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStop()
{
    LOGI("HdiWpaStop stop...");
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaObj == NULL || g_wpaStartSucceed == false) {
        g_wpaStartSucceed = false;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or wpa hdi already stopped", __func__);
        return WIFI_IDL_OPT_FAILED;
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
    LOGI("HdiWpaStart stop success!");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo IsHdiWpaStopped()
{
    pthread_mutex_lock(&g_wpaObjMutex);
    if (g_wpaStartSucceed == false && g_wpaObj == NULL && g_devMgr == NULL) {
        LOGI("HdiWpa already stopped");
        pthread_mutex_unlock(&g_wpaObjMutex);
        return WIFI_IDL_OPT_OK;
    }
    
    pthread_mutex_unlock(&g_wpaObjMutex);
    return WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiAddWpaIface(const char *ifName, const char *confName)
{
    pthread_mutex_lock(&g_wpaObjMutex);
    if (ifName == NULL || confName == NULL || strlen(ifName) == 0) {
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("HdiAddWpaIface: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_wpaObj == NULL || g_wpaStartSucceed == false) {
        g_wpaStartSucceed = false;
        pthread_mutex_unlock(&g_wpaObjMutex);
        LOGE("%{public}s g_wpaObj is NULL or wpa hdi already stopped", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    int count = GetIfaceCount();
    LOGI("HdiAddWpaIface ifName:%{public}s, confName:%{public}s", ifName, confName);
    if (!FindifaceName(ifName)) {
        int32_t ret = g_wpaObj->AddWpaIface(g_wpaObj, ifName, confName);
        if (ret != HDF_SUCCESS) {
            (count == 0)?(g_wpaStartSucceed = false):(g_wpaStartSucceed = true);
            LOGE("%{public}s AddWpaIface failed: %{public}d", __func__, ret);
            pthread_mutex_unlock(&g_wpaObjMutex);
            return WIFI_IDL_OPT_FAILED;
        }
        AddIfaceName(ifName);
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
        LOGE("%{public}s g_wpaObj is NULL or wpa hdi already stopped", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiRemoveWpaIface ifName:%{public}s", ifName);
    if (FindifaceName(ifName)) {
        int32_t ret = g_wpaObj->RemoveWpaIface(g_wpaObj, ifName);
        if (ret != HDF_SUCCESS) {
            LOGE("%{public}s RemoveWpaIface failed: %{public}d", __func__, ret);
            pthread_mutex_unlock(&g_wpaObjMutex);
            return WIFI_IDL_OPT_FAILED;
        }
        RemoveIfaceName(ifName);
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

WifiErrorNo SetHdiStaIfaceName(const char *ifaceName)
{
    pthread_mutex_lock(&g_ifaceNameMutex);
    if (ifaceName == NULL) {
        pthread_mutex_unlock(&g_ifaceNameMutex);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (memset_s(g_staIfaceName, IFACENAME_LEN, 0, IFACENAME_LEN) != EOK) {
        pthread_mutex_unlock(&g_ifaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    if (strcpy_s(g_staIfaceName, IFACENAME_LEN, ifaceName) != EOK) {
        pthread_mutex_unlock(&g_ifaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("SetHdiStaIfaceName, g_staIfaceName:%{public}s", g_staIfaceName);
    pthread_mutex_unlock(&g_ifaceNameMutex);
    return WIFI_IDL_OPT_OK;
}

const char *GetHdiStaIfaceName()
{
    const char *ifaceName = NULL;
    pthread_mutex_lock(&g_ifaceNameMutex);
    ifaceName = g_staIfaceName;
    pthread_mutex_unlock(&g_ifaceNameMutex);
    return ifaceName;
}

WifiErrorNo SetHdiP2pIfaceName(const char *ifaceName)
{
    pthread_mutex_lock(&g_ifaceNameMutex);
    if (ifaceName == NULL) {
        pthread_mutex_unlock(&g_ifaceNameMutex);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (memset_s(g_p2pIfaceName, IFACENAME_LEN, 0, IFACENAME_LEN) != EOK) {
        pthread_mutex_unlock(&g_ifaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    if (strcpy_s(g_p2pIfaceName, IFACENAME_LEN, ifaceName) != EOK) {
        pthread_mutex_unlock(&g_ifaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("SetHdiP2pIfaceName, g_p2pIfaceName:%{public}s", g_p2pIfaceName);
    pthread_mutex_unlock(&g_ifaceNameMutex);
    return WIFI_IDL_OPT_OK;
}

const char *GetHdiP2pIfaceName()
{
    const char *ifaceName = NULL;
    pthread_mutex_lock(&g_ifaceNameMutex);
    ifaceName = g_p2pIfaceName;
    pthread_mutex_unlock(&g_ifaceNameMutex);
    return ifaceName;
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

static void HdiApResetGlobalObj()
{
    LOGI("%{public}s try reset ap", __func__);
    if (IsHdiApStopped() == WIFI_IDL_OPT_OK) {
        LOGI("%{public}s HdiAp already stopped", __func__);
        return;
    }
    pthread_mutex_lock(&g_apObjMutex);
    g_apIsRunning = false;
    g_apObj = NULL;
    g_apDevMgr = NULL;
    pthread_mutex_unlock(&g_apObjMutex);
    HdiApStart(g_id, g_apIfaceName);
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

static WifiErrorNo RegistHdfApDeathCallBack()
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
    if (recipient == NULL) {
        LOGE("%{public}s: OsalMemCalloc is failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    recipient->OnRemoteDied = ProxyOnApRemoteDied;
    HdfRemoteServiceAddDeathRecipient(remote, recipient);
    return WIFI_IDL_OPT_OK;
}

static WifiErrorNo GetApInstance()
{
    g_apDevMgr = HDIDeviceManagerGet();
    if (g_apDevMgr == NULL) {
        LOGE("%{public}s HDIDeviceManagerGet failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    if (g_apDevMgr->LoadDevice(g_apDevMgr, HDI_AP_SERVICE_NAME) != HDF_SUCCESS) {
        g_apDevMgr = NULL;
        LOGE("%{public}s LoadDevice failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    g_apObj = IHostapdInterfaceGetInstance(HDI_AP_SERVICE_NAME, false);
    if (g_apObj == NULL) {
        g_apDevMgr->UnloadDevice(g_apDevMgr, HDI_AP_SERVICE_NAME);
        g_apDevMgr = NULL;
        LOGE("%{public}s HostapdInterfaceGetInstance failed", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

static WifiErrorNo StartApHdi(int id, const char *ifaceName)
{
    int32_t ret = g_apObj->StartApWithCmd(g_apObj, ifaceName, id);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Start failed: %{public}d", __func__, ret);
        IHostapdInterfaceGetInstance(HDI_AP_SERVICE_NAME, false);
        g_apObj = NULL;
        g_apDevMgr->UnloadDevice(g_apDevMgr, HDI_AP_SERVICE_NAME);
        g_apDevMgr = NULL;
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiApStart(int id, const char *ifaceName)
{
    LOGI("HdiApStart start...");
    pthread_mutex_lock(&g_apObjMutex);

    g_id = id;
    WifiErrorNo result = WIFI_IDL_OPT_FAILED;
    do {
#if (AP_NUM > 1)
        result = CopyConfigFile(WIFI_5G_CFG);
        if (result != WIFI_IDL_OPT_OK) {
            break;
        }
        result = CopyConfigFile(WIFI_2G_CFG);
#else
        result = CopyConfigFile(g_apCfgName);
#endif
        if (result != WIFI_IDL_OPT_OK) {
            break;
        }
            result = GetApInstance();
        if (result != WIFI_IDL_OPT_OK) {
            break;
        }
        result = StartApHdi(id, ifaceName);
        if (result != WIFI_IDL_OPT_OK) {
            break;
        }
        result = RegistHdfApDeathCallBack();
        if (result != WIFI_IDL_OPT_OK) {
            break;
        }
        g_apIsRunning = true;
        LOGI("HdiApStart start success");
    } while (0);
    pthread_mutex_unlock(&g_apObjMutex);
    return result;
}

WifiErrorNo HdiApStop(int id)
{
    LOGI("HdiApStop stop...");
    pthread_mutex_lock(&g_apObjMutex);

    int32_t ret;
    ret = g_apObj->DisableAp(g_apObj, g_apIfaceName, id);
    ret = g_apObj->StopAp(g_apObj);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s Stop failed: %{public}d", __func__, ret);
    }
    IHostapdInterfaceReleaseInstance(HDI_AP_SERVICE_NAME, g_apObj, false);
    g_apObj = NULL;
    g_apDevMgr->UnloadDevice(g_apDevMgr, HDI_AP_SERVICE_NAME);
    g_apDevMgr = NULL;
    g_apIsRunning = false;
    pthread_mutex_unlock(&g_apObjMutex);
    LOGI("HdiApStop stop success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo IsHdiApStopped()
{
    pthread_mutex_lock(&g_apObjMutex);
    if (g_apIsRunning == false && g_apObj == NULL && g_apDevMgr == NULL) {
        LOGI("IsHdiApStopped, HdiAp already stopped");
        pthread_mutex_unlock(&g_apObjMutex);
        return WIFI_IDL_OPT_OK;
    }

    pthread_mutex_unlock(&g_apObjMutex);
    return WIFI_IDL_OPT_FAILED;
}

struct IHostapdInterface* GetApInterface()
{
    struct IHostapdInterface *apObj = NULL;
    pthread_mutex_lock(&g_apObjMutex);
    apObj = g_apObj;
    pthread_mutex_unlock(&g_apObjMutex);
    return apObj;
}

WifiErrorNo SetHdiApIfaceName(const char *ifaceName)
{
    pthread_mutex_lock(&g_apIfaceNameMutex);
    if (ifaceName == NULL) {
        pthread_mutex_unlock(&g_apIfaceNameMutex);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (memset_s(g_apCfgName, CFGNAME_LEN, 0, CFGNAME_LEN) != EOK
        || memset_s(g_apIfaceName, IFACENAME_LEN, 0, IFACENAME_LEN) != EOK
        || memset_s(g_hostapdCfg, CTRL_LEN, 0, CTRL_LEN) != EOK) {
        pthread_mutex_unlock(&g_apIfaceNameMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    if (strncmp(ifaceName, AP_IFNAME_COEX, IFACENAME_LEN -1) == 0) {
        if (strcpy_s(g_apCfgName, CFGNAME_LEN, WIFI_COEX_CFG) != EOK
            || strcpy_s(g_apIfaceName, IFACENAME_LEN, AP_IFNAME_COEX) != EOK
            || strcpy_s(g_hostapdCfg, CTRL_LEN, HOSTAPD_DEFAULT_CFG_COEX) != EOK) {
            pthread_mutex_unlock(&g_apIfaceNameMutex);
            return WIFI_IDL_OPT_FAILED;
        }
    } else {
        if (strcpy_s(g_apCfgName, CFGNAME_LEN, WIFI_DEFAULT_CFG) != EOK
            || strcpy_s(g_apIfaceName, IFACENAME_LEN, AP_IFNAME) != EOK
            || strcpy_s(g_hostapdCfg, CTRL_LEN, HOSTAPD_DEFAULT_CFG) != EOK) {
            pthread_mutex_unlock(&g_apIfaceNameMutex);
            return WIFI_IDL_OPT_FAILED;
        }
    }

    LOGI("SetHdiApIfaceName, g_apIfaceName:%{public}s", g_apIfaceName);
    pthread_mutex_unlock(&g_apIfaceNameMutex);
    return WIFI_IDL_OPT_OK;
}

const char *GetHdiApIfaceName()
{
    const char *ifaceName = NULL;
    pthread_mutex_lock(&g_apIfaceNameMutex);
    ifaceName = g_apIfaceName;
    pthread_mutex_unlock(&g_apIfaceNameMutex);
    return ifaceName;
}

void SetExecDisable(int execDisable)
{
    g_execDisable = execDisable;
}

int GetExecDisable()
{
    return g_execDisable;
}

#endif