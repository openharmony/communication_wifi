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

#include "wifi_hal_adapter.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "securec.h"
#include "wifi_common_def.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalAdapter"

WifiHalVendorInterface *g_wifiHalVendorInterface = NULL;

#define MODULE_NAME_MAX_LEN 256
#define MODULE_CONFIG_FILE_PATH CONFIG_ROOR_DIR"/wifi_hal_vendor.conf"
#define PATH_NUM 2
#define BUFF_SIZE 256

static int ReadConfigModuleName(char *name, int size)
{
    if (name == NULL) {
        return HAL_FAILURE;
    }
    FILE *fp = fopen(MODULE_CONFIG_FILE_PATH, "r");
    if (fp == NULL) {
        LOGE("open module configuration file failed");
        return HAL_SUCCESS; /* file not exist, use default operators */
    }
    int flag = 0;
    do {
        fseek(fp, 0, SEEK_END);
        int len = ftell(fp);
        if ((len >= size) || (len == -1)) {
            LOGE("config file size too big, config file may not correct!");
            break;
        }
        rewind(fp);
        int ret = fread(name, sizeof(char), (size_t)len, fp);
        if (ret != len) {
            LOGE("read file failed!");
            break;
        }
        flag += 1;
    } while (0);
    fclose(fp);
    return (flag == 0) ? -1 : 0;
}

static int OpenHalVendorModule(WifiHalVendorInterface *pInterface)
{
    if (pInterface == NULL) {
        return HAL_FAILURE;
    }
    char name[MODULE_NAME_MAX_LEN] = {0};
    if (ReadConfigModuleName(name, MODULE_NAME_MAX_LEN) < 0) {
        return HAL_FAILURE;
    }
    if (strlen(name) <= 0) {
        LOGW("module name is null.");
        return HAL_SUCCESS;
    }

    void *handle = dlopen(name, RTLD_LAZY);
    if (handle == NULL) {
        LOGE("open config [%{public}s] so failed![%{public}s]", name, dlerror());
        return HAL_FAILURE;
    }
    int flag = 0;
    do {
        pInitHalVendorFunc pFunc = (pInitHalVendorFunc)dlsym(handle, "InitHalVendorFunc");
        if (pFunc == NULL) {
            LOGE("Not find InitHalVendorFunc, cannot use this [%{public}s] so", name);
            break;
        }
        HalVendorError err = pFunc(&pInterface->func);
        if (err != HAL_VENDOR_SUCCESS) {
            LOGE("init hal vendor function table failed! name [%{public}s], ret[%{public}d]", name, err);
            break;
        }
        err = pInterface->func.wifiInitialize();
        if (err != HAL_VENDOR_SUCCESS) {
            LOGE("init vendor hal failed!, ret[%{public}d]", err);
            break;
        }
        pInterface->handle = handle;
        flag += 1;
    } while (0);
    if (flag == 0) {
        dlclose(handle);
        return HAL_FAILURE;
    }
    return HAL_SUCCESS;
}

WifiHalVendorInterface *GetWifiHalVendorInterface(void)
{
    if (g_wifiHalVendorInterface != NULL) {
        return g_wifiHalVendorInterface;
    }
    g_wifiHalVendorInterface = (WifiHalVendorInterface *)calloc(1, sizeof(WifiHalVendorInterface));
    if (g_wifiHalVendorInterface == NULL) {
        return NULL;
    }
    InitDefaultHalVendorFunc(&g_wifiHalVendorInterface->func);
    int ret = OpenHalVendorModule(g_wifiHalVendorInterface);
    if (ret < 0) {
        ReleaseWifiHalVendorInterface();
    }
    return g_wifiHalVendorInterface;
}

void ReleaseWifiHalVendorInterface(void)
{
    if (g_wifiHalVendorInterface != NULL) {
        if (g_wifiHalVendorInterface->handle != NULL) {
            if (g_wifiHalVendorInterface->func.wifiCleanUp) {
                g_wifiHalVendorInterface->func.wifiCleanUp();
            }
            dlclose(g_wifiHalVendorInterface->handle);
        }
        free(g_wifiHalVendorInterface);
        g_wifiHalVendorInterface = NULL;
    }
    return;
}

int ExcuteCmd(const char *szCmd)
{
    LOGI("Execute cmd: %{private}s", szCmd);
    int ret = system(szCmd);
    if (ret == -1) {
        LOGE("Execute system cmd %{private}s failed!", szCmd);
        return HAL_FAILURE;
    }
    if (WIFEXITED(ret) && (WEXITSTATUS(ret) == 0)) {
        return HAL_SUCCESS;
    }
    LOGE("Execute system cmd %{private}s failed: %{private}d", szCmd, WEXITSTATUS(ret));
    return HAL_FAILURE;
}

int CopyConfigFile(const char* configName)
{
    char buf[BUFF_SIZE] = {0};
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%s/wpa_supplicant/%s", CONFIG_ROOR_DIR, configName) < 0) {
        LOGE("snprintf_s dest dir failed.");
        return HAL_FAILURE;
    }
    if (access(buf, F_OK) != -1) {
        LOGI("Configure file %{public}s is exist.", buf);
        return HAL_SUCCESS;
    }
    char path[PATH_NUM][BUFF_SIZE] = {"/vendor/etc/wifi/", "/system/etc/wifi/"};
    for (int i = 0; i != PATH_NUM; ++i) {
        if (strcat_s(path[i], sizeof(path[i]), configName) != EOK) {
            LOGE("strcat_s failed.");
            return HAL_FAILURE;
        }
        if (access(path[i], F_OK) != -1) {
            char cmd[BUFF_SIZE] = {0};
            if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
                "cp %s %s/wpa_supplicant/", path[i], CONFIG_ROOR_DIR) < 0) {
                LOGE("snprintf_s cp cmd failed.");
                return HAL_FAILURE;
            }
            return ExcuteCmd(cmd);
        }
    }
    LOGE("Copy config file failed: %{public}s", configName);
    return HAL_FAILURE;
}