/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

#include "wifi_hal_chba_interface.h"
#include "securec.h"
#include "wifi_common_hal.h"
#include "wifi_common_def.h"
#include "wifi_hal_adapter.h"
#include "wifi_hal_module_manage.h"
#include "wifi_log.h"
#include "wifi_wpa_hal.h"
#include "unistd.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalChbaInterface"

const char *g_wpaSupplicantChba = "wpa_supplicant";
const char *g_systemCmdWpaChbaStart = "wpa_supplicant -ichba0 -g/data/service/el1/public/wifi/sockets/wpa/chba0";

static WifiErrorNo ChbaStartSupplicant(void)
{
    LOGD("Start chba supplicant");
    if (CopyConfigFile("p2p_supplicant.conf") != 0) {
        return WIFI_HAL_FAILED;
    }
    ModuleManageRetCode ret = StartModule(g_wpaSupplicantChba, g_systemCmdWpaChbaStart);
    if (ret == MM_SUCCESS) {
        return WIFI_HAL_SUCCESS;
    }
    LOGE("start wpa_supplicant failed!");
    return WIFI_HAL_FAILED;
}

static WifiErrorNo ChbaConnectSupplicant(void)
{
    LOGD("Ready to connect chba_wpa_supplicant.");
    WifiWpaChbaInterface *pMainIfc = GetWifiWpaChbaInterface();
    if (pMainIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    return WIFI_HAL_SUCCESS;
}

static WifiErrorNo ChbaStopSupplicant(void)
{
    LOGD("stop chba supplicant");
    ModuleManageRetCode ret = StopModule(g_wpaSupplicantChba, false);
    if (ret == MM_FAILED) {
        LOGE("stop chba_wpa_supplicant failed!");
        return WIFI_HAL_FAILED;
    }
    if (ret == MM_SUCCESS) {
        ReleaseWpaGlobalInterface();
    }
    return WIFI_HAL_SUCCESS;
}

static WifiErrorNo ChbaDisconnectSupplicant(void)
{
    LOGD("Ready to disconnect chba_wpa_supplicant.");
    WifiWpaChbaInterface *pMainIfc = GetWifiWpaChbaInterface();
    if (pMainIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    LOGD("Disconnect chba_wpa_supplicant finish!");
    return WIFI_HAL_SUCCESS;
}

static WifiErrorNo StopChbaWpaAndWpaHal(void)
{
    if (ChbaDisconnectSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("chba_wpa_s hal already stop!");
    }
    WifiWpaInterface *pWpaInterface = GetWifiWapGlobalInterface();
    if (pWpaInterface != NULL) {
        pWpaInterface->wpaCliRemoveIface(pWpaInterface, "chba0");
    }
    if (ChbaStopSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("chba_wpa_supplicant stop failed!");
        return WIFI_HAL_FAILED;
    }
    LOGD("chba_wpa_supplicant stop success!");
    ReleaseWpaChbaInterface();
    return WIFI_HAL_SUCCESS;
}

static WifiErrorNo AddChbaIface(void)
{
    WifiWpaInterface *pWpaInterface = GetWifiWapGlobalInterface();
    if (pWpaInterface == NULL) {
        LOGE("chba Get wpa interface failed!");
        return WIFI_HAL_FAILED;
    }
    if (pWpaInterface->wpaCliConnect(pWpaInterface) < 0) {
        LOGE("chba Failed to connect to wpa!");
        return WIFI_HAL_FAILED;
    }
    AddInterfaceArgv argv;
    if (strcpy_s(argv.name, sizeof(argv.name), "chba0") != EOK ||
        strcpy_s(argv.confName, sizeof(argv.confName), "/data/service/el1/public/wifi/wpa_supplicant/p2p_supplicant.conf") != EOK) {
        return WIFI_HAL_FAILED;
    }
    if (pWpaInterface->wpaCliAddIface(pWpaInterface, &argv, true) < 0) {
        LOGE("Failed to add wpa iface!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ChbaStart(void)
{
    if (ChbaStartSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("chba_wpa_supplicant start failed!");
        return WIFI_HAL_OPEN_SUPPLICANT_FAILED;
    }
    if (AddChbaIface() != WIFI_HAL_SUCCESS || ChbaConnectSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("Supplicant connect chba_wpa_supplicant failed!");
        StopChbaWpaAndWpaHal();
        return WIFI_HAL_CONN_SUPPLICANT_FAILED;
    }
    int startchba = 1;
    char eventStr[25];
    if (sprintf_s(eventStr, sizeof(eventStr), "P2P-CONNECTED status =%d", startchba) < 0) {
        LOGE("ChbaStop sprintf_s failed! ");
        return WIFI_HAL_FAILED;
    }
    HalCallbackNotify(eventStr);
    LOGD("Supplicant connect chba_wpa_supplicant success!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ChbaStop(void)
{
    WifiErrorNo ret = StopChbaWpaAndWpaHal();
    if (ret == WIFI_HAL_FAILED) {
        return WIFI_HAL_FAILED;
    }
    int stopchba = 0;
    char eventStr[25];
    if (sprintf_s(eventStr, sizeof(eventStr), "P2P-CONNECTED status =%d", stopchba) < 0) {
        LOGE("ChbaStop sprintf_s failed! ");
        return WIFI_HAL_FAILED;
    }
    HalCallbackNotify(eventStr);
    return WIFI_HAL_SUCCESS;
}