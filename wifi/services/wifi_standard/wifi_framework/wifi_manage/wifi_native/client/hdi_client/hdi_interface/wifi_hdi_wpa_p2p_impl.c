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
#include "wifi_hdi_wpa_p2p_impl.h"
#include "wifi_hdi_util.h"
#include "wifi_log.h"
#include "stub_collector.h"
#include "wifi_native_define.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaP2pImpl"
#define REPLY_BUF_LENGTH (1024)
#define BUFF_SIZE 256
#define P2P_RANDOM_MAC_FLAG "p2p_device_random_mac_addr=1\n"
#define PERSISENT_MAC_LEN 55
#define PERSISENT_MAC_STRING "p2p_device_persistent_mac_addr"
#define P2P_SUPPLICANT_PATH CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf"

typedef struct HdiP2pWpaNetworkField {
    P2pGroupConfigType field;
    char fieldName[32];
    int flag; /* 0 need add "" 1 no need */
} HdiP2pWpaNetworkField;

static const HdiP2pWpaNetworkField g_hdiP2pWpaNetworkFields[] = {
    {GROUP_CONFIG_SSID, "ssid", 0},
    {GROUP_CONFIG_BSSID, "bssid", 1},
    {GROUP_CONFIG_PSK, "psk", 1},
    {GROUP_CONFIG_PROTO, "proto", 1},
    {GROUP_CONFIG_KEY_MGMT, "key_mgmt", 1},
    {GROUP_CONFIG_PAIRWISE, "pairwise", 1},
    {GROUP_CONFIG_AUTH_ALG, "auth_alg", 1},
    {GROUP_CONFIG_MODE, "mode", 1},
    {GROUP_CONFIG_DISABLED, "disabled", 1}
};

static struct IWpaCallback *g_hdiWpaP2pCallbackObj = NULL;

void ReleaseP2pCallback(void)
{
    StubCollectorRemoveObject(IWPACALLBACK_INTERFACE_DESC, g_hdiWpaP2pCallbackObj);
    free(g_hdiWpaP2pCallbackObj);
    g_hdiWpaP2pCallbackObj = NULL;
}

static WifiErrorNo RegisterP2pEventCallback()
{
    LOGI("RegisterP2pEventCallback enter");
    pthread_mutex_lock(GetWpaObjMutex());
    if (g_hdiWpaP2pCallbackObj == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterP2pEventCallback: g_hdiWpaP2pCallbackObj is NULL");
        return WIFI_HAL_OPT_FAILED;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterP2pEventCallback: wpaObj is NULL");
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->RegisterWpaEventCallback(wpaObj, g_hdiWpaP2pCallbackObj, GetHdiP2pIfaceName());
    if (result != HDF_SUCCESS) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterP2pEventCallback: RegisterEventCallback failed result:%{public}d", result);
        return WIFI_HAL_OPT_FAILED;
    }

    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("RegisterP2pEventCallback success.");
    return WIFI_HAL_OPT_OK;
}

static WifiErrorNo AddP2pRandomMacFlag()
{
    char str[BUFF_SIZE] = { 0 };
    int indicate = 0;
    FILE *fp = fopen(P2P_WPA_CONFIG_FILE, "a+");
    if (fp == NULL) {
        LOGE("%{public}s: failed to open the file", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    while (fgets(str, BUFF_SIZE, fp)) {
        if (strstr(str, P2P_RANDOM_MAC_FLAG) != NULL) {
            indicate = 1;
            break;
        }
        if (memset_s(str, sizeof(str), 0x0, sizeof(str)) != EOK) {
            LOGE("%{public}s: memset_s is failed", __func__);
            fclose(fp);
            return WIFI_HAL_OPT_FAILED;
        }
    }
    if (indicate == 0) {
        int ret = fputs(P2P_RANDOM_MAC_FLAG, fp);
        if (ret < 0) {
            LOGE("%{public}s: failed to update the file", __func__);
            fclose(fp);
            return WIFI_HAL_OPT_FAILED;
        } else {
            LOGD("%{public}s: success to update the file, ret:%{public}d", __func__, ret);
        }
    }
    fclose(fp);
    return WIFI_HAL_OPT_OK;
}

bool GetOldMac(char *mac, int len)
{
    char line[BUFF_SIZE];
 
    FILE *fp = fopen(P2P_SUPPLICANT_PATH, "r");
    if (fp == NULL) {
        return false;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, PERSISENT_MAC_STRING) != NULL) {
            if (memcpy_s(mac, len, line, strlen(line)) != EOK) {
                fclose(fp);
                return false;
            }
            fclose(fp);
            return true;
        }
    }
    if (fclose(fp) != 0) {
        LOGE("close fp failed");
    }
    return false;
}
 
void AppendMac(char *mac, int len)
{
    FILE *fp = fopen(P2P_SUPPLICANT_PATH, "a");
    if (fp == NULL) {
        LOGE("Error! Could not open file\n");
        return;
    }
    if (fwrite("\n", sizeof(char), strlen("\n"), fp) == 0) {
        LOGE("write \n faild");
    }
    if (fwrite(mac, sizeof(char), len, fp) == 0) {
        LOGE("write mac faild");
    }
    if (fclose(fp) != 0) {
        LOGE("close fp failed");
    }
}

WifiErrorNo HdiWpaP2pStart(const char *ifaceName, const bool hasPersisentGroup)
{
    char persisentMac[PERSISENT_MAC_LEN] = {0};
    bool hasPersisentMac = false;

    LOGI("HdiWpaP2pStart enter");
    if (SetHdiP2pIfaceName(ifaceName) != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStart: set p2p iface name failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    if (hasPersisentGroup) {
        hasPersisentMac = GetOldMac(persisentMac, PERSISENT_MAC_LEN);
    }
    if (CopyConfigFile("p2p_supplicant.conf") != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStart: CopyConfigFile failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    if (hasPersisentMac) {
        AppendMac(persisentMac, PERSISENT_MAC_LEN);
    }
    if (HdiWpaStart() != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStart: HdiWpaStart failed!");
        return WIFI_HAL_OPT_FAILED;
    }

    if (RegisterP2pEventCallback() != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStart: RegisterEventCallback failed!");
        return WIFI_HAL_OPT_FAILED;
    }

    if (HdiAddWpaIface(GetHdiP2pIfaceName(), CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStart: HdiAddWpaIface failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    
    LOGI("HdiWpaP2pStart success");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaP2pStop()
{
    LOGI("HdiWpaP2pStop enter");
    if (IsHdiWpaStopped() == WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStop: HdiWpa already stopped, HdiWpaP2pStop success");
        return WIFI_HAL_OPT_OK;
    }

    if (HdiRemoveWpaIface(GetHdiP2pIfaceName()) != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaP2pStop: HdiRemoveWpaIface failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    
    LOGI("HdiWpaP2pStop success");
    return WIFI_HAL_OPT_OK;
}

static void InitHdiWpaP2pCallbackObj(struct IWpaCallback *callback)
{
    g_hdiWpaP2pCallbackObj->OnEventDeviceFound = callback->OnEventDeviceFound;
    g_hdiWpaP2pCallbackObj->OnEventDeviceLost = callback->OnEventDeviceLost;
    g_hdiWpaP2pCallbackObj->OnEventGoNegotiationRequest = callback->OnEventGoNegotiationRequest;
    g_hdiWpaP2pCallbackObj->OnEventGoNegotiationCompleted = callback->OnEventGoNegotiationCompleted;
    g_hdiWpaP2pCallbackObj->OnEventInvitationReceived = callback->OnEventInvitationReceived;
    g_hdiWpaP2pCallbackObj->OnEventInvitationResult = callback->OnEventInvitationResult;
    g_hdiWpaP2pCallbackObj->OnEventGroupFormationSuccess = callback->OnEventGroupFormationSuccess;
    g_hdiWpaP2pCallbackObj->OnEventGroupFormationFailure = callback->OnEventGroupFormationFailure;
    g_hdiWpaP2pCallbackObj->OnEventGroupStarted = callback->OnEventGroupStarted;
    g_hdiWpaP2pCallbackObj->OnEventGroupInfoStarted = callback->OnEventGroupInfoStarted;
    g_hdiWpaP2pCallbackObj->OnEventGroupRemoved = callback->OnEventGroupRemoved;
    g_hdiWpaP2pCallbackObj->OnEventProvisionDiscoveryCompleted = callback->OnEventProvisionDiscoveryCompleted;
    g_hdiWpaP2pCallbackObj->OnEventFindStopped = callback->OnEventFindStopped;
    g_hdiWpaP2pCallbackObj->OnEventServDiscReq = callback->OnEventServDiscReq;
    g_hdiWpaP2pCallbackObj->OnEventServDiscResp = callback->OnEventServDiscResp;
    g_hdiWpaP2pCallbackObj->OnEventStaConnectState = callback->OnEventStaConnectState;
    g_hdiWpaP2pCallbackObj->OnEventIfaceCreated = callback->OnEventIfaceCreated;
}

WifiErrorNo RegisterHdiWpaP2pEventCallback(struct IWpaCallback *callback)
{
    LOGI("RegisterHdiWpaP2pEventCallback enter");
    pthread_mutex_lock(GetWpaObjMutex());
    if (callback == NULL || callback->OnEventDeviceFound == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterHdiWpaP2pEventCallback: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    if (g_hdiWpaP2pCallbackObj != NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGI("RegisterHdiWpaP2pEventCallback: already register!");
        return WIFI_HAL_OPT_OK;
    }

    g_hdiWpaP2pCallbackObj = (struct IWpaCallback *)malloc(sizeof(struct IWpaCallback));
    if (g_hdiWpaP2pCallbackObj == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterHdiWpaP2pEventCallback: IWpaCallback malloc failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    if (memset_s(g_hdiWpaP2pCallbackObj, sizeof(struct IWpaCallback),
        0, sizeof(struct IWpaCallback)) != EOK) {
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    InitHdiWpaP2pCallbackObj(callback);
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("RegisterHdiWpaP2pEventCallback success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetSsidPostfixName(const char *name)
{
    LOGI("HdiP2pSetSsidPostfixName enter, name:%{private}s", name);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetSsidPostfixName: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetSsidPostfixName(wpaObj, GetHdiP2pIfaceName(), name);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetSsidPostfixName: P2pSetSsidPostfixName failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetSsidPostfixName success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetWpsDeviceType(const char *type)
{
    LOGI("HdiP2pSetWpsDeviceType enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetWpsDeviceType: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetWpsDeviceType(wpaObj, GetHdiP2pIfaceName(), type);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetWpsDeviceType: P2pSetWpsDeviceType failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetWpsDeviceType success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetWpsConfigMethods(const char *methods)
{
    LOGI("HdiP2pSetWpsConfigMethods enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetWpsConfigMethods: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetWpsConfigMethods(wpaObj, GetHdiP2pIfaceName(), methods);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetWpsConfigMethods: P2pSetWpsConfigMethods failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetWpsConfigMethods success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetGroupMaxIdle(const char *groupIfc, int time)
{
    LOGI("HdiP2pSetGroupMaxIdle enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetGroupMaxIdle: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetGroupMaxIdle(wpaObj, groupIfc, time);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetGroupMaxIdle: P2pSetGroupMaxIdle failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetGroupMaxIdle success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetWfdEnable(int enable)
{
    LOGI("HdiP2pSetWfdEnable enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetWfdEnable: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetWfdEnable(wpaObj, GetHdiP2pIfaceName(), enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetWfdEnable: P2pSetWfdEnable failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetWfdEnable success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetPersistentReconnect(int status)
{
    LOGI("HdiP2pSetPersistentReconnect enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetPersistentReconnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetPersistentReconnect(wpaObj, GetHdiP2pIfaceName(), status);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetPersistentReconnect: P2pSetPersistentReconnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetPersistentReconnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetWpsSecondaryDeviceType(const char *type)
{
    LOGI("HdiP2pSetWpsSecondaryDeviceType enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetWpsSecondaryDeviceType: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetWpsSecondaryDeviceType(wpaObj, GetHdiP2pIfaceName(), type);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetWpsSecondaryDeviceType: P2pSetWpsSecondaryDeviceType failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetWpsSecondaryDeviceType success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetupWpsPbc(const char *groupIfc, const char *address)
{
    char anonymizeAddr[MAC_STRING_SIZE + 1] = {0};
    if (ConvertMacArr2String((const unsigned char *)address, MAC_UINT_SIZE,
                             anonymizeAddr, sizeof(anonymizeAddr)) != 0) {
        LOGE("HdiP2pSetupWpsPbc: failed to convert address!");
    }
    LOGI("HdiP2pSetupWpsPbc enter groupIfc=%{public}s anonymizeAddr=%{public}s", groupIfc, anonymizeAddr);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetupWpsPbc: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetupWpsPbc(wpaObj, groupIfc, address);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetupWpsPbc: P2pSetupWpsPbc failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetupWpsPbc success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetupWpsPin(const char *groupIfc, const char *address, const char *pin, char *result)
{
    LOGI("HdiP2pSetupWpsPin enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetupWpsPin: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t res = wpaObj->P2pSetupWpsPin(wpaObj, groupIfc, address, pin, result, REPLY_BUF_LENGTH);
    if (res != HDF_SUCCESS) {
        LOGE("HdiP2pSetupWpsPin: P2pSetupWpsPin failed res:%{public}s", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetupWpsPin success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetPowerSave(const char *groupIfc, int enable)
{
    LOGI("HdiP2pSetPowerSave enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetPowerSave: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetPowerSave(wpaObj, groupIfc, enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetPowerSave: P2pSetPowerSave failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetPowerSave success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetDeviceName(const char *name)
{
    LOGI("HdiP2pSetDeviceName enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetDeviceName: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetDeviceName(wpaObj, GetHdiP2pIfaceName(), name);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetDeviceName: P2pSetDeviceName failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetDeviceName success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetWfdDeviceConfig(const char *config)
{
    LOGI("HdiP2pSetWfdDeviceConfig enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetWfdDeviceConfig: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetWfdDeviceConfig(wpaObj, GetHdiP2pIfaceName(), config);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetWfdDeviceConfig: P2pSetWfdDeviceConfig failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetWfdDeviceConfig success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetRandomMac(int enable)
{
    LOGI("HdiP2pSetRandomMac enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetRandomMac: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetRandomMac(wpaObj, GetHdiP2pIfaceName(), enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetRandomMac: P2pSetRandomMac failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    if (AddP2pRandomMacFlag() != WIFI_HAL_OPT_OK) {
        LOGW("%{public}s: failed to write %{public}s", __func__, P2P_RANDOM_MAC_FLAG);
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetRandomMac success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pStartFind(int timeout)
{
    LOGI("HdiP2pStartFind enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pStartFind: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pStartFind(wpaObj, GetHdiP2pIfaceName(), timeout);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pStartFind: P2pStartFind failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pStartFind success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetExtListen(int enable, int period, int interval)
{
    LOGI("HdiP2pSetExtListen enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetExtListen: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetExtListen(wpaObj, GetHdiP2pIfaceName(), enable, period, interval);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetExtListen: P2pSetExtListen failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetExtListen success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetListenChannel(int channel, int regClass)
{
    LOGI("HdiP2pSetListenChannel enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetListenChannel: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetListenChannel(wpaObj, GetHdiP2pIfaceName(), channel, regClass);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetListenChannel: P2pSetListenChannel failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetListenChannel success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pProvisionDiscovery(const char *peerBssid, int mode)
{
    LOGI("HdiP2pProvisionDiscovery enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pProvisionDiscovery: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pProvisionDiscovery(wpaObj, GetHdiP2pIfaceName(), peerBssid, mode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pProvisionDiscovery: P2pProvisionDiscovery failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pProvisionDiscovery success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pAddGroup(int isPersistent, int networkId, int freq)
{
    LOGI("HdiP2pAddGroup enter isPersistent=%{public}d", isPersistent);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pAddGroup: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pAddGroup(wpaObj, GetHdiP2pIfaceName(), isPersistent, networkId, freq);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pAddGroup: P2pAddGroup failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pAddGroup success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pAddService(struct HdiP2pServiceInfo *info)
{
    LOGI("HdiP2pAddService enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pAddService: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pAddService(wpaObj, GetHdiP2pIfaceName(), info);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pAddService: P2pAddService failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pAddService success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pRemoveService(struct HdiP2pServiceInfo *info)
{
    LOGI("HdiP2pRemoveService enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pRemoveService: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pRemoveService(wpaObj, GetHdiP2pIfaceName(), info);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pRemoveService: P2pRemoveService failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pRemoveService success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pStopFind()
{
    LOGI("HdiP2pStopFind enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pStopFind: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pStopFind(wpaObj, GetHdiP2pIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pStopFind: P2pStopFind failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pStopFind success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pFlush()
{
    LOGI("HdiP2pFlush enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pFlush: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pFlush(wpaObj, GetHdiP2pIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pFlush: P2pFlush failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pFlush success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pFlushService()
{
    LOGI("HdiP2pFlushService enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pFlushService: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pFlushService(wpaObj, GetHdiP2pIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pFlushService: P2pFlushService failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pFlushService success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pRemoveNetwork(int networkId)
{
    LOGI("HdiP2pRemoveNetwork enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pRemoveNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pRemoveNetwork(wpaObj, GetHdiP2pIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pRemoveNetwork: P2pRemoveNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pRemoveNetwork success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetSingleConfig(int networkId, const char *key, const char *value)
{
    LOGI("HdiP2pSetSingleConfig enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetSingleConfig: wpaObj is NULL");
        return WIFI_HAL_OPT_FAILED;
    }
    char cfgValue[WIFI_P2P_GROUP_CONFIG_VALUE_LENGTH];
    if (sprintf_s(cfgValue, sizeof(cfgValue), "%s", value) < 0) {
        return WIFI_HAL_OPT_FAILED;
    }
    int32_t result = wpaObj->P2pSetGroupConfig(wpaObj, GetHdiP2pIfaceName(), networkId, key, cfgValue);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetSingleConfig failed result:%{public}d", result);
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiP2pSetSingleConfig success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetGroupConfig(int networkId, P2pGroupConfig *pConfig, int size)
{
    LOGI("HdiP2pSetGroupConfig enter size=%{public}d", size);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetGroupConfig: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    for (int i = 0; i < size; ++i) {
        int32_t result = wpaObj->P2pSetGroupConfig(wpaObj, GetHdiP2pIfaceName(), networkId,
            g_hdiP2pWpaNetworkFields[pConfig[i].cfgParam].fieldName, pConfig[i].cfgValue);
        if (result != HDF_SUCCESS) {
            LOGE("HdiP2pSetGroupConfig: %{public}s failed result:%{public}d",
                g_hdiP2pWpaNetworkFields[pConfig[i].cfgParam].fieldName, result);
            pthread_mutex_unlock(GetWpaObjMutex());
            return WIFI_HAL_OPT_FAILED;
        }
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetGroupConfig success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pInvite(const char *peerBssid, const char *goBssid, const char *ifname)
{
    LOGI("HdiP2pInvite enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pInvite: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pInvite(wpaObj, ifname, peerBssid, goBssid);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pInvite: P2pInvite failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pInvite success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pReinvoke(int networkId, const char *bssid)
{
    LOGI("HdiP2pReinvoke enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pReinvoke: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pReinvoke(wpaObj, GetHdiP2pIfaceName(), networkId, bssid);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pReinvoke: P2pReinvoke failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pReinvoke success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pGetDeviceAddress(char *deviceAddress, int size)
{
    LOGI("HdiP2pGetDeviceAddress enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pGetDeviceAddress: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pGetDeviceAddress(wpaObj, GetHdiP2pIfaceName(), deviceAddress, size);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pGetDeviceAddress: P2pGetDeviceAddress failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pGetDeviceAddress success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pReqServiceDiscovery(struct HdiP2pReqService *reqService, char *replyDisc, int size)
{
    LOGI("HdiP2pReqServiceDiscovery enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pReqServiceDiscovery: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pReqServiceDiscovery(wpaObj, GetHdiP2pIfaceName(), reqService,
        replyDisc, size);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pReqServiceDiscovery: P2pReqServiceDiscovery failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pReqServiceDiscovery success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pCancelServiceDiscovery(const char *id)
{
    LOGI("HdiP2pCancelServiceDiscovery enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pCancelServiceDiscovery: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pCancelServiceDiscovery(wpaObj, GetHdiP2pIfaceName(), id);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pCancelServiceDiscovery: P2pCancelServiceDiscovery failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pCancelServiceDiscovery success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pRespServerDiscovery(struct HdiP2pServDiscReqInfo *info)
{
    LOGI("HdiP2pRespServerDiscovery enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pRespServerDiscovery: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pRespServerDiscovery(wpaObj, GetHdiP2pIfaceName(), info);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pRespServerDiscovery: P2pRespServerDiscovery failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pRespServerDiscovery success.");
    return WIFI_HAL_OPT_OK;
}
#define HDI_POS_TEN 10
static int hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + HDI_POS_TEN;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + HDI_POS_TEN;
    }
    return -1;
}

static int hex2byte(const char *hex)
{
    int a = hex2num(*hex++);
    if (a < 0) {
        return -1;
    }
    int b = hex2num(*hex++);
    if (b < 0) {
        return -1;
    }
    return (a << HDI_POS_FOURTH) | b;
}

static char* hwaddr_parse(char *txt, uint8_t *addr)
{
    size_t i;

    for (i = 0; i < ETH_ALEN; i++) {
        int a;

        a = hex2byte(txt);
        if (a < 0)
            return NULL;
        txt += HDI_MAC_SUB_LEN;
        addr[i] = a;
        if (i < ETH_ALEN - 1 && *txt++ != ':')
            return NULL;
    }
    return txt;
}

static int hwaddr_aton(char *txt, uint8_t *addr)
{
    return hwaddr_parse(txt, addr) ? 0 : -1;
}

WifiErrorNo HdiP2pConnect(P2pConnectInfo *info, char *replyPin, int size)
{
    LOGI("HdiP2pConnect enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pConnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    struct HdiP2pConnectInfo wpsParam = {0};
    wpsParam.persistent = info->persistent;
    wpsParam.mode = info->mode;
    wpsParam.goIntent = info->goIntent;
    wpsParam.provdisc = info->provdisc;
    uint8_t addr[ETH_ALEN];
    hwaddr_aton(info->peerDevAddr, addr);
    wpsParam.peerDevAddr = addr;
    wpsParam.peerDevAddrLen = ETH_ALEN;
    wpsParam.pin = (uint8_t *)info->pin;
    wpsParam.pinLen = HDI_PIN_LEN;

    int32_t result = wpaObj->P2pConnect(wpaObj, GetHdiP2pIfaceName(), &wpsParam, replyPin, size - 1);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pConnect: P2pConnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pConnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pHid2dConnect(struct Hid2dConnectInfo *info)
{
    LOGI("HdiP2pHid2dConnect enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pHid2dConnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    struct HdiHid2dConnectInfo wpsParam = {0};
    uint8_t addr[ETH_ALEN];
    hwaddr_aton(info->bssid, addr);
    wpsParam.ssid = (uint8_t *)info->ssid;
    wpsParam.ssidLen = strlen(info->ssid) + 1;
    wpsParam.bssid = addr;
    wpsParam.bssidLen = ETH_ALEN;
    wpsParam.passphrase = (uint8_t *)info->passphrase;
    wpsParam.passphraseLen = strlen(info->passphrase) + 1;
    wpsParam.frequency = (info->frequency << 16) | (info->isLegacyGo);
    int32_t result = wpaObj->P2pHid2dConnect(wpaObj, GetHdiP2pIfaceName(), &wpsParam);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pHid2dConnect: P2pHid2dConnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pHid2dConnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSetServDiscExternal(int mode)
{
    LOGI("HdiP2pSetServDiscExternal enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSetServDiscExternal: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSetServDiscExternal(wpaObj, GetHdiP2pIfaceName(), mode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSetServDiscExternal: P2pSetServDiscExternal failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSetServDiscExternal success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pRemoveGroup(const char *groupName)
{
    LOGI("HdiP2pRemoveGroup enter groupName=%{public}s", groupName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pRemoveGroup: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pRemoveGroup(wpaObj, GetHdiP2pIfaceName(), groupName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pRemoveGroup: P2pRemoveGroup failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pRemoveGroup success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pCancelConnect()
{
    LOGI("HdiP2pCancelConnect enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pCancelConnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pCancelConnect(wpaObj, GetHdiP2pIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pCancelConnect: P2pCancelConnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pCancelConnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pGetGroupConfig(int networkId, char *param, char *value)
{
    LOGI("HdiP2pGetGroupConfig enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pGetGroupConfig: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pGetGroupConfig(wpaObj, GetHdiP2pIfaceName(), networkId,
        param, value, WIFI_P2P_GROUP_CONFIG_VALUE_LENGTH);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pGetGroupConfig: P2pGetGroupConfig failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pGetGroupConfig success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pAddNetwork(int *networkId)
{
    LOGI("HdiP2pAddNetwork enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pAddNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pAddNetwork(wpaObj, GetHdiP2pIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pAddNetwork: P2pAddNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pAddNetwork success networkId=%{public}d.", *networkId);
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pGetPeer(const char *bssid, struct HdiP2pDeviceInfo *info)
{
    LOGI("HdiP2pGetPeer enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pGetPeer: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pGetPeer(wpaObj, GetHdiP2pIfaceName(), bssid, info);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pGetPeer: P2pGetPeer failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pGetPeer success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pGetGroupCapability(const char *bssid, int cap)
{
    LOGI("HdiP2pGetGroupCapability enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pGetGroupCapability: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pGetGroupCapability(wpaObj, GetHdiP2pIfaceName(), bssid, &cap);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pGetGroupCapability: P2pGetGroupCapability failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pGetGroupCapability success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pListNetworks(struct HdiP2pNetworkList *infoList)
{
    LOGI("HdiP2pListNetworks enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pListNetworks: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pListNetworks(wpaObj, GetHdiP2pIfaceName(), infoList);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pListNetworks: P2pListNetworks failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pListNetworks success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pSaveConfig()
{
    LOGI("HdiP2pSaveConfig enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pSaveConfig: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->P2pSaveConfig(wpaObj, GetHdiP2pIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pSaveConfig: P2pSaveConfig failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pSaveConfig success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiDeliverP2pData(int32_t cmdType, int32_t dataType, const char *carryData)
{
    LOGI("HdiDeliverP2pData enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiDeliverP2pData: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->DeliverP2pData(wpaObj, "p2p0", cmdType, dataType, carryData);
    if (result != HDF_SUCCESS) {
        LOGE("HdiDeliverP2pData: send failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiDeliverP2pData success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pRemoveGroupClient(const char *deviceMac, const char *ifName)
{
    LOGI("HdiP2pRemoveGroupClient enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pRemoveGroupClient: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->DeliverP2pData(wpaObj, ifName, P2P_REMOVE_GROUP_CLIENT, 0, deviceMac);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pRemoveGroupClient: send failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pRemoveGroupClient success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiP2pReject(const char *bssid)
{
    LOGI("HdiP2pReject enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiP2pReject: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->DeliverP2pData(wpaObj, GetHdiP2pIfaceName(), P2P_REJECT, 0, bssid);
    if (result != HDF_SUCCESS) {
        LOGE("HdiP2pReject: send failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiP2pReject success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiSetMiracastSinkConfig(const char *config)
{
    LOGI("HdiSetMiracastSinkConfig enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiSetMiracastSinkConfig: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->DeliverP2pData(wpaObj, GetHdiP2pIfaceName(), P2P_SET_MIRACAST_SINK_CONFIG, 0, config);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetMiracastSinkConfig: send failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiSetMiracastSinkConfig success.");
    return WIFI_HAL_OPT_OK;
}
#endif