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
#include "wifi_hdi_wpa_sta_impl.h"
#include "wifi_hdi_util.h"
#include "wifi_log.h"
#include "stub_collector.h"
#include "wifi_native_define.h"
#include <osal_mem.h>

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaStaImpl"
#define COLUMN_INDEX_ZERO 0
#define COLUMN_INDEX_ONE 1
#define COLUMN_INDEX_TWO 2
#define COLUMN_INDEX_THREE 3
#define COLUMN_INDEX_FOUR 4
#define COLUMN_INDEX_FIVE 5
#define REPLY_BUF_LENGTH (4096 * 10)
#define ETH_ADDR_LEN 6

#ifndef INSTID_WLAN0
#define INSTID_WLAN0 (0)
#endif
#ifndef INSTID_WLAN1
#define INSTID_WLAN1 (1)
#endif

const int QUOTATION_MARKS_FLAG_YES = 0;
const int QUOTATION_MARKS_FLAG_NO = 1;

static struct IWpaCallback *g_hdiWpaStaCallbackObj[STA_INSTANCE_MAX_NUM];
static WpaSsidField g_wpaSsidFields[] = {
    {DEVICE_CONFIG_SSID, "ssid", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PSK, "psk", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_KEYMGMT, "key_mgmt", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PRIORITY, "priority", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SCAN_SSID, "scan_ssid", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP, "eap", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_IDENTITY, "identity", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PASSWORD, "password", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_BSSID, "bssid", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_AUTH_ALGORITHMS, "auth_alg", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_IDX, "wep_tx_keyidx", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_0, "wep_key0", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_1, "wep_key1", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_2, "wep_key2", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_3, "wep_key3", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP_CLIENT_CERT, "client_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PRIVATE_KEY, "private_key", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PHASE2METHOD, "phase2", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_IEEE80211W, "ieee80211w", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_ALLOW_PROTOCOLS, "proto", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_GROUP_CIPHERS, "group", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PAIRWISE_CIPHERS, "pairwise", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SAE_PASSWD, "sae_password", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_CA_CERT, "ca_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_CERT_PWD, "private_key_passwd", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_GROUP_MGMT_CIPHERS, "group_mgmt", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WAPI_PSK, "wapi_psk", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_PSK_TYPE, "psk_key_type", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WAPI_USER_CERT, "wapi_user_sel_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_CA_CERT, "wapi_ca_cert", QUOTATION_MARKS_FLAG_YES},
};

static int GetInstId(const char *ifaceName)
{
    int inst = INSTID_WLAN0;
    if (ifaceName == NULL) {
        LOGE("GetInstId ifaceName is null");
        return inst;
    }
    for (int instId = 0; instId < STA_INSTANCE_MAX_NUM; instId++) {
        const char *hdiStaIfname = GetHdiStaIfaceName(instId);
        if (hdiStaIfname == NULL) {
            continue;
        }
        if (strcmp(ifaceName, hdiStaIfname) == 0) {
            inst = instId;
            break;
        }
    }
    LOGI("GetInstId ifaceName = %{public}sm instId = %{public}d", ifaceName, inst);
    return inst;
}

void ReleaseStaCallback(const char *ifName)
{
    int instId = GetInstId(ifName);
    StubCollectorRemoveObject(IWPACALLBACK_INTERFACE_DESC, g_hdiWpaStaCallbackObj[instId]);
    free(g_hdiWpaStaCallbackObj[instId]);
    g_hdiWpaStaCallbackObj[instId] = NULL;
}

static WifiErrorNo RegisterEventCallback(const char *ifaceName)
{
    LOGI("RegisterEventCallback enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    int instId = GetInstId(ifaceName);
    if (g_hdiWpaStaCallbackObj[instId] == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterEventCallback: g_hdiWpaStaCallbackObj is NULL");
        return WIFI_HAL_OPT_FAILED;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterEventCallback: wpaObj is NULL");
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->RegisterWpaEventCallback(wpaObj, g_hdiWpaStaCallbackObj[instId], ifaceName);
    if (result != HDF_SUCCESS) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterEventCallback: RegisterEventCallback failed result:%{public}d", result);
        return WIFI_HAL_OPT_FAILED;
    }

    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("RegisterEventCallback success.");
    return WIFI_HAL_OPT_OK;
}

static int CalcQuotationMarksFlag(int pos, const char value[WIFI_NETWORK_CONFIG_VALUE_LENGTH])
{
    int flag = g_wpaSsidFields[pos].flag;
    const int HEX_PSK_MAX_LEN = 64;
    int len = strlen(value);
    /* if the psk length is 64, it's hex format and don't need quotation marks */
    if (pos == DEVICE_CONFIG_PSK && len >= HEX_PSK_MAX_LEN) {
        flag = QUOTATION_MARKS_FLAG_NO;
    }
    if (pos == DEVICE_CONFIG_WEP_KEY_0 ||
        pos == DEVICE_CONFIG_WEP_KEY_1 ||
        pos == DEVICE_CONFIG_WEP_KEY_2 ||
        pos == DEVICE_CONFIG_WEP_KEY_3) {
        const int WEP_KEY_LEN1 = 5;
        const int WEP_KEY_LEN2 = 13;
        const int WEP_KEY_LEN3 = 16;
        /* For wep key, ASCII format need quotation marks, hex format is not required */
        if (len == WEP_KEY_LEN1 || len == WEP_KEY_LEN2 || len == WEP_KEY_LEN3) {
            flag = QUOTATION_MARKS_FLAG_YES;
        }
    }
    return flag;
}

static WifiErrorNo SetNetwork(int networkId, SetNetworkConfig conf, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("GetInstId ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    int pos = -1;
    for (unsigned i = 0; i < sizeof(g_wpaSsidFields) / sizeof(g_wpaSsidFields[0]); ++i) {
        if (g_wpaSsidFields[i].field == conf.cfgParam) {
            pos = (int)i;
            break;
        }
    }
    if (pos < 0) {
        LOGE("SetNetwork: unsupported param: %{public}d", conf.cfgParam);
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    char tmpCfgValue[WIFI_NETWORK_CONFIG_VALUE_LENGTH] = {0};
    if (CalcQuotationMarksFlag(pos, conf.cfgValue) == QUOTATION_MARKS_FLAG_YES) {
        if (snprintf_s(tmpCfgValue, sizeof(tmpCfgValue), sizeof(tmpCfgValue) - 1, "\"%s\"", conf.cfgValue) < 0) {
            LOGE("SetNetwork: snprintf_s failed!");
            return WIFI_HAL_OPT_FAILED;
        }
        if (snprintf_s(conf.cfgValue, sizeof(conf.cfgValue), sizeof(conf.cfgValue) - 1, "%s", tmpCfgValue) < 0) {
            LOGE("SetNetwork: snprintf_s failed!");
            return WIFI_HAL_OPT_FAILED;
        }
    }
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("SetNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetNetwork(wpaObj, ifaceName, networkId, g_wpaSsidFields[pos].fieldName, conf.cfgValue);
    if (result != HDF_SUCCESS) {
        LOGE("SetNetwork: SetNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("SetNetwork success. ifaceName = %{public}s", ifaceName);
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaStart(const char *ifaceName, int instId)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaStart ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaStart enter! ifaceName = %{public}s, instId = %{public}d", ifaceName, instId);
    if (SetHdiStaIfaceName(ifaceName, instId) != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStart: set sta iface name failed!");
        return WIFI_HAL_OPT_FAILED;
    }

    if (CopyConfigFile("wpa_supplicant.conf") != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStart: CopyConfigFile failed!");
        return WIFI_HAL_OPT_FAILED;
    }

    if (HdiWpaStart() != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStart: HdiWpaStart failed!");
        return WIFI_HAL_OPT_FAILED;
    }

    if (RegisterEventCallback(ifaceName) != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStart: RegisterEventCallback failed!");
        return WIFI_HAL_OPT_FAILED;
    }

    if (HdiAddWpaIface(ifaceName, CONFIG_ROOR_DIR "/wpa_supplicant/wpa_supplicant.conf") != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStart: HdiAddWpaIface failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    
    LOGI("HdiWpaStaStart success");
    return WIFI_HAL_OPT_OK;
}

static WifiErrorNo HdiWpaStaStopWifi(int instId)
{
    for (int inst = instId; inst < STA_INSTANCE_MAX_NUM; inst++) {
        const char *ifaceName = GetHdiStaIfaceName(instId);
        if (ifaceName == NULL) {
            LOGE("HdiWpaStopWifi ifaceName is null");
            return WIFI_HAL_OPT_FAILED;
        }
        if (HdiRemoveWpaIface(ifaceName) != WIFI_HAL_OPT_OK) {
            LOGE("HdiWpaStop: HdiRemoveWpaIface failed");
            return WIFI_HAL_OPT_FAILED;
        }
        ClearHdiStaIfaceName(instId);
        LOGI("HdiWpaStaStopWifi success, instId = %{public}d, ifaceName = %{public}s", instId, ifaceName);
    }
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaStop(int instId)
{
    LOGI("HdiWpaStaStop enter, instId = %{public}d", instId);
    if (IsHdiWpaStopped() == WIFI_HAL_OPT_OK) {
        LOGI("HdiWpa already stopped, HdiWpaStaStop success!");
        return WIFI_HAL_OPT_OK;
    }

    if (instId == INSTID_WLAN1) {
        const char *ifaceName = GetHdiStaIfaceName(instId);
        if (ifaceName == NULL) {
            LOGE("HdiWpaStaStopWifi ifaceName is null");
            return WIFI_HAL_OPT_FAILED;
        }
        if (HdiRemoveWpaIface(ifaceName) != WIFI_HAL_OPT_OK) {
            LOGE("HdiWpaStaStop: HdiRemoveWpaStaIface failed!");
            return WIFI_HAL_OPT_FAILED;
        }
        ClearHdiStaIfaceName(instId);
        LOGI("HdiWpaStaStopWifi success, instId = %{public}d, ifaceName = %{public}s", instId, ifaceName);
        return WIFI_HAL_OPT_OK;
    }

    if (HdiRemoveWpaIface(GetHdiP2pIfaceName()) != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStop: HdiRemoveWpaP2pIface failed!");
    }

    HdiWpaStaStopWifi(INSTID_WLAN0);

    if (HdiWpaStop() != WIFI_HAL_OPT_OK) {
        LOGE("HdiWpaStaStop: HdiWpaStaStop failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    
    LOGI("HdiWpaStaStop success");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaConnect(int networkId, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaConnect ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaConnect enter, networkId:%{public}d, ifaceName = %{public}s", networkId, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaConnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->SelectNetwork(wpaObj, ifaceName, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaConnect: SelectNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaConnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaReconnect(const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaReconnect ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaReconnect enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaReconnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->Reconnect(wpaObj, ifaceName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaReconnect: Reconnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaReconnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaReassociate(const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaReassociate ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaReassociate: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->Reassociate(wpaObj, ifaceName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaReassociate: Reassociate failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaDisconnect(const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaDisconnect ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaDisconnect enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaDisconnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->Disconnect(wpaObj, ifaceName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaDisconnect: Disconnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaDisconnect success.");
    return WIFI_HAL_OPT_OK;
}

int ConvertMacToStr(char *mac, int macSize, char *macStr, int strLen)
{
    if (mac == NULL || macStr == NULL || macSize < ETH_ADDR_LEN || strLen <= HAL_BSSID_LENGTH) {
        return -1;
    }
    const int posZero = 0;
    const int posOne = 1;
    const int posTwo = 2;
    const int posThree = 3;
    const int posFour = 4;
    const int posFive = 5;
    if (snprintf_s(macStr, strLen, strLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x", mac[posZero], mac[posOne], mac[posTwo],
        mac[posThree], mac[posFour], mac[posFive]) < 0) {
        return -1;
    }
    return 0;
}

static void HdiWpaFree(struct HdiWpaCmdStatus *status)
{
    if (status->keyMgmt != NULL) {
        OsalMemFree(status->keyMgmt);
        status->keyMgmt = NULL;
    }
    if (status->ssid != NULL) {
        OsalMemFree(status->ssid);
        status->ssid = NULL;
    }
    if (status->address != NULL) {
        OsalMemFree(status->address);
        status->address = NULL;
    }
    if (status->bssid != NULL) {
        OsalMemFree(status->bssid);
        status->bssid = NULL;
    }
}

WifiErrorNo HdiWpaStaGetDeviceMacAddress(char *macAddr, int macAddrLen, const char *ifaceName)
{
    LOGI("HdiWpaStaGetDeviceMacAddress enter! ifaceName = %{public}s", ifaceName);
    if (macAddr == NULL) {
        LOGE("HdiWpaStaGetDeviceMacAddress: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    struct HdiWpaCmdStatus status = {0};
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaGetDeviceMacAddress: wpaObj is NULL");
        HdiWpaFree(&status);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->WifiStatus(wpaObj, ifaceName, &status);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaGetDeviceMacAddress: WifiStatus failed result:%{public}d", result);
        HdiWpaFree(&status);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    if ((uint32_t)macAddrLen < status.addressLen) {
        LOGE("Input mac length %{public}d is little than mac address length %{public}d", macAddrLen, status.addressLen);
        HdiWpaFree(&status);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_BUFFER_TOO_LITTLE;
    }

    if (ConvertMacToStr((char *)status.address, status.addressLen, macAddr, macAddrLen) != EOK) {
        LOGE("HdiWpaStaGetDeviceMacAddress: convertMacToStr failed!");
        HdiWpaFree(&status);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaGetDeviceMacAddress success.");
    HdiWpaFree(&status);
    pthread_mutex_unlock(GetWpaObjMutex());
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaScan()
{
    LOGI("HdiWpaStaScan enter");
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaScan: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->Scan(wpaObj, GetHdiStaIfaceName(INSTID_WLAN0));
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaScan: Scan failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaScan success.");
    return WIFI_HAL_OPT_OK;
}

ScanInfo *HdiWpaStaGetScanInfos(int *size, const char *ifaceName)
{
    LOGI("HdiWpaStaGetScanInfos enter");
    if (ifaceName == NULL || size == NULL) {
        LOGE("HdiWpaStaGetScanInfos ifaceName is null");
        return NULL;
    }

    ScanInfo *results = NULL;
    if (*size > 0) {
        results = (ScanInfo *)calloc(*size, sizeof(ScanInfo));
    }
    if (results == NULL) {
        LOGE("HdiWpaStaGetScanInfos: calloc scanInfo failed!");
        return NULL;
    }

    unsigned int resultBuffLen = REPLY_BUF_LENGTH;
    unsigned char *resultBuff = (unsigned char *)calloc(resultBuffLen, sizeof(unsigned char));
    if (resultBuff == NULL) {
        free(results);
        results = NULL;
        LOGE("HdiWpaStaGetScanInfos: calloc failed!");
        return NULL;
    }
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        free(results);
        results = NULL;
        free(resultBuff);
        resultBuff = NULL;
        LOGE("HdiWpaStaGetScanInfos: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return NULL;
    }

    int32_t result = wpaObj->ScanResult(wpaObj, ifaceName, resultBuff, &resultBuffLen);
    if (result != HDF_SUCCESS) {
        free(results);
        results = NULL;
        free(resultBuff);
        resultBuff = NULL;
        LOGE("HdiWpaStaGetScanInfos: ScanResult failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return NULL;
    }

    char *savedPtr = NULL;
    strtok_r((char *)resultBuff, "\n", &savedPtr);
    char *token = strtok_r(NULL, "\n", &savedPtr);
    int j = 0;
    while (token != NULL) {
        if (j >= *size) {
            *size = j;
            LOGE("HdiWpaStaGetScanInfos: get scan info full!");
            free(results);
            free(resultBuff);
            pthread_mutex_unlock(GetWpaObjMutex());
            return NULL;
        }
        int length = strlen(token);
        if (length <= 0) {
            break;
        }
        if (DelScanInfoLine(&results[j], token, length)) {
            LOGE("HdiWpaStaGetScanInfos: parse scan results line failed!");
            break;
        }
        LOGI("-->>%{public}2d %{private}s %{private}s %{public}d %{public}d %{public}d %{public}d \
         %{public}d %{public}d %{public}d %{public}d %{public}d %{public}d %{public}d %{public}d",
             j, results[j].ssid, results[j].bssid, results[j].freq, results[j].siglv,
             results[j].centerFrequency0, results[j].centerFrequency1, results[j].channelWidth,
             results[j].isVhtInfoExist, results[j].isHtInfoExist, results[j].isHeInfoExist, results[j].isEhtInfoExist,
             results[j].isErpExist, results[j].maxRates, results[j].extMaxRates);
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }

    *size = j;
    free(resultBuff);
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaGetScanInfos success.");
    return results;
}

WifiErrorNo HdiWpaStaRemoveNetwork(int networkId, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaRemoveNetwork ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaRemoveNetwork enter, networkId:%{public}d, ifaceName = %{public}s", networkId, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaRemoveNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->RemoveNetwork(wpaObj, ifaceName, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaRemoveNetwork: RemoveNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaRemoveNetwork success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaAddNetwork(int *networkId, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaAddNetwork ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaAddNetwork enter! ifaceName = %{public}s", ifaceName);
    if (networkId == NULL) {
        LOGE("HdiWpaStaAddNetwork: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaAddNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->AddNetwork(wpaObj, ifaceName, networkId);
    if (result != HDF_SUCCESS) {
        WIFI_HILOG_COMM_ERROR("HdiWpaStaAddNetwork: AddNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    WIFI_HILOG_COMM_INFO("HdiWpaStaAddNetwork success, networkId:%{public}d", *networkId);
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaEnableNetwork(int networkId, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaEnableNetwork ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaEnableNetwork enter, networkId:%{public}d, ifaceName = %{public}s", networkId, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaEnableNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->EnableNetwork(wpaObj, ifaceName, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaEnableNetwork: EnableNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaEnableNetwork success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaDisableNetwork(int networkId, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaDisableNetwork ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaDisableNetwork enter, networkId:%{public}d, ifaceName = %{public}s", networkId, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaDisableNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->DisableNetwork(wpaObj, ifaceName, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaDisableNetwork: DisableNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaDisableNetwork success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetNetwork(int networkId, SetNetworkConfig *confs, int size, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaSetNetwork ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaSetNetwork enter! ifaceName = %{public}s", ifaceName);
    if (confs == NULL) {
        LOGE("HdiWpaStaSetNetwork: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    for (int i = 0; i < size; ++i) {
        SetNetwork(networkId, confs[i], ifaceName);
    }

    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaSaveConfig(const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaSaveConfig ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaSaveConfig enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSaveConfig: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->SaveConfig(wpaObj, ifaceName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSaveConfig: SaveConfig failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaSaveConfig success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo RegisterHdiWpaStaEventCallback(struct IWpaCallback *callback, const char *ifaceName, int instId)
{
    if (ifaceName == NULL) {
        LOGE("RegisterHdiWpaStaEventCallback ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("RegisterHdiWpaStaEventCallback enter, ifaceName = %{public}s, instId = %{public}d", ifaceName, instId);
    pthread_mutex_lock(GetWpaObjMutex());
    if (callback == NULL || callback->OnEventConnected == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterHdiWpaStaEventCallback: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    if (g_hdiWpaStaCallbackObj[instId] != NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGI("RegisterHdiWpaStaEventCallback: already register!");
        return WIFI_HAL_OPT_OK;
    }

    g_hdiWpaStaCallbackObj[instId] = (struct IWpaCallback *)malloc(sizeof(struct IWpaCallback));
    if (g_hdiWpaStaCallbackObj[instId] == NULL) {
        pthread_mutex_unlock(GetWpaObjMutex());
        LOGE("RegisterHdiWpaStaEventCallback: IWpaCallback malloc failed!");
        return WIFI_HAL_OPT_FAILED;
    }
    if (memset_s(g_hdiWpaStaCallbackObj[instId], sizeof(struct IWpaCallback), 0, sizeof(struct IWpaCallback)) != EOK) {
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    g_hdiWpaStaCallbackObj[instId]->OnEventDisconnected = callback->OnEventDisconnected;
    g_hdiWpaStaCallbackObj[instId]->OnEventConnected = callback->OnEventConnected;
    g_hdiWpaStaCallbackObj[instId]->OnEventBssidChanged = callback->OnEventBssidChanged;
    g_hdiWpaStaCallbackObj[instId]->OnEventStateChanged = callback->OnEventStateChanged;
    g_hdiWpaStaCallbackObj[instId]->OnEventTempDisabled = callback->OnEventTempDisabled;
    g_hdiWpaStaCallbackObj[instId]->OnEventAssociateReject = callback->OnEventAssociateReject;
    g_hdiWpaStaCallbackObj[instId]->OnEventWpsOverlap = callback->OnEventWpsOverlap;
    g_hdiWpaStaCallbackObj[instId]->OnEventWpsTimeout = callback->OnEventWpsTimeout;
    g_hdiWpaStaCallbackObj[instId]->OnEventAuthTimeout = callback->OnEventAuthTimeout;
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    g_hdiWpaStaCallbackObj[instId]->OnEventScanResult = callback->OnEventScanResult;
#endif
    g_hdiWpaStaCallbackObj[instId]->OnEventStaNotify = callback->OnEventStaNotify;
    g_hdiWpaStaCallbackObj[instId]->OnEventAuthReject = callback->OnEventAuthReject;
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("RegisterHdiWpaStaEventCallback3 success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaStartWpsPbcMode(WifiWpsParam *config, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaStartWpsPbcMode ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaStartWpsPbcMode enter! ifaceName = %{public}s", ifaceName);
    if (config == NULL) {
        LOGE("HdiWpaStaStartWpsPbcMode: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    struct HdiWifiWpsParam wpsParam = {0};
    wpsParam.anyFlag = config->anyFlag;
    wpsParam.multiAp = config->multiAp;
    wpsParam.bssid = (uint8_t *)config->bssid;
    wpsParam.bssidLen = strlen(config->bssid);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaStartWpsPbcMode: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsPbcMode(wpaObj, ifaceName, &wpsParam);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaStartWpsPbcMode: WpsPbcMode failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaStartWpsPbcMode success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaStartWpsPinMode(WifiWpsParam *config, int *pinCode, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaStartWpsPinMode ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaStartWpsPinMode enter! ifaceName = %{public}s", ifaceName);
    if (config == NULL || pinCode == NULL) {
        LOGE("HdiWpaStaStartWpsPinMode: invalid parameter!");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    struct HdiWifiWpsParam wpsParam = {0};
    wpsParam.anyFlag = config->anyFlag;
    wpsParam.multiAp = config->multiAp;
    wpsParam.bssid = (uint8_t *)config->bssid;
    wpsParam.bssidLen = strlen(config->bssid);
    wpsParam.pinCode = (uint8_t *)config->pinCode;
    wpsParam.pinCodeLen = strlen(config->pinCode);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaStartWpsPinMode: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsPinMode(wpaObj, ifaceName, &wpsParam, pinCode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaStartWpsPinMode: WpsPbcMode failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaStartWpsPinMode success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiStopWpsSta(const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiStopWpsSta ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiStopWpsSta enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiStopWpsSta: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsCancel(wpaObj, ifaceName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiStopWpsSta: WpsCancel failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiStopWpsSta success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaAutoConnect(int enable, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaAutoConnect ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaAutoConnect enter, enable:%{public}d, ifaceName = %{public}s", enable, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaAutoConnect: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->AutoConnect(wpaObj, ifaceName, enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaAutoConnect: AutoConnect failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaAutoConnect success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaBlocklistClear(const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaBlocklistClear ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaBlocklistClear enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaBlocklistClear: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->BlocklistClear(wpaObj, ifaceName);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaBlocklistClear: BlocklistClear failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaBlocklistClear success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetPowerSave(int enable, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaSetPowerSave ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaSetPowerSave enter, enable:%{public}d, ifaceName = %{public}s", enable, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetPowerSave: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetPowerSave(wpaObj, ifaceName, enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetPowerSave: SetPowerSave failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaSetPowerSave success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetCountryCode(const char *countryCode, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaSetCountryCode ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaSetCountryCode enter, enable:%{public}s, ifaceName = %{public}s", countryCode, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetCountryCode: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetCountryCode(wpaObj, ifaceName, countryCode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetCountryCode: SetCountryCode failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaSetCountryCode success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaGetCountryCode(char *countryCode, uint32_t size, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaGetCountryCode ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaGetCountryCode enter, enable:%{public}s, ifaceName = %{public}s", countryCode, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaGetCountryCode: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->GetCountryCode(wpaObj, ifaceName, countryCode, size);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaGetCountryCode: SetCountryCode failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaGetCountryCode success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetSuspendMode(int mode, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaStaSetSuspendMode ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaStaSetSuspendMode enter, mode:%{public}d, ifaceName = %{public}s", mode, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetSuspendMode: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetSuspendMode(wpaObj, ifaceName, mode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetSuspendMode: SetSuspendMode failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGD("HdiWpaStaSetSuspendMode success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaListNetworks(struct HdiWifiWpaNetworkInfo *networkList, uint32_t *size, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaListNetworks ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaListNetworks enter! ifaceName = %{public}s", ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaListNetworks: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->ListNetworks(wpaObj, ifaceName, networkList, size);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaListNetworks: ListNetworks failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaListNetworks success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaGetNetwork(
    int32_t networkId, const char* param, char* value, uint32_t valueLen, const char *ifaceName)
{
    if (ifaceName == NULL) {
        LOGE("HdiWpaGetNetwork ifaceName is null");
        return WIFI_HAL_OPT_FAILED;
    }
    LOGI("HdiWpaGetNetwork enter,networkId:%{public}d, ifaceName = %{public}s", networkId, ifaceName);
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaGetNetwork: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->GetNetwork(wpaObj, ifaceName, networkId, param, value, valueLen);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaGetNetwork: GetNetwork failed result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaGetNetwork success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetShellCmd(const char *ifName, const char *cmd)
{
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetShellCmd: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->StaShellCmd(wpaObj, ifName, cmd);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetShellCmd: failed to StaShellCmd, result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("HdiWpaStaSetShellCmd success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiWpaStaGetPskPassphrase(const char *ifName, char *psk, uint32_t pskLen)
{
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("GetPskPassphrase: wpaObj is NULL");
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }

    int32_t result = wpaObj->GetPskPassphrase(wpaObj, ifName, psk, pskLen);
    if (result != HDF_SUCCESS) {
        LOGE("GetPskPassphrase: failed to StaShellCmd, result:%{public}d", result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("GetPskPassphrase success.");
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo HdiSetNativeProcessCallback(void (*callback)(int))
{
    LOGI("%{public}s enter", __func__);
    return SetNativeProcessCallback(callback);
}

WifiErrorNo HdiWpaGetMloLinkedInfo(const char *ifName, const char *staParam, char *staData,
    uint32_t staDataLen)
{
    pthread_mutex_lock(GetWpaObjMutex());
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("%{public}s: wpaObj is NULL", __func__);
        pthread_mutex_unlock(GetWpaObjMutex());
        return WIFI_HAL_OPT_FAILED;
    }
    int result = wpaObj->GetWpaStaData(wpaObj, ifName, staParam, staData, staDataLen);
    if (result != HDF_SUCCESS) {
        LOGE("%{public}s: failed to GetWpaStaData, result:%{public}d", __func__, result);
        pthread_mutex_unlock(GetWpaObjMutex());
        return result;
    }
    pthread_mutex_unlock(GetWpaObjMutex());
    LOGI("GetWpaStaData for mlo success.");
    return WIFI_HAL_OPT_OK;
}
#endif