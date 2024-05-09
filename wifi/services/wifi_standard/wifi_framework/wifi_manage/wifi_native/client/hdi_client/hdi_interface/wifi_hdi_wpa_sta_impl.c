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
#define WIFI_IDL_BSSID_LENGTH 17

const int QUOTATION_MARKS_FLAG_YES = 0;
const int QUOTATION_MARKS_FLAG_NO = 1;

static pthread_mutex_t g_hdiCallbackMutex = PTHREAD_MUTEX_INITIALIZER;
static struct IWpaCallback *g_hdiWpaStaCallbackObj = NULL;
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
};

static WifiErrorNo RegisterEventCallback()
{
    LOGI("RegisterEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiWpaStaCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterEventCallback: g_hdiWpaStaCallbackObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterEventCallback: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->RegisterEventCallback(wpaObj, g_hdiWpaStaCallbackObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterEventCallback: RegisterEventCallback failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("RegisterEventCallback success.");
    return WIFI_IDL_OPT_OK;
}

static WifiErrorNo UnRegisterEventCallback()
{
    LOGI("UnRegisterEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiWpaStaCallbackObj != NULL) {
        struct IWpaInterface *wpaObj = GetWpaInterface();
        if (wpaObj == NULL) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("UnRegisterEventCallback: wpaObj is NULL");
            return WIFI_IDL_OPT_FAILED;
        }

        int32_t result = wpaObj->UnregisterEventCallback(wpaObj, g_hdiWpaStaCallbackObj, GetHdiStaIfaceName());
        if (result != HDF_SUCCESS) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("UnRegisterEventCallback: UnregisterEventCallback failed result:%{public}d", result);
            return WIFI_IDL_OPT_FAILED;
        }

        free(g_hdiWpaStaCallbackObj);
        g_hdiWpaStaCallbackObj = NULL;
    }

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("UnRegisterEventCallback success.");
    return WIFI_IDL_OPT_OK;
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

static WifiErrorNo SetNetwork(int networkId, SetNetworkConfig conf)
{
    int pos = -1;
    for (unsigned i = 0; i < sizeof(g_wpaSsidFields) / sizeof(g_wpaSsidFields[0]); ++i) {
        if (g_wpaSsidFields[i].field == conf.cfgParam) {
            pos = i;
            break;
        }
    }
    if (pos < 0) {
        LOGE("SetNetwork: unsupported param: %{public}d", conf.cfgParam);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    char tmpCfgValue[WIFI_NETWORK_CONFIG_VALUE_LENGTH] = {0};
    if (CalcQuotationMarksFlag(pos, conf.cfgValue) == QUOTATION_MARKS_FLAG_YES) {
        if (snprintf_s(tmpCfgValue, sizeof(tmpCfgValue), sizeof(tmpCfgValue) - 1, "\"%s\"", conf.cfgValue) < 0) {
            LOGE("SetNetwork: snprintf_s failed!");
            return WIFI_IDL_OPT_FAILED;
        }
        if (snprintf_s(conf.cfgValue, sizeof(conf.cfgValue), sizeof(conf.cfgValue) - 1, "%s", tmpCfgValue) < 0) {
            LOGE("SetNetwork: snprintf_s failed!");
            return WIFI_IDL_OPT_FAILED;
        }
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("SetNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetNetwork(wpaObj, GetHdiStaIfaceName(), networkId, g_wpaSsidFields[pos].fieldName,
        conf.cfgValue);
    if (result != HDF_SUCCESS) {
        LOGE("SetNetwork: SetNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("SetNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaStart(const char *ifaceName)
{
    LOGI("HdiWpaStaStart enter");
    if (SetHdiStaIfaceName(ifaceName) != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStart: set sta iface name failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (CopyConfigFile("wpa_supplicant.conf") != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStart: CopyConfigFile failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiWpaStart() != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStart: HdiWpaStart failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (RegisterEventCallback() != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStart: RegisterEventCallback failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiAddWpaIface(GetHdiStaIfaceName(), CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStart: HdiAddWpaIface failed!");
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiWpaStaStart success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaStop()
{
    LOGI("HdiWpaStaStop enter");
    if (IsHdiWpaStopped() == WIFI_IDL_OPT_OK) {
        LOGI("HdiWpa already stopped, HdiWpaStaStop success!");
        return WIFI_IDL_OPT_OK;
    }

    if (UnRegisterEventCallback() != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStop: UnRegisterEventCallback failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiRemoveWpaIface(GetHdiP2pIfaceName()) != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStop: HdiRemoveWpaP2pIface failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiRemoveWpaIface(GetHdiStaIfaceName()) != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStop: HdiRemoveWpaStaIface failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiWpaStop() != WIFI_IDL_OPT_OK) {
        LOGE("HdiWpaStaStop: HdiWpaStaStop failed!");
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiWpaStaStop success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaConnect(int networkId)
{
    LOGI("HdiWpaStaConnect enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaConnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SelectNetwork(wpaObj, GetHdiStaIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaConnect: SelectNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaConnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaReconnect()
{
    LOGI("HdiWpaStaReconnect enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaReconnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Reconnect(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaReconnect: Reconnect failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaReconnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaReassociate()
{
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaReassociate: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Reassociate(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaReassociate: Reassociate failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaDisconnect()
{
    LOGI("HdiWpaStaDisconnect enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaDisconnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Disconnect(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaDisconnect: Disconnect failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaDisconnect success.");
    return WIFI_IDL_OPT_OK;
}

int ConvertMacToStr(char *mac, int macSize, char *macStr, int strLen)
{
    if (mac == NULL || macStr == NULL || macSize < ETH_ADDR_LEN || strLen <= WIFI_IDL_BSSID_LENGTH) {
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

WifiErrorNo HdiWpaStaGetDeviceMacAddress(char *macAddr, int macAddrLen)
{
    LOGI("HdiWpaStaGetDeviceMacAddress enter");
    if (macAddr == NULL) {
        LOGE("HdiWpaStaGetDeviceMacAddress: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct HdiWpaCmdStatus status;
    if (memset_s(&status, sizeof(status), 0, sizeof(status)) != EOK) {
        LOGE("HdiWpaStaGetDeviceMacAddress: memset_s failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaGetDeviceMacAddress: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WifiStatus(wpaObj, GetHdiStaIfaceName(), &status);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaGetDeviceMacAddress: WifiStatus failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    if (macAddrLen < status.addressLen) {
        LOGE("Input mac length %{public}d is little than mac address length %{public}d", macAddrLen, status.addressLen);
        return WIFI_IDL_OPT_BUFFER_TOO_LITTLE;
    }

    if (ConvertMacToStr((char *)status.address, status.addressLen, macAddr, macAddrLen) != EOK) {
        LOGE("HdiWpaStaGetDeviceMacAddress: convertMacToStr failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaGetDeviceMacAddress success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaScan()
{
    LOGI("HdiWpaStaScan enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaScan: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Scan(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaScan: Scan failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaScan success.");
    return WIFI_IDL_OPT_OK;
}

ScanInfo *HdiWpaStaGetScanInfos(int *size)
{
    LOGI("HdiWpaStaGetScanInfos enter");
    if (size == NULL) {
        LOGE("HdiWpaStaGetScanInfos: invalid parameter!");
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
        LOGE("HdiWpaStaGetScanInfos: calloc failed!");
        return NULL;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        free(results);
        free(resultBuff);
        LOGE("HdiWpaStaGetScanInfos: wpaObj is NULL");
        return NULL;
    }

    int32_t result = wpaObj->ScanResult(wpaObj, GetHdiStaIfaceName(), resultBuff, &resultBuffLen);
    if (result != HDF_SUCCESS) {
        free(results);
        free(resultBuff);
        LOGE("HdiWpaStaGetScanInfos: ScanResult failed result:%{public}d", result);
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
        LOGI("-->>%{public}2d %{private}s %{private}s %{public}d %{public}d %{public}d %{public}d %{public}d %{public}d \
         %{public}d %{public}d %{public}d %{public}d %{public}d",
             j, results[j].ssid, results[j].bssid, results[j].freq, results[j].siglv,
             results[j].centerFrequency0, results[j].centerFrequency1, results[j].channelWidth,
             results[j].isVhtInfoExist, results[j].isHtInfoExist, results[j].isHeInfoExist, results[j].isErpExist,
             results[j].maxRates, results[j].extMaxRates);
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }

    *size = j;
    free(resultBuff);
    LOGI("HdiWpaStaGetScanInfos success.");
    return results;
}

WifiErrorNo HdiWpaStaRemoveNetwork(int networkId)
{
    LOGI("HdiWpaStaRemoveNetwork enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaRemoveNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->RemoveNetwork(wpaObj, GetHdiStaIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaRemoveNetwork: RemoveNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaRemoveNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaAddNetwork(int *networkId)
{
    LOGI("HdiWpaStaAddNetwork enter");
    if (networkId == NULL) {
        LOGE("HdiWpaStaAddNetwork: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaAddNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->AddNetwork(wpaObj, GetHdiStaIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaAddNetwork: AddNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaAddNetwork success, networkId:%{public}d", *networkId);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaEnableNetwork(int networkId)
{
    LOGI("HdiWpaStaEnableNetwork enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaEnableNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->EnableNetwork(wpaObj, GetHdiStaIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaEnableNetwork: EnableNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaEnableNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaDisableNetwork(int networkId)
{
    LOGI("HdiWpaStaDisableNetwork enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaDisableNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->DisableNetwork(wpaObj, GetHdiStaIfaceName(), networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaDisableNetwork: DisableNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaDisableNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetNetwork(int networkId, SetNetworkConfig *confs, int size)
{
    LOGI("HdiWpaStaSetNetwork enter");
    if (confs == NULL) {
        LOGE("HdiWpaStaSetNetwork: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    for (int i = 0; i < size; ++i) {
        SetNetwork(networkId, confs[i]);
    }

    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaSaveConfig()
{
    LOGI("HdiWpaStaSaveConfig enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSaveConfig: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SaveConfig(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSaveConfig: SaveConfig failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaSaveConfig success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo RegisterHdiWpaStaEventCallback(struct IWpaCallback *callback)
{
    LOGI("RegisterHdiWpaStaEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (callback == NULL || callback->OnEventConnected == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterHdiWpaStaEventCallback: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_hdiWpaStaCallbackObj != NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGI("RegisterHdiWpaStaEventCallback: already register!");
        return WIFI_IDL_OPT_OK;
    }

    g_hdiWpaStaCallbackObj = (struct IWpaCallback *)malloc(sizeof(struct IWpaCallback ));
    if (g_hdiWpaStaCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterHdiWpaStaEventCallback: IWpaCallback malloc failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    g_hdiWpaStaCallbackObj->OnEventDisconnected = callback->OnEventDisconnected;
    g_hdiWpaStaCallbackObj->OnEventConnected = callback->OnEventConnected;
    g_hdiWpaStaCallbackObj->OnEventBssidChanged = callback->OnEventBssidChanged;
    g_hdiWpaStaCallbackObj->OnEventStateChanged = callback->OnEventStateChanged;
    g_hdiWpaStaCallbackObj->OnEventTempDisabled = callback->OnEventTempDisabled;
    g_hdiWpaStaCallbackObj->OnEventAssociateReject = callback->OnEventAssociateReject;
    g_hdiWpaStaCallbackObj->OnEventWpsOverlap = callback->OnEventWpsOverlap;
    g_hdiWpaStaCallbackObj->OnEventWpsTimeout = callback->OnEventWpsTimeout;
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    g_hdiWpaStaCallbackObj->OnEventScanResult = NULL;
#else
    g_hdiWpaStaCallbackObj->OnEventScanResult = callback->OnEventScanResult;
#endif
    g_hdiWpaStaCallbackObj->OnEventDeviceFound = NULL;
    g_hdiWpaStaCallbackObj->OnEventDeviceLost = NULL;
    g_hdiWpaStaCallbackObj->OnEventGoNegotiationRequest = NULL;
    g_hdiWpaStaCallbackObj->OnEventGoNegotiationCompleted = NULL;
    g_hdiWpaStaCallbackObj->OnEventInvitationReceived = NULL;
    g_hdiWpaStaCallbackObj->OnEventInvitationResult = NULL;
    g_hdiWpaStaCallbackObj->OnEventGroupFormationSuccess = NULL;
    g_hdiWpaStaCallbackObj->OnEventGroupFormationFailure = NULL;
    g_hdiWpaStaCallbackObj->OnEventGroupStarted = NULL;
    g_hdiWpaStaCallbackObj->OnEventGroupRemoved = NULL;
    g_hdiWpaStaCallbackObj->OnEventProvisionDiscoveryCompleted = NULL;
    g_hdiWpaStaCallbackObj->OnEventFindStopped = NULL;
    g_hdiWpaStaCallbackObj->OnEventServDiscReq = NULL;
    g_hdiWpaStaCallbackObj->OnEventServDiscResp = NULL;
    g_hdiWpaStaCallbackObj->OnEventStaConnectState = NULL;
    g_hdiWpaStaCallbackObj->OnEventIfaceCreated = NULL;
    g_hdiWpaStaCallbackObj->GetVersion = NULL;
    g_hdiWpaStaCallbackObj->AsObject = NULL;
    g_hdiWpaStaCallbackObj->OnEventStaNotify = callback->OnEventStaNotify;
    g_hdiWpaStaCallbackObj->OnEventVendorCb = NULL;

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("RegisterHdiWpaStaEventCallback3 success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaStartWpsPbcMode(WifiWpsParam *config)
{
    LOGI("HdiWpaStaStartWpsPbcMode enter");
    if (config == NULL) {
        LOGE("HdiWpaStaStartWpsPbcMode: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct HdiWifiWpsParam wpsParam = {0};
    wpsParam.anyFlag = config->anyFlag;
    wpsParam.multiAp = config->multiAp;
    wpsParam.bssid = (uint8_t *)config->bssid;
    wpsParam.bssidLen = strlen(config->bssid);
    
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaStartWpsPbcMode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsPbcMode(wpaObj, GetHdiStaIfaceName(), &wpsParam);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaStartWpsPbcMode: WpsPbcMode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaStartWpsPbcMode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaStartWpsPinMode(WifiWpsParam *config, int *pinCode)
{
    LOGI("HdiWpaStaStartWpsPinMode enter");
    if (config == NULL || pinCode == NULL) {
        LOGE("HdiWpaStaStartWpsPinMode: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct HdiWifiWpsParam wpsParam = {0};
    wpsParam.anyFlag = config->anyFlag;
    wpsParam.multiAp = config->multiAp;
    wpsParam.bssid = (uint8_t *)config->bssid;
    wpsParam.bssidLen = strlen(config->bssid);
    wpsParam.pinCode = (uint8_t *)config->pinCode;
    wpsParam.pinCodeLen = strlen(config->pinCode);
    
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaStartWpsPinMode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsPinMode(wpaObj, GetHdiStaIfaceName(), &wpsParam, pinCode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaStartWpsPinMode: WpsPbcMode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaStartWpsPinMode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStopWpsSta()
{
    LOGI("HdiStopWpsSta enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiStopWpsSta: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsCancel(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiStopWpsSta: WpsCancel failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiStopWpsSta success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaAutoConnect(int enable)
{
    LOGI("HdiWpaStaAutoConnect enter, enable:%{public}d", enable);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaAutoConnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->AutoConnect(wpaObj, GetHdiStaIfaceName(), enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaAutoConnect: AutoConnect failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaAutoConnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaBlocklistClear()
{
    LOGI("HdiWpaStaBlocklistClear enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaBlocklistClear: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->BlocklistClear(wpaObj, GetHdiStaIfaceName());
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaBlocklistClear: BlocklistClear failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaBlocklistClear success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetPowerSave(int enable)
{
    LOGI("HdiWpaStaSetPowerSave enter, enable:%{public}d", enable);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetPowerSave: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetPowerSave(wpaObj, GetHdiStaIfaceName(), enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetPowerSave: SetPowerSave failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaSetPowerSave success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetCountryCode(const char *countryCode)
{
    LOGI("HdiWpaStaSetCountryCode enter, enable:%{public}s", countryCode);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetCountryCode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetCountryCode(wpaObj, GetHdiStaIfaceName(), countryCode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetCountryCode: SetCountryCode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaSetCountryCode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaGetCountryCode(char *countryCode, uint32_t size)
{
    LOGI("HdiWpaStaGetCountryCode enter, enable:%{public}s", countryCode);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaGetCountryCode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->GetCountryCode(wpaObj, GetHdiStaIfaceName(), countryCode, size);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaGetCountryCode: SetCountryCode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaGetCountryCode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetSuspendMode(int mode)
{
    LOGI("HdiWpaStaSetSuspendMode enter, mode:%{public}d", mode);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetSuspendMode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetSuspendMode(wpaObj, GetHdiStaIfaceName(), mode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetSuspendMode: SetSuspendMode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaStaSetSuspendMode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaListNetworks(struct HdiWifiWpaNetworkInfo *networkList, uint32_t *size)
{
    LOGI("HdiWpaListNetworks enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaListNetworks: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->ListNetworks(wpaObj, GetHdiStaIfaceName(), networkList, size);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaListNetworks: ListNetworks failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaListNetworks success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaGetNetwork(int32_t networkId, const char* param, char* value, uint32_t valueLen)
{
    LOGI("HdiWpaGetNetwork enter,networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaGetNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->GetNetwork(wpaObj, GetHdiStaIfaceName(), networkId, param, value, valueLen);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaGetNetwork: GetNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaGetNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaSetShellCmd(const char *ifName, const char *cmd)
{
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaStaSetShellCmd: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }
 
    int32_t result = wpaObj->StaShellCmd(wpaObj, ifName, cmd);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaStaSetShellCmd: failed to StaShellCmd, result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("HdiWpaStaSetShellCmd success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaStaGetPskPassphrase(const char *ifName, char *psk, uint32_t pskLen)
{
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("GetPskPassphrase: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->GetPskPassphrase(wpaObj, ifName, psk, pskLen);
    if (result != HDF_SUCCESS) {
        LOGE("GetPskPassphrase: failed to StaShellCmd, result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("GetPskPassphrase success.");
    return WIFI_IDL_OPT_OK;
}
#endif