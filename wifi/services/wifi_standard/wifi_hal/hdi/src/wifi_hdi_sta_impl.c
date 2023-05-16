/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifdef HDI_INTERFACE_SUPPORT
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pthread.h>
#include "securec.h"
#include "v1_1/iwlan_callback.h"
#include "wifi_hdi_sta_impl.h"
#include "wifi_hdi_proxy.h"
#include "wifi_log.h"
#include "wifi_hal_callback.h"
#include "wifi_hdi_util.h"
#include "wifi_supplicant_hal.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiStaImpl"

#define WIFI_IDL_GET_MAX_SCAN_INFO 256 /* Maximum number of scan infos obtained at a time */
struct IWlanCallback* g_hdiWanCallbackObj = NULL;
ScanInfo* g_hdiScanResults = NULL;
int g_hdiScanResultsCount = 0;
static pthread_mutex_t g_hdiMutex;

void HdiStaInit()
{
    pthread_mutex_init(&g_hdiMutex, NULL);
}

void HdiStaUnInit()
{
    pthread_mutex_destroy(&g_hdiMutex);
}

int32_t HdiScanResultsCallback(struct IWlanCallback *self, uint32_t event,
    const struct HdfWifiScanResults *scanResults, const char* ifName)
{
    pthread_mutex_lock(&g_hdiMutex);
    g_hdiScanResultsCount = 0;
    if (g_hdiScanResults == NULL || scanResults == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("HdiScanResultsCallback param invalid.");
        WifiHalCbNotifyScanEnd(STA_CB_SCAN_FAILED);
        return WIFI_HAL_FAILED;
    }
    if (memset_s(g_hdiScanResults, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo),
        0, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo)) != EOK) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("HdiScanResultsCallback memset_s failed.");
        WifiHalCbNotifyScanEnd(STA_CB_SCAN_FAILED);
        return WIFI_HAL_FAILED;
    }
    char buff[1024] = {0};
    int buffLen = 1024;
    for (size_t i = 0; i < scanResults->resLen && i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
        struct HdfWifiScanResultExt *scanResult = &scanResults->res[i];
        struct HdiElems elems;
        Get80211ElemsFromIE((const uint8_t*)scanResult->ie, scanResult->ieLen, &elems, 1);
        if (elems.ssidLen == 0) {
            LOGE("HdiScanResultsCallback ssid empty.");
            continue;
        }
        buffLen = 1024;
        if (memset_s(buff, buffLen, 0, buffLen) != EOK) {
            pthread_mutex_unlock(&g_hdiMutex);
            LOGE("HdiScanResultsCallback buff memset_s failed.");
            WifiHalCbNotifyScanEnd(STA_CB_SCAN_FAILED);
            return WIFI_HAL_FAILED;
        }
        buffLen = GetScanResultText(scanResult, &elems, buff, buffLen);
        if (DelScanInfoLine(&g_hdiScanResults[g_hdiScanResultsCount], buff, buffLen)) {
            LOGE("HdiScanResultsCallback DelScanInfoLine failed.");
            continue;
        }
        g_hdiScanResultsCount++;
    }
    
    pthread_mutex_unlock(&g_hdiMutex);
    WifiHalCbNotifyScanEnd(STA_CB_SCAN_OVER_OK);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo HdiStartScan(const ScanSettings *settings)
{
    LOGI("HdiStartScan enter.");
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    struct HdfWifiScan scan = {0};
    if (settings->hiddenSsidSize > 0) {
        int size = settings->hiddenSsidSize * sizeof(struct HdfWifiDriverScanSsid);
        scan.ssids = (struct HdfWifiDriverScanSsid*)malloc(size);
        if (memset_s(scan.ssids, size, 0, size) != EOK) {
            LOGE("HdiStartScan memset ssids failed.");
            ret = 1;
            goto finish;
        }
        scan.ssidsLen = settings->hiddenSsidSize;
        for (size_t i = 0; i < scan.ssidsLen; i++) {
            scan.ssids[i].ssidLen = strlen(settings->hiddenSsid[i]);
            scan.ssids[i].ssid = (char*)malloc(scan.ssids[i].ssidLen + 1);
            if (memset_s(scan.ssids[i].ssid, scan.ssids[i].ssidLen + 1, 0, scan.ssids[i].ssidLen + 1) != EOK) {
                LOGE("HdiStartScan memset ssids failed.");
                ret = 1;
                goto finish;
            }
            if (strcpy_s(scan.ssids[i].ssid, scan.ssids[i].ssidLen + 1, settings->hiddenSsid[i]) != EOK) {
                LOGE("HdiStartScan copy hidden ssid failed.");
                ret = 1;
                goto finish;
            }
        }
    }

    ret = proxy.wlanObj->StartScan(proxy.wlanObj, proxy.feature, &scan);
    if (ret != 0) {
        LOGE("HdiStartScan failed ret:%{public}d", ret);
    }

finish:
    for (size_t i = 0; i < scan.ssidsLen; i++) {
        if (scan.ssids[i].ssid != NULL) {
            free(scan.ssids[i].ssid);
            scan.ssids[i].ssid = NULL;
        }
    }
    if (scan.ssids != NULL) {
        free(scan.ssids);
        scan.ssids = NULL;
    }

    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}

WifiErrorNo GetHdiScanInfos(ScanInfo* infos, int *size)
{
    if (infos == NULL || size == NULL || *size == 0) {
        LOGE("GetHdiScanInfos failed, input invalid.");
        return WIFI_HAL_FAILED;
    }
    
    pthread_mutex_lock(&g_hdiMutex);
    LOGI("GetHdiScanInfos enter, saved size:%{public}d.", g_hdiScanResultsCount);
    if (*size < g_hdiScanResultsCount) {
        LOGE("input size invalid. %{public}d < %{public}d.", *size, g_hdiScanResultsCount);
        pthread_mutex_unlock(&g_hdiMutex);
        return WIFI_HAL_FAILED;
    }

    if (memcpy_s(infos, *size * sizeof(struct ScanInfo),
        g_hdiScanResults, g_hdiScanResultsCount * sizeof(struct ScanInfo)) != EOK) {
        LOGE("GetHdiScanInfos memcpy_s failied.");
        pthread_mutex_unlock(&g_hdiMutex);
        return WIFI_HAL_FAILED;
    }

    *size = g_hdiScanResultsCount;
    pthread_mutex_unlock(&g_hdiMutex);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetHdiSignalInfo(WpaSignalInfo *info)
{
    if (info == NULL) {
        LOGE("GetHdiSignalInfo info is null.");
        return -1;
    }

    LOGI("GetHdiSignalInfo enter.");
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    struct SignalPollResult signalResult = {0};
    
    ret = proxy.wlanObj->GetSignalPollInfo(proxy.wlanObj, "wlan0", &signalResult);
    if (ret != 0) {
        LOGE("GetHdiSignalInfo failed ret:%{public}d", ret);
    }
    info->signal = signalResult.currentRssi;
    info->txrate = signalResult.txBitrate;
    info->rxrate = signalResult.rxBitrate;
    info->noise = signalResult.currentNoise;
    info->frequency = signalResult.associatedFreq;
    info->txPackets = signalResult.currentTxPackets;
    info->rxPackets = signalResult.currentRxPackets;
    return (ret == 0) ? 0 : -1;
}


WifiErrorNo RegisterHdiStaCallbackEvent()
{
    LOGI("RegisterHdiStaCallbackEvent enter.");
    pthread_mutex_lock(&g_hdiMutex);
    if (g_hdiWanCallbackObj != NULL) {
        LOGI("RegisterHdiStaCallbackEvent already register.");
        pthread_mutex_unlock(&g_hdiMutex);
        return WIFI_HAL_SUCCESS;
    }
    g_hdiWanCallbackObj = (struct IWlanCallback*)malloc(sizeof(struct IWlanCallback));
    if (g_hdiWanCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("g_hdiWanCallbackObj malloc failed.");
        return WIFI_HAL_FAILED;
    }
    g_hdiWanCallbackObj->ResetDriverResult = NULL;
    g_hdiWanCallbackObj->ScanResult = NULL;
    g_hdiWanCallbackObj->WifiNetlinkMessage = NULL;
    g_hdiWanCallbackObj->ScanResults = HdiScanResultsCallback;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    if (proxy.wlanObj == NULL || proxy.feature == NULL) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("Hdi proxy is NULL!");
        return WIFI_HAL_FAILED;
    }
    int32_t ret = proxy.wlanObj->RegisterEventCallback(proxy.wlanObj, g_hdiWanCallbackObj, "wlan0");
    if (ret != 0) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("Hdi RegisterEventCallback failed ret:%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    g_hdiScanResultsCount = 0;
    g_hdiScanResults = (struct ScanInfo*)malloc(WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo));
    if (g_hdiScanResults == NULL) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("g_hdiScanResults malloc failed.");
        return WIFI_HAL_FAILED;
    }
    if (memset_s(g_hdiScanResults, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo),
        0, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo)) != EOK) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("g_hdiScanResults memset_s failied.");
        return WIFI_HAL_FAILED;
    }
    pthread_mutex_unlock(&g_hdiMutex);
    return WIFI_HAL_SUCCESS;
}

void UnRegisterHdiStaCallbackEvent()
{
    LOGI("UnRegisterHdiStaCallbackEvent enter.");
    pthread_mutex_lock(&g_hdiMutex);
    if (g_hdiScanResults != NULL) {
        free(g_hdiScanResults);
        g_hdiScanResults = NULL;
    }
    if (g_hdiWanCallbackObj != NULL) {
        free(g_hdiWanCallbackObj);
        g_hdiWanCallbackObj = NULL;
    }
    pthread_mutex_unlock(&g_hdiMutex);
}

#ifdef RANDOM_MAC_SUPPORT
static const uint32_t MAC_ADDR_INDEX_0 = 0;
static const uint32_t MAC_ADDR_INDEX_1 = 1;
static const uint32_t MAC_ADDR_INDEX_2 = 2;
static const uint32_t MAC_ADDR_INDEX_3 = 3;
static const uint32_t MAC_ADDR_INDEX_4 = 4;
static const uint32_t MAC_ADDR_INDEX_5 = 5;
static const uint32_t MAC_ADDR_INDEX_SIZE = 6;

void UpDownLink(int flag)
{
    struct ifreq ifr;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK ||
        strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), "wlan0") != EOK) {
        LOGE("ccntoInit the ifreq struct failed!");
        return;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("ccntoget mac addr socket error");
        return;
    }

    if (flag == 1) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        LOGE("ccntoget mac addr ioctl SIOCGIFHWADDR error");
        close(fd);
        return;
    }

    close(fd);
}

WifiErrorNo SetAssocMacAddr(const unsigned char *mac, int lenMac)
{
    LOGI("SetAssocMacAddr enter.");
    if (strlen((const char *)mac) != WIFI_MAC_LENGTH || lenMac != WIFI_MAC_LENGTH) {
        LOGE("Mac size not correct! mac len %{public}zu, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }

    UpDownLink(0);
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);

    unsigned char mac_bin[MAC_ADDR_INDEX_SIZE];
    sscanf_s((char *)mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &mac_bin[MAC_ADDR_INDEX_0], &mac_bin[MAC_ADDR_INDEX_1], &mac_bin[MAC_ADDR_INDEX_2],
           &mac_bin[MAC_ADDR_INDEX_3], &mac_bin[MAC_ADDR_INDEX_4], &mac_bin[MAC_ADDR_INDEX_5]);

    int32_t ret = proxy.wlanObj->SetMacAddress(proxy.wlanObj, proxy.feature, mac_bin, MAC_ADDR_INDEX_SIZE);
    if (ret != HDF_SUCCESS) {
        LOGE("SetAssocMacAddr failed: %{public}d", ret);
    }
    UpDownLink(1);
    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}
#endif

#endif
