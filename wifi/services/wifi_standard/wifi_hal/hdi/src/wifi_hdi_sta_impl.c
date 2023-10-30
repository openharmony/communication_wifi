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
#include <unistd.h>
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
#include "stub_collector.h"
#include "wifi_hdi_util.h"
#include "wifi_supplicant_hal.h"
#include "wifi_common_def.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiStaImpl"

#define WIFI_PNO_SCAN_ITERATIONS 3
#define WIFI_PNO_SCAN_SECOND_TO_MS 1000

#define WIFI_IDL_GET_MAX_SCAN_INFO 256 /* Maximum number of scan infos obtained at a time */

#ifndef CHECK_STA_HDI_PROXY_AND_RETURN
#define CHECK_STA_HDI_PROXY_AND_RETURN(isRemoteDied) \
if (isRemoteDied) { \
    ReleaseLocalResources(); \
    if (HdiStart() != WIFI_HAL_SUCCESS) { \
        LOGE("[STA] Start hdi failed!"); \
        return WIFI_HAL_FAILED; \
    } \
    if (RegisterHdiStaCallbackEvent() != WIFI_HAL_SUCCESS) { \
        LOGE("[STA] RegisterHdiStaCallbackEvent failed!"); \
        return WIFI_HAL_FAILED; \
    } \
}
#endif

struct IWlanCallback* g_hdiWanCallbackObj = NULL;
static pthread_mutex_t g_hdiCallbackMutex;
ScanInfo* g_hdiScanResults = NULL;
int g_hdiScanResultsCount = 0;
static pthread_mutex_t g_hdiMutex;

void HdiStaInit()
{
    pthread_mutex_init(&g_hdiMutex, NULL);
    pthread_mutex_init(&g_hdiCallbackMutex, NULL);
}

void HdiStaUnInit()
{
    pthread_mutex_destroy(&g_hdiMutex);
    pthread_mutex_destroy(&g_hdiCallbackMutex);
}

int32_t HdiScanResultsCallback(struct IWlanCallback *self, uint32_t event,
    const struct HdfWifiScanResults *scanResults, const char* ifName)
{
    pthread_mutex_lock(&g_hdiMutex);
    g_hdiScanResultsCount = 0;
    if (g_hdiScanResults == NULL) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("HdiScanResultsCallback param invalid. g_hdiScanResults is null!");
        return WIFI_HAL_FAILED;
    }
    if (scanResults == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_hdiMutex);
        LOGE("HdiScanResultsCallback param invalid. scanResults or ifName is null!");
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
    char bssid[WIFI_BSSID_LENGTH] = {0};
    int buffLen = 1024;
    for (size_t i = 0; i < scanResults->resLen && i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
        struct HdfWifiScanResultExt *scanResult = &scanResults->res[i];
        struct HdiElems elems;
        Get80211ElemsFromIE((const uint8_t*)scanResult->ie, scanResult->ieLen, &elems, 1);
        if (elems.ssidLen == 0) {
            if (sprintf_s(bssid, sizeof(bssid), MACSTR, MAC2STR(scanResult->bssid)) < 0) {
                LOGD("HdiScanResultsCallback ssid empty.");
                continue;
            }
            LOGD("HdiScanResultsCallback ssid empty. bssid:%{private}s", bssid);
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
        LOGD("HdiScanResultsCallback bssid:%{private}s, ssid:%{private}s", g_hdiScanResults[g_hdiScanResultsCount].bssid,
            g_hdiScanResults[g_hdiScanResultsCount].ssid);
        g_hdiScanResultsCount++;
    }
    
    pthread_mutex_unlock(&g_hdiMutex);
    WifiHalCbNotifyScanEnd(STA_CB_SCAN_OVER_OK);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo HdiStartScan(const ScanSettings *settings)
{
    LOGI("HdiStartScan enter.");
    CHECK_STA_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    struct HdfWifiScan scan = {0};
    if (settings->hiddenSsidSize > 0) {
        int size = settings->hiddenSsidSize * sizeof(struct HdfWifiDriverScanSsid);
        scan.ssids = (struct HdfWifiDriverScanSsid*)malloc(size);
        if (scan.ssids == NULL) {
            LOGE("failed to alloc!");
            return WIFI_HAL_FAILED;
        }
        if (memset_s(scan.ssids, size, 0, size) != EOK) {
            LOGE("HdiStartScan memset ssids failed.");
            ret = 1;
            goto finish;
        }
        scan.ssidsLen = settings->hiddenSsidSize;
        for (size_t i = 0; i < scan.ssidsLen; i++) {
            scan.ssids[i].ssidLen = strlen(settings->hiddenSsid[i]);
            scan.ssids[i].ssid = (char*)malloc(scan.ssids[i].ssidLen + 1);
            if (scan.ssids[i].ssid == NULL) {
                continue;
            }
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
    LOGI("HdiStartScan end. ret: %{public}d", ret);
    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}

WifiErrorNo HdiStartPnoScan(const PnoScanSettings * settings)
{
    LOGI("HdiStartPnoScan enter.");
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    const char *ifName = "wlan0";
    struct PnoSettings pnoSettings;
    (void)memset_s(&pnoSettings, sizeof(struct PnoSettings), 0, sizeof(struct PnoSettings));
    if (settings->savedSsidSize > 0) {
        pnoSettings.min2gRssi = settings->minRssi2Dot4Ghz;
        pnoSettings.min5gRssi = settings->minRssi5Ghz;
        pnoSettings.scanIntervalMs = settings->scanInterval * WIFI_PNO_SCAN_SECOND_TO_MS;
        pnoSettings.scanIterations = WIFI_PNO_SCAN_ITERATIONS;

        pnoSettings.pnoNetworksLen = settings->savedSsidSize;
        int size = sizeof(struct PnoNetwork) * pnoSettings.pnoNetworksLen;
        pnoSettings.pnoNetworks = (struct PnoNetwork *)malloc(size);
        if (pnoSettings.pnoNetworks == NULL) {
            LOGE("HdiStartPnoScan malloc pno network failed.");
            return WIFI_HAL_FAILED;
        }
        (void)memset_s(pnoSettings.pnoNetworks, size, 0, size);
        for (size_t i = 0; i < pnoSettings.pnoNetworksLen; i++) {
            pnoSettings.pnoNetworks[i].isHidden = 0;
            pnoSettings.pnoNetworks[i].ssid.ssidLen = strlen(settings->savedSsid[i]) + 1;
            pnoSettings.pnoNetworks[i].ssid.ssid = settings->savedSsid[i];
            pnoSettings.pnoNetworks[i].freqsLen = settings->freqSize;
            pnoSettings.pnoNetworks[i].freqs = settings->freqs;
        }
    }

    ret = proxy.wlanObj->StartPnoScan(proxy.wlanObj, ifName, &pnoSettings);
    if (ret != 0) {
        LOGE("HdiStartPnoScan failed ret:%{public}d.", ret);
    }
    if (pnoSettings.pnoNetworks != NULL) {
        free(pnoSettings.pnoNetworks);
        pnoSettings.pnoNetworks = NULL;
    }

    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}

WifiErrorNo HdiStopPnoScan(void)
{
    LOGI("HdiStopPnoScan enter.");
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    const char *ifName = "wlan0";
    ret = proxy.wlanObj->StopPnoScan(proxy.wlanObj, ifName);
    if (ret != 0) {
        LOGE("HdiStopPnoScan failed ret:%{public}d.", ret);
        return WIFI_HAL_FAILED;
    }

    return WIFI_HAL_SUCCESS;
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
    CHECK_STA_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
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
    info->chload = signalResult.currentChload;
    info->snr = signalResult.currentSnr;
    info->ulDelay = signalResult.currentUlDelay;
    info->txFailed = signalResult.currentTxFailed;
    info->txBytes = signalResult.currentTxBytes;
    info->rxBytes = signalResult.currentRxBytes;
    return (ret == 0) ? 0 : -1;
}

static WifiErrorNo InitHdiScanResults()
{
    pthread_mutex_lock(&g_hdiMutex);
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

WifiErrorNo RegisterHdiStaCallbackEvent()
{
    LOGI("RegisterHdiStaCallbackEvent enter.");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiWanCallbackObj != NULL) {
        LOGI("RegisterHdiStaCallbackEvent already register.");
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        return WIFI_HAL_SUCCESS;
    }
    g_hdiWanCallbackObj = (struct IWlanCallback*)malloc(sizeof(struct IWlanCallback));
    if (g_hdiWanCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("g_hdiWanCallbackObj malloc failed.");
        return WIFI_HAL_FAILED;
    }
    g_hdiWanCallbackObj->ResetDriverResult = NULL;
    g_hdiWanCallbackObj->ScanResult = NULL;
    g_hdiWanCallbackObj->WifiNetlinkMessage = NULL;
    g_hdiWanCallbackObj->ScanResults = HdiScanResultsCallback;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    if (proxy.wlanObj == NULL || proxy.feature == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("Hdi proxy is NULL!");
        return WIFI_HAL_FAILED;
    }
    int32_t ret = proxy.wlanObj->RegisterEventCallback(proxy.wlanObj, g_hdiWanCallbackObj, "wlan0");
    if (ret != 0) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("Hdi RegisterEventCallback failed ret:%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    pthread_mutex_unlock(&g_hdiCallbackMutex);

    return InitHdiScanResults();
}

static void ClearHdiScanResults()
{
    pthread_mutex_lock(&g_hdiMutex);
    g_hdiScanResultsCount = 0;
    if (g_hdiScanResults != NULL) {
        free(g_hdiScanResults);
        g_hdiScanResults = NULL;
    }
    pthread_mutex_unlock(&g_hdiMutex);
    return;
}

void UnRegisterHdiStaCallbackEvent()
{
    LOGI("UnRegisterHdiStaCallbackEvent enter.");
    ClearHdiScanResults();
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiWanCallbackObj != NULL) {
        WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
        if (proxy.wlanObj == NULL || proxy.feature == NULL) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("Hdi proxy is NULL!");
            return;
        }
        int32_t ret = proxy.wlanObj->UnregisterEventCallback(proxy.wlanObj, g_hdiWanCallbackObj, "wlan0");
        if (ret != 0) {
            LOGE("Hdi UnregisterEventCallback failed ret:%{public}d", ret);
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            return;
        }
        StubCollectorRemoveObject(IWLANCALLBACK_INTERFACE_DESC, g_hdiWanCallbackObj);
        free(g_hdiWanCallbackObj);
        g_hdiWanCallbackObj = NULL;
    }
    pthread_mutex_unlock(&g_hdiCallbackMutex);
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
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        LOGE("ioctl failed, error:%{public}d.", errno);
        close(fd);
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
    if (mac == NULL) {
        LOGE("SetAssocMacAddr is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGI("SetAssocMacAddr enter.");
    CHECK_STA_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
    if (strlen((const char *)mac) != WIFI_MAC_LENGTH || lenMac != WIFI_MAC_LENGTH) {
        LOGE("Mac size not correct! mac len %{public}zu, request lenMac %{public}d", strlen((const char *)mac), lenMac);
        return WIFI_HAL_FAILED;
    }

    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);

    unsigned char mac_bin[MAC_ADDR_INDEX_SIZE];
    int32_t ret = sscanf_s((char *)mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &mac_bin[MAC_ADDR_INDEX_0], &mac_bin[MAC_ADDR_INDEX_1], &mac_bin[MAC_ADDR_INDEX_2],
           &mac_bin[MAC_ADDR_INDEX_3], &mac_bin[MAC_ADDR_INDEX_4], &mac_bin[MAC_ADDR_INDEX_5]);
    if (ret <= EOK) {
        LOGE("SetAssocMacAddr parse mac failed: %{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    
    UpDownLink(0);
    ret = proxy.wlanObj->SetMacAddress(proxy.wlanObj, proxy.feature, mac_bin, MAC_ADDR_INDEX_SIZE);
    if (ret != HDF_SUCCESS) {
        LOGE("SetAssocMacAddr failed: %{public}d", ret);
    }
    UpDownLink(1);
    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}

void ReleaseLocalResources()
{
    LOGI("ReleaseLocalResources enter.");
    ClearHdiScanResults();
    if (g_hdiWanCallbackObj != NULL) {
        StubCollectorRemoveObject(IWLANCALLBACK_INTERFACE_DESC, g_hdiWanCallbackObj);
        free(g_hdiWanCallbackObj);
        g_hdiWanCallbackObj = NULL;
    }
}
#endif

#endif
