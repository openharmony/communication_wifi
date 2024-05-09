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

#ifdef HDI_INTERFACE_SUPPORT
#include <pthread.h>
#include "securec.h"
#include "wifi_hdi_sta_impl.h"
#include "wifi_hdi_proxy.h"
#include "wifi_log.h"
#include "stub_collector.h"
#include "wifi_hdi_util.h"
#include "wifi_common_def.h"
#include "wifi_hdi_common.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiStaImpl"

#define WIFI_PNO_SCAN_ITERATIONS 3
#define WIFI_PNO_SCAN_SECOND_TO_MS 1000
#define WIFI_MAX_BUFFER_LENGTH 1024
#define WIFI_IDL_GET_MAX_SCAN_INFO 256 /* Maximum number of scan infos obtained at a time */
#define WIFI_HDI_STOP_SLEEP_MS 300000

#ifndef CHECK_STA_HDI_WIFI_PROXY_AND_RETURN
#define CHECK_STA_HDI_WIFI_PROXY_AND_RETURN(isRemoteDied) \
if (isRemoteDied) { \
    HdiReleaseLocalResources(); \
    if (StartHdiWifi() != WIFI_IDL_OPT_OK) { \
        LOGE("[STA] Start hdi failed!"); \
        return WIFI_IDL_OPT_FAILED; \
    } \
    struct IWlanCallback cEventCallback; \
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) { \
        LOGE("%{public}s: failed to memset", __func__); \
        return WIFI_IDL_OPT_FAILED; \
    } \
    cEventCallback.ScanResults = HdiWifiScanResultsCallback; \
    if (HdiRegisterEventCallback(&cEventCallback) != WIFI_IDL_OPT_OK) { \
        LOGE("[STA] RegisterHdiStaCallbackEvent failed!"); \
        return WIFI_IDL_OPT_FAILED; \
    } \
}
#endif

static ISupplicantEventCallback g_wifiHdiSupplicantEventCallback = {0};
struct IWlanCallback* g_hdiWifiCallbackObj = NULL;
static pthread_mutex_t g_hdiWifiCallbackMutex = PTHREAD_MUTEX_INITIALIZER;
ScanInfo* g_hdiWifiScanResults = NULL;
int g_hdiWifiScanResultsCount = 0;
static pthread_mutex_t g_hdiWifiMutex = PTHREAD_MUTEX_INITIALIZER;

static void ReleaseScanResultsInfoElems(ScanInfo* scanResult)
{
    if (scanResult == NULL) {
        LOGE("%{public}s: scan results is null", __func__);
        return;
    }
    if (scanResult->infoElems != NULL) {
        for (int i = 0; (i < scanResult->ieSize) && (i < WIFI_IDL_GET_MAX_SCAN_INFO); i++) {
            if (scanResult->infoElems[i].content != NULL) {
                free(scanResult->infoElems[i].content);
                scanResult->infoElems[i].content = NULL;
            }
        }
        free(scanResult->infoElems);
        scanResult->infoElems = NULL;
    }
}

static void ReleaseScanResultsResource()
{
    pthread_mutex_lock(&g_hdiWifiMutex);
    g_hdiWifiScanResultsCount = 0;
    if (g_hdiWifiScanResults != NULL) {
        for (int i = 0; i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
            ReleaseScanResultsInfoElems(&g_hdiWifiScanResults[i]);
        }
        free(g_hdiWifiScanResults);
        g_hdiWifiScanResults = NULL;
    }
    pthread_mutex_unlock(&g_hdiWifiMutex);
    return;
}

static WifiErrorNo InitScanResults()
{
    LOGD("initialize scan results");
    pthread_mutex_lock(&g_hdiWifiMutex);
    g_hdiWifiScanResultsCount = 0;
    if (g_hdiWifiScanResults != NULL) {
        LOGW("g_hdiScanResults has been initialized");
        for (int i = 0; i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
            ReleaseScanResultsInfoElems(&g_hdiWifiScanResults[i]);
        }
        if (memset_s(g_hdiWifiScanResults, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo),
            0, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo)) != EOK) {
            pthread_mutex_unlock(&g_hdiWifiMutex);
            LOGE("failed to memset_s");
            return WIFI_IDL_OPT_FAILED;
        }
        pthread_mutex_unlock(&g_hdiWifiMutex);
        return WIFI_IDL_OPT_OK;
    }

    g_hdiWifiScanResults = (struct ScanInfo*)malloc(WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo));
    if (g_hdiWifiScanResults == NULL) {
        pthread_mutex_unlock(&g_hdiWifiMutex);
        LOGE("failed to alloc memory");
        return WIFI_IDL_OPT_FAILED;
    }
    if (memset_s(g_hdiWifiScanResults, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo),
        0, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo)) != EOK) {
        pthread_mutex_unlock(&g_hdiWifiMutex);
        LOGE("failed to memset_s");
        return WIFI_IDL_OPT_FAILED;
    }
    pthread_mutex_unlock(&g_hdiWifiMutex);
    return WIFI_IDL_OPT_OK;
}

static void GetScanInfoElems(ScanInfo* src, ScanInfo* scanInfo)
{
    const int MAX_INFO_ELEMS_SIZE = 256;
    scanInfo->ieSize = src->ieSize;
    if (scanInfo->ieSize <= 0 || scanInfo->ieSize > MAX_INFO_ELEMS_SIZE) {
        return;
    }
    scanInfo->infoElems = (ScanInfoElem *)calloc(scanInfo->ieSize, sizeof(ScanInfoElem));
    if (scanInfo->infoElems == NULL) {
        return;
    }
    for (int i = 0; i < scanInfo->ieSize; ++i) {
        scanInfo->infoElems[i].id = src->infoElems[i].id;
        scanInfo->infoElems[i].size = src->infoElems[i].size;
        if (scanInfo->infoElems[i].size <= 0) {
            continue;
        }
        /* This pointer will be released in its client */
        scanInfo->infoElems[i].content = calloc(scanInfo->infoElems[i].size + 1, sizeof(char));
        if (scanInfo->infoElems[i].content == NULL) {
            return;
        }
        if (memcpy_s(scanInfo->infoElems[i].content, scanInfo->infoElems[i].size + 1,
            src->infoElems[i].content, src->infoElems[i].size) != EOK) {
            return;
        }
    }
}

static WifiErrorNo GetScanInfos(ScanInfo* infos, int *size)
{
    if (infos == NULL || size == NULL || *size == 0) {
        LOGE("%{public}s: invalid parameter", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    pthread_mutex_lock(&g_hdiWifiMutex);
    LOGI("%{public}s: saved size:%{public}d.", __func__, g_hdiWifiScanResultsCount);
    if (*size < g_hdiWifiScanResultsCount) {
        LOGE("input size invalid. %{public}d < %{public}d.", *size, g_hdiWifiScanResultsCount);
        pthread_mutex_unlock(&g_hdiWifiMutex);
        return WIFI_IDL_OPT_FAILED;
    }

    if (memcpy_s(infos, *size * sizeof(struct ScanInfo),
        g_hdiWifiScanResults, g_hdiWifiScanResultsCount * sizeof(struct ScanInfo)) != EOK) {
        LOGE("%{public}s: failed to memcpy_s", __func__);
        pthread_mutex_unlock(&g_hdiWifiMutex);
        return WIFI_IDL_OPT_FAILED;
    }
    *size = g_hdiWifiScanResultsCount;
    for (int i = 0; i < *size; i++) {
        GetScanInfoElems(&g_hdiWifiScanResults[i], &infos[i]);
    }
    for (int i = 0; i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
        ReleaseScanResultsInfoElems(&g_hdiWifiScanResults[i]);
    }
    pthread_mutex_unlock(&g_hdiWifiMutex);
    return WIFI_IDL_OPT_OK;
}

static WifiErrorNo GetSignalInfo(WpaSignalInfo *info)
{
    if (info == NULL) {
        LOGE("HdiWifiGetSignalInfo info is null.");
        return -1;
    }
    CHECK_STA_HDI_WIFI_PROXY_AND_RETURN(IsHdiRemoteDied());
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    struct SignalPollResult signalResult = {0};
    
    ret = proxy.wlanObj->GetSignalPollInfo(proxy.wlanObj, GetWifiHdiStaIfaceName(), &signalResult);
    if (ret != 0) {
        LOGE("HdiWifiGetSignalInfo failed ret:%{public}d", ret);
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

WifiErrorNo HdiWifiStart(const char *ifaceName)
{
    LOGI("%{public}s: begin to start wifi", __func__);
    if (SetWifiHdiStaIfaceName(ifaceName) != WIFI_IDL_OPT_OK) {
        LOGE("failed to set sta iface name!");
        return WIFI_IDL_OPT_FAILED;
    }
    if (StartHdiWifi() != WIFI_IDL_OPT_OK) {
        LOGE("failed to start hdi wifi!");
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckHdiNormalStart(PROTOCOL_80211_IFTYPE_STATION) != WIFI_IDL_OPT_OK) {
        LOGE("check hdi abnormal start, failed to start hdi wifi!");
        return WIFI_IDL_OPT_FAILED;
    }
    struct IWlanCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        LOGE("%{public}s: failed to memset", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    cEventCallback.ScanResults = HdiWifiScanResultsCallback;
    if (HdiRegisterEventCallback(&cEventCallback) != WIFI_IDL_OPT_OK) {
        LOGE("%{public}s: failed to register scan result callback!", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("Start wifi successfully");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWifiStop()
{
    LOGI("%{public}s: begin to stop wifi enter", __func__);
    if (IsHdiStopped() == WIFI_IDL_OPT_OK) {
        LOGI("%{public}s: wifi hdi already stopped, HdiWifiStop success", __func__);
        return WIFI_IDL_OPT_OK;
    }
    HdiUnRegisterStaCallbackEvent();
    usleep(WIFI_HDI_STOP_SLEEP_MS); /* 300ms */
    if (HdiStop() != WIFI_IDL_OPT_OK) {
        LOGE("failed to stop hdi");
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("%{public}s: begin to stop wifi exit", __func__);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWifiStartScan(const ScanSettings *settings)
{
    LOGI("%{public}s: begin to start to scan", __func__);
    CHECK_STA_HDI_WIFI_PROXY_AND_RETURN(IsHdiRemoteDied());
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    struct HdfWifiScan scan = {0};
    if (settings->hiddenSsidSize > 0) {
        int size = settings->hiddenSsidSize * sizeof(struct HdfWifiDriverScanSsid);
        scan.ssids = (struct HdfWifiDriverScanSsid*)malloc(size);
        if (scan.ssids == NULL) {
            LOGE("failed to alloc!");
            return WIFI_IDL_OPT_FAILED;
        }
        if (memset_s(scan.ssids, size, 0, size) != EOK) {
            LOGE("%{public}s: failed to memset", __func__);
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
                LOGE("%{public}s: failed to memset", __func__);
                ret = 1;
                goto finish;
            }
            if (strcpy_s(scan.ssids[i].ssid, scan.ssids[i].ssidLen + 1, settings->hiddenSsid[i]) != EOK) {
                LOGE("%{public}s: failed to strcpy", __func__);
                ret = 1;
                goto finish;
            }
        }
    }

    ret = proxy.wlanObj->StartScan(proxy.wlanObj, proxy.feature, &scan);
    if (ret != 0) {
        LOGE("%{public}s: failed to start scan, ret:%{public}d", __func__, ret);
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
    LOGI("%{public}s: start scanning, ret: %{public}d", __func__, ret);
    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiWifiStartPnoScan(const PnoScanSettings * settings)
{
    LOGI("HdiStartPnoScan enter.");
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
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
            return WIFI_IDL_OPT_FAILED;
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

    ret = proxy.wlanObj->StartPnoScan(proxy.wlanObj, GetWifiHdiStaIfaceName(), &pnoSettings);
    if (ret != 0) {
        LOGE("HdiStartPnoScan failed ret:%{public}d.", ret);
    }
    if (pnoSettings.pnoNetworks != NULL) {
        free(pnoSettings.pnoNetworks);
        pnoSettings.pnoNetworks = NULL;
    }

    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiWifiStopPnoScan(void)
{
    LOGI("%{public}s: begin to stop pno scan", __func__);
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    ret = proxy.wlanObj->StopPnoScan(proxy.wlanObj, GetWifiHdiStaIfaceName());
    if (ret != 0) {
        LOGE("%{public}s: failed to stop pno scan, ret:%{public}d.", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

int32_t HdiWifiScanResultsCallback(struct IWlanCallback *self, uint32_t event,
    const struct HdfWifiScanResults *scanResults, const char* ifName)
{
    LOGI("%{public}s: register scan result callback", __func__);
    pthread_mutex_lock(&g_hdiWifiMutex);
    g_hdiWifiScanResultsCount = 0;
    if (g_hdiWifiScanResults == NULL) {
        pthread_mutex_unlock(&g_hdiWifiMutex);
        LOGE("%{public}s: g_hdiWifiScanResults is null!", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    if (scanResults == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_hdiWifiMutex);
        LOGE("%{public}s: scanResults or ifName is null!", __func__);
        HdiNotifyScanResult(HDI_STA_CB_SCAN_FAILED);
        return WIFI_IDL_OPT_FAILED;
    }
    for (int i = 0; i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
        ReleaseScanResultsInfoElems(&g_hdiWifiScanResults[i]);
    }
    if (memset_s(g_hdiWifiScanResults, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo),
        0, WIFI_IDL_GET_MAX_SCAN_INFO * sizeof(struct ScanInfo)) != EOK) {
        pthread_mutex_unlock(&g_hdiWifiMutex);
        LOGE("%{public}s: failed to memset_s", __func__);
        HdiNotifyScanResult(HDI_STA_CB_SCAN_FAILED);
        return WIFI_IDL_OPT_FAILED;
    }
    char buff[WIFI_MAX_BUFFER_LENGTH] = {0};
    char bssid[HDI_BSSID_LENGTH] = {0};
    int buffLen = WIFI_MAX_BUFFER_LENGTH;
    for (size_t i = 0; i < scanResults->resLen && i < WIFI_IDL_GET_MAX_SCAN_INFO; i++) {
        struct WifiScanResultExt *scanResult = (struct WifiScanResultExt *)&scanResults->res[i];
        struct HdiElems elems;
        Get80211ElemsFromIE((const uint8_t*)scanResult->ie, scanResult->ieLen, &elems, 1);
        if (elems.ssidLen == 0) {
            if (sprintf_s(bssid, sizeof(bssid), MACSTR, MAC2STR(scanResult->bssid)) < 0) {
                LOGD("%{public}s: ssid empty.", __func__);
                continue;
            }
            LOGD("%{public}s: invalid ssid, bssid:%{private}s", bssid, __func__);
            continue;
        }
        buffLen = WIFI_MAX_BUFFER_LENGTH;
        if (memset_s(buff, buffLen, 0, buffLen) != EOK) {
            pthread_mutex_unlock(&g_hdiWifiMutex);
            LOGE("%{public}s: failed to memset_s", __func__);
            HdiNotifyScanResult(HDI_STA_CB_SCAN_FAILED);
            return WIFI_IDL_OPT_FAILED;
        }
        buffLen = GetScanResultText(scanResult, &elems, buff, buffLen);
        if (DelScanInfoLine(&g_hdiWifiScanResults[g_hdiWifiScanResultsCount], buff, buffLen)) {
            LOGE("%{public}s: failed to obtain the scanning result", __func__);
            continue;
        }
        GetScanResultInfoElem(&g_hdiWifiScanResults[g_hdiWifiScanResultsCount],
            (const uint8_t*)scanResult->ie, scanResult->ieLen);
        g_hdiWifiScanResults[g_hdiWifiScanResultsCount].timestamp = scanResult->tsf;
        g_hdiWifiScanResults[g_hdiWifiScanResultsCount].isHiLinkNetwork = RouterSupportHiLinkByWifiInfo(
            (const uint8_t*)scanResult->ie, scanResult->ieLen);
        LOGD("%{public}s: bssid:%{private}s, ssid:%{private}s isHiLinkNetwork = %{public}d",
            __func__,
            g_hdiWifiScanResults[g_hdiWifiScanResultsCount].bssid,
            g_hdiWifiScanResults[g_hdiWifiScanResultsCount].ssid,
            g_hdiWifiScanResults[g_hdiWifiScanResultsCount].isHiLinkNetwork);
        g_hdiWifiScanResultsCount++;
    }
    LOGI("%{public}s: the number of scan results is %{public}d", __func__, g_hdiWifiScanResultsCount);
    pthread_mutex_unlock(&g_hdiWifiMutex);
    HdiNotifyScanResult(HDI_STA_CB_SCAN_OVER_OK);
    return WIFI_IDL_OPT_OK;
}

void HdiUnRegisterStaCallbackEvent()
{
    ReleaseScanResultsResource();
    pthread_mutex_lock(&g_hdiWifiCallbackMutex);
    if (g_hdiWifiCallbackObj != NULL) {
        WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
        if (proxy.wlanObj == NULL || proxy.feature == NULL) {
            pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
            LOGE("%{public}s: Hdi proxy is NULL!", __func__);
            return;
        }
        int32_t ret = proxy.wlanObj->UnregisterEventCallback(proxy.wlanObj, g_hdiWifiCallbackObj,
            GetWifiHdiStaIfaceName());
        if (ret != 0) {
            LOGE("%{public}s: failed to unregister event callback, ret:%{public}d", __func__, ret);
            pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
            return;
        }
        StubCollectorRemoveObject(IWLANCALLBACK_INTERFACE_DESC, g_hdiWifiCallbackObj);
        free(g_hdiWifiCallbackObj);
        g_hdiWifiCallbackObj = NULL;
    }
    pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
}

void HdiSetSupplicantEventCallback(ISupplicantEventCallback callback)
{
    g_wifiHdiSupplicantEventCallback = callback;
}

ISupplicantEventCallback *HdiGetSupplicantEventCallback()
{
    return &g_wifiHdiSupplicantEventCallback;
}

WifiErrorNo HdiRegisterStaCallbackEvent(struct IWlanCallback *callback)
{
    pthread_mutex_lock(&g_hdiWifiCallbackMutex);
    if (callback == NULL || callback->ScanResults == NULL) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGE("%{public}s: invalid parameter!", __func__);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_hdiWifiCallbackObj != NULL) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGI("%{public}s: already register!", __func__);
        return WIFI_IDL_OPT_OK;
    }

    g_hdiWifiCallbackObj = (struct IWlanCallback *)malloc(sizeof(struct IWlanCallback));
    if (g_hdiWifiCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGE("%{public}s: failed to alloc memory", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    g_hdiWifiCallbackObj->ResetDriverResult = NULL;
    g_hdiWifiCallbackObj->ScanResult = NULL;
    g_hdiWifiCallbackObj->WifiNetlinkMessage = NULL;
    g_hdiWifiCallbackObj->ScanResults = callback->ScanResults;
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiRegisterEventCallback(struct IWlanCallback *callback)
{
    HdiRegisterStaCallbackEvent(callback);
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    if (proxy.wlanObj == NULL || proxy.feature == NULL) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGE("%{public}s:Hdi proxy is NULL!", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    int32_t ret = proxy.wlanObj->RegisterEventCallback(proxy.wlanObj, g_hdiWifiCallbackObj, GetWifiHdiStaIfaceName());
    if (ret != 0) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGE("%{public}s: failed to register event Callback, ret:%{public}d", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }
    pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
    LOGI("%{public}s: success to register event callback", __func__);
    return InitScanResults();
}

WifiErrorNo HdiWifiGetScanInfos(ScanInfo *results, int *size)
{
    if (results == NULL || size == NULL || *size == 0) {
        LOGE("%{public}s: invalid parameter", __func__);
        return WIFI_IDL_OPT_OK;
    }
    int ret = GetScanInfos(results, size);
    if (ret < 0) {
        LOGE("%{public}s: failed to get scanInfos, ret:%{public}d", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGD("%{public}s: success to get scanInfos", __func__);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWifiGetConnectSignalInfo(const char *endBssid, WpaSignalInfo *info)
{
    if (endBssid == NULL || info == NULL) {
        LOGE("%{public}s: endBssid or info is NULL", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    int ret = GetSignalInfo(info);
    if (ret < 0) {
        LOGE("%{public}s: failed to get signal information, ret=%{public}d", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

void HdiReleaseLocalResources()
{
    ReleaseScanResultsResource();
    if (g_hdiWifiCallbackObj != NULL) {
        StubCollectorRemoveObject(IWLANCALLBACK_INTERFACE_DESC, g_hdiWifiCallbackObj);
        free(g_hdiWifiCallbackObj);
        g_hdiWifiCallbackObj = NULL;
    }
}

void HdiNotifyScanResult(int status)
{
    LOGI("%{public}s: scan status:%{public}d", __func__, status);
    ISupplicantEventCallback *callback = HdiGetSupplicantEventCallback();
    if (callback != NULL && callback->onScanNotify != NULL) {
        callback->onScanNotify(status);
    }
}

WifiErrorNo HdiSetPmMode(int frequency, int mode)
{
    LOGI("Enter %{public}s", __func__);
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    ret = proxy.wlanObj->SetPowerSaveMode(proxy.wlanObj, GetWifiHdiStaIfaceName(), frequency, mode);
    if (ret != 0) {
        LOGE("%{public}s: failed to set power save mode, ret:%{public}d.", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetDpiMarkRule(int uid, int protocol, int enable)
{
    LOGI("Enter %{public}s", __func__);
    int32_t ret = 0;
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    ret = proxy.wlanObj->SetDpiMarkRule(proxy.wlanObj, uid, protocol, enable);
    if (ret != 0) {
        LOGE("%{public}s: failed to set dpi mark rule, ret:%{public}d.", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiGetChipsetCategory(int* chipsetCategory)
{
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    if (proxy.wlanObj == NULL || proxy.feature == NULL) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGE("%{public}s: Hdi proxy is NULL!", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    int8_t param[1] = {0};
    *chipsetCategory = proxy.wlanObj->WifiSendCmdIoctl(proxy.wlanObj, "wlan0",
        CMD_GET_WIFI_CATEGORY, (const int8_t *)param, 1);
    if (*chipsetCategory < 1) {
        *chipsetCategory = 1;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiGetChipsetWifiFeatrureCapability(int* chipsetFeatrureCapability)
{
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_STATION);
    if (proxy.wlanObj == NULL || proxy.feature == NULL) {
        pthread_mutex_unlock(&g_hdiWifiCallbackMutex);
        LOGE("%{public}s: Hdi proxy is NULL!", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    int8_t param[1] = {0};
    *chipsetFeatrureCapability = proxy.wlanObj->WifiSendCmdIoctl(proxy.wlanObj, "wlan0",
        CMD_GET_FEATURE_CAPAB, (const int8_t *)param, 1);
    if (*chipsetFeatrureCapability < WIFI_CAPABILITY_DEFAULT) {
        *chipsetFeatrureCapability = WIFI_CAPABILITY_DEFAULT;
    }
    return WIFI_IDL_OPT_OK;
}
#endif