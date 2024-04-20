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

#include "wifi_hdi_ap_impl.h"
#include "wifi_hdi_proxy.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiApImpl"

#define NUMS_BAND 2

#ifndef CHECK_AP_HDI_PROXY_AND_RETURN
#define CHECK_AP_HDI_PROXY_AND_RETURN(isRemoteDied) \
if (isRemoteDied) { \
    if (StartHdiWifi() != WIFI_IDL_OPT_OK) { \
        LOGE("failed to start ap hdi"); \
        return WIFI_IDL_OPT_FAILED; \
    } \
}
#endif
WifiErrorNo HdiGetFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id)
{
    if (frequencies == NULL || size == NULL) {
        LOGE("%{public}s: frequencies or size is null.", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    CHECK_AP_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    struct HdfWifiInfo wifiInfo;

    if (band > 0 && band <= NUMS_BAND) {
        wifiInfo.band = band - 1;
    } else {
        wifiInfo.band = band;
    }
    wifiInfo.size = *size;
    uint32_t count = 0xff;
    LOGI("%{public}s: Get freqs parameters [band: %{public}d, size: %{public}d]",
        __func__, wifiInfo.band, wifiInfo.size);
    int32_t ret = proxy.wlanObj->GetFreqsWithBand(proxy.wlanObj, proxy.feature, &wifiInfo, frequencies, &count);
    LOGI("%{public}s: Get freqs result, actual size: %{public}d", __func__, count);
    *size = count;
    if (ret != 0) {
        LOGE("%{public}s: failed to get freqs with band, ret: %{public}d", __func__, ret);
    }
    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiWifiSetPowerModel(const int mode, int id)
{
    LOGI("%{public}s: id is %{public}d, mode is %{public}d", __func__, id, mode);
    CHECK_AP_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    int32_t ret = proxy.wlanObj->SetPowerMode(proxy.wlanObj, proxy.feature, mode);
    if (ret != 0) {
        LOGE("%{public}s: failed to set power mode, ret: %{public}d", __func__, ret);
    }
    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiWifiGetPowerModel(int* mode, int id)
{
    LOGI("%{public}s: id is %{public}d", __func__, id);
    CHECK_AP_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    int32_t ret = proxy.wlanObj->GetPowerMode(proxy.wlanObj, proxy.feature, (uint8_t *)mode);
    if (ret != 0) {
        LOGE("%{public}s: failed to get power mode, ret: %{public}d", __func__, ret);
    }
    LOGI("%{public}s: power mode is %{public}d", __func__, *mode);
    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo HdiWifiSetCountryCode(const char* code, int id)
{
    if (code == NULL) {
        LOGE("%{public}s: id is %{public}d", __func__, id);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("%{public}s: id is %{public}d, code is %{public}s", __func__, id, code);
    CHECK_AP_HDI_PROXY_AND_RETURN(IsHdiRemoteDied());
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);
    int32_t ret = proxy.wlanObj->SetCountryCode(proxy.wlanObj, proxy.feature, code, (uint32_t)strlen(code));
    if (ret != 0) {
        LOGE("%{public}s: failed to set country code, ret: %{public}d", __func__, ret);
    }
    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}
#endif