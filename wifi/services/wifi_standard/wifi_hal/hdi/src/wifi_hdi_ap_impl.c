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

#include "wifi_hdi_ap_impl.h"
#include "wifi_hdi_proxy.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiApImpl"

#define NUMS_BAND 2

static int32_t ConvertToNl80211Band(int32_t band)
{
    return (band > 0 && band <= NUMS_BAND) ? (band - 1) : band;
}

WifiErrorNo GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id)
{
    if (frequencies == NULL || size == NULL) {
        LOGE("%{public}s frequencies or size is null.", __func__);
        return WIFI_HAL_FAILED;
    }
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    struct HdfWifiInfo wifiInfo;
    wifiInfo.band = ConvertToNl80211Band(band);
    wifiInfo.size = *size;
    uint32_t count = 0xff;
    LOGI("Get freqs parameters [band: %{public}d, alloc size: %{public}d]", wifiInfo.band, wifiInfo.size);
    int32_t ret = proxy.wlanObj->GetFreqsWithBand(proxy.wlanObj, proxy.feature, &wifiInfo, frequencies, &count);
    LOGI("Get freqs result, actual size: %{public}d", count);
    *size = count;
    if (ret != 0) {
        LOGE("Get freqs with band failed: %{public}d", ret);
    }
    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}

WifiErrorNo WifiSetPowerModel(const int mode, int id)
{
    LOGI("Instance %{public}d WifiSetPowerModel: %{public}d", id, mode);
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    int32_t ret = proxy.wlanObj->SetPowerMode(proxy.wlanObj, proxy.feature, mode);
    if (ret != 0) {
        LOGE("Set power mode failed: %{public}d", ret);
    }
    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}

WifiErrorNo WifiGetPowerModel(int* mode, int id)
{
    LOGI("Instance %{public}d WifiGetPowerModel", id);
    WifiHdiProxy proxy = GetHdiProxy(PROTOCOL_80211_IFTYPE_AP);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_HAL_FAILED);
    int32_t ret = proxy.wlanObj->GetPowerMode(proxy.wlanObj, proxy.feature, (uint8_t *)mode);
    if (ret != 0) {
        LOGE("Get power mode failed: %{public}d", ret);
    }
    LOGI("Get power mode: %{public}d", *mode);
    return (ret == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED;
}
#endif
