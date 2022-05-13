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

#ifndef OHOS_ARCH_LITE
#include "wifi_hdi_ap_instance.h"
#include "wifi_hal_define.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiInstance"

WifiErrorNo HdiGetAp(struct IWiFi **wifi, struct IWiFiAp **apFeature)
{
    if (wifi == NULL || apFeature == NULL) {
        return WIFI_HAL_FAILED;
    }

    LOGD("HdiGetAp");
    int32_t ret;
    ret = WifiConstruct(wifi);
    if (ret != 0 || *wifi == NULL) {
        LOGE("%{public}s WifiConstruct failed", __func__);
        return WIFI_HAL_FAILED;
    }

    ret = (*wifi)->start(*wifi);
    if (ret != 0) {
        (void)WifiDestruct(wifi);
        LOGE("%{public}s start failed", __func__);
        return WIFI_HAL_FAILED;
    }

    ret = (*wifi)->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)apFeature);
    if (ret != 0 || *apFeature == NULL) {
        (void)(*wifi)->stop(*wifi);
        (void)WifiDestruct(wifi);
        LOGE("%{public}s createFeature failed", __func__);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo HdiReleaseAp(struct IWiFi *wifi, struct IWiFiAp *apFeature)
{
    if (wifi == NULL) {
        return WIFI_HAL_FAILED;
    }

    LOGD("HdiReleaseAp");
    if (apFeature != NULL) {
        (void)wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
    }
    (void)wifi->stop(wifi);
    (void)WifiDestruct(&wifi);
    return WIFI_HAL_SUCCESS;
}
#endif
