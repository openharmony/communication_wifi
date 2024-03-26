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
#ifndef OHOS_WIFI_HDI_PROXY_H
#define OHOS_WIFI_HDI_PROXY_H

#include "wifi_hdi_define.h"
#include "wifi_error_no.h"
#include "securec.h"
#include "v1_2/iwlan_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WifiHdiProxy {
    struct IWlanInterface* wlanObj;
    struct HdfFeatureInfo* feature;
} WifiHdiProxy;

#ifndef CHECK_HDI_PROXY_AND_RETURN
#define CHECK_HDI_PROXY_AND_RETURN(proxy, retValue) \
if (proxy.wlanObj == NULL || proxy.feature == NULL) { \
    LOGE("Hdi proxy: %{public}s in %{public}s is NULL!", #proxy, __func__); \
    return retValue; \
}
#endif

/**
 * @Description Create a channel between the HAL and the driver.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo StartHdiWifi();

/**
 * @Description Stop the created channel.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiStop();

/**
 * @Description check hdi already stopped.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo IsHdiStopped();

/**
 * @Description Create the WiFi object.
 *
 * @return WifiErrorNo - operation result
 */
struct IWlanInterface* GetWlanInterface();

/**
 * @Description Get the hdi proxy by wlan type.
 *
 * @param wlanType - wlan type
 * @return WifiHdiProxy - interface proxy object
 */
WifiHdiProxy GetHdiProxy(const int32_t wlanType);

/**
 * @Description Release hdi proxy by wlan type.
 * This interface will be automatic called in the hid stop function,
 * So you can use it without releasing.
 *
 * @param wlanType - wlan type
 * @return WifiErrorNo - operation result
 */
WifiErrorNo ReleaseHdiProxy(const int32_t wlanType);

/**
 * @Description Is hdi remote died.
 *
 * @return bool - is hdi remote died
 */
bool IsHdiRemoteDied();

/**
 * @Description Clean local resources if remote died.
 */
void CleanLocalResources();

/**
 * @Description check hdi normal start
 *
 * @param wlanType - wlan type
 * @return WifiErrorNo - operation result
 */
WifiErrorNo CheckHdiNormalStart(const int32_t wlanType);

WifiErrorNo SetWifiHdiStaIfaceName(const char *ifaceName);
const char *GetWifiHdiStaIfaceName();
#ifdef __cplusplus
}
#endif
#endif
#endif