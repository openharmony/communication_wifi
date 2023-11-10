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
#ifndef OHOS_WIFI_HDI_WPA_PROXY_H
#define OHOS_WIFI_HDI_WPA_PROXY_H

#include "v1_0/iwpa_interface.h"
#include "v1_0/iwpa_callback.h"
#include "wifi_hal_base_feature.h"
#include "wifi_error_no.h"
#include "wifi_log.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_IFACENAME_LEN 17

#ifndef CHECK_HDI_WPA_INTERFACE
#define CHECK_HDI_WPA_INTERFACE(wpaObj) \
if (wpaObj == NULL) { \
    LOGE("Hdi wpa proxy: wpaObj in %{public}s is NULL!", __func__); \
    return; \
}
#endif

#ifndef CHECK_HDI_WPA_INTERFACE_AND_RETURN
#define CHECK_HDI_WPA_INTERFACE_AND_RETURN(wpaObj, retValue) \
if (wpaObj == NULL) { \
    LOGE("Hdi wpa proxy: wpaObj in %{public}s is NULL!", __func__); \
    return retValue; \
}
#endif

#ifndef CHECK_SECURE_FUNC
#define CHECK_SECURE_FUNC(ret) \
if (ret < 0) { \
    LOGE("Hdi wpa proxy: call secure func failed in %{public}s", __func__); \
    return; \
}
#endif

#ifndef CHECK_SECURE_FUNC_AND_RETURN
#define CHECK_SECURE_FUNC_AND_RETURN(ret, retValue) \
if (ret < 0) { \
    LOGE("Hdi wpa proxy: call secure func failed in %{public}s", __func__); \
    return retValue; \
}
#endif

/**
 * @Description Create a channel between the HAL and the driver.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWpaStart();

/**
 * @Description Stop the created channel.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWpaStop();

/**
 * @Description Create the WiFi object.
 *
 * @return WifiErrorNo - operation result
 */
struct IWpaInterface* GetWlanInterface();

#ifdef __cplusplus
}
#endif
#endif
#endif
