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

#include <pthread.h>
#include "v1_0/ihostapd_interface.h"
#include "v1_0/ihostapd_callback.h"
#include "v1_0/iwpa_interface.h"
#include "v1_0/iwpa_callback.h"
#include "v1_0/wpa_types.h"
#include "wifi_error_no.h"
#include "wifi_log.h"
#include "securec.h"
#include "wifi_common_def.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#define EXEC_DISABLE 1

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
 * @Description check wpa hdi already stopped.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo IsHdiWpaStopped();


/**
 * @Description Add interface.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiAddWpaIface(const char *ifName, const char *confName);

/**
 * @Description Remove interface.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiRemoveWpaIface(const char *ifName);

WifiErrorNo SetHdiStaIfaceName(const char *ifaceName);
const char *GetHdiStaIfaceName();
WifiErrorNo SetHdiP2pIfaceName(const char *ifaceName);
const char *GetHdiP2pIfaceName();

/**
 * @Description Create the WiFi object.
 *
 * @return WifiErrorNo - operation result
 */
struct IWpaInterface* GetWpaInterface();

/**
 * @Description copy file.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo CopyUserFile(const char *srcFilePath, const char* destFilePath);

/**
 * @Description copy wpa_supplicant config file.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo CopyConfigFile(const char* configName);

/**
 * @Description Create a ap channel between the HAL and the driver.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiApStart(int id, const char *ifaceName);

/**
 * @Description Stop the created ap channel.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiApStop(int id);

/**
 * @Description check wpa hdi ap already stopped.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo IsHdiApStopped();

/**
 * @Description Create the Ap object.
 *
 * @return WifiErrorNo - operation result
 */
struct IHostapdInterface* GetApInterface();

WifiErrorNo SetHdiApIfaceName(const char *ifaceName);
const char *GetHdiApIfaceName();

void SetExecDisable(int execDisable);
int GetExecDisable();

#ifdef __cplusplus
}
#endif
#endif
#endif
