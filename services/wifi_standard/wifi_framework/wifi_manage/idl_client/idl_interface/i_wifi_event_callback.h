/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IDL_IWIFIEVENTCALLBACK_H
#define OHOS_IDL_IWIFIEVENTCALLBACK_H

#include "wifi_error_no.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IWifiEventCallback {
    void *pInstance;
    void (*onStarted)(void);                /* The driver has been loaded */
    void (*onStopped)(void);                /* The Wi-Fi driver has been uninstalled. */
    void (*onFailure)(WifiErrorNo errCode); /* Driver loading/unloading failure */
    void (*onConnectChanged)(
        int status, int networkId, char *bssid, void *pInstance); /* Wi-Fi connection event notification */
    void (*onWpaStateChanged)(int status, void *pInstance);       /* WPA status event notification */
    void (*onSsidWrongkey)(int status, void *pInstance);          /* SSID password error notification */
    void (*onWpsOverlap)(int status, void *pInstance);            /* The PBC of the WPS is duplicate. */
    void (*onWpsTimeOut)(int status, void *pInstance);            /* WPS connect time out */
} IWifiEventCallback;

#ifdef __cplusplus
}
#endif
#endif