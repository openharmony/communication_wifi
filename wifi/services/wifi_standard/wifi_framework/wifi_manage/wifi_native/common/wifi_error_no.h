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

#ifndef OHOS_WIFI_ERROR_NO_H
#define OHOS_WIFI_ERROR_NO_H

/* Wifi Native Operation Error Code */
typedef enum WifiErrorNo {
    WIFI_HAL_OPT_OK = 0,                     /* Hal operation succeeded */
    WIFI_HAL_OPT_FAILED = 1,                 /* Hal operation failed */
    WIFI_HAL_OPT_SCAN_BUSY = 2,              /* Scan failed. Scan busy. */
    WIFI_HAL_OPT_PBC_OVERLAP = 3,            /* WPS PBC mode: overlap */
    WIFI_HAL_OPT_SUPPLICANT_NOT_INIT = 4,    /* The wpa_supplicant is not initialized or fails to be initialized */
    WIFI_HAL_OPT_OPEN_SUPPLICANT_FAILED = 5, /* Failed to enable wpa_supplicant. */
    WIFI_HAL_OPT_CONN_SUPPLICANT_FAILED = 6, /* Failed to connect to wpa_supplicant. */
    WIFI_HAL_OPT_HOSTAPD_NOT_INIT = 7,       /* Hostapd is not initialized or initialization fails. */
    WIFI_HAL_OPT_OPEN_HOSTAPD_FAILED = 8,    /* Failed to start the hostapd. */
    WIFI_HAL_OPT_CONN_HOSTAPD_FAILED = 9,    /* Failed to connect to the hostapd. */
    WIFI_HAL_OPT_NOT_SUPPORT,
    WIFI_HAL_OPT_GET_WIFI_COND_FAILED,
    WIFI_HAL_OPT_BUFFER_TOO_LITTLE,
    WIFI_HAL_OPT_INPUT_MAC_INVALID,
    WIFI_HAL_OPT_GET_VENDOR_HAL_FAILED,         /* Initialized vendor hal failed. */
    WIFI_HAL_OPT_VENDOR_UNKNOWN,
    WIFI_HAL_OPT_VENDOR_UNINITIALIZED,
    WIFI_HAL_OPT_VENDOR_NOT_AVAILABLE,
    WIFI_HAL_OPT_VENDOR_INVALID_ARGS,
    WIFI_HAL_OPT_VENDOR_INVALID_REQUEST_ID,
    WIFI_HAL_OPT_VENDOR_TIMED_OUT,
    WIFI_HAL_OPT_VENDOR_TOO_MANY_REQUESTS,
    WIFI_HAL_OPT_VENDOR_OUT_OF_MEMORY,
    WIFI_HAL_OPT_VENDOR_BUSY,
    WIFI_HAL_OPT_INVALID_PARAM,
    WIFI_HAL_OPT_GET_P2P_GROUP_INFACE_FAILED,
    WIFI_HAL_OPT_STA_ALREADY_STOP,
} WifiErrorNo;

#endif
