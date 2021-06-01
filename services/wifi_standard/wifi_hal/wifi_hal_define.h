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

#ifndef OHOS_WIFI_HAL_DEFINE_H
#define OHOS_WIFI_HAL_DEFINE_H

/* Contains common header files. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef char BOOL;
#define TRUE 1
#define FALSE 0

#define WIFI_COMMON_MAXLEN 512
#define WIFI_COUNTRY_CODE_MAXLEN 32
#define WIFI_IFACE_NAME_MAXLEN 32
#define WIFI_FUTURE_MAXLEN 128

typedef enum WifiErrorNo {
    WIFI_HAL_SUCCESS = 0,                /* Success. */
    WIFI_HAL_FAILED = 1,                 /* Failed. */
    WIFI_HAL_SCAN_BUSY = 2,              /* Scan failed. Scan busy. */
    WIFI_HAL_PBC_OVERLAP = 3,            /* WPS PBC mode overlap. */
    WIFI_HAL_SUPPLICANT_NOT_INIT = 4,    /* The wpa_supplicant is not initialized or fails to be initialized. */
    WIFI_HAL_OPEN_SUPPLICANT_FAILED = 5, /* Start wpa_supplicant failed. */
    WIFI_HAL_CONN_SUPPLICANT_FAILED = 6, /* Connect wpa_supplicant failed. */
    WIFI_HAL_HOSTAPD_NOT_INIT = 7,       /* Hostapd is not initialized or initialization fails. */
    WIFI_HAL_OPEN_HOSTAPD_FAILED = 8,    /* Start hostapd failed. */
    WIFI_HAL_CONN_HOSTAPD_FAILED = 9,    /* Connect hostapd failed. */
    WIFI_HAL_NOT_SUPPORT = 10,           /* Not supported currently. */
    WIFI_HAL_GET_WIFI_COND_FAILED,       /* Initialized  wificond failed. */
    WIFI_HAL_BUFFER_TOO_LITTLE,          /* request buffer size too small */
    WIFI_HAL_INPUT_MAC_INVALID,
    WIFI_HAL_GET_VENDOR_HAL_FAILED, /* Initialized vendor hal failed. */
    WIFI_HAL_VENDOR_UNKNOWN,
    WIFI_HAL_VENDOR_UNINITIALIZED,
    WIFI_HAL_VENDOR_NOT_AVAILABLE,
    WIFI_HAL_VENDOR_INVALID_ARGS,
    WIFI_HAL_VENDOR_INVALID_REQUEST_ID,
    WIFI_HAL_VENDOR_TIMED_OUT,
    WIFI_HAL_VENDOR_TOO_MANY_REQUESTS,
    WIFI_HAL_VENDOR_OUT_OF_MEMORY,
    WIFI_HAL_VENDOR_BUSY,
} WifiErrorNo;

/* ID of the callback event for registering the Hal service. */
typedef enum WifiHalEvent {
    WIFI_FAILURE_EVENT = 100,                /* Driver loading/unloading failure. */
    WIFI_START_EVENT = 101,                  /* The driver has been loaded. */
    WIFI_STOP_EVENT = 102,                   /* Driver uninstalled. */
    WIFI_ADD_IFACE_EVENT = 103,              /* The network device interface has been added. */
    WIFI_REMOVE_IFACE_EVENT = 104,           /* The network device interface has been deleted. */
    WIFI_STA_JOIN_EVENT = 105,               /* STA connection notification in AP mode. */
    WIFI_STA_LEAVE_EVENT = 106,              /* STA disconnection notification in AP mode. */
    WIFI_SCAN_RESULT_NOTIFY_EVENT = 107,     /* Scan result notification. */
    WIFI_CONNECT_CHANGED_NOTIFY_EVENT = 108, /* Connection status change notification. */
    WIFI_AP_ENABLE_EVENT = 109,              /* AP enabling notification. */
    WIFI_AP_DISABLE_EVENT = 110,             /* AP closure notification. */
    WIFI_WPA_STATE_EVENT = 111,              /* WPA status change. */
    WIFI_SSID_WRONG_KEY = 112,               /* Incorrect password. */
    WIFI_WPS_OVERLAP = 113,                  /* wps pbc overlap */
    WIFI_WPS_TIME_OUT = 114,                 /* wps connect time out */
    WIFI_HAL_MAX_EVENT,
} WifiHalEvent;

#define WIFI_BSSID_LENGTH 128
#define WIFI_SSID_LENGTH 128
#define WIFI_SCAN_RESULT_CAPABILITY_LENGTH 256
#define WIFI_NETWORK_CONFIG_VALUE_LENGTH 128
#define WIFI_MAC_LENGTH 17
#define WIFI_AP_PASSWORD_LENGTH 64
#define WIFI_STATUS_ERROR_MSG_LENGTH 64

/* Wifi network configuration parameter flag. */
typedef enum DeviceConfigType {
    DEVICE_CONFIG_SSID = 0, /* Network Name. */
    DEVICE_CONFIG_PSK = 1,  /* Password. */
    /**
     * Encryption Mode: WPA-PSK - wpa/wp2; NONE - password less network; WPA-EAP, SAE, wpa3.
     */
    DEVICE_CONFIG_KEYMGMT = 2,
    DEVICE_CONFIG_PRIORITY = 3, /* WPA network priority */
    /**
     * Set this bit to 1 and deliver it when the hidden network is connected.
     * In other cases, set this bit to 0 but do not deliver it.
     */
    DEVICE_CONFIG_SCAN_SSID = 4,
    DEVICE_CONFIG_EAP = 5,             /* EPA Mode:/EAP/PEAP. */
    DEVICE_CONFIG_IDENTITY = 6,        /* Account name. */
    DEVICE_CONFIG_PASSWORD = 7,        /* Account password. */
    DEVICE_CONFIG_BSSID = 8,           /* bssid. */
    DEVICE_CONFIG_AUTH_ALGORITHMS = 9, /* auth algorithms */
    DEVICE_CONFIG_WEP_KEY_IDX = 10,    /* wep key idx */
    DEVICE_CONFIG_WEP_KEY_0 = 11,
    DEVICE_CONFIG_WEP_KEY_1 = 12,
    DEVICE_CONFIG_WEP_KEY_2 = 13,
    DEVICE_CONFIG_WEP_KEY_3 = 14,
    /**
     * Number of network configuration parameters, which is used as the last
     * parameter.
     */
    DEVICE_CONFIG_END_POS,
} DeviceConfigType;

/* AP Band */
typedef enum APBand {
    AP_NONE_BAND = 0, /* Unknown Band */
    AP_2GHZ_BAND = 1, /* 2.4GHz Band */
    AP_5GHZ_BAND = 2, /* 5GHz Band */
    AP_ANY_BAND = 3,  /* Dual-mode frequency band */
    AP_DFS_BAND = 4
} APBand;

/*  Encryption Mode */
typedef enum KeyMgmt {
    NONE = 0,    /* WPA not used. */
    WPA_PSK = 1, /* WPA pre-shared key ({@ preSharedKey} needs to be specified.) */
    /**
     * WPA with EAP authentication. It is usually used with an external
     * authentication server.
     */
    WPA_EAP = 2,
    /**
     * IEEE 802.1X with EAP authentication and optionally dynamically generated
     * WEP keys.
     */
    IEEE8021X = 3,
    /**
     * WPA2 pre-shared key, which is used for soft APs({@ preSharedKey} needs to
     * be specified).
     */
    WPA2_PSK = 4,
    OSEN = 5,
    FT_PSK = 6,
    FT_EAP = 7
} keyMgmt;

/* Supplicant Status Code */
typedef enum SupplicantStatusCode {
    /* * No errors. */
    SUPPLICANT_SUCCESS,
    /* * Unknown failure occurred. */
    FAILURE_UNKNOWN,
    /* * One of the incoming args is invalid. */
    FAILURE_ARGS_INVALID,
    /* * |ISupplicantIface| HIDL interface object is no longer valid. */
    FAILURE_IFACE_INVALID,
    /* * Iface with the provided name does not exist. */
    FAILURE_IFACE_UNKNOWN,
    /* * Iface with the provided name already exists. */
    FAILURE_IFACE_EXISTS,
    /* * Iface is disabled and cannot be used. */
    FAILURE_IFACE_DISABLED,
    /* * Iface is not currently disconnected, so cannot reconnect. */
    FAILURE_IFACE_NOT_DISCONNECTED,
    /* * |ISupplicantNetwork| HIDL interface object is no longer valid. */
    FAILURE_NETWORK_INVALID,
    /* * Network with the provided id does not exist. */
    FAILURE_NETWORK_UNKNOWN
} SupplicantStatusCode;

/* Low-latency mode */
typedef enum LatencyMode { NORMAL = 0, LOW = 1 } LatencyMode;

/**
 * Enum values indicating the status of operation.
 */
typedef enum WifiStatusCode {
    /* * No errors. */
    WIFI_STATUS_SUCCESS,
    /* * Method invoked on an invalid |IWifiChip| object. */
    ERROR_WIFI_CHIP_INVALID,
    /* * Method invoked on an invalid |IWifiIface| object. */
    ERROR_WIFI_IFACE_INVALID,
    /* * Method invoked on an invalid |IWifiRttController| object. */
    ERROR_WIFI_RTT_CONTROLLER_INVALID,
    ERROR_NOT_SUPPORTED,
    ERROR_NOT_AVAILABLE,
    ERROR_NOT_STARTED,
    ERROR_INVALID_ARGS,
    ERROR_BUSY,
    ERROR_UNKNOWN
} WifiStatusCode;

typedef enum WpaStates {
    WPA_DISCONNECTED = 0,
    WPA_INTERFACE_DISABLED = 1,
    WPA_INACTIVE = 2,
    WPA_SCANNING = 3,
    WPA_AUTHENTICATING = 4,
    WPA_ASSOCIATING = 5,
    WPA_ASSOCIATED = 6,
    WPA_4WAY_HANDSHAKE = 7,
    WPA_GROUP_HANDSHAKE = 8,
    WPA_COMPLETED = 9,
    WPA_UNKNOWN = 10
} WpaStates;

/* Interface Mode */
typedef enum WifiInterfaceMode { WIFI_CLIENT_MODE = 1, WIFI_AP_MODE = 2 } WifiInterfaceMode;

/* chip supported interface combination mode */
typedef enum WifiInterfaceCombMode {
    STA_STA_MODE,
    STA_AP_MODE,
    STA_P2P_MODE,
    STA_NAN_MODE,
    AP_NAN_MODE,
} WifiInterfaceCombMode;

#ifdef __cplusplus
}
#endif
#endif