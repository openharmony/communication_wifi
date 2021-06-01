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
#ifndef OHOS_IDL_IWIFISTRUCT_H
#define OHOS_IDL_IWIFISTRUCT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef char BOOL;
#define TRUE 1
#define FALSE 0

#define WIFI_SSID_LENGTH 128
#define WIFI_BSSID_LENGTH 128
#define WIFI_SCAN_RESULT_ELEMENT_LENGTH 256
#define WIFI_SCAN_RESULT_CAPABILITIES_LENGTH 256
#define WIFI_NETWORK_CONFIG_NAME_LENGTH 64
#define WIFI_NETWORK_CONFIG_VALUE_LENGTH 128
#define WIFI_STATUS_ERROR_MSG_LENGTH 64
#define WIFI_MAC_ADDR_LENGTH 17
#define WIFI_AP_PASSWORD_LENGTH 64
#define WIFI_INTERFACE_NAME_SIZE 32

/* IWifiIface */
/*
 * This is a temporary definition. The empty structure compilation alarm needs
 * to be deleted, affecting other alarms.
 */
typedef struct TagIWifiIface {
    int index;
    int type;
    char name[WIFI_INTERFACE_NAME_SIZE];
    char macAddr[WIFI_MAC_ADDR_LENGTH + 1];
} IWifiIface;

/* IWifiClientIface */
/*
 * This is a temporary definition. The empty structure compilation alarm needs
 * to be deleted, affecting other alarms.
 */
typedef struct TagIWifiClientIface {
    char name[WIFI_INTERFACE_NAME_SIZE];
    int type;
} IWifiClientIface;

/* IWifiApIface */
/*
 * This is a temporary definition. The empty structure compilation alarm needs
 * to be deleted, affecting other alarms.
 */
typedef struct TagIWifiApIface {
    char name[WIFI_INTERFACE_NAME_SIZE];
    int type;
} IWifiApIface;

/* IWifiChip */
/*
 * This is a temporary definition. The empty structure compilation alarm needs
 * to be deleted, affecting other alarms.
 */
typedef struct TagIWifiChip {
    int i;
} IWifiChip;

typedef struct StSupplicantEventCallback {
    void *pInstance;
    void (*onScanNotify)(int32_t result, void *pInstance);
} ISupplicantEventCallback;

typedef struct ScanSettings {
    int freqSize;
    int *freqs;
    int hiddenSsidSize;
    char **hiddenSsid;
    int scanStyle;
} ScanSettings;

typedef struct ScanResult {
    char ssid[WIFI_SSID_LENGTH];
    char bssid[WIFI_BSSID_LENGTH];
    char infoElement[WIFI_SCAN_RESULT_ELEMENT_LENGTH];
    int frequency;
    int signalLevel;
    long timestamp;
    char capability[WIFI_SCAN_RESULT_CAPABILITIES_LENGTH];
    int associated;
} ScanResult;

typedef struct NetworkList {
    int id;
    char ssid[WIFI_SSID_LENGTH];
    char bssid[WIFI_BSSID_LENGTH];
    char flags[WIFI_BSSID_LENGTH];
} NetworkList;

typedef struct PnoScanSettings {
    int scanInterval;
    int minRssi2Dot4Ghz;
    int minRssi5Ghz;
    int freqSize;
    int *freqs;
    int hiddenSsidSize;
    char **hiddenSsid;
    int savedSsidSize;
    char **savedSsid;
} PnoScanSettings;

/* Wifi Network configuration parameter flag */
typedef enum DeviceConfigType {
    DEVICE_CONFIG_SSID = 0,            /* SSID */
    DEVICE_CONFIG_PSK = 1,             /* psk */
    DEVICE_CONFIG_KEYMGMT = 2,         /* key_mgmt，WPA-PSK，WPA-NONE，WPA-EAP */
    DEVICE_CONFIG_PRIORITY = 3,        /* wpaNetwork Priority */
    DEVICE_CONFIG_SCAN_SSID = 4,       /* Set this bit to 1 and deliver it when the hidden network is connected. */
    DEVICE_CONFIG_EAP = 5,             /* EPA mode:/EAP/PEAP */
    DEVICE_CONFIG_IDENTITY = 6,        /* Account name */
    DEVICE_CONFIG_PASSWORD = 7,        /* Account password */
    DEVICE_CONFIG_BSSID = 8,           /* bssid */
    DEVICE_CONFIG_AUTH_ALGORITHMS = 9, /* auth algorithms */
    DEVICE_CONFIG_WEP_KEY_IDX = 10,    /* wep key idx */
    DEVICE_CONFIG_WEP_KEY_0 = 11,
    DEVICE_CONFIG_WEP_KEY_1 = 12,
    DEVICE_CONFIG_WEP_KEY_2 = 13,
    DEVICE_CONFIG_WEP_KEY_3 = 14,
    DEVICE_CONFIG_END_POS, /* Number of network configuration parameters, which is used as the last parameter. */
} DeviceConfigType;

typedef struct NetWorkConfig {
    DeviceConfigType cfgParam;                       /* param */
    char cfgValue[WIFI_NETWORK_CONFIG_VALUE_LENGTH]; /* param value */
} NetWorkConfig;

typedef struct GetWpaNetWorkConfig {
    int networkId;
    char param[WIFI_NETWORK_CONFIG_VALUE_LENGTH];
    char value[WIFI_NETWORK_CONFIG_VALUE_LENGTH];
} GetWpaNetWorkConfig;

/* Supplicant status code */
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

/**
 * Generic structure to return the status of an operation.
 */
typedef struct WifiStatus {
    WifiStatusCode code;
    /**
     * A vendor specific error message from the vendor to provide more
     * information beyond the reason code.
     */
    char description[WIFI_STATUS_ERROR_MSG_LENGTH];
} WifiStatus;

typedef struct WifiWpsParam {
    int anyFlag;
    int multiAp;
    char bssid[WIFI_BSSID_LENGTH];
} WifiWpsParam;

typedef struct WifiRoamCapability {
    int maxBlocklistSize;
    int maxTrustlistSize;
} WifiRoamCapability;

typedef struct HostsapdConfig {
    char ssid[WIFI_SSID_LENGTH];
    int32_t ssidLen;
    char preSharedKey[WIFI_AP_PASSWORD_LENGTH];
    int32_t preSharedKeyLen;
    int32_t securityType;
    int32_t band;
    int32_t channel;
    int32_t maxConn;
} HostsapdConfig;

typedef struct CStationInfo {
    int type;
    char mac[WIFI_MAC_ADDR_LENGTH + 1];
} CStationInfo;

typedef struct IWifiApEventCallback {
    void (*onStaJoinOrLeave)(const CStationInfo *info);
    void (*onApEnableOrDisable)(int event);
} IWifiApEventCallback;

typedef enum WpaStates {
    WPA_DISCONNECTED = 0,
    WPA_INTERFACE_DISABLED = 1,
    WPA_INACTIVE = 2,
    WPA_SCANNING = 3,
    WPA_AUTHENTICATING = 4,
    WPA_ASSOCIATING = 5,
    WPA_ASSOCIATED = 6,
    WPA_4_WAY_HANDSHAKEEE = 7,
    WPA_GROUP_HANDSHAKE = 8,
    WPA_COMPLETED = 9,
    WPA_UNKNOWN = 10
} WpaStates;

typedef enum IfaceType { TYPE_STA, TYPE_AP, TYPE_P2P, TYPE_NAN } IfaceType;

#ifdef __cplusplus
}
#endif
#endif