/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Wifi
 * @{
 *
 * @brief Provide functions for querying the status of wifi switch.
 * @since 13
 */
/**
 * @file oh_wifi.h
 * @brief Define interfaces for querying wifi switch status.
 * @kit ConnectivityKit
 * @library libwifi_ndk.so
 * @syscap SystemCapability.Communication.WiFi.STA
 * @since 13
 */

#ifndef OH_WIFI_H
#define OH_WIFI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates the maximum length of a Wi-Fi SSID.
 * @since 24
 * The maximum length is 32, and the last bit is reserved and set to <b>\0</b>. \n
 */
#define WIFI_MAX_SSID_LEN 33 // 32 + \0
/**
 * @brief Indicates the maximum length of a Wi-Fi MAC address or a Wi-Fi BSSID.
 * @since 24
 */
#define WIFI_MAC_LEN 18

/**
 * @brief Enumerates the wifi result codes.
 *
 * @since 13
 */
typedef enum Wifi_ResultCode {
    /**
     * @error The operation is successful.
     */
    WIFI_SUCCESS = 0,
    /**
     * @error Permission verification failed. The application does not have the
     * permission required to call the API.
     */
    WIFI_PERMISSION_DENIED = 201,
    /**
     * @error Parameter error. Possible reasons: 1. The input parameter is a null pointer;\n
     * 2. Parameter values exceed the defined range.\n
     */
    WIFI_INVALID_PARAM = 401,
    /**
     * @error Capability not supported. Failed to call function due to limited device capabilities.
     */
    WIFI_NOT_SUPPORTED = 801,
    /**
     * @error Operation failed.
     * Possible reasons: Internal execution failed.
     */
    WIFI_OPERATION_FAILED = 2501000,
    /**
     * @error Wi-Fi STA disabled.
     * @since 21
     */
    WIFI_STA_DISABLED = 2501001
} Wifi_ResultCode;

/**
 * @brief Enumerates Wi-Fi connection states.
 *
 * @since 24
 */
typedef enum {
    /** Not disconnert */
    DISCONNECT = -1, 
    /** Default link */
    DEFAULT_LINK = 0,
    /** WiFi 7 single link */
    WIFI7_SINGLE_LINK = 1,
    /** WiFi 7 MLSR */
    WIFI7_MLSR = 2,
    /** WiFi 7 EMLSR */
    WIFI7_EMLSR = 3,
    /** WiFi 7 STR */
    WIFI7_STR = 4,
    /** WiFi 7 not MLO */
    WIFI7_LEGACY = 5
} OHWifiLinkType;
 
/**
 * @brief Enumerates Wi-Fi connection states.
 *
 * @since 24
 */
typedef enum {
    /** The device is searching for an available AP. */
    WIFI_CONN_SCANNING,
    /** The Wi-Fi connection is being set up. */
    WIFI_CONN_CONNECTING,
    /** The Wi-Fi connection is being authenticated. */
    WIFI_CONN_AUTHENTICATING,
    /** The IP address of the Wi-Fi connection is being obtained. */
    WIFI_CONN_OBTAINING_IPADDR,
    /** The Wi-Fi connection has been set up. */
    WIFI_CONN_CONNECTED,
    /** The Wi-Fi connection is being torn down. */
    WIFI_CONN_DISCONNECTING,
    /** The Wi-Fi connection has been torn down. */
    WIFI_CONN_DISCONNECTED,
    /** The Wi-Fi special connection. */
    WIFI_CONN_SPECIAL_CONNECT,
    /** Failed to set up the Wi-Fi connection. */
    WIFI_CONN_UNKNOWN
} OHWifiConnState;
 
/**
 * @brief Enumerates Wi-Fi supplicant state.
 *
 * @since 24
 */
typedef enum {
    /** The Wi-Fi disconnected. */
    WIFI_SUPP_DISCONNECTED = 0,
    /** The Wi-Fi interface disabled. */
    WIFI_SUPP_INTERFACE_DISABLED = 1,
    /** The Wi-Fi inactive. */
    WIFI_SUPP_INACTIVE = 2,
    /** The Wi-Fi scanning. */
    WIFI_SUPP_SCANNING = 3,
    /** The Wi-Fi authenticating. */
    WIFI_SUPP_AUTHENTICATING = 4,
    /** The Wi-Fi associating. */
    WIFI_SUPP_ASSOCIATING = 5,
    /** The Wi-Fi associated. */
    WIFI_SUPP_ASSOCIATED = 6,
    /** The Wi-Fi four way handshake. */
    WIFI_SUPP_FOUR_WAY_HANDSHAKE = 7,
    /** The Wi-Fi group handshake. */
    WIFI_SUPP_GROUP_HANDSHAKE = 8,
    /** The Wi-Fi completed. */
    WIFI_SUPP_COMPLETED = 9,
    /** The Wi-Fi unknow. */
    WIFI_SUPP_UNKNOWN = 10,
    /** The Wi-Fi invalid. */
    WIFI_SUPP_INVALID = 0xFF,
} OHWifiSupplicantState;
 
/**
 * @brief Enumerates detailed Wi-Fi connection states.
 *
 * @since 24
 */
typedef enum {
    /** Authentication is in progress. */
    WIFI_DETAIL_AUTHENTICATING = 0,
    /** Connection is blocked by policy or temporary restrictions. */
    WIFI_DETAIL_BLOCKED = 1,
    /** Captive portal detection/check is in progress. */
    WIFI_DETAIL_CAPTIVE_PORTAL_CHECK = 2,
    /** Link is connected. */
    WIFI_DETAIL_CONNECTED = 3,
    /** Connection setup is in progress. */
    WIFI_DETAIL_CONNECTING = 4,
    /** Link is disconnected. */
    WIFI_DETAIL_DISCONNECTED = 5,
    /** Disconnection is in progress. */
    WIFI_DETAIL_DISCONNECTING = 6,
    /** Connection failed (generic failure state). */
    WIFI_DETAIL_FAILED = 7,
    /** Wi-Fi is idle (no active connection attempt). */
    WIFI_DETAIL_IDLE = 8,
    /** IP address acquisition is in progress (typically DHCP). */
    WIFI_DETAIL_OBTAINING_IPADDR = 9,
    /** Network is working and reachable. */
    WIFI_DETAIL_WORKING = 10,
    /** Network is not working/reachable. */
    WIFI_DETAIL_NOTWORKING = 11,
    /** Wi-Fi scan is in progress. */
    WIFI_DETAIL_SCANNING = 12,
    /** Connection is suspended. */
    WIFI_DETAIL_SUSPENDED = 13,
    /** Poor link verification is in progress. */
    WIFI_DETAIL_VERIFYING_POOR_LINK = 14,
    /** Password is incorrect. */
    WIFI_DETAIL_PASSWORD_ERROR = 15,
    /** Connection request is rejected by the AP. */
    WIFI_DETAIL_CONNECTION_REJECT = 16,
    /** AP cannot accept more clients (connection full). */
    WIFI_DETAIL_CONNECTION_FULL = 17,
    /** Connection attempt timed out. */
    WIFI_DETAIL_CONNECTION_TIMEOUT = 18,
    /** Failed to obtain an IP address. */
    WIFI_DETAIL_OBTAINING_IPADDR_FAIL = 19,
    /** Invalid or unknown state. */
    WIFI_DETAIL_INVALID = 0xFF,
} OHWifiDetailedState;
 
/**
 * @brief Enumerates Wi-Fi channel widths.
 *
 * @since 24
 */
typedef enum {
    /** 20 MHz channel width. */
    WIDTH_20MHZ = 0,
    /** 40 MHz channel width. */
    WIDTH_40MHZ = 1,
    /** 80 MHz channel width. */
    WIDTH_80MHZ = 2,
    /** 160 MHz channel width. */
    WIDTH_160MHZ = 3,
    /** 80+80 MHz channel width (non-contiguous). */
    WIDTH_80MHZ_PLUS = 4,
    /** Invalid channel width. */
    WIDTH_INVALID
} OHWifiChannelWidth;
/**
 * @brief Enumerates Wi-Fi categories.
 *
 * @since 24
 */
typedef enum {
    /** Default category. */
    CATEGORY_DEFAULT = 1,
    /** Wi-Fi 6 category. */
    CATEGORY_WIFI6 = 2,
    /** Wi-Fi 6 enhanced category. */
    CATEGORY_WIFI6_PLUS = 3,
    /** Wi-Fi 7 category. */
    CATEGORY_WIFI7 = 4,
    /** Wi-Fi 7 enhanced category. */
    CATEGORY_WIFI7_PLUS = 5
} OHWifiCategory;
/**
 * @brief Represents the Wi-Fi connection information.
 *
 * This refers to the information about the hotspot connected to this station. The information is obtained using
 * {@link GetLinkedInfo}.
 *
 * @since 24
 */
typedef struct {
    /** Service set ID (SSID). For its length, see {@link WIFI_MAX_SSID_LEN}. */
    char ssid[WIFI_MAX_SSID_LEN];
    /** Basic service set ID (BSSID). For its length, see {@link WIFI_MAC_LEN}. */
    char bssid[WIFI_MAC_LEN];
    /** MAC address of the connected hotspot */
    char macAddress[WIFI_MAC_LEN];
    /** Received signal strength indicator (RSSI) */
    int rssi;
    /** Wi-Fi band information of hotspot */
    int band;
    /** Wi-Fi link speed (units: Mbps) */
    int linkSpeed;
    /** Wi-Fi frequency information of hotspot */
    int frequency;
    /** MAC address type */
    int macType;
    /** Wi-Fi connection state, which is defined in {@link OHWiFiConnState} */
    OHWifiConnState connState;
    /** Whether the SSID is hidden */
    int ifHiddenSSID;
    /** Whether data is restricted */
    int isDataRestricted;
    /** Supplicant state, defined in {@link OHWiFiSupplicantState} */
    OHWifiSupplicantState supplicantState;
    /** Detailed connection state, defined in {@link OHWiFiDetailedState} */
    OHWifiDetailedState detailedState;
    /** Wi-Fi link type, defined in {@link OHWiFiLinkType} */
    OHWifiLinkType wifiLinkType;
    /** Wi-Fi standard */
    int wifiStandard;
    /** Maximum supported RX link speed */
    int maxSupportedRxLinkSpeed;
    /** Maximum supported TX link speed */
    int maxSupportedTxLinkSpeed;
    /** Downstream network speed */
    int rxLinkSpeed;
    /** Current AP channel width */
    OHWifiChannelWidth channelWidth;
    /** Supported Wi-Fi category, defined in {@link WifiCategory} */
    OHWifiCategory supportedWifiCategory;
    /** Whether is HiLink network */
    int isHiLinkNetwork;
    /** IP address of the connected network */
    unsigned int ipAddress;
} OHWifiLinkedInfo;

/**
 * @brief Check whether the wifi switch is enabled.
 *
 * @param enabled - It is a boolean pointer used to receive wifi switch status values.\n
 * Equal to true indicates that the wifi switch is turned on, false indicates that\n
 * the wifi switch is turned off.\n
 * The caller needs to pass in a non empty boolean pointer, otherwise an error will be returned.\n
 * @return wifi functions result code.\n
 *     For a detailed definition, please refer to {@link Wifi_ResultCode}.\n
 *     {@link WIFI_SUCCESS} Successfully obtained the wifi switch status.\n
 *     {@link WIFI_INVALID_PARAM} The input parameter enabled is a null pointer.\n
 *     {@link WIFI_OPERATION_FAILED} Internal execution failed.\n
 * @since 13
 */
Wifi_ResultCode OH_Wifi_IsWifiEnabled(bool *enabled);

/**
 * @brief Get the device Mac address.
 *
 * @param macAddr - The character array of device Mac address terminated using '\0'.
 * @param macAddrLen - The size of the memory allocated for the macAddr character array.
 * @permission ohos.permission.GET_WIFI_LOCAL_MAC and ohos.permission.GET_WIFI_INFO.
 * @return wifi functions result code.
 *     For a detailed definition, please refer to {@link Wifi_ResultCode}.
 *     {@link WIFI_SUCCESS} Successfully obtained the device Mac address.
 *     {@link WIFI_PERMISSION_DENIED} Permission denied.
 *     {@link WIFI_NOT_SUPPORTED} Capability not supported.
 *     {@link WIFI_INVALID_PARAM} The input parameter macAddr is a null pointer.
 *     {@link WIFI_OPERATION_FAILED} Internal execution failed.
 *     {@link WIFI_STA_DISABLED} Wi-Fi STA disabled.
 * @since 21
 */
Wifi_ResultCode OH_Wifi_GetDeviceMacAddress(char *macAddr, unsigned int *macAddrLen);

/**
 * @brief Get wifi linked info.
 *
 * @param info - the data structure and macro of the Wi-Fi connection information.
 * @permission ohos.permission.GET_WIFI_INFO.
 * @return wifi functions result code.
 *     For a detailed definition, please refer to {@link Wifi_ResultCode}.
 *     {@link WIFI_SUCCESS} Successfully obtained the wifi linked info.
 *     {@link WIFI_PERMISSION_DENIED} Permission denied.
 *     {@link WIFI_NOT_SUPPORTED} Capability not supported.
 *     {@link WIFI_INVALID_PARAM} The input parameter info is a null pointer.
 *     {@link WIFI_OPERATION_FAILED} Internal execution failed.
 * @since 24
 */
Wifi_ResultCode OH_Wifi_GetLinkedInfo(OHWifiLinkedInfo *info);
#ifdef __cplusplus
}
#endif
/** @} */
#endif // OH_WIFI_H
