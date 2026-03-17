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
 * @kit ConnectivityKit
 * @brief Define interfaces for querying wifi switch status.
 * @library libwifi.so
 * @syscap SystemCapability.Communication.WiFi.STA
 * @since 13
 */

#ifndef OH_WIFI_H
#define OH_WIFI_H

#include <cstdint>

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
 * @brief Enumerates Wi-Fi link types.
 *
 * @since 24
 */
typedef enum OH_WifiLinkType {
    /**
     * @brief Not connected.
     * @since 24
     */
    OH_WIFI_LINK_DISCONNECT = -1,

    /**
     * @brief Default link.
     * @since 24
     */
    OH_WIFI_LINK_DEFAULT_LINK = 0,

    /**
     * @brief Wi-Fi 7 single link.
     * @since 24
     */
    OH_WIFI_LINK_WIFI7_SINGLE_LINK = 1,

    /**
     * @brief Wi-Fi 7 MLSR.
     * @since 24
     */
    OH_WIFI_LINK_WIFI7_MLSR = 2,

    /**
     * @brief Wi-Fi 7 EMLSR.
     * @since 24
     */
    OH_WIFI_LINK_WIFI7_EMLSR = 3,

    /**
     * @brief Wi-Fi 7 STR.
     * @since 24
     */
    OH_WIFI_LINK_WIFI7_STR = 4,

    /**
     * @brief Wi-Fi 7 legacy mode without MLO.
     * @since 24
     */
    OH_WIFI_LINK_WIFI7_LEGACY = 5
} OH_WifiLinkType;

/**
 * @brief Enumerates Wi-Fi connection states.
 *
 * @since 24
 */
typedef enum OH_WifiConnState {
    /**
     * @brief The device is searching for an available AP.
     * @since 24
     */
    OH_WIFI_CONN_SCANNING,

    /**
     * @brief The Wi-Fi connection is being set up.
     * @since 24
     */
    OH_WIFI_CONN_CONNECTING,

    /**
     * @brief The Wi-Fi connection is being authenticated.
     * @since 24
     */
    OH_WIFI_CONN_AUTHENTICATING,

    /**
     * @brief The IP address of the Wi-Fi connection is being obtained.
     * @since 24
     */
    OH_WIFI_CONN_OBTAINING_IPADDR,

    /**
     * @brief The Wi-Fi connection has been set up.
     * @since 24
     */
    OH_WIFI_CONN_CONNECTED,

    /**
     * @brief The Wi-Fi connection is being torn down.
     * @since 24
     */
    OH_WIFI_CONN_DISCONNECTING,

    /**
     * @brief The Wi-Fi connection has been torn down.
     * @since 24
     */
    OH_WIFI_CONN_DISCONNECTED,

    /**
     * @brief The Wi-Fi connection is in a special state.
     * @since 24
     */
    OH_WIFI_CONN_SPECIAL_CONNECT,

    /**
     * @brief Failed to set up the Wi-Fi connection.
     * @since 24
     */
    OH_WIFI_CONN_UNKNOWN
} OH_WifiConnState;

/**
 * @brief Enumerates Wi-Fi channel widths.
 *
 * @since 24
 */
typedef enum OH_WifiChannelWidth {
    /**
     * @brief 20 MHz channel width.
     * @since 24
     */
    OH_WIFI_WIDTH_20MHZ = 0,

    /**
     * @brief 40 MHz channel width.
     * @since 24
     */
    OH_WIFI_WIDTH_40MHZ = 1,

    /**
     * @brief 80 MHz channel width.
     * @since 24
     */
    OH_WIFI_WIDTH_80MHZ = 2,

    /**
     * @brief 160 MHz channel width.
     * @since 24
     */
    OH_WIFI_WIDTH_160MHZ = 3,

    /**
     * @brief 80 + 80 MHz channel width.
     * @since 24
     */
    OH_WIFI_WIDTH_80MHZ_PLUS = 4,

    /**
     * @brief Invalid channel width.
     * @since 24
     */
    OH_WIFI_WIDTH_INVALID
} OH_WifiChannelWidth;

/**
 * @brief Wi-Fi categories.
 *
 * @since 24
 */
typedef enum OH_WifiCategory {
    /**
     * @brief Default category.
     * @since 24
     */
    OH_WIFI_CATEGORY_DEFAULT = 1,

    /**
     * @brief Wi-Fi 6 category.
     * @since 24
     */
    OH_WIFI_CATEGORY_WIFI6 = 2,

    /**
     * @brief Wi-Fi 6 plus category.
     * @since 24
     */
    OH_WIFI_CATEGORY_WIFI6_PLUS = 3,

    /**
     * @brief Wi-Fi 7 category.
     * @since 24
     */
    OH_WIFI_CATEGORY_WIFI7 = 4,

    /**
     * @brief Wi-Fi 7 plus category.
     * @since 24
     */
    OH_WIFI_CATEGORY_WIFI7_PLUS = 5
} OH_WifiCategory;

/**
 * @brief Enumerates Wi-Fi standards.
 *
 * @since 24
 */
typedef enum OH_WifiStandard {
    /**
     * @brief Invalid Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_UNDEFINED = 0,

    /**
     * @brief 802.11a Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11A = 1,

    /**
     * @brief 802.11b Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11B = 2,

    /**
     * @brief 802.11g Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11G = 3,

    /**
     * @brief 802.11n Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11N = 4,

    /**
     * @brief 802.11ac Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11AC = 5,

    /**
     * @brief 802.11ax Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11AX = 6,

    /**
     * @brief 802.11ad Wi-Fi standard.
     * @since 24
     */
    OH_WIFI_STANDARD_11AD = 7
} OH_WifiStandard;

/**
 * @brief Represents the Wi-Fi connection information.
 *
 * This structure describes the hotspot information of the current station connection.
 * The information can be obtained by calling {@link OH_Wifi_GetLinkedInfo}.
 *
 * @since 24
 */
typedef struct {
    /**
     * @brief Service set identifier (SSID).
     *
     * For the length, see {@link WIFI_MAX_SSID_LEN}.
     * @since 24
     */
    char ssid[WIFI_MAX_SSID_LEN];

    /**
     * @brief Basic service set identifier (BSSID).
     * If the application has requested the ohos.permission.GET_WIFI_PEERS_MAC permission, the bssid .\n
     * in the returned result will be the real BSSID address; otherwise, it will be a randomized device address.
     * format: "AA:BB:CC:DD:EE:FF"
     * For the length, see {@link WIFI_MAC_LEN}.
     * @since 24
     */
    char bssid[WIFI_MAC_LEN];

    /**
     * @brief Received signal strength indicator (RSSI).
     * @since 24
     */
    int32_t rssi;

    /**
     * @brief Wi-Fi band information of the hotspot.
     * @since 24
     */
    int32_t band;

    /**
     * @brief Wi-Fi link speed, in Mbps.
     * @since 24
     */
    int32_t linkSpeed;

    /**
     * @brief Downlink speed, in Mbps.
     * @since 24
     */
    int32_t rxLinkSpeed;

    /**
     * @brief Maximum supported TX link speed, in Mbps.
     * @since 24
     */
    int32_t maxSupportedTxLinkSpeed;

    /**
     * @brief Maximum supported RX link speed, in Mbps.
     * @since 24
     */
    int32_t maxSupportedRxLinkSpeed;

    /**
     * @brief Wi-Fi frequency of the hotspot, in MHz.
     * @since 24
     */
    int32_t frequency;

    /**
     * @brief Indicates whether the SSID is hidden.
     * @since 24
     */
    bool isHidden;

    /**
     * @brief Indicates whether data access is restricted.
     * @since 24
     */
    bool isRestricted;

    /**
     * @brief MAC address type.
     * 0 indicates random MAC address; 1 indicates device MAC address
     * @since 24
     */
    int32_t macType;

    /**
     * @brief MAC address of the device.
     * @permission ohos.permission.GET_WIFI_LOCAL_MAC (When macType is 1)
     * format: "AA:BB:CC:DD:EE:FF"
     * For the maximum length, see {@link WIFI_MAC_LEN}.
     * @since 24
     */
    char macAddress[WIFI_MAC_LEN];

    /**
     * @brief IP address of the connected network.
     * @since 24
     */
    uint32_t ipAddress;

    /**
     * @brief Wi-Fi connection state.
     * For details, see {@link OH_WifiConnState}.
     * @since 24
     */
    OH_WifiConnState connState;

    /**
     * @brief Current AP channel width.
     * For details, see {@link OH_WifiChannelWidth}.
     * @since 24
     */
    OH_WifiChannelWidth channelWidth;

    /**
     * @brief Wi-Fi standard.
     * For details, see {@link OH_WifiStandard}.
     * @since 24
     */
    OH_WifiStandard wifiStandard;

    /**
     * @brief Supported Wi-Fi category.
     * For details, see {@link OH_WifiCategory}.
     * @since 24
     */
    OH_WifiCategory supportedWifiCategory;

    /**
     * @brief Indicates whether the network is a HiLink network.
     * @since 24
     */
    bool isHiLinkNetwork;

    /**
     * @brief Wi-Fi link type.
     * For details, see {@link OH_WifiLinkType}.
     * @since 24
     */
    OH_WifiLinkType wifiLinkType;
} OH_WifiLinkedInfo;

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
 * @brief Get wifi linked info. When macType is 1 (device MAC address), obtaining macAddress also requires the\n
 * ohos.permission.GET_WIFI_LOCAL_MAC permission. This permission is available only to system apps in\n
 * API versions 8–15. Starting from API 16, it is available to regular apps on PC/2-in-1 devices, while on other\n
 * devices it remains restricted to system apps. If the permission is not granted, macAddress will be returned\n
 * as empty. If the application has requested the ohos.permission.GET_WIFI_PEERS_MAC permission, the bssid\n
 * in the returned result will be the real BSSID address; otherwise, it will be a randomized device address.\n
 *
 * @param info - the data structure of the Wi-Fi connection information.
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
Wifi_ResultCode OH_Wifi_GetLinkedInfo(OH_WifiLinkedInfo *info);
#ifdef __cplusplus
}
#endif
/** @} */
#endif // OH_WIFI_H