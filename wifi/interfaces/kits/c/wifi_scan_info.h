/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
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
 * @addtogroup wifiservice
 * @{
 *
 * @brief Provides functions for the Wi-Fi station and hotspot modes.
 *
 * You can use this module to enable and disable the Wi-Fi station or hotspot mode, connect to and disconnect from a
 * station or hotspot, query the station or hotspot status, and listen for events. \n
 *
 * @since 7
 */

/**
 * @file wifi_scan_info.h
 *
 * @brief Defines the data structure and macro of the Wi-Fi scan result information.
 *
 * @since 7
 */

#ifndef WIFI_SCAN_INFO_C_H
#define WIFI_SCAN_INFO_C_H

#include <stdint.h>
#include "wifi_device_config.h"

/**
 * @brief Indicates the maximum number of hotspots that can be detected in a Wi-Fi scan.
 */
#define WIFI_SCAN_HOTSPOT_LIMIT 128

typedef enum {
    WIDTH_20MHZ = 0,
    WIDTH_40MHZ = 1,
    WIDTH_80MHZ = 2,
    WIDTH_160MHZ = 3,
    WIDTH_80MHZ_PLUS = 4,
    WIDTH_INVALID
} WifiChannelWidth;

/**
 * @brief Represents the Wi-Fi scan result information.
 *
 * @since 7
 */
typedef struct {
    /** Service set ID (SSID). For its length, see {@link WIFI_MAX_SSID_LEN}. */
    char ssid[WIFI_MAX_SSID_LEN];
    /** Basic service set ID (BSSID). For its length, see {@link WIFI_MAC_LEN}. */
    unsigned char bssid[WIFI_MAC_LEN];
    /** Security type. For details, see {@link WifiSecurityType}. */
    int securityType;
    /** Received signal strength indicator (RSSI) */
    int rssi;
    /** Frequency band */
    int band;
    /** Frequency in MHz */
    int frequency;
    /** Wifi channel width. For details, see {@link WifiChannelWidth}. */
    WifiChannelWidth channelWidth;
    /** Center frequency in MHz */
    int centerFrequency0;
    /** Center frequency in MHz */
    int centerFrequency1;
    /** Time stamp */
    int64_t timestamp;
} WifiScanInfo;

#endif // WIFI_SCAN_INFO_C_H
/** @} */
