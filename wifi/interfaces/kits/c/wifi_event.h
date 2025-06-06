/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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
 * @file wifi_event.h
 *
 * @brief Defines callbacks and structure of Wi-Fi events.
 *
 * {@link RegisterWifiEvent} can be used to listen for Wi-Fi connection, disconnection, and scan events. \n
 *
 * @since 7
 */
#ifndef WIFI_EVENT_C_H
#define WIFI_EVENT_C_H

#include "wifi_linked_info.h"
#include "station_info.h"
#include "wifi_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates that the Wi-Fi station mode is enabled.
 *
 */
#define WIFI_STA_ACTIVE 1
/**
 * @brief Indicates that the Wi-Fi station mode is disabled.
 *
 */
#define WIFI_STA_NOT_ACTIVE 0

/**
 * @brief Indicates that the Wi-Fi hotspot mode is enabled.
 *
 */
#define WIFI_HOTSPOT_ACTIVE 1
/**
 * @brief Indicates that the Wi-Fi hotspot mode is disabled.
 *
 */
#define WIFI_HOTSPOT_NOT_ACTIVE 0

/**
 * @brief Indicates the maximum number of event listeners that can be registered using {@link RegisterWifiEvent}.
 *
 * When the maximum number is reached, you need to unregister at least one listener before registering new ones. \n
 */
#define WIFI_MAX_EVENT_SIZE 10

/**
 * @brief Enumerates of device configuration change.
 *
 * @since 9
 */
typedef enum {
    CONFIG_ADD = 0,
    CONFIG_UPDATE = 1,
    CONFIG_REMOVE = 2,
} ConfigChange;

/**
 * @brief Represents the pointer to a Wi-Fi event callback for station and hotspot connection, disconnection, or scan.
 *
 *
 * If you do not need a callback, set the value of its pointer to <b>NULL</b>. \n
 *
 * @since 7
 */
typedef struct {
    /** Connection state change */
    void (*OnWifiConnectionChanged)(int state, WifiLinkedInfo *info);
    /** Scan state change */
    void (*OnWifiScanStateChanged)(int state, int size);
    /** Hotspot state change */
    void (*OnHotspotStateChanged)(int state);
    /** Station connected */
    void (*OnHotspotStaJoin)(StationInfo *info);
    /** Station disconnected */
    void (*OnHotspotStaLeave)(StationInfo *info);
    /** Device config change */
    void (*OnDeviceConfigChange)(ConfigChange state);
} WifiEvent;

typedef enum {
    /* Default reason */
    DISC_REASON_DEFAULT = 0,

    /* Password is wrong */
    DISC_REASON_WRONG_PWD = 1,

    /* The number of router's connection reaches the maximum number limit */
    DISC_REASON_CONNECTION_FULL = 2,

    /* Connection Rejected */
    DISC_REASON_CONNECTION_REJECTED = 3,

    /* Connect mdm blocklist wifi is fail*/
    DISC_REASON_CONNECTION_MDM_BLOCKLIST_FAIL = 5,

    /* Connect fail reason max value, add new reason before this*/
    DISC_REASON_MAX_VALUE
} DisconnectedReason;

#ifdef __cplusplus
}
#endif

#endif // WIFI_EVENT_C_H
/** @} */
