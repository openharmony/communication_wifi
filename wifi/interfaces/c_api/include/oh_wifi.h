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

#ifdef __cplusplus
extern "C" {
#endif

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
    WIFI_OPERATION_FAILED = 2501000
} Wifi_ResultCode;

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

#ifdef __cplusplus
}
#endif
/** @} */
#endif // OH_WIFI_H