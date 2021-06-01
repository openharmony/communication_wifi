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

#ifndef OHOS_WIFI_HAL_STRUCT_H
#define OHOS_WIFI_HAL_STRUCT_H

#include "wifi_hal_define.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WifiChip {
    int chip;
} WifiChip;

typedef struct WifiIface {
    int index;
    int type;
    char name[WIFI_IFACE_NAME_MAXLEN];
    char macAddr[WIFI_MAC_LENGTH + 1];
} WifiIface;

typedef enum ScanStyle {
    SCAN_TYPE_LOW_SPAN = 0,
    SCAN_TYPE_LOW_POWER = 1,
    SCAN_TYPE_HIGH_ACCURACY = 2,
    SCAN_TYPE_INVALID = 0XFF
} ScanStyle;

typedef struct ScanSettings {
    int freqSize;
    int *freqs;
    int hiddenSsidSize;
    char **hiddenSsid;
    ScanStyle scanStyle;
} ScanSettings;

typedef struct ScanResult {
    char bssid[WIFI_BSSID_LENGTH];
    int freq;
    int siglv;
    char flags[WIFI_SCAN_RESULT_CAPABILITY_LENGTH];
    char ssid[WIFI_SSID_LENGTH];
    uint64_t timestamp;
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

typedef struct HostsapdConfig {
    char ssid[WIFI_SSID_LENGTH];
    int32_t ssid_len;
    char preSharedKey[WIFI_AP_PASSWORD_LENGTH];
    int32_t preSharedKey_len;
    int32_t securityType;
    int32_t band;
    int32_t channel;
    int32_t maxConn;
} HostsapdConfig;

typedef struct NetWorkConfig {
    DeviceConfigType cfgParam;                       /* Setting parameters. */
    char cfgValue[WIFI_NETWORK_CONFIG_VALUE_LENGTH];  /* Parameter value. */
} NetWorkConfig;

typedef struct GetNetWorkConfig {
    int networkId;
    char param[WIFI_NETWORK_CONFIG_VALUE_LENGTH];
    char value[WIFI_NETWORK_CONFIG_VALUE_LENGTH];
} GetNetWorkConfig;
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

#ifdef __cplusplus
}
#endif
#endif