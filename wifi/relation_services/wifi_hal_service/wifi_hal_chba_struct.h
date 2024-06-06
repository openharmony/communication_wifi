/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_HAL_CHBA_STRUCT_H
#define OHOS_WIFI_HAL_CHBA_STRUCT_H

#include "wifi_hal_define.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAC_SIZE 7
#define CHBA_SSID_LEN 32
#define PASSPHRASE_LEN 64
#define BSSID_SIZE MAC_SIZE

typedef enum ChbaSupplicantErrCode {
    CHBA_SUP_ERRCODE_SUCCESS = 0,
    CHBA_SUP_ERRCODE_FAILED = 1,
    CHBA_SUP_ERRCODE_TIMEOUT = 2,
    CHBA_SUP_ERRCODE_PBC_OVERLAP = 3,
    CHBA_SUP_ERRCODE_UNKNOWN = 4,
    CHBA_SUP_ERRCODE_INPUT_ERROR = 5,
    CHBA_SUP_ERRCODE_INVALID = 0XFF,
} ChbaSupplicantErrCode;

typedef struct ChbaConnNotifyInfo {
    int32_t id;
    uint8_t peerAddress[MAC_SIZE];
    int32_t centerFreq20M;
    int32_t centetFreq1;
    int32_t centetFreq2;
    int32_t bandwidth;
    uint32_t expireTime;
} ChbaConnNotifyInfo;

typedef struct ChbaConnectInfo {
    int8_t ssid[CHBA_SSID_LEN + 1];
    int8_t passphrase[PASSPHRASE_LEN + 1];
    uint8_t bssid[BSSID_SIZE];
    int32_t freq;
    int32_t centerFreq1;
    int32_t centerFreq2;
    int32_t bandwidth;
}ChbaConnectInfo;

#ifdef __cplusplus
}
#endif
#endif  // OHOS_WIFI_HAL_CHBA_STRUCT_H