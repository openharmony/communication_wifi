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
#ifdef HDI_INTERFACE_SUPPORT
#ifndef OHOS_HDI_UTIL_H
#define OHOS_HDI_UTIL_H

#include "wifi_hdi_define.h"
#include "wifi_hdi_struct.h"
#include "wifi_hdi_common.h"
#include "v1_1/wlan_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int Get80211ElemsFromIE(const uint8_t *start, size_t len, struct HdiElems *elems,
    int show);

int GetScanResultText(const struct HdfWifiScanResultExt *scanResults,
    struct HdiElems *elems, char* buff, int buffLen);

#ifdef __cplusplus
}
#endif
#endif
#endif