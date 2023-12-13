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
#ifndef OHOS_WIFI_HDI_AP_IMPL_H
#define OHOS_WIFI_HDI_AP_IMPL_H

#include "wifi_hdi_define.h"
#include "wifi_error_no.h"

#ifdef __cplusplus
extern "C" {
#endif
WifiErrorNo HdiGetFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id);
WifiErrorNo HdiWifiSetPowerModel(const int mode, int id);
WifiErrorNo HdiWifiGetPowerModel(int* mode, int id);
WifiErrorNo HdiWifiSetCountryCode(const char* code, int id);
#ifdef __cplusplus
}
#endif
#endif
#endif
