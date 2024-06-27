/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_WPA_COMMON_TEST_H
#define OHOS_WIFI_WPA_COMMON_TEST_H

#include "wifi_wpa_hal.h"

typedef unsigned char u8;

#ifdef __cplusplus
extern "C" {
#endif

extern WifiWpaInterface *g_wpaInterface;

int Hex2num(char c);
int Hex2byte(const char *hex);
void DealDigital(u8 *buf, const char **pos, size_t *len);
void DealSymbol(u8 *buf, const char **pos, size_t *len);

#ifdef __cplusplus
}
#endif

#endif