/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef WIFI_C_HOTSPOT__H
#define WIFI_C_HOTSPOT__H

#define FUZZ_PROJECT_NAME "wifichotspot_fuzzer"

#define MAX_SSID_LEN 33

void IsHotspotDualBandSupportedTest(const uint8_t* data, size_t size);
void SetHotspotConfigTest(const uint8_t* data, size_t size);
void GetHotspotConfigTest(const uint8_t* data, size_t size);
void GetStationListTest(const uint8_t* data, size_t size);
void DisassociateStaTest(const uint8_t* data, size_t size);
void AddTxPowerInfoTest(const uint8_t* data, size_t size);

#endif
