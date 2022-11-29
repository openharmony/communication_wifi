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

#ifndef WIFI_C_HID2D__H
#define WIFI_C_HID2D__H

#define FUZZ_PROJECT_NAME "wifichid2d_fuzzer"
#define MACLEN 6
#define IPLEN 4
#define DATA_MAX_BYTES 255

void Hid2dRequestGcIpTest(const uint8_t* data, size_t size);
void Hid2dSharedlinkIncreaseTest(void);
void Hid2dSharedlinkDecreaseTest(void);
void Hid2dIsWideBandwidthSupportedTest(void);
void Hid2dCreateGroupTest(const uint8_t* data, size_t size);
void Hid2dRemoveGcGroupTest(const uint8_t* data, size_t size);
void Hid2dConnectTest(const uint8_t* data, size_t size);
void Hid2dConfigIPAddrTest(const uint8_t* data, size_t size);
void Hid2dReleaseIPAddrTest(const uint8_t* data, size_t size);
void Hid2dGetRecommendChannelTest(const uint8_t* data, size_t size);
void Hid2dGetSelfWifiCfgInfoTest(const uint8_t* data, size_t size);
void Hid2dSetPeerWifiCfgInfoTest(const uint8_t* data, size_t size);
void Hid2dSetUpperSceneTest(const uint8_t* data, size_t size);
#endif
