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

#ifndef WIFI_FUZZ_HOTSPOT_STUB_H
#define WIFI_FUZZ_HOTSPOT_STUB_H

#define FUZZ_PROJECT_NAME "wifihotspotstub_fuzzer"

enum class IWifiHotspotIpcCode {
    COMMAND_IS_HOTSPOT_ACTIVE = 1,
    COMMAND_IS_HOTSPOT_DUAL_BAND_SUPPORTED,
    COMMAND_IS_OPEN_SOFT_AP_ALLOWED,
    COMMAND_GET_HOTSPOT_CONFIG,
    COMMAND_GET_HOTSPOT_STATE,
    COMMAND_SET_HOTSPOT_CONFIG,
    COMMAND_SET_HOTSPOT_IDLE_TIMEOUT,
    COMMAND_GET_STATION_LIST,
    COMMAND_DISASSOCIATE_STA,
    COMMAND_ENABLE_HOTSPOT,
    COMMAND_DISABLE_HOTSPOT,
    COMMAND_GET_BLOCK_LISTS,
    COMMAND_ADD_BLOCK_LIST,
    COMMAND_DEL_BLOCK_LIST,
    COMMAND_GET_VALID_BANDS,
    COMMAND_GET_VALID_CHANNELS,
    COMMAND_REGISTER_CALL_BACK,
    COMMAND_GET_SUPPORTED_FEATURES,
    COMMAND_GET_SUPPORTED_POWER_MODEL,
    COMMAND_GET_POWER_MODEL,
    COMMAND_SET_POWER_MODEL,
    COMMAND_GET_AP_IFACE_NAME,
    COMMAND_ENABLE_LOCAL_ONLY_HOTSPOT,
    COMMAND_DISABLE_LOCAL_ONLY_HOTSPOT,
    COMMAND_GET_HOTSPOT_MODE,
    COMMAND_GET_LOCAL_ONLY_HOTSPOT_CONFIG,
};

#endif
