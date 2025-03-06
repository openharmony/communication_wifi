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

#ifndef CJ_WIFI_FFI_H
#define CJ_WIFI_FFI_H

#include "cj_ffi/cj_common_ffi.h"
#include "ffi_structs.h"

extern "C" {
FFI_EXPORT int32_t FfiWifiIsWifiActive(bool& ret);
FFI_EXPORT WifiScanInfoArr FfiWifiGetScanInfoList(int32_t& ret);
FFI_EXPORT int32_t FfiWifiRemoveCandidateConfig(int32_t id);
FFI_EXPORT int32_t FfiWifiConnectToCandidateConfig(int32_t id);
FFI_EXPORT int32_t FfiWifiGetSignalLevel(int32_t rssi, int32_t band, uint32_t& ret);
FFI_EXPORT int32_t FfiWifiIsConnected(bool& ret);
FFI_EXPORT int32_t FfiWifiIsFeatureSupported(int64_t featureId, bool& ret);
FFI_EXPORT int32_t FfiWifiGetIpInfo(CIpInfo& ret);
FFI_EXPORT int32_t FfiWifiGetIpv6Info(CIpv6Info& ret);
FFI_EXPORT char* FfiWifiGetCountryCode(int32_t& code);
FFI_EXPORT int32_t FfiWifiIsBandTypeSupported(int32_t bandType, bool& ret);
FFI_EXPORT int32_t FfiWifiIsMeteredHotspot(bool& ret);
FFI_EXPORT int32_t FfiWifiRemoveGroup();
FFI_EXPORT int32_t FfiWifiP2pConnect(CWifiP2PConfig& cfg);
FFI_EXPORT int32_t FfiWifiP2pCancelConnect();
FFI_EXPORT int32_t FfiWifiStartDiscoverDevices();
FFI_EXPORT int32_t FfiWifiStopDiscoverDevices();
FFI_EXPORT int32_t FfiWifiGetP2pLinkedInfo(CWifiP2PLinkedInfo& info);
FFI_EXPORT int32_t FfiWifiGetCurrentGroup(CWifiP2PGroupInfo& info);
FFI_EXPORT WifiP2pDeviceArr FfiWifiGetP2pPeerDevices(int32_t& ret);
FFI_EXPORT int32_t FfiWifiGetP2pLocalDevice(CWifiP2pDevice& info);
FFI_EXPORT int32_t FfiWifiCreateGroup(CWifiP2PConfig& cfg);
FFI_EXPORT int32_t FfiWifiGetLinkedInfo(CWifiLinkedInfo& info);
FFI_EXPORT int32_t FfiWifiAddCandidateConfig(CWifiDeviceConfig cfg, int32_t& ret);
FFI_EXPORT WifiDeviceConfigArr FfiWifiGetCandidateConfigs(int32_t& code);
FFI_EXPORT int32_t FfiWifiWifiOn(char* type, void (*callback)());
FFI_EXPORT int32_t FfiWifiWifiOff(char* type);
}

#endif // CJ_WIFI_FFI_H