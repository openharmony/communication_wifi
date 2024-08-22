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

char *MallocCString(const std::string &origin);

enum class SecTypeCj {
    /** Invalid security type */
    SEC_TYPE_INVALID = 0,
    /** Open */
    SEC_TYPE_OPEN = 1,
    /** Wired Equivalent Privacy (WEP) */
    SEC_TYPE_WEP = 2,
    /** Pre-shared key (PSK) */
    SEC_TYPE_PSK = 3,
    /** Simultaneous Authentication of Equals (SAE) */
    SEC_TYPE_SAE = 4,
    /** EAP authentication. */
    SEC_TYPE_EAP = 5,
    /** SUITE_B_192 192 bit level. */
    SEC_TYPE_EAP_SUITE_B = 6,
#ifdef ENABLE_NAPI_WIFI_MANAGER
    /** Opportunistic Wireless Encryption. */
    SEC_TYPE_OWE = 7,
#endif
    /** WAPI certificate to be specified. */
    SEC_TYPE_WAPI_CERT = 8,
    /** WAPI pre-shared key to be specified. */
    SEC_TYPE_WAPI_PSK = 9,
};

extern "C" {
FFI_EXPORT int32_t FfiWifiIsWifiActive(bool &ret);
FFI_EXPORT WifiScanInfoArr FfiWifiGetScanInfoList(int32_t &ret);
FFI_EXPORT int32_t FfiWifiRemoveCandidateConfig(int32_t id);
FFI_EXPORT int32_t FfiWifiConnectToCandidateConfig(int32_t id);
FFI_EXPORT int32_t FfiWifiGetSignalLevel(int32_t rssi, int32_t band, uint32_t &ret);
FFI_EXPORT int32_t FfiWifiIsConnected(bool &ret);
FFI_EXPORT int32_t FfiWifiIsFeatureSupported(int64_t featureId, bool &ret);
FFI_EXPORT int32_t FfiWifiGetIpInfo(CIpInfo &ret);
FFI_EXPORT int32_t FfiWifiGetIpv6Info(CIpv6Info &ret);
FFI_EXPORT char *FfiWifiGetCountryCode(int32_t &code);
FFI_EXPORT int32_t FfiWifiIsBandTypeSupported(int32_t bandType, bool &ret);
FFI_EXPORT int32_t FfiWifiIsMeteredHotspot(bool &ret);
FFI_EXPORT int32_t FfiWifiRemoveGroup();
FFI_EXPORT int32_t FfiWifiP2pConnect(CWifiP2PConfig &cfg);
FFI_EXPORT int32_t FfiWifiP2pCancelConnect();
FFI_EXPORT int32_t FfiWifiStartDiscoverDevices();
FFI_EXPORT int32_t FfiWifiStopDiscoverDevices();
FFI_EXPORT int32_t FfiWifiGetP2pLinkedInfo(CWifiP2PLinkedInfo &info);
FFI_EXPORT int32_t FfiWifiGetCurrentGroup(CWifiP2PGroupInfo &info);
FFI_EXPORT WifiP2pDeviceArr FfiWifiGetP2pPeerDevices(int32_t &ret);
FFI_EXPORT int32_t FfiWifiGetP2pLocalDevice(CWifiP2pDevice &info);
FFI_EXPORT int32_t FfiWifiCreateGroup(CWifiP2PConfig &cfg);
FFI_EXPORT int32_t FfiWifiGetLinkedInfo(CWifiLinkedInfo &info);
FFI_EXPORT int32_t FfiWifiAddCandidateConfig(CWifiDeviceConfig cfg, int32_t &ret);
FFI_EXPORT WifiDeviceConfigArr FfiWifiGetCandidateConfigs(int32_t &code);
FFI_EXPORT int32_t FfiWifiWifiOn(char *type, void (*callback)());
FFI_EXPORT int32_t FfiWifiWifiOff(char* type);
}

#endif // CJ_WIFI_FFI_H