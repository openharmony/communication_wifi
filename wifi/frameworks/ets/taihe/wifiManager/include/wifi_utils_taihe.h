/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_UTILS_TAIHE_H_
#define WIFI_UTILS_TAIHE_H_

#include "ohos.wifiManager.proj.hpp"
#include "ohos.wifiManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include <string>
#include "wifi_msg.h"
#include "wifi_ap_msg.h"
#include "wifi_p2p_msg.h"
namespace OHOS {
namespace Wifi {

enum class SecTypeTaihe {
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
    /** Opportunistic Wireless Encryption. */
    SEC_TYPE_OWE = 7,
    /** WAPI certificate to be specified. */
    SEC_TYPE_WAPI_CERT = 8,
    /** WAPI pre-shared key to be specified. */
    SEC_TYPE_WAPI_PSK = 9,
};

enum class IpTypeTaihe {
    /** Use statically configured IP settings */
    IP_TYPE_STATIC,
    /** Use dynamically configured IP settings */
    IP_TYPE_DHCP,
    /** No IP details are assigned */
    IP_TYPE_UNKNOWN,
};

::ohos::wifiManager::WifiProxyConfig MakeWifiProxyConfig(const WifiProxyConfig& proxyConfig);
::ohos::wifiManager::WifiEapConfig MakeWifiEapConfig(const WifiEapConfig& wifiEapConfig);
SecTypeTaihe ConvertKeyMgmtToSecType(const std::string& keyMgmt);
::ohos::wifiManager::IpConfig MakeIpConfig(const WifiIpConfig& wifiIpConfig);
::ohos::wifiManager::WifiWapiConfig MakeWifiWapiConfig(const WifiWapiConfig& wifiWapiConfig);
::ohos::wifiManager::WifiDeviceConfig MakeWifiDeviceConfig(const WifiDeviceConfig& wifiDeviceConfig);
void ConvertEncryptionMode(const SecTypeTaihe& securityType, std::string& keyMgmt);
void ProcessPassphrase(const SecTypeTaihe& securityType, WifiDeviceConfig& cppConfig);
void ConfigStaticIpv4(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& cppConfig);
void ProcessEapConfig(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& devConfig);
void ProcessWapiConfig(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& devConfig);
WifiDeviceConfig ConvertWifiDeviceConfig(const ::ohos::wifiManager::WifiDeviceConfig &config);
::ohos::wifiManager::WifiInfoElem MakeWifiInfoElem(const WifiInfoElem& wifiInfoElem);
::ohos::wifiManager::WifiScanInfo MakeWifiScanInfo(const WifiScanInfo& scanInfo);
::ohos::wifiManager::WifiLinkedInfo MakeWifiLinkedInfo(const WifiLinkedInfo& linkedInfo);
::ohos::wifiManager::IpInfo MakeIpInfo(const IpInfo& ipInfo);
::ohos::wifiManager::Ipv6Info MakeIpv6Info(const IpV6Info& ipInfo);
::ohos::wifiManager::StationInfo MakeStationInfo(const StationInfo& stationInfo);
StationInfo ConvertStationInfo(::ohos::wifiManager::StationInfo const& stationInfo);
int GetSecurityTypeFromKeyMgmt(KeyMgmt keyMgmt);
::ohos::wifiManager::HotspotConfig MakeHotspotConfig(const HotspotConfig& cppConfig);
::ohos::wifiManager::WifiP2pLinkedInfo MakeWifiP2pLinkedInfo(const WifiP2pLinkedInfo& linkedInfo);
::ohos::wifiManager::WifiP2pDevice MakeWifiP2pDevice(const WifiP2pDevice& device);
WifiP2pConfig ConvertWifiP2pConfig(const ::ohos::wifiManager::WifiP2PConfig &config);
bool IsSecTypeSupported(int secType);
KeyMgmt GetKeyMgmtFromJsSecurityType(int secType);
HotspotConfig ConvertHotspotConfig(const ::ohos::wifiManager::HotspotConfig &config);
::ohos::wifiManager::WifiP2pGroupInfo MakeWifiP2pGroupInfo(const WifiP2pGroupInfo& groupInfo);
}  // namespace Wifi
}  // namespace OHOS

#endif