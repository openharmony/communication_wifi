/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef NETWORK_PARSER
#define NETWORK_PARSER
#include "xml_parser.h"
#include <unordered_map>
#include "wifi_msg.h"
#include "wifi_internal_msg.h"

const unsigned int MGMT_NONE = 1 << 0;
const unsigned int MGMT_WPA_PSK = 1 << 1;
const unsigned int MGMT_WPA_EAP = 1 << 2;
const unsigned int MGMT_IEEE8021X = 1 << 3;
const unsigned int MGMT_WPA2_PSK = 1 << 4;
const unsigned int MGMT_OSEN = 1 << 5;
const unsigned int MGMT_FT_PSK = 1 << 6;
const unsigned int MGMT_FT_EAP = 1 << 7;
const unsigned int MGMT_SAE = 1 << 8;
const unsigned int MGMT_OWE = 1 << 9;
const unsigned int MGMT_SUITE_B_192 = 1 << 10;
const unsigned int MGMT_WPA_PSK_SHA256 = 1 << 11;
const unsigned int MGMT_WPA_EAP_SHA256 = 1 << 12;
const unsigned int MGMT_WAPI_PSK = 1 << 13;
const unsigned int MGMT_WAPI_CERT = 1 << 14;
const unsigned int MGMT_FILS_SHA384 = 1 << 15;
const unsigned int MGMT_Q_WAPI_PSK = 1 << 16;
const unsigned int MGMT_Q_WAPI_CERT = 1 << 17;

enum class WifiConfigType {
    SSID = 0,
    PRESHAREDKEY,
    HIDDENSSID,
    ALLOWEDKEYMGMT,
    RANDOMIZATIONSETTING,
    RANDOMIZEDMACADDRESS,
    STATUS,
    WEPKEYINDEX,
    WEPKEYS,
    GWMACADDRESS,
    IPASSIGNMENT,
    LINKADDRESS,
    PREFIXLENGTH,
    GATEWAYADDRESS,
    DNSSERVERADDRESSES,
    PROXYSETTINGS,
    PROXYPAC,
    PROXYHOST,
    PROXYPORT,
    PROXYEXCLUSIONLIST,
    UNVALID,
};

enum class NetworkSection {
    WIFI_CONFIGURATION,
    NETWORK_STATUS,
    IP_CONFIGURATION,
    ENTERPRISE_CONFIGURATION,
    UNVALID,
};

enum class NetworkParseType {
    UNKNOWN,
    MIGRATE,
    CLONE
};

namespace OHOS {
namespace Wifi {
class NetworkXmlParser : public XmlParser {
public:
    NetworkXmlParser() = default;
    ~NetworkXmlParser() override;

    /**
     * @Description get networkconfigs
     *
     * @return std::vector<WifiDeviceConfig> - networkconfigs
    */
    std::vector<WifiDeviceConfig> GetNetworks();

    /**
     * @Description get randommac map
     *
     * @return std::vector<WifiStoreRandomMac> - randommac map
    */
    std::vector<WifiStoreRandomMac> GetRandomMacmap();
private:
    std::vector<WifiDeviceConfig> wifiConfigs{};
    std::vector<WifiStoreRandomMac> wifiStoreRandomMacs{};

    bool ParseInternal(xmlNodePtr node) override;
    void ParseNetworkList(xmlNodePtr innode);
    NetworkParseType GetParseType(xmlNodePtr node);
    void EnableNetworks();
    xmlNodePtr GotoNetworkList(xmlNodePtr innode);
    WifiDeviceConfig ParseNetwork(xmlNodePtr innode);
    WifiConfigType GetConfigNameAsInt(xmlNodePtr node);
    NetworkSection GetNodeNameAsInt(xmlNodePtr node);
    WifiDeviceConfig ParseWifiConfig(xmlNodePtr innode);
    void ParseNetworkStatus(xmlNodePtr node, WifiDeviceConfig& wifiConfig);
    WifiIpConfig ParseIpConfig(xmlNodePtr innode);
    ConfigureProxyMethod GetProxyMethod(xmlNodePtr innode);
    WifiProxyConfig ParseProxyConfig(xmlNodePtr innode);
    AssignIpMethod GetIpConfig(xmlNodePtr innode);
    void GetKeyMgmt(xmlNodePtr node, WifiDeviceConfig& wifiConfig);
    OHOS::Wifi::WifiPrivacyConfig GetRandMacSetting(xmlNodePtr node);
    bool HasWepKeys(WifiDeviceConfig wifiConfig);
    void ParseMacMap();
    void ParseWepKeys(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig);
    void ParseStatus(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig);
    bool IsWifiConfigValid(WifiDeviceConfig wifiConfig);
    bool IsRandomMacValid(WifiDeviceConfig wifiConfig);
};
}
}
#endif