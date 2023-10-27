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

constexpr auto XML_TAG_SECTION_HEADER_NETWORK_LIST = "NetworkList";
constexpr auto XML_TAG_SECTION_HEADER_NETWORK = "Network";
constexpr auto XML_TAG_SECTION_HEADER_WIFI_CONFIGURATION = "WifiConfiguration";
constexpr auto XML_TAG_SECTION_HEADER_NETWORK_STATUS = "NetworkStatus";
constexpr auto XML_TAG_SECTION_HEADER_IP_CONFIGURATION = "IpConfiguration";
constexpr auto XML_TAG_SECTION_HEADER_WIFI_ENTERPRISE_CONFIGURATION = "WifiEnterpriseConfiguration";
constexpr auto XML_TAG_SSID = "SSID";
constexpr auto XML_TAG_BSSID = "BSSID";
constexpr auto XML_TAG_CONFIG_KEY = "ConfigKey";
constexpr auto XML_TAG_PRE_SHARED_KEY = "PreSharedKey";
constexpr auto XML_TAG_ORI_SSID = "OriSsid";
constexpr auto XML_TAG_WEP_KEYS = "WEPKeys";
constexpr auto XML_TAG_WEP_TX_KEY_INDEX = "WEPTxKeyIndex";
constexpr auto XML_TAG_HIDDEN_SSID = "HiddenSSID";
constexpr auto XML_TAG_ALLOWED_KEY_MGMT = "AllowedKeyMgmt";
constexpr auto XML_TAG_RANDOMIZED_MAC_ADDRESS = "RandomizedMacAddress";
constexpr auto XML_TAG_MAC_RANDOMIZATION_SETTING = "MacRandomizationSetting";
constexpr auto XML_TAG_STATUS = "Status";
constexpr auto XML_TAG_IP_ASSIGNMENT = "IpAssignment";
constexpr auto XML_TAG_LINK_ADDRESS = "LinkAddress";
constexpr auto XML_TAG_LINK_PREFIX_LENGTH = "LinkPrefixLength";
constexpr auto XML_TAG_GATEWAY_ADDRESS = "GatewayAddress";
constexpr auto XML_TAG_DNS_SERVER_ADDRESSES = "DNSServers";
constexpr auto XML_TAG_PROXY_SETTINGS = "ProxySettings";
constexpr auto XML_TAG_PROXY_HOST = "ProxyHost";
constexpr auto XML_TAG_PROXY_PORT = "ProxyPort";
constexpr auto XML_TAG_PROXY_PAC_FILE = "ProxyPac";
constexpr auto XML_TAG_PROXY_EXCLUSION_LIST = "ProxyExclusionList";
constexpr auto XML_TAG_SECTION_HEADER_MAC_ADDRESS_MAP = "MacAddressMap";
constexpr auto XML_TAG_MAC_MAP = "MacMapEntry";
constexpr auto XML_TAG_MAC_MAP_PLUS = "MacMapEntryPlus";
constexpr auto XML_TAG_DEFAULT_GW_MAC_ADDRESS = "DefaultGwMacAddress";

constexpr auto IP_DHCP = "DHCP";
constexpr auto IP_STATIC = "STATIC";
constexpr auto PROXY_STATIC = "STATIC";
constexpr auto PROXY_NONE = "NONE";
constexpr auto PROXY_PAC = "PAC";
constexpr auto PROXY_UNASSIGNED = "UNASSIGNED";

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

enum WifiConfigType {
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

const std::unordered_map<std::string, WifiConfigType> g_wifiConfigMap = {
    {XML_TAG_SSID, SSID},
    {XML_TAG_PRE_SHARED_KEY, PRESHAREDKEY},
    {XML_TAG_HIDDEN_SSID, HIDDENSSID},
    {XML_TAG_ALLOWED_KEY_MGMT, ALLOWEDKEYMGMT},
    {XML_TAG_MAC_RANDOMIZATION_SETTING, RANDOMIZATIONSETTING},
    {XML_TAG_RANDOMIZED_MAC_ADDRESS, RANDOMIZEDMACADDRESS},
    {XML_TAG_STATUS, STATUS},
    {XML_TAG_WEP_TX_KEY_INDEX, WEPKEYINDEX},
    {XML_TAG_WEP_KEYS, WEPKEYS},
    {XML_TAG_DEFAULT_GW_MAC_ADDRESS, GWMACADDRESS},
    {XML_TAG_IP_ASSIGNMENT, IPASSIGNMENT},
    {XML_TAG_LINK_ADDRESS, LINKADDRESS},
    {XML_TAG_LINK_PREFIX_LENGTH, PREFIXLENGTH},
    {XML_TAG_GATEWAY_ADDRESS, GATEWAYADDRESS},
    {XML_TAG_DNS_SERVER_ADDRESSES, DNSSERVERADDRESSES},
    {XML_TAG_PROXY_SETTINGS, PROXYSETTINGS},
    {XML_TAG_PROXY_PAC_FILE, PROXYPAC},
    {XML_TAG_PROXY_HOST, PROXYHOST},
    {XML_TAG_PROXY_PORT, PROXYPORT},
    {XML_TAG_PROXY_EXCLUSION_LIST, PROXYEXCLUSIONLIST},
};

enum class NetworkSection {
    WIFI_CONFIGURATION,
    NETWORK_STATUS,
    IP_CONFIGURATION,
    ENTERPRISE_CONFIGURATION,
    UNVALID,
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
    xmlNodePtr GotoNetworkList(xmlNodePtr innode);
    WifiDeviceConfig ParseNetwork(xmlNodePtr innode);
    WifiConfigType GetConfigNameAsInt(xmlNodePtr node);
    NetworkSection GetNodeNameAsInt(xmlNodePtr node);
    WifiDeviceConfig ParseWifiConfig(xmlNodePtr innode);
    WifiIpConfig ParseIpConfig(xmlNodePtr innode);
    ConfigureProxyMethod GetProxyMethod(xmlNodePtr innode);
    WifiProxyConfig ParseProxyConfig(xmlNodePtr innode);
    AssignIpMethod GetIpConfig(xmlNodePtr innode);
    void GetKeyMgmt(xmlNodePtr node, WifiDeviceConfig& wifiConfig);
    OHOS::Wifi::WifiPrivacyConfig GetRandMacSetting(xmlNodePtr node);
    bool HasWepKeys(WifiDeviceConfig wifiConfig);
    void ParseMacMapPlus(xmlNodePtr innode);
    xmlNodePtr GotoMacAddressMap(xmlNodePtr innode);
    void SetMacMap(std::map<std::string, std::string> macMap);
    void ParseWepKeys(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig);
    void ParseStatus(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig);
};
}
}
#endif