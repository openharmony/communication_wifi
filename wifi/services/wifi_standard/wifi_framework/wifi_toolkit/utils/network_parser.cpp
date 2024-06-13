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

#include "network_parser.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("NetworkXmlParser");
constexpr auto XML_TAG_MIGRATE_DOCUMENT_HEADER = "WifiConfigStoreData";
constexpr auto XML_TAG_CLONE_DOCUMENT_HEADER = "WifiBackupData";
constexpr auto XML_TAG_SECTION_HEADER_NETWORK_LIST = "NetworkList";
constexpr auto XML_TAG_SECTION_HEADER_NETWORK = "Network";
constexpr auto XML_TAG_SECTION_HEADER_WIFI_CONFIGURATION = "WifiConfiguration";
constexpr auto XML_TAG_SECTION_HEADER_NETWORK_STATUS = "NetworkStatus";
constexpr auto XML_TAG_SECTION_HEADER_IP_CONFIGURATION = "IpConfiguration";
constexpr auto XML_TAG_SECTION_HEADER_WIFI_ENTERPRISE_CONFIGURATION = "WifiEnterpriseConfiguration";
constexpr auto XML_TAG_SSID = "SSID";
constexpr auto XML_TAG_PRE_SHARED_KEY = "PreSharedKey";
constexpr auto XML_TAG_WEP_KEYS = "WEPKeys";
constexpr auto XML_TAG_WEP_TX_KEY_INDEX = "WEPTxKeyIndex";
constexpr auto XML_TAG_HIDDEN_SSID = "HiddenSSID";
constexpr auto XML_TAG_ALLOWED_KEY_MGMT = "AllowedKeyMgmt";
constexpr auto XML_TAG_RANDOMIZED_MAC_ADDRESS = "RandomizedMacAddress";
constexpr auto XML_TAG_MAC_RANDOMIZATION_SETTING = "MacRandomizationSetting";
constexpr auto XML_TAG_STATUS = "SelectionStatus";
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
constexpr auto XML_TAG_DEFAULT_GW_MAC_ADDRESS = "DefaultGwMacAddress";
constexpr auto IP_DHCP = "DHCP";
constexpr auto IP_STATIC = "STATIC";
constexpr auto PROXY_STATIC = "STATIC";
constexpr auto PROXY_PAC = "PAC";
static const std::string DEFAULT_BSSID = "00:00:00:00:00:00";
static const std::string DEFAULT_MAC_ADDRESS = "02:00:00:00:00:00";

const std::unordered_map<std::string, WifiConfigType> g_wifiConfigMap = {
    {XML_TAG_SSID, WifiConfigType::SSID},
    {XML_TAG_PRE_SHARED_KEY, WifiConfigType::PRESHAREDKEY},
    {XML_TAG_HIDDEN_SSID, WifiConfigType::HIDDENSSID},
    {XML_TAG_ALLOWED_KEY_MGMT, WifiConfigType::ALLOWEDKEYMGMT},
    {XML_TAG_MAC_RANDOMIZATION_SETTING, WifiConfigType::RANDOMIZATIONSETTING},
    {XML_TAG_RANDOMIZED_MAC_ADDRESS, WifiConfigType::RANDOMIZEDMACADDRESS},
    {XML_TAG_STATUS, WifiConfigType::STATUS},
    {XML_TAG_WEP_TX_KEY_INDEX, WifiConfigType::WEPKEYINDEX},
    {XML_TAG_WEP_KEYS, WifiConfigType::WEPKEYS},
    {XML_TAG_DEFAULT_GW_MAC_ADDRESS, WifiConfigType::GWMACADDRESS},
    {XML_TAG_IP_ASSIGNMENT, WifiConfigType::IPASSIGNMENT},
    {XML_TAG_LINK_ADDRESS, WifiConfigType::LINKADDRESS},
    {XML_TAG_LINK_PREFIX_LENGTH, WifiConfigType::PREFIXLENGTH},
    {XML_TAG_GATEWAY_ADDRESS, WifiConfigType::GATEWAYADDRESS},
    {XML_TAG_DNS_SERVER_ADDRESSES, WifiConfigType::DNSSERVERADDRESSES},
    {XML_TAG_PROXY_SETTINGS, WifiConfigType::PROXYSETTINGS},
    {XML_TAG_PROXY_PAC_FILE, WifiConfigType::PROXYPAC},
    {XML_TAG_PROXY_HOST, WifiConfigType::PROXYHOST},
    {XML_TAG_PROXY_PORT, WifiConfigType::PROXYPORT},
    {XML_TAG_PROXY_EXCLUSION_LIST, WifiConfigType::PROXYEXCLUSIONLIST},
};

const std::unordered_map<std::string, NetworkSection> g_networkSectionMap = {
    {XML_TAG_SECTION_HEADER_WIFI_CONFIGURATION, NetworkSection::WIFI_CONFIGURATION},
    {XML_TAG_SECTION_HEADER_NETWORK_STATUS, NetworkSection::NETWORK_STATUS},
    {XML_TAG_SECTION_HEADER_IP_CONFIGURATION, NetworkSection::IP_CONFIGURATION},
    {XML_TAG_SECTION_HEADER_WIFI_ENTERPRISE_CONFIGURATION, NetworkSection::ENTERPRISE_CONFIGURATION},
};

AssignIpMethod NetworkXmlParser::GetIpConfig(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("GetIpConfig node null");
        return AssignIpMethod::UNASSIGNED;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetConfigNameAsInt(node) != WifiConfigType::IPASSIGNMENT) {
            continue;
        }
        if (GetStringValue(node) == IP_DHCP) {
            return AssignIpMethod::DHCP;
        } else if (GetStringValue(node) == IP_STATIC) {
            return AssignIpMethod::STATIC;
        }
        break;
    }
    return AssignIpMethod::UNASSIGNED;
}

NetworkXmlParser::~NetworkXmlParser()
{
    wifiConfigs.clear();
    wifiStoreRandomMacs.clear();
}

xmlNodePtr NetworkXmlParser::GotoNetworkList(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("GotoNetworkList node null");
        return nullptr;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_SECTION_HEADER_NETWORK_LIST)) == 0) {
            return node;
        }
    }
    return nullptr;
}

WifiConfigType NetworkXmlParser::GetConfigNameAsInt(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("GetConfigNameAsInt node null");
        return WifiConfigType::UNVALID;
    }
    std::string tagName = GetNameValue(node);
    if (g_wifiConfigMap.find(tagName) != g_wifiConfigMap.end()) {
        return g_wifiConfigMap.at(tagName);
    }
    return WifiConfigType::UNVALID;
}

NetworkSection NetworkXmlParser::GetNodeNameAsInt(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("GetNodeNameAsInt node null");
        return NetworkSection::UNVALID;
    }
    std::string tagName = GetNodeValue(node);
    if (g_networkSectionMap.find(tagName) != g_networkSectionMap.end()) {
        return g_networkSectionMap.at(tagName);
    }
    return NetworkSection::UNVALID;
}

WifiIpConfig NetworkXmlParser::ParseIpConfig(xmlNodePtr innode)
{
    WifiIpConfig ipConfig{};
    if (innode == nullptr) {
        WIFI_LOGE("ParseIpConfig node null");
        return ipConfig;
    }
    ipConfig.assignMethod = GetIpConfig(innode);

    if (ipConfig.assignMethod != AssignIpMethod::STATIC) {
        return ipConfig;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case WifiConfigType::LINKADDRESS: {
                std::string ipAddress = GetStringValue(node);
                ipConfig.staticIpAddress.ipAddress.address.SetIpv4Address(ipAddress);
                break;
            }
            case WifiConfigType::PREFIXLENGTH: {
                ipConfig.staticIpAddress.ipAddress.prefixLength = GetPrimValue<int>(node, PrimType::INT);
                break;
            }
            case WifiConfigType::GATEWAYADDRESS: {
                ipConfig.staticIpAddress.gateway.SetIpv4Address(GetStringValue(node));
                break;
            }
            case WifiConfigType::DNSSERVERADDRESSES: {
                std::vector<std::string> dnsArr = GetStringArrValue(node);
                if (dnsArr.size() == 2) { // 2 dns
                    ipConfig.staticIpAddress.dnsServer1.SetIpv4Address(dnsArr[0]);
                    ipConfig.staticIpAddress.dnsServer2.SetIpv4Address(dnsArr[1]);
                }
                break;
            }
            default: {
                break;
            }
        }
    }
    return ipConfig;
}

ConfigureProxyMethod NetworkXmlParser::GetProxyMethod(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("GetProxyMethod node null");
        return ConfigureProxyMethod::CLOSED;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetConfigNameAsInt(node) != WifiConfigType::PROXYSETTINGS) {
            continue;
        }
        if (GetStringValue(node) == PROXY_STATIC) {
            return ConfigureProxyMethod::MANUALCONFIGUE;
        } else if (GetStringValue(node) == PROXY_PAC) {
            return ConfigureProxyMethod::AUTOCONFIGUE;
        }
        break;
    }
    return ConfigureProxyMethod::CLOSED;
}

WifiProxyConfig NetworkXmlParser::ParseProxyConfig(xmlNodePtr innode)
{
    WifiProxyConfig wifiProxyConfig{};
    if (innode == nullptr) {
        WIFI_LOGE("ParseProxyConfig node null");
        return wifiProxyConfig;
    }
    wifiProxyConfig.configureMethod = GetProxyMethod(innode);
    if (wifiProxyConfig.configureMethod == ConfigureProxyMethod::CLOSED) {
        return wifiProxyConfig;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case WifiConfigType::PROXYPAC:
                wifiProxyConfig.autoProxyConfig.pacWebAddress = GetStringValue(node);
                break;
            case WifiConfigType::PROXYHOST: {
                wifiProxyConfig.manualProxyConfig.serverHostName = GetStringValue(node);
                break;
            }
            case WifiConfigType::PROXYPORT: {
                wifiProxyConfig.manualProxyConfig.serverPort = GetPrimValue<int>(node, PrimType::INT);
                break;
            }
            case WifiConfigType::PROXYEXCLUSIONLIST: {
                wifiProxyConfig.manualProxyConfig.exclusionObjectList = GetStringValue(node);
                break;
            }
            default: {
                break;
            }
        }
    }
    return wifiProxyConfig;
}

bool NetworkXmlParser::HasWepKeys(WifiDeviceConfig wifiConfig)
{
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        if (!wifiConfig.wepKeys[i].empty()) {
            return true;
        }
    }
    return false;
}

void NetworkXmlParser::GetKeyMgmt(xmlNodePtr node, WifiDeviceConfig& wifiConfig)
{
    if (node == nullptr) {
        WIFI_LOGE("GetKeyMgmt node null");
        return;
    }
    std::vector<unsigned char> keyMgmtByte = GetByteArrValue(node);
    if (keyMgmtByte.size() > 4) { // trans byte to int always < 4
        wifiConfig.keyMgmt = "";
        return;
    }
    unsigned int keyMgmtInt = 0;
    for (size_t i = 0; i < keyMgmtByte.size(); i++) {
        keyMgmtInt |= (keyMgmtByte[i] << (8 * i)); // trans byte to int
    }
    if (keyMgmtInt & MGMT_SAE) {
        wifiConfig.keyMgmt = KEY_MGMT_SAE;
    } else if ((keyMgmtInt & MGMT_WPA_PSK) || (keyMgmtInt & MGMT_WPA2_PSK) || (keyMgmtInt & MGMT_FT_PSK)) {
        wifiConfig.keyMgmt = KEY_MGMT_WPA_PSK;
    } else if (keyMgmtInt & MGMT_NONE) {
        if (HasWepKeys(wifiConfig)) {
            wifiConfig.keyMgmt = KEY_MGMT_WEP;
        } else {
            wifiConfig.keyMgmt = KEY_MGMT_NONE;
        }
    } else {
        wifiConfig.keyMgmt = "";
    }
    return;
}

OHOS::Wifi::WifiPrivacyConfig NetworkXmlParser::GetRandMacSetting(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("GetRandMacSetting node null");
        return OHOS::Wifi::WifiPrivacyConfig::RANDOMMAC;
    }
    int randMacSetting = GetPrimValue<int>(node, PrimType::INT);
    if (randMacSetting == 0) {
        return OHOS::Wifi::WifiPrivacyConfig::DEVICEMAC;
    }
    return OHOS::Wifi::WifiPrivacyConfig::RANDOMMAC;
}

WifiDeviceConfig NetworkXmlParser::ParseWifiConfig(xmlNodePtr innode)
{
    WifiDeviceConfig wifiConfig;
    if (innode == nullptr) {
        WIFI_LOGE("ParseWifiConfig node null");
        return wifiConfig;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case WifiConfigType::SSID: {
                std::string ssid = GetStringValue(node);
                wifiConfig.ssid = ssid.substr(1, ssid.length() - 2); // remove ""
                break;
            }
            case WifiConfigType::PRESHAREDKEY: {
                std::string preSharedKey = GetStringValue(node);
                wifiConfig.preSharedKey = preSharedKey.substr(1, preSharedKey.length() - 2); // remove ""
                break;
            }
            case WifiConfigType::GWMACADDRESS: {
                wifiConfig.bssid = GetStringValue(node);
                break;
            }
            case WifiConfigType::HIDDENSSID:
                wifiConfig.hiddenSSID = GetPrimValue<bool>(node, PrimType::BOOLEAN);
                break;
            case WifiConfigType::ALLOWEDKEYMGMT:
                GetKeyMgmt(node, wifiConfig);
                break;
            case WifiConfigType::RANDOMIZATIONSETTING:
                wifiConfig.wifiPrivacySetting = GetRandMacSetting(node);
                break;
            case WifiConfigType::RANDOMIZEDMACADDRESS:
                wifiConfig.macAddress = GetStringValue(node);
                break;
            case WifiConfigType::WEPKEYINDEX:
                wifiConfig.wepTxKeyIndex = GetPrimValue<int>(node, PrimType::INT);
                break;
            case WifiConfigType::WEPKEYS:
                ParseWepKeys(node, wifiConfig);
                break;
            default: {
                break;
            }
        }
    }
    return wifiConfig;
}

void NetworkXmlParser::ParseNetworkStatus(xmlNodePtr innode, WifiDeviceConfig& wifiConfig)
{
    if (innode == nullptr) {
        WIFI_LOGE("ParseWifiConfig node null");
        return;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case WifiConfigType::STATUS: {
                ParseStatus(node, wifiConfig);
                break;
            }
            default: {
                break;
            }
        }
    }
}

void NetworkXmlParser::ParseWepKeys(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig)
{
    if (node == nullptr) {
        WIFI_LOGE("ParseWepKeys node null");
        return;
    }
    std::vector<std::string> wepKeys = GetStringArrValue(node);
    if (wepKeys.size() == WEPKEYS_SIZE) {
        for (size_t i = 0; i < wepKeys.size(); i++) {
            wifiDeviceConfig.wepKeys[i] = wepKeys[i];
        }
    }
}

void NetworkXmlParser::ParseStatus(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig)
{
    if (node == nullptr) {
        WIFI_LOGE("ParseStatus node null");
        return;
    }
    std::string status = GetStringValue(node);
    if (status.compare("NETWORK_SELECTION_ENABLED")) {
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
    } else {
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
    }
}


WifiDeviceConfig NetworkXmlParser::ParseNetwork(xmlNodePtr innode)
{
    WifiDeviceConfig wifiConfig;
    if (innode == nullptr) {
        WIFI_LOGE("ParseNetwork node null");
        return wifiConfig;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetNodeNameAsInt(node)) {
            case NetworkSection::WIFI_CONFIGURATION: {
                wifiConfig = ParseWifiConfig(node);
                break;
            }
            case NetworkSection::NETWORK_STATUS: {
                ParseNetworkStatus(node, wifiConfig);
                break;
            }
            case NetworkSection::IP_CONFIGURATION: {
                wifiConfig.wifiIpConfig = ParseIpConfig(node);
                wifiConfig.wifiProxyconfig = ParseProxyConfig(node);
                break;
            }
            default: {
                break;
            }
        }
    }
    return wifiConfig;
}

void NetworkXmlParser::ParseNetworkList(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("ParseNetworkList node null");
        return;
    }
    xmlNodePtr networkNodeList = GotoNetworkList(innode);
    int xmlSavedNetworkCount = 0;
    for (xmlNodePtr node = networkNodeList->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_SECTION_HEADER_NETWORK)) == 0) {
            xmlSavedNetworkCount++;
            WifiDeviceConfig wifiDeviceConfig = ParseNetwork(node);
            if (IsWifiConfigValid(wifiDeviceConfig)) {
                wifiConfigs.push_back(wifiDeviceConfig);
            }
        }
    }
    WIFI_LOGI("ParseNetwork size=%{public}lu, xml config total size=%{public}d",
        (unsigned long) wifiConfigs.size(), xmlSavedNetworkCount);
}

void NetworkXmlParser::ParseMacMap()
{
    WifiStoreRandomMac wifiStoreRandomMac{};
    for (auto wifiConfig : wifiConfigs) {
        if (IsRandomMacValid(wifiConfig)) {
            wifiStoreRandomMac.ssid = wifiConfig.ssid;
            wifiStoreRandomMac.keyMgmt = wifiConfig.keyMgmt;
            wifiStoreRandomMac.peerBssid = wifiConfig.bssid.empty() ? DEFAULT_BSSID : wifiConfig.bssid;
            wifiStoreRandomMac.randomMac = wifiConfig.macAddress;
            wifiStoreRandomMacs.push_back(wifiStoreRandomMac);
        }
    }
}

NetworkParseType NetworkXmlParser::GetParseType(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("GetParseType node null");
        return NetworkParseType::UNKNOWN;
    }

    if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_MIGRATE_DOCUMENT_HEADER)) == 0) {
        return NetworkParseType::MIGRATE;
    } else if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_CLONE_DOCUMENT_HEADER)) == 0) {
        return NetworkParseType::CLONE;
    }
    return NetworkParseType::UNKNOWN;
}

bool NetworkXmlParser::ParseInternal(xmlNodePtr node)
{
    if (node == nullptr) {
        WIFI_LOGE("ParseInternal node null");
        return false;
    }

    NetworkParseType parseType = GetParseType(node);
    if (parseType == NetworkParseType::UNKNOWN) {
        WIFI_LOGE("ParseInternal Doc invaild");
        return false;
    }
    WIFI_LOGI("ParseInternal parseType: %{public}d.", static_cast<int>(parseType));

    ParseNetworkList(node);
    if (parseType == NetworkParseType::CLONE) {
        // Enable all networks restored and no need to parse randommac.
        EnableNetworks();
    } else if (parseType == NetworkParseType::MIGRATE) {
        ParseMacMap();
    }
    return true;
}

void NetworkXmlParser::EnableNetworks()
{
    for (auto &wifiConfig : wifiConfigs) {
        wifiConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
    }
}

bool NetworkXmlParser::IsWifiConfigValid(WifiDeviceConfig wifiConfig)
{
    if (wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_SAE || wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_NONE
        || wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_WEP || wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_WPA_PSK) {
        return true;
    }
    WIFI_LOGE("invalid wifiConfig: ssid=%{public}s, keyMgmt=%{public}s",
        SsidAnonymize(wifiConfig.ssid).c_str(), wifiConfig.keyMgmt.c_str());
    return false;
}

bool NetworkXmlParser::IsRandomMacValid(WifiDeviceConfig wifiConfig)
{
    if (wifiConfig.macAddress.empty() || wifiConfig.macAddress == DEFAULT_MAC_ADDRESS) {
        return false;
    }
    return true;
}

std::vector<WifiDeviceConfig> NetworkXmlParser::GetNetworks()
{
    return wifiConfigs;
}

std::vector<WifiStoreRandomMac> NetworkXmlParser::GetRandomMacmap()
{
    return wifiStoreRandomMacs;
}
}
}