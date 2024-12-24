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
#include "network_status_history_manager.h"
#include "wifi_global_func.h"

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
constexpr auto XML_TAG_VALIDATED_INTERNET_ACCESS = "ValidatedInternetAccess";
constexpr auto XML_TAG_PORTAL_NETWORK = "PORTAL_NETWORK";
constexpr auto XML_TAG_INTERNET_HISTORY = "INTERNET_HISTORY";
constexpr auto XML_TAG_SECTION_HEADER_MAC_ADDRESS_MAP = "MacAddressMap";
constexpr auto XML_TAG_MAC_MAP_PLUS = "MacMapEntryPlus";
constexpr auto IP_DHCP = "DHCP";
constexpr auto IP_STATIC = "STATIC";
constexpr auto PROXY_STATIC = "STATIC";
constexpr auto PROXY_PAC = "PAC";
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
    {XML_TAG_VALIDATED_INTERNET_ACCESS, WifiConfigType::VALIDATEDINTERNETACCESS},
    {XML_TAG_PORTAL_NETWORK, WifiConfigType::PORTALNETWORK},
    {XML_TAG_INTERNET_HISTORY, WifiConfigType::INTERNETHISTORY},
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
            case WifiConfigType::SSID:
                ParseSsid(node, wifiConfig);
                break;
            case WifiConfigType::PRESHAREDKEY:
                ParsePreSharedKey(node, wifiConfig);
                break;
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
            case WifiConfigType::VALIDATEDINTERNETACCESS:
                wifiConfig.noInternetAccess = !GetPrimValue<bool>(node, PrimType::BOOLEAN);
                break;
            case WifiConfigType::PORTALNETWORK:
                wifiConfig.isPortal = GetPrimValue<bool>(node, PrimType::BOOLEAN);
                break;
            case WifiConfigType::INTERNETHISTORY:
                ParseInternetHistory(node, wifiConfig);
                break;
            default:
                break;
        }
    }
    return wifiConfig;
}

void NetworkXmlParser::ParseSsid(xmlNodePtr node, WifiDeviceConfig& wifiConfig)
{
    const int subStrBegin = 1;
    const int quotesCount = 2;
    if (node == nullptr) {
        WIFI_LOGE("ParseSsid node null");
        return;
    }
    std::string ssid = GetStringValue(node);
    if (ssid.length() == 0) {
        WIFI_LOGE("ParseSsid ssid is null");
        return;
    }
    // remove ""
    wifiConfig.ssid = ssid.substr(subStrBegin, ssid.length() - quotesCount);
}

void NetworkXmlParser::ParsePreSharedKey(xmlNodePtr node, WifiDeviceConfig& wifiConfig)
{
    const int subStrBegin = 1;
    const int quotesCount = 2;
    if (node == nullptr) {
        WIFI_LOGE("ParsePreSharedKey node null");
        return;
    }
    std::string preSharedKey = GetStringValue(node);
    if (preSharedKey.length() == 0) {
        WIFI_LOGE("ParsePreSharedKey preSharedKey is null");
        return;
    }
    // remove ""
    wifiConfig.preSharedKey = preSharedKey.substr(subStrBegin, preSharedKey.length() - quotesCount);
    std::string().swap(preSharedKey);
}

void NetworkXmlParser::ParseInternetHistory(xmlNodePtr node, WifiDeviceConfig& wifiConfig)
{
    if (node == nullptr) {
        WIFI_LOGE("ParseInternetHistory node null");
        return;
    }

    const int historyNoInternet = 0;
    const int historyInternet = 1;
    const int historyPortal = 2;
    std::string netHistory = GetStringValue(node);
    std::vector<int> netHistoryVec = SplitStringToIntVector(netHistory, "/");
    for (auto it = netHistoryVec.rbegin(); it != netHistoryVec.rend(); ++it) {
        NetworkStatus netState = NetworkStatus::UNKNOWN;
        if (*it == historyNoInternet) {
            netState = NetworkStatus::NO_INTERNET;
        } else if (*it == historyInternet) {
            netState = NetworkStatus::HAS_INTERNET;
        } else if (*it == historyPortal) {
            netState = NetworkStatus::PORTAL;
        } else {
            continue;
        }
        // 2: Bits occupied by history record
        wifiConfig.networkStatusHistory = wifiConfig.networkStatusHistory << 2;
        wifiConfig.networkStatusHistory += static_cast<unsigned int>(netState);
    }
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
    //@deprecated NETWORK_SELECTION_ENABLED
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
    if (networkNodeList == nullptr) {
        WIFI_LOGE("networkNodeList null");
        return;
    }
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

xmlNodePtr NetworkXmlParser::GotoMacAddressMap(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("GotoMacAddressMap node null");
        return nullptr;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_SECTION_HEADER_MAC_ADDRESS_MAP)) == 0) {
            return node;
        }
    }
    return nullptr;
}

void NetworkXmlParser::ParseMacMapPlus(xmlNodePtr innode)
{
    if (innode == nullptr) {
        WIFI_LOGE("ParseMacMapPlus node null");
        return;
    }
    xmlNodePtr macAddrNode = GotoMacAddressMap(innode);
    if (macAddrNode == nullptr) {
        WIFI_LOGE("ParseMacMapPlus macAddrNode null");
        return;
    }
    for (xmlNodePtr node = macAddrNode->children; node != nullptr; node = node->next) {
        if (GetNameValue(node) == XML_TAG_MAC_MAP_PLUS) {
            std::map<std::string, std::string> macMap = GetStringMapValue(node);
            SetMacByMacMapPlus(macMap);
            FillupMacByConfig();
        }
    }
    WIFI_LOGI("ParseMacMapPlus size[%{public}d]", static_cast<int>(wifiStoreRandomMacs.size()));
}

void NetworkXmlParser::SetMacByMacMapPlus(std::map<std::string, std::string> macMap)
{
    for (auto it = macMap.begin(); it != macMap.end(); ++it) {
        if (!IsRandomMacValid(it->second)) {
            continue;
        }
        bool isExist = false;
        for (auto &item : wifiStoreRandomMacs) {
            if (item.randomMac == it->second) {
                item.fuzzyBssids.insert(it->first);
                isExist = true;
                break;
            }
        }
        if (!isExist) {
            WifiStoreRandomMac wifiStoreRandomMac{};
            // need set default psk for GetRandomMac and AddRandomMac
            wifiStoreRandomMac.keyMgmt = KEY_MGMT_WPA_PSK;
            wifiStoreRandomMac.fuzzyBssids.insert(it->first);
            wifiStoreRandomMac.randomMac = it->second;
            wifiStoreRandomMacs.push_back(wifiStoreRandomMac);
        }
    }
}

void NetworkXmlParser::FillupMacByConfig()
{
    for (auto cfgItem : wifiConfigs) {
        if (!IsRandomMacValid(cfgItem.macAddress)) {
            continue;
        }
        bool isExist = false;
        for (auto &macItem : wifiStoreRandomMacs) {
            if (macItem.randomMac == cfgItem.macAddress) {
                macItem.ssid = cfgItem.ssid;
                macItem.keyMgmt = cfgItem.keyMgmt;
                isExist = true;
                break;
            }
        }
        if (!isExist) {
            WifiStoreRandomMac wifiStoreRandomMac{};
            wifiStoreRandomMac.ssid = cfgItem.ssid;
            wifiStoreRandomMac.keyMgmt = cfgItem.keyMgmt;
            wifiStoreRandomMac.randomMac = cfgItem.macAddress;
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
        ParseMacMapPlus(node);
    }
    return true;
}

void NetworkXmlParser::EnableNetworks()
{
    //@deprecated
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

bool NetworkXmlParser::IsRandomMacValid(const std::string &macAddress)
{
    constexpr size_t macStringLength = 17;
    if (macAddress.empty() || macAddress == DEFAULT_MAC_ADDRESS || macAddress.length() != macStringLength) {
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