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

DEFINE_WIFILOG_LABEL("NetworkXmlParser");
namespace OHOS {
namespace Wifi {
AssignIpMethod NetworkXmlParser::GetIpConfig(xmlNodePtr innode)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetConfigNameAsInt(node) == WifiConfigType::IPASSIGNMENT) {
            if (GetStringValue(node) == IP_DHCP) {
                return AssignIpMethod::DHCP;
            } else if (GetStringValue(node) == IP_STATIC) {
                return AssignIpMethod::STATIC;
            }
            break;
        }
    }
    return AssignIpMethod::UNASSIGNED;
}

NetworkXmlParser::~NetworkXmlParser()
{
    wifiConfigs.clear();
}

xmlNodePtr NetworkXmlParser::GotoNetworkList(xmlNodePtr innode)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_SECTION_HEADER_NETWORK_LIST)) == 0) {
            return node;
        }
    }
    return nullptr;
}

WifiConfigType NetworkXmlParser::GetConfigNameAsInt(xmlNodePtr node)
{
    std::string tagName = GetNameValue(node);
    if (g_wifiConfigMap.find(tagName) != g_wifiConfigMap.end()) {
        return g_wifiConfigMap.at(tagName);
    }
    return WifiConfigType::UNVALID;
}

NetworkSection NetworkXmlParser::GetNodeNameAsInt(xmlNodePtr node)
{
    std::string tagName = GetNodeValue(node);
    if (tagName == XML_TAG_SECTION_HEADER_WIFI_CONFIGURATION) {
        return NetworkSection::WIFI_CONFIGURATION;
    } else if (tagName == XML_TAG_SECTION_HEADER_NETWORK_STATUS) {
        return NetworkSection::NETWORK_STATUS;
    } else if (tagName == XML_TAG_SECTION_HEADER_IP_CONFIGURATION) {
        return NetworkSection::IP_CONFIGURATION;
    } else if (tagName == XML_TAG_SECTION_HEADER_WIFI_ENTERPRISE_CONFIGURATION) {
        return NetworkSection::ENTERPRISE_CONFIGURATION;
    } else {
        return NetworkSection::UNVALID;
    }
}

WifiIpConfig NetworkXmlParser::ParseIpConfig(xmlNodePtr innode)
{
    WifiIpConfig ipConfig{};
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
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (GetConfigNameAsInt(node) == WifiConfigType::PROXYSETTINGS) {
            if (GetStringValue(node) == PROXY_STATIC) {
                return ConfigureProxyMethod::MANUALCONFIGUE;
            } else if (GetStringValue(node) == PROXY_PAC) {
                return ConfigureProxyMethod::AUTOCONFIGUE;
            }
            break;
        }
    }
    return ConfigureProxyMethod::CLOSED;
}

WifiProxyConfig NetworkXmlParser::ParseProxyConfig(xmlNodePtr innode)
{
    WifiProxyConfig wifiProxyConfig{};
    wifiProxyConfig.configureMethod = GetProxyMethod(innode);
    if (wifiProxyConfig.configureMethod == ConfigureProxyMethod::CLOSED) {
        return wifiProxyConfig;
    }
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetConfigNameAsInt(node)) {
            case WifiConfigType::PROXYPAC: {
                wifiProxyConfig.autoProxyConfig.pacWebAddress = GetStringValue(node);
                break;
            }
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
    std::vector<unsigned char> keyMgmtByte = GetByteArrValue(node);
    if (keyMgmtByte.size() > 4) { // trans byte to int always < 4
        wifiConfig.keyMgmt = "";
        return;
    }
    unsigned int keyMgmtInt = 0;
    for (int i = 0; i < keyMgmtByte.size(); i++) {
        keyMgmtInt |= (keyMgmtByte[i] << (8 * i)); // trans byte to int
    }
    if (keyMgmtInt & MGMT_SAE) {
        wifiConfig.keyMgmt = OHOS::Wifi::KEY_MGMT_SAE;
    } else if (keyMgmtInt & MGMT_WPA_PSK || keyMgmtInt & MGMT_WPA2_PSK || keyMgmtInt & MGMT_FT_PSK) {
        wifiConfig.keyMgmt = OHOS::Wifi::KEY_MGMT_WPA_PSK;
    } else if (keyMgmtInt & MGMT_NONE) {
        if (HasWepKeys(wifiConfig)) {
            wifiConfig.keyMgmt = OHOS::Wifi::KEY_MGMT_WEP;
        } else {
            wifiConfig.keyMgmt = OHOS::Wifi::KEY_MGMT_NONE;
        }
    } else {
        wifiConfig.keyMgmt = "";
    }
    return;
}

OHOS::Wifi::WifiPrivacyConfig NetworkXmlParser::GetRandMacSetting(xmlNodePtr node)
{
    int randMacSetting = GetPrimValue<int>(node, PrimType::INT);
    if (randMacSetting == 0) {
        return OHOS::Wifi::WifiPrivacyConfig::DEVICEMAC;
    }
    return OHOS::Wifi::WifiPrivacyConfig::RANDOMMAC;
}

WifiDeviceConfig NetworkXmlParser::ParseWifiConfig(xmlNodePtr innode)
{
    WifiDeviceConfig wifiConfig;
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
            case WifiConfigType::STATUS:
                ParseStatus(node, wifiConfig);
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

void NetworkXmlParser::ParseWepKeys(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig)
{
    std::vector<std::string> wepKeys = GetStringArrValue(node);
    if (wepKeys.size() == WEPKEYS_SIZE) {
        for (auto i = 0; i < wepKeys.size(); i++) {
            wifiDeviceConfig.wepKeys[i] = wepKeys[i];
        }
    }
}

void NetworkXmlParser::ParseStatus(xmlNodePtr node, WifiDeviceConfig& wifiDeviceConfig)
{
    int status = GetPrimValue<int>(node, PrimType::INT);
    if (status == 1) { // 1 means DISABLED else enable
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
    } else {
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
    }
}


WifiDeviceConfig NetworkXmlParser::ParseNetwork(xmlNodePtr innode)
{
    WifiDeviceConfig wifiConfig;
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        switch (GetNodeNameAsInt(node)) {
            case NetworkSection::WIFI_CONFIGURATION: {
                wifiConfig = ParseWifiConfig(node);
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
    xmlNodePtr networkNodeList = GotoNetworkList(innode);
    for (xmlNodePtr node = networkNodeList->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_SECTION_HEADER_NETWORK)) == 0) {
            wifiConfigs.push_back(ParseNetwork(node));
        }
    }
    WIFI_LOGI("ParseNetworkList size[%{public}lu]", wifiConfigs.size());
}

xmlNodePtr NetworkXmlParser::GotoMacAddressMap(xmlNodePtr innode)
{
    for (xmlNodePtr node = innode->children; node != nullptr; node = node->next) {
        if (xmlStrcmp(node->name, BAD_CAST(XML_TAG_SECTION_HEADER_MAC_ADDRESS_MAP)) == 0) {
            return node;
        }
    }
    return nullptr;
}

void NetworkXmlParser::SetMacMap(std::map<std::string, std::string> macMap)
{
    WifiStoreRandomMac wifiStoreRandomMac{};
    for (auto it = macMap.begin(); it != macMap.end(); ++it) {
        for (auto wifiConfig : wifiConfigs) {
            if (wifiConfig.macAddress == it->second) {
                wifiStoreRandomMac.ssid = wifiConfig.ssid;
                wifiStoreRandomMac.keyMgmt = wifiConfig.keyMgmt;
                wifiStoreRandomMac.peerBssid = it->first;
                wifiStoreRandomMac.randomMac = it->second;
                wifiStoreRandomMacs.push_back(wifiStoreRandomMac);
                break;
            }
        }
    }
}

void NetworkXmlParser::ParseMacMapPlus(xmlNodePtr innode)
{
    xmlNodePtr macAddrNode = GotoMacAddressMap(innode);
    for (xmlNodePtr node = macAddrNode->children; node != nullptr; node = node->next) {
        if (GetNameValue(node) == XML_TAG_MAC_MAP_PLUS) {
            std::map<std::string, std::string> macMap = GetStringMapValue(node);
            SetMacMap(macMap);
        }
    }
    WIFI_LOGI("ParseMacMapPlus size[%{public}lu]", wifiStoreRandomMacs.size());
}

bool NetworkXmlParser::ParseInternal(xmlNodePtr node)
{
    if (IsDocValid(node) != true) {
        WIFI_LOGE("ParseInternal Doc invalid");
        return false;
    }
    ParseNetworkList(node);
    ParseMacMapPlus(node);
    return true;
}

bool IsWifiConfigValid(WifiDeviceConfig wifiConfig)
{
    if (wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_SAE || wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_NONE
        || wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_WEP || wifiConfig.keyMgmt == OHOS::Wifi::KEY_MGMT_WPA_PSK) {
        return true;
    }
    return false;
}

std::vector<WifiDeviceConfig> NetworkXmlParser::GetNetworks()
{
    std::vector<WifiDeviceConfig> wifiDeviceConfig{};
    for (auto wifiConfig : wifiConfigs) {
        if (IsWifiConfigValid(wifiConfig)) {
            wifiDeviceConfig.push_back(wifiConfig);
        }
    }
    return wifiDeviceConfig;
}

std::vector<WifiStoreRandomMac> NetworkXmlParser::GetRandomMacmap()
{
    return wifiStoreRandomMacs;
}
}
}