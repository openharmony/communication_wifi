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


#include "wifi_logger.h"
#include "wifi_utils_taihe.h"
#include "wifi_callback_taihe.h"
#include "wifi_errorcode_taihe.h"
DEFINE_WIFILOG_LABEL("WifiUtilsTaihe");
namespace OHOS {
namespace Wifi {
static const std::string EAP_METHOD[] = { "NONE", "PEAP", "TLS", "TTLS", "PWD", "SIM", "AKA", "AKA'" };
std::map<SecTypeTaihe, KeyMgmt> g_mapSecTypeToKeyMgmt = {
    {SecTypeTaihe::SEC_TYPE_OPEN, KeyMgmt::NONE},
    {SecTypeTaihe::SEC_TYPE_PSK, KeyMgmt::WPA2_PSK},
};

::ohos::wifiManager::WifiProxyConfig MakeWifiProxyConfig(const WifiProxyConfig& proxyConfig)
{
    switch (proxyConfig.configureMethod) {
        case ConfigureProxyMethod::CLOSED:
            return {
                ::taihe::optional<::ohos::wifiManager::ProxyMethod>(std::in_place_t{},
                    static_cast<::ohos::wifiManager::ProxyMethod::key_t>(proxyConfig.configureMethod)),
                ::taihe::optional<taihe::string>(std::nullopt),
                ::taihe::optional<taihe::string>(std::nullopt),
                ::taihe::optional<int32_t>(std::nullopt),
                ::taihe::optional<taihe::string>(std::nullopt)
            };
        case ConfigureProxyMethod::AUTOCONFIGUE:
            return {
                ::taihe::optional<::ohos::wifiManager::ProxyMethod>(std::in_place_t{},
                    static_cast<::ohos::wifiManager::ProxyMethod::key_t>(proxyConfig.configureMethod)),
                ::taihe::optional<taihe::string>(std::in_place_t{},
                    proxyConfig.autoProxyConfig.pacWebAddress),
                ::taihe::optional<taihe::string>(std::nullopt),
                ::taihe::optional<int32_t>(std::nullopt),
                ::taihe::optional<taihe::string>(std::nullopt)
            };
        case ConfigureProxyMethod::MANUALCONFIGUE:
            return {
                ::taihe::optional<::ohos::wifiManager::ProxyMethod>(std::in_place_t{},
                    static_cast<::ohos::wifiManager::ProxyMethod::key_t>(proxyConfig.configureMethod)),
                ::taihe::optional<taihe::string>(std::nullopt),
                ::taihe::optional<taihe::string>(std::in_place_t{},
                    proxyConfig.manualProxyConfig.serverHostName),
                ::taihe::optional<int32_t>(std::in_place_t{},
                    proxyConfig.manualProxyConfig.serverPort),
                ::taihe::optional<taihe::string>(std::in_place_t{},
                    proxyConfig.manualProxyConfig.exclusionObjectList)
            };
        default:
            break;
    }
}

int Str2EapMethod(const std::string& str)
{
    int len = sizeof(EAP_METHOD) / sizeof(EAP_METHOD[0]);
    for (int i = 0; i < len; i++) {
        if (EAP_METHOD[i] == str) {
            return i;
        }
    }
    return 0;
}

::ohos::wifiManager::WifiEapConfig MakeWifiEapConfig(const WifiEapConfig& wifiEapConfig)
{
    return {
        static_cast<::ohos::wifiManager::EapMethod::key_t>(Str2EapMethod(wifiEapConfig.eap)),
        static_cast<::ohos::wifiManager::Phase2Method::key_t>(wifiEapConfig.phase2Method),
        wifiEapConfig.identity, wifiEapConfig.anonymousIdentity, wifiEapConfig.password,
        wifiEapConfig.caCertAlias, wifiEapConfig.caCertPath, wifiEapConfig.clientCert,
        ::taihe::array<uint8_t>(
            taihe::copy_data_t{}, wifiEapConfig.certEntry.data(), wifiEapConfig.certEntry.size()),
        wifiEapConfig.certPassword, wifiEapConfig.altSubjectMatch, wifiEapConfig.domainSuffixMatch,
        wifiEapConfig.realm, wifiEapConfig.plmn, wifiEapConfig.eapSubId
    };
}

SecTypeTaihe ConvertKeyMgmtToSecType(const std::string& keyMgmt)
{
    std::map<std::string, SecTypeTaihe> mapKeyMgmtToSecType = {
        {KEY_MGMT_NONE, SecTypeTaihe::SEC_TYPE_OPEN},
        {KEY_MGMT_WEP, SecTypeTaihe::SEC_TYPE_WEP},
        {KEY_MGMT_WPA_PSK, SecTypeTaihe::SEC_TYPE_PSK},
        {KEY_MGMT_SAE, SecTypeTaihe::SEC_TYPE_SAE},
        {KEY_MGMT_EAP, SecTypeTaihe::SEC_TYPE_EAP},
        {KEY_MGMT_SUITE_B_192, SecTypeTaihe::SEC_TYPE_EAP_SUITE_B},
        {KEY_MGMT_WAPI_CERT, SecTypeTaihe::SEC_TYPE_WAPI_CERT},
        {KEY_MGMT_WAPI_PSK, SecTypeTaihe::SEC_TYPE_WAPI_PSK},
    };

    std::map<std::string, SecTypeTaihe>::iterator iter = mapKeyMgmtToSecType.find(keyMgmt);
    return iter == mapKeyMgmtToSecType.end() ? SecTypeTaihe::SEC_TYPE_OPEN : iter->second;
}

::ohos::wifiManager::IpConfig MakeIpConfig(const WifiIpConfig& wifiIpConfig)
{
    ::taihe::array<int32_t> resDns = {
        wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4,
        wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4
    };
    std::vector<std::string> vecDomains = {wifiIpConfig.staticIpAddress.domains};
    ::taihe::array<taihe::string> resDomains = ::taihe::array<taihe::string>(
            taihe::copy_data_t{}, vecDomains.data(), vecDomains.size());
    return {
        wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4,
        wifiIpConfig.staticIpAddress.gateway.addressIpv4,
        wifiIpConfig.staticIpAddress.ipAddress.prefixLength,
        resDns, resDomains
    };
}

::ohos::wifiManager::WifiWapiConfig MakeWifiWapiConfig(const WifiWapiConfig& wifiWapiConfig)
{
    return {
        static_cast<::ohos::wifiManager::WapiPskType::key_t>(wifiWapiConfig.wapiPskType),
        wifiWapiConfig.wapiAsCertData, wifiWapiConfig.wapiUserCertData
    };
}

::ohos::wifiManager::WifiDeviceConfig MakeWifiDeviceConfig(const WifiDeviceConfig& wifiDeviceConfig)
{
    auto ipType = wifiDeviceConfig.wifiIpConfig.assignMethod == AssignIpMethod::STATIC ?
        ::taihe::optional<::ohos::wifiManager::IpType>(std::in_place_t{},
            static_cast<::ohos::wifiManager::IpType::key_t>(IpTypeTaihe::IP_TYPE_STATIC)) :
        ::taihe::optional<::ohos::wifiManager::IpType>(std::in_place_t{},
            static_cast<::ohos::wifiManager::IpType::key_t>(IpTypeTaihe::IP_TYPE_DHCP));

    SecTypeTaihe type = ConvertKeyMgmtToSecType(wifiDeviceConfig.keyMgmt);
    auto eapConfig = ::taihe::optional<::ohos::wifiManager::WifiEapConfig>(std::nullopt);
    if (type == SecTypeTaihe::SEC_TYPE_EAP || type == SecTypeTaihe::SEC_TYPE_EAP_SUITE_B) {
        eapConfig = ::taihe::optional<::ohos::wifiManager::WifiEapConfig>(std::in_place_t{},
            MakeWifiEapConfig(wifiDeviceConfig.wifiEapConfig));
    }
    auto wapiConfig = ::taihe::optional<::ohos::wifiManager::WifiWapiConfig>(std::nullopt);
    if (type == SecTypeTaihe::SEC_TYPE_WAPI_CERT || type == SecTypeTaihe::SEC_TYPE_WAPI_PSK) {
        wapiConfig = ::taihe::optional<::ohos::wifiManager::WifiWapiConfig>(std::in_place_t{},
            MakeWifiWapiConfig(wifiDeviceConfig.wifiWapiConfig));
    }
    return {
        wifiDeviceConfig.ssid,
        ::taihe::optional<taihe::string>(std::in_place_t{}, wifiDeviceConfig.userSelectBssid),
        ::taihe::optional<::ohos::wifiManager::DeviceAddressType>(std::in_place_t{},
            static_cast<::ohos::wifiManager::DeviceAddressType::key_t>(wifiDeviceConfig.bssidType)),
        wifiDeviceConfig.preSharedKey,
        ::taihe::optional<bool>(std::in_place_t{}, wifiDeviceConfig.hiddenSSID),
        static_cast<::ohos::wifiManager::WifiSecurityType::key_t>(type),
        ::taihe::optional<int32_t>(std::in_place_t{}, wifiDeviceConfig.uid),
        ::taihe::optional<int32_t>(std::in_place_t{},
            static_cast<int32_t>(wifiDeviceConfig.networkSelectionStatus.networkSelectionDisableReason)),
        ::taihe::optional<int32_t>(std::in_place_t{}, wifiDeviceConfig.networkId),
        ::taihe::optional<int32_t>(std::in_place_t{},
            static_cast<int32_t>(wifiDeviceConfig.wifiPrivacySetting)),
        ::taihe::optional<taihe::string>(std::in_place_t{}, std::string("")),
        ipType,
        ::taihe::optional<::ohos::wifiManager::IpConfig>(std::in_place_t{},
            MakeIpConfig(wifiDeviceConfig.wifiIpConfig)),
        eapConfig,
        ::taihe::optional<::ohos::wifiManager::WifiProxyConfig>(std::in_place_t{},
            MakeWifiProxyConfig(wifiDeviceConfig.wifiProxyconfig)),
        wapiConfig,
        ::taihe::optional<int32_t>(std::in_place_t{},
            static_cast<int32_t>(wifiDeviceConfig.networkSelectionStatus.status)),
        ::taihe::optional<bool>(std::in_place_t{},
            static_cast<bool>(wifiDeviceConfig.isAllowAutoConnect)),
    };
}

void ConvertEncryptionMode(const SecTypeTaihe& securityType, std::string& keyMgmt)
{
    switch (securityType) {
        case SecTypeTaihe::SEC_TYPE_OPEN:
            keyMgmt = KEY_MGMT_NONE;
            break;
        case SecTypeTaihe::SEC_TYPE_WEP:
            keyMgmt = KEY_MGMT_WEP;
            break;
        case SecTypeTaihe::SEC_TYPE_PSK:
            keyMgmt = KEY_MGMT_WPA_PSK;
            break;
        case SecTypeTaihe::SEC_TYPE_SAE:
            keyMgmt = KEY_MGMT_SAE;
            break;
        case SecTypeTaihe::SEC_TYPE_EAP:
            keyMgmt = KEY_MGMT_EAP;
            break;
        case SecTypeTaihe::SEC_TYPE_EAP_SUITE_B:
            keyMgmt = KEY_MGMT_SUITE_B_192;
            break;
        case SecTypeTaihe::SEC_TYPE_WAPI_CERT:
            keyMgmt = KEY_MGMT_WAPI_CERT;
            break;
        case SecTypeTaihe::SEC_TYPE_WAPI_PSK:
            keyMgmt = KEY_MGMT_WAPI_PSK;
            break;
        default:
            keyMgmt = KEY_MGMT_NONE;
            break;
    }
}

void ProcessPassphrase(const SecTypeTaihe& securityType, WifiDeviceConfig& cppConfig)
{
    if (securityType == SecTypeTaihe::SEC_TYPE_WEP) {
        cppConfig.wepKeys[0] = cppConfig.preSharedKey;
        cppConfig.wepTxKeyIndex = 0;
        cppConfig.preSharedKey = "";
        std::string().swap(cppConfig.preSharedKey);
    }
}

void ConfigStaticIpv4(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& cppConfig)
{
    const int dnsNum = 2;
    if (bool(config.staticIp)) {
        ::ohos::wifiManager::IpConfig ipConfig = *(config.staticIp);
        cppConfig.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4 = ipConfig.ipAddress;
        cppConfig.wifiIpConfig.staticIpAddress.ipAddress.address.family = 0;
        cppConfig.wifiIpConfig.staticIpAddress.gateway.addressIpv4 = ipConfig.gateway;
        cppConfig.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = ipConfig.prefixLength;
        if (ipConfig.dnsServers.size() == 0 || ipConfig.dnsServers.size() > dnsNum) {
            WIFI_LOGE("ConfigStaticIpv4, It needs dns servers or dns too much.");
            return;
        }
        cppConfig.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4 = ipConfig.dnsServers[0];
        if (ipConfig.dnsServers.size() == dnsNum) {
            cppConfig.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4 = ipConfig.dnsServers[1];
        }
    }
}

void ProcessProxyConfig(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& cppConfig)
{
    if (bool(config.proxyConfig)) {
        ::ohos::wifiManager::WifiProxyConfig proxyConfig = *(config.proxyConfig);
        int proxyConfigMethod = static_cast<int>(ConfigureProxyMethod::CLOSED);
        cppConfig.wifiProxyconfig.configureMethod = ConfigureProxyMethod::CLOSED;
        if (bool(proxyConfig.proxyMethod)) {
            proxyConfigMethod = static_cast<int>(*(proxyConfig.proxyMethod));
        }
        switch (ConfigureProxyMethod(proxyConfigMethod)) {
            case ConfigureProxyMethod::AUTOCONFIGUE:
                cppConfig.wifiProxyconfig.configureMethod = ConfigureProxyMethod::AUTOCONFIGUE;
                if (bool(proxyConfig.pacWebAddress)) {
                    cppConfig.wifiProxyconfig.autoProxyConfig.pacWebAddress = *(proxyConfig.pacWebAddress);
                }
                WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_NOT_SUPPORTED, SYSCAP_WIFI_STA);
                break;
            case ConfigureProxyMethod::MANUALCONFIGUE:
                cppConfig.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
                if (bool(proxyConfig.serverHostName)) {
                    cppConfig.wifiProxyconfig.manualProxyConfig.serverHostName = *(proxyConfig.serverHostName);
                }
                if (bool(proxyConfig.exclusionObjects)) {
                    cppConfig.wifiProxyconfig.manualProxyConfig.exclusionObjectList = *(proxyConfig.exclusionObjects);
                }
                if (bool(proxyConfig.serverPort)) {
                    cppConfig.wifiProxyconfig.manualProxyConfig.serverPort = *(proxyConfig.serverPort);
                }
                
                if (cppConfig.wifiProxyconfig.manualProxyConfig.serverPort < 0) {
                    WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
                }
                break;
            case ConfigureProxyMethod::CLOSED:
                WIFI_LOGI("ProcessProxyConfig, configureMethod is closed.");
                break;
            default:
                WIFI_LOGE("ProcessProxyConfig, configureMethod %{public}d is not supported.", proxyConfigMethod);
                WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
        }
    }
}

std::string EapMethod2Str(const int& method)
{
    if (method < 0 || method >= static_cast<int>(sizeof(EAP_METHOD) / sizeof(EAP_METHOD[0]))) {
        return "NONE";
    }
    return EAP_METHOD[method];
}

void ProcessEapConfig(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& devConfig)
{
    if (bool(config.eapConfig)) {
        ::ohos::wifiManager::WifiEapConfig eapConfig = *(config.eapConfig);
        devConfig.wifiEapConfig.eap = EapMethod2Str(eapConfig.eapMethod);
        devConfig.wifiEapConfig.phase2Method = Phase2Method(static_cast<int32_t>(eapConfig.phase2Method));
        devConfig.wifiEapConfig.identity = eapConfig.identity;
        devConfig.wifiEapConfig.anonymousIdentity = eapConfig.anonymousIdentity;
        devConfig.wifiEapConfig.password = eapConfig.password;
        devConfig.wifiEapConfig.caCertAlias = eapConfig.caCertAlias;
        devConfig.wifiEapConfig.caCertPath = eapConfig.caPath;
        devConfig.wifiEapConfig.clientCert = eapConfig.clientCertAlias;
        devConfig.wifiEapConfig.privateKey = eapConfig.clientCertAlias;
        std::string pd = static_cast<std::string>(eapConfig.certPassword);
        if (strncpy_s(devConfig.wifiEapConfig.certPassword, sizeof(devConfig.wifiEapConfig.certPassword),
            pd.c_str(), pd.length()) != EOK) {
            WIFI_LOGE("%{public}s: failed to copy", __func__);
        }
        devConfig.wifiEapConfig.altSubjectMatch = eapConfig.altSubjectMatch;
        devConfig.wifiEapConfig.domainSuffixMatch = eapConfig.domainSuffixMatch;
        devConfig.wifiEapConfig.realm = eapConfig.realm;
        devConfig.wifiEapConfig.plmn = eapConfig.plmn;
        devConfig.wifiEapConfig.eapSubId = eapConfig.eapSubId;
    }
}

void ProcessWapiConfig(const ::ohos::wifiManager::WifiDeviceConfig &config, WifiDeviceConfig& devConfig)
{
    if (bool(config.wapiConfig)) {
        ::ohos::wifiManager::WifiWapiConfig wapiConfig = *(config.wapiConfig);
        devConfig.wifiWapiConfig.wapiPskType = wapiConfig.wapiPskType;
        devConfig.wifiWapiConfig.wapiAsCertData = wapiConfig.wapiAsCert;
        devConfig.wifiWapiConfig.wapiUserCertData = wapiConfig.wapiUserCert;
    }
}


WifiDeviceConfig ConvertWifiDeviceConfig(const ::ohos::wifiManager::WifiDeviceConfig &config)
{
    WifiDeviceConfig result;
    result.ssid = static_cast<std::string>(config.ssid);
    if (config.bssid) {
        result.bssid = static_cast<std::string>(*(config.bssid));
    }
    if (config.bssidType) {
        result.bssidType = static_cast<int>(*(config.bssidType));
    }
    result.preSharedKey = static_cast<std::string>(config.preSharedKey);
    if (config.isHiddenSsid) {
        result.hiddenSSID = *(config.isHiddenSsid);
    }
    int type = static_cast<int>(config.securityType);
    ConvertEncryptionMode(SecTypeTaihe(type), result.keyMgmt);
    ProcessPassphrase(SecTypeTaihe(type), result);
    if (config.creatorUid) {
        result.uid = *(config.creatorUid);
    }
    /* "disableReason" is not supported currently */
    if (config.netId) {
        result.networkId = *(config.netId);
    }
    if (config.randomMacType) {
        result.wifiPrivacySetting = WifiPrivacyConfig(*(config.randomMacType));
    }
    /* "randomMacAddr" is not supported currently */
    if (config.ipType) {
        int ipType = static_cast<int>(*(config.ipType));
        if (IpTypeTaihe(ipType) == IpTypeTaihe::IP_TYPE_DHCP) {
            result.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        } else if (IpTypeTaihe(ipType) == IpTypeTaihe::IP_TYPE_STATIC) {
            result.wifiIpConfig.assignMethod = AssignIpMethod::STATIC;
            ConfigStaticIpv4(config, result);
        }
    }
    ProcessProxyConfig(config, result);
    if (SecTypeTaihe(type) == SecTypeTaihe::SEC_TYPE_EAP ||
        SecTypeTaihe(type) == SecTypeTaihe::SEC_TYPE_EAP_SUITE_B) {
        ProcessEapConfig(config, result);
    }
    if (SecTypeTaihe(type) == SecTypeTaihe::SEC_TYPE_WAPI_CERT ||
        SecTypeTaihe(type) == SecTypeTaihe::SEC_TYPE_WAPI_PSK) {
        ProcessWapiConfig(config, result);
    }
    return result;
}

bool IsSecTypeSupported(int secType)
{
    return g_mapSecTypeToKeyMgmt.find(SecTypeTaihe(secType)) != g_mapSecTypeToKeyMgmt.end();
}

KeyMgmt GetKeyMgmtFromJsSecurityType(int secType)
{
    std::map<SecTypeTaihe, KeyMgmt>::iterator iter =
        g_mapSecTypeToKeyMgmt.find(SecTypeTaihe(secType));
    return iter == g_mapSecTypeToKeyMgmt.end() ? KeyMgmt::NONE : iter->second;
}

HotspotConfig ConvertHotspotConfig(const ::ohos::wifiManager::HotspotConfig &config)
{
    HotspotConfig result;
    result.SetSsid(static_cast<std::string>(config.ssid));
    int value = static_cast<int>(config.securityType);
    result.SetSecurityType(GetKeyMgmtFromJsSecurityType(value));
    result.SetBand(BandType(config.band));
    if (result.GetBand() == BandType::BAND_5GHZ) {
        result.SetChannel(AP_CHANNEL_5G_DEFAULT);
    }
    result.SetPreSharedKey(static_cast<std::string>(config.preSharedKey));
    result.SetMaxConn(config.maxConn);
    value = 0;
    if (bool(config.channel)) {
        value = *(config.channel);
    }
    if (value == 0) {
        value = (int)AP_CHANNEL_DEFAULT;
    }
    result.SetChannel(value);
    std::string ipAddr = "";
    if (bool(config.ipAddress)) {
        ipAddr = static_cast<std::string>(*(config.ipAddress));
    }
    result.SetIpAddress(ipAddr);
    return result;
}

::ohos::wifiManager::WifiInfoElem MakeWifiInfoElem(const WifiInfoElem& wifiInfoElem)
{
    std::vector<uint8_t> content;
    for (size_t i = 0; i < wifiInfoElem.content.size(); i++) {
        content.emplace_back(static_cast<uint8_t>(wifiInfoElem.content[i]));
    }
    return {
        wifiInfoElem.id,
        ::taihe::array<uint8_t>(taihe::copy_data_t{}, content.data(), content.size())
    };
}

::ohos::wifiManager::WifiScanInfo MakeWifiScanInfo(const WifiScanInfo& scanInfo)
{
    bool isHiLinkNetwork = static_cast<bool>((scanInfo.isHiLinkNetwork > 0
        && scanInfo.isHiLinkNetwork <= EXTERNAL_HILINK_MAX_VALUE) ? true : false);
    std::vector<::ohos::wifiManager::WifiInfoElem> infoTaihe;
    for (std::size_t i = 0; i < scanInfo.infoElems.size(); i++) {
        WifiInfoElem info = scanInfo.infoElems[i];
        infoTaihe.emplace_back(MakeWifiInfoElem(info));
    }
    auto infoElems = ::taihe::array<::ohos::wifiManager::WifiInfoElem>(
        taihe::copy_data_t{}, infoTaihe.data(), infoTaihe.size());
    return {scanInfo.ssid, scanInfo.bssid,
        static_cast<::ohos::wifiManager::DeviceAddressType::key_t>(scanInfo.bssidType),
        scanInfo.capabilities,
        static_cast<::ohos::wifiManager::WifiSecurityType::key_t>(scanInfo.securityType),
        scanInfo.rssi, scanInfo.band,
        scanInfo.frequency, static_cast<int32_t>(scanInfo.channelWidth),
        scanInfo.centerFrequency0, scanInfo.centerFrequency1,
        infoElems, scanInfo.timestamp,
        static_cast<::ohos::wifiManager::WifiCategory::key_t>(scanInfo.supportedWifiCategory),
        isHiLinkNetwork
    };
}

::ohos::wifiManager::WifiLinkedInfo MakeWifiLinkedInfo(const WifiLinkedInfo& linkedInfo)
{
    ::ohos::wifiManager::SuppState suppState =
        static_cast<::ohos::wifiManager::SuppState::key_t>(linkedInfo.supplicantState);
    ::ohos::wifiManager::ConnState connState =
        static_cast<::ohos::wifiManager::ConnState::key_t>(linkedInfo.connState);
    ::ohos::wifiManager::WifiChannelWidth channelWidth =
        static_cast<::ohos::wifiManager::WifiChannelWidth::key_t>(linkedInfo.channelWidth);
    ::ohos::wifiManager::WifiStandard wifiStandard =
        static_cast<::ohos::wifiManager::WifiStandard::key_t>(linkedInfo.wifiStandard);
    ::ohos::wifiManager::WifiCategory supportedWifiCategory =
        static_cast<::ohos::wifiManager::WifiCategory::key_t>(linkedInfo.supportedWifiCategory);
    bool isHiLinkNetwork = static_cast<bool>((linkedInfo.isHiLinkNetwork > 0
        && linkedInfo.isHiLinkNetwork <= EXTERNAL_HILINK_MAX_VALUE) ? true : false);
    return {linkedInfo.ssid, linkedInfo.bssid, linkedInfo.networkId,
        linkedInfo.rssi, linkedInfo.band, linkedInfo.linkSpeed, linkedInfo.rxLinkSpeed,
        linkedInfo.maxSupportedTxLinkSpeed, linkedInfo.maxSupportedRxLinkSpeed,
        linkedInfo.frequency, linkedInfo.ifHiddenSSID, linkedInfo.isDataRestricted,
        linkedInfo.chload, linkedInfo.snr, linkedInfo.macType,
        linkedInfo.macAddress, static_cast<int32_t>(linkedInfo.ipAddress),
        suppState, connState, channelWidth,
        wifiStandard, supportedWifiCategory, isHiLinkNetwork,
        ::taihe::optional<::ohos::wifiManager::WifiLinkType>(std::in_place_t{},
            static_cast<::ohos::wifiManager::WifiLinkType::key_t>(linkedInfo.wifiLinkType))
    };
}

::ohos::wifiManager::IpInfo MakeIpInfo(const IpInfo& ipInfo)
{
    return {static_cast<int32_t>(ipInfo.ipAddress),
        static_cast<int32_t>(ipInfo.gateway), static_cast<int32_t>(ipInfo.netmask),
        static_cast<int32_t>(ipInfo.primaryDns), static_cast<int32_t>(ipInfo.secondDns),
        static_cast<int32_t>(ipInfo.serverIp), ipInfo.leaseDuration
    };
}
 
::ohos::wifiManager::Ipv6Info MakeIpv6Info(const IpV6Info& ipInfo)
{
    return {ipInfo.linkIpV6Address, ipInfo.globalIpV6Address, ipInfo.randGlobalIpV6Address,
        ::taihe::optional<taihe::string>(std::in_place_t{}, ipInfo.uniqueLocalAddress1),
        ::taihe::optional<taihe::string>(std::in_place_t{}, ipInfo.uniqueLocalAddress2),
        ipInfo.gateway, ipInfo.netmask, ipInfo.primaryDns, ipInfo.secondDns
    };
}

::ohos::wifiManager::StationInfo MakeStationInfo(const StationInfo& stationInfo)
{
    return {
        stationInfo.deviceName, stationInfo.bssid,
        ::taihe::optional<::ohos::wifiManager::DeviceAddressType>(std::in_place_t{},
            static_cast<::ohos::wifiManager::DeviceAddressType::key_t>(stationInfo.bssidType)),
        stationInfo.ipAddr
    };
}

StationInfo ConvertStationInfo(::ohos::wifiManager::StationInfo const& stationInfo)
{
    StationInfo result;
    result.deviceName = stationInfo.name;
    result.bssid = stationInfo.macAddress;
    if (bool(stationInfo.macAddressType)) {
        result.bssidType = *(stationInfo.macAddressType);
    }
    result.ipAddr = stationInfo.ipAddress;
    return result;
}

int GetSecurityTypeFromKeyMgmt(KeyMgmt keyMgmt)
{
    for (auto& each : g_mapSecTypeToKeyMgmt) {
        if (each.second == keyMgmt) {
            return static_cast<int>(each.first);
        }
    }
    return static_cast<int>(SecTypeTaihe::SEC_TYPE_OPEN);
}

::ohos::wifiManager::HotspotConfig MakeHotspotConfig(const HotspotConfig& cppConfig)
{
    return {
        cppConfig.GetSsid(),
        static_cast<::ohos::wifiManager::WifiSecurityType::key_t>(
            GetSecurityTypeFromKeyMgmt(cppConfig.GetSecurityType())),
        static_cast<int32_t>(cppConfig.GetBand()),
        ::taihe::optional<int32_t>(std::in_place_t{}, cppConfig.GetChannel()),
        cppConfig.GetPreSharedKey(),
        cppConfig.GetMaxConn(),
        ::taihe::optional<taihe::string>(std::in_place_t{}, cppConfig.GetIpAddress())
    };
}

::ohos::wifiManager::WifiP2pLinkedInfo MakeWifiP2pLinkedInfo(const WifiP2pLinkedInfo& linkedInfo)
{
    return {
        static_cast<::ohos::wifiManager::P2pConnectState::key_t>(linkedInfo.GetConnectState()),
        linkedInfo.IsGroupOwner(),
        linkedInfo.GetGroupOwnerAddress()
    };
}

::ohos::wifiManager::WifiP2pDevice MakeWifiP2pDevice(const WifiP2pDevice& device)
{
    return {
        device.GetDeviceName(),
        device.GetDeviceAddress(),
        static_cast<::ohos::wifiManager::DeviceAddressType::key_t>(device.GetDeviceAddressType()),
        device.GetPrimaryDeviceType(),
        static_cast<::ohos::wifiManager::P2pDeviceStatus::key_t>(device.GetP2pDeviceStatus()),
        device.GetGroupCapabilitys()
    };
}

WifiP2pConfig ConvertWifiP2pConfig(const ::ohos::wifiManager::WifiP2PConfig &config)
{
    WifiP2pConfig newConfig;
    std::string address = "";
    int bssidType = RANDOM_DEVICE_ADDRESS;
    int netId = -1;
    std::string passphrase = "";
    std::string groupName = "";
    int band = static_cast<int>(GroupOwnerBand::GO_BAND_AUTO);
    address = static_cast<std::string>(config.deviceAddress);
    if (config.deviceAddressType) {
        bssidType = static_cast<int>(*(config.deviceAddressType));
    }
    netId = config.netId;
    passphrase = static_cast<std::string>(config.passphrase);
    groupName = static_cast<std::string>(config.groupName);
    band = static_cast<int>(config.goBand);
    newConfig.SetDeviceAddress(address);
    newConfig.SetDeviceAddressType(bssidType);
    newConfig.SetNetId(netId);
    newConfig.SetPassphrase(passphrase);
    newConfig.SetGroupName(groupName);
    newConfig.SetGoBand(static_cast<GroupOwnerBand>(band));
    return newConfig;
}

::ohos::wifiManager::WifiP2pGroupInfo MakeWifiP2pGroupInfo(const WifiP2pGroupInfo& groupInfo)
{
    std::vector<OHOS::Wifi::WifiP2pDevice> vecDevices = groupInfo.GetClientDevices();
    std::vector<::ohos::wifiManager::WifiP2pDevice> result;
    for (const OHOS::Wifi::WifiP2pDevice& device : vecDevices) {
        result.emplace_back(MakeWifiP2pDevice(device));
    }
    auto clientDevices = ::taihe::array<::ohos::wifiManager::WifiP2pDevice>(
        taihe::copy_data_t{}, result.data(), result.size());
    return {
        groupInfo.IsGroupOwner(),
        MakeWifiP2pDevice(groupInfo.GetOwner()),
        groupInfo.GetPassphrase(),
        groupInfo.GetInterface(),
        groupInfo.GetGroupName(),
        groupInfo.GetNetworkId(),
        groupInfo.GetFrequency(),
        clientDevices,
        groupInfo.GetGoIpAddress()
    };
}
}  // namespace Wifi
}  // namespace OHOS