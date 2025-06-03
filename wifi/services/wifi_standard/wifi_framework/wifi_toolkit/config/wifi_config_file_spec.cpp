/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "wifi_config_file_spec.h"
#include <unordered_set>
#include "wifi_global_func.h"
#ifdef FEATURE_ENCRYPTION_SUPPORT
#include "wifi_encryption_util.h"
#endif
#include "wifi_log.h"

#define CLIENT_PREFIX_NAME "vecDev_"
#define OWNER_DEV_PREFIX_NAME "ownerDev."

namespace OHOS {
namespace Wifi {
static void ClearWifiDeviceConfig(WifiDeviceConfig &item)
{
    item.instanceId = 0;
    item.networkId = 0;
    item.bssid.clear();
    item.ssid.clear();
    item.band = 0;
    item.channel = 0;
    item.frequency = 0;
    item.level = 0;
    item.isPasspoint = false;
    item.isEphemeral = false;
    item.preSharedKey.clear();
    item.keyMgmt.clear();
    item.keyMgmtBitset = 0;
    std::string().swap(item.preSharedKey);
    for (int i = 0; i < WEPKEYS_SIZE; ++i) {
        item.wepKeys[i].clear();
    }
    item.wepTxKeyIndex = 0;
    item.priority = 0;
    item.hiddenSSID = false;
    item.lastConnectTime = -1;
    item.lastUpdateTime = -1;
    item.numRebootsSinceLastUse = 0;
    item.numAssociation = 0;
    item.networkStatusHistory = 0;
    item.isPortal = false;
    item.portalAuthTime = -1;
    item.lastHasInternetTime = -1;
    item.noInternetAccess = false;
    item.callProcessName.clear();
    item.ancoCallProcessName.clear();
    item.randomizedMacSuccessEver = false;
    item.everConnected = false;
    item.acceptUnvalidated = false;
    item.macAddress.clear();
    item.internetSelfCureHistory.clear();
    item.isReassocSelfCureWithFactoryMacAddress = 0;
    item.isShared = true;
    item.lastTrySwitchWifiTimestamp = -1;
    item.isAllowAutoConnect = true;
    return;
}

static void ClearWifiIpConfig(WifiIpConfig &item)
{
    item.assignMethod = AssignIpMethod::DHCP;
    item.staticIpAddress.ipAddress.address.family = 0;
    item.staticIpAddress.ipAddress.address.addressIpv4 = 0;
    item.staticIpAddress.ipAddress.address.addressIpv6.clear();
    item.staticIpAddress.ipAddress.prefixLength = 0;
    item.staticIpAddress.ipAddress.flags = 0;
    item.staticIpAddress.ipAddress.scope = 0;
    item.staticIpAddress.gateway.family = 0;
    item.staticIpAddress.gateway.addressIpv4 = 0;
    item.staticIpAddress.gateway.addressIpv6.clear();
    item.staticIpAddress.dnsServer1.family = 0;
    item.staticIpAddress.dnsServer1.addressIpv4 = 0;
    item.staticIpAddress.dnsServer1.addressIpv6.clear();
    item.staticIpAddress.dnsServer2.family = 0;
    item.staticIpAddress.dnsServer2.addressIpv4 = 0;
    item.staticIpAddress.dnsServer2.addressIpv6.clear();
    item.staticIpAddress.domains.clear();
    return;
}

static void ClearWifiDeviceConfigEap(WifiDeviceConfig &item)
{
    item.wifiEapConfig.eap.clear();
    item.wifiEapConfig.identity.clear();
    item.wifiEapConfig.password.clear();
    item.wifiEapConfig.clientCert.clear();
    if (memset_s(item.wifiEapConfig.certPassword, sizeof(item.wifiEapConfig.certPassword),
        0x0, sizeof(item.wifiEapConfig.certPassword)) != EOK) {
        LOGW("%{public}s: failed to memset", __func__);
    }
    item.wifiEapConfig.privateKey.clear();
    item.wifiEapConfig.phase2Method = Phase2Method::NONE;
    return;
}

static void ClearWifiProxyConfig(WifiProxyConfig &item)
{
    item.configureMethod = ConfigureProxyMethod::CLOSED;
    item.autoProxyConfig.pacWebAddress.clear();
    item.manualProxyConfig.serverHostName.clear();
    item.manualProxyConfig.serverPort = 0;
    item.manualProxyConfig.exclusionObjectList.clear();
    return;
}

static void ClearWifiDeviceConfigPrivacy(WifiDeviceConfig &item)
{
    item.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
    return;
}

static void ClearWifiDeviceConfigWapi(WifiDeviceConfig &item)
{
    item.wifiWapiConfig.wapiPskType = -1;
    item.wifiWapiConfig.wapiAsCertData.clear();
    item.wifiWapiConfig.wapiUserCertData.clear();
    item.wifiWapiConfig.encryptedAsCertData.clear();
    item.wifiWapiConfig.asCertDataIV.clear();
    item.wifiWapiConfig.encryptedUserCertData.clear();
    item.wifiWapiConfig.userCertDataIV.clear();
    return;
}

static void ClearLastDhcpResultsConfig(WifiDeviceConfig &item)
{
    item.lastDhcpResult.ipAddress = 0;
    item.lastDhcpResult.gateway = 0;
    item.lastDhcpResult.netmask = 0;
    item.lastDhcpResult.primaryDns = 0;
    item.lastDhcpResult.secondDns = 0;
    item.lastDhcpResult.serverIp = 0;
    item.lastDhcpResult.leaseDuration = 0;
    item.lastDhcpResult.dnsAddr.clear();
    return;
}

template<>
void ClearTClass<WifiDeviceConfig>(WifiDeviceConfig &item)
{
    ClearWifiDeviceConfig(item);
    ClearWifiIpConfig(item.wifiIpConfig);
    ClearWifiDeviceConfigEap(item);
    ClearWifiProxyConfig(item.wifiProxyconfig);
    ClearWifiDeviceConfigPrivacy(item);
    ClearWifiDeviceConfigWapi(item);
    ClearLastDhcpResultsConfig(item);
    return;
}

static int SetWifiDeviceConfigOutDated(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    std::string tmpValue = value;
    if (key == "band") {
        item.band = CheckDataLegal(tmpValue);
    } else if (key == "channel") {
        item.channel = CheckDataLegal(tmpValue);
    } else if (key == "level") {
        item.level = CheckDataLegal(tmpValue);
    } else if (key == "isEphemeral") {
        item.isEphemeral = CheckDataLegal(tmpValue);
    } else {
        return -1;
    }
    return 0;
}

static int SetWifiDeviceConfigExternal(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    std::string tmpValue = value;
    if (key == "numRebootsSinceLastUse") {
        item.numRebootsSinceLastUse = CheckDataLegal(tmpValue);
    } else if (key == "numAssociation") {
        item.numAssociation = CheckDataLegal(tmpValue);
    } else if (key == "networkStatusHistory") {
        item.networkStatusHistory = static_cast<unsigned int>(CheckDataLegal(tmpValue));
    } else if (key == "isPortal") {
        item.isPortal = CheckDataLegal(tmpValue);
    } else if (key == "lastHasInternetTime") {
        item.lastHasInternetTime = CheckDataLegal(tmpValue);
    } else if (key == "noInternetAccess") {
        item.noInternetAccess = CheckDataLegal(tmpValue);
    } else if (key == "internetSelfCureHistory") {
        item.internetSelfCureHistory = value;
    } else if (key == "isReassocSelfCureWithFactoryMacAddress") {
        item.isReassocSelfCureWithFactoryMacAddress = CheckDataLegal(tmpValue);
    } else if (key == "isShared") {
        item.isShared = CheckDataLegal(tmpValue);
    } else if (key == "lastTrySwitchWifiTimestamp") {
        item.lastTrySwitchWifiTimestamp = static_cast<int64_t>(CheckDataTolonglong(tmpValue));
    } else if (key == "isAllowAutoConnect") {
        item.isAllowAutoConnect = (CheckDataLegal(tmpValue) != 0);
    } else if (key == "lastUpdateTime") {
        item.lastUpdateTime = CheckDataLegal(tmpValue);
    } else {
        return -1;
    }
    return 0;
}

static int SetWifiDeviceConfigFirst(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    if (SetWifiDeviceConfigOutDated(item, key, value) == 0) {
        return 0;
    }
    std::string tmpValue = value;

    if (key == "instanceId") {
        item.instanceId = CheckDataLegal(tmpValue);
    } else if (key == "networkId") {
        item.networkId = CheckDataLegal(tmpValue);
    } else if (key == "status") {
        //@deprecated
    } else if (key == "bssid") {
        item.bssid = value;
    } else if (key == "ssid") {
        item.ssid = value;
    } else if (key == "userSelectBssid") {
        item.userSelectBssid = value;
    } else if (key == "HexSsid") {
        std::vector<char> vec;
        vec.clear();
        if (HexStringToVec(value, vec) == 0) {
            std::string strSsid(vec.begin(), vec.end());
            item.ssid = strSsid;
        } else {
            return -1;
        }
    } else if (key == "frequency") {
        item.frequency = CheckDataLegal(tmpValue);
    } else if (key == "isPasspoint") {
        item.isPasspoint = CheckDataLegal(tmpValue);
    } else if (key == "preSharedKey") {
        item.preSharedKey = value;
    } else if (key == "keyMgmt") {
        item.keyMgmt = value;
    } else if (key == "keyMgmtBitset") {
        item.keyMgmtBitset = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "wepTxKeyIndex") {
        item.wepTxKeyIndex = CheckDataLegal(tmpValue);
    } else if (key == "priority") {
        item.priority = CheckDataLegal(tmpValue);
    } else if (key == "uid") {
        item.uid = CheckDataLegal(tmpValue);
    } else if (key == "lastConnectTime") {
        item.lastConnectTime = CheckDataLegal(tmpValue);
    } else if (key == "callProcessName") {
        item.callProcessName = value;
    } else if (key == "ancoCallProcessName") {
        item.ancoCallProcessName = value;
    } else if (key == "version") {
        item.version = CheckDataLegal(tmpValue);
    } else if (key == "randomizedMacSuccessEver") {
        item.randomizedMacSuccessEver = (CheckDataLegal(tmpValue) != 0); /* 0 -> false 1 -> true */
    } else if (key == "everConnected") {
        item.everConnected = (CheckDataLegal(tmpValue) != 0);
    } else if (key == "acceptUnvalidated") {
        item.acceptUnvalidated = (CheckDataLegal(tmpValue) != 0);
    } else if (key == "macAddress") {
        item.macAddress = value;
    } else if (key == "portalAuthTime") {
        item.portalAuthTime = CheckDataLegal(tmpValue);
    } else {
        return SetWifiDeviceConfigExternal(item, key, value);
    }
    return 0;
}

#ifdef FEATURE_ENCRYPTION_SUPPORT
static int SetWifiDeviceConfigEncrypt(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "encryptedData") {
        item.preSharedKey = "";
        std::string().swap(item.preSharedKey);
        item.encryptedData = value;
    } else if (key == "IV") {
        item.IV = value;
    } else if (key.compare(0, strlen("encryWepKeys"), "encryWepKeys") == 0) {
        std::string keyTmp = key.substr(strlen("encryWepKeys") + 1);
        int pos = CheckDataLegal(keyTmp);
        if (pos >= 0 && pos < WEPKEYS_SIZE) {
            item.encryWepKeys[pos] = value;
        }
    } else if (key == "IVWep") {
        if (item.wepTxKeyIndex < 0 || item.wepTxKeyIndex >= WEPKEYS_SIZE) {
            item.wepTxKeyIndex = 0;
        }
        item.IVWep = value;
    } else {
        return -1;
    }
    return errorKeyValue;
}
#endif

static int SetWifiDeviceConfig(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (SetWifiDeviceConfigFirst(item, key, value) == 0) {
        return errorKeyValue;
    }
#ifdef FEATURE_ENCRYPTION_SUPPORT
    errorKeyValue = SetWifiDeviceConfigEncrypt(item, key, value);
    if (errorKeyValue != -1) {
        return errorKeyValue;
    } else {
        errorKeyValue = 0;
    }
#endif
    std::string tmpValue = value;
    if (key == "hiddenSSID") {
        item.hiddenSSID = CheckDataLegal(tmpValue);
    } else if (key.compare(0, strlen("wepKeys"), "wepKeys") == 0) {
        std::string keyTmp = key.substr(strlen("wepKeys") + 1);
        int pos = CheckDataLegal(keyTmp);
        if (pos >= 0 && pos < WEPKEYS_SIZE) {
            item.wepKeys[pos] = value;
        }
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiIpConfig(WifiIpConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "wifiIpConfig.assignMethod") {
        item.assignMethod = AssignIpMethod(CheckDataLegal(tmpValue));
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.address.family") {
        item.staticIpAddress.ipAddress.address.family = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4") {
        item.staticIpAddress.ipAddress.address.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6") {
        item.staticIpAddress.ipAddress.address.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.prefixLength") {
        item.staticIpAddress.ipAddress.prefixLength = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.flags") {
        item.staticIpAddress.ipAddress.flags = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.scope") {
        item.staticIpAddress.ipAddress.scope = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.gateway.family") {
        item.staticIpAddress.gateway.family = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.gateway.addressIpv4") {
        item.staticIpAddress.gateway.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.gateway.addressIpv6") {
        item.staticIpAddress.gateway.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer1.family") {
        item.staticIpAddress.dnsServer1.family = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4") {
        item.staticIpAddress.dnsServer1.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer1.addressIpv6") {
        item.staticIpAddress.dnsServer1.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer2.family") {
        item.staticIpAddress.dnsServer2.family = CheckDataLegal(tmpValue);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4") {
        item.staticIpAddress.dnsServer2.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer2.addressIpv6") {
        item.staticIpAddress.dnsServer2.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.domains") {
        item.staticIpAddress.domains = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}


#ifdef FEATURE_ENCRYPTION_SUPPORT
static int SetWifiDeviceConfigEncryptEap(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "wifiEapConfig.encryptedData") {
        item.wifiEapConfig.encryptedData = value;
    } else if (key == "wifiEapConfig.IV") {
        item.wifiEapConfig.IV = value;
    } else {
        return -1;
    }
    return errorKeyValue;
}
#endif

static int SetWifiDeviceConfigEap(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    errorKeyValue = SetWifiDeviceConfigEncryptEap(item, key, value);
    if (errorKeyValue != -1) {
        return errorKeyValue;
    } else {
        errorKeyValue = 0;
    }
#endif
    if (key == "wifiEapConfig.eap") {
        item.wifiEapConfig.eap = value;
    } else if (key == "wifiEapConfig.identity") {
        item.wifiEapConfig.identity = value;
    } else if (key == "wifiEapConfig.password") {
        item.wifiEapConfig.password = value;
    } else if (key == "wifiEapConfig.clientCert") {
        item.wifiEapConfig.clientCert = value;
    } else if (key == "wifiEapConfig.privateKey") {
        item.wifiEapConfig.privateKey = value;
    } else if (key == "wifiEapConfig.phase2method") {
        item.wifiEapConfig.phase2Method = Phase2Method(CheckDataLegal(tmpValue));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiProxyConfig(WifiProxyConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "wifiProxyconfig.configureMethod") {
        item.configureMethod = ConfigureProxyMethod(CheckDataLegal(tmpValue));
    } else if (key == "wifiProxyconfig.autoProxyConfig.pacWebAddress") {
        item.autoProxyConfig.pacWebAddress = value;
    } else if (key == "wifiProxyconfig.ManualProxyConfig.serverHostName") {
        item.manualProxyConfig.serverHostName = value;
    } else if (key == "wifiProxyconfig.ManualProxyConfig.serverPort") {
        item.manualProxyConfig.serverPort = CheckDataLegal(tmpValue);
    } else if (key == "wifiProxyconfig.ManualProxyConfig.exclusionObjectList") {
        item.manualProxyConfig.exclusionObjectList = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiDeviceconfigPrivacy(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "wifiPrivacySetting") {
        item.wifiPrivacySetting = WifiPrivacyConfig(CheckDataLegal(tmpValue));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiDeviceconfigWapi(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (item.keyMgmt != KEY_MGMT_WAPI_CERT && item.keyMgmt != KEY_MGMT_WAPI_PSK) {
        return errorKeyValue;
    }
    std::string tmpValue = value;
    if (item.keyMgmt == KEY_MGMT_WAPI_PSK) {
        if (key == "wifiWapiConfig.wapiPskType") {
            item.wifiWapiConfig.wapiPskType = CheckDataLegal(tmpValue);
        } else {
            LOGE("Invalid config key value");
        }
        return errorKeyValue;
    }

    if (key == "wifiWapiConfig.encryptedAsCertData") {
        item.wifiWapiConfig.encryptedAsCertData = value;
    } else if (key == "wifiWapiConfig.asCertDataIV") {
        item.wifiWapiConfig.asCertDataIV = value;
    } else if (key == "wifiWapiConfig.encryptedUserCertData") {
        item.wifiWapiConfig.encryptedUserCertData = value;
    } else if (key == "wifiWapiConfig.userCertDataIV") {
        item.wifiWapiConfig.userCertDataIV = value;
    } else {
        LOGE("Invalid config key value");
    }
    return errorKeyValue;
}

static int SetLastDhcpResultsConfig(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "LastDhcpResults.ipAddress") {
        item.lastDhcpResult.ipAddress = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "LastDhcpResults.gateway") {
        item.lastDhcpResult.gateway = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "LastDhcpResults.netmask") {
        item.lastDhcpResult.netmask = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "LastDhcpResults.primaryDns") {
        item.lastDhcpResult.primaryDns = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "LastDhcpResults.secondDns") {
        item.lastDhcpResult.secondDns = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "LastDhcpResults.serverIp") {
        item.lastDhcpResult.serverIp = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "LastDhcpResults.leaseDuration") {
        item.lastDhcpResult.leaseDuration = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else {
        errorKeyValue++;
        LOGE("Invalid config key value");
    }
    return errorKeyValue;
}

template<>
int SetTClassKeyValue<WifiDeviceConfig>(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key.compare(0, strlen("wifiIpConfig"), "wifiIpConfig") == 0) {
        errorKeyValue += SetWifiIpConfig(item.wifiIpConfig, key, value);
    } else if (key.compare(0, strlen("wifiEapConfig"), "wifiEapConfig") == 0) {
        errorKeyValue += SetWifiDeviceConfigEap(item, key, value);
    } else if (key.compare(0, strlen("wifiProxyconfig"), "wifiProxyconfig") == 0) {
        errorKeyValue += SetWifiProxyConfig(item.wifiProxyconfig, key, value);
    } else if (key.compare(0, strlen("wifiPrivacySetting"), "wifiPrivacySetting") == 0) {
        errorKeyValue += SetWifiDeviceconfigPrivacy(item, key, value);
    } else if (key.compare(0, strlen("wifiWapiConfig"), "wifiWapiConfig") == 0) {
        errorKeyValue += SetWifiDeviceconfigWapi(item, key, value);
    } else if (key.compare(0, strlen("LastDhcpResults"), "LastDhcpResults") == 0) {
        errorKeyValue += SetLastDhcpResultsConfig(item, key, value);
    } else {
        errorKeyValue += SetWifiDeviceConfig(item, key, value);
    }
    return errorKeyValue;
}

template<>
std::string GetTClassName<WifiDeviceConfig>()
{
    return "WifiDeviceConfig";
}

template <>
std::string GetTClassName<WifiRestrictedInfo>()
{
    return "WifiRestrictedInfo";
}
 
template <>
int SetTClassKeyValue<WifiRestrictedInfo>(WifiRestrictedInfo &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "ssid") {
        item.ssid = value;
    } else if (key == "HexSsid") {
        std::vector<char> vec;
        vec.clear();
        if (HexStringToVec(value, vec) == 0) {
            std::string strSsid(vec.begin(), vec.end());
            item.ssid = strSsid;
        }
    } else if (key == "bssid") {
        item.bssid = value;
    } else if (key == "uid") {
        std::string tmpValue = value;
        item.uid = static_cast<int>(CheckDataLegal(tmpValue));
    } else if (key == "wifiRestrictedType") {
        std::string tmpValue = value;
        item.wifiRestrictedType = static_cast<WifiRestrictedType>(CheckDataLegal(tmpValue));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

#ifdef FEATURE_ENCRYPTION_SUPPORT
static std::string OutPutEncryptionDeviceConfig(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    if (item.version == 1) {
        ss << "    " << "encryptedData=" << item.encryptedData << std::endl;
        ss << "    " << "IV=" << item.IV << std::endl;
        ss << "    " << "wepTxKeyIndex=" << item.wepTxKeyIndex << std::endl;
        for (int i = 0; i < WEPKEYS_SIZE; ++i) {
            ss << "    " << "encryWepKeys_" << i << "=" << item.encryWepKeys[i] << std::endl;
        }
        ss << "    " << "IVWep=" << item.IVWep << std::endl;
    } else {
        ss << "    " <<"preSharedKey=" << item.preSharedKey << std::endl;
        ss << "    " <<"wepTxKeyIndex=" << item.wepTxKeyIndex << std::endl;
        for (int i = 0; i < WEPKEYS_SIZE; ++i) {
            ss << "    " <<"wepKeys_" << i << "=" << item.wepKeys[i] << std::endl;
        }
    }
    return ss.str();
}
#endif

static std::string OutPutWifiRestrictedInfoListInfo(WifiRestrictedInfo &item)
{
    std::ostringstream ss;
    ss << "    " << "<WifiRestrictedInfo>" << std::endl;
    ss << "    " << "ssid=" << ValidateString(item.ssid) << std::endl;
    ss << "    " << "HexSsid=" << ConvertArrayToHex((uint8_t*)&item.ssid[0], item.ssid.length()) << std::endl;
    ss << "    " << "bssid=" << item.bssid << std::endl;
    ss << "    " << "wifiRestrictedType=" << item.wifiRestrictedType << std::endl;
    ss << "    " << "uid=" << item.uid << std::endl;
    ss << "    " << "</WifiRestrictedInfo>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiDeviceConfig(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfig>" << std::endl;
    ss << "    " <<"version=" << item.version << std::endl;
    ss << "    " <<"instanceId=" << item.instanceId << std::endl;
    ss << "    " <<"uid=" << item.uid << std::endl;
    ss << "    " <<"bssid=" << item.bssid << std::endl;
    ss << "    " <<"userSelectBssid=" << item.userSelectBssid << std::endl;
    ss << "    " <<"ssid=" << ValidateString(item.ssid) << std::endl;
    ss << "    " <<"HexSsid=" << ConvertArrayToHex((uint8_t*)&item.ssid[0], item.ssid.length()) << std::endl;
    ss << "    " <<"frequency=" << item.frequency << std::endl;
    ss << "    " <<"isPasspoint=" << item.isPasspoint << std::endl;
    ss << "    " <<"priority=" << item.priority << std::endl;
    ss << "    " <<"hiddenSSID=" << (int)item.hiddenSSID << std::endl;
    ss << "    " <<"keyMgmt=" << item.keyMgmt << std::endl;
    ss << "    " <<"keyMgmtBitset=" << item.keyMgmtBitset << std::endl;
    ss << "    " <<"lastConnectTime=" << item.lastConnectTime << std::endl;
    ss << "    " <<"numRebootsSinceLastUse=" << item.numRebootsSinceLastUse << std::endl;
    ss << "    " <<"numAssociation=" << item.numAssociation << std::endl;
    ss << "    " <<"networkStatusHistory=" << item.networkStatusHistory << std::endl;
    ss << "    " <<"isPortal=" << item.isPortal << std::endl;
    ss << "    " <<"portalAuthTime=" << item.portalAuthTime << std::endl;
    ss << "    " <<"lastHasInternetTime=" << item.lastHasInternetTime << std::endl;
    ss << "    " <<"noInternetAccess=" << item.noInternetAccess << std::endl;
    ss << "    " <<"internetSelfCureHistory=" << item.internetSelfCureHistory << std::endl;
    ss << "    " <<"isReassocSelfCureWithFactoryMacAddress=" << item.isReassocSelfCureWithFactoryMacAddress
       << std::endl;
    ss << "    " <<"isShared=" << item.isShared << std::endl;
    ss << "    " <<"lastTrySwitchWifiTimestamp=" << item.lastTrySwitchWifiTimestamp << std::endl;
    ss << "    " <<"isAllowAutoConnect=" << item.isAllowAutoConnect << std::endl;
    ss << "    " <<"isSecurityWifi=" << item.isSecurityWifi << std::endl;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    ss <<OutPutEncryptionDeviceConfig(item);
#else
    ss << "    " <<"preSharedKey=" << item.preSharedKey << std::endl;
    ss << "    " <<"wepTxKeyIndex=" << item.wepTxKeyIndex << std::endl;
    for (int i = 0; i < WEPKEYS_SIZE; ++i) {
        ss << "    " <<"wepKeys_" << i << "=" << item.wepKeys[i] << std::endl;
    }
#endif
    ss << "    " <<"callProcessName=" << item.callProcessName << std::endl;
    ss << "    " <<"ancoCallProcessName=" << item.ancoCallProcessName << std::endl;
    ss << "    " <<"randomizedMacSuccessEver=" << item.randomizedMacSuccessEver << std::endl;
    ss << "    " <<"everConnected=" << item.everConnected << std::endl;
    ss << "    " <<"acceptUnvalidated=" << item.acceptUnvalidated << std::endl;
    ss << "    " <<"macAddress=" << item.macAddress << std::endl;
    ss << "    " <<"lastUpdateTime=" << item.lastUpdateTime << std::endl;
    ss << "    " <<"</WifiDeviceConfig>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiIpConfig(WifiIpConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfigIp>" << std::endl;
    ss << "    " <<"wifiIpConfig.assignMethod=" << (int)item.assignMethod << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.address.family="
       << item.staticIpAddress.ipAddress.address.family << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4="
       << item.staticIpAddress.ipAddress.address.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6="
       << item.staticIpAddress.ipAddress.address.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.prefixLength="
       << item.staticIpAddress.ipAddress.prefixLength << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.flags=" << item.staticIpAddress.ipAddress.flags
       << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.scope=" << item.staticIpAddress.ipAddress.scope
       << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.gateway.family=" << item.staticIpAddress.gateway.family
       << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.gateway.addressIpv4="
       << item.staticIpAddress.gateway.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.gateway.addressIpv6="
       << item.staticIpAddress.gateway.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer1.family="
       << item.staticIpAddress.dnsServer1.family << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4="
       << item.staticIpAddress.dnsServer1.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer1.addressIpv6="
       << item.staticIpAddress.dnsServer1.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer2.family="
       << item.staticIpAddress.dnsServer2.family << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4="
       << item.staticIpAddress.dnsServer2.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer2.addressIpv6="
       << item.staticIpAddress.dnsServer2.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.domains=" << item.staticIpAddress.domains << std::endl;
    ss << "    " <<"</WifiDeviceConfigIp>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiDeviceConfigEap(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    if (item.wifiEapConfig.eap.length() == 0) {
        return ss.str();
    }
    ss << "    " <<"<WifiDeviceConfigEap>" << std::endl;
    ss << "    " <<"wifiEapConfig.eap=" << item.wifiEapConfig.eap << std::endl;
    ss << "    " <<"wifiEapConfig.identity=" << item.wifiEapConfig.identity << std::endl;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    if (item.version == 1) {
        if (!item.wifiEapConfig.encryptedData.empty() && !item.wifiEapConfig.IV.empty()) {
            ss << "    " <<"wifiEapConfig.encryptedData=" << item.wifiEapConfig.encryptedData << std::endl;
            ss << "    " <<"wifiEapConfig.IV=" << item.wifiEapConfig.IV << std::endl;
        } else {
            ss << "    " <<"wifiEapConfig.password=" << item.wifiEapConfig.password << std::endl;
        }
    } else {
        ss << "    " <<"wifiEapConfig.password=" << item.wifiEapConfig.password << std::endl;
    }
#else
    ss << "    " <<"wifiEapConfig.password=" << item.wifiEapConfig.password << std::endl;
#endif
    ss << "    " <<"wifiEapConfig.clientCert=" << item.wifiEapConfig.clientCert << std::endl;
    ss << "    " <<"wifiEapConfig.privateKey=" << item.wifiEapConfig.privateKey << std::endl;
    ss << "    " <<"wifiEapConfig.phase2method=" << static_cast<int>(item.wifiEapConfig.phase2Method) << std::endl;
    ss << "    " <<"</WifiDeviceConfigEap>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiProxyConfig(WifiProxyConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfigProxy>" << std::endl;
    ss << "    " <<"wifiProxyconfig.configureMethod=" << (int)item.configureMethod << std::endl;
    ss << "    " <<"wifiProxyconfig.autoProxyConfig.pacWebAddress="
       << item.autoProxyConfig.pacWebAddress << std::endl;
    ss << "    " <<"wifiProxyconfig.ManualProxyConfig.serverHostName="
       << item.manualProxyConfig.serverHostName << std::endl;
    ss << "    " <<"wifiProxyconfig.ManualProxyConfig.serverPort="
       << item.manualProxyConfig.serverPort << std::endl;
    ss << "    " <<"wifiProxyconfig.ManualProxyConfig.exclusionObjectList="
       << item.manualProxyConfig.exclusionObjectList << std::endl;
    ss << "    " <<"</WifiDeviceConfigProxy>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiDeviceConfigPrivacy(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfigPrivacy>" << std::endl;
    ss << "    " <<"wifiPrivacySetting=" << (int)item.wifiPrivacySetting << std::endl;
    ss << "    " <<"</WifiDeviceConfigPrivacy>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiWapiConfig(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    if (item.keyMgmt != KEY_MGMT_WAPI_CERT && item.keyMgmt != KEY_MGMT_WAPI_PSK) {
        return ss.str();
    }
    ss << "    " <<"<WifiDeviceConfigWapi>" << std::endl;
    if (item.keyMgmt == KEY_MGMT_WAPI_PSK) {
        ss << "    " <<"wifiWapiConfig.wapiPskType=" << item.wifiWapiConfig.wapiPskType << std::endl;
        ss << "    " <<"</WifiDeviceConfigWapi>" << std::endl;
        return ss.str();
    }
    ss << "    " <<"wifiWapiConfig.encryptedAsCertData=" << item.wifiWapiConfig.encryptedAsCertData << std::endl;
    ss << "    " <<"wifiWapiConfig.asCertDataIV=" << item.wifiWapiConfig.asCertDataIV << std::endl;
    ss << "    " <<"wifiWapiConfig.encryptedUserCertData=" << item.wifiWapiConfig.encryptedUserCertData << std::endl;
    ss << "    " <<"wifiWapiConfig.userCertDataIV=" << item.wifiWapiConfig.userCertDataIV << std::endl;
    ss << "    " <<"</WifiDeviceConfigWapi>" << std::endl;
    return ss.str();
}

static std::string OutPutLastDhcpResultsConfig(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<LastDhcpResultsConfig>" << std::endl;
    ss << "    " <<"LastDhcpResults.ipAddress=" << item.lastDhcpResult.ipAddress << std::endl;
    ss << "    " <<"LastDhcpResults.gateway=" << item.lastDhcpResult.gateway << std::endl;
    ss << "    " <<"LastDhcpResults.netmask=" << item.lastDhcpResult.netmask << std::endl;
    ss << "    " <<"LastDhcpResults.primaryDns=" << item.lastDhcpResult.primaryDns << std::endl;
    ss << "    " <<"LastDhcpResults.secondDns=" << item.lastDhcpResult.secondDns << std::endl;
    ss << "    " <<"LastDhcpResults.serverIp=" << item.lastDhcpResult.serverIp << std::endl;
    ss << "    " <<"LastDhcpResults.leaseDuration=" << item.lastDhcpResult.leaseDuration << std::endl;
    ss << "    " <<"</LastDhcpResultsConfig>" << std::endl;
    return ss.str();
}

template<>
std::string OutTClassString<WifiDeviceConfig>(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << OutPutWifiDeviceConfig(item) << OutPutWifiIpConfig(item.wifiIpConfig)
       << OutPutWifiDeviceConfigEap(item) << OutPutWifiProxyConfig(item.wifiProxyconfig)
       << OutPutWifiDeviceConfigPrivacy(item) << OutPutWifiWapiConfig(item)
       << OutPutLastDhcpResultsConfig(item);
    return ss.str();
}

template<>
std::string OutTClassString<WifiRestrictedInfo> (WifiRestrictedInfo &item)
{
    std::ostringstream ss;
    ss << OutPutWifiRestrictedInfoListInfo(item);
    return ss.str();
}
 
template <>
void ClearTClass<WifiRestrictedInfo>(WifiRestrictedInfo &item)
{
    item.ssid.clear();
    item.bssid.clear();
    item.uid = 0;
    item.wifiRestrictedType = MDM_INVALID_LIST;
    return;
}

template<>
void ClearTClass<HotspotConfig>(HotspotConfig &item)
{
    item.SetSsid("");
    item.SetPreSharedKey("");
    item.SetSecurityType(KeyMgmt::NONE);
    item.SetBand(BandType::BAND_NONE);
    item.SetChannel(0);
    item.SetMaxConn(0);
    item.SetIpAddress("");
    item.SetLeaseTime((int)DHCP_LEASE_TIME);
    item.SetRandomMac("");
    return;
}

#ifdef FEATURE_ENCRYPTION_SUPPORT
static int SetWifiHotspotConfigEncrypt(HotspotConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    WifiEncryptionInfo mWifiEncryptionInfo;
    mWifiEncryptionInfo.SetFile(GetTClassName<HotspotConfig>());
    if (key == "encryptedData") {
        item.SetPreSharedKey(value);
    } else if (key == "IV") {
        EncryptedData *encry = new EncryptedData(item.GetPreSharedKey(), value);
        std::string decry = "";
        if (WifiDecryption(mWifiEncryptionInfo, *encry, decry) == HKS_SUCCESS) {
            item.SetPreSharedKey(decry);
        } else {
            WriteWifiEncryptionFailHiSysEvent(ENCRYPTION_EVENT,
                SsidAnonymize(item.GetSsid()), "WPA2_PSK", SOFTAP_MOUDLE_EVENT);
            item.SetPreSharedKey("");
            errorKeyValue++;
        }
        delete encry;
    } else {
        return -1;
    }
    return errorKeyValue;
}
#endif

template<>
int SetTClassKeyValue<HotspotConfig>(HotspotConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    errorKeyValue = SetWifiHotspotConfigEncrypt(item, key, value);
    if (errorKeyValue != -1) {
        return errorKeyValue;
    } else {
        errorKeyValue = 0;
    }
#endif
    std::string tmpValue = value;
    if (key == "ssid") {
        item.SetSsid(value);
    } else if (key == "HexSsid") {
        std::vector<char> vec;
        vec.clear();
        if (HexStringToVec(value, vec) == 0) {
            std::string strSsid(vec.begin(), vec.end());
            item.SetSsid(strSsid);
        } else {
            return -1;
        }
    } else if (key == "preSharedKey") {
        item.SetPreSharedKey(value);
    } else if (key == "securityType") {
        item.SetSecurityType(static_cast<KeyMgmt>(CheckDataLegal(tmpValue)));
    } else if (key == "band") {
        item.SetBand(static_cast<BandType>(CheckDataLegal(tmpValue)));
    } else if (key == "channel") {
        item.SetChannel(CheckDataLegal(tmpValue));
    } else if (key == "maxConn") {
        item.SetMaxConn(CheckDataLegal(tmpValue));
    } else if (key == "ipAddress") {
        item.SetIpAddress(value);
    } else if (key == "leaseTime") {
        item.SetLeaseTime(CheckDataLegal(tmpValue));
    } else if (key == "randomMac") {
        item.SetRandomMac(value);
    } else {
        LOGE("Invalid config key value");
    }
    return errorKeyValue;
}

template<>
std::string GetTClassName<HotspotConfig>()
{
    return "HotspotConfig";
}

template<>
std::string OutTClassString<HotspotConfig>(HotspotConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<HotspotConfig>" << std::endl;
    ss << "    " <<"ssid=" << ValidateString(item.GetSsid()) << std::endl;
    ss << "    " <<"HexSsid=" << ConvertArrayToHex((uint8_t*)&item.GetSsid()[0], item.GetSsid().length()) << std::endl;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    WifiEncryptionInfo mWifiEncryptionInfo;
    mWifiEncryptionInfo.SetFile(GetTClassName<HotspotConfig>());
    EncryptedData encry;
    if (WifiEncryption(mWifiEncryptionInfo, item.GetPreSharedKey(), encry) == HKS_SUCCESS) {
        ss << "    " <<"encryptedData=" << encry.encryptedPassword << std::endl;
        ss << "    " <<"IV=" << encry.IV << std::endl;
    } else {
        WriteWifiEncryptionFailHiSysEvent(DECRYPTION_EVENT,
            SsidAnonymize(item.GetSsid()), "WPA2_PSK", SOFTAP_MOUDLE_EVENT);
        ss << "    " <<"preSharedKey=" << item.GetPreSharedKey() << std::endl;
    }
#else
    ss << "    " <<"preSharedKey=" << item.GetPreSharedKey() << std::endl;
#endif
    ss << "    " <<"securityType=" << static_cast<int>(item.GetSecurityType()) << std::endl;
    ss << "    " <<"band=" << static_cast<int>(item.GetBand()) << std::endl;
    ss << "    " <<"channel=" << item.GetChannel() << std::endl;
    ss << "    " <<"maxConn=" << item.GetMaxConn() << std::endl;
    ss << "    " <<"ipAddress=" << item.GetIpAddress() << std::endl;
    ss << "    " <<"leaseTime=" << static_cast<int>(item.GetLeaseTime()) << std::endl;
    ss << "    " <<"randomMac=" << item.GetRandomMac() << std::endl;
    ss << "    " <<"</HotspotConfig>" << std::endl;
    return ss.str();
}

template<>
void ClearTClass<P2pVendorConfig>(P2pVendorConfig &item)
{
    item.SetRandomMacSupport(false);
    item.SetIsAutoListen(true);
    item.SetDeviceName("");
    item.SetPrimaryDeviceType("");
    item.SetSecondaryDeviceType("");
    return;
}

template<>
int SetTClassKeyValue<P2pVendorConfig>(P2pVendorConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "randomMacSupport") {
        item.SetRandomMacSupport(CheckDataLegal(tmpValue) != 0);
    } else if (key == "autoListen") {
        item.SetIsAutoListen(CheckDataLegal(tmpValue) != 0);
    } else if (key == "deviceName") {
        item.SetDeviceName(value);
    } else if (key == "primaryDeviceType") {
        item.SetPrimaryDeviceType(value);
    } else if (key == "secondaryDeviceType") {
        item.SetSecondaryDeviceType(value);
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template<>
std::string GetTClassName<P2pVendorConfig>()
{
    return "P2pVendorConfig";
}

template<>
std::string OutTClassString<P2pVendorConfig>(P2pVendorConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<P2pVendorConfig>" << std::endl;
    ss << "    " <<"randomMacSupport=" << item.GetRandomMacSupport() << std::endl;
    ss << "    " <<"autoListen=" << item.GetIsAutoListen() << std::endl;
    ss << "    " <<"deviceName=" << item.GetDeviceName() << std::endl;
    ss << "    " <<"primaryDeviceType=" << item.GetPrimaryDeviceType() << std::endl;
    ss << "    " <<"secondaryDeviceType=" << item.GetSecondaryDeviceType() << std::endl;
    ss << "    " <<"</P2pVendorConfig>" << std::endl;
    return ss.str();
}

template<>
void ClearTClass<StationInfo>(StationInfo &item)
{
    item.deviceName.clear();
    item.bssid.clear();
    item.ipAddr.clear();
    return;
}

template<>
int SetTClassKeyValue<StationInfo>(StationInfo &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "deviceName") {
        item.deviceName = value;
    } else if (key == "bssid") {
        item.bssid = value;
    } else if (key == "ipAddr") {
        item.ipAddr = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template<>
std::string GetTClassName<StationInfo>()
{
    return "StationInfo";
}

template<>
std::string OutTClassString<StationInfo>(StationInfo &item)
{
    std::ostringstream ss;
    ss << "    " <<"<StationInfo>" << std::endl;
    ss << "    " <<"deviceName=" << item.deviceName << std::endl;
    ss << "    " <<"bssid=" << item.bssid << std::endl;
    ss << "    " <<"ipAddr=" << item.ipAddr << std::endl;
    ss << "    " <<"</StationInfo>" << std::endl;
    return ss.str();
}

template<>
void ClearTClass<WifiConfig>(WifiConfig &item)
{
    item.scanAlwaysSwitch = false;
    item.staAirplaneMode = static_cast<int>(OperatorWifiType::WIFI_DISABLED);
    item.persistWifiTime = 0;
    item.toggleWifiCaller = 0;
    item.canOpenStaWhenAirplane = false;
    item.openWifiWhenAirplane = false;
    item.wifiDisabledByAirplane = false;
    item.staLastState = 0;
    item.lastAirplaneMode = AIRPLANE_MODE_CLOSE;
    item.savedDeviceAppraisalPriority = PRIORITY_1;
    item.scoretacticsScoreSlope = SCORE_SLOPE;
    item.scoretacticsInitScore = INIT_SCORE;
    item.scoretacticsSameBssidScore = SAME_BSSID_SCORE;
    item.scoretacticsSameNetworkScore = SAME_NETWORK_SCORE;
    item.scoretacticsFrequency5GHzScore = FREQUENCY_5_GHZ_SCORE;
    item.scoretacticsLastSelectionScore = LAST_SELECTION_SCORE;
    item.scoretacticsSecurityScore = SECURITY_SCORE;
    item.scoretacticsNormalScore = NORMAL_SCORE;
    item.whetherToAllowNetworkSwitchover = true;
    item.dhcpIpType = static_cast<int>(DhcpIpType::DHCP_IPTYPE_MIX);
    item.defaultWifiInterface = "wlan0";
    item.preLoadSta = false;
    item.preLoadScan = false;
    item.preLoadAp = false;
    item.preLoadP2p = false;
    item.preLoadAware = false;
    item.supportHwPnoFlag = true;
    item.minRssi2Dot4Ghz = MIN_RSSI_24GHZ;
    item.minRssi5Ghz = MIN_RSSI_5GHZ;
    item.firstRssiLevel2G = RSSI_LEVEL_1_2G;
    item.secondRssiLevel2G = RSSI_LEVEL_2_2G;
    item.thirdRssiLevel2G = RSSI_LEVEL_3_2G;
    item.fourthRssiLevel2G = RSSI_LEVEL_4_2G;
    item.firstRssiLevel5G = RSSI_LEVEL_1_5G;
    item.secondRssiLevel5G = RSSI_LEVEL_2_5G;
    item.thirdRssiLevel5G = RSSI_LEVEL_3_5G;
    item.fourthRssiLevel5G = RSSI_LEVEL_4_5G;
    char dns[DNS_IP_ADDR_LEN + 1] = { 0 };
    if (GetParamValue(WIFI_FIRST_DNS_NAME, 0, dns, DNS_IP_ADDR_LEN) <= 0) {
        LOGE("get WIFI_FIRST_DNS_NAME error");
    }
    item.strDnsBak = dns;
    item.isLoadStabak = true;
    item.scanOnlySwitch = true;
    item.realMacAddress = "";
    item.staApExclusionType = static_cast<int>(StaApExclusionType::INITIAL_TYPE);
    return;
}

using Func = std::function<void(WifiConfig &item, const std::string &value)>;

std::map<std::string, Func> g_wifiConfigSetValueMap = {
    {"scanAlwaysSwitch", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scanAlwaysSwitch = (CheckDataLegal(tmpValue) != 0); /* 0 -> false 1 -> true */
    }},
    {"staAirplaneMode", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.staAirplaneMode = CheckDataLegal(tmpValue);
    }},
    {"persistWifiTime", [](WifiConfig &item, const std::string &value) -> void {
        LOGI("last set Persist Wifi State time is:%{public}s", value.c_str());
        std::string tmpValue = value;
        item.persistWifiTime = CheckDataLegal(tmpValue);
    }},
    {"toggleWifiCaller", [](WifiConfig &item, const std::string &value) -> void {
        LOGI("last toggle wifi caller is:%{public}s", value.c_str());
        std::string tmpValue = value;
        item.toggleWifiCaller = CheckDataLegal(tmpValue);
    }},
    {"canOpenStaWhenAirplane", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.canOpenStaWhenAirplane = (CheckDataLegal(tmpValue) != 0);
    }},
    {"openWifiWhenAirplane", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.openWifiWhenAirplane = (CheckDataLegal(tmpValue) != 0);
    }},
    {"wifiDisabledByAirplane", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.wifiDisabledByAirplane = (CheckDataLegal(tmpValue) != 0);
    }},
    {"staLastState", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.staLastState = CheckDataLegal(tmpValue);
    }},
    {"lastAirplaneMode", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.lastAirplaneMode = CheckDataLegal(tmpValue);
    }},
    {"savedDeviceAppraisalPriority", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.savedDeviceAppraisalPriority = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsScoreSlope", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsScoreSlope = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsInitScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsInitScore = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsSameBssidScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsSameBssidScore = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsSameNetworkScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsSameNetworkScore = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsFrequency5GHzScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsFrequency5GHzScore = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsLastSelectionScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsLastSelectionScore = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsSecurityScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsSecurityScore = CheckDataLegal(tmpValue);
    }},
    {"scoretacticsNormalScore", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scoretacticsNormalScore = CheckDataLegal(tmpValue);
    }},
    {"whetherToAllowNetworkSwitchover", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.whetherToAllowNetworkSwitchover = (CheckDataLegal(tmpValue) != 0);
    }},
    {"dhcpIpType", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.dhcpIpType = CheckDataLegal(tmpValue);
    }},
    {"defaultWifiInterface", [](WifiConfig &item, const std::string &value) -> void {
        item.defaultWifiInterface = value;
    }},
    {"preLoadSta", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.preLoadSta = (CheckDataLegal(tmpValue) != 0);
    }},
    {"preLoadScan", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.preLoadScan = (CheckDataLegal(tmpValue) != 0);
    }},
    {"preLoadAp", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.preLoadAp = (CheckDataLegal(tmpValue) != 0);
    }},
    {"preLoadP2p", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.preLoadP2p = (CheckDataLegal(tmpValue) != 0);
    }},
    {"preLoadAware", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.preLoadAware = (CheckDataLegal(tmpValue) != 0);
    }},
    {"preLoadEnhance", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.preLoadEnhance = (CheckDataLegal(tmpValue) != 0);
    }},
    {"supportHwPnoFlag", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.supportHwPnoFlag = CheckDataLegal(tmpValue);
    }},
    {"minRssi2Dot4Ghz", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.minRssi2Dot4Ghz = CheckDataLegal(tmpValue);
    }},
    {"minRssi5Ghz", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.minRssi5Ghz = CheckDataLegal(tmpValue);
    }},
    {"firstRssiLevel2G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.firstRssiLevel2G = CheckDataLegal(tmpValue);
    }},
    {"secondRssiLevel2G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.secondRssiLevel2G = CheckDataLegal(tmpValue);
    }},
    {"thirdRssiLevel2G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.thirdRssiLevel2G = CheckDataLegal(tmpValue);
    }},
    {"fourthRssiLevel2G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.fourthRssiLevel2G = CheckDataLegal(tmpValue);
    }},
    {"firstRssiLevel5G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.firstRssiLevel5G = CheckDataLegal(tmpValue);
    }},
    {"secondRssiLevel5G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.secondRssiLevel5G = CheckDataLegal(tmpValue);
    }},
    {"thirdRssiLevel5G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.thirdRssiLevel5G = CheckDataLegal(tmpValue);
    }},
    {"fourthRssiLevel5G", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.fourthRssiLevel5G = CheckDataLegal(tmpValue);
    }},
    {"strDnsBak", [](WifiConfig &item, const std::string &value) -> void {
        item.strDnsBak = value;
    }},
    {"isLoadStabak", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.isLoadStabak = (CheckDataLegal(tmpValue) != 0);
    }},
    {"scanOnlySwitch", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.scanOnlySwitch = (CheckDataLegal(tmpValue) != 0);
    }},
    {"realMacAddress", [](WifiConfig &item, const std::string &value) -> void {
        item.realMacAddress = value;
    }},
    {"staApExclusionType", [](WifiConfig &item, const std::string &value) -> void {
        std::string tmpValue = value;
        item.staApExclusionType = CheckDataLegal(tmpValue);
    }}
};
static int SetWifiConfigValue(WifiConfig &item, const std::string &key, const std::string &value)
{
    auto it = g_wifiConfigSetValueMap.find(key);
    if (it == g_wifiConfigSetValueMap.end()) {
        return -1;
    }
    it->second(item, value);
    return 0;
}

template<>
int SetTClassKeyValue<WifiConfig>(WifiConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (SetWifiConfigValue(item, key, value) == 0) {
        return errorKeyValue;
    }
    LOGE("Invalid config key value");
    errorKeyValue++;
    return errorKeyValue;
}

template<>
std::string GetTClassName<WifiConfig>()
{
    return "WifiConfig";
}

template<>
std::string OutTClassString<WifiConfig>(WifiConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiConfig>" << std::endl;
    ss << "    " <<"scanAlwaysSwitch=" << item.scanAlwaysSwitch << std::endl; /* bool false->0 true->1 */
    ss << "    " <<"staAirplaneMode=" << item.staAirplaneMode << std::endl;
    ss << "    " <<"persistWifiTime=" << item.persistWifiTime << std::endl;
    ss << "    " <<"toggleWifiCaller=" << item.toggleWifiCaller << std::endl;
    ss << "    " <<"canOpenStaWhenAirplane=" << item.canOpenStaWhenAirplane << std::endl;
    ss << "    " <<"openWifiWhenAirplane=" << item.openWifiWhenAirplane << std::endl;
    ss << "    " <<"wifiDisabledByAirplane=" << item.wifiDisabledByAirplane << std::endl;
    ss << "    " <<"staLastState=" << item.staLastState << std::endl;
    ss << "    " <<"lastAirplaneMode=" << item.lastAirplaneMode << std::endl;
    ss << "    " <<"savedDeviceAppraisalPriority=" << item.savedDeviceAppraisalPriority << std::endl;
    ss << "    " <<"scoretacticsScoreSlope=" << item.scoretacticsScoreSlope << std::endl;
    ss << "    " <<"scoretacticsInitScore=" << item.scoretacticsInitScore << std::endl;
    ss << "    " <<"scoretacticsSameBssidScore=" << item.scoretacticsSameBssidScore << std::endl;
    ss << "    " <<"scoretacticsSameNetworkScore=" << item.scoretacticsSameNetworkScore << std::endl;
    ss << "    " <<"scoretacticsFrequency5GHzScore=" << item.scoretacticsFrequency5GHzScore << std::endl;
    ss << "    " <<"scoretacticsLastSelectionScore=" << item.scoretacticsLastSelectionScore << std::endl;
    ss << "    " <<"scoretacticsSecurityScore=" << item.scoretacticsSecurityScore << std::endl;
    ss << "    " <<"scoretacticsNormalScore=" << item.scoretacticsNormalScore << std::endl;
    ss << "    " <<"whetherToAllowNetworkSwitchover=" << item.whetherToAllowNetworkSwitchover << std::endl;
    ss << "    " <<"dhcpIpType=" << item.dhcpIpType << std::endl;
    ss << "    " <<"defaultWifiInterface=" << item.defaultWifiInterface << std::endl;
    ss << "    " <<"preLoadSta=" << item.preLoadSta << std::endl;
    ss << "    " <<"preLoadScan=" << item.preLoadScan << std::endl;
    ss << "    " <<"preLoadAp=" << item.preLoadAp << std::endl;
    ss << "    " <<"preLoadP2p=" << item.preLoadP2p << std::endl;
    ss << "    " <<"preLoadAware=" << item.preLoadAware << std::endl;
    ss << "    " <<"supportHwPnoFlag=" << item.supportHwPnoFlag << std::endl;
    ss << "    " <<"minRssi2Dot4Ghz=" << item.minRssi2Dot4Ghz << std::endl;
    ss << "    " <<"minRssi5Ghz=" << item.minRssi5Ghz << std::endl;
    ss << "    " <<"firstRssiLevel2G=" << item.firstRssiLevel2G << std::endl;
    ss << "    " <<"secondRssiLevel2G=" << item.secondRssiLevel2G << std::endl;
    ss << "    " <<"thirdRssiLevel2G=" << item.thirdRssiLevel2G << std::endl;
    ss << "    " <<"fourthRssiLevel2G=" << item.fourthRssiLevel2G << std::endl;
    ss << "    " <<"firstRssiLevel5G=" << item.firstRssiLevel5G << std::endl;
    ss << "    " <<"secondRssiLevel5G=" << item.secondRssiLevel5G << std::endl;
    ss << "    " <<"thirdRssiLevel5G=" << item.thirdRssiLevel5G << std::endl;
    ss << "    " <<"fourthRssiLevel5G=" << item.fourthRssiLevel5G << std::endl;
    ss << "    " <<"strDnsBak=" << item.strDnsBak << std::endl;
    ss << "    " <<"isLoadStabak=" << item.isLoadStabak << std::endl;
    ss << "    " <<"scanOnlySwitch=" << item.scanOnlySwitch << std::endl;
    ss << "    " <<"realMacAddress=" << item.realMacAddress << std::endl;
    ss << "    " <<"staApExclusionType=" << item.staApExclusionType << std::endl;
    ss << "    " <<"</WifiConfig>" << std::endl;
    return ss.str();
}

template<>
void ClearTClass<WifiP2pGroupInfo>(WifiP2pGroupInfo &item)
{
    item.SetIsGroupOwner(false);
    WifiP2pDevice device;
    item.SetOwner(device);
    item.SetPassphrase("");
    item.SetInterface("");
    item.SetGroupName("");
    item.SetFrequency(0);
    item.SetIsPersistent(false);
    item.SetP2pGroupStatus(static_cast<P2pGroupStatus>(0));
    item.SetNetworkId(0);
    item.SetGoIpAddress("");
    item.ClearClientDevices();
}

static int SetWifiP2pDevicClassKeyValue(WifiP2pDevice &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "deviceName") {
        item.SetDeviceName(value);
    } else if (key == "deviceAddress") {
        item.SetDeviceAddress(value);
    } else if (key == "primaryDeviceType") {
        item.SetPrimaryDeviceType(value);
    } else if (key == "status") {
        item.SetP2pDeviceStatus(static_cast<P2pDeviceStatus>(CheckDataLegal(tmpValue)));
    } else if (key == "supportWpsConfigMethods") {
        item.SetWpsConfigMethod(CheckDataLegal(tmpValue));
    } else if (key == "deviceCapabilitys") {
        item.SetDeviceCapabilitys(CheckDataLegal(tmpValue));
    } else if (key == "groupCapabilitys") {
        item.SetGroupCapabilitys(CheckDataLegal(tmpValue));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

#ifdef FEATURE_ENCRYPTION_SUPPORT
static int SetWifiP2pGroupInfoEncrypt(WifiP2pGroupInfo &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    WifiEncryptionInfo mWifiEncryptionInfo;
    mWifiEncryptionInfo.SetFile(GetTClassName<WifiP2pGroupInfo>());
    if (key == "encryptedData") {
        item.SetPassphrase(value);
    } else if (key == "IV") {
        EncryptedData *encry = new EncryptedData(item.GetPassphrase(), value);
        std::string decry = "";
        if (WifiDecryption(mWifiEncryptionInfo, *encry, decry) == HKS_SUCCESS) {
            item.SetPassphrase(decry);
        } else {
            item.SetPassphrase("");
            errorKeyValue++;
        }
        delete encry;
    } else {
        return -1;
    }
    return errorKeyValue;
}
#endif

static int SetWifiP2pGroupInfoDev(WifiP2pGroupInfo &item, const std::string &key, const std::string &value)
{
    if (key.compare(0, strlen(OWNER_DEV_PREFIX_NAME), OWNER_DEV_PREFIX_NAME) == 0) {
        WifiP2pDevice owner = item.GetOwner();
        SetWifiP2pDevicClassKeyValue(owner, key.substr(strlen(OWNER_DEV_PREFIX_NAME)), value);
        item.SetOwner(owner);
    } else if (key.compare(0, strlen(CLIENT_PREFIX_NAME), CLIENT_PREFIX_NAME) == 0) {
        std::string::size_type pos = key.find(".");
        if (pos == std::string::npos) {
            WifiP2pDevice device;
            item.AddPersistentDevice(device);
        } else {
            std::string keyTmp = key.substr(strlen(CLIENT_PREFIX_NAME), (pos - strlen(CLIENT_PREFIX_NAME)));
            unsigned long index = static_cast<unsigned long>(CheckDataLegal(keyTmp));
            if (index < item.GetPersistentDevices().size()) {
                std::vector<WifiP2pDevice> clients = item.GetPersistentDevices();
                SetWifiP2pDevicClassKeyValue(clients[index], key.substr(pos + 1), value);
                item.SetPersistentDevices(clients);
            }
        }
    } else {
        return -1;
    }
    return 0;
}

template<>
int SetTClassKeyValue<WifiP2pGroupInfo>(WifiP2pGroupInfo &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    errorKeyValue = SetWifiP2pGroupInfoEncrypt(item, key, value);
    if (errorKeyValue != -1) {
        return errorKeyValue;
    } else {
        errorKeyValue = 0;
    }
#endif
    std::string tmpValue = value;
    if (key == "isGroupOwner") {
        item.SetIsGroupOwner(CheckDataLegal(tmpValue) != 0);
    } else if (key == "passphrase") {
        item.SetPassphrase(value);
    } else if (key == "interface") {
        item.SetInterface(value);
    } else if (key == "groupName") {
        item.SetGroupName(value);
    } else if (key == "groupNameHex") {
        std::vector<char> vec;
        vec.clear();
        if (HexStringToVec(value, vec) == 0) {
            std::string strSsid(vec.begin(), vec.end());
            item.SetGroupName(strSsid);
        } else {
            return -1;
        }
    } else if (key == "networkId") {
        item.SetNetworkId(CheckDataLegal(tmpValue));
    } else if (key == "frequency") {
        item.SetFrequency(CheckDataLegal(tmpValue));
    } else if (key == "isPersistent") {
        item.SetIsPersistent(CheckDataLegal(tmpValue) != 0);
    } else if (key == "groupStatus") {
        item.SetP2pGroupStatus(static_cast<P2pGroupStatus>(CheckDataLegal(tmpValue)));
    } else if (key == "goIpAddress") {
        item.SetGoIpAddress(value);
    } else if (SetWifiP2pGroupInfoDev(item, key, value) == 0) {
        return errorKeyValue;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template<>
std::string GetTClassName<WifiP2pGroupInfo>()
{
    return "WifiP2pGroupInfo";
}

static std::string OutWifiP2pDeviceClassString(const WifiP2pDevice &item, const std::string prefix = "")
{
    std::ostringstream ss;

    ss << "    " <<prefix << "deviceName=" << item.GetDeviceName() << std::endl;
    ss << "    " <<prefix << "deviceAddress=" << item.GetDeviceAddress() << std::endl;
    ss << "    " <<prefix << "primaryDeviceType=" << item.GetPrimaryDeviceType() << std::endl;
    ss << "    " <<prefix << "status=" << static_cast<int>(item.GetP2pDeviceStatus()) << std::endl;
    ss << "    " <<prefix << "supportWpsConfigMethods=" << item.GetWpsConfigMethod() << std::endl;
    ss << "    " <<prefix << "deviceCapabilitys=" << item.GetDeviceCapabilitys() << std::endl;
    ss << "    " <<prefix << "groupCapabilitys=" << item.GetGroupCapabilitys() << std::endl;

    return ss.str();
}

template<>
std::string OutTClassString<WifiP2pGroupInfo>(WifiP2pGroupInfo &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiP2pGroupInfo>" << std::endl;
    ss << "    " <<"groupName=" << ValidateString(item.GetGroupName()) << std::endl;
    ss << "    " <<"groupNameHex="
       << ConvertArrayToHex((uint8_t*)&item.GetGroupName()[0], item.GetGroupName().length()) << std::endl;
    ss << "    " <<"networkId=" << item.GetNetworkId() << std::endl;
    ss << "    " <<"isGroupOwner=" << item.IsGroupOwner() << std::endl;
    ss << "    " <<"interface=" << item.GetInterface() << std::endl;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    WifiEncryptionInfo mWifiEncryptionInfo;
    mWifiEncryptionInfo.SetFile(GetTClassName<WifiP2pGroupInfo>());
    EncryptedData encry;
    if (WifiEncryption(mWifiEncryptionInfo, item.GetPassphrase(), encry) == HKS_SUCCESS) {
        ss << "    " <<"encryptedData=" << encry.encryptedPassword << std::endl;
        ss << "    " <<"IV=" << encry.IV << std::endl;
    } else {
        ss << "    " <<"passphrase=" << item.GetPassphrase() << std::endl;
    }
#else
    ss << "    " <<"passphrase=" << item.GetPassphrase() << std::endl;
#endif
    ss << "    " <<"frequency=" << item.GetFrequency() << std::endl;
    ss << "    " <<"isPersistent=" << item.IsPersistent() << std::endl;
    ss << "    " <<"groupStatus=" << static_cast<int>(item.GetP2pGroupStatus()) << std::endl;
    ss << "    " <<"goIpAddress=" << item.GetGoIpAddress() << std::endl;
    ss << OutWifiP2pDeviceClassString(item.GetOwner(), "ownerDev.");
    unsigned int size = item.GetPersistentDevices().size();
    for (unsigned int i = 0; i < size; i++) {
        std::string prefix = "vecDev_" + std::to_string(i) + ".";
        ss << "    " <<"vecDev_=" << i << std::endl;
        const WifiP2pDevice &tmp = item.GetPersistentDevices().at(i);
        ss << OutWifiP2pDeviceClassString(tmp, prefix);
    }
    ss << "    " <<"</WifiP2pGroupInfo>" << std::endl;
    return ss.str();
}

template <>
void ClearTClass<TrustListPolicy>(TrustListPolicy &item)
{
    item.sceneId = 0;
    item.sceneName.clear();
    item.trustList.clear();
    return;
}

template <>
int SetTClassKeyValue<TrustListPolicy>(TrustListPolicy &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "sceneId") {
        item.sceneId = CheckDataLegal(tmpValue);
    } else if (key == "sceneName") {
        item.sceneName = value;
    } else if (key == "trustList") {
        item.trustList = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template <>
std::string GetTClassName<TrustListPolicy>()
{
    return "TrustListPolicy";
}

template <> std::string OutTClassString<TrustListPolicy>(TrustListPolicy &item)
{
    std::ostringstream ss;
    ss << "    " <<"<TrustListPolicy>" << std::endl;
    ss << "    " <<"sceneId=" << item.sceneId << std::endl;
    ss << "    " <<"sceneName=" << item.sceneName << std::endl;
    ss << "    " <<"trustList=" << item.trustList << std::endl;
    ss << "    " <<"</TrustListPolicy>" << std::endl;
    return ss.str();
}

template <> void ClearTClass<MovingFreezePolicy>(MovingFreezePolicy &item)
{
    item.trustList.clear();
    return;
}

template <>
int SetTClassKeyValue<MovingFreezePolicy>(MovingFreezePolicy &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "trustList") {
        item.trustList = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template <> std::string GetTClassName<MovingFreezePolicy>()
{
    return "MovingFreezePolicy";
}

template <> std::string OutTClassString<MovingFreezePolicy>(MovingFreezePolicy &item)
{
    std::ostringstream ss;
    ss << "    " <<"<MovingFreezePolicy>" << std::endl;
    ss << "    " <<"trustList=" << item.trustList << std::endl;
    ss << "    " <<"<MovingFreezePolicy>" << std::endl;
    return ss.str();
}

template <> void ClearTClass<WifiStoreRandomMac>(WifiStoreRandomMac &item)
{
    item.version = -1;
    item.ssid.clear();
    item.keyMgmt.clear();
    item.peerBssid.clear();
    item.randomMac.clear();
    item.preSharedKey.clear();
    std::string().swap(item.preSharedKey);
    item.fuzzyBssids.clear();
    return;
}

static void SetWifiStoreRandomMacFuzzyBssids(WifiStoreRandomMac &item, const std::string &value)
{
    item.fuzzyBssids.clear();
    if (!IsPskEncryption(item.keyMgmt)) {
        item.fuzzyBssids.clear();
        return;
    }

    std::vector<std::string> fuzzyBssids;
    SplitString(value, "|", fuzzyBssids);
    if (fuzzyBssids.empty()) {
        return;
    }
    int tmpMax;
    switch (item.version) {
        case -1:
            tmpMax = 1;
            break;
        default:
            tmpMax = FUZZY_BSSID_MAX_MATCH_CNT;
            break;
    }
    if (fuzzyBssids.size() > FUZZY_BSSID_MAX_MATCH_CNT) {
        int i = 0;
        std::vector<std::string>::reverse_iterator rIter;
        for (rIter = fuzzyBssids.rbegin(); rIter != fuzzyBssids.rend(); ++rIter) {
            item.fuzzyBssids.insert(*rIter);
            i++;
            if (i >= tmpMax) {
                break;
            }
        }
    } else {
        for (auto &it: fuzzyBssids) {
            item.fuzzyBssids.insert(it);
        }
    }
    fuzzyBssids.clear();
}

template <>
int SetTClassKeyValue<WifiStoreRandomMac>(WifiStoreRandomMac &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    std::string tmpValue = value;
    if (key == "version") {
        item.version = CheckDataLegal(tmpValue);
    } else if (key == "ssid") {
        item.ssid = value;
    } else if (key == "HexSsid") {
        std::vector<char> vec;
        vec.clear();
        if (HexStringToVec(value, vec) == 0) {
            std::string strSsid(vec.begin(), vec.end());
            item.ssid = strSsid;
        } else {
            return -1;
        }
    } else if (key == "keyMgmt") {
        item.keyMgmt = value;
    } else if (key == "peerBssid") {
        item.peerBssid = value;
    } else if (key == "randomMac") {
        item.randomMac = value;
    } else if (key == "fuzzyBssids") {
        SetWifiStoreRandomMacFuzzyBssids(item, value);
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template <> std::string GetTClassName<WifiStoreRandomMac>()
{
    return "WifiStoreRandomMac";
}

static std::string OutWifiStoreRandomMacBssids(const std::unordered_set<std::string> &bssids,
    const std::string prefix = "|")
{
    std::ostringstream ss;
    size_t count = bssids.size();
    if (count > FUZZY_BSSID_MAX_MATCH_CNT) {
        LOGE("%{public}s fuzzyBssids.size:%{public}zu is bigger than %{public}d",
            __func__, count, FUZZY_BSSID_MAX_MATCH_CNT);
    }
    size_t index = 0;
    for (const auto &item: bssids) {
        if (index != count -1) {
            ss << item << prefix;
        } else {
            ss << item << std::endl;
        }
        index++;
        if (index >= FUZZY_BSSID_MAX_MATCH_CNT) {
            break;
        }
    }
    return ss.str();
}

template <> std::string OutTClassString<WifiStoreRandomMac>(WifiStoreRandomMac &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiStoreRandomMac>" << std::endl;
    ss << "    " <<"version=" << item.version << std::endl;
    ss << "    " <<"ssid=" << ValidateString(item.ssid) << std::endl;
    ss << "    " <<"HexSsid=" << ConvertArrayToHex((uint8_t*)&item.ssid[0], item.ssid.length()) << std::endl;
    ss << "    " <<"keyMgmt=" << item.keyMgmt << std::endl;
    ss << "    " <<"peerBssid=" << item.peerBssid << std::endl;
    ss << "    " <<"randomMac=" << item.randomMac << std::endl;
    ss << "    " <<"fuzzyBssids=" << OutWifiStoreRandomMacBssids(item.fuzzyBssids) << std::endl;
    ss << "    " <<"<WifiStoreRandomMac>" << std::endl;
    return ss.str();
}

int SetNetworkStatusHistory(WifiDeviceConfig &item, const std::string &value)
{
    std::string tmpValue = value;
    item.networkStatusHistory = static_cast<unsigned int>(CheckDataLegal(tmpValue));
    return 0;
}

int SetIsPortal(WifiDeviceConfig &item, const std::string &value)
{
    std::string tmpValue = value;
    item.isPortal = CheckDataLegal(tmpValue);
    return 0;
}

int SetLastHasInternetTime(WifiDeviceConfig &item, const std::string &value)
{
    std::string tmpValue = value;
    item.lastHasInternetTime = CheckDataLegal(tmpValue);
    return 0;
}

int SetNoInternetAccess(WifiDeviceConfig &item, const std::string &value)
{
    std::string tmpValue = value;
    item.noInternetAccess = CheckDataLegal(tmpValue);
    return 0;
}

#ifndef OHOS_ARCH_LITE
static void ClearWifiBackupConfig(WifiBackupConfig &item)
{
    item.instanceId = 0;
    item.uid = -1;
    item.bssid.clear();
    item.userSelectBssid.clear();
    item.ssid.clear();
    item.priority = 0;
    item.hiddenSSID = false;
    item.keyMgmt.clear();
    item.keyMgmtBitset = 0;
    item.networkStatusHistory = 0;
    item.isPortal = false;
    item.lastHasInternetTime = -1;
    item.noInternetAccess = false;
    item.preSharedKey.clear();
    std::string().swap(item.preSharedKey);
    item.wepTxKeyIndex = 0;
    for (int i = 0; i < WEPKEYS_SIZE; ++i) {
        item.wepKeys[i].clear();
    }
    return;
}

static void ClearWifiBackupConfigPrivacy(WifiBackupConfig &item)
{
    item.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
    return;
}

static int SetWifiBackupConfigFirst(WifiBackupConfig &item, const std::string &key, const std::string &value)
{
    std::string tmpValue = value;
    if (key == "instanceId") {
        item.instanceId = CheckDataLegal(tmpValue);
    } else if (key == "uid") {
        item.uid = CheckDataLegal(tmpValue);
    } else if (key == "status") {
        //@deprecated
    } else if (key == "bssid") {
        item.bssid = value;
    } else if (key == "userSelectBssid") {
        item.userSelectBssid = value;
    } else if (key == "ssid") {
        item.ssid = value;
    } else if (key == "HexSsid") {
        std::vector<char> vec;
        vec.clear();
        if (HexStringToVec(value, vec) == 0) {
            std::string strSsid(vec.begin(), vec.end());
            item.ssid = strSsid;
        }
    } else if (key == "priority") {
        item.priority = CheckDataLegal(tmpValue);
    } else if (key == "hiddenSSID") {
        item.hiddenSSID = CheckDataLegal(tmpValue);
    } else if (key == "keyMgmt") {
        item.keyMgmt = value;
    } else if (key == "keyMgmtBitset") {
        item.keyMgmtBitset = static_cast<uint32_t>(CheckDataLegal(tmpValue));
    } else if (key == "isAllowAutoConnect") {
        item.isAllowAutoConnect = CheckDataLegal(tmpValue);
    } else {
        return -1;
    }
    return 0;
}

static int SetWifiBackupConfig(WifiBackupConfig &item, const std::string &key, const std::string &value)
{
    if (SetWifiBackupConfigFirst(item, key, value) == 0) {
        return 0;
    }
    std::string tmpValue = value;
    if (key == "networkStatusHistory") {
        item.networkStatusHistory = static_cast<unsigned int>(CheckDataLegal(tmpValue));
    } else if (key == "isPortal") {
        item.isPortal = CheckDataLegal(tmpValue);
    } else if (key == "lastHasInternetTime") {
        item.lastHasInternetTime = CheckDataLegal(tmpValue);
    } else if (key == "noInternetAccess") {
        item.noInternetAccess = CheckDataLegal(tmpValue);
    } else if (key == "preSharedKey") {
        item.preSharedKey = value;
    } else if (key == "wepTxKeyIndex") {
        item.wepTxKeyIndex = CheckDataLegal(tmpValue);
    } else if (key.compare(0, strlen("wepKeys"), "wepKeys") == 0) {
        std::string keyTmp = key.substr(strlen("wepKeys") + 1);
        int pos = CheckDataLegal(keyTmp);
        if (pos >= 0 && pos < WEPKEYS_SIZE) {
            item.wepKeys[pos] = value;
        }
    } else {
        LOGE("Invalid config key value.");
    }
    return 0;
}

static int SetWifiBackupConfigPrivacy(WifiBackupConfig &item, const std::string &key, const std::string &value)
{
    std::string tmpValue = value;
    if (key == "wifiPrivacySetting") {
        item.wifiPrivacySetting = WifiPrivacyConfig(CheckDataLegal(tmpValue));
    } else {
        LOGE("Invalid config key value");
    }
    return 0;
}

static std::string OutPutWifiBackupConfig(WifiBackupConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfig>" << std::endl;
    ss << "    " <<"instanceId=" << item.instanceId << std::endl;
    ss << "    " <<"uid=" << item.uid << std::endl;
    ss << "    " <<"bssid=" << item.bssid << std::endl;
    ss << "    " <<"userSelectBssid=" << item.userSelectBssid << std::endl;
    ss << "    " <<"ssid=" << ValidateString(item.ssid) << std::endl;
    ss << "    " <<"HexSsid=" << ConvertArrayToHex((uint8_t*)&item.ssid[0], item.ssid.length()) << std::endl;
    ss << "    " <<"priority=" << item.priority << std::endl;
    ss << "    " <<"hiddenSSID=" << (int)item.hiddenSSID << std::endl;
    ss << "    " <<"keyMgmt=" << item.keyMgmt << std::endl;
    ss << "    " <<"keyMgmtBitset=" << item.keyMgmtBitset << std::endl;
    ss << "    " <<"networkStatusHistory=" << item.networkStatusHistory << std::endl;
    ss << "    " <<"isPortal=" << item.isPortal << std::endl;
    ss << "    " <<"lastHasInternetTime=" << item.lastHasInternetTime << std::endl;
    ss << "    " <<"noInternetAccess=" << item.noInternetAccess << std::endl;
    ss << "    " <<"preSharedKey=" << item.preSharedKey << std::endl;
    ss << "    " <<"isAllowAutoConnect=" << item.isAllowAutoConnect << std::endl;
    ss << "    " <<"wepTxKeyIndex=" << item.wepTxKeyIndex << std::endl;
    for (int i = 0; i < WEPKEYS_SIZE; ++i) {
        ss << "    " <<"wepKeys_" << i << "=" << item.wepKeys[i] << std::endl;
    }
    ss << "    " <<"</WifiDeviceConfig>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiBackupConfigPrivacy(WifiBackupConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfigPrivacy>" << std::endl;
    ss << "    " <<"wifiPrivacySetting=" << (int)item.wifiPrivacySetting << std::endl;
    ss << "    " <<"</WifiDeviceConfigPrivacy>" << std::endl;
    return ss.str();
}

template <>
void ClearTClass<WifiBackupConfig>(WifiBackupConfig &item)
{
    ClearWifiBackupConfig(item);
    ClearWifiIpConfig(item.wifiIpConfig);
    ClearWifiProxyConfig(item.wifiProxyconfig);
    ClearWifiBackupConfigPrivacy(item);
    return;
}

template <>
int SetTClassKeyValue<WifiBackupConfig>(WifiBackupConfig &item, const std::string &key, const std::string &value)
{
    if (key.compare(0, strlen("wifiIpConfig"), "wifiIpConfig") == 0) {
        SetWifiIpConfig(item.wifiIpConfig, key, value);
    } else if (key.compare(0, strlen("wifiProxyconfig"), "wifiProxyconfig") == 0) {
        SetWifiProxyConfig(item.wifiProxyconfig, key, value);
    } else if (key.compare(0, strlen("wifiPrivacySetting"), "wifiPrivacySetting") == 0) {
        SetWifiBackupConfigPrivacy(item, key, value);
    } else {
        SetWifiBackupConfig(item, key, value);
    }
    return 0;
}

template <>
std::string GetTClassName<WifiBackupConfig>()
{
    return "WifiBackupConfig";
}

template <>
std::string OutTClassString<WifiBackupConfig>(WifiBackupConfig &item)
{
    std::ostringstream ss;
    ss << OutPutWifiBackupConfig(item) << OutPutWifiIpConfig(item.wifiIpConfig)
       << OutPutWifiProxyConfig(item.wifiProxyconfig) << OutPutWifiBackupConfigPrivacy(item);
    return ss.str();
}
#endif
}  // namespace Wifi
}  // namespace OHOS
