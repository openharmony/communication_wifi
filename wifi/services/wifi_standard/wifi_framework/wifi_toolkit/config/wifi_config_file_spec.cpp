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
#include "wifi_global_func.h"
#ifdef FEATURE_ENCRYPTION_SUPPORT
#include "wifi_encryption_util.h"
#endif
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
static void ClearWifiDeviceConfig(WifiDeviceConfig &item)
{
    item.instanceId = 0;
    item.networkId = 0;
    item.status = 0;
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
    for (int i = 0; i < WEPKEYS_SIZE; ++i) {
        item.wepKeys[i].clear();
    }
    item.wepTxKeyIndex = 0;
    item.priority = 0;
    item.hiddenSSID = false;
    item.lastConnectTime = -1;
    item.numRebootsSinceLastUse = 0;
    item.numAssociation = 0;
    item.networkStatusHistory = 0;
    item.isPortal = false;
    item.lastHasInternetTime = -1;
    item.noInternetAccess = false;
    item.callProcessName.clear();
    item.ancoCallProcessName.clear();
    item.internetSelfCureHistory.clear();
    item.isReassocSelfCureWithFactoryMacAddress = 0;
    return;
}

static void ClearWifiDeviceConfigIp(WifiDeviceConfig &item)
{
    item.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
    item.wifiIpConfig.staticIpAddress.ipAddress.address.family = 0;
    item.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4 = 0;
    item.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6.clear();
    item.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = 0;
    item.wifiIpConfig.staticIpAddress.ipAddress.flags = 0;
    item.wifiIpConfig.staticIpAddress.ipAddress.scope = 0;
    item.wifiIpConfig.staticIpAddress.gateway.family = 0;
    item.wifiIpConfig.staticIpAddress.gateway.addressIpv4 = 0;
    item.wifiIpConfig.staticIpAddress.gateway.addressIpv6.clear();
    item.wifiIpConfig.staticIpAddress.dnsServer1.family = 0;
    item.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4 = 0;
    item.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv6.clear();
    item.wifiIpConfig.staticIpAddress.dnsServer2.family = 0;
    item.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4 = 0;
    item.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv6.clear();
    item.wifiIpConfig.staticIpAddress.domains.clear();
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

static void ClearWifiDeviceConfigProxy(WifiDeviceConfig &item)
{
    item.wifiProxyconfig.configureMethod = ConfigureProxyMethod::CLOSED;
    item.wifiProxyconfig.autoProxyConfig.pacWebAddress.clear();
    item.wifiProxyconfig.manualProxyConfig.serverHostName.clear();
    item.wifiProxyconfig.manualProxyConfig.serverPort = 0;
    item.wifiProxyconfig.manualProxyConfig.exclusionObjectList.clear();
    return;
}

static void ClearWifiDeviceConfigPrivacy(WifiDeviceConfig &item)
{
    item.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
    return;
}

template<>
void ClearTClass<WifiDeviceConfig>(WifiDeviceConfig &item)
{
    ClearWifiDeviceConfig(item);
    ClearWifiDeviceConfigIp(item);
    ClearWifiDeviceConfigEap(item);
    ClearWifiDeviceConfigProxy(item);
    ClearWifiDeviceConfigPrivacy(item);
    return;
}

static int SetWifiDeviceConfigOutDated(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    if (key == "band") {
        item.band = std::stoi(value);
    } else if (key == "channel") {
        item.channel = std::stoi(value);
    } else if (key == "level") {
        item.level = std::stoi(value);
    } else if (key == "isEphemeral") {
        item.isEphemeral = std::stoi(value);
    } else {
        return -1;
    }
    return 0;
}

static int SetWifiDeviceConfigExternal(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    if (key == "numRebootsSinceLastUse") {
        item.numRebootsSinceLastUse = std::stoi(value);
    } else if (key == "numAssociation") {
        item.numAssociation = std::stoi(value);
    } else if (key == "networkStatusHistory") {
        item.networkStatusHistory = std::stoi(value);
    } else if (key == "isPortal") {
        item.isPortal = std::stoi(value);
    } else if (key == "lastHasInternetTime") {
        item.lastHasInternetTime = std::stol(value);
    } else if (key == "noInternetAccess") {
        item.noInternetAccess = std::stoi(value);
    } else if (key == "internetSelfCureHistory") {
        item.internetSelfCureHistory = value;
    } else if (key == "isReassocSelfCureWithFactoryMacAddress") {
        item.isReassocSelfCureWithFactoryMacAddress = std::stoi(value);
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

    if (key == "instanceId") {
        item.instanceId = std::stoi(value);
    } else if (key == "networkId") {
        item.networkId = std::stoi(value);
    } else if (key == "status") {
        item.status = std::stoi(value);
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
        item.frequency = std::stoi(value);
    } else if (key == "isPasspoint") {
        item.isPasspoint = std::stoi(value);
    } else if (key == "preSharedKey") {
        item.preSharedKey = value;
    } else if (key == "keyMgmt") {
        item.keyMgmt = value;
    } else if (key == "wepTxKeyIndex") {
        item.wepTxKeyIndex = std::stoi(value);
    } else if (key == "priority") {
        item.priority = std::stoi(value);
    } else if (key == "uid") {
        item.uid = std::stoi(value);
    } else if (key == "lastConnectTime") {
        item.lastConnectTime = std::stol(value);
    } else if (key == "callProcessName") {
        item.callProcessName = value;
    } else if (key == "ancoCallProcessName") {
        item.ancoCallProcessName = value;
    } else if (key == "version") {
        item.version = std::stoi(value);
    } else if (key == "randomizedMacSuccessEver") {
        item.randomizedMacSuccessEver = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
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
        item.encryptedData = value;
    } else if (key == "IV") {
        item.IV = value;
    } else if (key.compare(0, strlen("encryWepKeys"), "encryWepKeys") == 0) {
        int pos = std::stoi(key.substr(strlen("encryWepKeys") + 1));
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
    if (key == "hiddenSSID") {
        item.hiddenSSID = std::stoi(value);
    } else if (key.compare(0, strlen("wepKeys"), "wepKeys") == 0) {
        int pos = std::stoi(key.substr(strlen("wepKeys") + 1));
        if (pos >= 0 && pos < WEPKEYS_SIZE) {
            item.wepKeys[pos] = value;
        }
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiDeviceConfigIp(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "wifiIpConfig.assignMethod") {
        item.wifiIpConfig.assignMethod = AssignIpMethod(std::stoi(value));
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.address.family") {
        item.wifiIpConfig.staticIpAddress.ipAddress.address.family = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4") {
        item.wifiIpConfig.staticIpAddress.ipAddress.address.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6") {
        item.wifiIpConfig.staticIpAddress.ipAddress.address.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.prefixLength") {
        item.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.flags") {
        item.wifiIpConfig.staticIpAddress.ipAddress.flags = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.ipAddress.scope") {
        item.wifiIpConfig.staticIpAddress.ipAddress.scope = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.gateway.family") {
        item.wifiIpConfig.staticIpAddress.gateway.family = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.gateway.addressIpv4") {
        item.wifiIpConfig.staticIpAddress.gateway.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.gateway.addressIpv6") {
        item.wifiIpConfig.staticIpAddress.gateway.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer1.family") {
        item.wifiIpConfig.staticIpAddress.dnsServer1.family = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4") {
        item.wifiIpConfig.staticIpAddress.dnsServer1.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer1.addressIpv6") {
        item.wifiIpConfig.staticIpAddress.dnsServer1.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer2.family") {
        item.wifiIpConfig.staticIpAddress.dnsServer2.family = std::stoi(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4") {
        item.wifiIpConfig.staticIpAddress.dnsServer2.SetIpv4Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.dnsServer2.addressIpv6") {
        item.wifiIpConfig.staticIpAddress.dnsServer2.SetIpv6Address(value);
    } else if (key == "wifiIpConfig.staticIpAddress.domains") {
        item.wifiIpConfig.staticIpAddress.domains = value;
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
        item.wifiEapConfig.phase2Method = Phase2Method(std::stoi(value));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiDeviceConfigProxy(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "wifiProxyconfig.configureMethod") {
        item.wifiProxyconfig.configureMethod = ConfigureProxyMethod(std::stoi(value));
    } else if (key == "wifiProxyconfig.autoProxyConfig.pacWebAddress") {
        item.wifiProxyconfig.autoProxyConfig.pacWebAddress = value;
    } else if (key == "wifiProxyconfig.ManualProxyConfig.serverHostName") {
        item.wifiProxyconfig.manualProxyConfig.serverHostName = value;
    } else if (key == "wifiProxyconfig.ManualProxyConfig.serverPort") {
        item.wifiProxyconfig.manualProxyConfig.serverPort = std::stoi(value);
    } else if (key == "wifiProxyconfig.ManualProxyConfig.exclusionObjectList") {
        item.wifiProxyconfig.manualProxyConfig.exclusionObjectList = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

static int SetWifiDeviceconfigPrivacy(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "wifiPrivacySetting") {
        item.wifiPrivacySetting = WifiPrivacyConfig(std::stoi(value));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template<>
int SetTClassKeyValue<WifiDeviceConfig>(WifiDeviceConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key.compare(0, strlen("wifiIpConfig"), "wifiIpConfig") == 0) {
        errorKeyValue += SetWifiDeviceConfigIp(item, key, value);
    } else if (key.compare(0, strlen("wifiEapConfig"), "wifiEapConfig") == 0) {
        errorKeyValue += SetWifiDeviceConfigEap(item, key, value);
    } else if (key.compare(0, strlen("wifiProxyconfig"), "wifiProxyconfig") == 0) {
        errorKeyValue += SetWifiDeviceConfigProxy(item, key, value);
    } else if (key.compare(0, strlen("wifiPrivacySetting"), "wifiPrivacySetting") == 0) {
        errorKeyValue += SetWifiDeviceconfigPrivacy(item, key, value);
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

static std::string OutPutWifiDeviceConfig(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfig>" << std::endl;
    ss << "    " <<"version=" << item.version << std::endl;
    ss << "    " <<"instanceId=" << item.instanceId << std::endl;
    ss << "    " <<"uid=" << item.uid << std::endl;
    ss << "    " <<"status=" << item.status << std::endl;
    ss << "    " <<"bssid=" << item.bssid << std::endl;
    ss << "    " <<"userSelectBssid=" << item.userSelectBssid << std::endl;
    ss << "    " <<"ssid=" << ValidateString(item.ssid) << std::endl;
    ss << "    " <<"HexSsid=" << ConvertArrayToHex((uint8_t*)&item.ssid[0], item.ssid.length()) << std::endl;
    ss << "    " <<"frequency=" << item.frequency << std::endl;
    ss << "    " <<"isPasspoint=" << item.isPasspoint << std::endl;
    ss << "    " <<"priority=" << item.priority << std::endl;
    ss << "    " <<"hiddenSSID=" << (int)item.hiddenSSID << std::endl;
    ss << "    " <<"keyMgmt=" << item.keyMgmt << std::endl;
    ss << "    " <<"lastConnectTime=" << item.lastConnectTime << std::endl;
    ss << "    " <<"numRebootsSinceLastUse=" << item.numRebootsSinceLastUse << std::endl;
    ss << "    " <<"numAssociation=" << item.numAssociation << std::endl;
    ss << "    " <<"networkStatusHistory=" << item.networkStatusHistory << std::endl;
    ss << "    " <<"isPortal=" << item.isPortal << std::endl;
    ss << "    " <<"lastHasInternetTime=" << item.lastHasInternetTime << std::endl;
    ss << "    " <<"noInternetAccess=" << item.noInternetAccess << std::endl;
    ss << "    " <<"internetSelfCureHistory=" << item.internetSelfCureHistory << std::endl;
    ss << "    " <<"isReassocSelfCureWithFactoryMacAddress=" << item.isReassocSelfCureWithFactoryMacAddress
       << std::endl;
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
    ss << "    " <<"</WifiDeviceConfig>" << std::endl;
    return ss.str();
}

static std::string OutPutWifiDeviceConfigIp(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfigIp>" << std::endl;
    ss << "    " <<"wifiIpConfig.assignMethod=" << (int)item.wifiIpConfig.assignMethod << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.address.family="
       << item.wifiIpConfig.staticIpAddress.ipAddress.address.family << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4="
       << item.wifiIpConfig.staticIpAddress.ipAddress.address.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv6="
       << item.wifiIpConfig.staticIpAddress.ipAddress.address.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.prefixLength="
       << item.wifiIpConfig.staticIpAddress.ipAddress.prefixLength << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.flags=" << item.wifiIpConfig.staticIpAddress.ipAddress.flags
       << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.ipAddress.scope=" << item.wifiIpConfig.staticIpAddress.ipAddress.scope
       << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.gateway.family=" << item.wifiIpConfig.staticIpAddress.gateway.family
       << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.gateway.addressIpv4="
       << item.wifiIpConfig.staticIpAddress.gateway.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.gateway.addressIpv6="
       << item.wifiIpConfig.staticIpAddress.gateway.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer1.family="
       << item.wifiIpConfig.staticIpAddress.dnsServer1.family << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4="
       << item.wifiIpConfig.staticIpAddress.dnsServer1.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer1.addressIpv6="
       << item.wifiIpConfig.staticIpAddress.dnsServer1.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer2.family="
       << item.wifiIpConfig.staticIpAddress.dnsServer2.family << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4="
       << item.wifiIpConfig.staticIpAddress.dnsServer2.GetIpv4Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.dnsServer2.addressIpv6="
       << item.wifiIpConfig.staticIpAddress.dnsServer2.GetIpv6Address() << std::endl;
    ss << "    " <<"wifiIpConfig.staticIpAddress.domains=" << item.wifiIpConfig.staticIpAddress.domains << std::endl;
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

static std::string OutPutWifiDeviceConfigProxy(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiDeviceConfigProxy>" << std::endl;
    ss << "    " <<"wifiProxyconfig.configureMethod=" << (int)item.wifiProxyconfig.configureMethod << std::endl;
    ss << "    " <<"wifiProxyconfig.autoProxyConfig.pacWebAddress="
       << item.wifiProxyconfig.autoProxyConfig.pacWebAddress << std::endl;
    ss << "    " <<"wifiProxyconfig.ManualProxyConfig.serverHostName="
       << item.wifiProxyconfig.manualProxyConfig.serverHostName << std::endl;
    ss << "    " <<"wifiProxyconfig.ManualProxyConfig.serverPort="
       << item.wifiProxyconfig.manualProxyConfig.serverPort << std::endl;
    ss << "    " <<"wifiProxyconfig.ManualProxyConfig.exclusionObjectList="
       << item.wifiProxyconfig.manualProxyConfig.exclusionObjectList << std::endl;
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

template<>
std::string OutTClassString<WifiDeviceConfig>(WifiDeviceConfig &item)
{
    std::ostringstream ss;
    ss << OutPutWifiDeviceConfig(item) << OutPutWifiDeviceConfigIp(item)
       << OutPutWifiDeviceConfigEap(item) << OutPutWifiDeviceConfigProxy(item)
       << OutPutWifiDeviceConfigPrivacy(item);
    return ss.str();
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
        item.SetSecurityType(static_cast<KeyMgmt>(std::stoi(value)));
    } else if (key == "band") {
        item.SetBand(static_cast<BandType>(std::stoi(value)));
    } else if (key == "channel") {
        item.SetChannel(std::stoi(value));
    } else if (key == "maxConn") {
        item.SetMaxConn(std::stoi(value));
    } else if (key == "ipAddress") {
        item.SetIpAddress(value);
    } else if (key == "leaseTime") {
        item.SetLeaseTime(std::stoi(value));
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
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
    if (key == "randomMacSupport") {
        item.SetRandomMacSupport(std::stoi(value) != 0);
    } else if (key == "autoListen") {
        item.SetIsAutoListen(std::stoi(value) != 0);
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
    item.canOpenStaWhenAirplane = false;
    item.openWifiWhenAirplane = false;
    item.staLastState = false;
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
    item.strDnsBak = "8.8.8.8";
    item.isLoadStabak = true;
    item.scanOnlySwitch = true;
    item.realMacAddress = "";
    item.staApExclusionType = static_cast<int>(StaApExclusionType::INITIAL_TYPE);
    return;
}

static int SetWifiConfigValueFirst(WifiConfig &item, const std::string &key, const std::string &value)
{
    if (key == "scanAlwaysSwitch") {
        item.scanAlwaysSwitch = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "staAirplaneMode") {
        item.staAirplaneMode = std::stoi(value);
    } else if (key == "canOpenStaWhenAirplane") {
        item.canOpenStaWhenAirplane = (std::stoi(value) != 0);
    } else if (key == "openWifiWhenAirplane") {
        item.openWifiWhenAirplane = (std::stoi(value) != 0);
    } else if (key == "staLastState") {
        item.staLastState = (std::stoi(value) != 0);
    } else if (key == "lastAirplaneMode") {
        item.lastAirplaneMode = std::stoi(value);
    } else if (key == "savedDeviceAppraisalPriority") {
        item.savedDeviceAppraisalPriority = std::stoi(value);
    } else if (key == "scoretacticsScoreSlope") {
        item.scoretacticsScoreSlope = std::stoi(value);
    } else if (key == "scoretacticsInitScore") {
        item.scoretacticsInitScore = std::stoi(value);
    } else if (key == "scoretacticsSameBssidScore") {
        item.scoretacticsSameBssidScore = std::stoi(value);
    } else if (key == "scoretacticsSameNetworkScore") {
        item.scoretacticsSameNetworkScore = std::stoi(value);
    } else if (key == "scoretacticsFrequency5GHzScore") {
        item.scoretacticsFrequency5GHzScore = std::stoi(value);
    } else if (key == "scoretacticsLastSelectionScore") {
        item.scoretacticsLastSelectionScore = std::stoi(value);
    } else if (key == "scoretacticsSecurityScore") {
        item.scoretacticsSecurityScore = std::stoi(value);
    } else if (key == "scoretacticsNormalScore") {
        item.scoretacticsNormalScore = std::stoi(value);
    } else if (key == "whetherToAllowNetworkSwitchover") {
        item.whetherToAllowNetworkSwitchover = (std::stoi(value) != 0);
    } else if (key == "dhcpIpType") {
        item.dhcpIpType = std::stoi(value);
    } else if (key == "defaultWifiInterface") {
        item.defaultWifiInterface = value;
    } else {
        return -1;
    }
    return 0;
}

static int SetWifiConfigValueSecond(WifiConfig &item, const std::string &key, const std::string &value)
{
    if (key == "preLoadSta") {
        item.preLoadSta = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "preLoadScan") {
        item.preLoadScan = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "preLoadAp") {
        item.preLoadAp = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "preLoadP2p") {
        item.preLoadP2p = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "preLoadAware") {
        item.preLoadAware = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "preLoadEnhance") {
        item.preLoadEnhance = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "supportHwPnoFlag") {
        item.supportHwPnoFlag = std::stoi(value);
    } else if (key == "minRssi2Dot4Ghz") {
        item.minRssi2Dot4Ghz = std::stoi(value);
    } else if (key == "minRssi5Ghz") {
        item.minRssi5Ghz = std::stoi(value);
    } else if (key == "firstRssiLevel2G") {
        item.firstRssiLevel2G = std::stoi(value);
    } else if (key == "secondRssiLevel2G") {
        item.secondRssiLevel2G = std::stoi(value);
    } else if (key == "thirdRssiLevel2G") {
        item.thirdRssiLevel2G = std::stoi(value);
    } else if (key == "fourthRssiLevel2G") {
        item.fourthRssiLevel2G = std::stoi(value);
    } else if (key == "firstRssiLevel5G") {
        item.firstRssiLevel5G = std::stoi(value);
    } else if (key == "secondRssiLevel5G") {
        item.secondRssiLevel5G = std::stoi(value);
    } else if (key == "thirdRssiLevel5G") {
        item.thirdRssiLevel5G = std::stoi(value);
    } else if (key == "fourthRssiLevel5G") {
        item.fourthRssiLevel5G = std::stoi(value);
    } else if (key == "strDnsBak") {
        item.strDnsBak = value;
    } else if (key == "isLoadStabak") {
        item.isLoadStabak = (std::stoi(value) != 0);
    } else if (key == "scanOnlySwitch") {
        item.scanOnlySwitch  = (std::stoi(value) != 0); /* 0 -> false 1 -> true */
    } else if (key == "realMacAddress") {
        item.realMacAddress = value;
    } else if (key == "staApExclusionType") {
        item.staApExclusionType = std::stoi(value);
    } else {
        return -1;
    }
    return 0;
}

template<>
int SetTClassKeyValue<WifiConfig>(WifiConfig &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (SetWifiConfigValueFirst(item, key, value) == 0) {
        return errorKeyValue;
    }
    if (SetWifiConfigValueSecond(item, key, value) == 0) {
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
    ss << "    " <<"canOpenStaWhenAirplane=" << item.canOpenStaWhenAirplane << std::endl;
    ss << "    " <<"openWifiWhenAirplane=" << item.openWifiWhenAirplane << std::endl;
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
    if (key == "deviceName") {
        item.SetDeviceName(value);
    } else if (key == "deviceAddress") {
        item.SetDeviceAddress(value);
    } else if (key == "primaryDeviceType") {
        item.SetPrimaryDeviceType(value);
    } else if (key == "status") {
        item.SetP2pDeviceStatus(static_cast<P2pDeviceStatus>(std::stoi(value)));
    } else if (key == "supportWpsConfigMethods") {
        item.SetWpsConfigMethod(std::stoi(value));
    } else if (key == "deviceCapabilitys") {
        item.SetDeviceCapabilitys(std::stoi(value));
    } else if (key == "groupCapabilitys") {
        item.SetGroupCapabilitys(std::stoi(value));
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
    if (key.compare(0, strlen("ownerDev."), "ownerDev.") == 0) {
        WifiP2pDevice owner = item.GetOwner();
        SetWifiP2pDevicClassKeyValue(owner, key.substr(strlen("ownerDev.")), value);
        item.SetOwner(owner);
    } else if (key.compare(0, strlen("vecDev_"), "vecDev_") == 0) {
        std::string::size_type pos = key.find(".");
        if (pos == std::string::npos) {
            WifiP2pDevice device;
            item.AddClientDevice(device);
        } else {
            unsigned long index = static_cast<unsigned long>(std::stoi(key.substr(strlen("vecDev_"), pos)));
            if (index < item.GetClientDevices().size()) {
                std::vector<WifiP2pDevice> clients = item.GetClientDevices();
                SetWifiP2pDevicClassKeyValue(clients[index], key.substr(pos + 1), value);
                item.SetClientDevices(clients);
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
    if (key == "isGroupOwner") {
        item.SetIsGroupOwner(std::stoi(value) != 0);
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
        item.SetNetworkId(std::stoi(value));
    } else if (key == "frequency") {
        item.SetFrequency(std::stoi(value));
    } else if (key == "isPersistent") {
        item.SetIsPersistent(std::stoi(value) != 0);
    } else if (key == "groupStatus") {
        item.SetP2pGroupStatus(static_cast<P2pGroupStatus>(std::stoi(value)));
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
    int size = item.GetClientDevices().size();
    for (int i = 0; i < size; i++) {
        std::string prefix = "vecDev_" + std::to_string(i) + ".";
        ss << "    " <<"vecDev_=" << i << std::endl;
        const WifiP2pDevice &tmp = item.GetClientDevices().at(i);
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
    if (key == "sceneId") {
        item.sceneId = std::stoi(value);
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
    item.ssid.clear();
    item.keyMgmt.clear();
    item.peerBssid.clear();
    item.randomMac.clear();
    return;
}

template <>
int SetTClassKeyValue<WifiStoreRandomMac>(WifiStoreRandomMac &item, const std::string &key, const std::string &value)
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
        } else {
            return -1;
        }
    } else if (key == "keyMgmt") {
        item.keyMgmt = value;
    } else if (key == "peerBssid") {
        item.peerBssid = value;
    } else if (key == "randomMac") {
        item.randomMac = value;
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

template <> std::string OutTClassString<WifiStoreRandomMac>(WifiStoreRandomMac &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiStoreRandomMac>" << std::endl;
    ss << "    " <<"ssid=" << ValidateString(item.ssid) << std::endl;
    ss << "    " <<"HexSsid=" << ConvertArrayToHex((uint8_t*)&item.ssid[0], item.ssid.length()) << std::endl;
    ss << "    " <<"keyMgmt=" << item.keyMgmt << std::endl;
    ss << "    " <<"peerBssid=" << item.peerBssid << std::endl;
    ss << "    " <<"randomMac=" << item.randomMac << std::endl;
    ss << "    " <<"<WifiStoreRandomMac>" << std::endl;
    return ss.str();
}

template <> void ClearTClass<SoftApRandomMac>(SoftApRandomMac &item)
{
    item.ssid.clear();
    item.keyMgmt = KeyMgmt::NONE;
    item.randomMac.clear();
    return;
}

template <>
int SetTClassKeyValue<SoftApRandomMac>(SoftApRandomMac &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "ssid") {
        item.ssid = value;
    } else if (key == "keyMgmt") {
        item.keyMgmt = static_cast<KeyMgmt>(std::stoi(value));
    } else if (key == "randomMac") {
        item.randomMac = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template <> std::string GetTClassName<SoftApRandomMac>()
{
    return "SoftApRandomMac";
}

template <> std::string OutTClassString<SoftApRandomMac>(SoftApRandomMac &item)
{
    std::ostringstream ss;
    ss << "    " <<"<SoftApRandomMac>" << std::endl;
    ss << "    " <<"ssid=" << item.ssid << std::endl;
    ss << "    " <<"keyMgmt=" << static_cast<int>(item.keyMgmt) << std::endl;
    ss << "    " <<"randomMac=" << item.randomMac << std::endl;
    ss << "    " <<"</SoftApRandomMac>" << std::endl;
    return ss.str();
}

template <> void ClearTClass<WifiPortalConf>(WifiPortalConf &item)
{
    item.portalHttpUrl.clear();
    item.portalHttpsUrl.clear();
    item.portalBakHttpUrl.clear();
    item.portalBakHttpsUrl.clear();
    return;
}

template <>
void ClearTClass<PackageFilterConf>(PackageFilterConf &item)
{
    item.filterName.clear();
    item.packageList.clear();
    return;
}

template <>
int SetTClassKeyValue<WifiPortalConf>(WifiPortalConf &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "http") {
        item.portalHttpUrl = value;
    } else if (key == "https") {
        item.portalHttpsUrl = value;
    } else if (key == "httpbak") {
        item.portalBakHttpUrl = value;
    } else if (key == "httpsbak") {
        item.portalBakHttpsUrl = value;
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template <>
int SetTClassKeyValue<PackageFilterConf>(PackageFilterConf &item, const std::string &key, const std::string &value)
{
    int errorKeyValue = 0;
    if (key == "filterName") {
        item.filterName = value;
    } else if (key == "package") {
        item.packageList.push_back(value);
    } else {
        LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

template <> std::string GetTClassName<WifiPortalConf>()
{
    return "WifiPortalConf";
}

template <> std::string OutTClassString<WifiPortalConf>(WifiPortalConf &item)
{
    std::ostringstream ss;
    ss << "    " <<"<WifiPortalConf>" << std::endl;
    ss << "    " <<"http=" << ValidateString(item.portalHttpUrl) << std::endl;
    return ss.str();
}

int SetNetworkStatusHistory(WifiDeviceConfig &item, const std::string &value)
{
    item.networkStatusHistory = std::stoi(value);
    return 0;
}

int SetIsPortal(WifiDeviceConfig &item, const std::string &value)
{
    item.isPortal = std::stoi(value);
    return 0;
}

int SetLastHasInternetTime(WifiDeviceConfig &item, const std::string &value)
{
    item.lastHasInternetTime = std::stol(value);
    return 0;
}

int SetNoInternetAccess(WifiDeviceConfig &item, const std::string &value)
{
    item.noInternetAccess = std::stoi(value);
    return 0;
}

}  // namespace Wifi
}  // namespace OHOS
