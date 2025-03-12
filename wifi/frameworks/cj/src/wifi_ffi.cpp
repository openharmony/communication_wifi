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

#include "wifi_ffi.h"

#include <functional>
#include <vector>

#include "wifi_callback.h"
#include "wifi_common_util.h"
#include "wifi_device.h"
#include "wifi_logger.h"
#include "wifi_p2p.h"
#include "wifi_scan.h"

DEFINE_WIFILOG_LABEL("CJ_WIFI_FFI");

namespace OHOS::Wifi {

std::shared_ptr<WifiDevice> cjWifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> cjWifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
std::shared_ptr<WifiP2p> cjWifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
static const std::string EAP_METHOD[] = { "NONE", "PEAP", "TLS", "TTLS", "PWD", "SIM", "AKA", "AKA'" };

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

static std::string EapMethod2Str(const int& method)
{
    if (method < 0 || method >= static_cast<int>(sizeof(EAP_METHOD) / sizeof(EAP_METHOD[0]))) {
        return "NONE";
    }
    return EAP_METHOD[method];
}

static char* MallocCString(const std::string& origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char* res = static_cast<char*>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

static SecTypeCj SecurityTypeNativeToCj(const WifiSecurity& cppSecurityType)
{
    SecTypeCj cjSecurityType = SecTypeCj::SEC_TYPE_INVALID;
    switch (cppSecurityType) {
        case WifiSecurity::OPEN:
            cjSecurityType = SecTypeCj::SEC_TYPE_OPEN;
            break;
        case WifiSecurity::WEP:
            cjSecurityType = SecTypeCj::SEC_TYPE_WEP;
            break;
        case WifiSecurity::PSK:
            cjSecurityType = SecTypeCj::SEC_TYPE_PSK;
            break;
        case WifiSecurity::SAE:
        case WifiSecurity::PSK_SAE:
            cjSecurityType = SecTypeCj::SEC_TYPE_SAE;
            break;
        case WifiSecurity::EAP:
            cjSecurityType = SecTypeCj::SEC_TYPE_EAP;
            break;
        case WifiSecurity::EAP_SUITE_B:
            cjSecurityType = SecTypeCj::SEC_TYPE_EAP_SUITE_B;
            break;
        case WifiSecurity::WAPI_CERT:
            cjSecurityType = SecTypeCj::SEC_TYPE_WAPI_CERT;
            break;
        case WifiSecurity::WAPI_PSK:
            cjSecurityType = SecTypeCj::SEC_TYPE_WAPI_PSK;
            break;
        default:
            cjSecurityType = SecTypeCj::SEC_TYPE_INVALID;
            break;
    }
    return cjSecurityType;
}

static void ConvertEncryptionMode(const SecTypeCj& securityType, std::string& keyMgmt)
{
    switch (securityType) {
        case SecTypeCj::SEC_TYPE_OPEN:
            keyMgmt = KEY_MGMT_NONE;
            break;
        case SecTypeCj::SEC_TYPE_WEP:
            keyMgmt = KEY_MGMT_WEP;
            break;
        case SecTypeCj::SEC_TYPE_PSK:
            keyMgmt = KEY_MGMT_WPA_PSK;
            break;
        case SecTypeCj::SEC_TYPE_SAE:
            keyMgmt = KEY_MGMT_SAE;
            break;
        case SecTypeCj::SEC_TYPE_EAP:
            keyMgmt = KEY_MGMT_EAP;
            break;
        case SecTypeCj::SEC_TYPE_EAP_SUITE_B:
            keyMgmt = KEY_MGMT_SUITE_B_192;
            break;
        case SecTypeCj::SEC_TYPE_WAPI_CERT:
            keyMgmt = KEY_MGMT_WAPI_CERT;
            break;
        case SecTypeCj::SEC_TYPE_WAPI_PSK:
            keyMgmt = KEY_MGMT_WAPI_PSK;
            break;
        default:
            keyMgmt = KEY_MGMT_NONE;
            break;
    }
}

static void ProcessPassphrase(const SecTypeCj& securityType, WifiDeviceConfig& cppConfig)
{
    if (securityType == SecTypeCj::SEC_TYPE_WEP) {
        cppConfig.wepKeys[0] = cppConfig.preSharedKey;
        cppConfig.wepTxKeyIndex = 0;
        cppConfig.preSharedKey = "";
        std::string().swap(cppConfig.preSharedKey);
    }
}

static void SetInfoElemContent(const WifiInfoElem& infoElem, CWifiInfoElem& cinfo)
{
    int valueStep = 2;
    const char* uStr = &infoElem.content[0];
    size_t len = infoElem.content.size();
    size_t inLen = static_cast<size_t>(infoElem.content.size() * valueStep + 1);
    char* buf = static_cast<char*>(calloc(inLen + 1, sizeof(char)));
    if (buf == nullptr) {
        return;
    }
    int pos = 0;
    for (size_t k = 0; k < len; ++k) {
        pos = (k << 1);
        if (snprintf_s(buf + pos, inLen - pos, inLen - pos - 1, "%02x", uStr[k]) < 0) {
            free(buf);
            buf = nullptr;
            return;
        }
    }
    cinfo.content.head = reinterpret_cast<uint8_t*>(buf);
    cinfo.content.size = inLen - 1;
}

static void NativeInfoElems2Cj(const std::vector<WifiInfoElem>& infoElems, CWifiScanInfo& info)
{
    info.infoElems = nullptr;
    info.elemsSize = 0;
    int64_t size = static_cast<int64_t>(infoElems.size());
    if (size <= 0) {
        return;
    }
    info.infoElems = static_cast<CWifiInfoElem*>(malloc(sizeof(CWifiInfoElem) * size));
    if (info.infoElems == nullptr) {
        return;
    }
    info.elemsSize = size;
    int64_t idx = 0;
    for (auto& each : infoElems) {
        info.infoElems[idx] = CWifiInfoElem { .eid = each.id, .content = CArrUI8 { .head = nullptr, .size = 0 } };
        SetInfoElemContent(each, info.infoElems[idx]);
        idx++;
    }
}

static int32_t ScanInfo2Cj(const std::vector<WifiScanInfo>& scanInfos, WifiScanInfoArr& infos)
{
    int64_t size = static_cast<int64_t>(scanInfos.size());
    WIFI_LOGI("GetScanInfoList, size: %{public}zu", scanInfos.size());

    if (size > 0) {
        infos.head = static_cast<CWifiScanInfo*>(malloc(sizeof(CWifiScanInfo) * size));
        if (infos.head == nullptr) {
            return WIFI_OPT_FAILED;
        }
        infos.size = size;

        uint32_t idx = 0;
        for (auto& each : scanInfos) {
            CWifiScanInfo info;
            info.ssid = MallocCString(each.ssid);
            info.bssid = MallocCString(each.bssid);
            info.bssidType = each.bssidType;
            info.capabilities = MallocCString(each.capabilities);
            info.securityType = static_cast<int32_t>(SecurityTypeNativeToCj(each.securityType));
            info.rssi = each.rssi;
            info.band = each.band;
            info.frequency = each.frequency;
            info.channelWidth = static_cast<int32_t>(each.channelWidth);
            info.centerFrequency0 = each.centerFrequency0;
            info.centerFrequency1 = each.centerFrequency1;
            NativeInfoElems2Cj(each.infoElems, info);
            info.channelWidth = static_cast<int32_t>(each.channelWidth);
            info.timestamp = each.timestamp;
            info.supportedWifiCategory = static_cast<int32_t>(each.supportedWifiCategory);
            info.isHiLinkNetwork = each.isHiLinkNetwork;
            infos.head[idx] = info;
            idx++;
        }
    }
    return WIFI_OPT_SUCCESS;
}

static void DeviceInfo2Cj(const WifiP2pDevice& device, CWifiP2pDevice& info)
{
    info.deviceName = MallocCString(device.GetDeviceName());
    info.deviceAddress = MallocCString(device.GetDeviceAddress());
    info.primaryDeviceType = MallocCString(device.GetPrimaryDeviceType());
    info.deviceStatus = static_cast<int32_t>(device.GetP2pDeviceStatus());
    info.groupCapabilities = device.GetGroupCapabilitys();
    info.deviceAddressType = device.GetDeviceAddressType();
}

static void CjWifiP2PConfig2C(const CWifiP2PConfig& cfg, WifiP2pConfig& config)
{
    config.SetDeviceAddress(std::string(cfg.deviceAddress));
    config.SetDeviceAddressType(cfg.deviceAddressType);
    config.SetNetId(cfg.netId);
    config.SetPassphrase(std::string(cfg.passphrase));
    config.SetGroupName(std::string(cfg.groupName));
    config.SetGoBand(static_cast<GroupOwnerBand>(cfg.goBand));
}

static void UpdateSecurityTypeAndPreSharedKey(WifiDeviceConfig& cppConfig)
{
    if (cppConfig.keyMgmt != KEY_MGMT_NONE) {
        return;
    }
    for (int i = 0; i != WEPKEYS_SIZE; ++i) {
        if (!cppConfig.wepKeys[i].empty() && cppConfig.wepTxKeyIndex == i) {
            cppConfig.keyMgmt = KEY_MGMT_WEP;
            cppConfig.preSharedKey = cppConfig.wepKeys[i];
        }
    }
}

static SecTypeCj ConvertKeyMgmtToSecType(const std::string& keyMgmt)
{
    std::map<std::string, SecTypeCj> mapKeyMgmtToSecType = {
        { KEY_MGMT_NONE, SecTypeCj::SEC_TYPE_OPEN },
        { KEY_MGMT_WEP, SecTypeCj::SEC_TYPE_WEP },
        { KEY_MGMT_WPA_PSK, SecTypeCj::SEC_TYPE_PSK },
        { KEY_MGMT_SAE, SecTypeCj::SEC_TYPE_SAE },
        { KEY_MGMT_EAP, SecTypeCj::SEC_TYPE_EAP },
        { KEY_MGMT_SUITE_B_192, SecTypeCj::SEC_TYPE_EAP_SUITE_B },
        { KEY_MGMT_WAPI_CERT, SecTypeCj::SEC_TYPE_WAPI_CERT },
        { KEY_MGMT_WAPI_PSK, SecTypeCj::SEC_TYPE_WAPI_PSK },
    };

    std::map<std::string, SecTypeCj>::iterator iter = mapKeyMgmtToSecType.find(keyMgmt);
    return iter == mapKeyMgmtToSecType.end() ? SecTypeCj::SEC_TYPE_OPEN : iter->second;
}

static int Str2EapMethod(const std::string& str)
{
    WIFI_LOGD("%{public}s: eapMethod is %{public}s", __func__, str.c_str());
    int len = sizeof(EAP_METHOD) / sizeof(EAP_METHOD[0]);
    for (int i = 0; i < len; i++) {
        if (EAP_METHOD[i] == str) {
            WIFI_LOGD("%{public}s: index is %{public}d", __func__, i);
            return i;
        }
    }
    return 0;
}

static void EapConfig2C(WifiEapConfig& wifiEapConfig, CWifiEapConfig& eapConfig)
{
    eapConfig.eapMethod = Str2EapMethod(wifiEapConfig.eap);
    eapConfig.phase2Method = static_cast<int>(wifiEapConfig.phase2Method);
    eapConfig.identity = MallocCString(wifiEapConfig.identity);
    eapConfig.anonymousIdentity = MallocCString(wifiEapConfig.anonymousIdentity);
    eapConfig.password = MallocCString(wifiEapConfig.password);
    eapConfig.caCertAlias = MallocCString(wifiEapConfig.caCertAlias);
    eapConfig.caPath = MallocCString(wifiEapConfig.caCertPath);
    eapConfig.clientCertAlias = MallocCString(wifiEapConfig.caCertAlias);
    CArrUI8 arr { .head = nullptr, .size = 0 };
    int64_t size = wifiEapConfig.certEntry.size();
    if (size > 0) {
        arr.head = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * size));
        if (arr.head != nullptr) {
            uint32_t idx = 0;
            for (auto& each : wifiEapConfig.certEntry) {
                arr.head[idx] = each;
                idx++;
            }
        }
    }
    eapConfig.certEntry = arr;
    eapConfig.certPassword = MallocCString(wifiEapConfig.certPassword);
    eapConfig.altSubjectMatch = MallocCString(wifiEapConfig.altSubjectMatch);
    eapConfig.domainSuffixMatch = MallocCString(wifiEapConfig.domainSuffixMatch);
    eapConfig.realm = MallocCString(wifiEapConfig.realm);
    eapConfig.plmn = MallocCString(wifiEapConfig.plmn);
    eapConfig.eapSubId = wifiEapConfig.eapSubId;
    eapConfig.isNone = false;
}

static void DeviceConfig2C(WifiDeviceConfig& config, CWifiDeviceConfig& cfg)
{
    UpdateSecurityTypeAndPreSharedKey(config);
    cfg.ssid = MallocCString(config.ssid);
    cfg.bssid = MallocCString(config.bssid);
    cfg.bssidType = config.bssidType;
    cfg.preSharedKey = MallocCString(config.preSharedKey);
    cfg.isHiddenSsid = config.hiddenSSID;
    cfg.eapConfig.isNone = true;
    cfg.wapiConfig.isNone = true;
    SecTypeCj type = ConvertKeyMgmtToSecType(config.keyMgmt);
    cfg.securityType = static_cast<int32_t>(type);
    if (type == SecTypeCj::SEC_TYPE_EAP || type == SecTypeCj::SEC_TYPE_EAP_SUITE_B) {
        EapConfig2C(config.wifiEapConfig, cfg.eapConfig);
    }
    if (type == SecTypeCj::SEC_TYPE_WAPI_CERT || type == SecTypeCj::SEC_TYPE_WAPI_PSK) {
        cfg.wapiConfig.wapiPskType = config.wifiWapiConfig.wapiPskType;
        cfg.wapiConfig.wapiAsCert = nullptr;
        cfg.wapiConfig.wapiUserCert = nullptr;
        cfg.wapiConfig.isNone = false;
    }
}

extern "C" {
int32_t FfiWifiIsWifiActive(bool& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiDevicePtr->IsWifiActive(ret);
}

WifiScanInfoArr FfiWifiGetScanInfoList(int32_t& ret)
{
    WifiScanInfoArr infos { .head = nullptr, .size = 0 };
    if (cjWifiScanPtr == nullptr) {
        ret = WIFI_OPT_FAILED;
        return infos;
    }
    std::vector<WifiScanInfo> scanInfos;
    ret = cjWifiScanPtr->GetScanInfoList(scanInfos, false);
    if (ret == WIFI_OPT_SUCCESS) {
        ret = ScanInfo2Cj(scanInfos, infos);
    }
    return infos;
}

int32_t FfiWifiRemoveCandidateConfig(int32_t id)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return static_cast<int32_t>(cjWifiDevicePtr->RemoveCandidateConfig(id));
}

int32_t FfiWifiConnectToCandidateConfig(int32_t id)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return static_cast<int32_t>(cjWifiDevicePtr->ConnectToNetwork(id, true));
}

int32_t FfiWifiGetSignalLevel(int32_t rssi, int32_t band, uint32_t& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    int level = -1;
    ErrCode code = cjWifiDevicePtr->GetSignalLevel(rssi, band, level);
    ret = static_cast<uint32_t>(level);
    return static_cast<int32_t>(code);
}

int32_t FfiWifiIsConnected(bool& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return static_cast<int32_t>(cjWifiDevicePtr->IsConnected(ret));
}

int32_t FfiWifiIsFeatureSupported(int64_t featureId, bool& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return static_cast<int32_t>(cjWifiDevicePtr->IsFeatureSupported(featureId, ret));
}

int32_t FfiWifiGetIpInfo(CIpInfo& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    IpInfo ipInfo;
    ErrCode code = cjWifiDevicePtr->GetIpInfo(ipInfo);
    if (code == WIFI_OPT_SUCCESS) {
        ret.ipAddress = ipInfo.ipAddress;
        ret.gateway = ipInfo.gateway;
        ret.netmask = ipInfo.netmask;
        ret.primaryDns = ipInfo.primaryDns;
        ret.secondDns = ipInfo.secondDns;
        ret.serverIp = ipInfo.serverIp;
        ret.leaseDuration = ipInfo.leaseDuration;
    }
    return code;
}

int32_t FfiWifiGetIpv6Info(CIpv6Info& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    IpV6Info ipInfo;
    ErrCode code = cjWifiDevicePtr->GetIpv6Info(ipInfo);
    if (code == WIFI_OPT_SUCCESS) {
        ret.linkIpV6Address = MallocCString(ipInfo.linkIpV6Address);
        ret.globalIpV6Address = MallocCString(ipInfo.globalIpV6Address);
        ret.randomGlobalIpV6Address = MallocCString(ipInfo.randGlobalIpV6Address);
        ret.uniqueIpv6Address = MallocCString(ipInfo.uniqueLocalAddress1);
        ret.randomUniqueIpv6Address = MallocCString(ipInfo.uniqueLocalAddress2);
        ret.gateway = MallocCString(ipInfo.gateway);
        ret.netmask = MallocCString(ipInfo.netmask);
        ret.primaryDns = MallocCString(ipInfo.primaryDns);
        ret.secondDNS = MallocCString(ipInfo.secondDns);
    }
    return code;
}

char* FfiWifiGetCountryCode(int32_t& code)
{
    if (cjWifiDevicePtr == nullptr) {
        code = WIFI_OPT_FAILED;
        return nullptr;
    }
    std::string countryCode;
    code = cjWifiDevicePtr->GetCountryCode(countryCode);
    if (code == WIFI_OPT_SUCCESS) {
        return MallocCString(countryCode);
    }
    return nullptr;
}

int32_t FfiWifiIsBandTypeSupported(int32_t bandType, bool& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiDevicePtr->IsBandTypeSupported(bandType, ret);
}

int32_t FfiWifiIsMeteredHotspot(bool& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiDevicePtr->IsMeteredHotspot(ret);
}

int32_t FfiWifiRemoveGroup()
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiP2pPtr->RemoveGroup();
}

int32_t FfiWifiP2pConnect(CWifiP2PConfig& cfg)
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    WifiP2pConfig config;
    CjWifiP2PConfig2C(cfg, config);
    return cjWifiP2pPtr->P2pConnect(config);
}

int32_t FfiWifiP2pCancelConnect()
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiP2pPtr->P2pCancelConnect();
}

int32_t FfiWifiStartDiscoverDevices()
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiP2pPtr->DiscoverDevices();
}

int32_t FfiWifiStopDiscoverDevices()
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return cjWifiP2pPtr->StopDiscoverDevices();
}

int32_t FfiWifiGetP2pLinkedInfo(CWifiP2PLinkedInfo& info)
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    WifiP2pLinkedInfo linkedInfo;
    ErrCode code = cjWifiP2pPtr->QueryP2pLinkedInfo(linkedInfo);
    if (code == WIFI_OPT_SUCCESS) {
        info.connectState = static_cast<int>(linkedInfo.GetConnectState());
        info.isGroupOwner = linkedInfo.IsGroupOwner();
        info.groupOwnerAddr = MallocCString(linkedInfo.GetGroupOwnerAddress());
    }
    return code;
}

int32_t FfiWifiGetCurrentGroup(CWifiP2PGroupInfo& info)
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    WifiP2pGroupInfo groupInfo;
    ErrCode code = cjWifiP2pPtr->GetCurrentGroup(groupInfo);
    if (code != WIFI_OPT_SUCCESS) {
        return code;
    }
    info.isP2pGo = groupInfo.IsGroupOwner();
    DeviceInfo2Cj(groupInfo.GetOwner(), info.ownerInfo);
    info.passphrase = MallocCString(groupInfo.GetPassphrase());
    info.interfaceName = MallocCString(groupInfo.GetInterface());
    info.groupName = MallocCString(groupInfo.GetGroupName());
    info.goIpAddress = MallocCString(groupInfo.GetGoIpAddress());
    info.networkId = groupInfo.GetNetworkId();
    info.frequency = groupInfo.GetFrequency();
    info.clientSize = 0;
    info.clientDevices = nullptr;
    if (groupInfo.IsClientDevicesEmpty()) {
        return code;
    }
    const std::vector<OHOS::Wifi::WifiP2pDevice>& vecDevices = groupInfo.GetClientDevices();
    int64_t size = static_cast<int64_t>(vecDevices.size());
    info.clientDevices = static_cast<CWifiP2pDevice*>(malloc(sizeof(CWifiP2pDevice) * size));
    if (info.clientDevices == nullptr) {
        return code;
    }
    info.clientSize = size;
    uint32_t idx = 0;
    for (auto& each : vecDevices) {
        CWifiP2pDevice device;
        DeviceInfo2Cj(each, device);
        info.clientDevices[idx] = device;
        idx++;
    }
    return code;
}

WifiP2pDeviceArr FfiWifiGetP2pPeerDevices(int32_t& ret)
{
    WifiP2pDeviceArr arr { .head = nullptr, .size = 0 };
    if (cjWifiP2pPtr == nullptr) {
        ret = WIFI_OPT_FAILED;
        return arr;
    }
    std::vector<WifiP2pDevice> vecP2pDevices;
    ret = cjWifiP2pPtr->QueryP2pDevices(vecP2pDevices);
    int64_t size = static_cast<int64_t>(vecP2pDevices.size());
    WIFI_LOGI("GetP2pDeviceList, size: %{public}d", static_cast<int>(size));

    if (ret == WIFI_OPT_SUCCESS && size > 0) {
        arr.head = static_cast<CWifiP2pDevice*>(malloc(sizeof(CWifiP2pDevice) * size));
        if (arr.head == nullptr) {
            ret = WIFI_OPT_FAILED;
            return arr;
        }
        arr.size = size;

        uint32_t idx = 0;
        for (auto& each : vecP2pDevices) {
            CWifiP2pDevice device;
            DeviceInfo2Cj(each, device);
            arr.head[idx] = device;
            idx++;
        }
    }
    return arr;
}

int32_t FfiWifiGetP2pLocalDevice(CWifiP2pDevice& info)
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    WifiP2pDevice deviceInfo;
    ErrCode code = cjWifiP2pPtr->QueryP2pLocalDevice(deviceInfo);
    if (code == WIFI_OPT_SUCCESS) {
        DeviceInfo2Cj(deviceInfo, info);
    }
    return code;
}

int32_t FfiWifiCreateGroup(CWifiP2PConfig& cfg)
{
    if (cjWifiP2pPtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    WifiP2pConfig config;
    CjWifiP2PConfig2C(cfg, config);
    return cjWifiP2pPtr->CreateGroup(config);
}

int32_t FfiWifiGetLinkedInfo(CWifiLinkedInfo& info)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }
    WifiLinkedInfo linkedInfo;
    ErrCode code = cjWifiDevicePtr->GetLinkedInfo(linkedInfo);
    if (code == WIFI_OPT_SUCCESS) {
        info.ssid = MallocCString(linkedInfo.ssid);
        info.bssid = MallocCString(linkedInfo.bssid);
        info.rssi = linkedInfo.rssi;
        info.band = linkedInfo.band;
        info.linkSpeed = linkedInfo.linkSpeed;
        info.frequency = linkedInfo.frequency;
        info.isHidden = linkedInfo.ifHiddenSSID;
        info.isRestricted = linkedInfo.isDataRestricted;
        info.macAddress = MallocCString(linkedInfo.macAddress);
        info.macType = linkedInfo.macType;
        info.ipAddress = linkedInfo.ipAddress;
        info.connState = static_cast<int32_t>(linkedInfo.connState);
        info.wifiStandard = linkedInfo.wifiStandard;
        info.maxSupportedRxLinkSpeed = linkedInfo.maxSupportedRxLinkSpeed;
        info.maxSupportedTxLinkSpeed = linkedInfo.maxSupportedTxLinkSpeed;
        info.rxLinkSpeed = linkedInfo.rxLinkSpeed;
        info.channelWidth = static_cast<int32_t>(linkedInfo.channelWidth);
        info.supportedWifiCategory = static_cast<int32_t>(linkedInfo.supportedWifiCategory);
        info.isHiLinkNetwork = linkedInfo.isHiLinkNetwork;
    }
    return code;
}

int32_t FfiWifiAddCandidateConfig(CWifiDeviceConfig cfg, int32_t& ret)
{
    if (cjWifiDevicePtr == nullptr) {
        return WIFI_OPT_FAILED;
    }

    WifiDeviceConfig config;

    config.ssid = std::string(cfg.ssid);
    config.preSharedKey = std::string(cfg.preSharedKey);
    SecTypeCj type = SecTypeCj(cfg.securityType);
    if (cfg.bssid != nullptr) {
        config.bssid = std::string(cfg.bssid);
    }
    config.bssidType = cfg.bssidType;
    config.hiddenSSID = cfg.isHiddenSsid;
    ConvertEncryptionMode(type, config.keyMgmt);
    ProcessPassphrase(type, config);
    config.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;

    if (!cfg.eapConfig.isNone && (type == SecTypeCj::SEC_TYPE_EAP || type == SecTypeCj::SEC_TYPE_EAP_SUITE_B)) {
        config.wifiEapConfig.eap = EapMethod2Str(cfg.eapConfig.eapMethod);
        config.wifiEapConfig.phase2Method = Phase2Method(cfg.eapConfig.phase2Method);
        config.wifiEapConfig.identity = std::string(cfg.eapConfig.identity);
        config.wifiEapConfig.anonymousIdentity = std::string(cfg.eapConfig.anonymousIdentity);
        config.wifiEapConfig.password = std::string(cfg.eapConfig.password);
        config.wifiEapConfig.caCertAlias = std::string(cfg.eapConfig.caCertAlias);
        config.wifiEapConfig.caCertPath = std::string(cfg.eapConfig.caPath);
        config.wifiEapConfig.clientCert = std::string(cfg.eapConfig.clientCertAlias);
        config.wifiEapConfig.privateKey = std::string(cfg.eapConfig.clientCertAlias);
        config.wifiEapConfig.certEntry = std::vector<uint8_t>(
            cfg.eapConfig.certEntry.head, cfg.eapConfig.certEntry.head + cfg.eapConfig.certEntry.size);
        if (strncpy_s(config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword),
                cfg.eapConfig.certPassword, strlen(cfg.eapConfig.certPassword)) != EOK) {
            WIFI_LOGE("%{public}s: failed to copy", __func__);
        }
        config.wifiEapConfig.altSubjectMatch = std::string(cfg.eapConfig.altSubjectMatch);
        config.wifiEapConfig.domainSuffixMatch = std::string(cfg.eapConfig.domainSuffixMatch);
        config.wifiEapConfig.realm = std::string(cfg.eapConfig.realm);
        config.wifiEapConfig.plmn = std::string(cfg.eapConfig.plmn);
        config.wifiEapConfig.eapSubId = cfg.eapConfig.eapSubId;
    }
    if (!cfg.wapiConfig.isNone && (type == SecTypeCj::SEC_TYPE_WAPI_CERT || type == SecTypeCj::SEC_TYPE_WAPI_PSK)) {
        config.wifiWapiConfig.wapiPskType = cfg.wapiConfig.wapiPskType;
        config.wifiWapiConfig.wapiAsCertData = MallocCString(cfg.wapiConfig.wapiAsCert);
        config.wifiWapiConfig.wapiUserCertData = MallocCString(cfg.wapiConfig.wapiUserCert);
    }

    ErrCode code = cjWifiDevicePtr->AddDeviceConfig(config, ret, true);
    if (ret < 0 || code != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Add candidate device config failed: %{public}d", static_cast<int>(code));
        ret = -1;
    }
    return code;
}

WifiDeviceConfigArr FfiWifiGetCandidateConfigs(int32_t& code)
{
    WifiDeviceConfigArr arr { .head = nullptr, .size = 0 };
    if (cjWifiDevicePtr == nullptr) {
        code = WIFI_OPT_FAILED;
        return arr;
    }
    std::vector<WifiDeviceConfig> vecDeviceConfigs;
    code = cjWifiDevicePtr->GetDeviceConfigs(vecDeviceConfigs, true);
    int64_t size = static_cast<int64_t>(vecDeviceConfigs.size());
    if (code == WIFI_OPT_SUCCESS && size > 0) {
        WIFI_LOGI("Get candidate device configs size: %{public}zu", vecDeviceConfigs.size());
        arr.head = static_cast<CWifiDeviceConfig*>(malloc(sizeof(CWifiDeviceConfig) * size));
        if (arr.head == nullptr) {
            code = WIFI_OPT_FAILED;
            return arr;
        }
        arr.size = size;
        for (int64_t i = 0; i < size; i++) {
            CWifiDeviceConfig cfg;
            DeviceConfig2C(vecDeviceConfigs[i], cfg);
            arr.head[i] = cfg;
        }
    }
    return arr;
}

int32_t FfiWifiWifiOn(char* type, void (*callback)())
{
    std::string eventType(type);
    if (eventType.empty()) {
        return WIFI_OPT_FAILED;
    }
    return CjEventRegister::GetInstance().Register(eventType, callback);
}

int32_t FfiWifiWifiOff(char* type)
{
    std::string eventType(type);
    if (eventType.empty()) {
        return WIFI_OPT_FAILED;
    }
    return CjEventRegister::GetInstance().UnRegister(eventType);
}
}
} // namespace OHOS::Wifi
