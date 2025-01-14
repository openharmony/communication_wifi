/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_client.h"

#include <codecvt>
#include <fstream>
#include <iostream>
#include <locale>
#include <securec.h>
#include <unistd.h>

#include "wifi_hdi_wpa_sta_impl.h"
#include "wifi_hdi_wpa_callback.h"
#include "wifi_hdi_wpa_ap_impl.h"
#include "wifi_hdi_wpa_p2p_impl.h"
#include "wifi_hdi_util.h"
#include "wifi_common_util.h"
#include "wifi_common_def.h"
#include "hdi_struct_toolkit.h"
#include "wifi_hdi_wpa_proxy.h"
#include "define.h"

#ifndef UT_TEST
#include "wifi_log.h"
#else
#define static
#define LOGI(...)
#define LOGE(...)
#endif

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaClient"

#define HOSTAPD_CFG_VALUE_ON 1
#define DEFAULT_HOSTAPD_CONF_PATH CONFIG_ROOR_DIR"/wpa_supplicant/hostapd.conf"

namespace OHOS {
namespace Wifi {
#define MAX_IFACENAME_LEN 6
#define MAX_CMD_BUFFER_SIZE 1024
#define MAX_PASSWORD_LEN 32
constexpr int PMF_OPTIONAL = 1;
constexpr int PMF_REQUIRED = 2;
const int BUFFER_SIZE = 4096;
constexpr int WIFI_HDI_STR_MAC_LENGTH = 17;
constexpr int WIFI_HDI_MAX_STR_LENGTH = 512;
constexpr int WIFI_MAX_SCAN_COUNT = 256;
constexpr int P2P_SUPPLICANT_DISCONNECTED = 0;
constexpr int P2P_SUPPLICANT_CONNECTED = 1;
constexpr int BAND_WIDTH_OFFSET = 16;

WifiErrorNo WifiHdiWpaClient::StartWifi(const std::string &ifaceName, int instId)
{
    WifiEventCallback callback;
    callback.onConnectChanged = [](int param1, int param2, const std::string &param3) {};
    ReqRegisterStaEventCallback(callback, ifaceName.c_str(), instId);
    LOGI("WifiHdiWpaClient StartWifi ifaceName:%{public}s instId:%{public}d", ifaceName.c_str(), instId);
    return HdiWpaStaStart(ifaceName.c_str(), instId);
}

WifiErrorNo WifiHdiWpaClient::StopWifi(int instId)
{
    return HdiWpaStaStop(instId);
}

WifiErrorNo WifiHdiWpaClient::ReqConnect(int networkId, const char *ifaceName)
{
    return HdiWpaStaConnect(networkId, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqReconnect(const char *ifaceName)
{
    return HdiWpaStaReconnect(ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqReassociate(const char *ifaceName)
{
    return HdiWpaStaReassociate(ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqDisconnect(const char *ifaceName)
{
    return HdiWpaStaDisconnect(ifaceName);
}

WifiErrorNo WifiHdiWpaClient::GetStaCapabilities(unsigned int &capabilities)
{
    capabilities = 0;
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::GetStaDeviceMacAddress(std::string &mac, const char *ifaceName)
{
    char macAddr[HAL_BSSID_LENGTH + 1] = {0};
    int macAddrLen = HAL_BSSID_LENGTH + 1;
    WifiErrorNo err = HdiWpaStaGetDeviceMacAddress(macAddr, macAddrLen, ifaceName);
    if (err == WIFI_HAL_OPT_OK) {
        mac = std::string(macAddr);
    }
    return err;
}

WifiErrorNo WifiHdiWpaClient::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::SetConnectMacAddr(const std::string &mac)
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::Scan(const WifiHalScanParam &scanParam)
{
    return HdiWpaStaScan();
}

WifiErrorNo WifiHdiWpaClient::QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    LOGI("WifiHdiWpaClient::%{public}s enter", __func__);
    int size = HAL_GET_MAX_SCAN_INFO;
    ScanInfo *results = HdiWpaStaGetScanInfos(&size, GetHdiStaIfaceName(INSTID_WLAN0));
    if (results == NULL) {
        return size == 0 ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
    }
    for (int i = 0; i < size; ++i) {
        InterScanInfo tmp;
        tmp.ssid = results[i].ssid;
        tmp.bssid = results[i].bssid;
        tmp.frequency = results[i].freq;
        tmp.rssi = results[i].siglv;
        tmp.timestamp = results[i].timestamp;
        tmp.capabilities = results[i].flags;
        tmp.channelWidth = (WifiChannelWidth)results[i].channelWidth;
        tmp.centerFrequency0 = results[i].centerFrequency0;
        tmp.centerFrequency1 = results[i].centerFrequency1;
        tmp.isVhtInfoExist = results[i].isVhtInfoExist;
        tmp.isHtInfoExist = results[i].isHtInfoExist;
        tmp.isHeInfoExist = results[i].isHeInfoExist;
        tmp.isErpExist = results[i].isErpExist;
        tmp.maxRates = results[i].maxRates > results[i].extMaxRates ? results[i].maxRates : results[i].extMaxRates;
        LOGI("WifiHdiWpaClient::QueryScanInfos ssid = %{public}s, ssid = %{public}s",
            SsidAnonymize(results[i].ssid).c_str(), MacAnonymize(results[i].bssid).c_str());
        for (int j = 0; j < results[i].ieSize; ++j) {
            WifiInfoElem infoElemTmp;
            int infoElemSize = results[i].infoElems[j].size;
            infoElemTmp.id = results[i].infoElems[j].id;
            for (int k = 0; k < infoElemSize; ++k) {
                infoElemTmp.content.emplace_back(results[i].infoElems[j].content[k]);
            }
            if (results[i].infoElems[j].content) {
                free(results[i].infoElems[j].content);
            }
            tmp.infoElems.emplace_back(infoElemTmp);
        }
        if (results[i].infoElems) {
            free(results[i].infoElems);
        }
        tmp.isHiLinkNetwork = results[i].isHiLinkNetwork;
        scanInfos.emplace_back(tmp);
    }
    free(results);
    results = nullptr;
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::ReqStartPnoScan(const WifiHalPnoScanParam &scanParam)
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqStopPnoScan(void)
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::RemoveDevice(int networkId, const char *ifaceName)
{
    if (networkId < 0) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }

    return HdiWpaStaRemoveNetwork(networkId, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ClearDeviceConfig(const char *ifaceName) const
{
    return HdiWpaStaRemoveNetwork(-1, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::GetNextNetworkId(int &networkId, const char *ifaceName)
{
    return HdiWpaStaAddNetwork(&networkId, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqEnableNetwork(int networkId, const char *ifaceName)
{
    return HdiWpaStaEnableNetwork(networkId, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqDisableNetwork(int networkId, const char *ifaceName)
{
    return HdiWpaStaDisableNetwork(networkId, ifaceName);
}

void WifiHdiWpaClient::SetWapiConfig(const WifiHalDeviceConfig &config, SetNetworkConfig *conf, int &num)
{
    LOGI("Enter SetWapiConfig, keyMgmt is %{public}s, pskType is %{public}d", config.keyMgmt.c_str(),
        config.wapiPskType);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_KEYMGMT, config.keyMgmt);
    if (config.keyMgmt == KEY_MGMT_WAPI_PSK) {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_WAPI_PSK_TYPE, config.wapiPskType);
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WAPI_PSK, config.psk);
    } else if (config.keyMgmt == KEY_MGMT_WAPI_CERT) {
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WAPI_USER_CERT, config.wapiUserCertData);
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WAPI_CA_CERT, config.wapiAsCertData);
    }
}

WifiErrorNo WifiHdiWpaClient::SetDeviceConfig(int networkId, const WifiHalDeviceConfig &config, const char *ifaceName)
{
    if (CheckValidDeviceConfig(config) != WIFI_HAL_OPT_OK) {
        LOGE("SetDeviceConfig, CheckValidDeviceConfig return error!");
        return WIFI_HAL_OPT_FAILED;
    }
    SetNetworkConfig conf[DEVICE_CONFIG_END_POS];
    if (memset_s(conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        LOGE("SetDeviceConfig, memset_s return error!");
        return WIFI_HAL_OPT_FAILED;
    }
    int num = 0;
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_SSID, config.ssid);
    do {
        if (config.keyMgmt.find(KEY_MGMT_WAPI) != std::string::npos) {
            SetWapiConfig(config, conf, num);
            break;
        }
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PSK, config.psk);
        if (config.keyMgmt.find(KEY_MGMT_SAE) != std::string::npos) {
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_SAE_PASSWD, config.psk);
        }
        if (config.keyMgmt == KEY_MGMT_NONE || config.keyMgmt == KEY_MGMT_WEP) {
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_KEYMGMT, KEY_MGMT_NONE);
        } else {
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_KEYMGMT, config.keyMgmt);
        }
    } while (0);
    EapMethod eapMethod = WifiEapConfig::Str2EapMethod(config.eapConfig.eap);
    LOGI("%{public}s, eap:%{public}s, eapMethod:%{public}d, identity:%{private}s, num:%{public}d",
        __func__, config.eapConfig.eap.c_str(), eapMethod, config.eapConfig.identity.c_str(), num);
    switch (eapMethod) {
        case EapMethod::EAP_PEAP:
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eapConfig.eap);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.eapConfig.identity);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PASSWORD, config.eapConfig.password);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_CA_CERT, config.eapConfig.caCertPath);
            if (config.eapConfig.phase2Method != static_cast<int>(Phase2Method::NONE)) {
                std::string strPhase2Method = WifiEapConfig::Phase2MethodToStr(config.eapConfig.eap,
                    config.eapConfig.phase2Method);
                num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_PHASE2METHOD, strPhase2Method);
            }
            break;
        case EapMethod::EAP_TLS:
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eapConfig.eap);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.eapConfig.identity);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_CA_CERT, config.eapConfig.caCertPath);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_CLIENT_CERT, config.eapConfig.clientCert);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_PRIVATE_KEY, config.eapConfig.privateKey);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PASSWORD, config.eapConfig.password);
            break;
        case EapMethod::EAP_TTLS:
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eapConfig.eap);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.eapConfig.identity);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_CA_CERT, config.eapConfig.caCertPath);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PASSWORD, config.eapConfig.password);
            if (config.eapConfig.phase2Method != static_cast<int>(Phase2Method::NONE)) {
                std::string strPhase2Method = WifiEapConfig::Phase2MethodToStr(config.eapConfig.eap,
                    config.eapConfig.phase2Method);
                num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_PHASE2METHOD, strPhase2Method);
            }
            break;
        case EapMethod::EAP_PWD:
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eapConfig.eap);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.eapConfig.identity);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PASSWORD, config.eapConfig.password);
            break;
        case EapMethod::EAP_SIM:
        case EapMethod::EAP_AKA:
        case EapMethod::EAP_AKA_PRIME:
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eapConfig.eap);
            num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.eapConfig.identity);
            break;
        default:
            LOGE("%{public}s, invalid eapMethod:%{public}d", __func__, eapMethod);
            break;
    }

    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_BSSID, config.bssid);
    int i = 0;
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WEP_KEY_0, config.wepKeys[i++]);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WEP_KEY_1, config.wepKeys[i++]);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WEP_KEY_2, config.wepKeys[i++]);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_WEP_KEY_3, config.wepKeys[i++]);
    if (config.priority >= 0) {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_PRIORITY, config.priority);
    }
    if (config.scanSsid == 1) {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_SCAN_SSID, config.scanSsid);
    }
    if (config.wepKeyIdx >= 0) {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_WEP_KEY_IDX, config.wepKeyIdx);
    }
    if (config.authAlgorithms > 0) {
        num += PushDeviceConfigAuthAlgorithm(conf + num, DEVICE_CONFIG_AUTH_ALGORITHMS, config.authAlgorithms);
    }
    if (config.isRequirePmf) {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_IEEE80211W, PMF_REQUIRED);
    } else {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_IEEE80211W, PMF_OPTIONAL);
    }
    if (config.allowedProtocols > 0) {
        std::string protocolsStr[] = {"WPA ", "RSN ", "WPA2 ", "OSEN ", "WAPI "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_ALLOW_PROTOCOLS, config.allowedProtocols,
                                         protocolsStr, sizeof(protocolsStr)/sizeof(protocolsStr[0]));
    }
    if (config.allowedPairwiseCiphers > 0) {
        std::string pairwiseCipherStr[] = {"NONE ", "TKIP ", "CCMP ", "GCMP ", "CCMP-256 ", "GCMP-256 ", "SMS4 "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_PAIRWISE_CIPHERS, config.allowedPairwiseCiphers,
                                         pairwiseCipherStr, sizeof(pairwiseCipherStr)/sizeof(pairwiseCipherStr[0]));
    }
    if (config.allowedGroupCiphers > 0) {
        std::string groupCipherStr[] = {"GTK_NOT_USED ", "TKIP ", "CCMP ", "GCMP ", "CCMP-256 ", "GCMP-256 ", "SMS4 "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_GROUP_CIPHERS, config.allowedGroupCiphers,
                                         groupCipherStr, sizeof(groupCipherStr)/sizeof(groupCipherStr[0]));
    }
    if (config.allowedGroupMgmtCiphers > 0) {
        std::string groupMgmtCipherStr[] = {"AES-128-CMAC ", "BIP-GMAC-128 ", "BIP-GMAC-256 ", "BIP-CMAC-256 "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_GROUP_MGMT_CIPHERS, config.allowedGroupMgmtCiphers,
                                         groupMgmtCipherStr, sizeof(groupMgmtCipherStr)/sizeof(groupMgmtCipherStr[0]));
    }
    if (num == 0) {
        return WIFI_HAL_OPT_OK;
    }
    return HdiWpaStaSetNetwork(networkId, conf, num, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::SetBssid(int networkId, const std::string &bssid, const char *ifaceName)
{
    SetNetworkConfig conf;
    int num = PushDeviceConfigString(&conf, DEVICE_CONFIG_BSSID, bssid, false);
    if (num == 0) {
        LOGE("SetBssid, PushDeviceConfigString return error!");
        return WIFI_HAL_OPT_OK;
    }
    
    return HdiWpaStaSetNetwork(networkId, &conf, num, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::SaveDeviceConfig(const char *ifaceName)
{
    return HdiWpaStaSaveConfig(ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqRegisterStaEventCallback(
    const WifiEventCallback &callback, const char *ifaceName, int instId)
{
    struct IWpaCallback cWifiHdiWpaCallback;
    if (memset_s(&cWifiHdiWpaCallback, sizeof(cWifiHdiWpaCallback), 0, sizeof(cWifiHdiWpaCallback)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }

    if (callback.onConnectChanged != nullptr) {
        cWifiHdiWpaCallback.OnEventDisconnected = OnEventDisconnected;
        cWifiHdiWpaCallback.OnEventConnected = OnEventConnected;
        cWifiHdiWpaCallback.OnEventBssidChanged = OnEventBssidChanged;
        cWifiHdiWpaCallback.OnEventStateChanged = OnEventStateChanged;
        cWifiHdiWpaCallback.OnEventTempDisabled = OnEventTempDisabled;
        cWifiHdiWpaCallback.OnEventAssociateReject = OnEventAssociateReject;
        cWifiHdiWpaCallback.OnEventWpsOverlap = OnEventWpsOverlap;
        cWifiHdiWpaCallback.OnEventWpsTimeout = OnEventWpsTimeout;
        cWifiHdiWpaCallback.OnEventAuthTimeout = OnEventAuthTimeout;
        cWifiHdiWpaCallback.OnEventScanResult = OnEventScanResult;
        cWifiHdiWpaCallback.OnEventStaNotify = OnEventStaNotify;
    }

    return RegisterHdiWpaStaEventCallback(&cWifiHdiWpaCallback, ifaceName, instId);
}

WifiErrorNo WifiHdiWpaClient::ReqStartWpsPbcMode(const WifiHalWpsConfig &config, const char *ifaceName)
{
    WifiWpsParam param;
    if (memset_s(&param, sizeof(param), 0, sizeof(param)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    param.anyFlag = config.anyFlag;
    param.multiAp = config.multiAp;
    if (strncpy_s(param.bssid, sizeof(param.bssid), config.bssid.c_str(), config.bssid.length()) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    return HdiWpaStaStartWpsPbcMode(&param, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqStartWpsPinMode(const WifiHalWpsConfig &config, int &pinCode, const char *ifaceName)
{
    WifiWpsParam param;
    if (memset_s(&param, sizeof(param), 0, sizeof(param)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    param.anyFlag = config.anyFlag;
    param.multiAp = config.multiAp;
    if (strncpy_s(param.bssid, sizeof(param.bssid), config.bssid.c_str(), config.bssid.length()) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    if (!config.pinCode.empty()) {
        if (strncpy_s(param.pinCode, sizeof(param.pinCode), config.pinCode.c_str(), config.pinCode.length()) != EOK) {
            return WIFI_HAL_OPT_FAILED;
        }
    }
    return HdiWpaStaStartWpsPinMode(&param, &pinCode, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqStopWps(const char *ifaceName)
{
    return HdiStopWpsSta(ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqGetRoamingCapabilities(WifiHalRoamCapability &capability)
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqSetRoamConfig(const WifiHalRoamConfig &config)
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqGetConnectSignalInfo(const std::string &endBssid, WifiSignalPollInfo &info) const
{
    return WIFI_HAL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqWpaAutoConnect(int enable, const char *ifaceName)
{
    return HdiWpaStaAutoConnect(enable, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaBlocklistClear(const char *ifaceName)
{
    return HdiWpaStaBlocklistClear(ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqSetPowerSave(bool enable, const char *ifaceName)
{
    return HdiWpaStaSetPowerSave(enable, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaSetCountryCode(const std::string &countryCode, const char *ifaceName)
{
    return HdiWpaStaSetCountryCode(countryCode.c_str(), ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaGetCountryCode(std::string &countryCode, const char *ifaceName)
{
    char szCountryCode[HAL_COUNTRY_CODE_LENGTH + 1] = "";
    if (WIFI_HAL_OPT_OK != HdiWpaStaGetCountryCode(szCountryCode, HAL_COUNTRY_CODE_LENGTH, ifaceName)) {
        return WIFI_HAL_OPT_FAILED;
    }
    countryCode = szCountryCode;
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::ReqWpaSetSuspendMode(bool mode, const char *ifaceName) const
{
    return HdiWpaStaSetSuspendMode(mode, ifaceName);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaShellCmd(const std::string &ifName, const std::string &cmd)
{
    char ifNameBuf[MAX_IFACENAME_LEN];
    if (strncpy_s(ifNameBuf, sizeof(ifNameBuf), ifName.c_str(), ifName.length()) != EOK) {
        LOGE("%{public}s: failed to copy", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
 
    char cmdBuf[MAX_CMD_BUFFER_SIZE];
    if (strncpy_s(cmdBuf, sizeof(cmdBuf), cmd.c_str(), cmd.length()) != EOK) {
        LOGE("%{public}s: failed to copy", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    return HdiWpaStaSetShellCmd(ifNameBuf, cmdBuf);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaGetPskPassphrase(const std::string &ifName, std::string &psk)
{
    char ifNameBuf[MAX_IFACENAME_LEN];
    char tmpPsk[MAX_CMD_BUFFER_SIZE] = {0};
    uint32_t pskLen = MAX_PASSWORD_LEN;
    if (strncpy_s(ifNameBuf, sizeof(ifNameBuf), ifName.c_str(), ifName.length()) != EOK) {
        LOGE("%{public}s: failed to copy", __func__);
        return WIFI_HAL_OPT_FAILED;
    }

    if (HdiWpaStaGetPskPassphrase(ifNameBuf, tmpPsk, pskLen) != WIFI_HAL_OPT_OK) {
        LOGE("%{public}s: GetPskPassphrase failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    psk = tmpPsk;
    return WIFI_HAL_OPT_OK;
}

int WifiHdiWpaClient::PushDeviceConfigString(
    SetNetworkConfig *pConfig, DeviceConfigType type, const std::string &msg, bool checkEmpty) const
{
    if (!checkEmpty || msg.length() > 0) {
        pConfig->cfgParam = type;
        if (strncpy_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), msg.c_str(), msg.length()) != EOK) {
            return 0;
        }
        return 1;
    } else {
        return 0;
    }
}

int WifiHdiWpaClient::PushDeviceConfigInt(SetNetworkConfig *pConfig, DeviceConfigType type, int i) const
{
    pConfig->cfgParam = type;
    if (snprintf_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), sizeof(pConfig->cfgValue) - 1, "%d", i) < 0) {
        return 0;
    }
    return 1;
}

int WifiHdiWpaClient::PushDeviceConfigAuthAlgorithm(
    SetNetworkConfig *pConfig, DeviceConfigType type, unsigned int alg) const
{
    pConfig->cfgParam = type;
    if (alg & 0x1) {
        if (strcat_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), "OPEN ") != EOK) {
            return 0;
        }
    }
    if (alg & 0x2) {
        if (strcat_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), "OPEN SHARED ") != EOK) {
            return 0;
        }
    }
    if (alg & 0x4) {
        if (strcat_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), "LEAP ") != EOK) {
            return 0;
        }
    }
    return 1;
}

int WifiHdiWpaClient::PushDeviceConfigParseMask(
    SetNetworkConfig *pConfig, DeviceConfigType type,
    unsigned int mask, const std::string parseStr[], int size) const
{
    pConfig->cfgParam = type;
    for (int i = 0; i < size; i++) {
        if (mask & (0x1 << i)) {
            if (strcat_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), parseStr[i].c_str()) != EOK) {
                return 0;
            }
        }
    }
    return 1;
}

WifiErrorNo WifiHdiWpaClient::CheckValidDeviceConfig(const WifiHalDeviceConfig &config) const
{
    if (config.psk.length() > 0) {
        if (config.psk.length() < HAL_PSK_MIN_LENGTH || config.psk.length() > HAL_PSK_MAX_LENGTH) {
            return WIFI_HAL_OPT_FAILED;
        }
    }
    if (config.authAlgorithms >= HAL_AUTH_ALGORITHM_MAX) { /* max is 0111 */
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::GetNetworkList(std::vector<WifiHalWpaNetworkInfo> &networkList, const char *ifaceName)
{
    HdiWifiWpaNetworkInfo *listNetwork = new HdiWifiWpaNetworkInfo[WIFI_MAX_SCAN_COUNT];
    if (listNetwork == nullptr) {
        LOGE("WifiHdiWpaClient::%{public}s alloc mem failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    uint32_t size = WIFI_MAX_SCAN_COUNT;
    if (WIFI_HAL_OPT_OK != HdiWpaListNetworks(listNetwork, &size, ifaceName)) {
        if (listNetwork != nullptr) {
            delete[] listNetwork;
            listNetwork = nullptr;
        }
        LOGE("WifiHdiWpaClient::%{public}s failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    for (uint32_t i = 0; i < size; i++) {
        WifiHalWpaNetworkInfo networkInfo;
        networkInfo.id = listNetwork[i].id;
        char szssid[WIFI_HDI_MAX_STR_LENGTH +1] = {0};
        for (uint32_t j = 0; j < listNetwork[i].ssidLen; j++) {
            szssid[j] = listNetwork[i].ssid[j];
        }
        networkInfo.ssid = szssid;
        char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(listNetwork[i].bssid, listNetwork[i].bssidLen, szBssid, sizeof(szBssid));
        networkInfo.bssid = szBssid;
        char flags[WIFI_HDI_MAX_STR_LENGTH +1] = {0};
        for (uint32_t j = 0; j < listNetwork[i].flagsLen;j++) {
            flags[j] = listNetwork[i].flags[j];
        }
        networkInfo.flag = flags;
        networkList.push_back(networkInfo);
        FreeHdiWifiWpaNetworkInfo(&listNetwork[i]);
    }
    if (listNetwork != nullptr) {
        delete[] listNetwork;
        listNetwork = nullptr;
    }
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::GetDeviceConfig(WifiHalGetDeviceConfig &config, const char *ifaceName)
{
    int32_t networkId = config.networkId;
    char param[WIFI_HDI_MAX_STR_LENGTH +1] = {0};
    if (memcpy_s(param, WIFI_HDI_MAX_STR_LENGTH, config.param.c_str(), config.param.length()) != EOK) {
        LOGE("WifiHdiWpaClient::%{public}s memcpy_s failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    char value[WIFI_HDI_MAX_STR_LENGTH +1] = {0};
    uint32_t valueLen = WIFI_HDI_MAX_STR_LENGTH;
    if (WIFI_HAL_OPT_OK != HdiWpaGetNetwork(networkId, param, value, valueLen, ifaceName)) {
        LOGE("WifiHdiWpaClient::%{public}s failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    config.value = value;
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::StartAp(int id, const std::string &ifaceName)
{
    return HdiStartAp(ifaceName.c_str(), id);
}

WifiErrorNo WifiHdiWpaClient::StopAp(int id)
{
    return HdiStopAp(id);
}

WifiErrorNo WifiHdiWpaClient::RegisterApEvent(IWifiApMonitorEventCallback callback, int id) const
{
    IHostapdCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    if (callback.onStaJoinOrLeave != nullptr) {
        cEventCallback.OnEventStaJoin = onEventStaJoin;
        cEventCallback.OnEventApState = onEventApState;
    }
    return HdiRegisterApEventCallback(&cEventCallback);
}

void WifiHdiWpaClient::AppendStr(std::string &dst, const char* format, va_list args)
{
    char space[MAX_CMD_BUFFER_SIZE] __attribute__((__uninitialized__));
    va_list argsTmp;

    va_copy(argsTmp, args);
    int result = vsnprintf_s(space, sizeof(space), sizeof(space) - 1, format, argsTmp);
    va_end(argsTmp);
    if (result >= 0) {
        dst.append(space, result);
        return;
    }
    if (result < 0) {
        LOGE("AppendStr failed");
        return;
    }
}

std::string WifiHdiWpaClient::StringCombination(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    std::string result;
    AppendStr(result, fmt, args);
    va_end(args);
    return result;
}

bool WifiHdiWpaClient::GetEncryptionString(const HotspotConfig &config, std::string &encryptionString)
{
    switch (config.GetSecurityType()) {
        case KeyMgmt::WPA_PSK:
            encryptionString = StringCombination(
                "wpa=3\n"
                "wpa_pairwise=TKIP CCMP\n"
                "wpa_passphrase=%s",
                config.GetPreSharedKey().c_str());
            break;
        case KeyMgmt::WPA2_PSK:
            encryptionString = StringCombination(
                "wpa=2\n"
                "rsn_pairwise=CCMP\n"
                "wpa_passphrase=%s",
                config.GetPreSharedKey().c_str());
            break;
        default:
            LOGE("unsupport security type");
            encryptionString = "";
            return false;
    }
    return true;
}

void WifiHdiWpaClient::GetChannelString(const HotspotConfig &config, std::string &channelString)
{
    uint32_t channel = (static_cast<uint32_t>(config.GetChannel()) |
        (static_cast<uint32_t>(config.GetBandWidth()) << BAND_WIDTH_OFFSET));
    LOGI("set ap channel mix info is %{public}u", channel);
    channelString = StringCombination(
        "channel=%u\n"
        "op_class=0",
        channel);
}

void WifiHdiWpaClient::GetModeString(const HotspotConfig &config, std::string &modeString)
{
    /* configure hardware mode */
    if (config.GetBand() == BandType::BAND_2GHZ) {
        modeString = "hw_mode=g";
    } else if (config.GetBand() == BandType::BAND_5GHZ) {
        modeString = "hw_mode=a";
    } else {
        LOGE("unsupport band");
        modeString = "";
    }
}

bool WifiHdiWpaClient::WriteConfigToFile(const std::string &fileContext)
{
    std::string destPath = DEFAULT_HOSTAPD_CONF_PATH;
    std::ofstream file;
    file.open(destPath, std::ios::out);
    if (!file.is_open()) {
        LOGE("hostapd file open failed");
        return false;
    }
    file << fileContext << std::endl;
    file.close();
    return true;
}

WifiErrorNo WifiHdiWpaClient::SetSoftApConfig(const std::string &ifName, const HotspotConfig &config, int id)
{
    std::string ssid2String;
    std::string encryptionString;
    std::string channelString;
    std::vector<uint8_t> ssidUtf8;
    std::string modeString;
    std::string fileContext;
    ssid2String = StringToHex(config.GetSsid());
    if (!GetEncryptionString(config, encryptionString)) {
        LOGE("set psk failed");
        return WIFI_HAL_OPT_FAILED;
    }
    GetChannelString(config, channelString);
    GetModeString(config, modeString);
    fileContext = StringCombination(
        "interface=%s\n"
        "driver=nl80211\n"
        "ctrl_interface=/data/service/el1/public/wifi/sockets/wpa\n"
        "ssid2=%s\n"
        "%s\n"
        "ieee80211n=1\n"
        "%s\n"
        "ignore_broadcast_ssid=0\n"
        "wowlan_triggers=any\n"
        "%s\n",
        ifName.c_str(), ssid2String.c_str(),
        channelString.c_str(),
        modeString.c_str(),
        encryptionString.c_str());
    if (!WriteConfigToFile(fileContext)) {
        LOGE("write config failed");
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::EnableAp(int id)
{
    if (HdiEnableAp(id) != WIFI_HAL_OPT_OK) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::GetStationList(std::vector<std::string> &result, int id)
{
    char *staInfos = new (std::nothrow) char[BUFFER_SIZE]();
    if (staInfos == nullptr) {
        return WIFI_HAL_OPT_FAILED;
    }
    WifiErrorNo err = HdiGetStaInfos(staInfos, BUFFER_SIZE, id);
    if (err != WIFI_HAL_OPT_OK) {
        delete[] staInfos;
        staInfos = nullptr;
        return WIFI_HAL_OPT_FAILED;
    }
    std::string strStaInfo = std::string(staInfos);
    SplitString(strStaInfo, ",", result);
    delete[] staInfos;
    staInfos = nullptr;
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::AddBlockByMac(const std::string &mac, int id)
{
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_HAL_OPT_INPUT_MAC_INVALID;
    }
    return HdiSetMacFilter(mac.c_str(), id);
}

WifiErrorNo WifiHdiWpaClient::DelBlockByMac(const std::string &mac, int id)
{
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_HAL_OPT_INPUT_MAC_INVALID;
    }
    return HdiDelMacFilter(mac.c_str(), id);
}

WifiErrorNo WifiHdiWpaClient::RemoveStation(const std::string &mac, int id)
{
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_HAL_OPT_INPUT_MAC_INVALID;
    }
    return HdiDisassociateSta(mac.c_str(), id);
}

WifiErrorNo WifiHdiWpaClient::ReqDisconnectStaByMac(const std::string &mac, int id)
{
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_HAL_OPT_INPUT_MAC_INVALID;
    }
    return HdiDisassociateSta(mac.c_str(), id);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pStart(const std::string &ifaceName, const bool hasPersisentGroup)
{
    WifiErrorNo ret = HdiWpaP2pStart(ifaceName.c_str(), hasPersisentGroup);
    if (ret == WIFI_HAL_OPT_OK) {
        OnEventP2pStateChanged(P2P_SUPPLICANT_CONNECTED);
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pStop()
{
    WifiErrorNo ret = HdiWpaP2pStop();
    if (ret == WIFI_HAL_OPT_OK) {
        OnEventP2pStateChanged(P2P_SUPPLICANT_DISCONNECTED);
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetDeviceName(const std::string &name) const
{
    return HdiP2pSetDeviceName(name.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetSsidPostfixName(const std::string &postfixName) const
{
    return HdiP2pSetSsidPostfixName(postfixName.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetWpsDeviceType(const std::string &type) const
{
    return HdiP2pSetWpsDeviceType(type.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetWpsSecondaryDeviceType(const std::string &type) const
{
    return HdiP2pSetWpsSecondaryDeviceType(type.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetWpsConfigMethods(const std::string &config) const
{
    return HdiP2pSetWpsConfigMethods(config.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pGetDeviceAddress(std::string &deviceAddress) const
{
    char address[HAL_P2P_DEV_ADDRESS_LEN] = {0};
    WifiErrorNo ret = HdiP2pGetDeviceAddress(address, HAL_P2P_DEV_ADDRESS_LEN);
    if (ret == WIFI_HAL_OPT_OK) {
        deviceAddress = address;
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pFlush() const
{
    return HdiP2pFlush();
}

WifiErrorNo WifiHdiWpaClient::ReqP2pFlushService() const
{
    return HdiP2pFlushService();
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSaveConfig() const
{
    return HdiP2pSaveConfig();
}

WifiErrorNo WifiHdiWpaClient::ReqP2pRegisterCallback(const P2pHalCallback &callbacks) const
{
    struct IWpaCallback cWifiHdiWpaCallback;
    if (memset_s(&cWifiHdiWpaCallback, sizeof(cWifiHdiWpaCallback), 0, sizeof(cWifiHdiWpaCallback)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }

    if (callbacks.onConnectSupplicant != nullptr) {
        cWifiHdiWpaCallback.OnEventDeviceFound = OnEventDeviceFound;
        cWifiHdiWpaCallback.OnEventDeviceLost = OnEventDeviceLost;
        cWifiHdiWpaCallback.OnEventGoNegotiationRequest = OnEventGoNegotiationRequest;
        cWifiHdiWpaCallback.OnEventGoNegotiationCompleted = OnEventGoNegotiationCompleted;
        cWifiHdiWpaCallback.OnEventInvitationReceived = OnEventInvitationReceived;
        cWifiHdiWpaCallback.OnEventInvitationResult = OnEventInvitationResult;
        cWifiHdiWpaCallback.OnEventGroupFormationSuccess = OnEventGroupFormationSuccess;
        cWifiHdiWpaCallback.OnEventGroupFormationFailure = OnEventGroupFormationFailure;
        cWifiHdiWpaCallback.OnEventGroupStarted = OnEventGroupStarted;
        cWifiHdiWpaCallback.OnEventGroupInfoStarted = OnEventGroupInfoStarted;
        cWifiHdiWpaCallback.OnEventGroupRemoved = OnEventGroupRemoved;
        cWifiHdiWpaCallback.OnEventProvisionDiscoveryCompleted = OnEventProvisionDiscoveryCompleted;
        cWifiHdiWpaCallback.OnEventFindStopped = OnEventFindStopped;
        cWifiHdiWpaCallback.OnEventServDiscReq = OnEventServDiscReq;
        cWifiHdiWpaCallback.OnEventServDiscResp = OnEventServDiscResp;
        cWifiHdiWpaCallback.OnEventStaConnectState = OnEventStaConnectState;
        cWifiHdiWpaCallback.OnEventIfaceCreated = OnEventIfaceCreated;
        cWifiHdiWpaCallback.OnEventStaNotify = OnEventStaNotify;
    }

    return RegisterHdiWpaP2pEventCallback(&cWifiHdiWpaCallback);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetupWpsPbc(const std::string &groupInterface, const std::string &bssid) const
{
    return HdiP2pSetupWpsPbc(groupInterface.c_str(), bssid.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetupWpsPin(
    const std::string &groupInterface, const std::string &address, const std::string &pin, std::string &result) const
{
    if (!pin.empty() && pin.size() != HAL_PIN_CODE_LENGTH) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
    char szPinCode[1024] = {0};
    WifiErrorNo ret = HdiP2pSetupWpsPin(groupInterface.c_str(), address.c_str(), pin.c_str(), szPinCode);
    if (ret == WIFI_HAL_OPT_OK) {
        result = szPinCode;
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pRemoveNetwork(int networkId) const
{
    return HdiP2pRemoveNetwork(networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pListNetworks(std::map<int, WifiP2pGroupInfo> &mapGroups) const
{
    HdiP2pNetworkList infoList = {0};
    WifiErrorNo ret = HdiP2pListNetworks(&infoList);
    if (ret != WIFI_HAL_OPT_OK) {
        return ret;
    }
    if (infoList.infos == nullptr) {
        return ret;
    }
    LOGI("ReqP2pListNetworks size=%{public}d", infoList.infoNum);
    for (int i = 0; i < infoList.infoNum; ++i) {
        WifiP2pGroupInfo groupInfo;
        groupInfo.SetNetworkId(infoList.infos[i].id);
        groupInfo.SetGroupName((char *)infoList.infos[i].ssid);

        char address[18] = {0};
        ConvertMacArr2String(infoList.infos[i].bssid, ETH_ALEN, address, sizeof(address));
        WifiP2pDevice device;
        device.SetDeviceAddress(address);
        groupInfo.SetOwner(device);
        if (strstr((char *)infoList.infos[i].flags, "P2P-PERSISTENT") != nullptr) {
            groupInfo.SetIsPersistent(true);
        }
        mapGroups.insert(std::pair<int, WifiP2pGroupInfo>(infoList.infos[i].id, groupInfo));
        std::string ssid(reinterpret_cast<const char*>(infoList.infos[i].ssid));
        LOGI("ReqP2pListNetworks id=%{public}d ssid=%{public}s address=%{private}s",
            infoList.infos[i].id, SsidAnonymize(ssid).c_str(), address);
    }
    FreeHdiP2pNetworkList(&infoList);
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetGroupMaxIdle(const std::string &groupInterface, size_t time) const
{
    return HdiP2pSetGroupMaxIdle(groupInterface.c_str(), time);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetPowerSave(const std::string &groupInterface, bool enable) const
{
    int flag = enable;
    return HdiP2pSetPowerSave(groupInterface.c_str(), flag);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetWfdEnable(bool enable) const
{
    int flag = enable;
    return HdiP2pSetWfdEnable(flag);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetWfdDeviceConfig(const std::string &config) const
{
    return HdiP2pSetWfdDeviceConfig(config.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pStartFind(size_t timeout) const
{
    return HdiP2pStartFind(timeout);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pStopFind() const
{
    return HdiP2pStopFind();
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetExtListen(bool enable, size_t period, size_t interval) const
{
    if (enable) {
        if (period < HAL_P2P_LISTEN_MIN_TIME || period > HAL_P2P_LISTEN_MAX_TIME ||
            interval < HAL_P2P_LISTEN_MIN_TIME || interval > HAL_P2P_LISTEN_MAX_TIME || period > interval) {
            return WIFI_HAL_OPT_INVALID_PARAM;
        }
    }
    int flag = enable;
    return HdiP2pSetExtListen(flag, period, interval);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetListenChannel(size_t channel, unsigned char regClass) const
{
    return HdiP2pSetListenChannel(channel, regClass);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pConnect(const WifiP2pConfigInternal &config, bool isJoinExistingGroup,
    std::string &pin) const
{
    LOGI("ReqP2pConnect");
    P2pConnectInfo info = {0};
    info.mode = isJoinExistingGroup;
    info.persistent = config.GetNetId();
    if (isJoinExistingGroup) {
        info.goIntent = 0;
    } else {
        info.goIntent = config.GetGroupOwnerIntent();
    }
    if (info.goIntent < HAL_P2P_GO_INTENT_MIN_LENGTH || info.goIntent > HAL_P2P_GO_INTENT_MAX_LENGTH) {
        info.goIntent = HAL_P2P_GO_INTENT_DEFAULT_LENGTH;
    }
    std::string address = config.GetDeviceAddress();
    if (address.size() < HAL_BSSID_LENGTH) {
        LOGI("ReqP2pConnect Device Address is too short");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
    WpsMethod mode = config.GetWpsInfo().GetWpsMethod();
    if (mode == WpsMethod::WPS_METHOD_LABEL) {
        mode = WpsMethod::WPS_METHOD_KEYPAD;
    }
    info.provdisc = (int)mode;
    std::string pinCode = config.GetWpsInfo().GetPin();
    if (mode == WpsMethod::WPS_METHOD_PBC && !pinCode.empty()) {
        LOGI("ReqP2pConnect Expected empty pin for PBC.");
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
    if (strncpy_s(info.peerDevAddr, sizeof(info.peerDevAddr), address.c_str(), address.length()) != EOK ||
        strncpy_s(info.pin, sizeof(info.pin), pinCode.c_str(), pinCode.length()) != EOK) {
        LOGI("ReqP2pConnect failed");
        return WIFI_HAL_OPT_FAILED;
    }
    char resPin[HAL_PIN_CODE_LENGTH + 1] = {0};
    WifiErrorNo ret = HdiP2pConnect(&info, resPin, HAL_PIN_CODE_LENGTH + 1);
    if (ret == WIFI_HAL_OPT_OK) {
        pin = resPin;
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pCancelConnect() const
{
    return HdiP2pCancelConnect();
}

WifiErrorNo WifiHdiWpaClient::ReqP2pProvisionDiscovery(const WifiP2pConfigInternal &config) const
{
    WpsMethod mode = config.GetWpsInfo().GetWpsMethod();
    if (mode == WpsMethod::WPS_METHOD_LABEL) {
        mode = WpsMethod::WPS_METHOD_DISPLAY;
    } else if (mode == WpsMethod::WPS_METHOD_DISPLAY) {
        mode = WpsMethod::WPS_METHOD_KEYPAD;
    } else if (mode == WpsMethod::WPS_METHOD_KEYPAD) {
        mode = WpsMethod::WPS_METHOD_DISPLAY;
    } else if (mode != WpsMethod::WPS_METHOD_PBC) {
        return WIFI_HAL_OPT_FAILED;
    }
    return HdiP2pProvisionDiscovery(config.GetDeviceAddress().c_str(), static_cast<int>(mode));
}

WifiErrorNo WifiHdiWpaClient::ReqP2pAddGroup(bool isPersistent, int networkId, int freq) const
{
    int flag = isPersistent;
    return HdiP2pAddGroup(flag, networkId, freq);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pRemoveGroup(const std::string &groupInterface) const
{
    return HdiP2pRemoveGroup(groupInterface.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pRemoveGroupClient(const std::string &deviceMac, const std::string &ifName) const
{
    return HdiP2pRemoveGroupClient(deviceMac.c_str(), ifName.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pInvite(const WifiP2pGroupInfo &group, const std::string &deviceAddr) const
{
    return HdiP2pInvite(deviceAddr.c_str(), group.GetOwner().GetDeviceAddress().c_str(),
        group.GetInterface().c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pReinvoke(int networkId, const std::string &deviceAddr) const
{
    LOGI("HdiP2pReinvoke networkId=%{public}d, bssid=%{public}s", networkId, MacAnonymize(deviceAddr).c_str());
    return HdiP2pReinvoke(networkId, deviceAddr.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pGetGroupCapability(const std::string &deviceAddress, uint32_t &cap) const
{
    int capacity = 0;
    WifiErrorNo ret = HdiP2pGetGroupCapability(deviceAddress.c_str(), capacity);
    if (ret == WIFI_HAL_OPT_OK) {
        cap = capacity;
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pAddService(const WifiP2pServiceInfo &info) const
{
    WifiErrorNo ret = WIFI_HAL_OPT_OK;
    HdiP2pServiceInfo servInfo = {0};
    std::vector<std::string> queryList = info.GetQueryList();
    for (auto iter = queryList.begin(); iter != queryList.end(); iter++) {
        std::vector<std::string> vec;
        SplitString(*iter, " ", vec);
        if (vec.size() < HAL_P2P_SERVICE_TYPE_MIN_SIZE) {
            return WIFI_HAL_OPT_FAILED;
        }
        if (memset_s(&servInfo, sizeof(servInfo), 0, sizeof(servInfo)) != EOK) {
            return WIFI_HAL_OPT_FAILED;
        }
        const std::string &tmp = vec[HAL_P2P_SERVICE_TYPE_2_POS];
        if (vec[0] == "upnp") {
            servInfo.mode = 0;
            servInfo.version = atoi(vec[1].c_str());
            if (strncpy_s((char *)servInfo.name, sizeof(servInfo.name), tmp.c_str(), tmp.length()) != EOK) {
                return WIFI_HAL_OPT_FAILED;
            }
            ret = HdiP2pAddService(&servInfo);
        } else if (vec[0] == "bonjour") {
            servInfo.mode = 1;
            if (strncpy_s((char *)servInfo.query, sizeof(servInfo.query), vec[1].c_str(), vec[1].length()) != EOK ||
                strncpy_s((char *)servInfo.resp, sizeof(servInfo.resp), tmp.c_str(), tmp.length()) != EOK) {
                return WIFI_HAL_OPT_FAILED;
            }
            ret = HdiP2pAddService(&servInfo);
        } else {
            ret = WIFI_HAL_OPT_FAILED;
        }
        if (ret != WIFI_HAL_OPT_OK) {
            break;
        }
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pRemoveService(const WifiP2pServiceInfo &info) const
{
    WifiErrorNo ret = WIFI_HAL_OPT_OK;
    HdiP2pServiceInfo servInfo = {0};
    std::vector<std::string> queryList = info.GetQueryList();
    for (auto iter = queryList.begin(); iter != queryList.end(); iter++) {
        std::vector<std::string> vec;
        SplitString(*iter, " ", vec);
        if (vec.size() < HAL_P2P_SERVICE_TYPE_MIN_SIZE) {
            return WIFI_HAL_OPT_FAILED;
        }
        if (memset_s(&servInfo, sizeof(servInfo), 0, sizeof(servInfo)) != EOK) {
            return WIFI_HAL_OPT_FAILED;
        }
        const std::string &tmp = vec[HAL_P2P_SERVICE_TYPE_2_POS];
        if (vec[0] == "upnp") {
            servInfo.mode = 0;
            servInfo.version = atoi(vec[1].c_str());
            if (strncpy_s((char *)servInfo.name, sizeof(servInfo.name), tmp.c_str(), tmp.length()) != EOK) {
                return WIFI_HAL_OPT_FAILED;
            }
            ret = HdiP2pRemoveService(&servInfo);
        } else if (vec[0] == "bonjour") {
            servInfo.mode = 1;
            if (strncpy_s((char *)servInfo.query, sizeof(servInfo.query), vec[1].c_str(), vec[1].length()) != EOK) {
                return WIFI_HAL_OPT_FAILED;
            }
            ret = HdiP2pRemoveService(&servInfo);
        } else {
            ret = WIFI_HAL_OPT_FAILED;
        }
        if (ret != WIFI_HAL_OPT_OK) {
            break;
        }
    }
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pReqServiceDiscovery(
    const std::string &deviceAddress, const std::vector<unsigned char> &tlvs, std::string &reqID) const
{
    if (deviceAddress.size() != HAL_BSSID_LENGTH || tlvs.empty()) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
    unsigned size = (tlvs.size() << 1) + 1;
    char *pTlvs = (char *)calloc(size, sizeof(char));
    if (pTlvs == nullptr || Val2HexChar(tlvs, pTlvs, size) < 0) {
        free(pTlvs);
        pTlvs = nullptr;
        return WIFI_HAL_OPT_FAILED;
    }
    struct HdiP2pReqService wpsParam = {0};
    wpsParam.bssid = (unsigned char *)deviceAddress.c_str();
    wpsParam.msg = (unsigned char *)pTlvs;
    char retBuf[HAL_P2P_TMP_BUFFER_SIZE_128] = {0};
    WifiErrorNo ret = HdiP2pReqServiceDiscovery(&wpsParam, retBuf, HAL_P2P_TMP_BUFFER_SIZE_128);
    if (ret == WIFI_HAL_OPT_OK) {
        reqID = retBuf;
    }
    free(pTlvs);
    pTlvs = nullptr;
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pCancelServiceDiscovery(const std::string &id) const
{
    return HdiP2pCancelServiceDiscovery(id.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetRandomMac(bool enable) const
{
    return HdiP2pSetRandomMac(enable ? 1 : 0);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetMiracastType(int type) const
{
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiHdiWpaClient::ReqSetPersistentReconnect(int mode) const
{
    return HdiP2pSetPersistentReconnect(mode);
}

WifiErrorNo WifiHdiWpaClient::ReqRespServiceDiscovery(
    const WifiP2pDevice &device, int frequency, int dialogToken, const std::vector<unsigned char> &tlvs) const
{
    if (tlvs.empty()) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
    unsigned size = (tlvs.size() << 1) + 1;
    char *pTlvs = (char *)calloc(size, sizeof(char));
    if (pTlvs == nullptr || Val2HexChar(tlvs, pTlvs, size) < 0) {
        if (pTlvs != nullptr) {
            free(pTlvs);
            pTlvs = nullptr;
        }
        return WIFI_HAL_OPT_FAILED;
    }
    struct HdiP2pServDiscReqInfo wpsParam = {0};
    wpsParam.freq = frequency;
    wpsParam.dialogToken = dialogToken;
    wpsParam.mac = (unsigned char *)device.GetDeviceAddress().c_str();
    wpsParam.tlvs = (unsigned char *)pTlvs;
    WifiErrorNo ret = HdiP2pRespServerDiscovery(&wpsParam);
    free(pTlvs);
    pTlvs = nullptr;
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqSetServiceDiscoveryExternal(bool isExternalProcess) const
{
    return HdiP2pSetServDiscExternal(isExternalProcess);
}

WifiErrorNo WifiHdiWpaClient::ReqGetP2pPeer(const std::string &deviceAddress, WifiP2pDevice &device) const
{
    HdiP2pDeviceInfo peerInfo;
    if (memset_s(&peerInfo, sizeof(peerInfo), 0, sizeof(peerInfo)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    WifiErrorNo ret = HdiP2pGetPeer(deviceAddress.c_str(), &peerInfo);
    if (ret == WIFI_HAL_OPT_OK) {
        device.SetDeviceAddress((char *)peerInfo.p2pDeviceAddress);
        device.SetDeviceName((char *)peerInfo.deviceName);
        device.SetPrimaryDeviceType((char *)peerInfo.primaryDeviceType);
        device.SetWpsConfigMethod(peerInfo.configMethods);
        device.SetDeviceCapabilitys(peerInfo.deviceCapabilities);
        device.SetGroupCapabilitys(peerInfo.groupCapabilities);
        device.SetNetworkName((char *)peerInfo.operSsid);
    }
    FreeHdiP2pDeviceInfo(&peerInfo);
    return ret;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pGetSupportFrequencies(int band, std::vector<int> &frequencies) const
{
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetSingleConfig(int networkId,
    const std::string &key, const std::string &value) const
{
    LOGI("WifiHdiWpaClient::%{public}s enter, key=%{public}s", __func__, key.c_str());
    return HdiP2pSetSingleConfig(networkId, key.c_str(), value.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqP2pSetGroupConfig(int networkId, const HalP2pGroupConfig &config) const
{
    P2pGroupConfig conf[GROUP_CONFIG_END_POS];
    if (memset_s(conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    int num = 0;
    num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_SSID, "\"" + config.ssid + "\"");
    num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_BSSID, config.bssid);
    // If the PSK length is less than 8 or greater than 63, Do not set this psk field.
    if (config.psk.length() >= HAL_PSK_MIN_LENGTH && config.psk.length() < HAL_PSK_MAX_LENGTH) {
        std::string tmp = "\"" + config.psk + "\"";
        num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_PSK, tmp);
    } else if (config.psk.length() == HAL_PSK_MAX_LENGTH) {
        num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_PSK, config.psk);
    }
    num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_PROTO, config.proto);
    num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_KEY_MGMT, config.keyMgmt);
    num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_PAIRWISE, config.pairwise);
    num += PushP2pGroupConfigString(conf + num, GROUP_CONFIG_AUTH_ALG, config.authAlg);

    num += PushP2pGroupConfigInt(conf + num, GROUP_CONFIG_MODE, config.mode);
    num += PushP2pGroupConfigInt(conf + num, GROUP_CONFIG_DISABLED, config.disabled);
    if (num == 0) {
        return WIFI_HAL_OPT_OK;
    }
    LOGI("WifiHdiWpaClient::%{public}s enter, mode=%{public}d", __func__, config.mode);
    return HdiP2pSetGroupConfig(networkId, conf, num);
}

int WifiHdiWpaClient::PushP2pGroupConfigString(
    P2pGroupConfig *pConfig, P2pGroupConfigType type, const std::string &str) const
{
    if (str.length() > 0) {
        pConfig->cfgParam = type;
        if (strncpy_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), str.c_str(), str.length()) != EOK) {
            return 0;
        }
        return 1;
    } else {
        return 0;
    }
}

int WifiHdiWpaClient::PushP2pGroupConfigInt(P2pGroupConfig *pConfig, P2pGroupConfigType type, int i) const
{
    pConfig->cfgParam = type;
    if (snprintf_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), sizeof(pConfig->cfgValue) - 1, "%d", i) < 0) {
        return 0;
    }
    return 1;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pGetGroupConfig(int networkId, HalP2pGroupConfig &config) const
{
    char ssid[] = "ssid";
    char cfgValue[WIFI_P2P_GROUP_CONFIG_VALUE_LENGTH];
    if (HdiP2pGetGroupConfig(networkId, ssid, cfgValue) != 0) {
        return WIFI_HAL_OPT_FAILED;
    }
    config.ssid = cfgValue;
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::ReqP2pAddNetwork(int &networkId) const
{
    return HdiP2pAddNetwork(&networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqP2pHid2dConnect(const Hid2dConnectConfig &config) const
{
    Hid2dConnectInfo info;
    if (memset_s(&info, sizeof(info), 0, sizeof(info)) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    if (strncpy_s(info.ssid, sizeof(info.ssid), config.GetSsid().c_str(), config.GetSsid().length()) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    if (strncpy_s(info.bssid, sizeof(info.bssid), config.GetBssid().c_str(),
        config.GetBssid().length()) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    if (strncpy_s(info.passphrase, sizeof(info.passphrase),
        config.GetPreSharedKey().c_str(), config.GetPreSharedKey().length()) != EOK) {
        return WIFI_HAL_OPT_FAILED;
    }
    info.frequency = config.GetFrequency();
    if (config.GetDhcpMode() == DhcpMode::CONNECT_AP_DHCP ||
        config.GetDhcpMode() == DhcpMode::CONNECT_AP_NODHCP) {
        info.isLegacyGo = 1;
    } else {
        info.isLegacyGo = 0;
    }
    WifiErrorNo ret = HdiP2pHid2dConnect(&info);
    return ret;
}

WifiErrorNo WifiHdiWpaClient::DeliverP2pData(int32_t cmdType, int32_t dataType, const std::string& carryData) const
{
    return HdiDeliverP2pData(cmdType, dataType, carryData.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqRegisterNativeProcessCallback(const std::function<void(int)> &callback) const
{
    if (callback) {
        return HdiSetNativeProcessCallback(OnNativeProcessDeath);
    }
    return WIFI_HAL_OPT_FAILED;
}

bool WifiHdiWpaClient::HandleMloLinkData(char *staData, uint32_t staDataLen, std::vector<WifiLinkedInfo> &mloLinkInfo)
{
    if (staData == NULL || staDataLen == 0) {
        LOGE("%{public}s: hdiInfo null or length err copy", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    char *savedPtr = NULL;
    char *value = NULL;
    char *token = strtok_r(staData, "=", &savedPtr);
    WifiLinkedInfo linkInfo;
    while (token != NULL) {
        value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(token, "freq") == 0) {
            linkInfo.frequency = atoi(value);
        } else if (strcmp(token, "ap_link_addr") == 0) {
            linkInfo.bssid = value;
        } else if (strcmp(token, "sta_link_addr") == 0) {
            linkInfo.macAddress = value;
            mloLinkInfo.push_back(linkInfo);
        }
        token = strtok_r(NULL, "=", &savedPtr);
    }
    if (mloLinkInfo.size() != WIFI_MAX_MLO_LINK_NUM) {
        LOGE("%{public}s: err link num", __func__);
        mloLinkInfo.clear();
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::GetMloLinkedInfo(const std::string &ifName,
    std::vector<WifiLinkedInfo> &mloLinkInfo)
{
    char ifNameBuf[MAX_IFACENAME_LEN];
    char staParam[] = "MLO_STATUS";
    char staData[WIFI_MAX_WPA_STA_BUF_SIZE] = {0};
    uint32_t staDataLen = WIFI_MAX_WPA_STA_BUF_SIZE;
    if (strncpy_s(ifNameBuf, sizeof(ifNameBuf), ifName.c_str(), ifName.length()) != EOK) {
        LOGE("%{public}s: failed to copy", __func__);
        return WIFI_HAL_OPT_FAILED;
    }

    if (HdiWpaGetMloLinkedInfo(ifNameBuf, staParam, staData, staDataLen) != WIFI_HAL_OPT_OK) {
        LOGE("%{public}s: failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }

    if (!HandleMloLinkData(staData, staDataLen, mloLinkInfo)) {
        LOGE("%{public}s: HandleMloLinkData failed", __func__);
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
}
}  // namespace Wifi
}  // namespace OHOS
#endif