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
#include "wifi_hdi_wpa_sta_impl.h"
#include "wifi_hdi_wpa_callback.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaClient"

namespace OHOS {
namespace Wifi {
constexpr int PMF_OPTIONAL = 1;
constexpr int PMF_REQUIRED = 2;

WifiErrorNo WifiHdiWpaClient::StartWifi(void)
{
    return HdiStaStart();
}

WifiErrorNo WifiHdiWpaClient::StopWifi(void)
{
    return HdiWpaStaStop();
}

WifiErrorNo WifiHdiWpaClient::ReqConnect(int networkId)
{
    return HdiWpaStaConnect(networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqReconnect(void)
{
    return HdiWpaStaReconnect();
}

WifiErrorNo WifiHdiWpaClient::ReqReassociate(void)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqDisconnect(void)
{
    return HdiWpaStaDisconnect();
}

WifiErrorNo WifiHdiWpaClient::GetStaCapabilities(unsigned int &capabilities)
{
    capabilities = 0;
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::GetStaDeviceMacAddress(std::string &mac)
{
    char macAddr[WIFI_IDL_BSSID_LENGTH + 1] = {0};
    int macAddrLen = WIFI_IDL_BSSID_LENGTH;
    WifiErrorNo err = HdiWpaStaGetDeviceMacAddress(macAddr, macAddrLen);
    if (err == WIFI_IDL_OPT_OK) {
        mac = std::string(macAddr);
    }
    return err;
}

WifiErrorNo WifiHdiWpaClient::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::SetConnectMacAddr(const std::string &mac)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::Scan(const WifiScanParam &scanParam)
{
    return HdiWpaStaScan();
}

WifiErrorNo WifiHdiWpaClient::QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    int size = WIFI_IDL_GET_MAX_SCAN_INFO;
    ScanInfo* results = HdiWpaStaGetScanInfos(&size);
    if (results == NULL) {
        return size == 0 ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
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
        scanInfos.emplace_back(tmp);
    }
    free(results);
    results = nullptr;
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::ReqStartPnoScan(const WifiPnoScanParam &scanParam)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqStopPnoScan(void)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::RemoveDevice(int networkId)
{
    if (networkId < 0) {
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    return HdiWpaStaRemoveNetwork(networkId);
}

WifiErrorNo WifiHdiWpaClient::ClearDeviceConfig(void) const
{
    return HdiWpaStaRemoveNetwork(-1);
}

WifiErrorNo WifiHdiWpaClient::GetNextNetworkId(int &networkId)
{
    return HdiWpaStaAddNetwork(&networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqEnableNetwork(int networkId)
{
    return HdiWpaStaEnableNetwork(networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqDisableNetwork(int networkId)
{
    return HdiWpaStaDisableNetwork(networkId);
}

WifiErrorNo WifiHdiWpaClient::SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    if (CheckValidDeviceConfig(config) != WIFI_IDL_OPT_OK) {
        LOGE("SetDeviceConfig, CheckValidDeviceConfig return error!");
        return WIFI_IDL_OPT_FAILED;
    }
    SetNetworkConfig conf[DEVICE_CONFIG_END_POS];
    if (memset_s(conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        LOGE("SetDeviceConfig, memset_s return error!");
        return WIFI_IDL_OPT_FAILED;
    }
    int num = 0;
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_SSID, config.ssid);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PSK, config.psk);
    if (config.keyMgmt.find(KEY_MGMT_SAE) != std::string::npos) {
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_SAE_PASSWD, config.psk);
    }
    if (config.keyMgmt == KEY_MGMT_NONE || config.keyMgmt == KEY_MGMT_WEP) {
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_KEYMGMT, KEY_MGMT_NONE);
    } else {
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_KEYMGMT, config.keyMgmt);
    }
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eap);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.identity);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PASSWORD, config.password);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_CLIENT_CERT, config.clientCert);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_PRIVATE_KEY, config.privateKey);
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
    if (config.phase2Method != static_cast<int>(Phase2Method::NONE)) {
        std::string strPhase2Method = WifiEapConfig::Phase2MethodToStr(config.eap, config.phase2Method);
        num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP_PHASE2METHOD, strPhase2Method);
    }
    if (config.isRequirePmf) {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_IEEE80211W, PMF_REQUIRED);
    } else {
        num += PushDeviceConfigInt(conf + num, DEVICE_CONFIG_IEEE80211W, PMF_OPTIONAL);
    }
    if (config.allowedProtocols > 0) {
        std::string protocolsStr[] = {"WPA ", "RSN ", "WPA2 ", "OSEN "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_ALLOW_PROTOCOLS, config.allowedProtocols,
                                         protocolsStr, sizeof(protocolsStr)/sizeof(protocolsStr[0]));
    }
    if (config.allowedPairwiseCiphers > 0) {
        std::string pairwiseCipherStr[] = {"NONE ", "TKIP ", "CCMP ", "GCMP ", "CCMP-256 ", "GCMP-256 "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_PAIRWISE_CIPHERS, config.allowedPairwiseCiphers,
                                         pairwiseCipherStr, sizeof(pairwiseCipherStr)/sizeof(pairwiseCipherStr[0]));
    }
    if (config.allowedGroupCiphers > 0) {
        std::string groupCipherStr[] = {"GTK_NOT_USED ", "TKIP ", "CCMP ", "GCMP ", "CCMP-256 ", "GCMP-256 "};
        num += PushDeviceConfigParseMask(conf + num, DEVICE_CONFIG_GROUP_CIPHERS, config.allowedGroupCiphers,
                                         groupCipherStr, sizeof(groupCipherStr)/sizeof(groupCipherStr[0]));
    }
    if (num == 0) {
        return WIFI_IDL_OPT_OK;
    }
    return HdiWpaStaSetNetwork(networkId, conf, num);
}

WifiErrorNo WifiHdiWpaClient::SetBssid(int networkId, const std::string &bssid)
{
    SetNetworkConfig conf;
    int num = PushDeviceConfigString(&conf, DEVICE_CONFIG_BSSID, bssid, false);
    if (num == 0) {
        LOGE("SetBssid, PushDeviceConfigString return error!");
        return WIFI_IDL_OPT_OK;
    }
    
    return HdiWpaStaSetNetwork(networkId, &conf, num);
}

WifiErrorNo WifiHdiWpaClient::SaveDeviceConfig(void)
{
    return HdiWpaStaSaveConfig();
}

WifiErrorNo WifiHdiWpaClient::ReqRegisterStaEventCallback(const WifiEventCallback &callback)
{
    struct IWpaCallback cWifiHdiWpaCallback;
    if (memset_s(&cWifiHdiWpaCallback, sizeof(cWifiHdiWpaCallback), 0, sizeof(cWifiHdiWpaCallback)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
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
        cWifiHdiWpaCallback.OnEventScanResult = OnEventScanResult;
    }

    return RegisterHdiWpaStaEventCallback(&cWifiHdiWpaCallback);
}

WifiErrorNo WifiHdiWpaClient::ReqStartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    WifiWpsParam param;
    if (memset_s(&param, sizeof(param), 0, sizeof(param)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    param.anyFlag = config.anyFlag;
    param.multiAp = config.multiAp;
    if (strncpy_s(param.bssid, sizeof(param.bssid), config.bssid.c_str(), config.bssid.length()) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    return HdiWpaStaStartWpsPbcMode(&param);
}

WifiErrorNo WifiHdiWpaClient::ReqStartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    WifiWpsParam param;
    if (memset_s(&param, sizeof(param), 0, sizeof(param)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    param.anyFlag = config.anyFlag;
    param.multiAp = config.multiAp;
    if (strncpy_s(param.bssid, sizeof(param.bssid), config.bssid.c_str(), config.bssid.length()) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (!config.pinCode.empty()) {
        if (strncpy_s(param.pinCode, sizeof(param.pinCode), config.pinCode.c_str(), config.pinCode.length()) != EOK) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    return HdiWpaStaStartWpsPinMode(&param, &pinCode);
}

WifiErrorNo WifiHdiWpaClient::ReqStopWps(void)
{
    return HdiStopWpsSta();
}

WifiErrorNo WifiHdiWpaClient::ReqGetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqSetRoamConfig(const WifiIdlRoamConfig &config)
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqGetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info) const
{
    return WIFI_IDL_OPT_NOT_SUPPORT;
}

WifiErrorNo WifiHdiWpaClient::ReqWpaAutoConnect(int enable)
{
    return HdiWpaStaAutoConnect(enable);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaBlocklistClear(void)
{
    return HdiWpaStaBlocklistClear();
}

WifiErrorNo WifiHdiWpaClient::ReqSetPowerSave(bool enable)
{
    return HdiWpaStaSetPowerSave(enable);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaSetCountryCode(const std::string &countryCode)
{
    return HdiWpaSetCountryCode(countryCode.c_str());
}

WifiErrorNo WifiHdiWpaClient::ReqWpaSetSuspendMode(bool mode) const
{
    return HdiWpaStaSetSuspendMode(mode);
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

WifiErrorNo WifiHdiWpaClient::CheckValidDeviceConfig(const WifiIdlDeviceConfig &config) const
{
    if (config.psk.length() > 0) {
        if (config.psk.length() < WIFI_IDL_PSK_MIN_LENGTH || config.psk.length() > WIFI_IDL_PSK_MAX_LENGTH) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    if (config.authAlgorithms >= AUTH_ALGORITHM_MAX) { /* max is 0111 */
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}
}  // namespace Wifi
}  // namespace OHOS
#endif