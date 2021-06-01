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
#include "wifi_idl_client.h"
#include <cstdio>
#include "wifi_global_func.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "i_wifi.h"
#include "i_wifi_chip.h"
#include "i_wifi_chip_event_callback.h"
#include "i_wifi_hotspot_iface.h"
#include "i_wifi_sta_iface.h"
#include "i_wifi_supplicant_iface.h"


#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_WIFI_IDL_CLIENT"

namespace OHOS {
namespace Wifi {
const int BUFFER_SIZE = 4096;

WifiIdlClient::WifiIdlClient()
{
    pRpcClient = nullptr;
}

WifiIdlClient::~WifiIdlClient()
{
    if (pRpcClient != nullptr) {
        ReleaseRpcClient(pRpcClient);
        pRpcClient = nullptr;
    }
}

int WifiIdlClient::InitClient(void)
{
    const std::string idlSockPath = "/data/misc/wifi/unix_sock.sock";
    pRpcClient = CreateRpcClient(idlSockPath.c_str());
    if (pRpcClient == nullptr) {
        LOGE("init rpc client failed!");
        return -1;
    }
    return 0;
}

void WifiIdlClient::ExitAllClient(void)
{
    if (pRpcClient == nullptr) {
        return;
    }
    NotifyClear();
    return;
}

WifiErrorNo WifiIdlClient::StartWifi(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return Start();
}

WifiErrorNo WifiIdlClient::StopWifi(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return Stop();
}

WifiErrorNo WifiIdlClient::ReqConnect(int networkId)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return Connect(networkId);
}

WifiErrorNo WifiIdlClient::ReqReconnect(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return Reconnect();
}

WifiErrorNo WifiIdlClient::ReqReassociate(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return Reassociate();
}

WifiErrorNo WifiIdlClient::ReqDisconnect(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return Disconnect();
}

WifiErrorNo WifiIdlClient::GetStaCapabilities(unsigned int &capabilities)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return GetCapabilities((uint32_t *)&capabilities);
}

WifiErrorNo WifiIdlClient::GetStaDeviceMacAddress(std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    char szMac[WIFI_MAC_ADDR_LENGTH + 1] = {0};
    int len = WIFI_MAC_ADDR_LENGTH + 1;
    WifiErrorNo err = GetDeviceMacAddress((unsigned char *)szMac, &len);
    if (err == WIFI_IDL_OPT_OK) {
        mac = std::string(szMac);
    }
    return err;
}

WifiErrorNo WifiIdlClient::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }

    int values[WIFI_IDL_GET_MAX_BANDS] = {0};
    int size = WIFI_IDL_GET_MAX_BANDS;

    if (GetFrequencies(band, values, &size) != 0) {
        return WIFI_IDL_OPT_FAILED;
    }

    for (int i = 0; i < size; i++) {
        frequencies.push_back(values[i]);
    }

    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::SetConnectMacAddr(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return SetAssocMacAddr((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiIdlClient::SetScanMacAddress(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return SetScanningMacAddress((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiIdlClient::DisconnectLastRoamingBssid(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return DeauthLastRoamingBssid((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiIdlClient::ReqGetSupportFeature(long &feature)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return GetSupportFeature(&feature);
}

WifiErrorNo WifiIdlClient::SendRequest(const WifiStaRequest &request)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    /* RunCmd */
    LOGD("Start run cmd %{public}d about iface %s", request.cmdId, request.ifName.c_str());
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::SetTxPower(int power)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return SetWifiTxPower((int32_t)power);
}

WifiErrorNo WifiIdlClient::Scan(const WifiScanParam &scanParam)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    ScanSettings settings;
    if (memset_s(&settings, sizeof(settings), 0, sizeof(settings)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    bool bfail = false;
    do {
        if (scanParam.hiddenNetworkSsid.size() > 0) {
            settings.hiddenSsidSize = scanParam.hiddenNetworkSsid.size();
            settings.hiddenSsid = ConVectorToCArrayString(scanParam.hiddenNetworkSsid);
            if (settings.hiddenSsid == nullptr) {
                bfail = true;
                break;
            }
        }
        if (scanParam.scanFreqs.size() > 0) {
            settings.freqSize = scanParam.scanFreqs.size();
            settings.freqs = (int *)calloc(settings.freqSize, sizeof(int));
            if (settings.freqs == nullptr) {
                bfail = true;
                break;
            }
            for (int i = 0; i < settings.freqSize; ++i) {
                settings.freqs[i] = scanParam.scanFreqs[i];
            }
        }
        if (scanParam.scanStyle > 0) {
            settings.scanStyle = scanParam.scanStyle;
        }
    } while (0);
    WifiErrorNo err = WIFI_IDL_OPT_FAILED;
    if (!bfail) {
        err = StartScan(&settings);
    }
    if (settings.freqs != nullptr) {
        free(settings.freqs);
    }
    if (settings.hiddenSsid != nullptr) {
        for (int i = 0; i < settings.hiddenSsidSize; ++i) {
            free(settings.hiddenSsid[i]);
        }
        free(settings.hiddenSsid);
    }
    return err;
}

WifiErrorNo WifiIdlClient::ReGetNetworkList(std::vector<WifiWpaNetworkList> &networkList)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    NetworkList idlNetworkList[WIFI_IDL_GET_MAX_NETWORK_LIST];
    if (memset_s(idlNetworkList, sizeof(idlNetworkList), 0, sizeof(idlNetworkList)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    int size = WIFI_IDL_GET_MAX_NETWORK_LIST;
    WifiErrorNo err = GetNetworkList(idlNetworkList, &size);
    if (err != WIFI_IDL_OPT_OK) {
        return err;
    }
    for (int i = 0; i < size; ++i) {
        WifiWpaNetworkList tmp;
        tmp.id = idlNetworkList[i].id;
        tmp.ssid = idlNetworkList[i].ssid;
        tmp.bssid = idlNetworkList[i].bssid;
        tmp.flag = idlNetworkList[i].flags;
        networkList.emplace_back(tmp);
    }
    return err;
}

WifiErrorNo WifiIdlClient::QueryScanResults(std::vector<WifiScanResult> &scanResults)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    ScanResult results[WIFI_IDL_GET_MAX_SCAN_RESULT];
    if (memset_s(results, sizeof(results), 0, sizeof(results)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    int size = WIFI_IDL_GET_MAX_SCAN_RESULT;
    WifiErrorNo err = GetScanResults(results, &size);
    if (err != WIFI_IDL_OPT_OK) {
        return err;
    }
    for (int i = 0; i < size; ++i) {
        WifiScanResult tmp;
        tmp.ssid = results[i].ssid;
        tmp.bssid = results[i].bssid;
        tmp.infoElement = results[i].infoElement;
        tmp.frequency = results[i].frequency;
        tmp.signalLevel = results[i].signalLevel;
        tmp.timestamp = results[i].timestamp;
        tmp.capability = results[i].capability;
        tmp.associated = results[i].associated;
        scanResults.emplace_back(tmp);
    }
    return err;
}

WifiErrorNo WifiIdlClient::ConvertPnoScanParam(const WifiPnoScanParam &param, PnoScanSettings *pSettings)
{
    if (param.scanInterval > 0) {
        pSettings->scanInterval = param.scanInterval;
    }
    pSettings->minRssi2Dot4Ghz = param.minRssi2Dot4Ghz;
    pSettings->minRssi5Ghz = param.minRssi5Ghz;
    if (param.hiddenSsid.size() > 0) {
        pSettings->hiddenSsidSize = param.hiddenSsid.size();
        pSettings->hiddenSsid = ConVectorToCArrayString(param.hiddenSsid);
        if (pSettings->hiddenSsid == nullptr) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    if (param.savedSsid.size() > 0) {
        pSettings->savedSsidSize = param.savedSsid.size();
        pSettings->savedSsid = ConVectorToCArrayString(param.savedSsid);
        if (pSettings->savedSsid == nullptr) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    if (param.scanFreqs.size() > 0) {
        pSettings->freqSize = param.scanFreqs.size();
        pSettings->freqs = (int *)calloc(pSettings->freqSize, sizeof(int));
        if (pSettings->freqs == nullptr) {
            return WIFI_IDL_OPT_FAILED;
        }
        for (int i = 0; i < pSettings->freqSize; ++i) {
            pSettings->freqs[i] = param.scanFreqs[i];
        }
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::ReqStartPnoScan(const WifiPnoScanParam &scanParam)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    PnoScanSettings settings;
    if (memset_s(&settings, sizeof(settings), 0, sizeof(settings)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    WifiErrorNo err = ConvertPnoScanParam(scanParam, &settings);
    if (err == WIFI_IDL_OPT_OK) {
        err = StartPnoScan(&settings);
    }
    if (settings.freqs != nullptr) {
        free(settings.freqs);
    }
    if (settings.hiddenSsid != nullptr) {
        for (int i = 0; i < settings.hiddenSsidSize; ++i) {
            free(settings.hiddenSsid[i]);
        }
        free(settings.hiddenSsid);
    }
    if (settings.savedSsid != nullptr) {
        for (int i = 0; i < settings.savedSsidSize; ++i) {
            free(settings.savedSsid[i]);
        }
        free(settings.savedSsid);
    }
    return err;
}

WifiErrorNo WifiIdlClient::ReqStopPnoScan(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StopPnoScan();
}

WifiErrorNo WifiIdlClient::RemoveDeviceConfig(int networkId)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return RemoveNetwork(networkId);
}

WifiErrorNo WifiIdlClient::GetNextNetworkId(int &networkId)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return AddNetwork(&networkId);
}

WifiErrorNo WifiIdlClient::ReqEnableNetwork(int networkId)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return EnableNetwork(networkId);
}

WifiErrorNo WifiIdlClient::ReqDisableNetwork(int networkId)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return DisableNetwork(networkId);
}

WifiErrorNo WifiIdlClient::GetDeviceConfig(WifiIdlGetDeviceConfig &config)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    GetWpaNetWorkConfig conf;
    if (memset_s(&conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    conf.networkId = config.networkId;
    if (strncpy_s(conf.param, sizeof(conf.param), config.param.c_str(), sizeof(conf.param) - 1) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    int ret = WpaGetNetwork(&conf);
    if (ret != WIFI_IDL_OPT_OK) {
        return WIFI_IDL_OPT_FAILED;
    }
    config.value = conf.value;
    return WIFI_IDL_OPT_OK;
}

int WifiIdlClient::PushDeviceConfigString(NetWorkConfig *pConfig, DeviceConfigType type, const std::string &msg)
{
    if (msg.length() > 0) {
        pConfig->cfgParam = type;
        if (strncpy_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), msg.c_str(), sizeof(pConfig->cfgValue) - 1) !=
            EOK) {
            return 0;
        }
        return 1;
    } else {
        return 0;
    }
}

int WifiIdlClient::PushDeviceConfigInt(NetWorkConfig *pConfig, DeviceConfigType type, int i)
{
    pConfig->cfgParam = type;
    if (snprintf_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), sizeof(pConfig->cfgValue) - 1, "%d", i) < 0) {
        return 0;
    }
    return 1;
}

int WifiIdlClient::PushDeviceConfigAuthAlgorithm(NetWorkConfig *pConfig, DeviceConfigType type, unsigned int alg)
{
    pConfig->cfgParam = type;
    if (alg & 0x1) {
        if (strcat_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), "OPEN ") != EOK) {
            return 0;
        }
    }
    if (alg & 0x2) {
        if (strcat_s(pConfig->cfgValue, sizeof(pConfig->cfgValue), "SHARED ") != EOK) {
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

WifiErrorNo WifiIdlClient::CheckValidDeviceConfig(const WifiIdlDeviceConfig &config)
{
    if (config.psk.length() > 0) {
        if (config.psk.length() < WIFI_PSK_MIN_LENGTH || config.psk.length() > WIFI_PSK_MAX_LENGTH) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    if (config.authAlgorithms >= AUTH_ALGORITHM_MAX) { /* max is 0111 */
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckValidDeviceConfig(config) != WIFI_IDL_OPT_OK) {
        return WIFI_IDL_OPT_FAILED;
    }
    NetWorkConfig conf[DEVICE_CONFIG_END_POS];
    if (memset_s(&conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    int num = 0;
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_SSID, config.ssid);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PSK, config.psk);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_KEYMGMT, config.keyMgmt);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_EAP, config.eap);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_IDENTITY, config.identity);
    num += PushDeviceConfigString(conf + num, DEVICE_CONFIG_PASSWORD, config.password);
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
    if (num == 0) {
        return WIFI_IDL_OPT_OK;
    }
    return SetNetwork(networkId, conf, num);
}

WifiErrorNo WifiIdlClient::SaveDeviceConfig(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return SaveNetworkConfig();
}

WifiErrorNo WifiIdlClient::ReqRegisterStaEventCallback(const WifiEventCallback &callback)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    IWifiEventCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    cEventCallback.pInstance = callback.pInstance;
    cEventCallback.onConnectChanged = callback.onConnectChanged;
    cEventCallback.onWpaStateChanged = callback.onWpaStateChanged;
    cEventCallback.onSsidWrongkey = callback.onWpaSsidWrongKey;
    cEventCallback.onWpsOverlap = callback.onWpsOverlap;
    cEventCallback.onWpsTimeOut = callback.onWpsTimeOut;
    return RegisterStaEventCallback(cEventCallback);
}

WifiErrorNo WifiIdlClient::ReqStartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    WifiWpsParam param;
    if (memset_s(&param, sizeof(param), 0, sizeof(param)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    param.anyFlag = config.anyFlag;
    param.multiAp = config.multiAp;
    if (strncpy_s(param.bssid, sizeof(param.bssid), config.bssid.c_str(), sizeof(param.bssid) - 1) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StartWpsPbcMode(&param);
}

WifiErrorNo WifiIdlClient::ReqStartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    WifiWpsParam param;
    if (memset_s(&param, sizeof(param), 0, sizeof(param)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    param.anyFlag = config.anyFlag;
    param.multiAp = config.multiAp;
    if (strncpy_s(param.bssid, sizeof(param.bssid), config.bssid.c_str(), sizeof(param.bssid) - 1) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StartWpsPinMode(&param, &pinCode);
}

WifiErrorNo WifiIdlClient::ReqStopWps(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StopWps();
}

WifiErrorNo WifiIdlClient::ReqGetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    WifiRoamCapability tmp;
    if (memset_s(&tmp, sizeof(tmp), 0, sizeof(tmp)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    WifiErrorNo err = GetRoamingCapabilities(&tmp);
    if (err == WIFI_IDL_OPT_OK) {
        capability.maxBlocklistSize = tmp.maxBlocklistSize;
        capability.maxTrustlistSize = tmp.maxTrustlistSize;
    }
    return err;
}

char **WifiIdlClient::ConVectorToCArrayString(const std::vector<std::string> &vec)
{
    int size = vec.size();
    if (size == 0) {
        return nullptr;
    }
    char **list = (char **)calloc(size, sizeof(char *));
    if (list == nullptr) {
        return nullptr;
    }
    int i = 0;
    for (; i < size; ++i) {
        int len = vec[i].length();
        list[i] = (char *)calloc(len + 1, sizeof(char));
        if (list[i] == nullptr) {
            break;
        }
        if (strncpy_s(list[i], len + 1, vec[i].c_str(), len) != EOK) {
            break;
        }
    }
    if (i < size) {
        for (int j = 0; j <= i; ++j) {
            free(list[j]);
        }
        free(list);
        return nullptr;
    } else {
        return list;
    }
}

WifiErrorNo WifiIdlClient::ReqSetRoamConfig(const WifiIdlRoamConfig &config)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    char **blocklist = nullptr;
    int blocksize = config.blocklistBssids.size();
    char **trustlist = nullptr;
    int size = config.trustlistBssids.size();
    if (blocksize == 0 && size == 0) {
        return WIFI_IDL_OPT_FAILED;
    }
    WifiErrorNo err = WIFI_IDL_OPT_FAILED;
    do {
        if (blocksize > 0) {
            blocklist = ConVectorToCArrayString(config.blocklistBssids);
            if (blocklist == nullptr) {
                break;
            }
        }
        if (size > 0) {
            trustlist = ConVectorToCArrayString(config.trustlistBssids);
            if (trustlist == nullptr) {
                break;
            }
        }
        err = SetRoamConfig(blocklist, blocksize, trustlist, size);
    } while (0);
    if (blocklist != nullptr) {
        for (int i = 0; i < blocksize; ++i) {
            free(blocklist[i]);
        }
        free(blocklist);
    }
    if (trustlist != nullptr) {
        for (int i = 0; i < size; ++i) {
            free(trustlist[i]);
        }
        free(trustlist);
    }
    return err;
}

WifiErrorNo WifiIdlClient::StartAp(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StartSoftAp();
}

WifiErrorNo WifiIdlClient::StopAp(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StopSoftAp();
}

WifiErrorNo WifiIdlClient::SetSoftApConfig(const HotspotConfig &config)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    HostsapdConfig tmp;
    if (memset_s(&tmp, sizeof(tmp), 0, sizeof(tmp)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    tmp.ssidLen = config.GetSsid().length();
    if (strncpy_s(tmp.ssid, sizeof(tmp.ssid), config.GetSsid().c_str(), sizeof(tmp.ssid) - 1) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    tmp.preSharedKeyLen = config.GetPreSharedKey().length();
    if (strncpy_s(
        tmp.preSharedKey,
        sizeof(tmp.preSharedKey),
        config.GetPreSharedKey().c_str(),
        sizeof(tmp.preSharedKey) - 1) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    tmp.securityType = static_cast<int>(config.GetSecurityType());
    tmp.band = static_cast<int>(config.GetBand());
    tmp.channel = config.GetChannel();
    tmp.maxConn = config.GetMaxConn();
    return SetHostapdConfig(&tmp);
}

WifiErrorNo WifiIdlClient::GetStationList(std::vector<std::string> &result)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }

    char *staInfos = new char[BUFFER_SIZE]();
    if (staInfos == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    int32_t size = BUFFER_SIZE;
    if (GetStaInfos(staInfos, &size) != 0) {
        delete[] staInfos;
        return WIFI_IDL_OPT_FAILED;
    }
    std::string strStaInfo = std::string(staInfos);
    OHOS::Wifi::SplitString(strStaInfo, ",", result);
    delete[] staInfos;
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::SetHotspotConfig(int channel, const std::string &mscb)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return ConfigHotspot(channel, mscb.c_str());
}

WifiErrorNo WifiIdlClient::AddBlockByMac(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return SetMacFilter((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiIdlClient::DelBlockByMac(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return DelMacFilter((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiIdlClient::RemoveStation(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return DisassociateSta((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiIdlClient::GetFrequenciesByBand(int32_t band, std::vector<int> &frequencies)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }

    int values[WIFI_IDL_GET_MAX_BANDS] = {0};
    int size = WIFI_IDL_GET_MAX_BANDS;
    if (GetValidFrequenciesForBand(band, values, &size) != 0) {
        return WIFI_IDL_OPT_FAILED;
    }

    for (int i = 0; i < size; i++) {
        frequencies.push_back(values[i]);
    }

    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::RegisterApEvent(IWifiApEventCallback callback)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return RegisterAsscociatedEvent(callback);
}

WifiErrorNo WifiIdlClient::SetWifiCountryCode(const std::string &code)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return SetCountryCode(code.c_str());
}

WifiErrorNo WifiIdlClient::ReqDisconnectStaByMac(const std::string &mac)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    return DisassociateSta((unsigned char *)mac.c_str(), strlen(mac.c_str()));
}

WifiErrorNo WifiIdlClient::GetWifiChipObject(int id, IWifiChip &chip)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    LOGD("Get wifi chip object accord %{public}d, %{public}d",
        id,
        chip.i); /* fixed compile error, -Werror,-Wunused-parameter */
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::GetChipIds(std::vector<int> &ids)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    LOGD("start GetChipIds %{public}d", ids.size()); /* fixed compile error, -Werror,-Wunused-parameter */
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::GetUsedChipId(int &id)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    id = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::GetChipCapabilities(int &capabilities)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    capabilities = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::GetSupportedModes(std::vector<int> &modes)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    int size = WIFI_IDL_INTERFACE_SUPPORT_COMBINATIONS;
    int supportModes[WIFI_IDL_INTERFACE_SUPPORT_COMBINATIONS] = {0};
    WifiErrorNo err = GetSupportedComboModes(supportModes, &size);
    if (err == WIFI_IDL_OPT_OK) {
        for (int i = 0; i < size; ++i) {
            modes.push_back(supportModes[i]);
        }
    }
    return err;
}

WifiErrorNo WifiIdlClient::ConfigRunModes(int mode)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    LOGD("start ConfigRunModes mode %{public}d", mode);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::GetCurrentMode(int &mode)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    mode = 0; /* fixed compile error, -Werror,-Wunused-parameter */
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::RegisterChipEventCallback(WifiChipEventCallback &callback)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    IWifiChipEventCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    cEventCallback.onIfaceAdded = callback.onIfaceAdded;
    cEventCallback.onIfaceRemoved = callback.onIfaceRemoved;
    return RegisterEventCallback(cEventCallback);
}

WifiErrorNo WifiIdlClient::RequestFirmwareDebugInfo(std::string &debugInfo)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    debugInfo.clear(); /* fixed compile error, -Werror,-Wunused-parameter */
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiIdlClient::SetWifiPowerMode(int mode)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    LOGD("start SetWifiPowerMode mode %{public}d", mode);
    return WIFI_IDL_OPT_OK;
}

WifiStatus WifiIdlClient::ReqSetLatencyMode(int mode)
{
    if (pRpcClient == nullptr) {
        WifiStatus status = {ERROR_UNKNOWN, "UNKNOWN"};
        return status;
    }
    LatencyMode latencyMode = (LatencyMode)mode;
    return SetLatencyMode(latencyMode);
}

WifiErrorNo WifiIdlClient::ReqStartSupplicant(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StartSupplicant();
}

WifiErrorNo WifiIdlClient::ReqStopSupplicant(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return StopSupplicant();
}

WifiErrorNo WifiIdlClient::ReqConnectSupplicant(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return ConnectSupplicant();
}

WifiErrorNo WifiIdlClient::ReqDisconnectSupplicant(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return DisConnectSupplicant();
}

WifiErrorNo WifiIdlClient::ReqRequestToSupplicant(const std::string &request)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    unsigned char *p = (unsigned char *)request.c_str();
    return RequestToSupplicant(p, request.length());
}

WifiErrorNo WifiIdlClient::ReqRigisterSupplicantEventCallback(SupplicantEventCallback &callback)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    ISupplicantEventCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    cEventCallback.pInstance = callback.pInstance;
    cEventCallback.onScanNotify = callback.onScanNotify;
    return RigisterSupplicantEventCallback(cEventCallback);
}

WifiErrorNo WifiIdlClient::ReqUnRigisterSupplicantEventCallback(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    ISupplicantEventCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }
    return RigisterSupplicantEventCallback(cEventCallback);
}

WifiErrorNo WifiIdlClient::ReqSetPowerSave(bool enable)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    int mode = 0;
    if (enable) {
        mode = 1;
    }

    return SetPowerSave(mode);
}

WifiErrorNo WifiIdlClient::ReqWpaSetCountryCode(const std::string &countryCode)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WpaSetCountryCode(countryCode.c_str());
}

WifiErrorNo WifiIdlClient::ReqWpaGetCountryCode(std::string &countryCode)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    const int idlCountryCodeLen = 32;
    char code[idlCountryCodeLen] = {0};
    WifiErrorNo ret = WpaGetCountryCode(code, idlCountryCodeLen);
    if (ret == WIFI_IDL_OPT_OK) {
        countryCode = code;
    }
    return ret;
}

WifiErrorNo WifiIdlClient::ReqWpaAutoConnect(int enable)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WpaAutoConnect(enable);
}

WifiErrorNo WifiIdlClient::ReWpaReconfigure(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WpaReconfigure();
}

WifiErrorNo WifiIdlClient::ReWpaBlocklistClear(void)
{
    if (pRpcClient == nullptr) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WpaBlocklistClear();
}
}  // namespace Wifi
}  // namespace OHOS