/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include <mutex>
#include "wifi_sta_hal_interface.h"
#include "hal_device_manage.h"
#include "wifi_log.h"
#include "wifi_idl_define.h"
#include "wifi_hdi_util.h"

#undef LOG_TAG
#define LOG_TAG "WifiStaHalInterface"

namespace OHOS {
namespace Wifi {
WifiStaHalInterface &WifiStaHalInterface::GetInstance(void)
{
    static WifiStaHalInterface inst;
    static int initFlag = 0;
    static std::mutex initMutex;
    if (initFlag == 0) {
        std::unique_lock<std::mutex> lock(initMutex);
        if (initFlag == 0) {
#ifdef HDI_WPA_INTERFACE_SUPPORT
            if (inst.InitHdiWpaClient()) {
                initFlag = 1;
            }
#else
            if (inst.InitIdlClient()) {
                initFlag = 1;
            }
#endif
        }
    }
    return inst;
}

WifiErrorNo WifiStaHalInterface::StartWifi(const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->StartWifi(ifaceName);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StartWifi();
#endif
}
    

WifiErrorNo WifiStaHalInterface::StopWifi(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->StopWifi();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StopWifi();
#endif
}

WifiErrorNo WifiStaHalInterface::Connect(int networkId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqConnect(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqConnect(networkId);
#endif
}

WifiErrorNo WifiStaHalInterface::Reconnect(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqReconnect();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqReconnect();
#endif
}

WifiErrorNo WifiStaHalInterface::Reassociate(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqReassociate();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqReassociate();
#endif
}

WifiErrorNo WifiStaHalInterface::Disconnect(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqDisconnect();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqDisconnect();
#endif
}

WifiErrorNo WifiStaHalInterface::GetStaCapabilities(unsigned int &capabilities)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetStaCapabilities(capabilities);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStaCapabilities(capabilities);
#endif
}

WifiErrorNo WifiStaHalInterface::GetStaDeviceMacAddress(std::string &mac)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetStaDeviceMacAddress(mac);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStaDeviceMacAddress(mac);
#endif
}

WifiErrorNo WifiStaHalInterface::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetSupportFrequencies(band, frequencies);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetSupportFrequencies(band, frequencies);
#endif
}

WifiErrorNo WifiStaHalInterface::SetConnectMacAddr(const std::string &ifaceName, const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->SetStaMacAddress(ifaceName, mac)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetConnectMacAddr(mac, WIFI_HAL_PORT_TYPE_STATION);
#endif
}

WifiErrorNo WifiStaHalInterface::SetScanMacAddress(const std::string &mac)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiStaHalInterface::%{public}s!", __func__);
    return WIFI_IDL_OPT_FAILED;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetScanMacAddress(mac);
#endif
}

WifiErrorNo WifiStaHalInterface::DisconnectLastRoamingBssid(const std::string &mac)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiStaHalInterface::%{public}s!", __func__);
    return WIFI_IDL_OPT_FAILED;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->DisconnectLastRoamingBssid(mac);
#endif
}

WifiErrorNo WifiStaHalInterface::GetSupportFeature(long &feature)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiStaHalInterface::%{public}s!", __func__);
    return WIFI_IDL_OPT_FAILED;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetSupportFeature(feature);
#endif
}

WifiErrorNo WifiStaHalInterface::SendRequest(const WifiStaRequest &request)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiStaHalInterface::%{public}s!", __func__);
    return WIFI_IDL_OPT_FAILED;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SendRequest(request);
#endif
}

WifiErrorNo WifiStaHalInterface::SetTxPower(int power)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiStaHalInterface::%{public}s!", __func__);
    return WIFI_IDL_OPT_FAILED;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetTxPower(power);
#endif
}

WifiErrorNo WifiStaHalInterface::Scan(const std::string &ifaceName, const WifiScanParam &scanParam)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    ScanParams scanParams;
    scanParams.ssids = scanParam.hiddenNetworkSsid;
    scanParams.freqs = scanParam.scanFreqs;
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->Scan(ifaceName, scanParams)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->Scan(scanParam);
#endif
}

#ifdef HDI_CHIP_INTERFACE_SUPPORT
static void ConvertsScanInfo(InterScanInfo &interScanInfo, ScanInfo &scanInfo)
{
    interScanInfo.ssid = scanInfo.ssid;
    interScanInfo.bssid = scanInfo.bssid;
    interScanInfo.frequency = scanInfo.freq;
    interScanInfo.rssi = scanInfo.siglv;
    interScanInfo.timestamp = scanInfo.timestamp;
    interScanInfo.capabilities = scanInfo.flags;
    interScanInfo.channelWidth = (WifiChannelWidth)scanInfo.channelWidth;
    interScanInfo.centerFrequency0 = scanInfo.centerFrequency0;
    interScanInfo.centerFrequency1 = scanInfo.centerFrequency1;
    interScanInfo.isVhtInfoExist = scanInfo.isVhtInfoExist;
    interScanInfo.isHtInfoExist = scanInfo.isHtInfoExist;
    interScanInfo.isHeInfoExist = scanInfo.isHeInfoExist;
    interScanInfo.isErpExist = scanInfo.isErpExist;
    interScanInfo.maxRates = scanInfo.maxRates > scanInfo.extMaxRates ? scanInfo.maxRates : scanInfo.extMaxRates;
    for (int i = 0; i < scanInfo.ieSize; ++i) {
        WifiInfoElem infoElem;
        infoElem.id = scanInfo.infoElems[i].id;
        for (int j = 0; j < scanInfo.infoElems[i].size; ++j) {
            infoElem.content.emplace_back(scanInfo.infoElems[i].content[j]);
        }
        if (scanInfo.infoElems[i].content) {
            free(scanInfo.infoElems[i].content);
            scanInfo.infoElems[i].content = nullptr;
        }
        interScanInfo.infoElems.emplace_back(infoElem);
    }
    
    if (scanInfo.infoElems) {
        free(scanInfo.infoElems);
        scanInfo.infoElems = nullptr;
    }
    interScanInfo.isHiLinkNetwork = scanInfo.isHiLinkNetwork;
    return;
}

static void ConvertScanResultsInfo(WifiScanResultExt &wifiScanResultExt, ScanResultsInfo &scanResultsInfo)
{
    wifiScanResultExt.flags = scanResultsInfo.flags;
    wifiScanResultExt.bssid = (uint8_t *)scanResultsInfo.bssid.c_str();
    wifiScanResultExt.bssidLen = scanResultsInfo.bssid.size();
    wifiScanResultExt.caps = scanResultsInfo.caps;
    wifiScanResultExt.freq = scanResultsInfo.freq;
    wifiScanResultExt.beaconInt = scanResultsInfo.beaconInterval;
    wifiScanResultExt.qual = scanResultsInfo.qual;
    wifiScanResultExt.level = scanResultsInfo.level;
    wifiScanResultExt.age = scanResultsInfo.age;
    wifiScanResultExt.tsf = scanResultsInfo.tsf;
    wifiScanResultExt.variable = scanResultsInfo.variable.data();
    wifiScanResultExt.variableLen = scanResultsInfo.variable.size();
    wifiScanResultExt.ie = scanResultsInfo.ie.data();
    wifiScanResultExt.ieLen = scanResultsInfo.ie.size();
    wifiScanResultExt.beaconIe = scanResultsInfo.beaconIe.data();
    wifiScanResultExt.beaconIeLen = scanResultsInfo.beaconIe.size();
    return;
}

static void ParseScanInfo(std::vector<ScanResultsInfo> &scanResultsInfo, std::vector<InterScanInfo> &scanInfos)
{
    for (auto &scanResult : scanResultsInfo) {
        struct HdiElems elems = {0};
        Get80211ElemsFromIE(scanResult.ie.data(), scanResult.ie.size(), &elems, 1);
        if (elems.ssidLen == 0) {
            char bssid[HDI_BSSID_LENGTH] = {0};
            if (sprintf_s(bssid, sizeof(bssid), MACSTR, MAC2STR(scanResult.bssid.c_str())) < 0) {
                LOGD("%{public}s: ssid empty.", __func__);
                continue;
            }
            LOGD("%{public}s: ssid empty, bssid:%{private}s", __func__, bssid);
            continue;
        }

        WifiScanResultExt wifiScanResultExt = {0};
        ConvertScanResultsInfo(wifiScanResultExt, scanResult);
        char buff[HDI_SCAN_RESULTS_MAX_LEN] = {0};
        int buffLen = HDI_SCAN_RESULTS_MAX_LEN;
        buffLen = GetScanResultText(&wifiScanResultExt, &elems, buff, buffLen);
        ScanInfo scanInfo;
        (void)memset_s(&scanInfo, sizeof(scanInfo), 0, sizeof(scanInfo));
        if (DelScanInfoLine(&scanInfo, buff, buffLen)) {
            LOGE("%{public}s: failed to obtain the scanning result", __func__);
            continue;
        }
        GetScanResultInfoElem(&scanInfo, scanResult.ie.data(), scanResult.ie.size());
        scanInfo.timestamp = scanResult.tsf;
        scanInfo.isHiLinkNetwork = RouterSupportHiLinkByWifiInfo(scanResult.ie.data(), scanResult.ie.size());
        LOGD("%{public}s: bssid:%{private}s, ssid:%{private}s isHiLinkNetwork = %{public}d", __func__, scanInfo.bssid,
            scanInfo.ssid, scanInfo.isHiLinkNetwork);
        InterScanInfo interScanInfo;
        ConvertsScanInfo(interScanInfo, scanInfo);
        scanInfos.emplace_back(interScanInfo);
    }
    return;
}
#endif

WifiErrorNo WifiStaHalInterface::QueryScanInfos(const std::string &ifaceName, std::vector<InterScanInfo> &scanInfos)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::vector<ScanResultsInfo> scanResultsInfo;
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->GetScanInfos(ifaceName, scanResultsInfo)) {
        return WIFI_IDL_OPT_FAILED;
    }
    ParseScanInfo(scanResultsInfo, scanInfos);
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->QueryScanInfos(scanInfos);
#endif
}

WifiErrorNo WifiStaHalInterface::GetNetworkList(std::vector<WifiWpaNetworkInfo> &networkList)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGI("call WifiStaHalInterface::%{public}s!", __func__);
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetNetworkList(networkList);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetNetworkList(networkList);
#endif
}

WifiErrorNo WifiStaHalInterface::StartPnoScan(const std::string &ifaceName, const WifiPnoScanParam &scanParam)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    PnoScanParams scanParams;
    scanParams.min2gRssi = scanParam.minRssi2Dot4Ghz;
    scanParams.min5gRssi = scanParam.minRssi5Ghz;
    scanParams.scanIntervalMs = scanParam.scanInterval;
    scanParams.hiddenssids = scanParam.hiddenSsid;
    scanParams.savedssids = scanParam.savedSsid;
    scanParams.freqs = scanParam.scanFreqs;
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->StartPnoScan(ifaceName, scanParams)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartPnoScan(scanParam);
#endif
}

WifiErrorNo WifiStaHalInterface::StopPnoScan(const std::string &ifaceName)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->StopPnoScan(ifaceName)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStopPnoScan();
#endif
}

WifiErrorNo WifiStaHalInterface::RemoveDevice(int networkId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->RemoveDevice(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RemoveDevice(networkId);
#endif
}

WifiErrorNo WifiStaHalInterface::ClearDeviceConfig(void) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ClearDeviceConfig();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ClearDeviceConfig();
#endif
}

WifiErrorNo WifiStaHalInterface::GetNextNetworkId(int &networkId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetNextNetworkId(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetNextNetworkId(networkId);
#endif
}

WifiErrorNo WifiStaHalInterface::EnableNetwork(int networkId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqEnableNetwork(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqEnableNetwork(networkId);
#endif
}

WifiErrorNo WifiStaHalInterface::DisableNetwork(int networkId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqDisableNetwork(networkId);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqDisableNetwork(networkId);
#endif
}

WifiErrorNo WifiStaHalInterface::SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->SetDeviceConfig(networkId, config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetDeviceConfig(networkId, config);
#endif
}

WifiErrorNo WifiStaHalInterface::GetDeviceConfig(WifiIdlGetDeviceConfig &config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGI("call WifiStaHalInterface::%{public}s!", __func__);
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->GetDeviceConfig(config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetDeviceConfig(config);
#endif
}

WifiErrorNo WifiStaHalInterface::SaveDeviceConfig(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->SaveDeviceConfig();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SaveDeviceConfig();
#endif
}

WifiErrorNo WifiStaHalInterface::RegisterStaEventCallback(const WifiEventCallback &callback)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mHdiWpaClient->ReqRegisterStaEventCallback(callback);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->ReqRegisterStaEventCallback(callback);
#endif
    if (err == WIFI_IDL_OPT_OK || callback.onConnectChanged == nullptr) {
        mStaCallback = callback;
    }
    return err;
}

WifiErrorNo WifiStaHalInterface::StartWpsPbcMode(const WifiIdlWpsConfig &config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqStartWpsPbcMode(config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartWpsPbcMode(config);
#endif
}

WifiErrorNo WifiStaHalInterface::StartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    if (!config.pinCode.empty() && config.pinCode.length() != WIFI_IDL_PIN_CODE_LENGTH) {
        return WIFI_IDL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqStartWpsPinMode(config, pinCode);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartWpsPinMode(config, pinCode);
#endif
}

WifiErrorNo WifiStaHalInterface::StopWps(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqStopWps();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStopWps();
#endif
}

WifiErrorNo WifiStaHalInterface::GetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqGetRoamingCapabilities(capability);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetRoamingCapabilities(capability);
#endif
}

WifiErrorNo WifiStaHalInterface::SetBssid(int networkId, const std::string &bssid)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->SetBssid(networkId, bssid);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetBssid(networkId, bssid);
#endif
}

WifiErrorNo WifiStaHalInterface::SetRoamConfig(const WifiIdlRoamConfig &config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqSetRoamConfig(config);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetRoamConfig(config);
#endif
}

WifiErrorNo WifiStaHalInterface::WpaAutoConnect(int enable)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaAutoConnect(enable);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqWpaAutoConnect(enable);
#endif
}

WifiErrorNo WifiStaHalInterface::WpaBlocklistClear()
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaBlocklistClear();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqWpaBlocklistClear();
#endif
}

WifiErrorNo WifiStaHalInterface::GetConnectSignalInfo(const std::string &ifaceName, const std::string &endBssid,
    WifiWpaSignalInfo &info)
{
    if (endBssid.length() != WIFI_IDL_BSSID_LENGTH) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    SignalPollResult signalPollResult;
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->GetConnectSignalInfo(ifaceName, signalPollResult)) {
        return WIFI_IDL_OPT_FAILED;
    }
    info.signal = signalPollResult.currentRssi;
    info.txrate = signalPollResult.txBitrate;
    info.rxrate = signalPollResult.rxBitrate;
    info.noise = signalPollResult.currentNoise;
    info.frequency = signalPollResult.associatedFreq;
    info.txPackets = signalPollResult.currentTxPackets;
    info.rxPackets = signalPollResult.currentRxPackets;
    info.snr = signalPollResult.currentSnr;
    info.chload = signalPollResult.currentChload;
    info.ulDelay = signalPollResult.currentUlDelay;
    info.txBytes = signalPollResult.currentTxBytes;
    info.rxBytes = signalPollResult.currentRxBytes;
    info.txFailed = signalPollResult.currentTxFailed;
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetConnectSignalInfo(endBssid, info);
#endif
}

WifiErrorNo WifiStaHalInterface::SetPmMode(const std::string &ifaceName, int frequency, int mode)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->SetPmMode(ifaceName, mode)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetPmMode(frequency, mode);
#endif
}

WifiErrorNo WifiStaHalInterface::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->SetDpiMarkRule(ifaceName, uid, protocol, enable)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetDpiMarkRule(uid, protocol, enable);
#endif
}

WifiErrorNo WifiStaHalInterface::ShellCmd(const std::string &ifName, const std::string &cmd)
{
    if ((ifName.length() <= 0) || (cmd.length() <= 0)) {
        return WIFI_IDL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaShellCmd(ifName, cmd);
#else
    return WIFI_IDL_OPT_OK;
#endif
}

WifiErrorNo WifiStaHalInterface::GetPskPassphrase(const std::string &ifName, std::string &psk)
{
    if (ifName.length() <= 0) {
        return WIFI_IDL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_IDL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaGetPskPassphrase(ifName, psk);
#else
    return WIFI_IDL_OPT_FAILED;
#endif
}

WifiErrorNo WifiStaHalInterface::GetChipsetCategory(const std::string &ifaceName, int& chipsetCategory)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->GetChipsetCategory(ifaceName, chipsetCategory)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    return WIFI_IDL_OPT_OK;
#endif
}

WifiErrorNo WifiStaHalInterface::GetChipsetWifiFeatrureCapability(
    const std::string &ifaceName, int& chipsetFeatrureCapability)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->GetChipsetWifiFeatrureCapability(
        ifaceName, chipsetFeatrureCapability)) {
            return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    return WIFI_IDL_OPT_OK;
#endif
}

WifiErrorNo WifiStaHalInterface::SetNetworkInterfaceUpDown(const std::string &ifaceName, bool upDown)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->SetNetworkUpDown(ifaceName, upDown)) {
        return WIFI_IDL_OPT_FAILED;
    }
    return WIFI_IDL_OPT_OK;
#else
    return WIFI_IDL_OPT_OK;
#endif
}

const WifiEventCallback &WifiStaHalInterface::GetCallbackInst(void) const
{
    return mStaCallback;
}
}  // namespace Wifi
}  // namespace OHOS