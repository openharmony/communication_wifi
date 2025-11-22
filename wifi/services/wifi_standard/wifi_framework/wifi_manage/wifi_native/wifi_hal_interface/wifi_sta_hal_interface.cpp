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
#include "wifi_hdi_util.h"
#include "wifi_code_convert.h"
#include "wifi_config_center.h"
#include "define.h"
#ifdef READ_MAC_FROM_OEM
#include "wifi_oeminfo_mac.h"
#endif

#undef LOG_TAG
#define LOG_TAG "WifiStaHalInterface"

namespace OHOS {
namespace Wifi {
static int GetInstId(const std::string &ifaceName)
{
    int inst = INSTID_WLAN0;
    for (int instId = INSTID_WLAN0; instId < STA_INSTANCE_MAX_NUM; instId++) {
        if (ifaceName.compare(WifiConfigCenter::GetInstance().GetStaIfaceName(instId)) == 0) {
            inst = instId;
            break;
        }
    }
    return inst;
}

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
#endif
        }
    }
    return inst;
}

WifiErrorNo WifiStaHalInterface::StartWifi(const std::string &ifaceName, int instId)
{
    LOGD("WifiStaHalInterface ifaceName:%{public}s, instId:%{public}d", ifaceName.c_str(), instId);
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->StartWifi(ifaceName, instId);
#endif
    return WIFI_HAL_OPT_FAILED;
}
    

WifiErrorNo WifiStaHalInterface::StopWifi(int instId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->StopWifi(instId);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Connect(int networkId, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqConnect(networkId, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Reconnect(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqReconnect(WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Reassociate(const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqReassociate(ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Disconnect(const std::string &ifaceName)
{
    LOGD("WifiStaHalInterface Disconnect ifaceName:%{public}s", ifaceName.c_str());
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqDisconnect(ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetStaCapabilities(unsigned int &capabilities)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetStaCapabilities(capabilities);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetStaDeviceMacAddress(std::string &mac, const std::string &ifaceName, int macSrc)
{
#ifdef READ_MAC_FROM_OEM
    LOGI("GetStaDeviceMacAddress oem enter, %{public}d", macSrc);
    if (macSrc == WIFI_OEMINFO_MAC &&
        ifaceName == WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0)) {
        mac = wifiOemMac_ == ""? GetWifiOeminfoMac() : wifiOemMac_;
    }
    if (!mac.empty()) {
        wifiOemMac_ = mac;
        return WIFI_HAL_OPT_OK;
    }
#endif
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetStaDeviceMacAddress(mac, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

#ifdef READ_MAC_FROM_OEM
std::string WifiStaHalInterface::GetWifiOeminfoMac()
{
    LOGI("read mac from oem");
    WifiOeminfoMac oeminfoMac;
    std::string oemMac = "";
    int ret = oeminfoMac.GetOeminfoMac(oemMac);
    if (ret != 0) {
        LOGE("GetWifiOeminfoMac fail, ret = %{public}d", ret);
        return std::string("");
    }
    return oemMac;
}
#endif

WifiErrorNo WifiStaHalInterface::SetWifiCountryCode(const std::string &ifaceName, const std::string &code)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetWifiCountryCode(ifaceName, code)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetSupportFrequencies(const std::string &ifaceName, int band,
    std::vector<int> &frequencies)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, frequencies)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetConnectMacAddr(const std::string &ifaceName, const std::string &mac)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetStaMacAddress(ifaceName, mac)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetScanMacAddress(const std::string &mac)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGE("call WifiStaHalInterface::%{public}s!", __func__);
    return WIFI_HAL_OPT_FAILED;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::DisconnectLastRoamingBssid(const std::string &mac)
{
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetSupportFeature(long &feature)
{
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetTxPower(int power)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetTxPower(power)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Scan(const std::string &ifaceName, const WifiHalScanParam &scanParam)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    ScanParams scanParams;
    scanParams.ssids = scanParam.hiddenNetworkSsid;
    scanParams.freqs = scanParam.scanFreqs;
    scanParams.fastConnectFlag = static_cast<uint8_t>(scanParam.scanStyle);
    LOGI("call WifiStaHalInterface::%{public}d!", scanParams.fastConnectFlag);
    if (!HalDeviceManager::GetInstance().Scan(ifaceName, scanParams)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

#ifdef HDI_CHIP_INTERFACE_SUPPORT
static void ConvertsScanInfo(InterScanInfo &interScanInfo, ScanInfo &scanInfo)
{
    interScanInfo.ssid = WifiCodeConvertUtil::GbkToUtf8(scanInfo.ssid);
    interScanInfo.oriSsid = scanInfo.ssid;
    interScanInfo.bssid = scanInfo.bssid;
    interScanInfo.frequency = scanInfo.freq;
    interScanInfo.rssi = scanInfo.siglv;
    interScanInfo.timestamp = scanInfo.timestamp;
    interScanInfo.capabilities = scanInfo.flags;
    interScanInfo.channelWidth = (WifiChannelWidth)scanInfo.channelWidth;
    interScanInfo.centerFrequency0 = scanInfo.centerFrequency0;
    interScanInfo.centerFrequency1 = scanInfo.centerFrequency1;
    interScanInfo.isEhtInfoExist = scanInfo.isEhtInfoExist;
    interScanInfo.isVhtInfoExist = scanInfo.isVhtInfoExist;
    interScanInfo.isHtInfoExist = scanInfo.isHtInfoExist;
    interScanInfo.isHeInfoExist = scanInfo.isHeInfoExist;
    interScanInfo.isErpExist = scanInfo.isErpExist;
    interScanInfo.maxRates = scanInfo.maxRates > scanInfo.extMaxRates ? scanInfo.maxRates : scanInfo.extMaxRates;
    for (int i = 0; i < scanInfo.ieSize; ++i) {
        WifiInfoElem infoElem;
        if (!scanInfo.infoElems) {
            LOGE("ConvertsScanInfo scanInfo.infoElems is NULL!");
            return;
        }
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
    interScanInfo.isHiLinkProNetwork = scanInfo.isHiLinkProNetwork;
    return;
}

static void ConvertScanResultsInfo(WifiScanResultExt &wifiScanResultExt, ScanResultsInfo &scanResultsInfo)
{
    wifiScanResultExt.flags = scanResultsInfo.flags;
    wifiScanResultExt.bssid = scanResultsInfo.bssid.data();
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
        WifiScanResultExt wifiScanResultExt = {0};
        ConvertScanResultsInfo(wifiScanResultExt, scanResult);
        char buff[HDI_SCAN_RESULTS_MAX_LEN] = {0};
        int buffLen = GetScanResultText(&wifiScanResultExt, &elems, buff, HDI_SCAN_RESULTS_MAX_LEN);
        ScanInfo scanInfo;
        if (memset_s(&scanInfo, sizeof(scanInfo), 0, sizeof(scanInfo)) != EOK) {
            LOGE("%{public}s: memset_s is failed", __func__);
            return;
        }
        if (DelScanInfoLine(&scanInfo, buff, buffLen)) {
            LOGE("%{public}s: failed to obtain the scanning result", __func__);
            continue;
        }
        GetScanResultInfoElem(&scanInfo, scanResult.ie.data(), scanResult.ie.size());
        scanInfo.timestamp = scanResult.tsf;
        scanInfo.isHiLinkNetwork = RouterSupportHiLinkByWifiInfo(scanResult.ie.data(), scanResult.ie.size());
        if (scanInfo.isHiLinkNetwork == HILINK_PRO_NETWORK) {
            scanInfo.isHiLinkProNetwork = true;
        }
        int hiLinkNetwork = WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetHilinkAbility(scanInfo.bssid);
        if (InternalHiLinkNetworkToBool(scanInfo.isHiLinkNetwork)) {
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->RecordHilinkAbility(
                scanInfo.bssid, scanInfo.isHiLinkNetwork);
        } else if (InternalHiLinkNetworkToBool(hiLinkNetwork)) {
            scanInfo.isHiLinkNetwork = hiLinkNetwork;
        }
        LOGD("%{public}s: bssid:%{private}s, ssid:%{private}s isHiLinkNetwork:%{public}d, flags:%{public}s",
            __func__, scanInfo.bssid, scanInfo.ssid, scanInfo.isHiLinkNetwork, scanInfo.flags);
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
    if (!HalDeviceManager::GetInstance().GetScanInfos(ifaceName, scanResultsInfo)) {
        return WIFI_HAL_OPT_FAILED;
    }
    ParseScanInfo(scanResultsInfo, scanInfos);
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetNetworkList(std::vector<WifiHalWpaNetworkInfo> &networkList)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGI("call WifiStaHalInterface::%{public}s!", __func__);
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetNetworkList(
        networkList, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StartPnoScan(const std::string &ifaceName, const WifiHalPnoScanParam &scanParam)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    PnoScanParams scanParams;
    scanParams.min2gRssi = scanParam.minRssi2Dot4Ghz;
    scanParams.min5gRssi = scanParam.minRssi5Ghz;
    scanParams.scanIntervalMs = scanParam.scanInterval;
    scanParams.hiddenssids = scanParam.hiddenSsid;
    scanParams.savedssids = scanParam.savedSsid;
    scanParams.freqs = scanParam.scanFreqs;
    if (!HalDeviceManager::GetInstance().StartPnoScan(ifaceName, scanParams)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StopPnoScan(const std::string &ifaceName)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().StopPnoScan(ifaceName)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::RemoveDevice(int networkId)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->RemoveDevice(
        networkId, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::ClearDeviceConfig(const std::string &ifaceName) const
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ClearDeviceConfig(ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetNextNetworkId(int &networkId, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetNextNetworkId(networkId, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::EnableNetwork(int networkId, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqEnableNetwork(networkId, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::DisableNetwork(int networkId, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqDisableNetwork(networkId, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetDeviceConfig(
    int networkId, const WifiHalDeviceConfig &config, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetDeviceConfig(WifiHalGetDeviceConfig &config, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    LOGI("call WifiStaHalInterface::%{public}s!", __func__);
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetDeviceConfig(config, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SaveDeviceConfig(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SaveDeviceConfig(WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::RegisterStaEventCallback(
    const WifiEventCallback &callback, const std::string &ifaceName)
{
    int instId = GetInstId(ifaceName);
    WifiErrorNo err = WIFI_HAL_OPT_FAILED;
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    err = mHdiWpaClient->ReqRegisterStaEventCallback(callback, ifaceName.c_str(), instId);
#endif
    if (err == WIFI_HAL_OPT_OK || callback.onConnectChanged == nullptr) {
        mStaCallback[instId] = callback;
    }
    return err;
}

WifiErrorNo WifiStaHalInterface::StartWpsPbcMode(const WifiHalWpsConfig &config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqStartWpsPbcMode(
        config, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StartWpsPinMode(const WifiHalWpsConfig &config, int &pinCode)
{
    if (!config.pinCode.empty() && config.pinCode.length() != HAL_PIN_CODE_LENGTH) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqStartWpsPinMode(
        config, pinCode, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StopWps(void)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqStopWps(WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetRoamingCapabilities(WifiHalRoamCapability &capability)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqGetRoamingCapabilities(capability);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetBssid(int networkId, const std::string &bssid, const std::string &ifaceName)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->SetBssid(networkId, bssid, ifaceName.c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetRoamConfig(const WifiHalRoamConfig &config)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqSetRoamConfig(config);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::WpaAutoConnect(int enable)
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaAutoConnect(
        enable, WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::WpaBlocklistClear()
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaBlocklistClear(WifiConfigCenter::GetInstance().GetStaIfaceName(INSTID_WLAN0).c_str());
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetConnectSignalInfo(const std::string &ifaceName, const std::string &endBssid,
    WifiSignalPollInfo &info)
{
    if (endBssid.length() != HAL_BSSID_LENGTH) {
        return WIFI_HAL_OPT_INPUT_MAC_INVALID;
    }
    info.timeStamp = GetCurrentTimeSeconds();
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    SignalPollResult signalPollResult;
    if (!HalDeviceManager::GetInstance().GetConnectSignalInfo(ifaceName, signalPollResult)) {
        return WIFI_HAL_OPT_FAILED;
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
    info.txBytes = static_cast<unsigned int>(signalPollResult.currentTxBytes);
    info.rxBytes = static_cast<unsigned int>(signalPollResult.currentRxBytes);
    info.txFailed = signalPollResult.currentTxFailed;
    info.chloadSelf = signalPollResult.chloadSelf;
    info.c0Rssi = signalPollResult.c0Rssi;
    info.c1Rssi = signalPollResult.c1Rssi;
    info.ext.assign(signalPollResult.ext.begin(), signalPollResult.ext.end());
    info.extLen = static_cast<int>(info.ext.size());
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetPmMode(const std::string &ifaceName, int frequency, int mode)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetPmMode(ifaceName, mode)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetDpiMarkRule(ifaceName, uid, protocol, enable)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetPskPassphrase(const std::string &ifName, std::string &psk)
{
    if (ifName.length() <= 0) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaGetPskPassphrase(ifName, psk);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetChipsetCategory(const std::string &ifaceName, int& chipsetCategory)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    unsigned int chipsetCategorySupported = static_cast<unsigned int>(WifiCategory::DEFAULT);
    if (!HalDeviceManager::GetInstance().GetChipsetCategory(ifaceName, chipsetCategorySupported)) {
        return WIFI_HAL_OPT_FAILED;
    }
    if (chipsetCategorySupported & static_cast<unsigned int>(WifiCategory::WIFI7)) {
        chipsetCategory = static_cast<int>(WifiCategory::WIFI7);
    } else if (chipsetCategorySupported & static_cast<unsigned int>(WifiCategory::WIFI6)) {
        chipsetCategory = static_cast<int>(WifiCategory::WIFI6);
    } else {
        chipsetCategory = static_cast<int>(WifiCategory::DEFAULT);
    }
    LOGI("%{public}s success, chipsetCategorySupported: %{public}u, chipsetCategory: %{public}d",
        __FUNCTION__, chipsetCategorySupported, chipsetCategory);
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetChipsetWifiFeatrureCapability(
    const std::string &ifaceName, int& chipsetFeatrureCapability)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetChipsetWifiFeatrureCapability(
        ifaceName, chipsetFeatrureCapability)) {
            return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::ShellCmd(const std::string &ifName, const std::string &cmd)
{
    if ((ifName.length() <= 0) || (cmd.length() <= 0)) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqWpaShellCmd(ifName, cmd);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetNetworkInterfaceUpDown(const std::string &ifaceName, bool upDown)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().SetNetworkUpDown(ifaceName, upDown)) {
        return WIFI_HAL_OPT_FAILED;
    }
    return WIFI_HAL_OPT_OK;
#endif
    return WIFI_HAL_OPT_FAILED;
}

const WifiEventCallback &WifiStaHalInterface::GetCallbackInst(const std::string &ifaceName) const
{
    int instId = GetInstId(ifaceName);
    return mStaCallback[instId];
}

const std::function<void(int)> &WifiStaHalInterface::GetDeathCallbackInst(void) const
{
    return mDeathCallback;
}

WifiErrorNo WifiStaHalInterface::RegisterNativeProcessCallback(const std::function<void(int)> &callback)
{
    mDeathCallback = callback;
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->ReqRegisterNativeProcessCallback(callback);
#endif
    return WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetConnectionMloLinkedInfo(const std::string &ifName,
    std::vector<WifiLinkedInfo> &mloLinkInfo)
{
    if (ifName.length() <= 0) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetMloLinkedInfo(ifName, mloLinkInfo);
#endif
    return WIFI_HAL_OPT_FAILED;
}
WifiErrorNo WifiStaHalInterface::GetConnectionMloSignalInfo(const std::string &ifName,
    std::vector<WifiMloSignalInfo> &mloSignalInfo)
{
    if (ifName.length() <= 0) {
        return WIFI_HAL_OPT_INVALID_PARAM;
    }
#ifdef HDI_WPA_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiWpaClient, WIFI_HAL_OPT_FAILED);
    return mHdiWpaClient->GetMloSignalPollInfo(ifName, mloSignalInfo);
#endif
    return WIFI_HAL_OPT_FAILED;
}
}  // namespace Wifi
}  // namespace OHOS