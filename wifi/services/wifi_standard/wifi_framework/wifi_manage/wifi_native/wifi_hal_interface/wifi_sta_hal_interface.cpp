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
#include "wifi_sta_hal_interface.h"
#include <mutex>
#include "wifi_log.h"
#include "wifi_idl_define.h"

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

#ifdef HDI_INTERFACE_SUPPORT
            if (inst.InitHdiClient()) {
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

WifiErrorNo WifiStaHalInterface::SetConnectMacAddr(const std::string &mac)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->SetConnectMacAddr(mac, WIFI_HAL_PORT_TYPE_STATION);
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

WifiErrorNo WifiStaHalInterface::Scan(const WifiScanParam &scanParam)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->Scan(scanParam);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->Scan(scanParam);
#endif
}

WifiErrorNo WifiStaHalInterface::QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->QueryScanInfos(scanInfos);
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

WifiErrorNo WifiStaHalInterface::StartPnoScan(const WifiPnoScanParam &scanParam)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqStartPnoScan(scanParam);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartPnoScan(scanParam);
#endif
}

WifiErrorNo WifiStaHalInterface::StopPnoScan(void)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqStopPnoScan();
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

WifiErrorNo WifiStaHalInterface::GetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info)
{
    if (endBssid.length() != WIFI_IDL_BSSID_LENGTH) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqGetConnectSignalInfo(endBssid, info);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetConnectSignalInfo(endBssid, info);
#endif
}

WifiErrorNo WifiStaHalInterface::SetPmMode(int frequency, int mode)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqSetPmMode(frequency, mode);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetPmMode(frequency, mode);
#endif
}

WifiErrorNo WifiStaHalInterface::SetDpiMarkRule(int uid, int protocol, int enable)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqSetDpiMarkRule(uid, protocol, enable);
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

WifiErrorNo WifiStaHalInterface::GetChipsetCategory(int& chipsetCategory)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqGetChipsetCategory(chipsetCategory);
#else
    return WIFI_IDL_OPT_OK;
#endif
}

WifiErrorNo WifiStaHalInterface::GetChipsetWifiFeatrureCapability(int& chipsetFeatrureCapability)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqGetChipsetWifiFeatrureCapability(chipsetFeatrureCapability);
#else
    return WIFI_IDL_OPT_OK;
#endif
}

WifiErrorNo WifiStaHalInterface::StartWifiHdi(const std::string &ifaceName)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->StartWifi(ifaceName);
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StartWifi();
#endif
}

WifiErrorNo WifiStaHalInterface::StopWifiHdi()
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->StopWifi();
#else
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StopWifi();
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
    return WIFI_IDL_OPT_FAILED;
#endif
}

WifiErrorNo WifiStaHalInterface::SetNetworkInterfaceUpDown(const std::string &ifaceName, bool upDown)
{
#ifdef HDI_INTERFACE_SUPPORT
    CHECK_NULL_AND_RETURN(mHdiClient, WIFI_IDL_OPT_FAILED);
    return mHdiClient->ReqUpDownNetworkInterface(ifaceName, upDown);
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