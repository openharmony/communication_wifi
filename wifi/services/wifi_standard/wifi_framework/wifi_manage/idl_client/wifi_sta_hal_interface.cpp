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
            if (inst.InitIdlClient()) {
                initFlag = 1;
            }
        }
    }
    return inst;
}

WifiErrorNo WifiStaHalInterface::StartWifi(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StartWifi();
}

WifiErrorNo WifiStaHalInterface::StopWifi(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->StopWifi();
}

WifiErrorNo WifiStaHalInterface::Connect(int networkId)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqConnect(networkId);
}

WifiErrorNo WifiStaHalInterface::Reconnect(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqReconnect();
}

WifiErrorNo WifiStaHalInterface::Reassociate(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqReassociate();
}

WifiErrorNo WifiStaHalInterface::Disconnect(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqDisconnect();
}

WifiErrorNo WifiStaHalInterface::GetStaCapabilities(unsigned int &capabilities)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStaCapabilities(capabilities);
}

WifiErrorNo WifiStaHalInterface::GetStaDeviceMacAddress(std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetStaDeviceMacAddress(mac);
}

WifiErrorNo WifiStaHalInterface::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetSupportFrequencies(band, frequencies);
}

WifiErrorNo WifiStaHalInterface::SetConnectMacAddr(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetConnectMacAddr(mac);
}

WifiErrorNo WifiStaHalInterface::SetScanMacAddress(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetScanMacAddress(mac);
}

WifiErrorNo WifiStaHalInterface::DisconnectLastRoamingBssid(const std::string &mac)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->DisconnectLastRoamingBssid(mac);
}

WifiErrorNo WifiStaHalInterface::GetSupportFeature(long &feature)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetSupportFeature(feature);
}

WifiErrorNo WifiStaHalInterface::SendRequest(const WifiStaRequest &request)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SendRequest(request);
}

WifiErrorNo WifiStaHalInterface::SetTxPower(int power)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetTxPower(power);
}

WifiErrorNo WifiStaHalInterface::Scan(const WifiScanParam &scanParam)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->Scan(scanParam);
}

WifiErrorNo WifiStaHalInterface::QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->QueryScanInfos(scanInfos);
}

WifiErrorNo WifiStaHalInterface::GetNetworkList(std::vector<WifiWpaNetworkInfo> &networkList)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetNetworkList(networkList);
}

WifiErrorNo WifiStaHalInterface::StartPnoScan(const WifiPnoScanParam &scanParam)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartPnoScan(scanParam);
}

WifiErrorNo WifiStaHalInterface::StopPnoScan(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStopPnoScan();
}

WifiErrorNo WifiStaHalInterface::RemoveDevice(int networkId)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->RemoveDevice(networkId);
}

WifiErrorNo WifiStaHalInterface::ClearDeviceConfig(void) const
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ClearDeviceConfig();
}

WifiErrorNo WifiStaHalInterface::GetNextNetworkId(int &networkId)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetNextNetworkId(networkId);
}

WifiErrorNo WifiStaHalInterface::EnableNetwork(int networkId)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqEnableNetwork(networkId);
}

WifiErrorNo WifiStaHalInterface::DisableNetwork(int networkId)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqDisableNetwork(networkId);
}

WifiErrorNo WifiStaHalInterface::SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetDeviceConfig(networkId, config);
}

WifiErrorNo WifiStaHalInterface::GetDeviceConfig(WifiIdlGetDeviceConfig &config)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->GetDeviceConfig(config);
}

WifiErrorNo WifiStaHalInterface::SaveDeviceConfig(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SaveDeviceConfig();
}

WifiErrorNo WifiStaHalInterface::RegisterStaEventCallback(const WifiEventCallback &callback)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    WifiErrorNo err = mIdlClient->ReqRegisterStaEventCallback(callback);
    if (err == WIFI_IDL_OPT_OK || callback.onConnectChanged == nullptr) {
        mStaCallback = callback;
    }
    return err;
}

WifiErrorNo WifiStaHalInterface::StartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartWpsPbcMode(config);
}

WifiErrorNo WifiStaHalInterface::StartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    if (!config.pinCode.empty() && config.pinCode.length() != WIFI_IDL_PIN_CODE_LENGTH) {
        return WIFI_IDL_OPT_INVALID_PARAM;
    }
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStartWpsPinMode(config, pinCode);
}

WifiErrorNo WifiStaHalInterface::StopWps(void)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqStopWps();
}

WifiErrorNo WifiStaHalInterface::GetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetRoamingCapabilities(capability);
}

WifiErrorNo WifiStaHalInterface::SetWpsBssid(int networkId, const std::string &bssid)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->SetWpsBssid(networkId, bssid);
}

WifiErrorNo WifiStaHalInterface::SetRoamConfig(const WifiIdlRoamConfig &config)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqSetRoamConfig(config);
}

WifiErrorNo WifiStaHalInterface::WpaAutoConnect(int enable)
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqWpaAutoConnect(enable);
}

WifiErrorNo WifiStaHalInterface::WpaBlocklistClear()
{
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqWpaBlocklistClear();
}

WifiErrorNo WifiStaHalInterface::GetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info)
{
    if (endBssid.length() != WIFI_IDL_BSSID_LENGTH) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    CHECK_NULL_AND_RETURN(mIdlClient, WIFI_IDL_OPT_FAILED);
    return mIdlClient->ReqGetConnectSignalInfo(endBssid, info);
}

const WifiEventCallback &WifiStaHalInterface::GetCallbackInst(void) const
{
    return mStaCallback;
}
}  // namespace Wifi
}  // namespace OHOS