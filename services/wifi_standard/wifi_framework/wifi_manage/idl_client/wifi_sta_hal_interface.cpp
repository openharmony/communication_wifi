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
#include "wifi_sta_hal_interface.h"
#include <mutex>
#include "wifi_log.h"
#include "wifi_idl_inner_interface.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_IDLCLIENT_WIFI_STA_HAL_INTERFACE"

RpcClient *GetStaRpcClient(void)
{
    return OHOS::Wifi::WifiStaHalInterface::GetInstance().mIdlClient->pRpcClient;
}

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
            inst.InitIdlClient();
            initFlag = 1;
        }
    }
    return inst;
}

WifiErrorNo WifiStaHalInterface::StartWifi(void)
{
    return mIdlClient->StartWifi();
}

WifiErrorNo WifiStaHalInterface::StopWifi(void)
{
    return mIdlClient->StopWifi();
}

WifiErrorNo WifiStaHalInterface::Connect(int networkId)
{
    return mIdlClient->ReqConnect(networkId);
}

WifiErrorNo WifiStaHalInterface::Reconnect(void)
{
    return mIdlClient->ReqReconnect();
}

WifiErrorNo WifiStaHalInterface::Reassociate(void)
{
    return mIdlClient->ReqReassociate();
}

WifiErrorNo WifiStaHalInterface::Disconnect(void)
{
    return mIdlClient->ReqDisconnect();
}

WifiErrorNo WifiStaHalInterface::GetStaCapabilities(unsigned int &capabilities)
{
    return mIdlClient->GetStaCapabilities(capabilities);
}

WifiErrorNo WifiStaHalInterface::GetStaDeviceMacAddress(std::string &mac)
{
    return mIdlClient->GetStaDeviceMacAddress(mac);
}

WifiErrorNo WifiStaHalInterface::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return mIdlClient->GetSupportFrequencies(band, frequencies);
}

WifiErrorNo WifiStaHalInterface::SetConnectMacAddr(const std::string &mac)
{
    return mIdlClient->SetConnectMacAddr(mac);
}

WifiErrorNo WifiStaHalInterface::SetScanMacAddress(const std::string &mac)
{
    return mIdlClient->SetScanMacAddress(mac);
}

WifiErrorNo WifiStaHalInterface::DisconnectLastRoamingBssid(const std::string &mac)
{
    return mIdlClient->DisconnectLastRoamingBssid(mac);
}

WifiErrorNo WifiStaHalInterface::GetSupportFeature(long &feature)
{
    return mIdlClient->ReqGetSupportFeature(feature);
}

WifiErrorNo WifiStaHalInterface::SendRequest(const WifiStaRequest &request)
{
    return mIdlClient->SendRequest(request);
}

WifiErrorNo WifiStaHalInterface::SetTxPower(int power)
{
    return mIdlClient->SetTxPower(power);
}

WifiErrorNo WifiStaHalInterface::Scan(const WifiScanParam &scanParam)
{
    return mIdlClient->Scan(scanParam);
}

WifiErrorNo WifiStaHalInterface::QueryScanResults(std::vector<WifiScanResult> &scanResults)
{
    return mIdlClient->QueryScanResults(scanResults);
}

WifiErrorNo WifiStaHalInterface::GetNetworkList(std::vector<WifiWpaNetworkList> &networkList)
{
    return mIdlClient->ReGetNetworkList(networkList);
}
WifiErrorNo WifiStaHalInterface::StartPnoScan(const WifiPnoScanParam &scanParam)
{
    return mIdlClient->ReqStartPnoScan(scanParam);
}

WifiErrorNo WifiStaHalInterface::StopPnoScan(void)
{
    return mIdlClient->ReqStopPnoScan();
}

WifiErrorNo WifiStaHalInterface::RemoveDeviceConfig(int networkId)
{
    return mIdlClient->RemoveDeviceConfig(networkId);
}

WifiErrorNo WifiStaHalInterface::GetNextNetworkId(int &networkId)
{
    return mIdlClient->GetNextNetworkId(networkId);
}

WifiErrorNo WifiStaHalInterface::EnableNetwork(int networkId)
{
    return mIdlClient->ReqEnableNetwork(networkId);
}

WifiErrorNo WifiStaHalInterface::DisableNetwork(int networkId)
{
    return mIdlClient->ReqDisableNetwork(networkId);
}

WifiErrorNo WifiStaHalInterface::SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    return mIdlClient->SetDeviceConfig(networkId, config);
}

WifiErrorNo WifiStaHalInterface::GetDeviceConfig(WifiIdlGetDeviceConfig &config)
{
    return mIdlClient->GetDeviceConfig(config);
}

WifiErrorNo WifiStaHalInterface::SaveDeviceConfig(void)
{
    return mIdlClient->SaveDeviceConfig();
}

WifiErrorNo WifiStaHalInterface::RegisterStaEventCallback(const WifiEventCallback &callback)
{
    return mIdlClient->ReqRegisterStaEventCallback(callback);
}

WifiErrorNo WifiStaHalInterface::StartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    return mIdlClient->ReqStartWpsPbcMode(config);
}

WifiErrorNo WifiStaHalInterface::StartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    return mIdlClient->ReqStartWpsPinMode(config, pinCode);
}

WifiErrorNo WifiStaHalInterface::StopWps(void)
{
    return mIdlClient->ReqStopWps();
}

WifiErrorNo WifiStaHalInterface::GetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    return mIdlClient->ReqGetRoamingCapabilities(capability);
}

WifiErrorNo WifiStaHalInterface::SetRoamConfig(const WifiIdlRoamConfig &config)
{
    return mIdlClient->ReqSetRoamConfig(config);
}

WifiErrorNo WifiStaHalInterface::WpaAutoConnect(int enable)
{
    return mIdlClient->ReqWpaAutoConnect(enable);
}

WifiErrorNo WifiStaHalInterface::WpaReconfigure()
{
    return mIdlClient->ReWpaReconfigure();
}

WifiErrorNo WifiStaHalInterface::WpaBlocklistClear()
{
    return mIdlClient->ReWpaBlocklistClear();
}
}  // namespace Wifi
}  // namespace OHOS