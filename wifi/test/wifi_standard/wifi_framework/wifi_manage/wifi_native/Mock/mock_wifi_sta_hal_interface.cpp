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

#include "mock_wifi_sta_hal_interface.h"

namespace OHOS {
namespace Wifi {

MockWifiStaHalInterface::MockWifiStaHalInterface()
{
    mRetResult = WIFI_HAL_OPT_OK;
}

MockWifiStaHalInterface &MockWifiStaHalInterface::GetInstance(void)
{
    static MockWifiStaHalInterface inst;
    return inst;
}
void MockWifiStaHalInterface::SetRetResult(WifiErrorNo retResult)
{
    mRetResult = retResult;
}
WifiErrorNo MockWifiStaHalInterface::GetRetResult()
{
    return mRetResult;
}

void MockWifiStaHalInterface::SetStaCapabilities(WifiErrorNo retResult)
{
    mGetStaCapabilities = retResult;
}

void MockWifiStaHalInterface::SetChipsetFeatureCapability(int chipsetFeatureCapability)
{
    chipsetFeatureCapability_ = chipsetFeatureCapability;
}

WifiStaHalInterface &WifiStaHalInterface::GetInstance(void)
{
    static WifiStaHalInterface inst;
    return inst;
}

WifiErrorNo WifiStaHalInterface::StartWifi(const std::string &ifaceName, int instId)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StopWifi(int instId)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Connect(int networkId, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Reconnect(void)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Reassociate(const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Disconnect(const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetStaCapabilities(unsigned int &capabilities)
{
    return (MockWifiStaHalInterface::GetInstance().mGetStaCapabilities == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetStaDeviceMacAddress(std::string &mac, const std::string &ifaceName, int macSrc)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetWifiCountryCode(const std::string &ifaceName, const std::string &code)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetSupportFrequencies(const std::string &ifaceName, int band,
    std::vector<int> &frequencies)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetConnectMacAddr(const std::string &ifaceName, const std::string &mac)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetScanMacAddress(const std::string &mac)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::DisconnectLastRoamingBssid(const std::string &mac)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetSupportFeature(long &feature)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetTxPower(const std::string &ifaceName, int power)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::Scan(const std::string &ifaceName, const WifiHalScanParam &scanParam)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::QueryScanInfos(const std::string &ifaceName, std::vector<InterScanInfo> &scanInfos)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetNetworkList(std::vector<WifiHalWpaNetworkInfo> &networkList)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StartPnoScan(const std::string &ifaceName, const WifiHalPnoScanParam &scanParam)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StopPnoScan(const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::RemoveDevice(int networkId)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::ClearDeviceConfig(const std::string &ifaceName) const
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetNextNetworkId(int &networkId, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::EnableNetwork(int networkId, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::DisableNetwork(int networkId, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetDeviceConfig(
    int networkId, const WifiHalDeviceConfig &config, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetDeviceConfig(WifiHalGetDeviceConfig &config, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SaveDeviceConfig(void)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::RegisterStaEventCallback(
    const WifiEventCallback &callback, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StartWpsPbcMode(const WifiHalWpsConfig &config)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StartWpsPinMode(const WifiHalWpsConfig &config, int &pinCode)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::StopWps(void)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetRoamingCapabilities(WifiHalRoamCapability &capability)
{
    capability = mCapability;
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetBssid(int networkId, const std::string &bssid, const std::string &ifaceName)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetRoamConfig(const WifiHalRoamConfig &config)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::WpaAutoConnect(int enable)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::WpaBlocklistClear()
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetConnectSignalInfo(const std::string &ifaceName, const std::string &endBssid,
    WifiSignalPollInfo &info)
{
    info = mInfo;
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetPmMode(const std::string &ifaceName, int frequency, int mode)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetPskPassphrase(const std::string &ifName, std::string &psk)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetChipsetCategory(const std::string &ifaceName, int& chipsetCategory)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::GetChipsetWifiFeatrureCapability(
    const std::string &ifaceName, int& chipsetFeatrureCapability)
{
    chipsetFeatrureCapability = MockWifiStaHalInterface::GetInstance().chipsetFeatureCapability_;
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::ShellCmd(const std::string &ifName, const std::string &cmd)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WifiStaHalInterface::SetNetworkInterfaceUpDown(const std::string &ifaceName, bool upDown)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

const WifiEventCallback &WifiStaHalInterface::GetCallbackInst(const std::string &ifaceName) const
{
    return mStaCallback;
}

const std::function<void(int)> &WifiStaHalInterface::GetDeathCallbackInst(void) const
{
    return mDeathCallback;
}

WifiErrorNo WifiStaHalInterface::RegisterNativeProcessCallback(const std::function<void(int)> &callback)
{
    mDeathCallback = callback;
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
        WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}
WifiErrorNo WifiStaHalInterface::GetConnectionMloLinkedInfo(const std::string &ifName,
    std::vector<WifiLinkedInfo> &mloLinkInfo)
{
    return (MockWifiStaHalInterface::GetInstance().GetRetResult() == WIFI_HAL_OPT_OK) ?
    WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}
}  // namespace Wifi
}  // namespace OHOS
