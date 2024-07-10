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

#include "mock_wifi_sta_interface.h"

namespace OHOS {
namespace Wifi {
namespace WifiStaHalInterface {

WifiErrorNo StartWifi()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWifi ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StopWifi()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo Connect(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.connect ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo Reconnect()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reconnect ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo Reassociate()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo Disconnect()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetStaCapabilities(unsigned int &capabilities)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getCapabilities ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetStaDeviceMacAddress(std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceAddress ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getSupportFre ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SetConnectMacAddr(const std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setConnectMac ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SetScanMacAddress(const std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setScanMac ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo DisconnectLastRoamingBssid(const std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnectLast ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetSupportFeature(long &feature)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getSupport ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SetTxPower(int power)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setTxPower ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo RemoveDevice(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.removeDevice ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo ClearDeviceConfig()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetNextNetworkId(int &networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getNextNetworkId ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo EnableNetwork(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo DisableNetwork(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disableNetwork ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SetDeviceConfig(int networkId, const WifiHalDeviceConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetDeviceConfig(WifiHalGetDeviceConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceConfig ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SaveDeviceConfig()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo RegisterStaEventCallback(const WifiEventCallback &callback)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.callback ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StartWpsPbcMode(const WifiHalWpsConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPbcMode ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StartWpsPinMode(const WifiHalWpsConfig &config, int &pinCode)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPinMode ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo StopWps()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetRoamingCapabilities(WifiHalRoamCapability &capability)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getRoaming ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SetRoamConfig(const WifiHalRoamConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setRoamConfig ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WpaAutoConnect(int enable)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaAutoConnect ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo WpaBlocklistClear()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaBlocklist ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetNetworkList(std::vector<WifiHalWpaNetworkInfo> &networkList)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getNetworkList ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo GetConnectSignalInfo(const std::string &endBssid, WifiHalWpaSignalInfo &info)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getConnect ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}

WifiErrorNo SetBssid(int networkId, const std::string &bssid)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setBssid ? WIFI_HAL_OPT_OK : WIFI_HAL_OPT_FAILED;
}
};
}  // namespace Wifi
}  // namespace OHOS