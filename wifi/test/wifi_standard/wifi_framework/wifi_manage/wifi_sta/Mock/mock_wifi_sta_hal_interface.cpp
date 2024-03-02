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

#include <map>
#include <string>
#include <vector>
#include "wifi_msg.h"
#include "wifi_error_no.h"
#include "wifi_idl_struct.h"
#include "wifi_sta_request.h"
#include "wifi_event_callback.h"
#include "mock_wifi_sta_interface.h"

namespace OHOS {
namespace Wifi {
namespace WifiStaHalInterface {

WifiErrorNo StartWifi()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWifi ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StopWifi()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Connect(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.connect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Reconnect()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reconnect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Reassociate()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Disconnect()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetStaCapabilities(unsigned int &capabilities)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getCapabilities ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetStaDeviceMacAddress(std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceAddress ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getSupportFre ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetConnectMacAddr(const std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setConnectMac ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetScanMacAddress(const std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setScanMac ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo DisconnectLastRoamingBssid(const std::string &mac)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnectLast ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetSupportFeature(long &feature)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getSupportFeature ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SendRequest(const WifiStaRequest &request)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.sendRequest ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetTxPower(int power)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setTxPower ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo RemoveDevice(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.removeDevice ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo ClearDeviceConfig()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetNextNetworkId(int &networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getNextNetworkId ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo EnableNetwork(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo DisableNetwork(int networkId)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disableNetwork ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetDeviceConfig(WifiIdlGetDeviceConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SaveDeviceConfig()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo RegisterStaEventCallback(const WifiEventCallback &callback)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.callback ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPbcMode ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPinMode ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StopWps()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getRoamingCapabilities ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetRoamConfig(const WifiIdlRoamConfig &config)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setRoamConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo WpaAutoConnect(int enable)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaAutoConnect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo WpaBlocklistClear()
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaBlocklistClear ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetNetworkList(std::vector<WifiWpaNetworkInfo> &networkList)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getNetworkList ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getConnectSignalInfo ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetBssid(int networkId, const std::string &bssid)
{
    return MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setBssid ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}
};
}  // namespace Wifi
}  // namespace OHOS