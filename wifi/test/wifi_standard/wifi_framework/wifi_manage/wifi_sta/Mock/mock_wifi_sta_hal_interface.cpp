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
std::unique_ptr<MockWifiStaInterface> pStaInterface = std::make_unique<MockWifiStaInterface>();
namespace WifiStaHalInterface {
WifiErrorNo StartWifi()
{
    return pStaInterface->pWifiStaHalInfo.startWifi ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StopWifi()
{
    return pStaInterface->pWifiStaHalInfo.stopWifi ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Connect(int networkId)
{
    return pStaInterface->pWifiStaHalInfo.connect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Reconnect()
{
    return pStaInterface->pWifiStaHalInfo.reconnect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Reassociate()
{
    return pStaInterface->pWifiStaHalInfo.reassociate ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo Disconnect()
{
    return pStaInterface->pWifiStaHalInfo.disconnect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetStaCapabilities(unsigned int &capabilities)
{
    return pStaInterface->pWifiStaHalInfo.getCapabilities ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetStaDeviceMacAddress(std::string &mac)
{
    return pStaInterface->pWifiStaHalInfo.getDeviceAddress ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    return pStaInterface->pWifiStaHalInfo.getSupportFre ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetConnectMacAddr(const std::string &mac)
{
    return pStaInterface->pWifiStaHalInfo.setConnectMac ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetScanMacAddress(const std::string &mac)
{
    return pStaInterface->pWifiStaHalInfo.setScanMac ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo DisconnectLastRoamingBssid(const std::string &mac)
{
    return pStaInterface->pWifiStaHalInfo.disconnectLast ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetSupportFeature(long &feature)
{
    return pStaInterface->pWifiStaHalInfo.getSupportFeature ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SendRequest(const WifiStaRequest &request)
{
    return pStaInterface->pWifiStaHalInfo.sendRequest ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetTxPower(int power)
{
    return pStaInterface->pWifiStaHalInfo.setTxPower ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo RemoveDevice(int networkId)
{
    return pStaInterface->pWifiStaHalInfo.removeDevice ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo ClearDeviceConfig()
{
    return pStaInterface->pWifiStaHalInfo.clearDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetNextNetworkId(int &networkId)
{
    return pStaInterface->pWifiStaHalInfo.getNextNetworkId ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo EnableNetwork(int networkId)
{
    return pStaInterface->pWifiStaHalInfo.enableNetwork ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo DisableNetwork(int networkId)
{
    return pStaInterface->pWifiStaHalInfo.disableNetwork ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    return pStaInterface->pWifiStaHalInfo.setDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetDeviceConfig(WifiIdlGetDeviceConfig &config)
{
    return pStaInterface->pWifiStaHalInfo.getDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SaveDeviceConfig()
{
    return pStaInterface->pWifiStaHalInfo.saveDeviceConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo RegisterStaEventCallback(const WifiEventCallback &callback)
{
    return pStaInterface->pWifiStaHalInfo.callback ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    return pStaInterface->pWifiStaHalInfo.startWpsPbcMode ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    return pStaInterface->pWifiStaHalInfo.startWpsPinMode ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo StopWps()
{
    return pStaInterface->pWifiStaHalInfo.stopWps ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    return pStaInterface->pWifiStaHalInfo.getRoamingCapabilities ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetRoamConfig(const WifiIdlRoamConfig &config)
{
    return pStaInterface->pWifiStaHalInfo.setRoamConfig ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo WpaAutoConnect(int enable)
{
    return pStaInterface->pWifiStaHalInfo.WpaAutoConnect ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo WpaBlocklistClear()
{
    return pStaInterface->pWifiStaHalInfo.wpaBlocklistClear ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetNetworkList(std::vector<WifiWpaNetworkInfo> &networkList)
{
    return pStaInterface->pWifiStaHalInfo.getNetworkList ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo GetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info)
{
    return pStaInterface->pWifiStaHalInfo.getConnectSignalInfo ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}

WifiErrorNo SetBssid(int networkId, const std::string &bssid)
{
    return pStaInterface->pWifiStaHalInfo.setBssid ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}
};
}  // namespace Wifi
}  // namespace OHOS