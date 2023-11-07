/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_client.h"
#include "wifi_hdi_wpa_sta_impl.h"

WifiErrorNo WifiHdiWpaClient::StartWifi(void)
{
    return Start();
}

WifiErrorNo WifiHdiWpaClient::StopWifi(void)
{
    return Stop();
}

WifiErrorNo WifiHdiWpaClient::ReqConnect(int networkId)
{
    return Connect(networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqReconnect(void)
{
    return Reconnect();
}

WifiErrorNo WifiHdiWpaClient::ReqReassociate(void)
{
    return Reassociate();
}

WifiErrorNo WifiHdiWpaClient::ReqDisconnect(void)
{
    return Disconnect();
}


WifiErrorNo WifiHdiWpaClient::GetStaCapabilities(unsigned int &capabilities)
{
    return GetCapabilities((uint32_t *)&capabilities);
}


WifiErrorNo WifiHdiWpaClient::GetStaDeviceMacAddress(std::string &mac)
{
    char macAddr[WIFI_IDL_BSSID_LENGTH + 1] = {0};
    int macAddrLen = 0;
    WifiErrorNo err = GetDeviceMacAddress((unsigned char *)macAddr, &macAddrLen);
    if (err == WIFI_IDL_OPT_OK) {
        mac = std::string(macAddr);
    }
    return err;
}

WifiErrorNo WifiHdiWpaClient::GetSupportFrequencies(int band, std::vector<int> &frequencies)
{
    int values[WIFI_IDL_GET_MAX_BANDS] = {0};
    int size = 0;
    if (GetFrequencies(band, values, &size) != 0) {
        return WIFI_IDL_OPT_FAILED;
    }

    for (int i = 0; i < size; i++) {
        frequencies.push_back(values[i]);
    }

    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiWpaClient::SetConnectMacAddr(const std::string &mac)
{
    if (CheckMacIsValid(mac) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    int len = mac.length();
    return SetAssocMacAddr((unsigned char *)mac.c_str(), len);
}

WifiErrorNo WifiHdiWpaClient::Scan(const WifiScanParam &scanParam)
{
    return Scan(scanParam);
}

WifiErrorNo WifiHdiWpaClient::QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    return GetScanInfos(&scanInfos);
}

WifiErrorNo WifiHdiWpaClient::ReqStartPnoScan(const WifiPnoScanParam &scanParam)
{
    return StartPnoScan(&scanParam);
}

WifiErrorNo WifiHdiWpaClient::ReqStopPnoScan(void)
{
    return StopPnoScan();
}

WifiErrorNo WifiHdiWpaClient::RemoveDevice(int networkId)
{
    if (networkId < 0) {
        return WIFI_IDL_OPT_INVALID_PARAM;
    }
    return RemoveNetwork(networkId);
}

WifiErrorNo WifiHdiWpaClient::ClearDeviceConfig(void) const
{
    return RemoveNetwork(-1);
}


WifiErrorNo WifiHdiWpaClient::GetNextNetworkId(int &networkId)
{
    return AddNetwork(&networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqEnableNetwork(int networkId)
{
    return EnableNetwork(networkId);
}

WifiErrorNo WifiHdiWpaClient::ReqDisableNetwork(int networkId)
{
    return DisableNetwork(networkId);
}


WifiErrorNo WifiHdiWpaClient::SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config)
{
    return SetNetwork(networkId, config.name, config.value);
}


WifiErrorNo WifiHdiWpaClient::SetBssid(int networkId, const std::string &bssid)
{
    return SetNetwork(networkId, DEVICE_CONFIG_BSSID, &bssid);
}


WifiErrorNo WifiHdiWpaClient::SaveDeviceConfig(void)
{
    return SaveConfig();
}


WifiErrorNo WifiHdiWpaClient::ReqRegisterStaEventCallback(const WifiEventCallback &callback)
{
    IWifiHdiWpaCallback cWifiHdiWpaCallback;
    if (memset_s(&cWifiHdiWpaCallback, sizeof(cWifiHdiWpaCallback), 0, sizeof(cWifiHdiWpaCallback)) != EOK) {
        return WIFI_IDL_OPT_FAILED;
    }

    if (callback.onConnectChanged != nullptr) {
        cWifiHdiWpaCallback.OnEventDisconnected = OnEventDisconnected;
        cWifiHdiWpaCallback.OnEventConnected = OnEventConnected;
        cWifiHdiWpaCallback.OnEventBssidChanged = OnEventBssidChanged;
        cWifiHdiWpaCallback.OnEventStateChanged = OnEventStateChanged;
        cWifiHdiWpaCallback.OnEventTempDisabled = OnEventTempDisabled;
        cWifiHdiWpaCallback.OnEventAssociateReject = OnEventAssociateReject;
        cWifiHdiWpaCallback.OnEventWpsOverlap = OnEventWpsOverlap;
        cWifiHdiWpaCallback.OnEventWpsTimeout = OnEventWpsTimeout;
        cWifiHdiWpaCallback.OnEventScanResult = OnEventScanResult;
    }

    return RegisterHdiWpaStaEventCallback(&cWifiHdiWpaCallback);
}


WifiErrorNo WifiHdiWpaClient::ReqStartWpsPbcMode(const WifiIdlWpsConfig &config)
{
    return StartWpsPbcMode(&config);
}


WifiErrorNo WifiHdiWpaClient::ReqStartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode)
{
    return StartWpsPinMode(&config, &pinCode);
}


WifiErrorNo WifiHdiWpaClient::ReqStopWps(void)
{
    return StopWpa();
}

WifiErrorNo WifiHdiWpaClient::ReqGetRoamingCapabilities(WifiIdlRoamCapability &capability)
{
    return GetRoamingCapabilities(&capability);
}


WifiErrorNo WifiHdiWpaClient::ReqSetRoamConfig(const WifiIdlRoamConfig &config)
{
    return SetRoamConfig(&config);
}


WifiErrorNo WifiHdiWpaClient::ReqGetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info) const
{
    return GetConnectSignalInfo(&endBssid, &info);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaAutoConnect(int enable)
{
    return WpaAutoConnect(enable);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaBlocklistClear(void)
{
    return WpaBlocklistClear();
}

WifiErrorNo WifiHdiWpaClient::ReqSetPowerSave(bool enable)
{
    return SetPowerSave(enable);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaSetCountryCode(const std::string &countryCode)
{
    return WpaSetCountryCode(&countryCode);
}

WifiErrorNo WifiHdiWpaClient::ReqWpaSetSuspendMode(bool mode) const
{
    return WpaSetSuspendMode(mode);
}
#endif