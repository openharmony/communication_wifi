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
#ifndef OHOS_WIFI_HDI_WPA_CLIENT_H
#define OHOS_WIFI_HDI_WPA_CLIENT_H

#include <string>
#include <vector>
#include "wifi_internal_msg.h"
#include "wifi_error_no.h"
#include "wifi_sta_request.h"
#include "wifi_scan_param.h"
#include "wifi_idl_struct.h"
#include "wifi_idl_define.h"
#include "wifi_global_func.h"
#include "i_wifi_struct.h"
#include "wifi_event_callback.h"

namespace OHOS {
namespace Wifi {
class WifiHdiWpaClient {
public:
    WifiHdiWpaClient() = default;
    ~WifiHdiWpaClient() = default;

    /* ************************ Sta Interface ************************** */
    /**
     * @Description Open Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StartWifi(void);

    /**
     * @Description Close Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopWifi(void);

    /**
     * @Description Connect Wifi.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo ReqConnect(int networkId);

    /**
     * @Description Reconnect Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqReconnect(void);

    /**
     * @Description Reassociate Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqReassociate(void);

    /**
     * @Description Disconnect Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqDisconnect(void);

    /**
     * @Description Obtaining the STA Support Capability.
     *
     * @param capabilities
     * @return WifiErrorNo
     */
    WifiErrorNo GetStaCapabilities(unsigned int &capabilities);

    /**
     * @Description Obtaining the MAC Address of a STA.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo GetStaDeviceMacAddress(std::string &mac);

    /**
     * @Description Obtains the frequencies supported by a specified
     *              frequency band.
     *
     * @param band
     * @param frequencies
     * @return WifiErrorNo
     */
    WifiErrorNo GetSupportFrequencies(int band, std::vector<int> &frequencies);

    /**
     * @Description Sets the MAC address of the Wi-Fi connection.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo SetConnectMacAddr(const std::string &mac);

    /**
     * @Description Scan by specified parameter.
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo Scan(const WifiScanParam &scanParam);

    /**
     * @Description Obtain the scanning result.
     *
     * @param scanInfos
     * @return WifiErrorNo
     */
    WifiErrorNo QueryScanInfos(std::vector<InterScanInfo> &scanInfos);

    /**
     * @Description Initiate PNO scanning.
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStartPnoScan(const WifiPnoScanParam &scanParam);

    /**
     * @Description Stop PNO Scanning.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStopPnoScan(void);

    /**
     * @Description Deleting a Network.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo RemoveDevice(int networkId);

    /**
     * @Description Clears the network configuration information saved by wpa_supplicant.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ClearDeviceConfig(void) const;

    /**
     * @Description Request to obtain the next network ID.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo GetNextNetworkId(int &networkId);

    /**
     * @Description Enable a network.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo ReqEnableNetwork(int networkId);

    /**
     * @Description Disable a network.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo ReqDisableNetwork(int networkId);

    /**
     * @Description Setting the network.
     *
     * @param networkId
     * @param config - Setting Network Parameters.
     * @return WifiErrorNo
     */
    WifiErrorNo SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config);

    /**
     * @Description Set bssid to supplicant.
     *
     * @param networkId
     * @param bssid
     * @return WifiErrorNo
     */
    WifiErrorNo SetBssid(int networkId, const std::string &bssid);

    /**
     * @Description Save the network.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo SaveDeviceConfig(void);

    /**
     * @Description Registering the Sta Event Callback.
     *
     * @param callback - Registering an Event Callback Function.
     * @return WifiErrorNo
     */
    WifiErrorNo ReqRegisterStaEventCallback(const WifiEventCallback &callback);

    /**
     * @Description Enabling WPS in PBC Mode.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStartWpsPbcMode(const WifiIdlWpsConfig &config);

    /**
     * @Description Enable PIN mode WPS.
     *
     * @param config
     * @param pinCode
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStartWpsPinMode(const WifiIdlWpsConfig &config, int &pinCode);

    /**
     * @Description Close wps.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStopWps(void);

    /**
     * @Description Obtains the roaming support capability.
     *
     * @param capability - Roaming Support Capability.
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetRoamingCapabilities(WifiIdlRoamCapability &capability);

    /**
     * @Description Setting Roaming Configurations.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetRoamConfig(const WifiIdlRoamConfig &config);

    /**
     * @Description Get current connect signal info, rssi, linkspeed, noise ...
     *
     * @param endBssid - peer end bssid, i.e. linked ap's bssid
     * @param info - signal info
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info) const;

    /**
     * @Description Wpa_s disable/enable(0/1) automatic reconnection.
     *
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaAutoConnect(int enable);

    /**
     * @Description Clearing the wpa Blocklist.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaBlocklistClear(void);

    /**
     * @Description Turn on/off power save mode for the interface.
     *
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetPowerSave(bool enable);

    /**
     * @Description Setting the country code.
     *
     * @param countCode
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaSetCountryCode(const std::string &countryCode);

    /**
     * @Description Send suspend mode to wpa
     *
     * @param mode: true for suspend, false for resume
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaSetSuspendMode(bool mode) const;

private:
    int PushDeviceConfigString(SetNetworkConfig *pConfig, DeviceConfigType type,
        const std::string &msg, bool checkEmpty = true) const;
    int PushDeviceConfigInt(SetNetworkConfig *pConfig, DeviceConfigType type, int i) const;
    int PushDeviceConfigAuthAlgorithm(SetNetworkConfig *pConfig, DeviceConfigType type, unsigned int alg) const;
    int PushDeviceConfigParseMask(SetNetworkConfig *pConfig, DeviceConfigType type, unsigned int mask,
        const std::string parseStr[], int size) const;
    WifiErrorNo CheckValidDeviceConfig(const WifiIdlDeviceConfig &config) const;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif