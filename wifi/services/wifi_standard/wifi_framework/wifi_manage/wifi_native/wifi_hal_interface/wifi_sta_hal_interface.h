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

#ifndef OHOS_WIFI_STA_HAL_INTERFACE_H
#define OHOS_WIFI_STA_HAL_INTERFACE_H

#include <string>
#include <vector>
#include "define.h"
#include "wifi_base_hal_interface.h"
#include "wifi_event_callback.h"
#include "wifi_native_struct.h"
#include "i_wifi_struct.h"
#include "wifi_error_no.h"
#include "wifi_msg.h"
#include "inter_scan_info.h"

namespace OHOS {
namespace Wifi {
class WifiStaHalInterface : public WifiBaseHalInterface {
public:
    /**
     * @Description Get the Instance object.
     *
     * @return WifiStaHalInterface&
     */
    static WifiStaHalInterface &GetInstance(void);

    /**
     * @Description Open Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StartWifi(const std::string &ifaceName = "wlan0", int instId = 0);

    /**
     * @Description Close Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopWifi(int instId = 0);

    /**
     * @Description Connect Wifi.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo Connect(int networkId, const std::string &ifaceName);

    /**
     * @Description Reconnect Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo Reconnect(void);

    /**
     * @Description Reassociate Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo Reassociate(const std::string &ifaceName);

    /**
     * @Description Disconnect Wifi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo Disconnect(const std::string &ifaceName);

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
    WifiErrorNo GetStaDeviceMacAddress(std::string &mac, const std::string &ifaceName, int macSrc = 0);

    /**
     * @Description Sets the Wi-Fi country code.
     *
     * @param code
     * @return WifiErrorNo
     */
    WifiErrorNo SetWifiCountryCode(const std::string &ifaceName, const std::string &code);

    /**
     * @Description Obtains the frequencies supported by a specified frequency band.
     *
     * @param band
     * @param frequencies
     * @return WifiErrorNo
     */
    WifiErrorNo GetSupportFrequencies(const std::string &ifaceName, int band, std::vector<int> &frequencies);

    /**
     * @Description Sets the MAC address of the Wi-Fi connection.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo SetConnectMacAddr(const std::string &ifaceName, const std::string &mac);

    /**
     * @Description Sets the MAC address for Wi-Fi scanning.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo SetScanMacAddress(const std::string &mac);

    /**
     * @Description Disconnect the BSSID of the last roaming subscriber.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo DisconnectLastRoamingBssid(const std::string &mac);

    /**
     * @Description Get total supported feature, and call user can
     *              determine whether support a feature.
     *
     * @param feature
     * @return WifiErrorNo
     */
    WifiErrorNo GetSupportFeature(long &feature);

    /**
     * @Description Set the Wi-Fi transmit power.
     *
     * @param power
     * @return WifiErrorNo
     */
    WifiErrorNo SetTxPower(int power);

    /**
     * @Description Scan by specified parameter.
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo Scan(const std::string &ifaceName, const WifiHalScanParam &scanParam);

    /**
     * @Description Obtain the scanning result.
     *
     * @param scanResults
     * @return WifiErrorNo
     */
    WifiErrorNo QueryScanInfos(const std::string &ifaceName, std::vector<InterScanInfo> &scanInfos);

    /**
     * @Description Initiate PNO scanning.
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo StartPnoScan(const std::string &ifaceName, const WifiHalPnoScanParam &scanParam);

    /**
     * @Description Stop PNO Scanning.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopPnoScan(const std::string &ifaceName);

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
    WifiErrorNo ClearDeviceConfig(const std::string &ifaceName) const;

    /**
     * @Description Request to obtain the next network ID.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo GetNextNetworkId(int &networkId, const std::string &ifaceName);

    /**
     * @Description Enable a network.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo EnableNetwork(int networkId, const std::string &ifaceName);

    /**
     * @Description Disable a network.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo DisableNetwork(int networkId, const std::string &ifaceName);

    /**
     * @Description Setting the network.
     *
     * @param networkId
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo SetDeviceConfig(int networkId, const WifiHalDeviceConfig &config, const std::string &ifaceName);

    /**
     * @Description Obtaining Network Configurations.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo GetDeviceConfig(WifiHalGetDeviceConfig &config, const std::string &ifaceName);

    /**
     * @Description Save network config.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo SaveDeviceConfig(void);

    /**
     * @Description Registering the Sta Event Callback.
     *
     * @param callback
     * @return WifiErrorNo
     */
    WifiErrorNo RegisterStaEventCallback(const WifiEventCallback &callback, const std::string &ifaceName);

    /**
     * @Description Enabling WPS in PBC Mode.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo StartWpsPbcMode(const WifiHalWpsConfig &config);

    /**
     * @Description Enable PIN mode WPS.
     *
     * @param config
     * @param pinCode
     * @return WifiErrorNo
     */
    WifiErrorNo StartWpsPinMode(const WifiHalWpsConfig &config, int &pinCode);

    /**
     * @Description Close wps.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopWps(void);

    /**
     * @Description Obtains the roaming support capability.
     *
     * @param capability
     * @return WifiErrorNo
     */
    WifiErrorNo GetRoamingCapabilities(WifiHalRoamCapability &capability);

    /**
     * @Description Set bssid to supplicant.
     *
     * @param networkId
     * @param bssid
     * @return WifiErrorNo
     */
    WifiErrorNo SetBssid(int networkId, const std::string &bssid, const std::string &ifaceName);

    /**
     * @Description Setting Roaming Configurations.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo SetRoamConfig(const WifiHalRoamConfig &config);

    /**
     * @Description Wpa_s disable/enable(0/1) automatic reconnection.
     *
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo WpaAutoConnect(int enable);

    /**
     * @Description Clearing the wpa Blocklist.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo WpaBlocklistClear();

    /**
     * @Description Obtaining the Network List.
     *
     * @param networkList
     * @return WifiErrorNo
     */
    WifiErrorNo GetNetworkList(std::vector<WifiHalWpaNetworkInfo> &networkList);

    /**
     * @Description Get current connect signal info, rssi, linkspeed, noise ...
     *
     * @param endBssid - peer end bssid, i.e. linked ap's bssid
     * @param info - signal info
     * @return WifiErrorNo
     */
    WifiErrorNo GetConnectSignalInfo(const std::string &ifaceName, const std::string &endBssid,
        WifiSignalPollInfo &info);

    /**
     * @Description set power save mode
     *
     * @param frequency - connected ap frequency
     * @param mode - power save mode
     */
    WifiErrorNo SetPmMode(const std::string &ifaceName, int frequency, int mode);

    /**
     * @Description set data packet identification mark rule
     *
     * @param uid - target app uid
     * @param protocol - target protocol type
     * @param enable - enable/disable dpi mark
     */
    WifiErrorNo SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable);

    /**
     * @Description Send SIM/AKA/AKA' authentication to wpa
     *
     * @param ifName: Interface name
     * @param cmd: Request message content
     * @return WifiErrorNo
     */
    WifiErrorNo ShellCmd(const std::string &ifName, const std::string &cmd);

    /**
     * @Description get psk pass phrase
     *
     * @param ifName: Interface name
     * @param psk: psk
     * @return WifiErrorNo
     */
    WifiErrorNo GetPskPassphrase(const std::string &ifName, std::string &psk);

    /**
     * @Description set background limit speed uid&pid list
     *
     * @param chipsetCategory - chipset category
     */
    WifiErrorNo GetChipsetCategory(const std::string &ifaceName, int& chipsetCategory);

    /**
     * @Description set background limit speed uid&pid list
     *
     * @param chipsetFeatrureCapability - chipset featrure capability
     */
    WifiErrorNo GetChipsetWifiFeatrureCapability(const std::string &ifaceName, int& chipsetFeatrureCapability);

    /**
     * @Description Set network interface updown.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo SetNetworkInterfaceUpDown(const std::string &ifaceName, bool upDown);

    /**
     * @Description Get register callback objects
     *
     * @return const WifiEventCallback& - register sta callback objects
     */
    const WifiEventCallback &GetCallbackInst(const std::string &ifaceName) const;

    /**
     * @Description Get register callback objects for death receiver
     *
     * @return const std::function<void(int)>& - register death callback objects
     */
    const std::function<void(int)> &GetDeathCallbackInst(void) const;

    /**
     * @Description Register the native process callback.
     *
     * @param callback
     * @return WifiErrorNo
     */
    WifiErrorNo RegisterNativeProcessCallback(const std::function<void(int)> &callback);

    /**
     * @Description get wifi7 mlo link info
     *
     * @param ifName - interface name
     * @param mloLinkInfo - MLO link info
     * @return WifiErrorNo
     */
    WifiErrorNo GetConnectionMloLinkedInfo(const std::string &ifName, std::vector<WifiLinkedInfo> &mloLinkInfo);

    /**
     * @Description get wifi7 mlo signal poll info
     *
     * @param ifName - interface name
     * @param mloLinkInfo - MLO signal poll info
     * @return WifiErrorNo
     */
    WifiErrorNo GetConnectionMloSignalInfo(const std::string &ifName, std::vector<WifiMloSignalInfo> &mloSignalInfo);

private:
#ifdef READ_MAC_FROM_OEM
    std::string GetWifiOeminfoMac();
    std::string wifiOemMac_ = "";
#endif

private:
    WifiEventCallback mStaCallback[2];
    std::function<void(int)> mDeathCallback;
};
}  // namespace Wifi
}  // namespace OHOS

#endif