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
#include "wifi_ap_event_callback.h"
#include "wifi_p2p_event_callback.h"

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
    WifiErrorNo StartWifi(const std::string &ifaceName);

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
    static WifiErrorNo ReqWpaGetCountryCode(std::string &countryCode);
    /**
     * @Description Send suspend mode to wpa
     *
     * @param mode: true for suspend, false for resume
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaSetSuspendMode(bool mode) const;
    WifiErrorNo GetNetworkList(std::vector<WifiWpaNetworkInfo> &networkList);
    static WifiErrorNo GetDeviceConfig(WifiIdlGetDeviceConfig &config);

    /**
     * @Description Send SIM/AKA/AKA' authentication to wpa
     *
     * @param ifName: Interface name
     * @param cmd: Request message content
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaShellCmd(const std::string &ifName, const std::string &cmd);

    /**
     * @Description get psk pass phrase
     *
     * @param ifName: Interface name
     * @param psk: psk
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaGetPskPassphrase(const std::string &ifName, std::string &psk);

    /* ************************ softAp Interface ************************** */
    /**
     * @Description Start Ap.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StartAp(int id, const std::string &ifaceName);

    /**
     * @Description Close Ap.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopAp(int id = 0);

    /**
     * @Description Save callback.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo RegisterApEvent(IWifiApMonitorEventCallback callback, int id = 0) const;

    /**
     * @Description Setting SoftAp Configurations.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo SetSoftApConfig(const HotspotConfig &config, int id = 0);

    /**
     * @Description Obtain information about all connected STAs.
     *
     * @param result
     * @return WifiErrorNo
     */
    WifiErrorNo GetStationList(std::vector<std::string> &result, int id = 0);

     /**
     * @Description To set the blocked list filtering in AP mode to prohibit the MAC address connection.
     *
     * @param mac The mac is going to be added
     * @return WifiErrorNo
     */
    WifiErrorNo AddBlockByMac(const std::string &mac, int id = 0);

    /**
     * @Description To set the blocked list filtering in AP mode and delete a specified MAC address
     *              from the blocked list.
     *
     * @param mac The mac is going to be deleted
     * @return WifiErrorNo
     */
    WifiErrorNo DelBlockByMac(const std::string &mac, int id = 0);

    /**
     * @Description Disconnect the STA with a specified MAC address.
     *
     * @param mac The mac is going to be removed
     * @return WifiErrorNo
     */
    WifiErrorNo RemoveStation(const std::string &mac, int id = 0);

    /**
     * @Description Disconnect the STA connection based on the MAC address.
     *
     * @param mac The mac is going to be disconnected
     * @return WifiErrorNo
     */
    WifiErrorNo ReqDisconnectStaByMac(const std::string &mac, int id = 0);

    /* ************************ P2p Interface ************************** */
    /**
     * @Description P2P start
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pStart(const std::string &ifaceName);

    /**
     * @Description P2P stop
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pStop();

    /**
     * @Description P2P hal-layer registration event
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pRegisterCallback(const P2pHalCallback &callbacks) const;

    /**
     * @Description Send a request for setup wps pbc to the P2P
     *
     * @param groupInterface
     * @param bssid
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetupWpsPbc(const std::string &groupInterface, const std::string &bssid) const;

    /**
     * @Description Enable Wps Pin mode
     *
     * @param groupInterface - p2p group
     * @param address
     * @param pin - pin code
     * @param result - when pin is empty, represent use pin display mode, this return pin code
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetupWpsPin(const std::string &groupInterface, const std::string &address, const std::string &pin,
        std::string &result) const;

    /**
     * @Description Send a request for remove a p2p network to the P2P
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pRemoveNetwork(int networkId) const;

    /**
     * @Description Send a request for get p2p network list to the P2P
     *
     * @param mapGroups
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pListNetworks(std::map<int, WifiP2pGroupInfo> &mapGroups) const;

    /**
     * @Description Requesting P2P Setting Device Name
     *
     * @param name
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetDeviceName(const std::string &name) const;

    /**
     * @Description Send a request for setting the WPS primary device type in P2P mode
     *
     * @param type
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetWpsDeviceType(const std::string &type) const;

    /**
     * @Description Send a request for setting the WPS secondary device type in P2P mode
     *
     * @param type
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetWpsSecondaryDeviceType(const std::string &type) const;

    /**
     * @Description Send a request for setting the WPS configuration method to the P2P.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetWpsConfigMethods(const std::string &config) const;

    /**
     * @Description Send a P2P request for setting the SSID suffix
     *
     * @param postfixName
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetSsidPostfixName(const std::string &postfixName) const;

    /**
     * @Description Send a request for set group max idle to the P2P
     *
     * @param groupInterface
     * @param time
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetGroupMaxIdle(const std::string &groupInterface, size_t time) const;

    /**
     * @Description Send a request for set power save to the P2P
     *
     * @param groupInterface
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetPowerSave(const std::string &groupInterface, bool enable) const;

    /**
     * @Description enable/disable Wi-Fi Display
     *
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetWfdEnable(bool enable) const;

    /**
     * @Description Send a request for set Wi-Fi Display config
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetWfdDeviceConfig(const std::string &config) const;

    /**
     * @Description Send a request for start p2p find to the P2P
     *
     * @param timeout
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pStartFind(size_t timeout) const;

    /**
     * @Description Send a request for stop p2p find to the P2P
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pStopFind() const;

    /**
     * @Description Send a request for set ext listen to the P2P
     *
     * @param enable
     * @param period
     * @param interval
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetExtListen(bool enable, size_t period, size_t interval) const;

    /**
     * @Description Send a request for set listen channel to the P2P
     *
     * @param channel
     * @param regClass
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetListenChannel(size_t channel, unsigned char regClass) const;

    /**
     * @Description Send a request for flush to the P2P.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pFlush() const;

    /**
     * @Description Send a request for connect to the P2P
     *
     * @param config
     * @param isJoinExistingGroup
     * @param pin
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pConnect(const WifiP2pConfigInternal &config, bool isJoinExistingGroup, std::string &pin) const;

    /**
     * @Description Send a request for cancel connect to the P2P
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pCancelConnect() const;

    /**
     * @Description Send a request for Provision Discovery to the P2P
     *
     */
    WifiErrorNo ReqP2pProvisionDiscovery(const WifiP2pConfigInternal &config) const;

    /**
     * @Description Send a request for add a P2P group to the P2P
     *
     * @param isPersistent
     * @param networkId
     * @param freq
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pAddGroup(bool isPersistent, int networkId, int freq) const;

    /**
     * @Description Send a request for remove group to the P2P
     *
     * @param groupInterface
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pRemoveGroup(const std::string &groupInterface) const;

    /**
     * @Description Send a request for invite to the P2P
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pInvite(const WifiP2pGroupInfo &group, const std::string &deviceAddr) const;

    /**
     * @Description Send a request for reinvoke to the P2P
     *
     * @param networkId
     * @param deviceAddr
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pReinvoke(int networkId, const std::string &deviceAddr) const;

    /**
     * @Description Send a request for get device address to the P2P.
     *
     * @param deviceAddress
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pGetDeviceAddress(std::string &deviceAddress) const;

    /**
     * @Description Send a request for get group capability to the P2P
     *
     * @param deviceAddress
     * @param cap
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pGetGroupCapability(const std::string &deviceAddress, uint32_t &cap) const;

    /**
     * @Description Send a request for add service to the P2P
     *
     * @param WifiP2pServiceInfo
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pAddService(const WifiP2pServiceInfo &info) const;

    /**
     * @Description Send a request for remove service to the P2P
     *
     * @param RemoveService
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pRemoveService(const WifiP2pServiceInfo &info) const;

    /**
     * @Description Send a request for flush service to the P2P
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pFlushService() const;

    /**
     * @Description Send a request for save config to the P2P
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSaveConfig() const;

    /**
     * @Description Send a request for request service discovery to the P2P
     *
     * @param macAddr
     * @param queryMsg
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pReqServiceDiscovery(
        const std::string &deviceAddress, const std::vector<unsigned char> &tlvs, std::string &reqID) const;

    /**
     * @Description Send a request for cancel request service discovery to the P2P
     *
     * @param id
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pCancelServiceDiscovery(const std::string &id) const;

    /**
     * @Description set enable/disable using random mac address
     *
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetRandomMac(bool enable) const;

    /**
     * @Description Send a request for set the miracast type to the P2P
     *
     * @param type
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetMiracastType(int type) const;

    /**
     * @Description Set the Persistent Reconnect mode.
     *
     * @param mode
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetPersistentReconnect(int mode) const;

    /**
     * @Description
     *
     * @param deviceAddress
     * @param frequency
     * @param dialogToken
     * @param tlvs
     * @param tlvsLength
     * @return WifiErrorNo
     */
    WifiErrorNo ReqRespServiceDiscovery(
        const WifiP2pDevice &device, int frequency, int dialogToken, const std::vector<unsigned char> &tlvs) const;

    /**
     * @Description Set P2p server discovery external.
     *
     * @param isExternalProcess
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetServiceDiscoveryExternal(bool isExternalProcess) const;

     /**
     * @Description Show information about known P2P peer
     *
     * @param deviceAddress
     * @param device
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetP2pPeer(const std::string &deviceAddress, WifiP2pDevice &device) const;

    /**
     * @Description Obtains the P2P frequency supported by a specified frequency band.
     *
     * @param band - Frequency band.
     * @param frequencies - Frequency list.
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pGetSupportFrequencies(int band, std::vector<int> &frequencies) const;

    /**
     * @Description Setting the P2P group config.
     *
     * @param networkId
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pSetGroupConfig(int networkId, const IdlP2pGroupConfig &config) const;

    int PushP2pGroupConfigString(P2pGroupConfig *pConfig, P2pGroupConfigType type, const std::string &str) const;

    int PushP2pGroupConfigInt(P2pGroupConfig *pConfig, P2pGroupConfigType type, int i) const;

    /**
     * @Description Getting the P2P group config.
     *
     * @param networkId
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pGetGroupConfig(int networkId, IdlP2pGroupConfig &config) const;

    /**
     * @Description Request to obtain the next network ID.
     *
     * @param networkId
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pAddNetwork(int &networkId) const;

    /**
     * @Description Send a request for hid2d connect
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo ReqP2pHid2dConnect(const Hid2dConnectConfig &config) const;

    /**
     * @Description Send power mode to wpa
     *
     * @param mode: true for power, false for resume
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaSetPowerMode(bool mode) const;
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