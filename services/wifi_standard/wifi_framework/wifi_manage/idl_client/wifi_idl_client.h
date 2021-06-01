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

#ifndef OHOS_WIFIDLCLIENT_H
#define OHOS_WIFIDLCLIENT_H

#include <string>
#include <vector>
#include "wifi_msg.h"
#include "supplicant_event_callback.h"
#include "wifi_chip_event_callback.h"
#include "wifi_error_no.h"
#include "wifi_event_callback.h"
#include "wifi_idl_struct.h"
#include "wifi_scan_param.h"
#include "wifi_scan_result.h"
#include "wifi_sta_request.h"
#include "client.h"
#include "i_wifi_chip.h"
#include "i_wifi_hotspot_iface.h"
#include "i_wifi_struct.h"

namespace OHOS {
namespace Wifi {
class WifiIdlClient {
public:
    /**
     * @Description Construct a new Wifi Idl Client object.
     *
     */
    WifiIdlClient();
    /**
     * @Description Destroy the Wifi Idl Client object.
     *
     */
    ~WifiIdlClient();

    /**
     * @Description Init Client.
     *
     * @return int - 0 Success, -1 Failed.
     */
    int InitClient(void);
    /**
     * @Description Exit All Client.
     *
     */
    void ExitAllClient(void);
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
     * @Description Get total supported feature, and call user can determine whether
     *              support a feature.
     *
     * @param feature
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetSupportFeature(long &feature);

    /**
     * @Description Send instructions to the Wi-Fi driver or chip.
     *
     * @param request
     * @return WifiErrorNo
     */
    WifiErrorNo SendRequest(const WifiStaRequest &request);

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
    WifiErrorNo Scan(const WifiScanParam &scanParam);

    /**
     * @Description Obtain the scanning result.
     *
     * @param scanResults
     * @return WifiErrorNo
     */
    WifiErrorNo QueryScanResults(std::vector<WifiScanResult> &scanResults);

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
    WifiErrorNo RemoveDeviceConfig(int networkId);

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
     * @Description Get the network.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo GetDeviceConfig(WifiIdlGetDeviceConfig &config);

    /**
     * @Description Setting the network.
     *
     * @param networkId
     * @param config - Setting Network Parameters.
     * @return WifiErrorNo
     */
    WifiErrorNo SetDeviceConfig(int networkId, const WifiIdlDeviceConfig &config);

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

    /* -------------------AP Interface-------------------------- */

    /**
     * @Description Start Ap.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StartAp(void);

    /**
     * @Description Close Ap.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopAp(void);

    /**
     * @Description Setting SoftAP Configurations.
     *
     * @param config
     * @return WifiErrorNo
     */
    WifiErrorNo SetSoftApConfig(const HotspotConfig &config);

    /**
     * @Description Obtains information about all connected STAs.
     *
     * @param result
     * @return WifiErrorNo
     */
    WifiErrorNo GetStationList(std::vector<std::string> &result);

    /**
     * @Description Configuring the Wi-Fi hotspot channel and maximum number of connections.
     *
     * @param channel
     * @param mscb
     * @return WifiErrorNo
     */

    WifiErrorNo SetHotspotConfig(int channel, const std::string &mscb);

    /**
     * @Description To set the blocklist filtering in AP mode to prohibit the MAC
     *              address connection.
     *
     * @param mac - Blocklisted address.
     * @return WifiErrorNo
     */
    WifiErrorNo AddBlockByMac(const std::string &mac);

    /**
     * @Description To set blocklist filtering in AP mode and delete a specified MAC
     *              address from the blocklist.
     *
     * @param mac - Blocklisted address.
     * @return WifiErrorNo
     */
    WifiErrorNo DelBlockByMac(const std::string &mac);

    /**
     * @Description Disconnect the STA with a specified MAC address.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo RemoveStation(const std::string &mac);

    /**
     * @Description Obtains the hotspot frequency supported by a specified frequency band.
     *
     * @param band
     * @param frequencies
     * @return WifiErrorNo
     */
    WifiErrorNo GetFrequenciesByBand(int band, std::vector<int> &frequencies);

    /**
     * @Description Listening to Wi-Fi disconnection or connection events
     *              of the STA in AP mode.
     *
     * @param callback
     * @return WifiErrorNo
     */
    WifiErrorNo RegisterApEvent(IWifiApEventCallback callback);

    /**
     * @Description Sets the Wi-Fi country code.
     *
     * @param code
     * @return WifiErrorNo
     */
    WifiErrorNo SetWifiCountryCode(const std::string &code);

    /**
     * @Description Disconnect the STA connection based on the MAC address.
     *
     * @param mac
     * @return WifiErrorNo
     */
    WifiErrorNo ReqDisconnectStaByMac(const std::string &mac);

    /* ************************** ChipMode interface **************************** */

    /**
     * @Description Obtains the chip object by ID.
     *
     * @param id
     * @param chip
     * @return WifiErrorNo
     */
    WifiErrorNo GetWifiChipObject(int id, IWifiChip &chip);

    /**
     * @Description Obtains the Wi-Fi chip ID set.
     *
     * @param ids
     * @return WifiErrorNo
     */
    WifiErrorNo GetChipIds(std::vector<int> &ids);

    /**
     * @Description Obtains the chip ID.
     *
     * @param id
     * @return WifiErrorNo
     */
    WifiErrorNo GetUsedChipId(int &id);

    /**
     * @Description Obtains chip capabilities.
     *
     * @param capabilities
     * @return WifiErrorNo
     */
    WifiErrorNo GetChipCapabilities(int &capabilities);

    /**
     * @Description Obtains the joint mode supported by the chip, for
     *              example, sta+sta/sta+p2p/sta+ap/sta+nan/ap+nan.
     *
     * @param modes
     * @return WifiErrorNo
     */
    WifiErrorNo GetSupportedModes(std::vector<int> &modes);

    /**
     * @Description Configure the current joint mode of the chip.
     *
     * @param mode
     * @return WifiErrorNo
     */
    WifiErrorNo ConfigRunModes(int mode);

    /**
     * @Description Gets the current federation mode.
     *
     * @param mode
     * @return WifiErrorNo
     */
    WifiErrorNo GetCurrentMode(int &mode);

    /**
     * @Description Registering a Wi-Fi Chip Event.
     *
     * @param callback
     * @return WifiErrorNo
     */
    WifiErrorNo RegisterChipEventCallback(WifiChipEventCallback &callback);

    /**
     * @Description Requesting the debugging information of the firmware chip.
     *
     * @param debugInfo
     * @return WifiErrorNo
     */
    WifiErrorNo RequestFirmwareDebugInfo(std::string &debugInfo);

    /**
     * @Description Setting the Power Mode.
     *
     * @param mode
     * @return WifiErrorNo
     */
    WifiErrorNo SetWifiPowerMode(int mode);

    /**
     * @Description API to set the wifi latency mode.
     *
     * @param mode
     * @return WifiStatus
     */
    WifiStatus ReqSetLatencyMode(int mode);

    /* ******************************* Supplicant interface********************** */

    /**
     * @Description Starting the Supplementary Service.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStartSupplicant(void);

    /**
     * @Description Disabling the Supplementary Service.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStopSupplicant(void);

    /**
     * @Description Connecting to the Supplier.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqConnectSupplicant(void);

    /**
     * @Description Disconnecting the Supply.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqDisconnectSupplicant(void);

    /**
     * @Description Send a request to the supplier.
     *
     * @param request
     * @return WifiErrorNo
     */
    WifiErrorNo ReqRequestToSupplicant(const std::string &request);

    /**
     * @Description Registers the supplementary event callback function.
     *
     * @param callback
     * @return WifiErrorNo
     */
    WifiErrorNo ReqRigisterSupplicantEventCallback(SupplicantEventCallback &callback);

    /**
     * @Description Deregisters the supplementary event callback function.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqUnRigisterSupplicantEventCallback(void);

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
    WifiErrorNo ReqWpaSetCountryCode(const std::string &countCode);

    /**
     * @Description Obtains the country code.
     *
     * @param countCode
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaGetCountryCode(std::string &countCode);

    /**
     * @Description Wpa_s disable/enable(0/1) automatic reconnection.
     *
     * @param enable
     * @return WifiErrorNo
     */
    WifiErrorNo ReqWpaAutoConnect(int enable);

    /**
     * @Description Force wpa_supplicant to re-read its configuration file.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReWpaReconfigure(void);

    /**
     * @Description Clearing the wpa Blocklist.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReWpaBlocklistClear(void);

    /**
     * @Description Obtaining the Network List.
     *
     * @param networkList
     * @return WifiErrorNo
     */
    WifiErrorNo ReGetNetworkList(std::vector<WifiWpaNetworkList> &networkList);

public:
    RpcClient *pRpcClient;

private:
    char **ConVectorToCArrayString(const std::vector<std::string> &vec);
    WifiErrorNo ConvertPnoScanParam(const WifiPnoScanParam &param, PnoScanSettings *pSettings);
    int PushDeviceConfigString(NetWorkConfig *pConfig, DeviceConfigType type, const std::string &msg);
    int PushDeviceConfigInt(NetWorkConfig *pConfig, DeviceConfigType type, int i);
    int PushDeviceConfigAuthAlgorithm(NetWorkConfig *pConfig, DeviceConfigType type, unsigned int alg);
    WifiErrorNo CheckValidDeviceConfig(const WifiIdlDeviceConfig &config);
};
}  // namespace Wifi
}  // namespace OHOS

#endif