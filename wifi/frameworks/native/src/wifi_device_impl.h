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
#ifndef OHOS_WIFI_DEVICE_IMPL_H
#define OHOS_WIFI_DEVICE_IMPL_H

#include <string>
#include <vector>
#include "i_wifi_device.h"
#include "i_wifi_device_callback.h"
#include "refbase.h"
#include "wifi_device.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
class WifiDeviceImpl : public WifiDevice {
public:
    WifiDeviceImpl();
    virtual ~WifiDeviceImpl();
    bool Init(int systemAbilityId, int instId);

    /**
     * @Description Turn on Wi-Fi
     *
     * @return ErrCode - operation result
     */
    ErrCode EnableWifi() override;

    /**
     * @Description Turn off Wi-Fi
     *
     * @return ErrCode - operation result
     */
    ErrCode DisableWifi() override;

    /**
     * @Description create the Wi-Fi protect.
     *
     * @param protectType - WifiProtectMode object
     * @param protectName - the protect name
     * @return ErrCode - operation result
     */
    ErrCode InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName) override;

    /**
     * @Description Acquire the Wi-Fi protect mode.
     *
     * @param protectMode - WifiProtectMode object
     * @param protectName - the protect name
     * @return ErrCode - operation result
     */
    ErrCode GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName) override;

    /**
     * @Description Release the Wi-Fi protect mode.
     *
     * @param protectName - the protect name
     * @return ErrCode - operation result
     */
    ErrCode PutWifiProtectRef(const std::string &protectName) override;

    /**
     * @Description Query application whether or not has held the Wi-Fi protect.
     *
     * @param protectName - the protect name
     * @param isHeld - out whether or not has held the Wi-Fi protect
     * @return ErrCode - operation result
     */
    ErrCode IsHeldWifiProtectRef(const std::string &protectName, bool &isHeld) override;

#ifndef OHOS_ARCH_LITE
    ErrCode IsHeldWifiProtect(bool &isHeld) override;
    /**
     * @Description Acquire the Wi-Fi protect mode.
     *
     * @param protectMode - WifiProtectMode object
     * @return ErrCode - operation result
     */
    ErrCode GetWifiProtect(const WifiProtectMode &protectMode) override;

    /**
     * @Description Release the Wi-Fi protect mode.
     *
     * @return ErrCode - operation result
     */
    ErrCode PutWifiProtect() override;
#endif
    /**
     * @Description Remove the wifi candidate device config equals to input network id
     *
     * @param networkId - the candidate device network id
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveCandidateConfig(int networkId) override;

    /**
     * @Description Remove a specified candidate hotspot configuration.
     *
     * @param config - WifiDeviceConfig object
     * @return ErrCode - operation result
     */
    virtual ErrCode RemoveCandidateConfig(const WifiDeviceConfig &config) override;

    /**
     * @Description Add a wifi device configuration.
     *
     * @param config - WifiDeviceConfig object
     * @param result - the device configuration's network id
     * @param isCandidate - Whether is candidate
     * @return ErrCode - operation result
     */
    ErrCode AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate) override;

    /**
     * @Description set tx power for sar
     * @param power - 1001 1002 1003······
     * @return ErrCode - operation result
     */
    ErrCode SetWifiTxPower(int power) override;

    /**
     * @Description Update a wifi device configuration.
     *
     * @param config - WifiDeviceConfig object
     * @param result - the device configuration's network id after updated
     * @return ErrCode - operation result
     */
    ErrCode UpdateDeviceConfig(const WifiDeviceConfig &config, int &result) override;

    /**
     * @Description Remove the wifi device config equals to input network id
     *
     * @param networkId - want to remove device config's network id
     * @return ErrCode - operation result
     */
    ErrCode RemoveDevice(int networkId) override;

    /**
     * @Description Remove all device configs.
     *
     * @return ErrCode - operation result
     */
    ErrCode RemoveAllDevice() override;

    /**
     * @Description Get all the device configs
     *
     * @param result - Get result vector of WifiDeviceConfig
     * @param isCandidate - Whether is candidate
     * @return ErrCode - operation result
     */
    ErrCode GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate) override;

    /**
     * @Description Connecting to a Specified Network
     *
     * @param networkId - network id
     * @param isCandidate - Whether is candidate
     * @return ErrCode - operation result
     */
    ErrCode ConnectToNetwork(int networkId, bool isCandidate) override;

    /**
     * @Description Connect To a network base WifiDeviceConfig object
     *
     * @param config - WifiDeviceConfig object
     * @return ErrCode - operation result
     */
    ErrCode ConnectToDevice(const WifiDeviceConfig &config) override;

    /**
     * @Description Check whether Wi-Fi is connected.
     *
     * @param isConnected - true: connected, false: not connected
     * @return ErrCode - operation result
     */
    ErrCode IsConnected(bool &isConnected) override;

    /**
     * @Description Disconnect
     *
     * @return ErrCode - operation result
     */
    ErrCode Disconnect(void) override;

    /**
     * @Description Check whether Wi-Fi is active
     *
     * @param bActive - active / inactive
     * @return ErrCode - operation result
     */
    ErrCode IsWifiActive(bool &bActive) override;

    /**
     * @Description Check whether Wi-Fi is metered hotspot
     *
     * @param bMeteredHotspot - isMeteredHotspot / notMeteredHotspot
     * @return ErrCode - operation result
     */
    ErrCode IsMeteredHotspot(bool &bMeteredHotspot) override;
    /**
     * @Description Get the Wifi State
     *
     * @param state - return current wifi state
     * @return ErrCode - operation result
     */
    ErrCode GetWifiState(int &state) override;

    /**
     * @Description Obtains the current Wi-Fi connection information
     *
     * @param info - WifiLinkedInfo object
     * @return ErrCode - operation result
     */
    ErrCode GetLinkedInfo(WifiLinkedInfo &info) override;

    ErrCode GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length) override;

    /**
     * @Description Obtains the disconnected reason information
     *
     * @param reason - DisconnectedReason object
     * @return ErrCode - operation result
     */
    ErrCode GetDisconnectedReason(DisconnectedReason &reason) override;

    /**
     * @Description Set the Country Code
     *
     * @param countryCode - country code
     * @return ErrCode - operation result
     */
    ErrCode SetCountryCode(const std::string &countryCode) override;

    /**
     * @Description Obtains the country code
     *
     * @param countryCode - output the country code
     * @return ErrCode - operation result
     */
    ErrCode GetCountryCode(std::string &countryCode) override;

    /**
     * @Description Register callback function.
     *
     * @param callback - IWifiDeviceCallBack object
     * @return ErrCode - operation result
     */
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback,
        const std::vector<std::string> &event) override;
#else
    ErrCode RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback, const std::vector<std::string> &event) override;
#endif

    /**
     * @Description Get the Signal Level object
     *
     * @param rssi - rssi
     * @param band - band
     * @param level - return the level
     * @return ErrCode - operation result
     */
    ErrCode GetSignalLevel(const int &rssi, const int &band, int &level) override;

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedFeatures(long &features) override;

    /**
     * @Description Check if supported input feature
     *
     * @param feature - input feature
     * @param isSupported - return true if supported, false if unsupported
     * @return ErrCode - operation result
     */
    ErrCode IsFeatureSupported(long feature, bool &isSupported) override;

    /**
     * @Description Enable device config, when set attemptEnable, disable other device config
     *
     * @param networkId - need enable device config's network id
     * @param attemptEnable - if set true, disable other device config
     * @return ErrCode - operation result
     */
    ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) override;

    /**
     * @Description Disable Wi-Fi device configuration.
     *
     * @param networkId - device config's network id
     * @return ErrCode - operation result
     */
    ErrCode DisableDeviceConfig(int networkId) override;

    /**
     * @Description Set whether to allow automatic connect by networkid.
     *
     * @param networkId - Identifies the network to be set. The value of networkId cannot be less thann 0.
     * @param isAllowed - Identifies whether allow auto connect or not.
     * @return ErrCode - operation result
     */
    ErrCode AllowAutoConnect(int32_t networkId, bool isAllowed) override;

    /**
     * @Description Obtaining ip Request Information
     *
     * @param info - IpInfo object
     * @return ErrCode - operation result
     */
    ErrCode GetIpInfo(IpInfo &info) override;

    /**
     * @Description Obtaining ipV6 Request Information
     *
     * @param info - IpInfo object
     * @return ErrCode - operation result
     */
    ErrCode GetIpv6Info(IpV6Info &info) override;

    /**
     * @Description Reconnect to the currently active network
     *
     * @return ErrCode - operation result
     */
    ErrCode ReConnect() override;

    /**
     * @Description ReAssociate network
     *
     * @return ErrCode - operation result
     */
    ErrCode ReAssociate() override;

    /**
     * @Description Enable WPS connection
     *
     * @param config - WpsConfig object
     * @return ErrCode - operation result
     */
    ErrCode StartWps(const WpsConfig &config);

    /**
     * @Description Close the WPS connection
     *
     * @return ErrCode - operation result
     */
    ErrCode CancelWps(void);

    /**
     * @Description  Get the device MAC address.
     *
     * @param result - Get device mac String
     * @return ErrCode - operation result
     */
    ErrCode GetDeviceMacAddress(std::string &result) override;

    /**
     * @Description check wifi-band type is supported
     *
     * @param bandType - wifi band type
     * @param supported - supported / unsupported
     * @return ErrCode - operation result
     */
    ErrCode IsBandTypeSupported(int bandType, bool &supported) override;

    /**
     * @Description get all 5g channellist
     *
     * @param result - get result vector of int
     * @return ErrCode - operation result
     */
    ErrCode Get5GHzChannelList(std::vector<int> &result) override;

    /**
     * @Description start portal certification
     *
     * @return ErrCode - operation result
     */
    ErrCode StartPortalCertification() override;

    /**
     * @Description set low latency mode
     *
     * @param enabled - true: enable low latency, false: disable low latency
     * @return bool - operation result
     */
    bool SetLowLatencyMode(bool enabled) override;

    /**
     * @Description set frozen app
     *
     * @param pidList - pids of frozen app
     * @param isFrozen - is app frozen
     * @return ErrCode - operation result
     */
    ErrCode SetAppFrozen(std::set<int> pidList, bool isFrozen) override;

    /**
     * @Description reset all frozen app
     *
     * @return ErrCode - operation result
     */
    ErrCode ResetAllFrozenApp() override;

    /**
     * @Description  disable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    ErrCode DisableAutoJoin(const std::string &conditionName) override;

    /**
     * @Description  enable auto join.
     *
     * @param conditionName autoJoinDisabled condition.
     * @return WifiErrorNo
     */
    ErrCode EnableAutoJoin(const std::string &conditionName) override;

    /**
     * @Description  register auto join condition.
     *
     * @param conditionName the name of condition.
     * @param autoJoinCondition condition.
     * @return WifiErrorNo
     */
    ErrCode RegisterAutoJoinCondition(const std::string &conditionName,
                                      const std::function<bool()> &autoJoinCondition) override;

    /**
     * @Description  deregister auto join condition.
     *
     * @param conditionName the name of condition.
     * @return WifiErrorNo
     */
    ErrCode DeregisterAutoJoinCondition(const std::string &conditionName) override;

    /**
     * @Description  register external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @param filterBuilder filter builder.
     * @return WifiErrorNo
     */
    ErrCode RegisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName,
                                  const FilterBuilder &filterBuilder) override;

    /**
     * @Description  deregister external filter builder.
     *
     * @param filterTag filterTag which define where the filter should be inserted.
     * @param filterName the name of the filter to build.
     * @return WifiErrorNo
     */
    ErrCode DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName) override;

    /**
     * Register the common builder function
     *
     * @param TagType scoreTag which define where the score or filter should be inserted.
     * @param tagName the score or filter name.
     * @param CommonBuilder CommonBuilder function.
     */
    ErrCode RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                               const CommonBuilder &commonBuilder) override;
    /**
     * Deregister the common builder function
     *
     * @param TagType TagType which define where the score or filter should be inserted.
     * @param tagName the score or filte name.
     */
    ErrCode DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName) override;
 
    /**
     * @Description Check whether service is died.
     *
     * @return bool - true: service is died, false: service is not died.
     */
    bool IsRemoteDied(void);

    /**
     * @Description get last Change devicecConfig
     *
     * @return ErrCode - operation result
     */
    ErrCode GetChangeDeviceConfig(ConfigChange &value, WifiDeviceConfig &config) override;

    /**
     * @Description reset factiry
     *
     * @return ErrCode - operation result
     */
    ErrCode FactoryReset() override;

    /**
     * @Description Accept network control information from RSS.
     *
     * @param networkControlInfo - structure of network control infomation
     * @return ErrCode - operation result
     */
    ErrCode ReceiveNetworkControlInfo(const WifiNetworkControlInfo& networkControlInfo) override;

    /**
     * @Description  limit speed
     *
     * @param controlId 1: game 2: stream 3：temp 4: cellular speed limit
     * @param limitMode speed limit mode, ranges 1 to 9
     * @return WifiErrorNo
     */
    ErrCode LimitSpeed(const int controlId, const int limitMode) override;

    /**
     * @Description set low tx power
     *
     * @return ErrCode - operation result
     */
    ErrCode SetLowTxPower(const WifiLowPowerParam wifiLowPowerParam) override;

    /**
     * @Description hilink connect
     *
     * @return ErrCode - hilink connect result
     */
    ErrCode EnableHiLinkHandshake(bool uiFlag, std::string &bssid, WifiDeviceConfig &deviceConfig) override;

    /**
     * @Description Enable semi-Wifi
     *
     * @return ErrCode - operation result
     */
    ErrCode EnableSemiWifi() override;

    /**
     * @Description Obtains the wifi detail state
     *
     * @param state - WifiDetailState object
     * @return ErrCode - operation result
     */
    ErrCode GetWifiDetailState(WifiDetailState &state) override;

    /**
     * @Description set satellite state
     * @param state 3009:satellite start 3010:satellite stop 3011:satellite check
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode SetSatelliteState(const int state) override;

    /**
     * @Description roam to target bssid
     *
     * @param networkId - target networkId
     * @param bssid - target bssid
     * @param isCandidate - Whether is candidate
     * @return ErrCode - operation result
     */
    ErrCode StartRoamToNetwork(const int networkId, const std::string bssid, const bool isCandidate) override;

    /**
     * @Description connect to user select ssid and bssid network
     *
     * @param networkId - target networkId
     * @param bssid - target bssid
     * @param isCandidate - Whether is candidate
     * @return ErrCode - operation result
     */
    ErrCode StartConnectToUserSelectNetwork(int networkId, std::string bssid, bool isCandidate) override;

    /**
     * @Description Get single device config
     *
     * @param networkId - the network id of the device config
     * @param config - Get result vector of WifiDeviceConfig
     * @return ErrCode - operation result
     */
    ErrCode GetDeviceConfig(const int &networkId, WifiDeviceConfig &config) override;

    /**
     * @Description set data packet identification mark rule
     *
     * @param uid - target app uid
     * @param protocol - target protocol type
     * @param enable - enable/disable dpi mark
     */
    ErrCode SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable) override;

    /**
     * @Description Update Network Lag Info
     *
     * @param networkLagType - recv networkLagType
     * @param networkLagInfo - recv networkLagInfo
     * @return ErrCode - operation result
     */
    ErrCode UpdateNetworkLagInfo(const NetworkLagType networkLagType, const NetworkLagInfo &networkLagInfo) override;

    /**
     * @Description Get Vowifi Signal Info.
     *
     * @return VoWifiSignalInfo : wifi signal info
     */
    ErrCode FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo) override;
 
    /**
     * @Description Check Is Support VoWifi Detect.
     *
     * @return bool - supported: true, unsupported: false.
     */
    ErrCode IsSupportVoWifiDetect(bool &isSupported) override;
 
    /**
     * @Description set VoWifi detect mode.
     *
     * @param info WifiDetectConfInfo
     */
    ErrCode SetVoWifiDetectMode(WifiDetectConfInfo info) override;
 
    /**
     * indicate VoWifiDetectMode
     *
     * @return VoWifiDetectMode
     */
    ErrCode GetVoWifiDetectMode(WifiDetectConfInfo &info) override;
 
    /**
     * @Description set vowifi detect period.
     *
     * @param period period of vowifi detect
     */
    ErrCode SetVoWifiDetectPeriod(int period) override;
 
    /**
     * @Description Get vowifi detection period
     *
     * @return vowifi detection period
     */
    ErrCode GetVoWifiDetectPeriod(int &period) override;

    /**
     * @Description Obtains the MLO Wi-Fi connection information
     *
     * @param multiLinkedInfo - Wifi MLO Linked Info
     * @return ErrCode - operation result
     */
    ErrCode GetMultiLinkedInfo(std::vector<WifiLinkedInfo> &multiLinkedInfo) override;

private:
    bool GetWifiDeviceProxy();
    std::atomic<int> systemAbilityId_;
    int instId_;
    std::mutex mutex_;
#ifdef OHOS_ARCH_LITE
    IWifiDevice *client_;
#else
    sptr<IWifiDevice> client_;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
