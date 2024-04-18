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
#ifndef OHOS_WIFI_DEVICE_PROXY_H
#define OHOS_WIFI_DEVICE_PROXY_H

#ifdef OHOS_ARCH_LITE
#include "iproxy_client.h"
#include "serializer.h"
#else
#include "iremote_proxy.h"
#endif
#include "i_wifi_device.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class WifiDeviceProxy : public IWifiDevice {
public:
    static WifiDeviceProxy *GetInstance(void);
    static void ReleaseInstance(void);
    explicit WifiDeviceProxy();
    ErrCode Init(void);
#else
class WifiDeviceProxy : public IRemoteProxy<IWifiDevice> {
public:
    explicit WifiDeviceProxy(const sptr<IRemoteObject> &impl);
#endif
    ~WifiDeviceProxy();

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
     * @Description Query application whether or not acquired the Wi-Fi protect.
     *
     * @param protectName - the protect name
     * @param isHoldProtect - out Whether or not acquired the Wi-Fi protect
     * @return ErrCode - operation result
     */
    ErrCode IsHeldWifiProtectRef(const std::string &protectName, bool &isHoldProtect) override;
    /**
     * @Description Remove a specified untrusted hotspot configuration.
     *
     * @param config - WifiDeviceConfig object
     * @return ErrCode - operation result
     */
    ErrCode RemoveCandidateConfig(const WifiDeviceConfig &config) override;

    /**
     * @Description Remove the wifi Untrusted device config equals to input network id
     *
     * @param networkId - the untrusted device network id
     * @return ErrCode - operation result
     */
    ErrCode RemoveCandidateConfig(int networkId) override;

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
     * @Description Delete all device configs.
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
     * @param bool - true: connected, false: not connected
     * @return ErrCode - operation result
     */
    ErrCode IsConnected(bool &isConnected) override;

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
    ErrCode ReAssociate(void) override;

    /**
     * @Description Disconnect
     *
     * @return ErrCode - operation result
     */
    ErrCode Disconnect(void) override;

    /**
     * @Description Enable WPS connection
     *
     * @param config - WpsConfig object
     * @return ErrCode - operation result
     */
    ErrCode StartWps(const WpsConfig &config) override;

    /**
     * @Description Close the WPS connection
     *
     * @return ErrCode - operation result
     */
    ErrCode CancelWps(void) override;

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

    /**
     * @Description Obtains the disconnected reason
     *
     * @param reason - DisconnectedReason object
     * @return ErrCode - operation result
     */
    ErrCode GetDisconnectedReason(DisconnectedReason &reason) override;

    /**
     * @Description Obtaining DHCP Request Information
     *
     * @param info - IpInfo object
     * @return ErrCode - operation result
     */
    ErrCode GetIpInfo(IpInfo &info) override;

    /**
     * @Description Obtaining DHCP IPV6 Request Information
     *
     * @param info - IpV6Info object
     * @return ErrCode - operation result
     */
    ErrCode GetIpv6Info(IpV6Info &info) override;

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
     * @Description  Get the device MAC address
     *
     * @param result - Get device mac String
     * @return ErrCode - operation result
     */
    ErrCode GetDeviceMacAddress(std::string &result) override;

    /**
     * @Description set low latency mode
     *
     * @param enabled - true: enable low latency, false: disable low latency
     * @return bool - operation result
     */
    bool SetLowLatencyMode(bool enabled) override;

    /**
     * @Description Check whether service is died.
     *
     * @return bool - true: service is died, false: service is not died.
     */
    bool IsRemoteDied(void) override;

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
     * @Description start portal certification
     *
     * @return ErrCode - operation result
     */
    ErrCode StartPortalCertification() override;

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

    ErrCode GetChangeDeviceConfig(ConfigChange& value, WifiDeviceConfig &config) override;
    /**
     * @Description reset factory
     *
     * @return ErrCode - operation result
     */
    ErrCode FactoryReset() override;

    /**
     * @Description  limit speed
     *
     * @param controlId 1: game 2: stream 3：temp 4: cellular speed limit
     * @param limitMode speed limit mode, ranges 1 to 9
     * @return WifiErrorNo
     */
    ErrCode LimitSpeed(const int controlId, const int limitMode) override;
	
    /**
     * @Description hilink connect
     *
     * @return ErrCode - hilink connect result
     */
    ErrCode EnableHiLinkHandshake(bool uiFlag, std::string &bssid, WifiDeviceConfig &deviceConfig) override;
#ifdef OHOS_ARCH_LITE
    /**
    * @Description Handle remote object died event.
    */
    void OnRemoteDied(void);
private:
    static WifiDeviceProxy *g_instance;
    IClientProxy *remote_ = nullptr;
    SvcIdentity svcIdentity_ = { 0 };
    bool remoteDied_;
    void WriteIpAddress(IpcIo &req, const WifiIpAddress &address);
    void WriteEapConfig(IpcIo &req, const WifiEapConfig &wifiEapConfig);
    void WriteDeviceConfig(const WifiDeviceConfig &config, IpcIo &req);
#else
private:
    class WifiDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit WifiDeathRecipient(WifiDeviceProxy &client) : client_(client) {}
        ~WifiDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        WifiDeviceProxy &client_;
    };

    /**
    * @Description Handle remote object died event.
    * @param remoteObject remote object.
    */
    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject);
    void WriteIpAddress(MessageParcel &data, const WifiIpAddress &address);
    void WriteEapConfig(MessageParcel &data, const WifiEapConfig &wifiEapConfig);
    void ReadIpAddress(MessageParcel &reply, WifiIpAddress &address);
    void ReadEapConfig(MessageParcel &reply, WifiEapConfig &wifiEapConfig);
    void ReadLinkedInfo(MessageParcel &reply, WifiLinkedInfo &info);
    void WriteDeviceConfig(const WifiDeviceConfig &config, MessageParcel &data);
    void ParseDeviceConfigs(MessageParcel &reply, std::vector<WifiDeviceConfig> &result);
    void RemoveDeathRecipient(void);
    static BrokerDelegator<WifiDeviceProxy> g_delegator;
    sptr<IRemoteObject> remote_ = nullptr;
    bool mRemoteDied;
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
