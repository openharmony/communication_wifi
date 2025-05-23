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

#ifndef OHOS_WIFI_HOTSPOT_PROXY_H
#define OHOS_WIFI_HOTSPOT_PROXY_H

#include "iremote_proxy.h"
#include "i_wifi_hotspot.h"
#include "wifi_errcode.h"
#include "wifi_ap_msg.h"

namespace OHOS {
namespace Wifi {
class WifiHotspotProxy : public IRemoteProxy<IWifiHotspot> {
public:
    explicit WifiHotspotProxy(const sptr<IRemoteObject> &impl);

    ~WifiHotspotProxy();

    /**
     * @Description Check whether the hotspot is active.
     *
     * @param isActive - active / inactive
     * @return ErrCode - operation result
     */
    ErrCode IsHotspotActive(bool &isActive) override;

    /**
     * @Description Check whether the hotspot supports dual band.
     *
     * @param isSupported - Supported / NOT Supported
     * @return ErrCode - operation result
     */
    ErrCode IsHotspotDualBandSupported(bool &isSupported) override;

    /**
     * @Description Check whether Wi-Fi hotspot is can be operated under some situation. For example, When the airplane
     * mode is turned on and does not support the coexistence of softap and sta, nor does it support signal bridge,
     * the hotspot switch cannot be operated.
     *
     * @param isSupported - Supported / NOT Supported
     * @return ErrCode - operation result
     */
    ErrCode IsOpenSoftApAllowed(bool &isSupported) override;

    /**
     * @Description Get the Hotspot Config object
     *
     * @param config - HotapotConfig object
     * @return ErrCode - operation result
     */
    ErrCode GetHotspotConfig(HotspotConfig &config) override;

    /**
     * @Description Get the Hotspot State object
     *
     * @param state - current Hotspot state
     * @return ErrCode - operation result
     */
    ErrCode GetHotspotState(int &state) override;

    /**
     * @Description Set the configuration of Hotspot
     *
     * @param config - HotspotConfig object
     * @return ErrCode - operation result
     */
    ErrCode SetHotspotConfig(const HotspotConfig &config) override;

    /**
     * @Description Set the idel timeout of Hotspot
     *
     * @param time -input time,
     * @return ErrCode - operation result
     */
    ErrCode SetHotspotIdleTimeout(int time) override;

    /**
     * @Description Get the Station List object
     *
     * @param result - Get result vector of connect Station Info
     * @return ErrCode - operation result
     */
    ErrCode GetStationList(std::vector<StationInfo> &result) override;

    /**
     * @Description Disconnects a specified sta connection
     *
     * @param info - Station object
     * @return ErrCode - operation result
     */
    ErrCode DisassociateSta(const StationInfo &info) override;

    /**
     * @Description Enable Hotspot
     *
     * @param type - service type
     * @return ErrCode - operation result
     */
    ErrCode EnableHotspot(const ServiceType type = ServiceType::DEFAULT) override;

    /**
     * @Description Disable Hotspot
     *
     * @param type - service type
     * @return ErrCode - operation result
     */
    ErrCode DisableHotspot(const ServiceType type = ServiceType::DEFAULT) override;

    /**
     * @Description Get the Block Lists object
     *
     * @param infos - Get Blocklist result vector of StationInfo
     * @return ErrCode - operation result
     */
    ErrCode GetBlockLists(std::vector<StationInfo> &infos) override;

    /**
     * @Description Add a StationInfo object to Blocklist
     *
     * @param info - Station object
     * @return ErrCode - operation result
     */
    ErrCode AddBlockList(const StationInfo &info) override;

    /**
     * @Description Del a StationInfo object from Blocklist
     *
     * @param info - StationInfo object
     * @return ErrCode - operation result
     */
    ErrCode DelBlockList(const StationInfo &info) override;

    /**
     * @Description Get the Valid Bands object
     *
     * @param bands - Get result vector of BandType
     * @return ErrCode - operation result
     */
    ErrCode GetValidBands(std::vector<BandType> &bands) override;

    /**
     * @Description Get the Valid Channels object
     *
     * @param band - Specified band
     * @param validchannels - Obtains the channels corresponding to the specified band
     * @return ErrCode - operation result
     */
    ErrCode GetValidChannels(BandType band, std::vector<int32_t> &validchannels) override;

    /**
     * @Description Register callback client
     *
     * @param callback - callback struct
     * @return ErrCode - operation result
     */
    ErrCode RegisterCallBack(const sptr<IWifiHotspotCallback> &callback,
        const std::vector<std::string> &event) override;

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedFeatures(long &features) override;

    /**
    * @Description Handle remote object died event.
    * @param remoteObject remote object.
    */
    void OnRemoteDied(const wptr<IRemoteObject>& remoteObject);

    /**
     * @Description Get supported power model list
     *
     * @param setPowerModelList - supported power model list
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList) override;

    /**
     * @Description Get power model
     *
     * @param model - current power model
     * @return ErrCode - operation result
     */
    ErrCode GetPowerModel(PowerModel& model) override;

    /**
     * @Description Get supported power model list
     *
     * @param model - the model to be set
     * @return ErrCode - operation result
     */
    ErrCode SetPowerModel(const PowerModel& model) override;

    /**
     * @Description Check whether service is died.
     *
     * @return bool - true: service is died, false: service is not died.
     */
    bool IsRemoteDied(void) override;

    /**
     * @Description Get ap iface name
     *
     * @param ifaceName - the ifaceName to be set
     * @return ErrCode - operation result
     */
    ErrCode GetApIfaceName(std::string& ifaceName) override;

    /**
     * @Description Enable local only Hotspot
     *
     * @param type - service type
     * @return ErrCode - operation result
     */
    ErrCode EnableLocalOnlyHotspot(const ServiceType type = ServiceType::DEFAULT) override;
 
    /**
     * @Description Disable local only Hotspot
     *
     * @param type - service type
     * @return ErrCode - operation result
     */
    ErrCode DisableLocalOnlyHotspot(const ServiceType type = ServiceType::DEFAULT) override;
 
    /**
     * @Description Get local only Hotspot mode
     *
     * @param mode - hotspot mode
     * @return ErrCode - operation result
     */
    ErrCode GetHotspotMode(HotspotMode &mode) override;
 
    /**
     * @Description Get the LocalOnly Hotspot Config object
     *
     * @param config - LocalOnly HotapotConfig object
     * @return ErrCode - operation result
     */
    ErrCode GetLocalOnlyHotspotConfig(HotspotConfig &config) override;
private:
    class WifiDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit WifiDeathRecipient(WifiHotspotProxy &client) : client_(client) {}
        ~WifiDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        WifiHotspotProxy &client_;
    };

    void RemoveDeathRecipient(void);
    static BrokerDelegator<WifiHotspotProxy> g_delegator;
    std::atomic<bool> mRemoteDied;
    sptr<IRemoteObject> remote_ = nullptr;
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
};
}  // namespace Wifi
}  // namespace OHOS
#endif