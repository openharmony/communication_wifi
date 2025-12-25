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

#ifndef OHOS_WIFI_HOTSPOT_SERVICE_IMPL_H
#define OHOS_WIFI_HOTSPOT_SERVICE_IMPL_H

#include "wifi_ap_msg.h"
#include "wifi_hotspot_stub.h"
#include "wifi_config_center.h"
#include "wifi_hotspot_death_recipient.h"

namespace OHOS {
namespace Wifi {
constexpr int MAX_IPV4_SPLIT_LEN = 4;
constexpr int MAX_IPV4_VALUE = 255;
class WifiHotspotServiceImpl : public WifiHotspotStub {
public:
    WifiHotspotServiceImpl();
    explicit WifiHotspotServiceImpl(int id);
    virtual ~WifiHotspotServiceImpl();
    /**
     * @Description Check whether the hotspot is active.
     * 
     * @param bActive - hotspot state
     * @return ErrCode - operation result
     */
    int32_t IsHotspotActive(bool &bActive) override;

    /**
     * @Description Check whether the hotspot supports dual band.
     *
     * @param isSpuported - Supported / NOT supported
     * @return ErrCode - operation result
     */
    int32_t IsHotspotDualBandSupported(bool &isSpuported) override;

    /**
     * @Description Check whether Wi-Fi hotspot is can be operated under some situation.
     * Prerequisites: Flight mode must be turned on
     * If flight mode is turned off, there is no need to call this interface,
     * and can directly enable the personal hotspot.
     *
     * @param isSpuported - Supported / NOT supported
     * @return ErrCode - operation result
     */
    int32_t IsOpenSoftApAllowed(bool &isSpuported) override;

    /**
     * @Description Get the Hotspot Config object
     *
     * @param state - Result of obtaining the hotspot status
     * @return ErrCode - operation result
     */
    int32_t GetHotspotState(int &state) override;

    /**
     * @Description Get the Hotspot State object
     *
     * @param config - Current hotspot configuration
     * @return ErrCode - operation result
     */
    int32_t GetHotspotConfig(HotspotConfigParcel &parcelconfig) override;

    /**
     * @Description Set the configuration of Hotspot
     *
     * @param config - HotspotConfigParcel object,
     * @return ErrCode - operation result
     */
    int32_t SetHotspotConfig(const HotspotConfigParcel &config) override;

    /**
     * @Description Get the LocalOnly Hotspot State object
     *
     * @param config - Current LocalOnly hotspot configuration
     * @return ErrCode - operation result
     */
    int32_t GetLocalOnlyHotspotConfig(HotspotConfigParcel &config) override;

    /**
     * @Description Set the idel timeout of Hotspot
     *
     * @param time -input time,
     * @return ErrCode - operation result
     */
    int32_t SetHotspotIdleTimeout(int time) override;

    /**
     * @Description Get the Station List object
     *
     * @param result - Get result vector of connect Station Info
     * @return ErrCode - operation result
     */
    int32_t GetStationList(std::vector<StationInfoParcel> &result) override;

    /**
     * @Description Disconnects a specified sta connection when ap is opened
     *
     * @param info - StationInfoParcel object
     * @return ErrCode - operation result
     */
    int32_t DisassociateSta(const StationInfoParcel &info) override;

    /**
     * @Description Enable Hotspot
     *
     * @return ErrCode - operation result
     */
    int32_t EnableHotspot(ServiceTypeParcel type = ServiceTypeParcel::DEFAULT) override;

    /**
     * @Description Disable Hotspot
     *
     * @return ErrCode - operation result
     */
    int32_t DisableHotspot(ServiceTypeParcel type = ServiceTypeParcel::DEFAULT) override;

    /**
     * @Description Enable local only Hotspot
     *
     * @param type - service type
     * @return ErrCode - operation result
     */
    int32_t EnableLocalOnlyHotspot(const ServiceTypeParcel type = ServiceTypeParcel::DEFAULT) override;
 
    /**
     * @Description Disable local only Hotspot
     *
     * @param type - service type
     * @return ErrCode - operation result
     */
    int32_t DisableLocalOnlyHotspot(const ServiceTypeParcel type = ServiceTypeParcel::DEFAULT) override;
 
    /**
     * @Description Get local only Hotspot mode
     *
     * @param mode - hotspot mode
     * @return ErrCode - operation result
     */
    int32_t GetHotspotMode(HotspotModeParcel &mode) override;

    /**
     * @Description Get the Block Lists object
     *
     * @param infos - Get Blocklist result vector of StationInfoParcel
     * @return ErrCode - operation result
     */
    int32_t GetBlockLists(std::vector<StationInfoParcel> &infos) override;

    /**
     * @Description Add a StationInfoParcel object to Blocklist when ap is opened
     *
     * @param info - StationInfoParcel object
     * @return ErrCode - operation result
     */
    int32_t AddBlockList(const StationInfoParcel &info) override;

    /**
     * @Description Del a StationInfoParcel object from Blocklist
     *
     * @param info - StationInfoParcel object
     * @return ErrCode - operation result
     */
    int32_t DelBlockList(const StationInfoParcel &info) override;

    /**
     * @Description Get the Valid Bands object
     *
     * @param bands - Get result vector of BandTypeParcel when ap is opened
     * @return ErrCode - operation result
     */
    int32_t GetValidBands(std::vector<BandTypeParcel> &bands) override;

    /**
     * @Description Get the Valid Channels object when ap is opened
     *
     * @param band - Specified Valid Band.
     * @param validchannels - Obtains the channels corresponding to the specified band
     * @return ErrCode - operation result
     */
    int32_t GetValidChannels(BandTypeParcel band, std::vector<int32_t> &validchannels) override;

    /**
     * @Description Register callback client
     *
     * @param callback - callback struct
     * @return int32_t - operation result
     */
    int32_t RegisterCallBack(const sptr<IRemoteObject> &cbParcel, const std::vector<std::string> &event) override;

    /**
     * @Description Get supported feature
     *
     * @param features - return supported feature
     * @return int32_t - operation result
     */
    int32_t GetSupportedFeatures(int64_t &features) override;

    /**
     * @Description Get supported power model list
     *
     * @param setPowerModelList - supported power model list
     * @return int32_t - operation result
     */
    int32_t GetSupportedPowerModel(std::set<PowerModelParcel>& setPowerModelList) override;

    /**
     * @Description Get power model
     *
     * @param model - current power model
     * @return int32_t - operation result
     */
    int32_t GetPowerModel(PowerModelParcel &model) override;

    /**
     * @Description Get supported power model list
     *
     * @param model - the model to be set
     * @return int32_t - operation result
     */
    int32_t SetPowerModel(PowerModelParcel model) override;

    /**
     * @Description Dump sa basic information
     *
     * @param result[out] - dump result
     */
    static void SaBasicDump(std::string& result);

    /**
     * @Description Check whether service is died.
     *
     * @return bool - true: service is died, false: service is not died.
     */
    bool IsRemoteDied(void);

    /**
     * @Description Check valid ssid config
     *
     * @param cfg - HotspotConfigParcel
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckSsid(const HotspotConfig &cfg);

    /**
     * @Description Check valid psk config
     *
     * @param cfg - HotspotConfigParcel
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckPsk(const HotspotConfig &cfg);

    /**
     * @Description Check valid band config
     *
     * @param cfg - HotspotConfig
     * @param bandsFromCenter - vector of BandTypeParcel
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckBand(const HotspotConfig &cfg, std::vector<BandType> &bandsFromCenter);

    /**
     * @Description Check dhcp server ip address
     *
     * @param ipAddress - string
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckIpAddress(const std::string &ipAddress);

    /**
     * @Description Check valid hotspot config
     *
     * @param cfg - HotspotConfig
     * @param cfgFromCenter - Get HotspotConfig from config center
     * @param bandsFromCenter - vector of BandTypeParcel
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode IsValidHotspotConfig(const HotspotConfig &cfg, const HotspotConfig &cfgFromCenter,
        std::vector<BandType> &bandsFromCenter);

    /**
     * @Description Get ap iface name
     *
     * @param ifaceName - the ifaceName to be set
     * @return int32_t - operation result
     */
    int32_t GetApIfaceName(std::string &ifaceName) override;
    /**
     * @Description convert randomMac to realMac
     *
     * @param ifaceName - the ifaceName to be set
     * @return ErrCode - operation result
     */
    ErrCode TransRandomToRealMac(StationInfo &updateInfo, const StationInfo &info);
    static int32_t HandleHotspotIdlRet(ErrCode originRet);
    static ErrCode OnBackup(MessageParcel& data, MessageParcel& reply);
    static ErrCode OnRestore(MessageParcel& data, MessageParcel& reply);
private:
    ErrCode CheckCanEnableHotspot(const ServiceType type);
    ErrCode VerifyGetStationListPermission();
    int CheckOperHotspotSwitchPermission(const ServiceType type);
    bool IsApServiceRunning();
    bool IsRptRunning();
    static void ConfigInfoDump(std::string& result);
    static void StationsInfoDump(std::string& result);
    ErrCode VerifyConfigValidity(const HotspotConfig &config);
    ErrCode RegisterCallBack(const sptr<IWifiHotspotCallback> &callback, const std::vector<std::string> &event);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    void ProcessMacAddressRandomization(std::vector<StationInfo> &infos);
#endif
    int m_id;
    bool mSingleCallback;
    std::mutex deathRecipientMutex;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
