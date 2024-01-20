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
#include "wifi_config_center.h"
#include "wifi_errcode.h"
#include "wifi_hotspot_stub.h"

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
    ErrCode IsHotspotActive(bool &bActive) override;

    /**
     * @Description Check whether the hotspot supports dual band.
     *
     * @param isSpuported - Supported / NOT supported
     * @return ErrCode - operation result
     */
    ErrCode IsHotspotDualBandSupported(bool &isSpuported) override;

    /**
     * @Description Get the Hotspot Config object
     *
     * @param state - Result of obtaining the hotspot status
     * @return ErrCode - operation result
     */
    ErrCode GetHotspotState(int &state) override;

    /**
     * @Description Get the Hotspot State object
     *
     * @param config - Current hotspot configuration
     * @return ErrCode - operation result
     */
    ErrCode GetHotspotConfig(HotspotConfig &config) override;

    /**
     * @Description Set the configuration of Hotspot
     *
     * @param config - HotspotConfig object,
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
     * @Description Disconnects a specified sta connection when ap is opened
     *
     * @param info - StationInfo object
     * @return ErrCode - operation result
     */
    ErrCode DisassociateSta(const StationInfo &info) override;

    /**
     * @Description Enable Hotspot
     *
     * @return ErrCode - operation result
     */
    ErrCode EnableHotspot(const ServiceType type = ServiceType::DEFAULT) override;

    /**
     * @Description Disable Hotspot
     *
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
     * @Description Add a StationInfo object to Blocklist when ap is opened
     *
     * @param info - StationInfo object
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
     * @param bands - Get result vector of BandType when ap is opened
     * @return ErrCode - operation result
     */
    ErrCode GetValidBands(std::vector<BandType> &bands) override;

    /**
     * @Description Get the Valid Channels object when ap is opened
     *
     * @param band - Specified Valid Band.
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
     * @Description Get supported feature
     *
     * @param features - return supported feature
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedFeatures(long &features) override;

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
    bool IsRemoteDied(void) override;

    /**
     * @Description Check valid ssid config
     *
     * @param cfg - HotspotConfig
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckSsid(const HotspotConfig &cfg);

    /**
     * @Description Check valid psk config
     *
     * @param cfg - HotspotConfig
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckPsk(const HotspotConfig &cfg);

    /**
     * @Description Check valid band config
     *
     * @param cfg - HotspotConfig
     * @param bandsFromCenter - vector of BandType
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckBand(const HotspotConfig &cfg, std::vector<BandType> &bandsFromCenter);

    /**
     * @Description Check valid channel config
     *
     * @param cfg - HotspotConfig
     * @param channInfoFromCenter - ChannelsTable object
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode CfgCheckChannel(const HotspotConfig &cfg, ChannelsTable &channInfoFromCenter);

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
     * @param bandsFromCenter - vector of BandType
     * @param channInfoFromCenter - ChannelsTable object
     * @return ErrCode - WIFI_OPT_SUCCESS or others
     */
    ErrCode IsValidHotspotConfig(const HotspotConfig &cfg, const HotspotConfig &cfgFromCenter,
        std::vector<BandType> &bandsFromCenter, ChannelsTable &channInfoFromCenter);

    /**
     * @Description Get ap iface name
     *
     * @param ifaceName - the ifaceName to be set
     * @return ErrCode - operation result
     */
    ErrCode GetApIfaceName(std::string& ifaceName) override;
    /**
     * @Description convert randomMac to realMac
     *
     * @param ifaceName - the ifaceName to be set
     * @return ErrCode - operation result
     */
    ErrCode TransRandomToRealMac(StationInfo &updateInfo, const StationInfo &info);
private:
    ErrCode CheckCanEnableHotspot(const ServiceType type);
    int CheckOperHotspotSwitchPermission(const ServiceType type);
    bool IsApServiceRunning();
    static void ConfigInfoDump(std::string& result);
    static void StationsInfoDump(std::string& result);
    static void SigHandler(int sig);
    static bool IsProcessNeedToRestart();

private:
    bool mGetChannels = false;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
