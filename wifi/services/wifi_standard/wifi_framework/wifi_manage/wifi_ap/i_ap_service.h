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
#ifndef OHOS_IAP_SERVICE_H
#define OHOS_IAP_SERVICE_H

#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "i_ap_service_callbacks.h"
#ifndef OHOS_ARCH_LITE
#include "ienhance_service.h"
#endif
namespace OHOS {
namespace Wifi {
class IApService {
public:
    /**
     * @DescriptionDestroy the IApService object.
     *
     */
    virtual ~IApService() = default;
    virtual ErrCode EnableHotspot() = 0;
    virtual ErrCode DisableHotspot() = 0;
    virtual ErrCode AddBlockList(const StationInfo &stationInfo) = 0;
    virtual ErrCode DelBlockList(const StationInfo &stationInfo) = 0;
    virtual ErrCode SetHotspotConfig(const HotspotConfig &hotspotConfig) = 0;
    virtual ErrCode DisconnetStation(const StationInfo &stationInfo) = 0;
    virtual ErrCode GetStationList(std::vector<StationInfo> &result) = 0;
    virtual ErrCode GetValidBands(std::vector<BandType> &bands) = 0;
    virtual ErrCode GetValidChannels(BandType band, std::vector<int32_t> &validChannel) = 0;
    virtual ErrCode GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList) = 0;
    virtual ErrCode GetPowerModel(PowerModel& model) = 0;
    virtual ErrCode SetPowerModel(const PowerModel& model) = 0;
    virtual ErrCode SetHotspotIdleTimeout(int time) = 0;
    virtual void OnNetCapabilitiesChanged(const int apStatus) = 0;
#ifndef OHOS_ARCH_LITE
    virtual void SetEnhanceService(IEnhanceService* enhanceService) = 0;
#endif

    /**
     * @Description - Registers all callbacks provided by the P2P service.
     * @param callbacks - All callbacks
     * @return ErrCode
     */
    virtual ErrCode RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks) = 0;

    /**
     * @Description get hotspot mode
     *
     * @param model - the model to be set
     * @return ErrCode - operation result
     */
    virtual ErrCode GetHotspotMode(HotspotMode &mode);

    /**
     * @Description set hotspot mode
     *
     * @param model - the model to be set
     * @return ErrCode - operation result
     */
    virtual ErrCode SetHotspotMode(const HotspotMode &mode);
};
}  // namespace Wifi
}  // namespace OHOS
#endif
