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
#ifndef OHOS_MOCK_AP_INTERFACE_H
#define OHOS_MOCK_AP_INTERFACE_H
#include "wifi_errcode.h"
#include "station_info.h"
#include "wifi_ap_msg.h"
#include "i_ap_service_callbacks.h"
namespace OHOS {
namespace Wifi {
class ApInterface {
public:
    explicit ApInterface(int id = 0);
    ~ApInterface();

public:
    virtual ErrCode EnableHotspot();
    virtual ErrCode DisableHotspot();
    virtual ErrCode AddBlockList(const StationInfo &stationInfo);
    virtual ErrCode DelBlockList(const StationInfo &stationInfo);
    virtual ErrCode SetHotspotConfig(const HotspotConfig &hotspotConfig);
    virtual ErrCode SetHotspotIdleTimeout(int time);
    virtual ErrCode DisconnetStation(const StationInfo &stationInfo);
    virtual ErrCode GetStationList(std::vector<StationInfo> &result);
    virtual ErrCode RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks);
    virtual ErrCode GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList);
    virtual ErrCode GetPowerModel(PowerModel& model);
    virtual ErrCode SetPowerModel(const PowerModel& model);
};
}  // namespace Wifi
}  // namespace OHOS

#endif
