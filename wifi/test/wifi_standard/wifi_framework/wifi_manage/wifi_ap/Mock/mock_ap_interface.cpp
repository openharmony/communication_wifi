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
#include "mock_ap_interface.h"

namespace OHOS {
namespace Wifi {
ApInterface::ApInterface(int id)
{}

ApInterface::~ApInterface()
{}

ErrCode ApInterface::EnableHotspot()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::DisableHotspot()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::AddBlockList(const StationInfo &stationInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::DelBlockList(const StationInfo &stationInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::SetHotspotConfig(const HotspotConfig &hotspotConfig)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::SetHotspotIdleTimeout(int time)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::DisconnetStation(const StationInfo &stationInfo)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::GetStationList(std::vector<StationInfo> &result)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::GetPowerModel(PowerModel& model)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ApInterface::SetPowerModel(const PowerModel& model)
{
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS