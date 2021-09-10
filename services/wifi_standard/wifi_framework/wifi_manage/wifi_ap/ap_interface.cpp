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
#include "ap_interface.h"
#include "ap_config_use.h"
#include "ap_monitor.h"
#include "ap_service.h"
#include "ap_state_machine.h"
#include "wifi_ap_nat_manager.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
ApInterface::ApInterface()
{
    ApService::GetInstance();
    ApMonitor::GetInstance();
    ApStateMachine::GetInstance();
    WifiApDhcpInterface::GetInstance();
    WifiApNatManager::GetInstance();
    ApConfigUse::GetInstance();
}

ApInterface::~ApInterface()
{
    ApConfigUse::DeleteInstance();
    WifiApNatManager::DeleteInstance();
    WifiApDhcpInterface::DeleteInstance();
    ApStateMachine::DeleteInstance();
    ApMonitor::DeleteInstance();
    ApService::DeleteInstance();
}

extern "C" IApService *Create(void)
{
    return new ApInterface();
}

extern "C" void Destroy(IApService *pservice)
{
    delete pservice;
}
ErrCode ApInterface::EnableHotspot()
{
    return ApService::GetInstance().EnableHotspot();
}

ErrCode ApInterface::DisableHotspot()
{
    return ApService::GetInstance().DisableHotspot();
}

ErrCode ApInterface::AddBlockList(const StationInfo &stationInfo)
{
    return ApService::GetInstance().AddBlockList(stationInfo);
}

ErrCode ApInterface::DelBlockList(const StationInfo &stationInfo)
{
    return ApService::GetInstance().DelBlockList(stationInfo);
}

ErrCode ApInterface::SetHotspotConfig(const HotspotConfig &hotspotConfig)
{
    return ApService::GetInstance().SetHotspotConfig(hotspotConfig);
}

ErrCode ApInterface::DisconnetStation(const StationInfo &stationInfo)
{
    return ApService::GetInstance().DisconnetStation(stationInfo);
}

ErrCode ApInterface::GetStationList(std::vector<StationInfo> &result)
{
    return ErrCode::WIFI_OPT_FAILED;
}

ErrCode ApInterface::GetValidBands(std::vector<BandType> &bands)
{
    return ErrCode::WIFI_OPT_FAILED;
}

ErrCode ApInterface::GetValidChannels(BandType band, std::vector<int32_t> &validchannel)
{
    return ErrCode::WIFI_OPT_FAILED;
}

ErrCode ApInterface::RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks)
{
    return ApService::GetInstance().RegisterApServiceCallbacks(callbacks);
}
}  // namespace Wifi
}  // namespace OHOS