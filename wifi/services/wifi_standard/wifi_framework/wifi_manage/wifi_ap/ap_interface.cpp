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
#include "wifi_ap_nat_manager.h"

namespace OHOS {
namespace Wifi {
ApInterface::ApInterface(int id)
    : m_ApRootState(id),
      m_ApStartedState(m_ApStateMachine, m_ApConfigUse, m_ApMonitor, id),
      m_ApIdleState(m_ApStateMachine, id),
      m_ApMonitor(id),
      m_ApStateMachine(m_ApStationsManager, m_ApRootState, m_ApIdleState, m_ApStartedState, m_ApMonitor, id),
      m_ApService(m_ApStateMachine, m_ApStartedState, id),
      m_ApStationsManager(id),
      m_ApConfigUse(id)
{}

ApInterface::~ApInterface()
{}

extern "C" IApService *CreateApInterface(int id)
{
    return new ApInterface(id);
}

extern "C" void DestroyApInterface(IApService *apInterface)
{
    if (apInterface == nullptr) {
        return;
    }
    delete apInterface;
    apInterface = nullptr;
}

ErrCode ApInterface::EnableHotspot()
{
    return m_ApService.EnableHotspot();
}

ErrCode ApInterface::DisableHotspot()
{
    return m_ApService.DisableHotspot();
}

ErrCode ApInterface::AddBlockList(const StationInfo &stationInfo)
{
    return m_ApService.AddBlockList(stationInfo);
}

ErrCode ApInterface::DelBlockList(const StationInfo &stationInfo)
{
    return m_ApService.DelBlockList(stationInfo);
}

ErrCode ApInterface::SetHotspotConfig(const HotspotConfig &hotspotConfig)
{
    return m_ApService.SetHotspotConfig(hotspotConfig);
}

ErrCode ApInterface::SetHotspotIdleTimeout(int time)
{
    return m_ApService.SetHotspotIdleTimeout(time);
}

ErrCode ApInterface::DisconnetStation(const StationInfo &stationInfo)
{
    return m_ApService.DisconnetStation(stationInfo);
}

ErrCode ApInterface::GetStationList(std::vector<StationInfo> &result)
{
    return m_ApService.GetStationList(result);
}

ErrCode ApInterface::GetValidBands(std::vector<BandType> &bands)
{
    return m_ApService.GetValidBands(bands);
}

ErrCode ApInterface::GetValidChannels(BandType band, std::vector<int32_t> &validChannel)
{
    return m_ApService.GetValidChannels(band, validChannel);
}

ErrCode ApInterface::RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks)
{
    return m_ApService.RegisterApServiceCallbacks(callbacks);
}

ErrCode ApInterface::GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList)
{
    return m_ApService.GetSupportedPowerModel(setPowerModelList);
}

ErrCode ApInterface::GetPowerModel(PowerModel& model)
{
    return m_ApService.GetPowerModel(model);
}

ErrCode ApInterface::SetPowerModel(const PowerModel& model)
{
    return m_ApService.SetPowerModel(model);
}

ErrCode ApInterface::GetHotspotMode(HotspotMode &mode)
{
    return m_ApService.GetHotspotMode(mode);
}

ErrCode ApInterface::SetHotspotMode(const HotspotMode &mode)
{
    return m_ApService.SetHotspotMode(mode);
}

void ApInterface::OnNetCapabilitiesChanged(const int apStatus)
{
    m_ApService.HandleNetCapabilitiesChanged(apStatus);
    return;
}

#ifndef OHOS_ARCH_LITE
void ApInterface::SetEnhanceService(IEnhanceService* enhanceService)
{
    m_ApService.SetEnhanceService(enhanceService);
    return; 
}
#endif
}  // namespace Wifi
}  // namespace OHOS