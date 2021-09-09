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
#include "ap_service.h"
#include <unistd.h>
#include "ap_state_machine.h"
#include "log_helper.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("ApService");
namespace OHOS {
namespace Wifi {
ApService &ApService::GetInstance()
{
    static ApService instance_;
    return instance_;
}

void ApService::DeleteInstance()
{}

ApService::ApService()
{}

ApService::~ApService()
{}

ErrCode ApService::EnableHotspot() const
{
    ApStateMachine::GetInstance().SendMessage(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::DisableHotspot() const
{
    ApStateMachine::GetInstance().SendMessage(static_cast<int>(ApStatemachineEvent::CMD_STOP_HOTSPOT));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::SetHotspotConfig(const HotspotConfig &cfg) const
{
    ApStateMachine::GetInstance().SetHotspotConfig(cfg);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::AddBlockList(const StationInfo &stationInfo) const
{
    ApStateMachine::GetInstance().AddBlockList(stationInfo);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::DelBlockList(const StationInfo &stationInfo) const
{
    ApStateMachine::GetInstance().DelBlockList(stationInfo);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::DisconnetStation(const StationInfo &stationInfo) const
{
    ApStateMachine::GetInstance().DisconnetStation(stationInfo);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks)
{
    WIFI_LOGI("RegisterApServiceCallbacks.");
     ApStateMachine::GetInstance().RegisterApServiceCallbacks(callbacks);
    return ErrCode::WIFI_OPT_SUCCESS;
}

}  // namespace Wifi
}  // namespace OHOS