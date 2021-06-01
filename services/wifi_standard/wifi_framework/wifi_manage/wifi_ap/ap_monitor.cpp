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
#include "ap_monitor.h"
#include <unistd.h>
#include "ap_state_machine.h"
#include "internal_message.h"
#include "log_helper.h"
#include "wifi_log.h"
#include "wifi_settings.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_ApMonitor"
extern "C" void OnStaJoinOrLeave(const CStationInfo *cinfo)
{
    if (cinfo == nullptr) {
        LOGE("fatal error!");
        return;
    }
    OHOS::Wifi::StationInfo info;
    info.bssid = cinfo->mac;
    info.deviceName = OHOS::Wifi::GETTING_INFO;
    info.ipAddr = OHOS::Wifi::GETTING_INFO;
    OHOS::Wifi::ApMonitor::GetInstance().StationChangeEvent(info, cinfo->type);
    return;
}

extern "C" void OnApEnableOrDisable(int state)
{
    OHOS::Wifi::ApMonitor::GetInstance().OnHotspotStateEvent(state);
}

namespace OHOS {
namespace Wifi {
ApMonitor::ApMonitor() : wifiApEventCallback({nullptr, nullptr})
{}

ApMonitor::~ApMonitor()
{
    StopMonitor();
}

ApMonitor &ApMonitor::GetInstance()
{
    static ApMonitor instance_;
    return instance_;
}

void ApMonitor::DeleteInstance()
{}

void ApMonitor::StationChangeEvent(StationInfo &staInfo, const int event) const
{
    LOGI("StationChangeEvent  event: [%{public}d]", event);
    if (event == WIFI_IDL_CBK_CMD_STA_JOIN) {
        ApStateMachine::GetInstance().StationJoin(staInfo);
    }
    if (event == WIFI_IDL_CBK_CMD_STA_LEAVE) {
        ApStateMachine::GetInstance().StationLeave(staInfo);
    }
}

void ApMonitor::OnHotspotStateEvent(int state) const
{
    LOGI("update HotspotConfig result is [%{public}d]\n", state);
    if (state == WIFI_IDL_CBK_CMD_AP_DISABLE) {
        ApStateMachine::GetInstance().UpdateHotspotConfigResult(false);
    } else if (state == WIFI_IDL_CBK_CMD_AP_ENABLE) {
        ApStateMachine::GetInstance().UpdateHotspotConfigResult(true);
    } else {
        LOGE("Error: Incorrect status code [%{public}d]", state);
    }
}

void ApMonitor::StartMonitor()
{
    wifiApEventCallback.onApEnableOrDisable = OnApEnableOrDisable;
    wifiApEventCallback.onStaJoinOrLeave = OnStaJoinOrLeave;

    WifiApDhcpInterface::DhcpCallback callback = [](StationInfo &staInfo) {
        LOGI("name     = [%s]", staInfo.deviceName.c_str());
        LOGI("mac      = [%s]", staInfo.bssid.c_str());
        LOGI("ip       = [%s]", staInfo.ipAddr.c_str());
        ApStateMachine::GetInstance().StationJoin(staInfo);
    };

    WifiApHalInterface::GetInstance().RegisterApEvent(wifiApEventCallback);
    WifiApDhcpInterface::GetInstance().RegisterApCallback(callback);
}

void ApMonitor::StopMonitor()
{
    wifiApEventCallback.onStaJoinOrLeave = NULL;
    wifiApEventCallback.onApEnableOrDisable = NULL;
    WifiApHalInterface::GetInstance().RegisterApEvent(wifiApEventCallback);
    WifiApDhcpInterface::GetInstance().RegisterApCallback(nullptr);
}
}  // namespace Wifi
}  // namespace OHOS