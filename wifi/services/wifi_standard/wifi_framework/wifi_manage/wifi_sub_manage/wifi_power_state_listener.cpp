/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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

#include "wifi_power_state_listener.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_manager.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiPowerStateListener");
WifiPowerStateListener &WifiPowerStateListener::GetInstance()
{
    static WifiPowerStateListener gWifiPowerStateListener;
    return gWifiPowerStateListener;
}

WifiPowerStateListener::WifiPowerStateListener()
{
    bWifiStateBeforeSleep[0] = WIFI_STATE_CLOSED;
}

void WifiPowerStateListener::OnSyncSleep(bool onForceSleep)
{
    WIFI_LOGI("Enter OnSyncSleep");
    if (!onForceSleep) {
        WIFI_LOGI("OnSyncSleep not force sleep");
        return;
    }

    DealPowerEnterSleepEvent();
}

void WifiPowerStateListener::OnSyncWakeup(bool onForceSleep)
{
    WIFI_LOGI("Enter OnSyncWakeup");
    if (!onForceSleep) {
        WIFI_LOGI("OnSyncWakeup not force sleep");
        return;
    }

    DealPowerExitSleepEvent();
}

void WifiPowerStateListener::DealPowerEnterSleepEvent()
{
    WIFI_LOGI("DealPowerEnterSleepEvent Enter!");
    WifiConfigCenter::GetInstance().SetPowerSleepState(MODE_STATE_OPEN);

#ifdef FEATURE_AP_SUPPORT
    for (int idx = 0; idx < AP_INSTANCE_MAX_NUM; idx++) {
        WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, idx);
    }
#endif

    for (int idx = 0; idx < STA_INSTANCE_MAX_NUM; idx++) {
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(idx);
        WifiDetailState staDetailState = WifiConfigCenter::GetInstance().GetWifiDetailState(idx);
        if (staState == WifiOprMidState::RUNNING || staDetailState == WifiDetailState::STATE_SEMI_ACTIVE) {
            bWifiStateBeforeSleep[idx] = (staState == WifiOprMidState::RUNNING) ?
                WIFI_STATE_OPENED : WIFI_STATE_SEMI_ACTIVE;
            WifiSettings::GetInstance().SetWifiToggledState(false);
            WifiConfigCenter::GetInstance().SetWifiAllowSemiActive(false);
            WifiSettings::GetInstance().SetSemiWifiEnable(false);
            WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(0, idx);
        }
    }
    return;
}

void WifiPowerStateListener::DealPowerExitSleepEvent()
{
    WIFI_LOGI("DealPowerExitSleepEvent Enter!");
    WifiConfigCenter::GetInstance().SetPowerSleepState(MODE_STATE_CLOSE);

    /* Re-opening is required only if it was previously turned on and then turned off when entering enforce sleep. */
    for (int idx = 0; idx < STA_INSTANCE_MAX_NUM; idx++) {
        if (bWifiStateBeforeSleep[idx] == WIFI_STATE_OPENED) {
            WifiSettings::GetInstance().SetWifiToggledState(true);
            ErrCode ret = WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, idx);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("DealPowerExitSleepEvent, AutoStartStaService failed, err_code = %{public}d!", ret);
            } else {
                WIFI_LOGI("DealPowerExitSleepEvent, auto start wifi success!");
            }
        } else if (bWifiStateBeforeSleep[idx] == WIFI_STATE_SEMI_ACTIVE) {
            WifiSettings::GetInstance().SetWifiToggledState(false);
            WifiSettings::GetInstance().SetSemiWifiEnable(true);
            WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(0, idx);
        }
        bWifiStateBeforeSleep[idx] = WIFI_STATE_CLOSED;
    }
    return;
}
} // namespace Wifi
} // namespace OHOS
