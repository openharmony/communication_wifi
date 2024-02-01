/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
    bWifiStateBeforeSleep[0] = false;
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
        if (staState == WifiOprMidState::RUNNING) {
            bWifiStateBeforeSleep[idx] = true;
            WifiSettings::GetInstance().SetWifiToggledState(false);
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
        if (bWifiStateBeforeSleep[idx]) {
            WifiSettings::GetInstance().SetWifiToggledState(true);
            ErrCode ret = WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, idx);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("DealPowerExitSleepEvent, AutoStartStaService failed, err_code = %{public}d!", ret);
            } else {
                WIFI_LOGI("DealPowerExitSleepEvent, auto start wifi success!");
            }
            bWifiStateBeforeSleep[idx] = false;
        }
    }
    return;
}
} // namespace Wifi
} // namespace OHOS
