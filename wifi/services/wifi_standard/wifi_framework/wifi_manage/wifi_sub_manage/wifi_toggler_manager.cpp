/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_toggler_manager.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

DEFINE_WIFILOG_LABEL("WifiTogglerManager")

namespace OHOS {
namespace Wifi {
WifiTogglerManager::WifiTogglerManager()
{
    WIFI_LOGI("create WifiTogglerManager");
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    DelayedSingleton<HalDeviceManager>::GetInstance()->StartChipHdi();
#endif
    InitConcreteCallback();
    InitSoftapCallback();
    pWifiControllerMachine = std::make_unique<WifiControllerMachine>();
    if (pWifiControllerMachine) {
        pWifiControllerMachine->InitWifiControllerMachine();
    }
}

ConcreteModeCallback& WifiTogglerManager::GetConcreteCallback()
{
    return mConcreteModeCb;
}

SoftApModeCallback& WifiTogglerManager::GetSoftApCallback()
{
    return mSoftApModeCb;
}

ErrCode WifiTogglerManager::WifiToggled(int isOpen, int id)
{
    pWifiControllerMachine->ClearWifiStartFailCount();
    pWifiControllerMachine->SendMessage(CMD_WIFI_TOGGLED, isOpen, id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::SoftapToggled(int isOpen, int id)
{
    if (isOpen) {
        WIFI_LOGI("set softap toggled true");
        pWifiControllerMachine->ClearApStartFailCount();
        WifiSettings::GetInstance().SetSoftapToggledState(true);
    } else {
        WIFI_LOGI("set softap toggled false");
        WifiSettings::GetInstance().SetSoftapToggledState(false);
    }
    pWifiControllerMachine->SendMessage(CMD_SOFTAP_TOGGLED, isOpen, id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::ScanOnlyToggled(int isOpen)
{
    int airplanState = WifiConfigCenter::GetInstance().GetAirplaneModeState();
    if (airplanState == MODE_STATE_OPEN) {
        WIFI_LOGE("Airplane mode do not start scanonly.");
        return WIFI_OPT_FAILED;
    }
    pWifiControllerMachine->SendMessage(CMD_SCAN_ALWAYS_MODE_CHANGED, isOpen, 0);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::AirplaneToggled(int isOpen)
{
    pWifiControllerMachine->SendMessage(CMD_AIRPLANE_TOGGLED, isOpen);
    return WIFI_OPT_SUCCESS;
}

bool WifiTogglerManager::HasAnyApRuning()
{
    WifiOprMidState apState0 = WifiConfigCenter::GetInstance().GetApMidState(0);
    WifiOprMidState apState1 = WifiConfigCenter::GetInstance().GetApMidState(1);
    if (apState0 == WifiOprMidState::RUNNING || apState0 == WifiOprMidState::OPENING ||
        apState1 == WifiOprMidState::RUNNING || apState1 == WifiOprMidState::OPENING) {
        return true;
    }
    return false;
}

std::unique_ptr<WifiControllerMachine>& WifiTogglerManager::GetControllerMachine()
{
    return pWifiControllerMachine;
}

void WifiTogglerManager::InitConcreteCallback()
{
    using namespace std::placeholders;
    mConcreteModeCb.onStartFailure = std::bind(&WifiTogglerManager::DealConcreateStartFailure, this, _1);
    mConcreteModeCb.onStopped = std::bind(&WifiTogglerManager::DealConcreateStop, this, _1);
    mConcreteModeCb.onRemoved = std::bind(&WifiTogglerManager::DealClientRemoved, this, _1);
}

void WifiTogglerManager::InitSoftapCallback()
{
    using namespace std::placeholders;
    mSoftApModeCb.onStartFailure = std::bind(&WifiTogglerManager::DealSoftapStartFailure, this, _1);
    mSoftApModeCb.onStopped = std::bind(&WifiTogglerManager::DealSoftapStop, this, _1);
}

void WifiTogglerManager::DealConcreateStop(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_CONCRETE_STOPPED, id);
    }
}

void WifiTogglerManager::DealConcreateStartFailure(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_STA_START_FAILURE, id);
    }
}

void WifiTogglerManager::DealSoftapStop(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_AP_STOPPED, id);
    }
}

void WifiTogglerManager::DealSoftapStartFailure(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_AP_START_FAILURE, id);
    }
}

void WifiTogglerManager::DealClientRemoved(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_CONCRETECLIENT_REMOVED, id);
    }
}

}  // namespace Wifi
}  // namespace OHOS