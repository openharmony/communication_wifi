/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include "mock_wifi_toggler_manager.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("MockWifiTogglerManager");

namespace OHOS {
namespace Wifi {
WifiTogglerManager::WifiTogglerManager()
{
    WIFI_LOGI("create WifiTogglerManager");
    InitConcreteCallback();
    InitSoftapCallback();
    InitMultiStacallback();
    InitRptCallback();
    pWifiControllerMachine = std::make_unique<WifiControllerMachine>();
}

ConcreteModeCallback& WifiTogglerManager::GetConcreteCallback()
{
    return mConcreteModeCb;
}

SoftApModeCallback& WifiTogglerManager::GetSoftApCallback()
{
    return mSoftApModeCb;
}

MultiStaModeCallback& WifiTogglerManager::GetMultiStaCallback()
{
    return mMultiStaModeCb;
}

RptModeCallback& WifiTogglerManager::GetRptCallback()
{
    return mRptModeCb;
}

ErrCode WifiTogglerManager::WifiToggled(int isOpen, int id)
{
    return WIFI_OPT_SUCCESS;
}

void WifiTogglerManager::StartWifiToggledTimer()
{
    WIFI_LOGI("StartWifiToggledTimer");
    return;
}

void WifiTogglerManager::StopWifiToggledTimer()
{
    WIFI_LOGI("StopWifiToggledTimer");
    return;
}

void WifiTogglerManager::OnWifiToggledTimeOut()
{
    return;
}

void WifiTogglerManager::StartSemiWifiToggledTimer()
{
    WIFI_LOGI("StartSemiWifiToggledTimer");
    return;
}

void WifiTogglerManager::StopSemiWifiToggledTimer()
{
    WIFI_LOGI("StopSemiWifiToggledTimer");
    return;
}

void WifiTogglerManager::OnSemiWifiToggledTimeOut()
{
    return;
}

ErrCode WifiTogglerManager::SoftapToggled(int isOpen, int id)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::ScanOnlyToggled(int isOpen)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::AirplaneToggled(int isOpen)
{
    return WIFI_OPT_SUCCESS;
}

bool WifiTogglerManager::HasAnyApRuning()
{
    return false;
}

std::unique_ptr<WifiControllerMachine>& WifiTogglerManager::GetControllerMachine()
{
    return pWifiControllerMachine;
}

void WifiTogglerManager::InitConcreteCallback()
{
    mConcreteModeCb.onStartFailure = [this](int id) { this->DealConcreateStartFailure(id); };
    mConcreteModeCb.onStopped = [this](int id) { this->DealConcreateStop(id); };
    mConcreteModeCb.onRemoved = [this](int id) { this->DealClientRemoved(id); };
}

void WifiTogglerManager::InitSoftapCallback()
{
    mSoftApModeCb.onStartFailure = [this](int id) { this->DealSoftapStartFailure(id); };
    mSoftApModeCb.onStopped =  [this](int id) { this->DealSoftapStop(id); };
}

void WifiTogglerManager::InitMultiStacallback()
{
    using namespace std::placeholders;
    mMultiStaModeCb.onStartFailure = std::bind(&WifiTogglerManager::DealMultiStaStartFailure, this, _1);
    mMultiStaModeCb.onStopped = std::bind(&WifiTogglerManager::DealMultiStaStop, this, _1);
}

void WifiTogglerManager::InitRptCallback()
{
    using namespace std::placeholders;
    mRptModeCb.onStartFailure = std::bind(&WifiTogglerManager::DealRptStartFailure, this, _1);
    mRptModeCb.onStopped = std::bind(&WifiTogglerManager::DealRptStop, this, _1);
}

void WifiTogglerManager::DealConcreateStop(int id)
{
    return;
}

void WifiTogglerManager::DealConcreateStartFailure(int id)
{
    return;
}

void WifiTogglerManager::DealSoftapStop(int id)
{
    return;
}

void WifiTogglerManager::DealSoftapStartFailure(int id)
{
    return;
}

void WifiTogglerManager::DealRptStop(int id)
{
    return;
}

void WifiTogglerManager::DealRptStartFailure(int id)
{
    return;
}

void WifiTogglerManager::DealClientRemoved(int id)
{
    return;
}

void WifiTogglerManager::DealMultiStaStartFailure(int id)
{
    return;
}

void WifiTogglerManager::DealMultiStaStop(int id)
{
    return;
}

void WifiTogglerManager::ForceStopWifi()
{
    return;
}

ErrCode WifiTogglerManager::SatelliteToggled(int state)
{
    return WIFI_OPT_SUCCESS;
}

void WifiTogglerManager::SetSatelliteStartState(bool state)
{
    return;
}

void WifiTogglerManager::CheckSatelliteState()
{
    return;
}

bool WifiTogglerManager::IsInterfaceUp(std::string &iface)
{
    return false;
}

bool WifiTogglerManager::IsSatelliteStateStart() const
{
    return false;
}

void WifiTogglerManager::RetryOpenP2p(void) const
{
    return;
}
}
}