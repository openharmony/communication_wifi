/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "wifi_controller_state_machine.h"
#include "wifi_controller_define.h"
#include "wifi_manager.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_msg.h"
#include "wifi_system_timer.h"
#include "wifi_hisysevent.h"
#ifdef HAS_BATTERY_MANAGER_PART
#include "battery_srv_client.h"
#endif
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiControllerMachine");
int WifiControllerMachine::mWifiStartFailCount{0};
int WifiControllerMachine::mSoftapStartFailCount{0};

WifiControllerMachine::WifiControllerMachine()
    : StateMachine("WifiControllerMachine"),
#ifndef HDI_CHIP_INTERFACE_SUPPORT
      mApidStopWifi(0),
#endif
      pEnableState(nullptr),
      pDisableState(nullptr),
      pDefaultState(nullptr)
{}

WifiControllerMachine::~WifiControllerMachine()
{
    WIFI_LOGI("WifiControllerMachine::~WifiControllerMachine");
    StopHandlerThread();
    ParsePointer(pEnableState);
    ParsePointer(pDisableState);
    ParsePointer(pDefaultState);
}

/* --------------------------Initialization functions--------------------------*/
ErrCode WifiControllerMachine::InitWifiControllerMachine()
{
    WIFI_LOGI("Enter WifiControllerMachine::InitWifiControllerMachine.\n");
    if (!InitialStateMachine("WifiControllerMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (InitWifiStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pDisableState);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

void WifiControllerMachine::BuildStateTree()
{
    StatePlus(pDefaultState, nullptr);
    StatePlus(pEnableState, pDefaultState);
    StatePlus(pDisableState, pDefaultState);
}

ErrCode WifiControllerMachine::InitWifiStates()
{
    int tmpErrNumber;

    WIFI_LOGE("Enter InitWifiStates.\n");
    pDefaultState = new (std::nothrow) DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState);
    pEnableState = new (std::nothrow) EnableState(this);
    tmpErrNumber += JudgmentEmpty(pEnableState);
    pDisableState = new (std::nothrow) DisableState(this);
    tmpErrNumber += JudgmentEmpty(pDisableState);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitWifiStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

WifiControllerMachine::DisableState::DisableState(WifiControllerMachine *wifiControllerMachine)
    : State("DisableState"), pWifiControllerMachine(wifiControllerMachine)
{}

WifiControllerMachine::DisableState::~DisableState()
{}

void WifiControllerMachine::DisableState::GoInState()
{
    WIFI_LOGE("DisableState GoInState function.");
}

void WifiControllerMachine::DisableState::GoOutState()
{
    WIFI_LOGE("DisableState GoOutState function.");
}

bool WifiControllerMachine::DisableState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("DisableState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
#ifdef FEATURE_AP_SUPPORT
        case CMD_SOFTAP_TOGGLED:
            if (msg->GetParam1()) {
                int id = msg->GetParam2();
                pWifiControllerMachine->MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, id);
                pWifiControllerMachine->StartTimer(CMD_AP_START_TIME, SFOT_AP_TIME_OUT);
                pWifiControllerMachine->SwitchState(pWifiControllerMachine->pEnableState);
            }
            break;
#endif
        case CMD_WIFI_TOGGLED:
        case CMD_SCAN_ALWAYS_MODE_CHANGED:
            if (pWifiControllerMachine->ShouldEnableWifi()) {
                ConcreteManagerRole role = pWifiControllerMachine->GetWifiRole();
                if (role == ConcreteManagerRole::ROLE_UNKNOW) {
                    WIFI_LOGE("Get unknow wifi role, break");
                    break;
                }
                pWifiControllerMachine->MakeConcreteManager(role, msg->GetParam2());
                pWifiControllerMachine->SwitchState(pWifiControllerMachine->pEnableState);
            }
            break;
        case CMD_AIRPLANE_TOGGLED:
            if (msg->GetParam1()) {
                pWifiControllerMachine->HandleAirplaneOpen();
            } else {
                pWifiControllerMachine->HandleAirplaneClose();
            }
            break;
        default:
            break;
    }
    return true;
}

WifiControllerMachine::EnableState::EnableState(WifiControllerMachine *wifiControllerMachine)
    : State("EnableState"), pWifiControllerMachine(wifiControllerMachine)
{}

WifiControllerMachine::EnableState::~EnableState()
{}

void WifiControllerMachine::EnableState::GoInState()
{
    WIFI_LOGE("EnableState GoInState function.");
}

void WifiControllerMachine::EnableState::GoOutState()
{
    WIFI_LOGE("EnableState GoOutState function.");
}

bool WifiControllerMachine::EnableState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("EnableState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case CMD_WIFI_TOGGLED:
        case CMD_SCAN_ALWAYS_MODE_CHANGED:
            pWifiControllerMachine->StopTimer(CMD_OPEN_WIFI_RETRY);
            HandleWifiToggleChangeInEnabledState(msg);
            break;
#ifdef FEATURE_AP_SUPPORT
        case CMD_SOFTAP_TOGGLED:
            HandleSoftapToggleChangeInEnabledState(msg);
            break;
        case CMD_AP_STOPPED:
        case CMD_AP_START_FAILURE:
            pWifiControllerMachine->StopTimer(CMD_AP_STOP_TIME);
            pWifiControllerMachine->StopSoftapCloseTimer();
            pWifiControllerMachine->HandleSoftapStop(msg->GetParam1());
            break;
        case CMD_AP_START:
            pWifiControllerMachine->StopTimer(CMD_AP_START_TIME);
            HandleApStart(msg->GetParam1());
            break;
        case CMD_AP_START_TIME:
            WriteSoftApOpenAndCloseFailedEvent(static_cast<int>(SoftApperateType::OPEN_SOFT_AP_FAILED), "TIME_OUT");
            break;
        case CMD_AP_STOP_TIME:
            WriteSoftApOpenAndCloseFailedEvent(static_cast<int>(SoftApperateType::CLOSE_SOFT_AP_FAILED), "TIME_OUT");
            break;
#endif
        case CMD_STA_START_FAILURE:
            HandleStaStartFailure(msg->GetParam1());
            break;
        case CMD_CONCRETE_STOPPED:
            pWifiControllerMachine->HandleConcreteStop(msg->GetParam1());
            break;
        case CMD_AIRPLANE_TOGGLED:
            if (msg->GetParam1()) {
                pWifiControllerMachine->HandleAirplaneOpen();
            } else {
                pWifiControllerMachine->HandleAirplaneClose();
            }
            break;
        case CMD_OPEN_WIFI_RETRY:
            pWifiControllerMachine->SendMessage(CMD_WIFI_TOGGLED, 1, 0);
            break;
        case CMD_AP_SERVICE_START_FAILURE:
            HandleAPServiceStartFail(msg->GetParam1());
            break;
        case CMD_STA_REMOVED:
            HandleStaRemoved(msg);
            break;
        case CMD_CONCRETECLIENT_REMOVED:
            HandleConcreteClientRemoved(msg);
            break;
        case CMD_AP_REMOVED:
#ifdef FEATURE_AP_SUPPORT
            HandleApRemoved(msg);
#endif
            break;
        default:
            break;
    }
    return true;
}

WifiControllerMachine::DefaultState::DefaultState(WifiControllerMachine *wifiControllerMachine)
    : State("DefaultState"), pWifiControllerMachine(wifiControllerMachine)
{}

WifiControllerMachine::DefaultState::~DefaultState()
{}

void WifiControllerMachine::DefaultState::GoInState()
{
    WIFI_LOGE("DefaultState GoInState function.");
}

void WifiControllerMachine::DefaultState::GoOutState()
{
    WIFI_LOGE("DefaultState GoOutState function.");
}

bool WifiControllerMachine::DefaultState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr || pWifiControllerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    return true;
}

void WifiControllerMachine::HandleAirplaneOpen()
{
    WIFI_LOGI("airplane open set softap false");
#ifdef FEATURE_AP_SUPPORT
    WifiSettings::GetInstance().SetSoftapToggledState(false);
    StopAllSoftapManagers();
#endif
    if (!WifiConfigCenter::GetInstance().GetWifiFlagOnAirplaneMode()) {
        StopAllConcreteManagers();
    }
}

void WifiControllerMachine::HandleAirplaneClose()
{
    if (!ShouldEnableWifi() || WifiSettings::GetInstance().GetWifiStopState()) {
        return;
    }
#ifdef FEATURE_AP_SUPPORT
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiSettings::GetInstance().GetCoexSupport() && HasAnySoftApManager()) {
        WIFI_LOGE("HandleAirplaneClose, has softap in runing return.");
        return;
    }
#endif
#endif
    ConcreteManagerRole role = GetWifiRole();
    if (role == ConcreteManagerRole::ROLE_UNKNOW) {
        WIFI_LOGE("Get unknow wifi role in HandleAirplaneClose.");
        return;
    }
    if (!HasAnyConcreteManager()) {
        MakeConcreteManager(role, 0);
        SwitchState(pEnableState);
    } else {
        SwitchRole(role);
    }
}

#ifdef FEATURE_AP_SUPPORT
bool WifiControllerMachine::SoftApIdExist(int id)
{
    if (!HasAnySoftApManager()) {
        return false;
    }
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    for (auto iter = softapManagers.begin(); iter != softapManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            return true;
        }
    }
    return false;
}

SoftApManager *WifiControllerMachine::GetSoftApManager(int id)
{
    if (!HasAnySoftApManager()) {
        return nullptr;
    }

    std::unique_lock<std::mutex> lock(softapManagerMutex);
    for (auto iter = softapManagers.begin(); iter != softapManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            return *iter;
        }
    }
    return nullptr;
}
#endif

bool WifiControllerMachine::ConcreteIdExist(int id)
{
    if (!HasAnyConcreteManager()) {
        return false;
    }
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            return true;
        }
    }
    return false;
}

bool WifiControllerMachine::HasAnyConcreteManager()
{
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    if (concreteManagers.empty()) {
        return false;
    }
    return true;
}

#ifdef FEATURE_AP_SUPPORT
bool WifiControllerMachine::HasAnySoftApManager()
{
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    if (softapManagers.empty()) {
        return false;
    }
    return true;
}
#endif

bool WifiControllerMachine::HasAnyManager()
{
    if (!HasAnyConcreteManager()
#ifdef FEATURE_AP_SUPPORT
        && !HasAnySoftApManager()
#endif
    ) {
        return false;
    }
    return true;
}

void WifiControllerMachine::MakeConcreteManager(ConcreteManagerRole role, int id)
{
    WIFI_LOGE("Enter MakeConcreteManager");
    ConcreteClientModeManager *clientmode = new (std::nothrow) ConcreteClientModeManager(role, id);
    clientmode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetConcreteCallback());
    clientmode->InitConcreteManager();
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    concreteManagers.push_back(clientmode);
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::MakeSoftapManager(SoftApManager::Role role, int id)
{
    WIFI_LOGE("Enter MakeSoftapManager");
    SoftApManager *softapmode = new (std::nothrow) SoftApManager(role, id);
    softapmode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetSoftApCallback());
    softapmode->InitSoftapManager();
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    softapManagers.push_back(softapmode);
}

bool WifiControllerMachine::ShouldEnableSoftap()
{
    WIFI_LOGI("Enter ShouldEnableSoftap");
    if (WifiSettings::GetInstance().GetSoftapToggledState()) {
        return true;
    }
    return false;
}
#endif

bool WifiControllerMachine::ShouldEnableWifi()
{
    WIFI_LOGI("Enter ShouldEnableWifi");
#ifndef OHOS_ARCH_LITE
    if (WifiManager::GetInstance().GetWifiEventSubscriberManager()->IsMdmForbidden()) {
        return false;
    }
#endif
    if (WifiSettings::GetInstance().IsWifiToggledEnable() || IsScanOnlyEnable()) {
        WIFI_LOGI("Should start wifi or scanonly.");
        return true;
    }

    WIFI_LOGI("no need to start Wifi or scanonly");
    return false;
}

ConcreteManagerRole WifiControllerMachine::GetWifiRole()
{
    if (IsWifiEnable() && IsScanOnlyEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_MIX;
    } else if (IsWifiEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_STA;
    } else if (IsScanOnlyEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY;
    } else {
        return ConcreteManagerRole::ROLE_UNKNOW;
    }
}

bool WifiControllerMachine::IsWifiEnable()
{
    return WifiSettings::GetInstance().IsWifiToggledEnable();
}

bool WifiControllerMachine::IsScanOnlyEnable()
{
    if (WifiSettings::GetInstance().GetScanOnlySwitchState()) {
        WIFI_LOGI("scanonly available is true");
#ifndef OHOS_ARCH_LITE
        if (WifiManager::GetInstance().GetWifiEventSubscriberManager()->GetLocationModeByDatashare()) {
            WIFI_LOGI("location mode is 1");
            return true;
        } else {
            WIFI_LOGI("No need to StartScanOnly");
            return false;
        }
#endif
        return true;
    }
    WIFI_LOGI("No need to StartScanOnly");
    return false;
}

void WifiControllerMachine::StopAllConcreteManagers()
{
    WIFI_LOGI("Enter StopAllConcreteManagers.");
    if (!HasAnyConcreteManager()) {
        return;
    }
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STOP);
    }
}

void WifiControllerMachine::StopConcreteManager(int id)
{
    if (!HasAnyConcreteManager()) {
        return;
    }

    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STOP);
            return;
        }
    }
    return;
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::StopSoftapManager(int id)
{
    if (!HasAnySoftApManager()) {
        return;
    }
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    for (auto iter = softapManagers.begin(); iter != softapManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            (*iter)->GetSoftapMachine()->SendMessage(SOFTAP_CMD_STOP);
            return;
        }
    }
}

void WifiControllerMachine::StopAllSoftapManagers()
{
    if (!HasAnySoftApManager()) {
        WIFI_LOGE("Not found AnySoftApManager.");
        return;
    }
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    for (auto iter = softapManagers.begin(); iter != softapManagers.end(); ++iter) {
        (*iter)->GetSoftapMachine()->SendMessage(SOFTAP_CMD_STOP);
    }
}
#endif

void WifiControllerMachine::RemoveConcreteManager(int id)
{
    ConcreteClientModeManager *concreteManager = nullptr;

    if (!HasAnyConcreteManager()) {
        return;
    }
    {
        std::unique_lock<std::mutex> lock(concreteManagerMutex);
        for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
            if ((*iter)->mid == id) {
                concreteManager = *iter;
                concreteManagers.erase(iter);
                break;
            }
        }
    }
    if (concreteManager != nullptr) {
        delete concreteManager;
    }
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::RmoveSoftapManager(int id)
{
    SoftApManager *softapManager = nullptr;

    if (!HasAnySoftApManager()) {
        return;
    }
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    for (auto iter = softapManagers.begin(); iter != softapManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            softapManager = *iter;
            softapManagers.erase(iter);
            break;
        }
    }
    if (softapManager != nullptr) {
        delete softapManager;
    }
}
#endif

void WifiControllerMachine::HandleStaClose(int id)
{
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    if (concreteManagers.empty()) {
        return;
    }
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STA_STOP);
            break;
        }
    }
}

void WifiControllerMachine::SwitchRole(ConcreteManagerRole role)
{
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        (*iter)->SetRole(role);
    }
}

void WifiControllerMachine::EnableState::HandleWifiToggleChangeInEnabledState(InternalMessage *msg)
{
    ConcreteManagerRole presentRole;
    if (!(pWifiControllerMachine->ShouldEnableWifi())) {
        pWifiControllerMachine->StopAllConcreteManagers();
        return;
    }
    if (pWifiControllerMachine->ConcreteIdExist(msg->GetParam2())) {
        if (WifiSettings::GetInstance().GetWifiStopState()) {
            return;
        }
        presentRole = pWifiControllerMachine->GetWifiRole();
        if (presentRole == ConcreteManagerRole::ROLE_UNKNOW) {
            WIFI_LOGE("Get unknow wifi role in enablestate.");
            return;
        }
        pWifiControllerMachine->SwitchRole(presentRole);
        return;
    }
    WifiSettings::GetInstance().SetWifiStopState(false);
#ifdef FEATURE_AP_SUPPORT
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiSettings::GetInstance().GetCoexSupport() &&
        pWifiControllerMachine->HasAnySoftApManager()) {
        pWifiControllerMachine->StopAllSoftapManagers();
        return;
    }
#endif
#endif
    presentRole = pWifiControllerMachine->GetWifiRole();
    if (presentRole == ConcreteManagerRole::ROLE_UNKNOW) {
        WIFI_LOGE("Get unknow wifi role  in EnableState.");
        return;
    }
    pWifiControllerMachine->MakeConcreteManager(presentRole, msg->GetParam2());
    return;
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::EnableState::HandleSoftapToggleChangeInEnabledState(InternalMessage *msg)
{
    int id = msg->GetParam2();
    WIFI_LOGE("handleSoftapToggleChangeInEnabledState");
    if (msg->GetParam1() == 1) {
#ifndef HDI_CHIP_INTERFACE_SUPPORT
        if (!WifiSettings::GetInstance().GetCoexSupport() &&
            pWifiControllerMachine->HasAnyConcreteManager()) {
            pWifiControllerMachine->StopAllConcreteManagers();
            pWifiControllerMachine->mApidStopWifi = id;
            return;
        }
#endif
        if (!pWifiControllerMachine->SoftApIdExist(id)) {
            pWifiControllerMachine->MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, id);
            return;
        }
    }
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiSettings::GetInstance().GetCoexSupport() &&
        pWifiControllerMachine->ShouldEnableWifi() && !WifiSettings::GetInstance().GetWifiStopState() &&
        pWifiControllerMachine->HasAnyConcreteManager()) {
        ConcreteManagerRole role = pWifiControllerMachine->GetWifiRole();
        if (role != ConcreteManagerRole::ROLE_UNKNOW) {
            pWifiControllerMachine->SwitchRole(role);
        }
    }
#endif
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(id);
    if (apState == WifiOprMidState::CLOSING || apState == WifiOprMidState::OPENING) {
        return;
    }
    if (pWifiControllerMachine->SoftApIdExist(id)) {
        pWifiControllerMachine->StopSoftapManager(id);
        pWifiControllerMachine->StartTimer(CMD_AP_STOP_TIME, SFOT_AP_TIME_OUT);
        return;
    }
}
#endif

void WifiControllerMachine::EnableState::HandleStaStartFailure(int id)
{
    WIFI_LOGE("HandleStaStartFailure");
    pWifiControllerMachine->RemoveConcreteManager(id);
    mWifiStartFailCount++;
    if (pWifiControllerMachine->ShouldEnableWifi() && mWifiStartFailCount < WIFI_OPEN_RETRY_MAX_COUNT) {
        pWifiControllerMachine->StartTimer(CMD_OPEN_WIFI_RETRY, WIFI_OPEN_RETRY_TIMEOUT);
    }
}

void WifiControllerMachine::EnableState::HandleStaRemoved(InternalMessage *msg)
{
    pWifiControllerMachine->StopConcreteManager(msg->GetParam2());
}

void WifiControllerMachine::EnableState::HandleConcreteClientRemoved(InternalMessage *msg)
{
    int id = msg->GetParam1();
    pWifiControllerMachine->RemoveConcreteManager(id);
    if (!(pWifiControllerMachine->HasAnyManager())) {
        pWifiControllerMachine->SwitchState(pWifiControllerMachine->pDisableState);
    }
}

void WifiControllerMachine::EnableState::HandleAPServiceStartFail(int id)
{
    mSoftapStartFailCount++;
    WIFI_LOGI("Softap start fail count %{public}d", mSoftapStartFailCount);
    if (mSoftapStartFailCount >= AP_OPEN_RETRY_MAX_COUNT) {
        WIFI_LOGE("Ap start fail, set softap toggled false");
        WifiSettings::GetInstance().SetSoftapToggledState(false);
    }
}

void WifiControllerMachine::ClearWifiStartFailCount()
{
    WIFI_LOGD("Clear wifi start fail count");
    mWifiStartFailCount = 0;
}

void WifiControllerMachine::ClearApStartFailCount()
{
    WIFI_LOGD("Clear ap start fail count");
    mSoftapStartFailCount = 0;
}

void WifiControllerMachine::HandleStaStart(int id)
{
    mWifiStartFailCount = 0;
    this->StopTimer(CMD_OPEN_WIFI_RETRY);
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STA_START);
    }
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::EnableState::HandleApStart(int id)
{
    mSoftapStartFailCount = 0;
    if (!pWifiControllerMachine->ShouldEnableSoftap()) {
        pWifiControllerMachine->StopSoftapManager(id);
        return;
    }
    pWifiControllerMachine->StartSoftapCloseTimer();
}

void WifiControllerMachine::EnableState::HandleApRemoved(InternalMessage *msg)
{
    pWifiControllerMachine->StopSoftapManager(msg->GetParam2());
    SoftApManager *softap = pWifiControllerMachine->GetSoftApManager(msg->GetParam2());
    softap->SetRole(SoftApManager::Role::ROLE_HAS_REMOVED);
}
#endif

void WifiControllerMachine::HandleConcreteStop(int id)
{
    RemoveConcreteManager(id);
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiSettings::GetInstance().GetCoexSupport()) {
#ifdef FEATURE_AP_SUPPORT
        int airplanestate = WifiConfigCenter::GetInstance().GetAirplaneModeState();
        if (ShouldEnableSoftap() && airplanestate != MODE_STATE_OPEN &&
            !SoftApIdExist(mApidStopWifi)) {
            MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, mApidStopWifi);
            return;
        }
#endif
        if (!WifiManager::GetInstance().GetWifiTogglerManager()->HasAnyApRuning()) {
            if (WifiSettings::GetInstance().IsWifiToggledEnable()) {
                ConcreteManagerRole presentRole = GetWifiRole();
                MakeConcreteManager(presentRole, 0);
                return;
            }
        }
    } else {
#endif
        if (WifiSettings::GetInstance().IsWifiToggledEnable()) {
            ConcreteManagerRole presentRole = GetWifiRole();
            MakeConcreteManager(presentRole, 0);
            return;
        }
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    }
#endif
    if (!(HasAnyManager())) {
        SwitchState(pDisableState);
    }
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::HandleSoftapStop(int id)
{
    ConcreteManagerRole role;
    SoftApManager *softap = GetSoftApManager(id);
    if (softap->GetRole() == SoftApManager::Role::ROLE_HAS_REMOVED) {
        RmoveSoftapManager(id);
        if (!HasAnyManager()) {
            SwitchState(pDisableState);
        } else {
            return;
        }
    }

    RmoveSoftapManager(id);
    if (ShouldEnableSoftap() && !SoftApIdExist(0)) {
        MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, 0);
        return;
    }
    if (HasAnyManager()) {
        return;
    }
    if (ShouldEnableWifi() && !WifiSettings::GetInstance().GetWifiStopState()) {
        role = GetWifiRole();
        if (role == ConcreteManagerRole::ROLE_UNKNOW) {
            WIFI_LOGE("Get unknow wifi role in HandleSoftapStop.");
            return;
        }
        MakeConcreteManager(role, 0);
    } else {
        SwitchState(pDisableState);
    }
}

static void AlarmStopSoftap()
{
    WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, 0);
}

void WifiControllerMachine::StartSoftapCloseTimer()
{
    WIFI_LOGI("enter softapCloseTimer");
    int mTimeoutDelay = WifiSettings::GetInstance().GetHotspotIdleTimeout();
    if (stopSoftapTimerId_ != 0) {
        return;
    }
#ifdef HAS_BATTERY_MANAGER_PART
    auto &batterySrvClient = PowerMgr::BatterySrvClient::GetInstance();
    auto batteryPluggedType = batterySrvClient.GetPluggedType();
    if (batteryPluggedType == PowerMgr::BatteryPluggedType::PLUGGED_TYPE_USB) {
        WIFI_LOGI("usb connect do not start timer");
        return;
    }
#endif
    std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, true, false);
    wifiSysTimer->SetCallbackInfo(AlarmStopSoftap);
    stopSoftapTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
    int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    MiscServices::TimeServiceClient::GetInstance()->StartTimer(stopSoftapTimerId_, currentTime + mTimeoutDelay);
}

void WifiControllerMachine::StopSoftapCloseTimer()
{
    WIFI_LOGI("enter StopSoftapCloseTimer");
    if (stopSoftapTimerId_ == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(stopSoftapTimerId_);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(stopSoftapTimerId_);
    stopSoftapTimerId_ = 0;
}
#endif

} // namespace Wifi
} // namespace OHOS
