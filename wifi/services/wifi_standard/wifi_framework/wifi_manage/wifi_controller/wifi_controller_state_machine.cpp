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

WifiControllerMachine::WifiControllerMachine()
    : StateMachine("WifiControllerMachine"),
#ifndef HDI_CHIP_INTERFACE_SUPPORT
      mApidStopWifi(0),
#endif
      pEnableState(nullptr), pDisableState(nullptr), pDefaultState(nullptr)
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

bool WifiControllerMachine::DisableState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGI("DisableState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
#ifdef FEATURE_AP_SUPPORT
        case CMD_SOFTAP_TOGGLED:
            if (msg->GetParam1()) {
                int id = msg->GetParam2();
                pWifiControllerMachine->MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, id);
                pWifiControllerMachine->StartTimer(CMD_AP_START_TIME, SOFT_AP_TIME_OUT);
                pWifiControllerMachine->SwitchState(pWifiControllerMachine->pEnableState);
            }
            break;
#endif
        case CMD_WIFI_TOGGLED:
        case CMD_SCAN_ALWAYS_MODE_CHANGED:
            if (!pWifiControllerMachine->ShouldEnableWifi(msg->GetParam2())) {
                WIFI_LOGW("keep disable, shouldn't enabled wifi.");
                break;
            }
            if (msg->GetParam2() == INSTID_WLAN1) {
                pWifiControllerMachine->MakeMultiStaManager(MultiStaManager::Role::ROLE_STA_WIFI_2, msg->GetParam2());
                pWifiControllerMachine->SwitchState(pWifiControllerMachine->pEnableState);
            } else if (msg->GetParam2() == INSTID_WLAN0) {
                ConcreteManagerRole roleStaWifi1 = pWifiControllerMachine->GetWifiRole();
                if (roleStaWifi1 == ConcreteManagerRole::ROLE_UNKNOW) {
                    WIFI_LOGE("Get unknow wifi role, break");
                    break;
                }
                pWifiControllerMachine->MakeConcreteManager(roleStaWifi1, msg->GetParam2());
                pWifiControllerMachine->SwitchState(pWifiControllerMachine->pEnableState);
            } else {
                WIFI_LOGE("DisableState, invalid instance id");
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

bool WifiControllerMachine::EnableState::ExecuteStateMsg(InternalMessagePtr msg)
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
            HandleApStop(msg);
            break;
        case CMD_AP_START_FAILURE:
            HandleAPServiceStartFail(msg->GetParam1());
            HandleApStop(msg);
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
            msg->GetParam1() == INSTID_WLAN0 ?
                HandleStaStartFailure(INSTID_WLAN0) : pWifiControllerMachine->RemoveMultiStaManager(INSTID_WLAN1);
            break;
        case CMD_CONCRETE_STOPPED:
            pWifiControllerMachine->HandleConcreteStop(INSTID_WLAN0);
            break;
        case CMD_MULTI_STA_STOPPED:
            pWifiControllerMachine->RemoveMultiStaManager(INSTID_WLAN1);
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
        case CMD_STA_REMOVED:
            INSTID_WLAN0 == msg->GetParam2() ? HandleStaRemoved(msg) : HandleWifi2Removed(msg);
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

bool WifiControllerMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
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
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    StopAllSoftapManagers();
#endif
    if (!WifiSettings::GetInstance().GetWifiFlagOnAirplaneMode() ||
        WifiConfigCenter::GetInstance().GetWifiDetailState() == WifiDetailState::STATE_SEMI_ACTIVE) {
        StopAllConcreteManagers();
    }
}

void WifiControllerMachine::HandleAirplaneClose()
{
    WIFI_LOGI("HandleAirplaneClose in");
#ifndef OHOS_ARCH_LITE
    WifiManager::GetInstance().GetWifiEventSubscriberManager()->GetWifiAllowSemiActiveByDatashare();
#endif
    if (!ShouldEnableWifi(INSTID_WLAN0) || WifiConfigCenter::GetInstance().GetWifiStopState()) {
        return;
    }
#ifdef FEATURE_AP_SUPPORT
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() && HasAnySoftApManager()) {
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
            WIFI_LOGI("Softap id %{public}d exist.", id);
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
            WIFI_LOGI("Get softap manager id %{public}d.", id);
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
            WIFI_LOGI("concreteManagers is match");
            return true;
        }
    }
    return false;
}

bool WifiControllerMachine::IsWifi2IdExist(int id)
{
    if (!HasAnyMultiStaManager()) {
        return false;
    }
    std::unique_lock<std::mutex> lock(multiStaManagerMutex);
    for (auto iter = multiStaManagers.begin(); iter != multiStaManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            WIFI_LOGI("multiStaManagers is match");
            return true;
        }
    }
    return false;
}

bool WifiControllerMachine::HasAnyConcreteManager()
{
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    if (concreteManagers.empty()) {
        WIFI_LOGE("Enter HasAnyConcreteManager is empty");
        return false;
    }
    return true;
}

bool WifiControllerMachine::HasAnyMultiStaManager()
{
    std::unique_lock<std::mutex> lock(multiStaManagerMutex);
    if (multiStaManagers.empty()) {
        WIFI_LOGE("Enter HasAnyMultiStaManager is empty");
        return false;
    }
    return true;
}

#ifdef FEATURE_AP_SUPPORT
bool WifiControllerMachine::HasAnySoftApManager()
{
    std::unique_lock<std::mutex> lock(softapManagerMutex);
    if (softapManagers.empty()) {
        WIFI_LOGI("Softap managers is empty");
        return false;
    }
    WIFI_LOGI("Has softap manager");
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
    WIFI_LOGI("Enter MakeConcreteManager, curRole = %{public}d id = %{public}d", static_cast<int>(role), id);
    ConcreteClientModeManager *clientmode = new (std::nothrow) ConcreteClientModeManager(role, id);
    clientmode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetConcreteCallback());
    clientmode->InitConcreteManager();
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    concreteManagers.push_back(clientmode);
}

void WifiControllerMachine::MakeMultiStaManager(MultiStaManager::Role role, int instId)
{
    WIFI_LOGI("Enter MakeMultiStaManager");
    MultiStaManager *multiStaMode = new (std::nothrow) MultiStaManager(role, instId);
    if (multiStaMode == nullptr) {
        WIFI_LOGE("new multiStaMode failed");
        return;
    }
    multiStaMode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetMultiStaCallback());
    multiStaMode->InitMultiStaManager();
    std::unique_lock<std::mutex> lock(multiStaManagerMutex);
    multiStaManagers.push_back(multiStaMode);
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
    bool toggledState = WifiConfigCenter::GetInstance().GetSoftapToggledState();
    WIFI_LOGI("Softap toggled state is %{public}d", toggledState);
    return toggledState;
}
#endif

bool WifiControllerMachine::ShouldDisableWifi(InternalMessagePtr msg)
{
    auto currState = WifiConfigCenter::GetInstance().GetWifiDetailState(msg->GetParam2());
    if (WifiConfigCenter::GetInstance().GetWifiToggledEnable() == WIFI_STATE_SEMI_ENABLED &&
        (currState == WifiDetailState::STATE_ACTIVATED || currState == WifiDetailState::STATE_ACTIVATING) &&
        msg->GetMessageName() == CMD_WIFI_TOGGLED && ConcreteIdExist(msg->GetParam2())) {
        WIFI_LOGI("Should disable wifi");
        return true;
    }
    return !ShouldEnableWifi(msg->GetParam2());
}

bool WifiControllerMachine::ShouldEnableWifi(int id)
{
    WIFI_LOGI("Enter ShouldEnableWifi");
    if (id == INSTID_WLAN1) {
        return WifiConfigCenter::GetInstance().GetWifiToggledEnable(INSTID_WLAN0) == WIFI_STATE_ENABLED;
    }
#ifndef OHOS_ARCH_LITE
    if (WifiManager::GetInstance().GetWifiEventSubscriberManager()->IsMdmForbidden()) {
        return false;
    }
#endif
    if (WifiConfigCenter::GetInstance().GetWifiToggledEnable(id) != WIFI_STATE_DISABLED || IsScanOnlyEnable()) {
        WIFI_LOGI("Should start wifi or scanonly.");
        return true;
    }

    WIFI_LOGI("no need to start Wifi or scanonly");
    return false;
}

ConcreteManagerRole WifiControllerMachine::GetWifiRole()
{
    if (IsWifiEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_STA;
    } else if (IsSemiWifiEnable() && IsScanOnlyEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE;
    } else if (IsSemiWifiEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE;
    } else if (IsScanOnlyEnable()) {
        return ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY;
    } else {
        return ConcreteManagerRole::ROLE_UNKNOW;
    }
}

bool WifiControllerMachine::IsWifiEnable(int id)
{
    return WifiConfigCenter::GetInstance().GetWifiToggledEnable(id) == WIFI_STATE_ENABLED;
}

bool WifiControllerMachine::IsSemiWifiEnable()
{
    return WifiConfigCenter::GetInstance().GetWifiToggledEnable() == WIFI_STATE_SEMI_ENABLED;
}

bool WifiControllerMachine::IsScanOnlyEnable()
{
    if (WifiConfigCenter::GetInstance().CheckScanOnlyAvailable()) {
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
        WIFI_LOGD("Enter StopAllConcreteManagers. mid = %{public}d", (*iter)->mid);
        (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STOP);
    }
}

void WifiControllerMachine::StopConcreteManager(int id)
{
    WIFI_LOGI("Enter StopConcreteManager. id = %{public}d", id);
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

void WifiControllerMachine::StopMultiStaManager(int id)
{
    WIFI_LOGI("Enter StopMultiStaManager, id = %{public}d", id);
    if (!HasAnyMultiStaManager()) {
        return;
    }
    std::unique_lock<std::mutex> lock(multiStaManagerMutex);
    for (auto iter = multiStaManagers.begin(); iter != multiStaManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            (*iter)->GetMultiStaMachine()->SendMessage(MULTI_STA_CMD_STOP);
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

void WifiControllerMachine::RemoveMultiStaManager(int id)
{
    MultiStaManager *multiStaMgr = nullptr;

    if (!HasAnyMultiStaManager()) {
        return;
    }
    {
        std::unique_lock<std::mutex> lock(multiStaManagerMutex);
        for (auto iter = multiStaManagers.begin(); iter != multiStaManagers.end(); ++iter) {
            if ((*iter)->mid == id) {
                multiStaMgr = *iter;
                multiStaManagers.erase(iter);
                break;
            }
        }
    }
    if (multiStaMgr != nullptr) {
        delete multiStaMgr;
        multiStaMgr = nullptr;
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

void WifiControllerMachine::HandleWifi2Close(int id)
{
    std::unique_lock<std::mutex> lock(multiStaManagerMutex);
    if (multiStaManagers.empty()) {
        return;
    }
    for (auto iter = multiStaManagers.begin(); iter != multiStaManagers.end(); ++iter) {
        if ((*iter)->mid == id) {
            (*iter)->GetMultiStaMachine()->SendMessage(MULTI_STA_CMD_STOPPED);
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

void WifiControllerMachine::EnableState::HandleWifiToggleChangeInEnabledState(InternalMessagePtr msg)
{
    if (msg->GetParam2() == INSTID_WLAN1 && msg->GetParam1() == 0) {
        WIFI_LOGI("Toggle disable wlan1.");
        pWifiControllerMachine->StopMultiStaManager(INSTID_WLAN1);
        return;
    }
    if (msg->GetParam2() == INSTID_WLAN1 && WifiConfigCenter::GetInstance().GetPersistWifiState(INSTID_WLAN0)
        == WIFI_STATE_ENABLED && msg->GetParam1() == 1) {
        pWifiControllerMachine->MakeMultiStaManager(MultiStaManager::Role::ROLE_STA_WIFI_2, msg->GetParam2());
        return;
    }

    ConcreteManagerRole presentRole;
    if (!pWifiControllerMachine->ShouldEnableWifi(msg->GetParam2())) {
        pWifiControllerMachine->StopMultiStaManager(INSTID_WLAN1);
        pWifiControllerMachine->StopAllConcreteManagers();
        return;
    }
    if (pWifiControllerMachine->ConcreteIdExist(msg->GetParam2())) {
        if (WifiConfigCenter::GetInstance().GetWifiStopState()) {
            return;
        }
        presentRole = pWifiControllerMachine->GetWifiRole();
        if (presentRole == ConcreteManagerRole::ROLE_UNKNOW) {
            WIFI_LOGE("Get unknow wifi role in enablestate.");
            return;
        }
        if (presentRole != ConcreteManagerRole::ROLE_CLIENT_STA) {
            pWifiControllerMachine->StopMultiStaManager(INSTID_WLAN1);
        }
        pWifiControllerMachine->SwitchRole(presentRole);
        return;
    }
    WifiConfigCenter::GetInstance().SetWifiStopState(false);
#ifdef FEATURE_AP_SUPPORT
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() && pWifiControllerMachine->HasAnySoftApManager()) {
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
void WifiControllerMachine::EnableState::HandleSoftapToggleChangeInEnabledState(InternalMessagePtr msg)
{
    int id = msg->GetParam2();
    WIFI_LOGI("handleSoftapToggleChangeInEnabledState");
    if (msg->GetParam1() == 1) {
#ifndef HDI_CHIP_INTERFACE_SUPPORT
        if (!WifiConfigCenter::GetInstance().GetCoexSupport() &&
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
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() &&
        pWifiControllerMachine->ShouldEnableWifi(INSTID_WLAN0) &&
        !WifiConfigCenter::GetInstance().GetWifiStopState() &&
        pWifiControllerMachine->HasAnyConcreteManager()) {
        ConcreteManagerRole role = pWifiControllerMachine->GetWifiRole();
        if (role != ConcreteManagerRole::ROLE_UNKNOW) {
            pWifiControllerMachine->SwitchRole(role);
        }
    }
#endif
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(id);
    if (apState == WifiOprMidState::CLOSING || apState == WifiOprMidState::OPENING) {
        WIFI_LOGI("Current ap state is %{public}d, return", apState);
        return;
    }
    if (pWifiControllerMachine->SoftApIdExist(id)) {
        pWifiControllerMachine->StopSoftapManager(id);
        pWifiControllerMachine->StartTimer(CMD_AP_STOP_TIME, SOFT_AP_TIME_OUT);
        return;
    }
}
#endif

void WifiControllerMachine::EnableState::HandleStaStartFailure(int id)
{
    WIFI_LOGI("HandleStaStartFailure");
    pWifiControllerMachine->RemoveConcreteManager(id);
    mWifiStartFailCount++;
    if (pWifiControllerMachine->ShouldEnableWifi(id) && mWifiStartFailCount < WIFI_OPEN_RETRY_MAX_COUNT) {
        pWifiControllerMachine->StartTimer(CMD_OPEN_WIFI_RETRY, WIFI_OPEN_RETRY_TIMEOUT);
    }
}

void WifiControllerMachine::EnableState::HandleStaRemoved(InternalMessagePtr msg)
{
    {
        std::unique_lock<std::mutex> lock(pWifiControllerMachine->concreteManagerMutex);
        for (auto iter = pWifiControllerMachine->concreteManagers.begin();
            iter != pWifiControllerMachine->concreteManagers.end(); ++iter) {
            if ((*iter)->mid == msg->GetParam2() && msg->GetParam1() >= 0) {
                (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STA_REMOVED);
            }
        }
    }
    pWifiControllerMachine->StopConcreteManager(msg->GetParam2());
}

void WifiControllerMachine::EnableState::HandleWifi2Removed(InternalMessagePtr msg)
{
    pWifiControllerMachine->StopMultiStaManager(msg->GetParam2());
}

void WifiControllerMachine::EnableState::HandleConcreteClientRemoved(InternalMessagePtr msg)
{
    int id = msg->GetParam1();
    pWifiControllerMachine->RemoveConcreteManager(id);
    if (!(pWifiControllerMachine->HasAnyManager())) {
        pWifiControllerMachine->SwitchState(pWifiControllerMachine->pDisableState);
    }
}

void WifiControllerMachine::EnableState::HandleAPServiceStartFail(int id)
{
    WIFI_LOGE("Ap start fail, set softap toggled false");
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
}

void WifiControllerMachine::ClearWifiStartFailCount()
{
    WIFI_LOGD("Clear wifi start fail count");
    mWifiStartFailCount = 0;
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

void WifiControllerMachine::HandleWifi2Start(int id)
{
    std::unique_lock<std::mutex> lock(multiStaManagerMutex);
    for (auto iter = multiStaManagers.begin(); iter != multiStaManagers.end(); ++iter) {
        (*iter)->GetMultiStaMachine()->SendMessage(MULTI_STA_CMD_STARTED);
    }
}

void WifiControllerMachine::HandleStaSemiActive(int id)
{
    mWifiStartFailCount = 0;
    this->StopTimer(CMD_OPEN_WIFI_RETRY);
    std::unique_lock<std::mutex> lock(concreteManagerMutex);
    for (auto iter = concreteManagers.begin(); iter != concreteManagers.end(); ++iter) {
        (*iter)->GetConcreteMachine()->SendMessage(CONCRETE_CMD_STA_SEMI_ACTIVE);
    }
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::EnableState::HandleApStart(int id)
{
    if (!pWifiControllerMachine->ShouldEnableSoftap()) {
        pWifiControllerMachine->StopSoftapManager(id);
        return;
    }
    pWifiControllerMachine->StartSoftapCloseTimer();
}

void WifiControllerMachine::EnableState::HandleApRemoved(InternalMessagePtr msg)
{
    pWifiControllerMachine->StopSoftapManager(msg->GetParam2());
    SoftApManager *softap = pWifiControllerMachine->GetSoftApManager(msg->GetParam2());
    if (softap != nullptr) {
        softap->SetRole(SoftApManager::Role::ROLE_HAS_REMOVED);
    }
}

void WifiControllerMachine::EnableState::HandleApStop(InternalMessagePtr msg)
{
    pWifiControllerMachine->StopTimer(CMD_AP_STOP_TIME);
    pWifiControllerMachine->StopSoftapCloseTimer();
    pWifiControllerMachine->HandleSoftapStop(msg->GetParam1());
}
#endif

void WifiControllerMachine::HandleConcreteStop(int id)
{
    WIFI_LOGD("WifiControllerMachine HandleConcreteStop id = %{public}d", id);
    RemoveConcreteManager(id);
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiConfigCenter::GetInstance().GetCoexSupport()) {
#ifdef FEATURE_AP_SUPPORT
        int airplanstate = WifiConfigCenter::GetInstance().GetAirplaneModeState();
        if (ShouldEnableSoftap() && airplanstate != MODE_STATE_OPEN &&
            !SoftApIdExist(mApidStopWifi)) {
            MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, mApidStopWifi);
            return;
        }
#endif
        if (!WifiManager::GetInstance().GetWifiTogglerManager()->HasAnyApRuning()) {
            if (ShouldEnableWifi(id)) {
                ConcreteManagerRole presentRole = GetWifiRole();
                MakeConcreteManager(presentRole, 0);
                return;
            }
        }
    } else {
#endif
        if (ShouldEnableWifi(id)) {
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
    if (softap != nullptr && softap->GetRole() == SoftApManager::Role::ROLE_HAS_REMOVED) {
        RmoveSoftapManager(id);
        if (!HasAnyManager()) {
            SwitchState(pDisableState);
        }
        return;
    }

    RmoveSoftapManager(id);
    if (ShouldEnableSoftap() && !SoftApIdExist(0)) {
        MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, 0);
        return;
    }
    if (HasAnyManager()) {
        return;
    }
    if (ShouldEnableWifi(INSTID_WLAN0) && !WifiConfigCenter::GetInstance().GetWifiStopState()) {
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
    int mTimeoutDelay = WifiConfigCenter::GetInstance().GetHotspotIdleTimeout();
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
    std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, false, false);
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

void WifiControllerMachine::ShutdownWifi(bool shutDownAp)
{
    WIFI_LOGI("shutdownWifi.");
    if (shutDownAp) {
#ifdef FEATURE_AP_SUPPORT
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    StopAllSoftapManagers();
#endif
    }
    StopAllConcreteManagers();
}
} // namespace Wifi
} // namespace OHOS
