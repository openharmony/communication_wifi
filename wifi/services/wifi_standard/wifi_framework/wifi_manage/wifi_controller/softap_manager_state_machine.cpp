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

#include "softap_manager_state_machine.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_chip_hal_interface.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_hisysevent.h"
#include "wifi_settings.h"
#include "wifi_common_event_helper.h"
#include "wifi_country_code_manager.h"
#include "i_ap_service.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("SoftapManagerMachine");
int SoftapManagerMachine::mid{0};

SoftapManagerMachine::SoftapManagerMachine()
    : StateMachine("SoftapManagerMachine"), pDefaultState(nullptr), pIdleState(nullptr), pStartedState(nullptr)
{}

SoftapManagerMachine::~SoftapManagerMachine()
{
    WIFI_LOGE("SoftapManagerMachine::~SoftapManagerMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pIdleState);
    ParsePointer(pStartedState);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!ifaceName.empty()) {
        DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveApIface(ifaceName);
        ifaceName.clear();
        WifiSettings::GetInstance().SetApIfaceName("");
    }
#endif
}

/* --------------------------Initialization functions--------------------------*/
ErrCode SoftapManagerMachine::InitSoftapManagerMachine()
{
    WIFI_LOGE("Enter SoftapManagerMachine::InitSoftapManagerMachine.\n");
    if (!InitialStateMachine("SoftapManagerMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (InitSoftapManagerStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pIdleState);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

void SoftapManagerMachine::BuildStateTree()
{
    StatePlus(pDefaultState, nullptr);
    StatePlus(pIdleState, pDefaultState);
    StatePlus(pStartedState, pDefaultState);
}

ErrCode SoftapManagerMachine::InitSoftapManagerStates()
{
    int tmpErrNumber;

    WIFI_LOGE("Enter InitConcreteMangerStates\n");
    pDefaultState = new (std::nothrow) DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState);
    pIdleState = new (std::nothrow) IdleState(this);
    tmpErrNumber += JudgmentEmpty(pIdleState);
    pStartedState = new (std::nothrow) StartedState(this);
    tmpErrNumber += JudgmentEmpty(pStartedState);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitSoftapManagerStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode SoftapManagerMachine::RegisterCallback(const SoftApModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

SoftapManagerMachine::DefaultState::DefaultState(SoftapManagerMachine *softapManagerMachine)
    : State("DefaultState"), pSoftapManagerMachine(softapManagerMachine)
{}

SoftapManagerMachine::DefaultState::~DefaultState()
{}

void SoftapManagerMachine::DefaultState::GoInState()
{
    WIFI_LOGE("DefaultState GoInState function.\n");
}

void SoftapManagerMachine::DefaultState::GoOutState()
{
    WIFI_LOGE("DefaultState GoOutState function.\n");
}

bool SoftapManagerMachine::DefaultState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr || pSoftapManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    return true;
}

SoftapManagerMachine::IdleState::IdleState(SoftapManagerMachine *softapManagerMachine)
    : State("IdleState"), pSoftapManagerMachine(softapManagerMachine)
{}

SoftapManagerMachine::IdleState::~IdleState()
{}

void SoftapManagerMachine::IdleState::GoInState()
{
    WIFI_LOGE("IdleState GoInState function.\n");
}

void SoftapManagerMachine::IdleState::GoOutState()
{
    WIFI_LOGE("IdleState GoOutState function.\n");
}

bool SoftapManagerMachine::IdleState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("IdleState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case SOFTAP_CMD_START:
            HandleStartInIdleState(msg);
            break;
        case SOFTAP_CMD_STOP:
            pSoftapManagerMachine->StopSoftap();
            break;
        default:
            break;
    }
    return true;
}

void SoftapManagerMachine::IdleState::HandleStartInIdleState(InternalMessage *msg)
{
    mid = msg->GetParam2();
    ErrCode ret = pSoftapManagerMachine->AutoStartApService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        pSoftapManagerMachine->mcb.onStartFailure(mid);
        return;
    }
    pSoftapManagerMachine->SwitchState(pSoftapManagerMachine->pStartedState);
}

SoftapManagerMachine::StartedState::StartedState(SoftapManagerMachine *softapManagerMachine)
    : State("StartedState"), pSoftapManagerMachine(softapManagerMachine)
{}

SoftapManagerMachine::StartedState::~StartedState()
{}

void SoftapManagerMachine::StartedState::GoInState()
{
    WIFI_LOGE("StartedState GoInState function.\n");
}

void SoftapManagerMachine::StartedState::GoOutState()
{
    WIFI_LOGE("StartedState GoOutState function.\n");
}

bool SoftapManagerMachine::StartedState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("StartedState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case SOFTAP_CMD_STOP:
            pSoftapManagerMachine->StopSoftap();
            break;
        default:
            break;
    }
    return true;
}

void SoftapManagerMachine::StopSoftap()
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(mid);
    if (apState == WifiOprMidState::CLOSING || apState == WifiOprMidState::OPENING) {
        return;
    }
    ErrCode ret = AutoStopApService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Stop softap failed ret = %{public}d", ret);
    }
    SwitchState(pIdleState);
}

ErrCode SoftapManagerMachine::TryToStartApService(int id)
{
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_AP) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_AP);
            break;
        }
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(id);
        if (pService == nullptr) {
            WIFI_LOGE("Instance get hotspot service is null!");
            break;
        }
        errCode = pService->RegisterApServiceCallbacks(
            WifiManager::GetInstance().GetWifiHotspotManager()->GetApCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register ap service callback failed!");
            break;
        }
        errCode = pService->RegisterApServiceCallbacks(WifiCountryCodeManager::GetInstance().GetApCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("WifiCountryCodeManager Register ap service callback failed! ret %{public}d!",
                static_cast<int>(errCode));
            break;
        }
        errCode = pService->EnableHotspot();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable ap failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (false);
    return errCode;
}

ErrCode SoftapManagerMachine::AutoStartApService(int id)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(id);
    WIFI_LOGE("AutoStartApService, current ap state:%{public}d", apState);
    if (apState != WifiOprMidState::CLOSED) {
        if (apState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_FAILED;
        } else {
            return WIFI_OPT_SUCCESS;
        }
    }
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateApIface(
        std::bind(&SoftapManagerMachine::IfaceDestoryCallback, this, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("AutoStartApService, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SetApIfaceName(ifaceName);
#endif
    if (!WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::OPENING, 0)) {
        WIFI_LOGE("AutoStartApService, set ap mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = TryToStartApService(id);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, mid);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, mid);
        return errCode;
    }
    WifiManager::GetInstance().GetWifiHotspotManager()->StopUnloadApSaTimer();
    return WIFI_OPT_SUCCESS;
}

ErrCode SoftapManagerMachine::AutoStopApService(int id)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(id);
    WIFI_LOGE("AutoStopApService, current ap state:%{public}d", apState);
    if (apState != WifiOprMidState::RUNNING) {
        if (apState == WifiOprMidState::OPENING) {
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }

    if (!WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, mid)) {
        WIFI_LOGE("AutoStopApService,set ap mid state closing failed!");
        return WIFI_OPT_SUCCESS;
    }

    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(id);
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopApService, Instance get hotspot service is null!");
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, mid);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, mid);
        return WIFI_OPT_SUCCESS;
    }

    ErrCode ret = pService->DisableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable ap failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING, mid);
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

void SoftapManagerMachine::IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    WIFI_LOGI("IfaceDestoryCallback, ifaceName:%{public}s, ifaceType:%{public}d",
        destoryIfaceName.c_str(), createIfaceType);
    if (destoryIfaceName == ifaceName) {
        ifaceName.clear();
        WifiSettings::GetInstance().SetApIfaceName("");
    }

    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->SendMessage(CMD_AP_REMOVED, createIfaceType, mid);
    return;
}

} // namespace Wifi
} // namespace OHOS