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
#include "wifi_internal_event_dispatcher.h"
#include "wifi_hisysevent.h"
#include "wifi_settings.h"
#include "wifi_common_event_helper.h"
#include "wifi_country_code_manager.h"
#include "wifi_service_scheduler.h"
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
        HalDeviceManager::GetInstance().RemoveApIface(ifaceName);
        ifaceName.clear();
        WifiServiceScheduler::GetInstance().ClearSoftApIfaceNameMap(mid);
        WifiConfigCenter::GetInstance().SetApIfaceName("");
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

bool SoftapManagerMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
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

bool SoftapManagerMachine::IdleState::ExecuteStateMsg(InternalMessagePtr msg)
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

void SoftapManagerMachine::IdleState::HandleStartInIdleState(InternalMessagePtr msg)
{
    int hotspotMode = msg->GetParam1();
    mid = msg->GetParam2();
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartApService(mid,
        pSoftapManagerMachine->ifaceName, hotspotMode);
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

bool SoftapManagerMachine::StartedState::ExecuteStateMsg(InternalMessagePtr msg)
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
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopApService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Stop softap failed ret = %{public}d", ret);
    }
    SwitchState(pIdleState);
}
} // namespace Wifi
} // namespace OHOS