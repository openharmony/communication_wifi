/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "multi_sta_state_machine.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_settings.h"
#include "wifi_common_event_helper.h"
#include "wifi_service_scheduler.h"
#include "i_ap_service.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("MultiStaStateMachine");
int MultiStaStateMachine::mid{0};

MultiStaStateMachine::MultiStaStateMachine()
    : StateMachine("MultiStaStateMachine"), pDefaultState(nullptr), pIdleState(nullptr), pStartedState(nullptr)
{}

MultiStaStateMachine::~MultiStaStateMachine()
{
    WIFI_LOGE("MultiStaStateMachine::~MultiStaStateMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pIdleState);
    ParsePointer(pStartedState);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!ifaceName.empty()) {
        WIFI_LOGW("~MultiStaStateMachine ifaceName: %{public}s,instId:%{public}d",
            ifaceName.c_str(), mid);
        HalDeviceManager::GetInstance().RemoveStaIface(ifaceName);
        ifaceName.clear();
        WifiServiceScheduler::GetInstance().ClearStaIfaceNameMap(mid);
        WifiConfigCenter::GetInstance().SetStaIfaceName("", mid);
    }
#endif
}

/* --------------------------Initialization functions--------------------------*/
ErrCode MultiStaStateMachine::InitMultiStaStateMachine()
{
    WIFI_LOGI("Enter MultiStaStateMachine::InitMultiStaStateMachine.\n");
    if (!InitialStateMachine("MultiStaStateMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (InitMultiStaStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pIdleState);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

void MultiStaStateMachine::BuildStateTree()
{
    StatePlus(pDefaultState, nullptr);
    StatePlus(pIdleState, pDefaultState);
    StatePlus(pStartedState, pDefaultState);
}

ErrCode MultiStaStateMachine::InitMultiStaStates()
{
    int tmpErrNumber;

    WIFI_LOGE("Enter MultiStaStateMachine\n");
    pDefaultState = new (std::nothrow) DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState);
    pIdleState = new (std::nothrow) IdleState(this);
    tmpErrNumber += JudgmentEmpty(pIdleState);
    pStartedState = new (std::nothrow) StartedState(this);
    tmpErrNumber += JudgmentEmpty(pStartedState);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitMultiStaStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode MultiStaStateMachine::RegisterCallback(const MultiStaModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

MultiStaStateMachine::DefaultState::DefaultState(MultiStaStateMachine *multiStaStateMachine)
    : State("DefaultState"), pMultiStaStateMachine(multiStaStateMachine)
{}

MultiStaStateMachine::DefaultState::~DefaultState()
{}

void MultiStaStateMachine::DefaultState::GoInState()
{
    WIFI_LOGE("DefaultState GoInState function.\n");
}

void MultiStaStateMachine::DefaultState::GoOutState()
{
    WIFI_LOGE("DefaultState GoOutState function.\n");
}

bool MultiStaStateMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pMultiStaStateMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    return true;
}

MultiStaStateMachine::IdleState::IdleState(MultiStaStateMachine *multiStaStateMachine)
    : State("IdleState"), pMultiStaStateMachine(multiStaStateMachine)
{}

MultiStaStateMachine::IdleState::~IdleState()
{}

void MultiStaStateMachine::IdleState::GoInState()
{
    WIFI_LOGE("IdleState GoInState function.\n");
}

void MultiStaStateMachine::IdleState::GoOutState()
{
    WIFI_LOGE("IdleState GoOutState function.\n");
}

bool MultiStaStateMachine::IdleState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGI("IdleState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case MULTI_STA_CMD_START:
            HandleStartInIdleState(msg);
            break;
        case MULTI_STA_CMD_STARTED:
            pMultiStaStateMachine->SwitchState(pMultiStaStateMachine->pStartedState);
            break;
        default:
            break;
    }
    return true;
}

void MultiStaStateMachine::IdleState::HandleStartInIdleState(InternalMessagePtr msg)
{
    mid = msg->GetParam2();
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartWifi2Service(mid, pMultiStaStateMachine->ifaceName);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("IdelState start wifi2 fail.\n");
        pMultiStaStateMachine->mcb.onStartFailure(mid);
        return;
    }
}

MultiStaStateMachine::StartedState::StartedState(MultiStaStateMachine *multiStaStateMachine)
    : State("StartedState"), pMultiStaStateMachine(multiStaStateMachine)
{}

MultiStaStateMachine::StartedState::~StartedState()
{}

void MultiStaStateMachine::StartedState::GoInState()
{
    WIFI_LOGE("StartedState GoInState function.\n");
}

void MultiStaStateMachine::StartedState::GoOutState()
{
    WIFI_LOGE("StartedState GoOutState function.\n");
}

bool MultiStaStateMachine::StartedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("StartedState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    ErrCode ret = WIFI_OPT_FAILED;
    switch (msg->GetMessageName()) {
        case MULTI_STA_CMD_STOP:
            ret = WifiServiceScheduler::GetInstance().AutoStopWifi2Service(mid);
            if (ret != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("AutoStopWifi2Service fail.\n");
            }
            pMultiStaStateMachine->mcb.onStopped(mid);
            break;
        default:
            break;
    }
    return true;
}

} // namespace Wifi
} // namespace OHOS