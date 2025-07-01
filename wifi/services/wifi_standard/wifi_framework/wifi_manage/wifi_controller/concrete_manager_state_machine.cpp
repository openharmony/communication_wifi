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

#include "concrete_manager_state_machine.h"
#include "wifi_controller_define.h"
#include "wifi_manager.h"
#include "wifi_config_center.h"
#include "wifi_internal_msg.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_event_helper.h"
#include "wifi_service_scheduler.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_country_code_manager.h"
#include "wifi_common_util.h"
#include "app_network_speed_limit_service.h"
#include "wifi_internal_event_dispatcher.h"
#else
#include "wifi_internal_event_dispatcher_lite.h"
#endif
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("ConcreteMangerMachine");
int ConcreteMangerMachine::mTargetRole{static_cast<int>(ConcreteManagerRole::ROLE_UNKNOW)};
using TimeOutCallback = std::function<void()>;
int ConcreteMangerMachine::mid{0};
std::string ConcreteMangerMachine::ifaceName{""};

ConcreteMangerMachine::ConcreteMangerMachine()
    : StateMachine("ConcreteMangerMachine"), pDefaultState(nullptr), pIdleState(nullptr), pConnectState(nullptr),
      pScanonlyState(nullptr), pSemiActiveState(nullptr)
{}

ConcreteMangerMachine::~ConcreteMangerMachine()
{
    WIFI_LOGE("~ConcreteMangerMachine");
    StopTimer(CONCRETE_CMD_STOP_MACHINE_RETRY);
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pIdleState);
    ParsePointer(pConnectState);
    ParsePointer(pScanonlyState);
    ParsePointer(pSemiActiveState);
    WIFI_LOGE("set wifi stoping state is false");
    WifiConfigCenter::GetInstance().SetWifiStopState(false);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!ifaceName.empty()) {
        WIFI_LOGW("destroy ConcreteMangerMachine RemoveStaIface ifaceName:%{public}s, instId:%{public}d",
            ifaceName.c_str(), mid);
        HalDeviceManager::GetInstance().RemoveStaIface(ifaceName);
        ifaceName.clear();
        WifiServiceScheduler::GetInstance().ClearStaIfaceNameMap(mid);
        WifiConfigCenter::GetInstance().SetStaIfaceName("", mid);
    }
#endif
}

/* --------------------------Initialization functions--------------------------*/
ErrCode ConcreteMangerMachine::InitConcreteMangerMachine()
{
    WIFI_LOGE("Enter InitConcreteMangerMachine.\n");
    if (!InitialStateMachine("ConcreteManagerMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetWifiStopState(false);
    if (InitConcreteMangerStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pIdleState);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

void ConcreteMangerMachine::BuildStateTree()
{
    StatePlus(pDefaultState, nullptr);
    StatePlus(pIdleState, pDefaultState);
    StatePlus(pConnectState, pDefaultState);
    StatePlus(pScanonlyState, pDefaultState);
    StatePlus(pSemiActiveState, pDefaultState);
}

ErrCode ConcreteMangerMachine::InitConcreteMangerStates()
{
    int tmpErrNumber;

    WIFI_LOGE("Enter InitConcreteMangerStates.\n");
    pDefaultState = new (std::nothrow) DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState);
    pIdleState = new (std::nothrow) IdleState(this);
    tmpErrNumber += JudgmentEmpty(pIdleState);
    pConnectState = new (std::nothrow) ConnectState(this);
    tmpErrNumber += JudgmentEmpty(pConnectState);
    pScanonlyState = new (std::nothrow) ScanonlyState(this);
    tmpErrNumber += JudgmentEmpty(pScanonlyState);
    pSemiActiveState = new (std::nothrow) SemiActiveState(this);
    tmpErrNumber += JudgmentEmpty(pSemiActiveState);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitConcreteMangerStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void ConcreteMangerMachine::RegisterCallback(ConcreteModeCallback &callback)
{
    mcb = callback;
}

void ConcreteMangerMachine::SetTargetRole(ConcreteManagerRole role)
{
    WIFI_LOGI("SetTargetRole:%{public}d", static_cast<int>(role));
    mTargetRole = static_cast<int>(role);
}

ConcreteMangerMachine::DefaultState::DefaultState(ConcreteMangerMachine *concreteMangerMachine)
    : State("DefaultState"), pConcreteMangerMachine(concreteMangerMachine)
{}

ConcreteMangerMachine::DefaultState::~DefaultState()
{}

void ConcreteMangerMachine::DefaultState::GoInState()
{
    WIFI_LOGE("DefaultState  GoInState function.\n");
}

void ConcreteMangerMachine::DefaultState::GoOutState()
{
    WIFI_LOGE("DefaultState  GoOutState function.\n");
}

bool ConcreteMangerMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pConcreteMangerMachine == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGE("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_STOP:
            ret = EXECUTED;
            pConcreteMangerMachine->CheckAndContinueToStopWifi(msg);
            break;
        case CONCRETE_CMD_STA_STOP:
            ret = EXECUTED;
            pConcreteMangerMachine->HandleStaStop();
            break;
        case CONCRETE_CMD_SET_TARGET_ROLE: {
            ret = EXECUTED;
            int role = msg->GetParam1();
            ConcreteManagerRole targetRole = static_cast<ConcreteManagerRole>(role);
            pConcreteMangerMachine->SetTargetRole(targetRole);
            break;
        }
        case CONCRETE_CMD_STOP_MACHINE_RETRY: {
            ret = EXECUTED;
            WIFI_LOGI("CONCRETE_CMD_STOP_MACHINE_RETRY");
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->HandleStopConcretRetry();
            break;
        }
        default:
            WIFI_LOGI("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

ConcreteMangerMachine::IdleState::IdleState(ConcreteMangerMachine *concreteMangerMachine)
    : State("IdleState"), pConcreteMangerMachine(concreteMangerMachine)
{}

ConcreteMangerMachine::IdleState::~IdleState()
{}

void ConcreteMangerMachine::IdleState::GoInState()
{
    WIFI_LOGE("IdleState  GoInState function.\n");
}

void ConcreteMangerMachine::IdleState::GoOutState()
{
    WIFI_LOGE("IdleState  GoOutState function.\n");
}

bool ConcreteMangerMachine::IdleState::ExecuteStateMsg(InternalMessagePtr msg) __attribute__((no_sanitize("cfi")))
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGE("IdleState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_START:
            ret = EXECUTED;
            HandleStartInIdleState(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            ret = EXECUTED;
            HandleSwitchToConnectMode(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            ret = EXECUTED;
            HandleSwitchToScanOnlyMode(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            ret = EXECUTED;
            HandleSwitchToSemiActiveMode(msg);
            break;
        default:
            break;
    }
    return ret;
}

void ConcreteMangerMachine::IdleState::HandleSwitchToConnectMode(InternalMessagePtr msg)
{
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartStaService(mid, ifaceName);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
}

void ConcreteMangerMachine::IdleState::HandleSwitchToScanOnlyMode(InternalMessagePtr msg)
{
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartScanOnly(mid, ifaceName);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
}

void ConcreteMangerMachine::IdleState::HandleSwitchToSemiActiveMode(InternalMessagePtr msg)
{
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartSemiStaService(mid, ifaceName);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pSemiActiveState);
}

void ConcreteMangerMachine::IdleState::HandleStartInIdleState(InternalMessagePtr msg)
{
    mid = msg->GetParam1();
    WIFI_LOGI("HandleStartInIdleState mTargetRole:%{public}d mid:%{public}d", mTargetRole, mid);
    ErrCode res = WifiServiceScheduler::GetInstance().AutoStartScanOnly(mid, ifaceName);
    if (res != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartStaService(mid, ifaceName);
        if (ret != WIFI_OPT_SUCCESS) {
            WifiConfigCenter::GetInstance().SetWifiStopState(true);
            pConcreteMangerMachine->mcb.onStartFailure(mid);
            return;
        }
        pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        WIFI_LOGI("HandleStartInIdleState, current role is %{public}d, start scan only success.", mTargetRole);
        pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartSemiStaService(mid, ifaceName);
        if (ret != WIFI_OPT_SUCCESS) {
            WifiConfigCenter::GetInstance().SetWifiStopState(true);
            pConcreteMangerMachine->mcb.onStartFailure(mid);
            return;
        }
        pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pSemiActiveState);
    } else {
        WIFI_LOGE("idlestate start role is error");
    }
}

ConcreteMangerMachine::ConnectState::ConnectState(ConcreteMangerMachine *concreteMangerMachine)
    : State("ConnectState"), pConcreteMangerMachine(concreteMangerMachine)
{}

ConcreteMangerMachine::ConnectState::~ConnectState()
{}

void ConcreteMangerMachine::ConnectState::GoInState()
{
    WIFI_LOGE("ConnectState  GoInState function.\n");
}

void ConcreteMangerMachine::ConnectState::GoOutState()
{
    WIFI_LOGE("ConnectState  GoOutState function.\n");
}

bool ConcreteMangerMachine::ConnectState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("ConnectState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            ret = EXECUTED;
            SwitchScanOnlyInConnectState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            ret = EXECUTED;
            SwitchSemiActiveInConnectState();
            break;
        default:
            break;
    }
    return ret;
}

void ConcreteMangerMachine::ConnectState::SwitchScanOnlyInConnectState()
{
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("stop sta failed ret =%{public}d \n", ret);
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
}

void ConcreteMangerMachine::ConnectState::SwitchSemiActiveInConnectState()
{
    ErrCode ret = pConcreteMangerMachine->SwitchSemiFromEnable();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("switch semi wifi failed ret =%{public}d \n", ret);
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pSemiActiveState);
}

ConcreteMangerMachine::ScanonlyState::ScanonlyState(ConcreteMangerMachine *concreteMangerMachine)
    : State("ScanonlyState"), pConcreteMangerMachine(concreteMangerMachine)
{}

ConcreteMangerMachine::ScanonlyState::~ScanonlyState()
{}

void ConcreteMangerMachine::ScanonlyState::GoInState()
{
    WIFI_LOGE("ScanonlyState  GoInState function.\n");
}

void ConcreteMangerMachine::ScanonlyState::GoOutState()
{
    WIFI_LOGE("ScanonlyState  GoOutState function.\n");
}

bool ConcreteMangerMachine::ScanonlyState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGE("ScanonlyState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            ret = EXECUTED;
            SwitchConnectInScanOnlyState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            ret = EXECUTED;
            SwitchSemiActiveInScanOnlyState();
            break;
        default:
            break;
    }
    return ret;
}

void ConcreteMangerMachine::ScanonlyState::SwitchConnectInScanOnlyState()
{
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartStaService(mid, ifaceName);
    if (ret != WIFI_OPT_SUCCESS) {
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
}

void ConcreteMangerMachine::ScanonlyState::SwitchSemiActiveInScanOnlyState()
{
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartSemiStaService(mid, ifaceName);
    if (ret != WIFI_OPT_SUCCESS) {
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pSemiActiveState);
}

ConcreteMangerMachine::SemiActiveState::SemiActiveState(ConcreteMangerMachine *concreteMangerMachine)
    : State("SemiActiveState"), pConcreteMangerMachine(concreteMangerMachine)
{}

ConcreteMangerMachine::SemiActiveState::~SemiActiveState()
{}

void ConcreteMangerMachine::SemiActiveState::GoInState()
{
    WIFI_LOGI("SemiActiveState  GoInState function.\n");
}

void ConcreteMangerMachine::SemiActiveState::GoOutState()
{
    WIFI_LOGI("SemiActiveState  GoOutState function.\n");
}

bool ConcreteMangerMachine::SemiActiveState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("SemiActiveState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            ret = EXECUTED;
            SwitchConnectInSemiActiveState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            ret = EXECUTED;
            SwitchScanOnlyInSemiActiveState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            ret = EXECUTED;
            if (pConcreteMangerMachine->mTargetRole ==
                static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
                WIFI_LOGI("switch ROLE_CLIENT_STA_SEMI_ACTIVE");
                WifiManager::GetInstance().GetWifiScanManager()->CheckAndStopScanService(mid);
            } else {
                WIFI_LOGI("switch ROLE_CLIENT_MIX_SEMI_ACTIVE");
                WifiServiceScheduler::GetInstance().AutoStartScanOnly(mid, ifaceName);
            }
            WifiManager::GetInstance().GetWifiTogglerManager()->StopSemiWifiToggledTimer();
            break;
        default:
            break;
    }
    return ret;
}

void ConcreteMangerMachine::SemiActiveState::SwitchConnectInSemiActiveState()
{
    WifiServiceScheduler::GetInstance().AutoStartScanOnly(mid, ifaceName);
    ErrCode ret = pConcreteMangerMachine->SwitchEnableFromSemi();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SemiActiveState SwitchEnableFromSemi failed");
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
}

void ConcreteMangerMachine::SemiActiveState::SwitchScanOnlyInSemiActiveState()
{
    WIFI_LOGI("SwitchScanOnlyInSemiActiveState");
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
}

bool ConcreteMangerMachine::HandleCommonMessage(InternalMessagePtr msg)
{
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_STA_STOP:
            HandleStaStop();
            return true;
        case CONCRETE_CMD_STA_START:
            HandleStaStart();
            return true;
        case CONCRETE_CMD_STOP:
            DelayMessage(msg);
            SwitchState(pDefaultState);
            return true;
        case CONCRETE_CMD_STA_SEMI_ACTIVE:
            HandleStaSemiActive();
            return true;
        case CONCRETE_CMD_STA_REMOVED:
            ClearIfaceName();
            return true;
        case CONCRETE_CMD_RESET_STA:
            HandleSelfcureResetSta(msg);
            return true;
        default:
            return false;
    }
}

void ConcreteMangerMachine::HandleStaStop()
{
    if (WifiConfigCenter::GetInstance().GetWifiStopState()) {
        WIFI_LOGE("Sta stoped remove manager.");
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopScanOnly(mid, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop scanonly failed ret = %{public}d", ret);
        }
        StartTimer(CONCRETE_CMD_STOP_MACHINE_RETRY, CONCRETE_STOP_TIMEOUT);
        return ReportClose();
    }
    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
#ifdef HDI_CHIP_INTERFACE_SUPPORT
        HalDeviceManager::GetInstance().SetNetworkUpDown(
            WifiConfigCenter::GetInstance().GetStaIfaceName(), true);
#endif
        WIFI_LOGI("HandleStaStop, current role is %{public}d, sta stop success.", mTargetRole);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartStaService(mid, ifaceName);
        if (ret != WIFI_OPT_SUCCESS) {
            mcb.onStartFailure(mid);
            return;
        }
        SwitchState(pConnectState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStartSemiStaService(mid, ifaceName);
        if (ret != WIFI_OPT_SUCCESS) {
            mcb.onStartFailure(mid);
            return;
        }
        SwitchState(pSemiActiveState);
    } else {
        WIFI_LOGE("Now targetrole is unknow, stop concrete.");
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopScanOnly(mid, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop scanonly failed ret = %{public}d", ret);
        }
        return ReportClose();
    }
}

void ConcreteMangerMachine::ReportClose()
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!ifaceName.empty()) {
        mcb.onStopped(mid);
    } else {
        mcb.onRemoved(mid);
    }
#else
    mcb.onStopped(mid);
#endif
}

void ConcreteMangerMachine::HandleStaStart()
{
    ErrCode ret;

    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
        SwitchState(pScanonlyState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        WIFI_LOGI("HandleStaStart, current role is %{public}d, sta start success.", mTargetRole);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        ret = SwitchSemiFromEnable();
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("switch semi wifi failed ret = %{public}d", ret);
        }
        SwitchState(pSemiActiveState);
    } else {
        WIFI_LOGE("Now targetrole is unknow.");
        ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
    }
}

void ConcreteMangerMachine::HandleStaSemiActive()
{
    ErrCode ret;

    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ret = SwitchEnableFromSemi();
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("switch enable failed ret = %{public}d", ret);
            mcb.onStartFailure(mid);
            return;
        }
        WifiServiceScheduler::GetInstance().AutoStartScanOnly(mid, ifaceName);
        SwitchState(pConnectState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
        SwitchState(pScanonlyState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE)) {
        WifiManager::GetInstance().GetWifiScanManager()->CheckAndStartScanService(mid);
        WIFI_LOGI("HandleStaSemiActive, current role is %{public}d, sta semi start success.", mTargetRole);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        WifiManager::GetInstance().GetWifiScanManager()->CheckAndStopScanService(mid);
        WIFI_LOGI("HandleStaSemiActive, current role is %{public}d, sta semi start success.", mTargetRole);
    } else {
        WIFI_LOGE("Now targetrole is unknow.");
        ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
    }
}

ErrCode ConcreteMangerMachine::SwitchSemiFromEnable()
{
    auto detailState = WifiConfigCenter::GetInstance().GetWifiDetailState(mid);
    WIFI_LOGI("SwitchSemiFromEnable: current sta detailState:%{public}d", detailState);
    if (detailState == WifiDetailState::STATE_SEMI_ACTIVE || detailState == WifiDetailState::STATE_SEMI_ACTIVATING) {
        return WIFI_OPT_SUCCESS;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(mid);
    if (pService == nullptr) {
        WIFI_LOGE("SwitchSemiFromEnable, Instance get sta service is null!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, mid);
        return WIFI_OPT_FAILED;
    }
    WifiServiceScheduler::GetInstance().DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_OPENING, mid);
    ErrCode ret = pService->DisableStaService();
    if (ret != static_cast<int>(WIFI_OPT_SUCCESS)) {
        WIFI_LOGE("DisableStaService failed!");
        return WIFI_OPT_FAILED;
    }
    WifiServiceScheduler::GetInstance().DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_SUCCEED, mid);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaSemiActive(mid);
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::SwitchEnableFromSemi()
{
    auto detailState = WifiConfigCenter::GetInstance().GetWifiDetailState(mid);
    WIFI_LOGI("SwitchEnableFromSemi, current sta detailState:%{public}d", detailState);
    if (detailState == WifiDetailState::STATE_ACTIVATED) {
        auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
        ins->HandleStaStartSuccess(mid);
        return WIFI_OPT_SUCCESS;
    }
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(mid);
    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::OPENING, mid)) {
        WIFI_LOGE("SwitchEnableFromSemi, set wifi mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = WIFI_OPT_FAILED;
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(mid);
    if (pService == nullptr) {
        WIFI_LOGE("Get %{public}s service failed!", WIFI_SERVICE_STA);
        return WIFI_OPT_FAILED;
    }
    WifiServiceScheduler::GetInstance().DispatchWifiOpenRes(OperateResState::OPEN_WIFI_OPENING, mid);
    errCode = pService->EnableStaService();
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Service enable sta failed ,ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
    WifiServiceScheduler::GetInstance().DispatchWifiOpenRes(OperateResState::OPEN_WIFI_SUCCEED, mid);
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, mid);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaStartSuccess(mid);
    return WIFI_OPT_SUCCESS;
}

void ConcreteMangerMachine::CheckAndContinueToStopWifi(InternalMessagePtr msg)
{
    if (WifiConfigCenter::GetInstance().GetWifiStopState()) {
        WIFI_LOGE("CheckAndContinueToStopWifi: wifi is stoping");
        return;
    }

    mTargetRole = static_cast<int>(ConcreteManagerRole::ROLE_UNKNOW);
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(mid);
    auto detailState = WifiConfigCenter::GetInstance().GetWifiDetailState(mid);
    WIFI_LOGI("CheckAndContinueToStopWifi: current sta state: %{public}d detailState:%{public}d", staState,
        detailState);
    if (detailState != WifiDetailState::STATE_SEMI_ACTIVE && detailState != WifiDetailState::STATE_SEMI_ACTIVATING &&
        (staState == WifiOprMidState::CLOSING || staState == WifiOprMidState::OPENING)) {
        return;
    }

    WifiConfigCenter::GetInstance().SetWifiStopState(true);
    WIFI_LOGI("Set WifiStopState is true.");
    if (staState == WifiOprMidState::RUNNING || detailState == WifiDetailState::STATE_SEMI_ACTIVE ||
        detailState == WifiDetailState::STATE_SEMI_ACTIVATING) {
        ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("stop sta failed in timer ret = %{public}d", ret);
            WifiConfigCenter::GetInstance().SetWifiStopState(false);
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->HandleStaClose(mid);
        }
    } else {
        auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
        ins->HandleStaClose(mid);
    }
}

void ConcreteMangerMachine::ClearIfaceName()
{
    ifaceName.clear();
}

void ConcreteMangerMachine::HandleSelfcureResetSta(InternalMessagePtr msg)
{
    int id = msg->GetParam1();
    ErrCode ret = WifiServiceScheduler::GetInstance().AutoStopStaService(id, RESET_STA_TYPE_SELFCURE);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("HandleSelfcureResetSta AutoStopStaService failed ret =%{public}d \n", ret);
        return;
    }
    ret = WifiServiceScheduler::GetInstance().AutoStartStaService(id, ifaceName, RESET_STA_TYPE_SELFCURE);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("HandleSelfcureResetSta AutoStartStaService failed ret =%{public}d \n", ret);
        return;
    }
}
} // namespace Wifi
} // namespace OHOS
