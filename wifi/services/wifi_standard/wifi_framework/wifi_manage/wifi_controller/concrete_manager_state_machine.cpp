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
        DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveStaIface(ifaceName);
        ifaceName.clear();
        WifiConfigCenter::GetInstance().SetStaIfaceName("");
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

bool ConcreteMangerMachine::DefaultState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr || pConcreteMangerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    return true;
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

bool ConcreteMangerMachine::IdleState::ExecuteStateMsg(InternalMessage *msg) __attribute__((no_sanitize("cfi")))
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("IdleState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_START:
            HandleStartInIdleState(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            HandleSwitchToConnectMode(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            HandleSwitchToScanOnlyMode(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            HandleSwitchToSemiActiveMode(msg);
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::IdleState::HandleSwitchToConnectMode(InternalMessage *msg)
{
    ErrCode ret = pConcreteMangerMachine->AutoStartStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
}

void ConcreteMangerMachine::IdleState::HandleSwitchToScanOnlyMode(InternalMessage *msg)
{
    ErrCode ret = AutoStartScanOnly(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
}

void ConcreteMangerMachine::IdleState::HandleSwitchToSemiActiveMode(InternalMessage *msg)
{
    ErrCode ret = pConcreteMangerMachine->AutoStartSemiStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
}

void ConcreteMangerMachine::IdleState::HandleStartInIdleState(InternalMessage *msg)
{
    mid = msg->GetParam1();
    WIFI_LOGI("HandleStartInIdleState targetRole:%{public}d mid:%{public}d", mTargetRole, mid);
    ErrCode res = AutoStartScanOnly(mid);
    if (res != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ErrCode ret = pConcreteMangerMachine->AutoStartStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WifiConfigCenter::GetInstance().SetWifiStopState(true);
            pConcreteMangerMachine->mcb.onStartFailure(mid);
            return;
        }
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        WIFI_LOGI("HandleStartInIdleState, current role is %{public}d, start scan only success.", mTargetRole);
        pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        ErrCode ret = pConcreteMangerMachine->AutoStartSemiStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WifiConfigCenter::GetInstance().SetWifiStopState(true);
            pConcreteMangerMachine->mcb.onStartFailure(mid);
            return;
        }
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

bool ConcreteMangerMachine::ConnectState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("ConnectState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            SwitchScanOnlyInConnectState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            SwitchSemiActiveInConnectState();
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::ConnectState::SwitchScanOnlyInConnectState()
{
    ErrCode ret = pConcreteMangerMachine->AutoStopStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("stop sta failed ret =%{public}d \n", ret);
    }
}

void ConcreteMangerMachine::ConnectState::SwitchSemiActiveInConnectState()
{
    ErrCode ret = pConcreteMangerMachine->SwitchSemiFromEnable();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("switch semi wifi failed ret =%{public}d \n", ret);
    }
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

bool ConcreteMangerMachine::ScanonlyState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("ScanonlyState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            SwitchConnectInScanOnlyState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            SwitchSemiActiveInScanOnlyState();
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::ScanonlyState::SwitchConnectInScanOnlyState()
{
    ErrCode ret = pConcreteMangerMachine->AutoStartStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
}

void ConcreteMangerMachine::ScanonlyState::SwitchSemiActiveInScanOnlyState()
{
    ErrCode ret = pConcreteMangerMachine->AutoStartSemiStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
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

bool ConcreteMangerMachine::SemiActiveState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGI("SemiActiveState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            SwitchConnectInSemiActiveState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            SwitchScanOnlyInSemiActiveState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE:
            if (pConcreteMangerMachine->mTargetRole ==
                static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
                WIFI_LOGI("switch ROLE_CLIENT_STA_SEMI_ACTIVE");
                AutoStopScanOnly(mid, false);
            } else {
                WIFI_LOGI("switch ROLE_CLIENT_MIX_SEMI_ACTIVE");
                AutoStartScanOnly(mid);
            }
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::SemiActiveState::SwitchConnectInSemiActiveState()
{
    AutoStartScanOnly(mid);
    ErrCode ret = pConcreteMangerMachine->SwitchEnableFromSemi();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SemiActiveState SwitchEnableFromSemi failed");
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
}

void ConcreteMangerMachine::SemiActiveState::SwitchScanOnlyInSemiActiveState()
{
    WIFI_LOGI("SwitchScanOnlyInSemiActiveState");
    ErrCode ret = pConcreteMangerMachine->AutoStopStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
    }
}

bool ConcreteMangerMachine::HandleCommonMessage(InternalMessage *msg)
{
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_STA_STOP:
            HandleStaStop();
            return true;
        case CONCRETE_CMD_STA_START:
            HandleStaStart();
            return true;
        case CONCRETE_CMD_STOP:
            checkAndContinueToStopWifi(msg);
            return true;
        case CONCRETE_CMD_STA_SEMI_ACTIVE:
            HandleStaSemiActive();
            return true;
        default:
            return false;
    }
}

#ifdef FEATURE_SELF_CURE_SUPPORT
ErrCode ConcreteMangerMachine::StartSelfCureService(int instId)
{
    if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_SELFCURE) < 0) {
        WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_SELFCURE);
        return WIFI_OPT_FAILED;
    }
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId);
    if (pSelfCureService == nullptr) {
        WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_SELFCURE);
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = pSelfCureService->InitSelfCureService();
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Service enable self cure failed, ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("Get %{public}s service failed!", WIFI_SERVICE_STA);
        return WIFI_OPT_FAILED;
    }
    errCode = pService->RegisterStaServiceCallback(pSelfCureService->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SelfCure register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
#endif

ErrCode ConcreteMangerMachine::InitStaService(IStaService *pService)
{
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr");
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = pService->RegisterStaServiceCallback(
        WifiManager::GetInstance().GetWifiStaManager()->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
    errCode = pService->RegisterStaServiceCallback(WifiManager::GetInstance().GetWifiScanManager()->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("WifiScanManager register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    errCode = pService->RegisterStaServiceCallback(WifiCountryCodeManager::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("wifiCountryCodeManager register sta service callback failed, ret=%{public}d!",
            static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }

    errCode = pService->RegisterStaServiceCallback(AppNetworkSpeedLimitService::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AppNetworkSpeedLimitService register sta service callback failed, ret=%{public}d!",
            static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::PreStartWifi(int instId)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateStaIface(
        std::bind(ConcreteMangerMachine::IfaceDestoryCallback, std::placeholders::_1, std::placeholders::_2),
        std::bind(ConcreteMangerMachine::OnRssiReportCallback, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("PreStartWifi, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetStaIfaceName(ifaceName);
#endif
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::OPENING, instId)) {
        WIFI_LOGE("PreStartWifi, set wifi mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::PostStartWifi(int instId)
{
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_STA) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }
        if (InitStaService(pService) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitStaService failed!");
            break;
        }
#ifdef FEATURE_SELF_CURE_SUPPORT
        if (StartSelfCureService(instId) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("StartSelfCureService failed!");
            break;
        }
#endif
        errCode = pService->EnableStaService();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Service enable sta failed ,ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
#ifdef FEATURE_P2P_SUPPORT
    errCode = WifiManager::GetInstance().GetWifiP2pManager()->AutoStartP2pService();
    if (errCode != WIFI_OPT_SUCCESS && errCode != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
        WIFI_LOGE("AutoStartStaService, AutoStartP2pService failed!");
    }
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::AutoStartSemiStaService(int instId)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartSemiStaService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::SEMI_ACTIVE) {
        return WIFI_OPT_SUCCESS;
    }
    if (PreStartWifi(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_OPENING, instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName());
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartSemiStaService start wifi fail.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(staState));
        return WIFI_OPT_FAILED;
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, instId);
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_SUCCEED, instId);
    if (PostStartWifi(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    HandleStaSemiActive();
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::AutoStartStaService(int instId)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartStaService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::RUNNING) {
        return WIFI_OPT_SUCCESS;
    }
    if (PreStartWifi(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_OPENING, instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName());
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartStaService start wifi fail.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::OPEN_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(staState));
        return WIFI_OPT_FAILED;
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, instId);
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_SUCCEED, instId);
    if (PostStartWifi(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    HandleStaStart();
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::AutoStopStaService(int instId)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStopStaService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::CLOSED) {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ret = WIFI_OPT_FAILED;
#ifdef FEATURE_P2P_SUPPORT
    ret = WifiManager::GetInstance().GetWifiP2pManager()->AutoStopP2pService();
    if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED) {
        WIFI_LOGE("AutoStopStaService,AutoStopP2pService failed!");
    }
#endif

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGE("AutoStopStaService,set wifi mid state closing failed!");
        return WIFI_OPT_FAILED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopStaService, Instance get sta service is null!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
#ifdef FEATURE_SELF_CURE_SUPPORT
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SELFCURE, instId);
#endif
        return WIFI_OPT_SUCCESS;
    }
    DispatchWifiCloseRes(OperateResState::CLOSE_WIFI_CLOSING, instId);
    ret = pService->DisableStaService();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable sta failed, ret %{public}d!", static_cast<int>(ret));
    }
    if (WifiStaHalInterface::GetInstance().StopWifi() != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("stop wifi failed.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::CLOSE_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(staState));
        return WIFI_OPT_FAILED;
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_STOPED, instId);
    DispatchWifiCloseRes(OperateResState::CLOSE_WIFI_SUCCEED, instId);
    HandleStaStop();
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::AutoStartScanOnly(int instId)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("AutoStartScanOnly, Wifi scan only state is %{public}d", static_cast<int>(curState));

    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGE("ScanOnly State  is not closed, return\n");
        return WIFI_OPT_SUCCESS;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId) ||
        WifiOprMidState::OPENING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
        return WIFI_OPT_SUCCESS;
    }
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateStaIface(
        std::bind(ConcreteMangerMachine::IfaceDestoryCallback, std::placeholders::_1, std::placeholders::_2),
        std::bind(ConcreteMangerMachine::OnRssiReportCallback, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("AutoStartScanOnly, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetStaIfaceName(ifaceName);
#endif
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING, instId);
    WifiManager::GetInstance().AutoStartEnhanceService();
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStartScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::AutoStopScanOnly(int instId, bool setIfaceDown)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("AutoStopScanOnly, current wifi scan only state is %{public}d", static_cast<int>(curState));
    if (curState != WifiOprMidState::RUNNING) {
        return WIFI_OPT_SUCCESS;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId) ||
        WifiOprMidState::OPENING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
        return WIFI_OPT_SUCCESS;
    }

    if (!WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGE("set wifi scan only mid state opening failed!");
        return WIFI_OPT_FAILED;
    }

    if (setIfaceDown) {
#ifdef HDI_CHIP_INTERFACE_SUPPORT
        DelayedSingleton<HalDeviceManager>::GetInstance()->SetNetworkUpDown(
            WifiConfigCenter::GetInstance().GetStaIfaceName(), false);
#endif
    }
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStopScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
    return WIFI_OPT_SUCCESS;
}

void ConcreteMangerMachine::HandleStaStop()
{
    if (WifiConfigCenter::GetInstance().GetWifiStopState()) {
        WIFI_LOGE("Sta stoped remove manager.");
        ErrCode ret = AutoStopScanOnly(mid, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop scanonly failed ret = %{public}d", ret);
        }
        return ReportClose();
    }
    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
#ifdef HDI_CHIP_INTERFACE_SUPPORT
        DelayedSingleton<HalDeviceManager>::GetInstance()->SetNetworkUpDown(
            WifiConfigCenter::GetInstance().GetStaIfaceName(), true);
#endif
        SwitchState(pScanonlyState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ErrCode ret = AutoStartStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            mcb.onStartFailure(mid);
            return;
        }
        SwitchState(pConnectState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        ErrCode ret = AutoStartSemiStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            mcb.onStartFailure(mid);
            return;
        }
        SwitchState(pSemiActiveState);
    } else {
        WIFI_LOGE("Now targetrole is unknow, stop concrete.");
        ErrCode ret = AutoStopScanOnly(mid, true);
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
        ret = AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        SwitchState(pConnectState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        ret = SwitchSemiFromEnable();
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("switch semi wifi failed ret = %{public}d", ret);
        }
    } else {
        WIFI_LOGE("Now targetrole is unknow.");
        ret = AutoStopStaService(mid);
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
        AutoStartScanOnly(mid);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        ret = AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE)) {
        AutoStartScanOnly(mid);
        SwitchState(pSemiActiveState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE)) {
        AutoStopScanOnly(mid, false);
        SwitchState(pSemiActiveState);
    } else {
        WIFI_LOGE("Now targetrole is unknow.");
        ret = AutoStopStaService(mid);
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
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, mid);
#ifdef FEATURE_SELF_CURE_SUPPORT
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SELFCURE, mid);
#endif
        return WIFI_OPT_FAILED;
    }
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_OPENING, mid);
    ErrCode ret = pService->DisableStaService();
    if (ret != static_cast<int>(WIFI_OPT_SUCCESS)) {
        WIFI_LOGE("DisableStaService failed!");
        return WIFI_OPT_FAILED;
    }
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_SUCCEED, mid);
    HandleStaSemiActive();
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::SwitchEnableFromSemi()
{
    auto detailState = WifiConfigCenter::GetInstance().GetWifiDetailState(mid);
    WIFI_LOGI("SwitchEnableFromSemi, current sta detailState:%{public}d", detailState);
    if (detailState == WifiDetailState::STATE_ACTIVATED) {
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
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_OPENING, mid);
    errCode = pService->EnableStaService();
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Service enable sta failed ,ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_SUCCEED, mid);
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, mid);
    HandleStaStart();
    return WIFI_OPT_SUCCESS;
}

void ConcreteMangerMachine::checkAndContinueToStopWifi(InternalMessage *msg)
{
    if (WifiConfigCenter::GetInstance().GetWifiStopState()) {
        WIFI_LOGE("checkAndContinueToStopWifi: wifi is stoping");
        return;
    }

    mTargetRole = static_cast<int>(ConcreteManagerRole::ROLE_UNKNOW);
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(mid);
    auto detailState = WifiConfigCenter::GetInstance().GetWifiDetailState(mid);
    WIFI_LOGI("checkAndContinueToStopWifi: current sta state: %{public}d detailState:%{public}d", staState,
        detailState);
    if (detailState != WifiDetailState::STATE_SEMI_ACTIVE && detailState != WifiDetailState::STATE_SEMI_ACTIVATING &&
        (staState == WifiOprMidState::CLOSING || staState == WifiOprMidState::OPENING)) {
        return;
    }

    WifiConfigCenter::GetInstance().SetWifiStopState(true);
    WIFI_LOGI("Set WifiStopState is true.");
    if (staState == WifiOprMidState::RUNNING || detailState == WifiDetailState::STATE_SEMI_ACTIVE ||
        detailState == WifiDetailState::STATE_SEMI_ACTIVATING) {
        ErrCode ret = AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("stop sta failed in timer ret = %{public}d", ret);
            WifiConfigCenter::GetInstance().SetWifiStopState(false);
            HandleStaStop();
        }
    } else {
        HandleStaStop();
    }
}

void ConcreteMangerMachine::IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    WIFI_LOGI("IfaceDestoryCallback, ifaceName:%{public}s, ifaceType:%{public}d",
        destoryIfaceName.c_str(), createIfaceType);
    if (destoryIfaceName == ifaceName) {
        ifaceName.clear();
        WifiConfigCenter::GetInstance().SetStaIfaceName("");
    }

    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->SendMessage(CMD_STA_REMOVED, createIfaceType, mid);
    return;
}

void ConcreteMangerMachine::OnRssiReportCallback(int index, int antRssi)
{
    WIFI_LOGI("HwWiTas OnRssiReportCallback, index:%{public}d, antRssi:%{public}d", index, antRssi);

    std::string data = std::to_string(antRssi);
    WifiCommonEventHelper::PublishWiTasRssiValueChangedEvent(index, data);
}

void ConcreteMangerMachine::DispatchWifiOpenRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiOpenRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::OPEN_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::ENABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENING));
        return;
    }
    if (state == OperateResState::OPEN_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, instId);
        WifiSettings::GetInstance().SetStaLastRunState(WIFI_STATE_ENABLED, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::ENABLE);
        return;
    }
}

void ConcreteMangerMachine::DispatchWifiSemiActiveRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiSemiActiveRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::ENABLE_SEMI_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSING));
        return;
    }
    if (state == OperateResState::ENABLE_SEMI_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVE, instId);
        WifiSettings::GetInstance().SetStaLastRunState(WIFI_STATE_SEMI_ENABLED, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::SEMI_ACTIVE, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::SEMI_ENABLE);
        return;
    }
}

void ConcreteMangerMachine::DispatchWifiCloseRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiCloseRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::CLOSE_WIFI_CLOSING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_DEACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        if (!WifiConfigCenter::GetInstance().GetWifiSelfcureReset()) {
            WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        }
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSING));
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_INACTIVE, instId);
        WifiSettings::GetInstance().SetStaLastRunState(WIFI_STATE_DISABLED, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::DISABLE);
        return;
    }
}
} // namespace Wifi
} // namespace OHOS
