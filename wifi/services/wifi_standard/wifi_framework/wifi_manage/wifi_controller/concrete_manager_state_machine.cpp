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
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_internal_msg.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_country_code_manager.h"
#include "wifi_common_util.h"
#include "app_network_speed_limit_service.h"
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
      pScanonlyState(nullptr), pMixState(nullptr)
{}

ConcreteMangerMachine::~ConcreteMangerMachine()
{
    WIFI_LOGE("~ConcreteMangerMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pIdleState);
    ParsePointer(pConnectState);
    ParsePointer(pScanonlyState);
    ParsePointer(pMixState);
    WIFI_LOGE("set wifi stoping state is false");
    WifiSettings::GetInstance().SetWifiStopState(false);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!ifaceName.empty()) {
        DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveStaIface(ifaceName);
        ifaceName.clear();
        WifiSettings::GetInstance().SetStaIfaceName("");
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
    WifiSettings::GetInstance().SetWifiStopState(false);
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
    StatePlus(pMixState, pDefaultState);
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
    pMixState = new (std::nothrow) MixState(this);
    tmpErrNumber += JudgmentEmpty(pMixState);
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
            pConcreteMangerMachine->mTargetRole = msg->GetParam1();
            HandleStartInIdleState(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
        case CONCRETE_CMD_SWITCH_TO_MIX_MODE:
            HandleSwitchToConnectOrMixMode(msg);
            break;
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            HandleSwitchToScanOnlyMode(msg);
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::IdleState::HandleSwitchToConnectOrMixMode(InternalMessage *msg)
{
    ErrCode ret = AutoStartStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiSettings::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
}

void ConcreteMangerMachine::IdleState::HandleSwitchToScanOnlyMode(InternalMessage *msg)
{
    ErrCode ret = AutoStartScanOnly(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiSettings::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
}

void ConcreteMangerMachine::IdleState::HandleStartInIdleState(InternalMessage *msg)
{
    mTargetRole = msg->GetParam1();
    mid = msg->GetParam2();
    ErrCode res = AutoStartScanOnly(mid);
    if (res != WIFI_OPT_SUCCESS) {
        WifiSettings::GetInstance().SetWifiStopState(true);
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX) ||
        mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ErrCode ret = AutoStartStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WifiSettings::GetInstance().SetWifiStopState(true);
            pConcreteMangerMachine->mcb.onStartFailure(mid);
            return;
        }
        pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
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
        case CONCRETE_CMD_SWITCH_TO_MIX_MODE:
            SwitchMixInConnectState();
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::ConnectState::SwitchScanOnlyInConnectState()
{
    ErrCode ret = AutoStopStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("stop sta failed ret =%{public}d \n", ret);
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pScanonlyState);
}

void ConcreteMangerMachine::ConnectState::SwitchMixInConnectState()
{
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pMixState);
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
        case CONCRETE_CMD_SWITCH_TO_MIX_MODE:
            SwitchMixInScanOnlyState();
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::ScanonlyState::SwitchConnectInScanOnlyState()
{
    ErrCode ret = AutoStartStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
}

void ConcreteMangerMachine::ScanonlyState::SwitchMixInScanOnlyState()
{
    ErrCode ret = AutoStartStaService(mid);
    if (ret != WIFI_OPT_SUCCESS) {
        pConcreteMangerMachine->mcb.onStartFailure(mid);
        return;
    }
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pMixState);
}

ConcreteMangerMachine::MixState::MixState(ConcreteMangerMachine *concreteMangerMachine)
    : State("MixState"), pConcreteMangerMachine(concreteMangerMachine)
{}

ConcreteMangerMachine::MixState::~MixState()
{}

void ConcreteMangerMachine::MixState::GoInState()
{
    WIFI_LOGE("MixState  GoInState function.\n");
}

void ConcreteMangerMachine::MixState::GoOutState()
{
    WIFI_LOGE("MixState  GoOutState function.\n");
}

bool ConcreteMangerMachine::MixState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGE("MixState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    if (pConcreteMangerMachine->HandleCommonMessage(msg)) {
        return true;
    }
    switch (msg->GetMessageName()) {
        case CONCRETE_CMD_SWITCH_TO_CONNECT_MODE:
            SwitchConnectInMixState();
            break;
        case CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE:
            SwitchScanOnlyInMixState();
            break;
        default:
            break;
    }
    return true;
}

void ConcreteMangerMachine::MixState::SwitchConnectInMixState()
{
    pConcreteMangerMachine->SwitchState(pConcreteMangerMachine->pConnectState);
}

void ConcreteMangerMachine::MixState::SwitchScanOnlyInMixState()
{
    ErrCode ret = AutoStopStaService(mid);
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

ErrCode ConcreteMangerMachine::AutoStartStaService(int instId)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartStaService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::RUNNING) {
        return WIFI_OPT_SUCCESS;
    }

#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateStaIface(
        std::bind(ConcreteMangerMachine::IfaceDestoryCallback, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("AutoStartStaService, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SetStaIfaceName(ifaceName);
#endif

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::OPENING, instId)) {
        WIFI_LOGE("AutoStartStaService, set wifi mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
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
#ifdef FEATURE_SELF_CURE_SUPPORT
        if (StartSelfCureService(instId) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("StartSelfCureService failed!");
            break;
        }
#endif
        errCode = pService->RegisterStaServiceCallback(WifiManager::GetInstance().GetWifiStaManager()->GetStaCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register sta service callback failed!");
            break;
        }
#ifndef OHOS_ARCH_LITE
        errCode = pService->RegisterStaServiceCallback(WifiCountryCodeManager::GetInstance().GetStaCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("wifiCountryCodeManager register sta service callback failed, ret=%{public}d!",
                static_cast<int>(errCode));
            break;
        }

        errCode = pService->RegisterStaServiceCallback(AppNetworkSpeedLimitService::GetInstance().GetStaCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("AppNetworkSpeedLimitService register sta service callback failed, ret=%{public}d!",
                static_cast<int>(errCode));
            break;
        }
#endif
        errCode = pService->EnableWifi();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Service enable sta failed ,ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
#ifdef FEATURE_SELF_CURE_SUPPORT
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SELFCURE);
#endif
        return errCode;
    }
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
#ifdef FEATURE_P2P_SUPPORT
    errCode = WifiManager::GetInstance().GetWifiP2pManager()->AutoStartP2pService();
    if (errCode != WIFI_OPT_SUCCESS && errCode != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
        WIFI_LOGE("AutoStartStaService, AutoStartP2pService failed!");
    }
#endif
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
    ret = pService->DisableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable sta failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING, instId);
        return ret;
    }

#ifdef HAS_POWERMGR_PART
    if (WifiConfigCenter::GetInstance().GetPowerSleepState() == MODE_STATE_OPEN) {
        WIFI_LOGI("AutoStopStaService, do not set staLastState to false for forcesleep!");
        return WIFI_OPT_SUCCESS;
    }
#endif

    WifiConfigCenter::GetInstance().SetStaLastRunState(false);
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
        ifaceName)) {
        WIFI_LOGE("AutoStartScanOnly, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SetStaIfaceName(ifaceName);
#endif
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING, instId);
    WifiManager::GetInstance().AutoStartEnhanceService();
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStartScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode ConcreteMangerMachine::AutoStopScanOnly(int instId)
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

    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
        return WIFI_OPT_FAILED;
    }
    pService->SetNetworkInterfaceUpDown(false);
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStopScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
    return WIFI_OPT_SUCCESS;
}

void ConcreteMangerMachine::HandleStaStop()
{
    if (WifiSettings::GetInstance().GetWifiStopState()) {
        WIFI_LOGE("Sta stoped remove manager.");
        ErrCode ret = AutoStopScanOnly(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop scanonly failed ret = %{public}d", ret);
        }
        return ReportClose();
    }
    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX)) {
        ErrCode ret = AutoStartStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            mcb.onStartFailure(mid);
            return;
        }
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(mid);
        if (pService == nullptr) {
            WIFI_LOGE("HandleStaStop scan service is null");
            return ReportClose();
        }
        pService->SetNetworkInterfaceUpDown(true);
        SwitchState(pScanonlyState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        ErrCode ret = AutoStartStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            mcb.onStartFailure(mid);
            return;
        }
        SwitchState(pConnectState);
    } else {
        WIFI_LOGE("Now targetrole is unknow, stop concrete.");
        ErrCode ret = AutoStopScanOnly(mid);
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

    if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_MIX)) {
        SwitchState(pMixState);
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY)) {
        ret = AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
    } else if (mTargetRole == static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA)) {
        SwitchState(pConnectState);
    } else {
        WIFI_LOGE("Now targetrole is unknow.");
        ret = AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Stop sta failed ret = %{public}d", ret);
        }
    }
}

void ConcreteMangerMachine::checkAndContinueToStopWifi(InternalMessage *msg)
{
    if (WifiSettings::GetInstance().GetWifiStopState()) {
        WIFI_LOGE("checkAndContinueToStopWifi: wifi is stoping");
        return;
    }

    mTargetRole = static_cast<int>(ConcreteManagerRole::ROLE_UNKNOW);
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(mid);
    WIFI_LOGI("checkAndContinueToStopWifi: current sta state: %{public}d", staState);
    if (staState == WifiOprMidState::CLOSING || staState == WifiOprMidState::OPENING) {
        return;
    }

    WifiSettings::GetInstance().SetWifiStopState(true);
    WIFI_LOGI("Set WifiStopState is true.");
    if (staState == WifiOprMidState::RUNNING) {
        ErrCode ret = AutoStopStaService(mid);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("stop sta failed in timer ret = %{public}d", ret);
            WifiSettings::GetInstance().SetWifiStopState(false);
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->HandleStaClose(mid);
        }
    } else {
        auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
        ins->HandleStaClose(mid);
    }
}

void ConcreteMangerMachine::IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    WIFI_LOGI("IfaceDestoryCallback, ifaceName:%{public}s, ifaceType:%{public}d",
        destoryIfaceName.c_str(), createIfaceType);
    if (destoryIfaceName == ifaceName) {
        ifaceName.clear();
        WifiSettings::GetInstance().SetStaIfaceName("");
    }

    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->SendMessage(CMD_STA_REMOVED, createIfaceType, mid);
    return;
}

} // namespace Wifi
} // namespace OHOS