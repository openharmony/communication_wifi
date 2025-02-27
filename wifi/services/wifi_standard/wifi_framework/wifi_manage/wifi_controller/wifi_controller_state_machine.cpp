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
#include "wifi_global_func.h"
#include "wifi_battery_utils.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher.h"
#else
#include "wifi_internal_event_dispatcher_lite.h"
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

bool WifiControllerMachine::DisableState::ExecuteStateMsg(InternalMessagePtr msg)
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
                pWifiControllerMachine->MakeHotspotManager(id, true);
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
            return false;
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
        case CMD_STA_START_FAILURE:
            msg->GetParam1() == INSTID_WLAN0 ? HandleStaStartFailure(INSTID_WLAN0) :
                pWifiControllerMachine->multiStaManagers.RemoveManager(INSTID_WLAN1);
            break;
        case CMD_CONCRETE_STOPPED:
            pWifiControllerMachine->HandleConcreteStop(INSTID_WLAN0);
            break;
        case CMD_MULTI_STA_STOPPED:
            pWifiControllerMachine->multiStaManagers.RemoveManager(INSTID_WLAN1);
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
        default:
#ifdef FEATURE_AP_SUPPORT
            return HandleApMsg(msg);
#else
            return false;
#endif
    }
    return true;
}

#ifdef FEATURE_AP_SUPPORT
bool WifiControllerMachine::EnableState::HandleApMsg(InternalMessagePtr msg)
{
    switch (msg->GetMessageName()) {
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
        case CMD_AP_REMOVED:
            HandleApRemoved(msg);
            break;
#ifdef FEATURE_RPT_SUPPORT
        case CMD_RPT_STOPPED:
            pWifiControllerMachine->HandleRptStop(msg->GetParam1());
            break;
        case CMD_P2P_STOPPED:
            HandleP2pStop(msg);
            break;
        case CMD_RPT_START_FAILURE:
            HandleRptStartFail(msg);
            break;
#endif
        default:
            return false;
    }
    return true;
}
#endif

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
    switch (msg->GetMessageName()) {
        case CMD_WIFI_TOGGLED_TIMEOUT:
            WifiManager::GetInstance().GetWifiTogglerManager()->OnWifiToggledTimeOut();
            break;
        case CMD_SEMI_WIFI_TOGGLED_TIMEOUT:
            WifiManager::GetInstance().GetWifiTogglerManager()->OnSemiWifiToggledTimeOut();
            break;
        default:
            return false;
    }
    return true;
}

void WifiControllerMachine::HandleAirplaneOpen()
{
    WIFI_LOGI("airplane open set softap false");
    this->StopTimer(CMD_WIFI_TOGGLED_TIMEOUT);
    this->StopTimer(CMD_SEMI_WIFI_TOGGLED_TIMEOUT);
#ifdef FEATURE_AP_SUPPORT
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    softApManagers.StopAllManagers();
#ifdef FEATURE_RPT_SUPPORT
    rptManagers.StopAllManagers();
#endif
#endif
    if (!WifiSettings::GetInstance().GetWifiFlagOnAirplaneMode() || !ShouldEnableWifi(INSTID_WLAN0)) {
        multiStaManagers.StopAllManagers();
        concreteManagers.StopAllManagers();
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
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() && softApManagers.HasAnyManager()) {
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
    if (role == ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE ||
        role == ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE) {
        WifiManager::GetInstance().GetWifiTogglerManager()->StartSemiWifiToggledTimer();
    }
    if (!concreteManagers.HasAnyManager()) {
        MakeConcreteManager(role, 0);
        SwitchState(pEnableState);
    } else {
        SwitchRole(role);
    }
}

bool WifiControllerMachine::HasAnyManager()
{
    return (concreteManagers.HasAnyManager() || multiStaManagers.HasAnyManager()
#ifdef FEATURE_AP_SUPPORT
    || softApManagers.HasAnyManager()
#ifdef FEATURE_RPT_SUPPORT
    || rptManagers.HasAnyManager()
#endif
#endif
    );
}

void WifiControllerMachine::MakeConcreteManager(ConcreteManagerRole role, int id)
{
    WIFI_LOGE("Enter MakeConcreteManager");
    auto clientmode = std::make_shared<ConcreteClientModeManager>(role, id);
    clientmode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetConcreteCallback());
    clientmode->InitConcreteManager();
    concreteManagers.AddManager(clientmode);
}

void WifiControllerMachine::MakeMultiStaManager(MultiStaManager::Role role, int instId)
{
    WIFI_LOGI("Enter MakeMultiStaManager");
    auto multiStaMode = std::make_shared<MultiStaManager>(role, instId);
    if (multiStaMode == nullptr) {
        WIFI_LOGE("new multiStaMode failed");
        return;
    }
    multiStaMode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetMultiStaCallback());
    multiStaMode->InitMultiStaManager();
    multiStaManagers.AddManager(multiStaMode);
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::MakeSoftapManager(SoftApManager::Role role, int id)
{
    WIFI_LOGE("Enter MakeSoftapManager");
    auto softapmode = std::make_shared<SoftApManager>(role, id);
    softapmode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetSoftApCallback());
    softapmode->InitSoftapManager();
    softApManagers.AddManager(softapmode);
}

bool WifiControllerMachine::ShouldEnableSoftap()
{
    bool toggledState = WifiConfigCenter::GetInstance().GetSoftapToggledState();
    WIFI_LOGI("Softap toggled state is %{public}d", toggledState);
    return toggledState;
}

#ifdef FEATURE_RPT_SUPPORT
std::shared_ptr<RptManager> WifiControllerMachine::GetRptManager(int id)
{
    return id == ANY_ID ? rptManagers.GetFirstManager() : rptManagers.GetManager(id);
}

void WifiControllerMachine::MakeRptManager(RptManager::Role role, int id)
{
    WIFI_LOGE("Enter MakeRptManager");
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_BRIDGE_REQUEST);
    auto rptmode = std::make_shared<RptManager>(role, id);
    rptmode->RegisterCallback(WifiManager::GetInstance().GetWifiTogglerManager()->GetRptCallback());
    rptmode->InitRptManager();
    rptManagers.AddManager(rptmode);
}

bool WifiControllerMachine::ShouldUseRpt(int id)
{
#ifndef FEATURE_P2P_SUPPORT
    return false;
#else
    const int bufferLen = 32;
    char buffer[bufferLen] = {0};
    GetParamValue("const.wifi.support_rpt", "false", buffer, bufferLen);
    std::string supportRpt = buffer;
    if (supportRpt == "false") {
        WIFI_LOGI("ShouldUseRpt not support rpt");
        return false;
    }

    GetParamValue("const.wifi.support_sapcoexist", "false", buffer, bufferLen);
    std::string supportSapcoexist = buffer;
    if (supportSapcoexist == "true") {
        WIFI_LOGI("ShouldUseRpt support coexist, not use rpt");
        return false;
    }

    if (WifiConfigCenter::GetInstance().GetWifiMidState(id) != WifiOprMidState::RUNNING) {
        WIFI_LOGI("ShouldUseRpt wifi is off");
        return false;
    }

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGI("ShouldUseRpt wifi is not connected");
        return false;
    }

    if (WifiConfigCenter::GetInstance().GetP2pMidState() != WifiOprMidState::RUNNING) {
        WIFI_LOGI("ShouldUseRpt p2p is not on");
        return false;
    }
    return true;
#endif
}
#endif

WifiControllerMachine::HotspotMode WifiControllerMachine::CalculateHotspotMode(int id)
{
    if (hotspotMode != HotspotMode::NONE) {
        return hotspotMode;
    }
#ifdef FEATURE_RPT_SUPPORT
    if (softApManagers.HasAnyManager()) {
        return HotspotMode::SOFTAP;
    } else if (rptManagers.HasAnyManager()) {
        return HotspotMode::RPT;
    } else if (ShouldUseRpt(id)) {
        return HotspotMode::RPT;
    }
#endif
    return HotspotMode::SOFTAP;
}

void WifiControllerMachine::MakeHotspotManager(int id, bool startTimer)
{
    hotspotMode = CalculateHotspotMode(id);
    if (hotspotMode == HotspotMode::SOFTAP && !softApManagers.IdExist(id)) {
        MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, id);
        if (startTimer) {
            StartTimer(CMD_AP_START_TIME, SOFT_AP_TIME_OUT);
        }
        return;
    }
#ifdef FEATURE_RPT_SUPPORT
    if (hotspotMode == HotspotMode::RPT && !rptManagers.IdExist(id)) {
        MakeRptManager(RptManager::Role::ROLE_RPT, id);
        return;
    }
#endif
}
#endif

bool WifiControllerMachine::ShouldDisableWifi(InternalMessagePtr msg)
{
    auto currState = WifiConfigCenter::GetInstance().GetWifiDetailState(msg->GetParam2());
    if (WifiConfigCenter::GetInstance().GetWifiToggledEnable() == WIFI_STATE_SEMI_ENABLED &&
        (currState == WifiDetailState::STATE_ACTIVATED || currState == WifiDetailState::STATE_ACTIVATING) &&
        msg->GetMessageName() == CMD_WIFI_TOGGLED && concreteManagers.IdExist(msg->GetParam2())) {
        WIFI_LOGI("Should disable wifi");
        WifiEventCallbackMsg cbMsg;
        cbMsg.msgCode = WIFI_CBK_MSG_SEMI_STATE_CHANGE;
        cbMsg.id = msg->GetParam2();
        cbMsg.msgData = static_cast<int>(WifiDetailState::STATE_INACTIVE);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
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

void WifiControllerMachine::HandleStaClose(int id)
{
    concreteManagers.SendMessage(CONCRETE_CMD_STA_STOP, id);
}

void WifiControllerMachine::HandleWifi2Close(int id)
{
    multiStaManagers.SendMessage(MULTI_STA_CMD_STOPPED, id);
}

void WifiControllerMachine::SwitchRole(ConcreteManagerRole role)
{
    std::unique_lock<std::mutex> lock(concreteManagers.mutex_);
    for (auto iter = concreteManagers.managers.begin(); iter != concreteManagers.managers.end(); ++iter) {
        (*iter)->SetRole(role);
    }
}

void WifiControllerMachine::EnableState::HandleWifiToggleChangeForRpt(int id, int isOpen)
{
#ifdef FEATURE_RPT_SUPPORT
    if (isOpen == 0 && pWifiControllerMachine->hotspotMode == HotspotMode::RPT) {
        WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
        pWifiControllerMachine->SendMessage(CMD_SOFTAP_TOGGLED, 0, id);
    }
#endif
}

bool WifiControllerMachine::EnableState::HandleWifiToggleChangeForWlan1(int id, int isOpen)
{
    if (id == INSTID_WLAN1 && isOpen == 0) {
        WIFI_LOGI("Toggle disable wlan1.");
        pWifiControllerMachine->multiStaManagers.StopManager(INSTID_WLAN1);
        return true;
    }
    if (id == INSTID_WLAN1 && isOpen == 1 &&
        WifiConfigCenter::GetInstance().GetPersistWifiState(INSTID_WLAN0) == WIFI_STATE_ENABLED) {
        pWifiControllerMachine->MakeMultiStaManager(MultiStaManager::Role::ROLE_STA_WIFI_2, id);
        return true;
    }
    return false;
}

void WifiControllerMachine::EnableState::HandleWifiToggleChangeInEnabledState(InternalMessagePtr msg)
{
    int id = msg->GetParam2();
    int isOpen = msg->GetParam1();
    int msgName = msg->GetMessageName();

    if (HandleWifiToggleChangeForWlan1(id, isOpen)) {
        return;
    }

    if (pWifiControllerMachine->ShouldDisableWifi(msg)) {
        HandleWifiToggleChangeForRpt(id, isOpen);
        pWifiControllerMachine->multiStaManagers.StopAllManagers();
        pWifiControllerMachine->concreteManagers.StopAllManagers();
        return;
    }
    ConcreteManagerRole presentRole;
    if (pWifiControllerMachine->concreteManagers.IdExist(id)) {
        if (WifiConfigCenter::GetInstance().GetWifiStopState()) {
            return;
        }
        presentRole = pWifiControllerMachine->GetWifiRole();
        if (presentRole == ConcreteManagerRole::ROLE_UNKNOW) {
            WIFI_LOGE("Get unknow wifi role in enablestate.");
            return;
        }
        if (presentRole != ConcreteManagerRole::ROLE_CLIENT_STA) {
            pWifiControllerMachine->multiStaManagers.StopManager(INSTID_WLAN1);
        }
        pWifiControllerMachine->SwitchRole(presentRole);
        return;
    }
    WifiConfigCenter::GetInstance().SetWifiStopState(false);
#ifdef FEATURE_AP_SUPPORT
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() &&
        pWifiControllerMachine->softApManagers.HasAnyManager()) {
        pWifiControllerMachine->softApManagers.StopAllManagers();
        return;
    }
#endif
#endif
    presentRole = pWifiControllerMachine->GetWifiRole();
    if (presentRole == ConcreteManagerRole::ROLE_UNKNOW) {
        WIFI_LOGE("Get unknow wifi role  in EnableState.");
        return;
    }
    pWifiControllerMachine->MakeConcreteManager(presentRole, id);
    return;
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::EnableState::HandleSoftapToggleChangeInEnabledState(InternalMessagePtr msg)
{
    int open = msg->GetParam1();
    int id = msg->GetParam2();
    WIFI_LOGE("handleSoftapToggleChangeInEnabledState");
    if (open == 1) {
        HandleSoftapOpen(id);
    } else {
        HandleSoftapClose(id);
    }
}

void WifiControllerMachine::EnableState::HandleSoftapOpen(int id)
{
#ifndef HDI_CHIP_INTERFACE_SUPPORT
        if (!WifiConfigCenter::GetInstance().GetCoexSupport() &&
            pWifiControllerMachine->concreteManagers.HasAnyManager()) {
            pWifiControllerMachine->multiStaManagers.StopAllManagers();
            pWifiControllerMachine->concreteManagers.StopAllManagers();
            pWifiControllerMachine->mApidStopWifi = id;
            return;
        }
#endif
    pWifiControllerMachine->MakeHotspotManager(id);
}

void WifiControllerMachine::EnableState::HandleSoftapClose(int id)
{
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() &&
        pWifiControllerMachine->ShouldEnableWifi(INSTID_WLAN0) &&
        !WifiConfigCenter::GetInstance().GetWifiStopState() &&
        pWifiControllerMachine->concreteManagers.HasAnyManager()) {
        ConcreteManagerRole role = pWifiControllerMachine->GetWifiRole();
        if (role != ConcreteManagerRole::ROLE_UNKNOW) {
            pWifiControllerMachine->SwitchRole(role);
        }
    }
#endif
#ifdef FEATURE_RPT_SUPPORT
    if (pWifiControllerMachine->hotspotMode == HotspotMode::RPT) {
        if (pWifiControllerMachine->rptManagers.IdExist(id)) {
            pWifiControllerMachine->rptManagers.StopManager(id);
        }
        return;
    }
#endif
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(id);
    if (apState == WifiOprMidState::CLOSING || apState == WifiOprMidState::OPENING) {
        WIFI_LOGI("Current ap state is %{public}d, return", apState);
        return;
    }
    if (pWifiControllerMachine->softApManagers.IdExist(id)) {
        pWifiControllerMachine->softApManagers.StopManager(id);
        pWifiControllerMachine->StartTimer(CMD_AP_STOP_TIME, SOFT_AP_TIME_OUT);
        return;
    }
}
#endif

void WifiControllerMachine::EnableState::HandleStaStartFailure(int id)
{
    WIFI_LOGE("HandleStaStartFailure");
    pWifiControllerMachine->concreteManagers.RemoveManager(id);
    mWifiStartFailCount++;
    if (pWifiControllerMachine->ShouldEnableWifi(id) && mWifiStartFailCount < WIFI_OPEN_RETRY_MAX_COUNT) {
        pWifiControllerMachine->StartTimer(CMD_OPEN_WIFI_RETRY, WIFI_OPEN_RETRY_TIMEOUT);
    }
}

void WifiControllerMachine::EnableState::HandleStaRemoved(InternalMessagePtr msg)
{
    if (msg->GetParam1() >= 0) {
        pWifiControllerMachine->concreteManagers.SendMessage(CONCRETE_CMD_STA_REMOVED, msg->GetParam2());
    }
    pWifiControllerMachine->multiStaManagers.StopAllManagers();
    pWifiControllerMachine->concreteManagers.StopManager(msg->GetParam2());
}

void WifiControllerMachine::EnableState::HandleWifi2Removed(InternalMessagePtr msg)
{
    pWifiControllerMachine->multiStaManagers.StopManager(msg->GetParam2());
}

void WifiControllerMachine::EnableState::HandleConcreteClientRemoved(InternalMessagePtr msg)
{
    int id = msg->GetParam1();
    pWifiControllerMachine->concreteManagers.RemoveManager(id);
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

void WifiControllerMachine::HandleStaStartSuccess(int id)
{
    mWifiStartFailCount = 0;
    this->StopTimer(CMD_WIFI_TOGGLED_TIMEOUT);
    this->StopTimer(CMD_OPEN_WIFI_RETRY);
    concreteManagers.SendMessageToAll(CONCRETE_CMD_STA_START);
}

void WifiControllerMachine::HandleWifi2Start(int id)
{
    multiStaManagers.SendMessageToAll(MULTI_STA_CMD_STARTED);
}

void WifiControllerMachine::HandleStaSemiActive(int id)
{
    mWifiStartFailCount = 0;
    this->StopTimer(CMD_SEMI_WIFI_TOGGLED_TIMEOUT);
    this->StopTimer(CMD_OPEN_WIFI_RETRY);
    concreteManagers.SendMessageToAll(CONCRETE_CMD_STA_SEMI_ACTIVE);
}

#ifdef FEATURE_AP_SUPPORT
void WifiControllerMachine::EnableState::HandleApStart(int id)
{
    if (!pWifiControllerMachine->ShouldEnableSoftap()) {
        pWifiControllerMachine->softApManagers.StopManager(id);
        return;
    }
}

void WifiControllerMachine::EnableState::HandleApRemoved(InternalMessagePtr msg)
{
    pWifiControllerMachine->softApManagers.StopManager(msg->GetParam2());
    auto softap = pWifiControllerMachine->softApManagers.GetManager(msg->GetParam2());
    if (softap != nullptr) {
        softap->SetRole(SoftApManager::Role::ROLE_HAS_REMOVED);
    }
}

void WifiControllerMachine::EnableState::HandleApStop(InternalMessagePtr msg)
{
    pWifiControllerMachine->StopTimer(CMD_AP_STOP_TIME);
    pWifiControllerMachine->HandleSoftapStop(msg->GetParam1());
}

#ifdef FEATURE_RPT_SUPPORT
void WifiControllerMachine::EnableState::HandleP2pStop(InternalMessagePtr msg)
{
    auto rpt = pWifiControllerMachine->rptManagers.GetManager(msg->GetParam1());
    if (rpt != nullptr) {
        rpt->OnP2pClosed();
    }
}

void WifiControllerMachine::EnableState::HandleRptStartFail(InternalMessagePtr msg)
{
    WIFI_LOGE("rpt start fail, set softap toggled false");
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
}
#endif
#endif

void WifiControllerMachine::HandleConcreteStop(int id)
{
    WIFI_LOGD("WifiControllerMachine HandleConcreteStop id = %{public}d", id);
    concreteManagers.RemoveManager(id);
#ifndef HDI_CHIP_INTERFACE_SUPPORT
    if (!WifiConfigCenter::GetInstance().GetCoexSupport()) {
#ifdef FEATURE_AP_SUPPORT
        int airplanstate = WifiConfigCenter::GetInstance().GetAirplaneModeState();
        if (ShouldEnableSoftap() && airplanstate != MODE_STATE_OPEN) {
            MakeHotspotManager(id);
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
template <class T>
void WifiControllerMachine::HandleHotspotStop(int id, HotspotMode THotspotMode, ManagerControl<T> &TManagers)
{
    auto softap = TManagers.GetManager(id);
    bool roleIsRemoved = softap != nullptr && softap->GetRole() == T::Role::ROLE_HAS_REMOVED;
    softap = nullptr;
    TManagers.RemoveManager(id);
    if (hotspotMode == THotspotMode && !TManagers.HasAnyManager()) {
        hotspotMode = HotspotMode::NONE;
    }
    if (roleIsRemoved) {
        if (!HasAnyManager()) {
            SwitchState(pDisableState);
        }
        return;
    }

    if (ShouldEnableSoftap()) {
        MakeHotspotManager(id);
        return;
    }
    if (HasAnyManager()) {
        return;
    }
    if (ShouldEnableWifi(INSTID_WLAN0) && !WifiConfigCenter::GetInstance().GetWifiStopState()) {
        ConcreteManagerRole role = GetWifiRole();
        if (role == ConcreteManagerRole::ROLE_UNKNOW) {
            WIFI_LOGE("Get unknow wifi role in HandleSoftapStop.");
            return;
        }
        MakeConcreteManager(role, 0);
    } else {
        SwitchState(pDisableState);
    }
}

void WifiControllerMachine::HandleSoftapStop(int id)
{
    HandleHotspotStop(id, HotspotMode::SOFTAP, softApManagers);
}

#ifdef FEATURE_RPT_SUPPORT
void WifiControllerMachine::HandleRptStop(int id)
{
    HandleHotspotStop(id, HotspotMode::RPT, rptManagers);
}
#endif
#endif

void WifiControllerMachine::ShutdownWifi(bool shutDownAp)
{
    WIFI_LOGI("shutdownWifi.");
    if (shutDownAp) {
#ifdef FEATURE_AP_SUPPORT
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    softApManagers.StopAllManagers();
#ifdef FEATURE_RPT_SUPPORT
    rptManagers.StopAllManagers();
#endif
#endif
    }

    multiStaManagers.StopAllManagers();
    concreteManagers.StopAllManagers();
}

void WifiControllerMachine::SelfcureResetWifi(int id)
{
    concreteManagers.SendMessage(CONCRETE_CMD_RESET_STA, id);
}
} // namespace Wifi
} // namespace OHOS
