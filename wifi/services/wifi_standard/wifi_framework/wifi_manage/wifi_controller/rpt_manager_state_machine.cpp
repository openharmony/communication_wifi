/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#ifdef FEATURE_RPT_SUPPORT
#include "rpt_manager_state_machine.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_chip_hal_interface.h"
#include "wifi_settings.h"
#include "wifi_common_event_helper.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_p2p_msg.h"
#include "ip2p_service.h"
#include "wifi_p2p_hal_interface.h"

#define TIME_DELAY (1000)
#define MAX_RETRY_COUNT (3)

namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("RptManagerMachine");
int RptManagerMachine::mid{0};

RptManagerMachine::RptManagerMachine() : StateMachine("RptManagerMachine"), pDefaultState(nullptr),
    pIdleState(nullptr), pStartingState(nullptr), pP2pConflictState(nullptr), pStartedState(nullptr),
    pStoppingState(nullptr), pStoppedState(nullptr)
{}

RptManagerMachine::~RptManagerMachine()
{
    WIFI_LOGE("RptManagerMachine::~RptManagerMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pIdleState);
    ParsePointer(pStartingState);
    ParsePointer(pP2pConflictState);
    ParsePointer(pStartedState);
    ParsePointer(pStoppingState);
    ParsePointer(pStoppedState);
}

/* --------------------------Initialization functions--------------------------*/
ErrCode RptManagerMachine::InitRptManagerMachine()
{
    WIFI_LOGE("Enter RptManagerMachine::InitRptManagerMachine.\n");
    if (!InitialStateMachine("RptManagerMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (InitRptManagerStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pIdleState);
    StartStateMachine();
    return WIFI_OPT_SUCCESS;
}

void RptManagerMachine::BuildStateTree()
{
    StatePlus(pDefaultState, nullptr);
    StatePlus(pIdleState, pDefaultState);
    StatePlus(pStartingState, pDefaultState);
    StatePlus(pP2pConflictState, pDefaultState);
    StatePlus(pStartedState, pDefaultState);
    StatePlus(pStoppingState, pDefaultState);
    StatePlus(pStoppedState, pDefaultState);
}

ErrCode RptManagerMachine::InitRptManagerStates()
{
    WIFI_LOGE("Enter InitConcreteMangerStates\n");
    pDefaultState = new (std::nothrow) DefaultState(this);
    pIdleState = new (std::nothrow) IdleState(this);
    pStartingState = new (std::nothrow) StartingState(this);
    pP2pConflictState = new (std::nothrow) P2pConflictState(this);
    pStartedState = new (std::nothrow) StartedState(this);
    pStoppingState = new (std::nothrow) StoppingState(this);
    pStoppedState = new (std::nothrow) StoppedState(this);
    int tmpErrNumber = 0;
    tmpErrNumber += JudgmentEmpty(pDefaultState);
    tmpErrNumber += JudgmentEmpty(pIdleState);
    tmpErrNumber += JudgmentEmpty(pStartingState);
    tmpErrNumber += JudgmentEmpty(pP2pConflictState);
    tmpErrNumber += JudgmentEmpty(pStartedState);
    tmpErrNumber += JudgmentEmpty(pStoppingState);
    tmpErrNumber += JudgmentEmpty(pStoppedState);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitRptManagerStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode RptManagerMachine::RegisterCallback(const RptModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

/* ---------------- DefaultState ---------------- */
RptManagerMachine::DefaultState::DefaultState(RptManagerMachine *rptManagerMachine)
    : State("DefaultState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::DefaultState::~DefaultState()
{}

void RptManagerMachine::DefaultState::GoInState()
{
    WIFI_LOGE("DefaultState GoInState function.\n");
}

void RptManagerMachine::DefaultState::GoOutState()
{
    WIFI_LOGE("DefaultState GoOutState function.\n");
}

bool RptManagerMachine::DefaultState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("DefaultState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    return true;
}

/* ---------------- IdleState ---------------- */
RptManagerMachine::IdleState::IdleState(RptManagerMachine *rptManagerMachine)
    : State("IdleState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::IdleState::~IdleState()
{}

void RptManagerMachine::IdleState::GoInState()
{
    WIFI_LOGE("IdleState GoInState function.\n");
}

void RptManagerMachine::IdleState::GoOutState()
{
    WIFI_LOGE("IdleState GoOutState function.\n");
}

bool RptManagerMachine::IdleState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("IdleState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case RPT_CMD_START:
            pRptManagerMachine->pStartingState->retryCount = 0;
            pRptManagerMachine->pP2pConflictState->retryCount = 0;
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStartingState);
            break;
        case RPT_CMD_STOP:
        case RPT_CMD_ON_P2P_CLOSE:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            break;
        default:
            break;
    }
    return true;
}

/* ---------------- StartingState ---------------- */
RptManagerMachine::StartingState::StartingState(RptManagerMachine *rptManagerMachine)
    : State("StartingState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::StartingState::~StartingState()
{}

void RptManagerMachine::StartingState::GoInState()
{
    WIFI_LOGE("StartingState GoInState function.\n");
    WriteWifiBridgeStateHiSysEvent(P2P_BRIDGE_ON);
    StartRpt();
}

void RptManagerMachine::StartingState::GoOutState()
{
    WIFI_LOGE("StartingState GoOutState function.\n");
}

bool RptManagerMachine::StartingState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("StartingState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case RPT_CMD_ON_GROUP_CREATED:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStartedState);
            break;
        case RPT_CMD_ON_P2P_CLOSE:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            break;
        case RPT_CMD_STOP:
            pRptManagerMachine->MessageExecutedLater(RPT_CMD_STOP, TIME_DELAY);
            break;
        case RPT_CMD_ON_CREATE_RPT_GROUP_TIMEOUT:
            if (retryCount < MAX_RETRY_COUNT) {
                StartRpt();
            } else {
                pRptManagerMachine->mcb.onStartFailure(mid);
                pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            }
            break;
        default:
            break;
    }
    return true;
}

void RptManagerMachine::StartingState::StartRpt()
{
#ifdef FEATURE_P2P_SUPPORT
    if (WifiConfigCenter::GetInstance().GetP2pMidState() != WifiOprMidState::RUNNING) {
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
        return;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
        return;
    }
    int p2pConnectedStatus;
    pService->GetP2pConnectedStatus(p2pConnectedStatus);
    if (p2pConnectedStatus != static_cast<int>(P2pConnectedState::P2P_DISCONNECTED)) {
        WIFI_LOGE("P2p is already connected, remove current group and retry");
        pRptManagerMachine->SwitchState(pRptManagerMachine->pP2pConflictState);
        return;
    }
    retryCount++;
    auto config = pRptManagerMachine->CreateRptConfig();
    pService->CreateRptGroup(config);
    pRptManagerMachine->MessageExecutedLater(RPT_CMD_ON_CREATE_RPT_GROUP_TIMEOUT, TIME_DELAY);
#endif
}

/* ---------------- P2pConflictState ---------------- */
RptManagerMachine::P2pConflictState::P2pConflictState(RptManagerMachine *rptManagerMachine)
    : State("P2pConflictState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::P2pConflictState::~P2pConflictState()
{}

void RptManagerMachine::P2pConflictState::GoInState()
{
    WIFI_LOGE("P2pConflictState GoInState function.\n");
    RemoveP2pConflictGroup();
}

void RptManagerMachine::P2pConflictState::GoOutState()
{
    WIFI_LOGE("P2pConflictState GoOutState function.\n");
}

bool RptManagerMachine::P2pConflictState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("P2pConflictState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case RPT_CMD_ON_GROUP_REMOVED:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStartingState);
            break;
        case RPT_CMD_ON_REMOVE_CONFLICT_GROUP_TIMEOUT:
            if (retryCount < MAX_RETRY_COUNT) {
                RemoveP2pConflictGroup();
            } else {
                pRptManagerMachine->mcb.onStartFailure(mid);
                pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            }
            break;
        case RPT_CMD_ON_P2P_CLOSE:
        case RPT_CMD_STOP:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            break;
        default:
            break;
    }
    return true;
}

void RptManagerMachine::P2pConflictState::RemoveP2pConflictGroup()
{
#ifdef FEATURE_P2P_SUPPORT
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
        return;
    }
    int p2pConnectedStatus;
    pService->GetP2pConnectedStatus(p2pConnectedStatus);
    if (p2pConnectedStatus == static_cast<int>(P2pConnectedState::P2P_DISCONNECTED)) {
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStartingState);
        return;
    }
    retryCount++;
    pService->RemoveGroup();
    pRptManagerMachine->MessageExecutedLater(RPT_CMD_ON_REMOVE_CONFLICT_GROUP_TIMEOUT, TIME_DELAY);
#endif
}

/* ---------------- StartedState ---------------- */
RptManagerMachine::StartedState::StartedState(RptManagerMachine *rptManagerMachine)
    : State("StartedState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::StartedState::~StartedState()
{}

void RptManagerMachine::StartedState::GoInState()
{
    WIFI_LOGE("StartedState GoInState function.\n");
    pRptManagerMachine->BroadcastApState(static_cast<int>(ApState::AP_STATE_STARTED));
    pRptManagerMachine->InitBlockList();
}

void RptManagerMachine::StartedState::GoOutState()
{
    WIFI_LOGE("StartedState GoOutState function.\n");
    pRptManagerMachine->BroadcastApState(static_cast<int>(ApState::AP_STATE_CLOSED));
}

bool RptManagerMachine::StartedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("StartedState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case RPT_CMD_STOP:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppingState);
            break;
        case RPT_CMD_ON_GROUP_REMOVED:
            pRptManagerMachine->mcb.onStartFailure(mid);
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            break;
        case RPT_CMD_ON_P2P_CLOSE:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            break;
        case RPT_CMD_ON_STATION_JOIN: {
            auto mac = msg->GetStringFromMessage();
            pRptManagerMachine->BroadcastStationJoin(mac);
        }
            break;
        case RPT_CMD_ON_STATION_LEAVE: {
            auto mac = msg->GetStringFromMessage();
            pRptManagerMachine->BroadcastStationLeave(mac);
        }
            break;
        case RPT_CMD_ADD_BLOCK: {
            auto mac = msg->GetStringFromMessage();
            pRptManagerMachine->AddBlockList(mac);
        }
            break;
        case RPT_CMD_DEL_BLOCK: {
            auto mac = msg->GetStringFromMessage();
            pRptManagerMachine->DelBlockList(mac);
        }
            break;
        default:
            break;
    }
    return true;
}

/* ---------------- StoppingState ---------------- */
RptManagerMachine::StoppingState::StoppingState(RptManagerMachine *rptManagerMachine)
    : State("StoppingState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::StoppingState::~StoppingState()
{}

void RptManagerMachine::StoppingState::GoInState()
{
    WIFI_LOGE("StoppingState GoInState function.\n");
    StopRpt();
}

void RptManagerMachine::StoppingState::GoOutState()
{
    WIFI_LOGE("StoppingState GoOutState function.\n");
}

bool RptManagerMachine::StoppingState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("StoppingState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case RPT_CMD_ON_P2P_CLOSE:
        case RPT_CMD_ON_GROUP_REMOVED:
            pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
            break;
        default:
            break;
    }
    return true;
}

void RptManagerMachine::StoppingState::StopRpt()
{
#ifdef FEATURE_P2P_SUPPORT
    if (WifiConfigCenter::GetInstance().GetP2pMidState() != WifiOprMidState::RUNNING) {
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
        return;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
        return;
    }
    WifiP2pGroupInfo group;
    if (pService->GetCurrentGroup(group) != ErrCode::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("group not exist when stop rpt");
        pRptManagerMachine->SwitchState(pRptManagerMachine->pStoppedState);
        return;
    }
    pService->DeleteGroup(group);
#endif
}

/* ---------------- StoppedState ---------------- */
RptManagerMachine::StoppedState::StoppedState(RptManagerMachine *rptManagerMachine)
    : State("StoppedState"), pRptManagerMachine(rptManagerMachine)
{}

RptManagerMachine::StoppedState::~StoppedState()
{}

void RptManagerMachine::StoppedState::GoInState()
{
    WIFI_LOGE("StoppedState GoInState function.\n");
    WriteWifiBridgeStateHiSysEvent(P2P_BRIDGE_OFF);
    pRptManagerMachine->mcb.onStopped(mid);
}

void RptManagerMachine::StoppedState::GoOutState()
{
    WIFI_LOGE("StoppedState GoOutState function.\n");
}

bool RptManagerMachine::StoppedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr || pRptManagerMachine == nullptr) {
        return false;
    }
    WIFI_LOGE("StoppedState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    return true;
}

/* ---------------- RptManagerMachine ---------------- */
WifiP2pConfig RptManagerMachine::CreateRptConfig()
{
    WifiP2pConfig p2pConfig;
    HotspotConfig hotspotConfig;
    WifiSettings::GetInstance().GetHotspotConfig(hotspotConfig, mid);
    p2pConfig.SetGroupName(hotspotConfig.GetSsid());
    p2pConfig.SetPassphrase(hotspotConfig.GetPreSharedKey());
    p2pConfig.SetGoBand(hotspotConfig.GetBand() == BandType::BAND_2GHZ ? GroupOwnerBand::GO_BAND_2GHZ :
                        hotspotConfig.GetBand() == BandType::BAND_5GHZ ? GroupOwnerBand::GO_BAND_5GHZ :
                        GroupOwnerBand::GO_BAND_AUTO);
    return p2pConfig;
}

void RptManagerMachine::BroadcastApState(int apState)
{
    WIFI_LOGI("RptManagerMachine NotifyApState, state %{public}d", apState);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = apState;
    cbMsg.id = mid;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    std::string msg = std::string("OnHotspotStateChanged") + std::string("id = ") + std::to_string(mid);
    WifiCommonEventHelper::PublishHotspotStateChangedEvent(apState, msg);
}

void RptManagerMachine::BroadcastStationJoin(std::string mac)
{
    StationInfo info;
    info.bssid = mac;
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_JOIN;
    cbMsg.staInfo = info;
    cbMsg.id = mid;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    std::string msg = std::string("ApStaJoined") + std::string("id = ") + std::to_string(mid);
    WifiCommonEventHelper::PublishApStaJoinEvent(0, msg);
}

void RptManagerMachine::BroadcastStationLeave(std::string mac)
{
    StationInfo info;
    info.bssid = mac;
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE;
    cbMsg.staInfo = info;
    cbMsg.id = mid;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    std::string msg = std::string("ApStaLeaved") + std::string("id = ") + std::to_string(mid);
    WifiCommonEventHelper::PublishApStaLeaveEvent(0, msg);
}

std::string GetRptIfaceName()
{
#ifdef FEATURE_P2P_SUPPORT
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return "";
    }
    WifiP2pGroupInfo group;
    pService->GetCurrentGroup(group);
    return group.GetInterface();
#else
    return "";
#endif
}

void RptManagerMachine::SetMacFilter(std::string mac)
{
    std::vector<StationInfo> blockList;
    WifiSettings::GetInstance().GetBlockList(blockList, mid);

    std::vector<std::string> blockMacs;
    for (auto& sta : blockList) {
        if (mac != sta.bssid) {
            blockMacs.push_back(sta.bssid);
        }
    }

    std::string p2pIfname = WifiConfigCenter::GetInstance().GetP2pIfaceName();
    std::string p2pInterfaceName = GetRptIfaceName();
    WIFI_LOGI("SetMacFilter size:%{public}d", static_cast<int>(blockMacs.size()));
    WifiP2PHalInterface::GetInstance().SetRptBlockList(p2pIfname, p2pInterfaceName, blockMacs);
}

void DisAssSta(std::string mac)
{
    std::string p2pIfname = WifiConfigCenter::GetInstance().GetP2pIfaceName();
    std::string p2pInterfaceName = GetRptIfaceName();
    WifiP2PHalInterface::GetInstance().DisAssociateSta(p2pIfname, p2pInterfaceName, mac);
}

void RptManagerMachine::InitBlockList()
{
    SetMacFilter("");
}

void RptManagerMachine::AddBlockList(std::string mac)
{
    DisAssSta(mac);
    SetMacFilter("");
}

void RptManagerMachine::DelBlockList(std::string mac)
{
    SetMacFilter(mac);
}
} // namespace OHOS::Wifi
#endif