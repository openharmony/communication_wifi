/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sta_state_machine.h"
#include <cstdio>
#include <random>
#include "http_request.h"
#include "log_helper.h"
#include "if_config.h"
#include "sta_monitor.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_STATE_MACHINE"
#define PBC_ANY_BSSID "any"

const int SLEEPTIME = 3;
const int BAND_ONE = 1;
const int BAND_TWO = 2;

#define MAC_LENGTH 12
#define MAC_STEP 2
#define RAND_SEED_16 16
#define RAND_SEED_8 8
#define BUFFER_SIZE 128


namespace OHOS {
namespace Wifi {
StaStateMachine::StaStateMachine()
    : StateMachine("StaStateMachine"),
      statusId(0),
      lastNetworkId(INVALID_NETWORK_ID),
      operationalMode(STA_CONNECT_MODE),
      targetNetworkId(INVALID_NETWORK_ID),
      pinCode(0),
      wpsState(SetupMethod::INVALID),
      lastConnectToNetworkTimer(-1),
      targetRoamBssid(SUPPLICANT_BSSID_ANY),
      currentTpType(IPTYPE_IPV4),
      isWpsConnect(IsWpsConnected::WPS_INVALID),
      pDhcpServer(nullptr),
      pNetSpeed(nullptr),
      pNetcheck(nullptr),
      msgQueueUp(nullptr),
      pDefaultState(nullptr),
      pInitState(nullptr),
      pWpaStartingState(nullptr),
      pWpaStartedState(nullptr),
      pWpaStoppingState(nullptr),
      pConnectState(nullptr),
      pDisconnectingState(nullptr),
      pDisconnectedState(nullptr),
      pApConnectedState(nullptr),
      pWpsState(nullptr),
      pObtainingIpState(nullptr),
      pConnectedState(nullptr),
      pRoamingState(nullptr)
{}

StaStateMachine::~StaStateMachine()
{
    LOGI("StaStateMachine::~StaStateMachine");
    StopHandlerThread();
    ParsePointer(pDefaultState);
    ParsePointer(pInitState);
    ParsePointer(pWpaStartingState);
    ParsePointer(pWpaStartedState);
    ParsePointer(pWpaStoppingState);
    ParsePointer(pConnectState);
    ParsePointer(pDisconnectingState);
    ParsePointer(pDisconnectedState);
    ParsePointer(pApConnectedState);
    ParsePointer(pWpsState);
    ParsePointer(pObtainingIpState);
    ParsePointer(pConnectedState);
    ParsePointer(pRoamingState);
    ParsePointer(pDhcpServer);
    ParsePointer(pNetSpeed);
    ParsePointer(pNetcheck);
}

/* ---------------------------Initialization functions------------------------------ */
ErrCode StaStateMachine::InitStaStateMachine()
{
    LOGD("Enter StaStateMachine::InitStaStateMachine.\n");
    if (!InitialStateMachine()) {
        LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (InitStaStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetInitialState(pInitState);
    Start();
    InitStaSMHandleMap();

    pDhcpServer =
        new (std::nothrow) StaDhcpServer(std::bind(&StaStateMachine::HandleDhcpResult, this, std::placeholders::_1));
    if (pDhcpServer == nullptr) {
        LOGE("pDhcpServer is null\n");
        return WIFI_OPT_FAILED;
    }
    pDhcpServer->InitDhcpThread();

    pNetcheck = new (std::nothrow)
        StaNetworkCheck(std::bind(&StaStateMachine::HandleNetCheckResult, this, std::placeholders::_1));
    if (pNetcheck == nullptr) {
        LOGE("pNetcheck is null\n");
        return WIFI_OPT_FAILED;
    }
    pNetcheck->InitNetCheckThread();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaStateMachine::InitStaStates()
{
    LOGE("Enter InitStaStates\n");
    int tmpErrNumber;
    pDefaultState = new DefaultState(this);
    tmpErrNumber = JudgmentEmpty(pDefaultState);
    pInitState = new InitState(this);
    tmpErrNumber += JudgmentEmpty(pInitState);
    pWpaStartingState = new WpaStartingState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStartingState);
    pWpaStartedState = new WpaStartedState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStartedState);
    pWpaStoppingState = new WpaStoppingState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStoppingState);
    pConnectState = new ConnectState(this);
    tmpErrNumber += JudgmentEmpty(pConnectState);
    pDisconnectingState = new DisconnectingState(this);
    tmpErrNumber += JudgmentEmpty(pDisconnectingState);
    pDisconnectedState = new DisconnectedState(this);
    tmpErrNumber += JudgmentEmpty(pDisconnectedState);
    pApConnectedState = new ApConnectedState(this);
    tmpErrNumber += JudgmentEmpty(pApConnectedState);
    pWpsState = new WpsState(this);
    tmpErrNumber += JudgmentEmpty(pWpsState);
    pObtainingIpState = new ObtainingIpState(this);
    tmpErrNumber += JudgmentEmpty(pObtainingIpState);
    pConnectedState = new ConnectedState(this);
    tmpErrNumber += JudgmentEmpty(pConnectedState);
    pRoamingState = new RoamingState(this);
    tmpErrNumber += JudgmentEmpty(pRoamingState);
    pNetSpeed = new StaNetWorkSpeed();
    tmpErrNumber += JudgmentEmpty(pNetSpeed);
    if (tmpErrNumber != 0) {
        LOGE("InitStaStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::InitWifiLinkedInfo()
{
    linkedInfo.networkId = INVALID_NETWORK_ID;
    linkedInfo.ssid = "";
    linkedInfo.bssid = "";
    linkedInfo.macAddress = "";
    linkedInfo.rssi = 0;
    linkedInfo.band = 0;
    linkedInfo.frequency = 0;
    linkedInfo.linkSpeed = 0;
    linkedInfo.ipAddress = 0;
    linkedInfo.connState = ConnState::DISCONNECTED;
    linkedInfo.ifHiddenSSID = false;
    linkedInfo.chload = 0;
    linkedInfo.snr = 0;
    linkedInfo.detailedState = DetailedState::DISCONNECTED;
}

void StaStateMachine::InitLastWifiLinkedInfo()
{
    lastLinkedInfo.networkId = INVALID_NETWORK_ID;
    lastLinkedInfo.ssid = "";
    lastLinkedInfo.bssid = "";
    lastLinkedInfo.macAddress = "";
    lastLinkedInfo.rssi = 0;
    lastLinkedInfo.band = 0;
    lastLinkedInfo.frequency = 0;
    lastLinkedInfo.linkSpeed = 0;
    lastLinkedInfo.ipAddress = 0;
    lastLinkedInfo.connState = ConnState::DISCONNECTED;
    lastLinkedInfo.ifHiddenSSID = false;
    lastLinkedInfo.chload = 0;
    lastLinkedInfo.snr = 0;
    lastLinkedInfo.detailedState = DetailedState::DISCONNECTED;
}

void StaStateMachine::SetResponseQueue(WifiMessageQueue<WifiResponseMsgInfo> *pMsgQueueUp)
{
    msgQueueUp = pMsgQueueUp;
    return;
}

void StaStateMachine::BuildStateTree()
{
    AddState(pDefaultState, nullptr);
    AddState(pInitState, pDefaultState);
    AddState(pWpaStartingState, pDefaultState);
    AddState(pWpaStartedState, pDefaultState);
    AddState(pConnectState, pWpaStartedState);
    AddState(pDisconnectingState, pConnectState);
    AddState(pDisconnectedState, pConnectState);
    AddState(pApConnectedState, pConnectState);
    AddState(pObtainingIpState, pApConnectedState);
    AddState(pConnectedState, pApConnectedState);
    AddState(pRoamingState, pApConnectedState);
    AddState(pWpsState, pConnectState);
    AddState(pWpaStoppingState, pDefaultState);
}

/* --------------------------- state machine default state ------------------------------ */
StaStateMachine::DefaultState::DefaultState(StaStateMachine *staStateMachine) : State("DefaultState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::DefaultState::~DefaultState()
{}

void StaStateMachine::DefaultState::Enter()
{
    LOGI("DefaultState Enter function.");
    return;
}

void StaStateMachine::DefaultState::Exit()
{
    LOGI("DefaultState Exit function.");
    return;
}

bool StaStateMachine::DefaultState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    LOGI("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return true;
}

/* --------------------------- state machine Init State ------------------------------ */
StaStateMachine::InitState::InitState(StaStateMachine *staStateMachine) : State("InitState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::InitState::~InitState()
{}

void StaStateMachine::InitState::Enter()
{
    LOGI("InitState Enter function.");
    CleanUp();
    return;
}

void StaStateMachine::InitState::Exit()
{}

bool StaStateMachine::InitState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_START_SUPPLICANT: {
            ret = HANDLED;
            pStaStateMachine->StartWifiProcess();
            break;
        }

        case WIFI_SVR_CMD_STA_ENABLE_WIFI: {
            ret = HANDLED;
            pStaStateMachine->operationalMode = msg->GetArg1();
            pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_START_SUPPLICANT);
            break;
        }

        case WIFI_SVR_CMD_STA_OPERATIONAL_MODE:
            break;

        case WIFI_SVR_CMD_STA_REMOVE_DEVICE_CONFIG: {
            ret = HANDLED;
            pStaStateMachine->RemoveDeviceConfigProcess(msg);
            break;
        }
        default:
            break;
    }
    return ret;
}

void StaStateMachine::InitState::CleanUp()
{}

void StaStateMachine::StartWifiProcess()
{
    int res = WifiStaHalInterface::GetInstance().StartWifi();
    if (res == static_cast<int>(WIFI_IDL_OPT_OK)) {
        LOGD("Start wifi successfully!");
        if (WifiStaHalInterface::GetInstance().WpaAutoConnect(false) != WIFI_IDL_OPT_OK) {
            LOGI("The automatic Wpa connection is disabled failed.");
        }

        /* Reload wifi Configurations. */
        if (WifiSettings::GetInstance().ReloadDeviceConfig() != 0) {
            LOGE("ReloadDeviceConfig() failed!");
        }

        /* Sets the MAC address of WifiSettings. */
        std::string mac;
        if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(mac)) != WIFI_IDL_OPT_OK) {
            LOGI("GetStaDeviceMacAddress failed!");
        } else {
            WifiSettings::GetInstance().SetMacAddress(mac);
        }
        /* Initialize Connection Information. */
        InitWifiLinkedInfo();
        InitLastWifiLinkedInfo();
        WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);

        /* Notify the InterfaceService that wifi is enabled successfully. */
        NotifyResult(WifiInternalMsgCode::STA_OPEN_RES, static_cast<int>(OperateResState::OPEN_WIFI_SUCCEED));
        /* The current state of StaStateMachine transfers to DisconnectedState after
         * enable supplicant.
         */
        TransitionTo(pDisconnectedState);
        /* Set country code */
        SetCountryCode();
    } else {
        /* Notify the InterfaceService that wifi is failed to enable wifi. */
        LOGE("StartWifi failed, and errcode is %{public}d", res);
        NotifyResult(WifiInternalMsgCode::STA_OPEN_RES, static_cast<int>(OperateResState::OPEN_WIFI_FAILED));
        NotifyResult(WifiInternalMsgCode::STA_OPEN_RES, static_cast<int>(OperateResState::OPEN_WIFI_DISABLED));
    }
}

/* --------------------------- state machine WpaStarting State ------------------------------ */
StaStateMachine::WpaStartingState::WpaStartingState(StaStateMachine *staStateMachine) : State("WpaStartingState")
{
    pStaStateMachine = staStateMachine;
}
StaStateMachine::WpaStartingState::~WpaStartingState()
{}

void StaStateMachine::WpaStartingState::InitWpsSettings()
{
    LOGI("WpaStartingState InitWpsSettings function.");
    return;
}

void StaStateMachine::WpaStartingState::Enter()
{
    LOGI("WpaStartingState Enter function.");
    return;
}

void StaStateMachine::WpaStartingState::Exit()
{
    return;
}

bool StaStateMachine::WpaStartingState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_SUP_CONNECTION_EVENT: {
            ret = HANDLED;
            pStaStateMachine->TransitionTo(pStaStateMachine->pWpaStartedState);
            break;
        }
        default:
            break;
    }
    return ret;
}

/* --------------------------- state machine WpaStarted State ------------------------------ */
StaStateMachine::WpaStartedState::WpaStartedState(StaStateMachine *staStateMachine) : State("WpaStartedState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::WpaStartedState::~WpaStartedState()
{}

void StaStateMachine::WpaStartedState::Enter()
{
    LOGD("WpaStartedState Enter function.");
    if (pStaStateMachine->operationalMode == STA_CONNECT_MODE) {
        /* Update the wifi status. */
        WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING));
        pStaStateMachine->TransitionTo(pStaStateMachine->pDisconnectedState);
    } else if (pStaStateMachine->operationalMode == STA_DISABLED_MODE) {
        pStaStateMachine->TransitionTo(pStaStateMachine->pWpaStoppingState);
    }
    return;
}
void StaStateMachine::WpaStartedState::Exit()
{
    return;
}

bool StaStateMachine::WpaStartedState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_STOP_SUPPLICANT: {
            ret = HANDLED;
            pStaStateMachine->StopWifiProcess();
            break;
        }

        case WIFI_SVR_CMD_STA_DISABLE_WIFI: {
            ret = HANDLED;
            pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_STOP_SUPPLICANT);
            break;
        }

        case WIFI_SVR_CMD_STA_REMOVE_DEVICE_CONFIG: {
            ret = HANDLED;
            pStaStateMachine->RemoveDeviceConfigProcess(msg);
            break;
        }

        default:
            break;
    }
    return ret;
}

void StaStateMachine::StopWifiProcess()
{
    LOGD("Enter StaStateMachine::StopWifiProcess.\n");
    if (lastNetworkId != INVALID_NETWORK_ID) {
        if (statusId == static_cast<int>(WifiDeviceConfigStatus::DISABLED)) {
            LOGD("The network status is DISABLED:1.\n");
            WifiSettings::GetInstance().SetDeviceState(
                lastNetworkId, static_cast<int>(WifiDeviceConfigStatus::DISABLED));
        } else if (statusId == static_cast<int>(WifiDeviceConfigStatus::ENABLED)) {
            LOGD("The network status is ENABLED:2.\n");
            WifiSettings::GetInstance().SetDeviceState(
                lastNetworkId, static_cast<int>(WifiDeviceConfigStatus::ENABLED));
        }
        WifiSettings::GetInstance().SyncDeviceConfig();
    }
    LOGD("linkedInfo network = %{public}d", linkedInfo.networkId);

    /* clear connection information. */
    InitWifiLinkedInfo();
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);

    WifiErrorNo errorNo = WifiStaHalInterface::GetInstance().StopWifi();
    if (errorNo == WIFI_IDL_OPT_OK) {
        /* Notify result to InterfaceService. */
        NotifyResult(WifiInternalMsgCode::STA_CLOSE_RES, static_cast<int>(OperateResState::CLOSE_WIFI_SUCCEED));
        LOGD("Stop WifiProcess successfully!");

        /* The current state of StaStateMachine transfers to InitState. */
        TransitionTo(pInitState);
    } else {
        LOGE("StopWifiProcess failed，and errcode is %{public}d", errorNo);
        NotifyResult(WifiInternalMsgCode::STA_OPEN_RES, static_cast<int>(OperateResState::CLOSE_WIFI_FAILED));
    }
}

void StaStateMachine::RemoveDeviceConfigProcess(const InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGD("Enter StaStateMachine::RemoveDeviceConfigProcess.\n");
    /* Remove network configuration. */
    if (WifiStaHalInterface::GetInstance().RemoveDeviceConfig(msg->GetArg1()) == WIFI_IDL_OPT_OK) {
        LOGD("Remove device config successfully!");

        if (WifiStaHalInterface::GetInstance().SaveDeviceConfig() != WIFI_IDL_OPT_OK) {
            LOGE("RemoveDeviceConfig:SaveDeviceConfig failed!");
        }
        LOGD("RemoveDeviceConfig-SaveDeviceConfig successfully!");
    } else {
        LOGE("RemoveDeviceConfig failed!");
    }

    /* Remove network configuration directly without notification to InterfaceService. */
    WifiSettings::GetInstance().RemoveDeviceConfig(msg->GetArg1());
    if (WifiSettings::GetInstance().SyncDeviceConfig() != 0) {
        LOGE("RemoveDeviceConfigProcess-SyncDeviceConfig() failed!");
    }
}

/* --------------------------- state machine WpaStopping State ------------------------------ */
StaStateMachine::WpaStoppingState::WpaStoppingState(StaStateMachine *staStateMachine) : State("WpaStoppingState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::WpaStoppingState::~WpaStoppingState()
{}

void StaStateMachine::WpaStoppingState::Enter()
{
    LOGE("WpaStoppingState Enter function.");
    pStaStateMachine->TransitionTo(pStaStateMachine->pInitState);
    return;
}

void StaStateMachine::WpaStoppingState::Exit()
{}

bool StaStateMachine::WpaStoppingState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    LOGI("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return ret;
}

/* --------------------------- state machine Connect State ------------------------------ */
StaStateMachine::ConnectState::ConnectState(StaStateMachine *staStateMachine) : State("ConnectState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::ConnectState::~ConnectState()
{}

void StaStateMachine::ConnectState::Enter()
{
    LOGI("ConnectState Enter function.");

    return;
}

void StaStateMachine::ConnectState::Exit()
{}

bool StaStateMachine::ConnectState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    auto iter = pStaStateMachine->staSmHandleFuncMap.find(msg->GetMessageName());
    if (iter != pStaStateMachine->staSmHandleFuncMap.end()) {
        (pStaStateMachine->*(iter->second))(msg);
        return HANDLED;
    }
    return NOT_HANDLED;
}

/* -- state machine Connect State Message processing function -- */
int StaStateMachine::InitStaSMHandleMap()
{
    staSmHandleFuncMap[CMD_START_CONNECT_SELECTED_NETWORK] = &StaStateMachine::DealConnectToSelectedNetCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CONNECT_NETWORK] = &StaStateMachine::DealConnectToUserSelectedNetwork;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK] = &StaStateMachine::DealConnectToUserSelectedNetwork;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT] = &StaStateMachine::DealDisconnectEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT] = &StaStateMachine::DealConnectionEvent;
    staSmHandleFuncMap[CMD_NETWORK_CONNECT_TIMEOUT] = &StaStateMachine::DealConnectTimeOutCmd;
    staSmHandleFuncMap[WPA_BLOCK_LIST_CLEAR_EVENT] = &StaStateMachine::DealWpaBlockListClearEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_STARTWPS] = &StaStateMachine::DealStartWpsCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET] = &StaStateMachine::DealWpsConnectTimeOutEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CANCELWPS] = &StaStateMachine::DealCancelWpsCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK] = &StaStateMachine::DealReassociateCmd;
    staSmHandleFuncMap[WIFI_SVR_COM_STA_START_ROAM] = &StaStateMachine::DealStartRoamCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT] = &StaStateMachine::DealWpaWrongPskEvent;
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::DealConnectToUserSelectedNetwork(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGI("enter ConnectToUserSelectedNetwork\n");
    int networkId = msg->GetArg1();
    bool forceReconnect = msg->GetArg2();

    /* Sets network status. */
    WifiSettings::GetInstance().EnableNetwork(networkId, forceReconnect);
    StartConnectToNetwork(networkId);
}

void StaStateMachine::DealConnectToSelectedNetCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGD("Enter StaStateMachine::DealConnectToSelectedNetCmd.\n");
    WifiDeviceConfig config;
    targetNetworkId = msg->GetArg1();

    SetRandomMac(targetNetworkId);
    SetTargetBssid(config, config.bssid);

    /* Sets linkedinfo */
    linkedInfo.networkId = targetNetworkId;
    linkedInfo.ssid = config.ssid;
    lastLinkedInfo.networkId = targetNetworkId;
    lastLinkedInfo.ssid = config.ssid;

    /* test */
    std::string countryCode;
    if (WifiSupplicantHalInterface::GetInstance().WpaGetCountryCode(countryCode) != WIFI_IDL_OPT_OK) {
        LOGE("WpaGetCountryCode() failed!");
    }
    LOGD("WpaGetCountryCode() success countryCode=%{public}s!", countryCode.c_str());

    if (WifiStaHalInterface::GetInstance().EnableNetwork(targetNetworkId) == WIFI_IDL_OPT_OK) {
        LOGD("EnableNetwork() succeed!");
        int connRes = WifiStaHalInterface::GetInstance().Connect(targetNetworkId);
        if (connRes == static_cast<int>(WIFI_IDL_OPT_OK)) {
            LOGD("Connect() succeed!");

            if (WifiStaHalInterface::GetInstance().SaveDeviceConfig() != WIFI_IDL_OPT_OK) {
                LOGE("SaveDeviceConfig() failed!");
            }
            LOGD("SaveDeviceConfig() succeed!");

            /* Update wifi status. */
            WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING));

            /* Save connection information. */
            SaveLinkstate(ConnState::CONNECTING, DetailedState::CONNECTING);

            /* Notify result to InterfaceService. */
            NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_CONNECTING));
            StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
        } else {
            LOGE("Connect failed!");
            NotifyResult(
                WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_SELECT_NETWORK_FAILED));
        }
    } else {
        LOGE("EnableNetwork() failed!");
    }
}

void StaStateMachine::DealConnectTimeOutCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("msg is nul\n");
    }
    LOGD("enter DealDisableOneNetCmd\n");
    DisableNetwork(linkedInfo.networkId);
    InitWifiLinkedInfo();
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);
    NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_CONNECTING_TIMEOUT));
}

void StaStateMachine::DealConnectionEvent(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGD("enter DealConnectionEvent");
    /* Stop clearing the Wpa_blocklist. */
    StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    ConnectToNetworkProcess(msg);

    if (wpsState != SetupMethod::INVALID) {
        SyncAllDeviceConfigs();
        wpsState = SetupMethod::INVALID;
    }
    /* Notify result to InterfaceService. */
    NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_AP_CONNECTED));

    /* The current state of StaStateMachine transfers to ObtainingIpState. */
    TransitionTo(pObtainingIpState);
}

void StaStateMachine::DealDisconnectEvent(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("msg is null\n");
    }

    LOGD("Enter DealDisconnectEvent.\n");
    pNetcheck->StopNetCheckThread();
    if (statusId == static_cast<int>(WifiDeviceConfigStatus::DISABLED)) {
        LOGD("The network status is DISABLED:1.\n");
        WifiSettings::GetInstance().SetDeviceState(lastNetworkId, static_cast<int>(WifiDeviceConfigStatus::DISABLED));
    } else if (statusId == static_cast<int>(WifiDeviceConfigStatus::ENABLED)) {
        LOGD("The network status is ENABLED:2.\n");
        WifiSettings::GetInstance().SetDeviceState(lastNetworkId, static_cast<int>(WifiDeviceConfigStatus::ENABLED));
    } else {
        LOGI("The network status is other:%{public}d.\n", statusId);
    }

    WifiSettings::GetInstance().SyncDeviceConfig();
    statusId = static_cast<int>(WifiDeviceConfigStatus::INVALID);
    /* Initialize connection informatoin. */
    InitWifiLinkedInfo();
    if (lastLinkedInfo.detailedState == DetailedState::CONNECTING) {
        linkedInfo.networkId = lastLinkedInfo.networkId;
        linkedInfo.ssid = lastLinkedInfo.ssid;
        linkedInfo.connState = ConnState::CONNECTING;
        linkedInfo.detailedState = DetailedState::CONNECTING;
        WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);
    } else {
        WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);
    }
    /* Notify result to InterfaceService. */
    NotifyResult(WifiInternalMsgCode::STA_DISCONNECT_RES, static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED));
    TransitionTo(pDisconnectedState);
}

void StaStateMachine::DealWpaWrongPskEvent(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("msg is null\n");
    }
    LOGD("enter DealStartWpsCmd\n");
    InitWifiLinkedInfo();
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);
    NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_PASSWORD_WRONG));
}

void StaStateMachine::DealReassociateCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("msg is null\n");
    }
    LOGD("enter DealStartWpsCmd\n");
    /* Obtains the current system time, assigns the timestamp of the last
     * connection attempt, and prohibits scanning requests within 10 seconds.
     */
    lastConnectToNetworkTimer = static_cast<int>(WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal());
    LOGD("the last time connect to network is %{public}d", lastConnectToNetworkTimer);

    if (WifiStaHalInterface::GetInstance().Reassociate() == WIFI_IDL_OPT_OK) {
        /* Notify result to InterfaceService */
        NotifyResult(WifiInternalMsgCode::STA_REASSOCIATE_RES, static_cast<int>(OperateResState::CONNECT_AP_CONNECTED));
        LOGD("StaStateMachine::ConnectState::ProcessMessage  ReAssociate successfully!");
    } else {
        LOGE("ReAssociate failed!");
    }
}

void StaStateMachine::DealStartWpsCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGD("enter DealStartWpsCmd\n");
    RemoveAllDeviceConfigs();
    StartWpsMode(msg);

    if (wpsState == SetupMethod::DISPLAY) {
        LOGD("Clear WPA block list every ten second!");
        SendMessage(WPA_BLOCK_LIST_CLEAR_EVENT);
    }
}

void StaStateMachine::StartWpsMode(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    constexpr int multiAp = 0;
    WifiIdlWpsConfig wpsParam;
    WpsConfig wpsConfig;
    wpsConfig.setup = static_cast<SetupMethod>(msg->GetArg1());
    wpsConfig.pin = msg->GetStringFromMessage();
    wpsConfig.bssid = msg->GetStringFromMessage();
    if (wpsConfig.bssid.length() == 0 || wpsConfig.bssid == PBC_ANY_BSSID) {
        wpsParam.anyFlag = 1;
        wpsParam.bssid = PBC_ANY_BSSID;
    } else {
        wpsParam.anyFlag = 0;
        wpsParam.bssid = wpsConfig.bssid;
    }
    wpsParam.multiAp = multiAp;
    LOGI("wpsConfig  setup = %{public}d", wpsConfig.setup);
    LOGI("wpsParam.AnyFlag = %{public}d, wpsParam.mulitAp = %{public}d, wpsParam.bssid = %s",
        wpsParam.anyFlag,
        wpsParam.multiAp,
        wpsParam.bssid.c_str());

    if (wpsConfig.setup == SetupMethod::PBC) {
        if (WifiStaHalInterface::GetInstance().StartWpsPbcMode(wpsParam) == WIFI_IDL_OPT_OK) {
            wpsState = wpsConfig.setup;
            LOGD("StartWpsPbcMode() succeed!");
            /* Notify result to InterfaceService. */
            NotifyResult(WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::START_PBC_SUCCEED));
            TransitionTo(pWpsState);
        } else {
            LOGE("StartWpsPbcMode() failed!");
            NotifyResult(WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::START_PBC_FAILED));
        }
    } else if (wpsConfig.setup == SetupMethod::DISPLAY) {
        if (WifiStaHalInterface::GetInstance().StartWpsPinMode(wpsParam, pinCode) == WIFI_IDL_OPT_OK) {
            wpsState = wpsConfig.setup;
            /* Notify result to InterfaceService. */
            NotifyResult(WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::START_PIN_SUCCEED));
            LOGD("StartWpsPinMode() succeed!  pincode: %d", pinCode);
            TransitionTo(pWpsState);
        } else {
            LOGE("StartWpsPinMode() failed!");
            NotifyResult(WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::START_PIN_FAILED));
        }
    } else {
        LOGE("Start Wps failed!");
        NotifyResult(WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::START_WPS_FAILED));
    }
}

void StaStateMachine::RemoveAllDeviceConfigs()
{
    std::vector<WifiWpaNetworkList> wpaNetworkList;
    WifiStaHalInterface::GetInstance().GetNetworkList(wpaNetworkList);
    for (std::vector<WifiWpaNetworkList>::iterator it = wpaNetworkList.begin(); it != wpaNetworkList.end(); it++) {
        WifiStaHalInterface::GetInstance().RemoveDeviceConfig(it->id);
    }
    WifiStaHalInterface::GetInstance().SaveDeviceConfig();
    LOGD("Remove all device configurations completed!");
    return;
}

void StaStateMachine::DealWpaBlockListClearEvent(InternalMessage *msg)
{
    if (msg != nullptr) {
        LOGD("enter DealWpaBlockListClearEvent\n");
    }
    if (WifiStaHalInterface::GetInstance().WpaBlocklistClear() != WIFI_IDL_OPT_OK) {
        LOGE("Clearing the Wpa_blocklist failed\n");
    }
    StartTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT), BLOCK_LIST_CLEAR_TIMER);
    LOGD("Clearing the Wpa_blocklist.\n");
}

void StaStateMachine::DealWpsConnectTimeOutEvent(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGD("enter DealWpsConnectTimeOutEvent\n");
    LOGD("Wps Time out!");
    DealCancelWpsCmd(msg);

    /* Notify InterfaceService that WPS time out. */
    NotifyResult(WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::WPS_TIME_OUT));
    TransitionTo(pDisconnectedState);
}

void StaStateMachine::DealCancelWpsCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("msg is null\n");
    }

    StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    isWpsConnect = IsWpsConnected::WPS_INVALID;
    if (WifiStaHalInterface::GetInstance().StopWps() == WIFI_IDL_OPT_OK) {
        LOGI("CancelWps succeed!");
        /* Notify result to InterfaceService that stop Wps connection successfully. */
        if (wpsState == SetupMethod::PBC) {
            NotifyResult(WifiInternalMsgCode::STA_CANCEL_WPS_RES, static_cast<int>(WpsStartState::STOP_PBC_SUCCEED));
        } else if (wpsState == SetupMethod::DISPLAY) {
            NotifyResult(WifiInternalMsgCode::STA_CANCEL_WPS_RES, static_cast<int>(WpsStartState::STOP_PIN_SUCCEED));
        }
        if (wpsState != SetupMethod::INVALID) {
            wpsState = SetupMethod::INVALID;
            SyncAllDeviceConfigs();

            if (WifiStaHalInterface::GetInstance().EnableNetwork(lastNetworkId) == WIFI_IDL_OPT_OK) {
                LOGI("EnableNetwork success! networkId is %{public}d", lastNetworkId);
                if (WifiStaHalInterface::GetInstance().SaveDeviceConfig() != WIFI_IDL_OPT_OK) {
                    LOGE("SaveDeviceConfig failed!");
                }
                LOGI("SaveDeviceConfig success!");
            } else {
                LOGE("EnableNetwork failed");
            }
        }
    } else {
        LOGE("CancelWps failed!");
        if (wpsState == SetupMethod::PBC) {
            NotifyResult(WifiInternalMsgCode::STA_CANCEL_WPS_RES, static_cast<int>(WpsStartState::STOP_PBC_FAILED));
        } else if (wpsState == SetupMethod::DISPLAY) {
            NotifyResult(WifiInternalMsgCode::STA_CANCEL_WPS_RES, static_cast<int>(WpsStartState::STOP_PIN_FAILED));
        }
    }
    TransitionTo(pDisconnectedState);
}

void StaStateMachine::DealStartRoamCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    LOGD("enter DealStartRoamCmd\n");
    std::string bssid = msg->GetStringFromMessage();
    /* GetDeviceConfig from Configuration center. */
    WifiDeviceConfig network;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, network);

    /* Setting the network. */
    WifiIdlDeviceConfig idlConfig;
    idlConfig.networkId = linkedInfo.networkId;
    idlConfig.ssid = linkedInfo.ssid;
    idlConfig.bssid = bssid;
    idlConfig.psk = network.preSharedKey;
    idlConfig.keyMgmt = network.keyMgmt;
    idlConfig.priority = network.priority;
    idlConfig.scanSsid = network.hiddenSSID ? 1 : 0;
    idlConfig.eap = network.wifiEapConfig.eap;
    idlConfig.identity = network.wifiEapConfig.identity;
    idlConfig.password = network.wifiEapConfig.password;

    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(linkedInfo.networkId, idlConfig) != WIFI_IDL_OPT_OK) {
        LOGE("DealStartRoamCmd SetDeviceConfig() failed!");
        return;
    }
    LOGD("DealStartRoamCmd  SetDeviceConfig() succeed!");

    /* Save to Configuration center. */
    network.bssid = bssid;
    WifiSettings::GetInstance().AddDeviceConfig(network);
    WifiSettings::GetInstance().SyncDeviceConfig();

    /* Save linkedinfo */
    linkedInfo.bssid = bssid;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);

    /* Start roaming */
    TransitionTo(pRoamingState);
    if (WifiStaHalInterface::GetInstance().Reassociate() != WIFI_IDL_OPT_OK) {
        LOGE("START_ROAM-ReAssociate() failed!");
    }
    LOGI("START_ROAM-ReAssociate() succeeded!");
}

void StaStateMachine::StartConnectToNetwork(int networkId)
{
    InternalMessage *msg = ObtainMessage();
    if (msg == nullptr) {
        return;
    }

    msg->SetMessageName(CMD_START_CONNECT_SELECTED_NETWORK);
    msg->SetArg1(networkId);
    SendMessage(msg);
}

void StaStateMachine::StartRoamToNetwork(std::string bssid)
{
    InternalMessage *msg = ObtainMessage();
    if (msg == nullptr) {
        return;
    }

    msg->SetMessageName(WIFI_SVR_COM_STA_START_ROAM);
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

void StaStateMachine::OnNetworkConnectionEvent(int networkId, std::string bssid)
{
    InternalMessage *msg = ObtainMessage();
    if (msg == nullptr) {
        return;
    }

    msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
    msg->SetArg1(networkId);
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

void StaStateMachine::SyncLinkInfo(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaStateMachine::SyncLinkInfo.\n");
    if (scanResults.empty()) {
        return;
    }
    for (auto scanInfo : scanResults) {
        if ((scanInfo.ssid == linkedInfo.ssid) && (scanInfo.bssid == linkedInfo.bssid)) {
            InternalMessage *msg = ObtainMessage();
            if (msg == nullptr) {
                break;
            }
            msg->SetMessageName(CMD_SYNC_LINKINFO);
            msg->SetArg1(scanInfo.level);
            msg->SetArg2(scanInfo.frequency);
            msg->AddStringMessageBody(scanInfo.capabilities);
            LOGI("scanInfo.level == [%{public}d]\n", scanInfo.level);
            LOGI("scanInfo.frequency == [%{public}d]\n", scanInfo.frequency);
            LOGI("scanInfo.capabilities ==[%{public}s]\n", scanInfo.capabilities.c_str());
            SendMessage(msg);
            return;
        }
    }
}

/* --------------------------- state machine Disconnecting State ------------------------------ */
StaStateMachine::DisconnectingState::DisconnectingState(StaStateMachine *staStateMachine) : State("DisconnectingState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::DisconnectingState::~DisconnectingState()
{}

void StaStateMachine::DisconnectingState::Enter()
{
    LOGI("DisconnectingState Enter function.");

    return;
}

void StaStateMachine::DisconnectingState::Exit()
{}

bool StaStateMachine::DisconnectingState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    LOGI("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return ret;
}

/* --------------------------- state machine Disconnected State ------------------------------ */
StaStateMachine::DisconnectedState::DisconnectedState(StaStateMachine *staStateMachine) : State("DisconnectedState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::DisconnectedState::~DisconnectedState()
{}

void StaStateMachine::DisconnectedState::Enter()
{
    LOGI("DisconnectedState Enter function.");

    return;
}

void StaStateMachine::DisconnectedState::Exit()
{}

bool StaStateMachine::DisconnectedState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_COM_STA_SET_COUNTRY_CODE: {
            ret = HANDLED;
            /* Get code from config center. */
            std::string countryCode;
            WifiSettings::GetInstance().GetCountryCode(countryCode);

            LOGI("WpaSetCountryCode()  countryCode=%{public}s!", countryCode.c_str());
            if (WifiSupplicantHalInterface::GetInstance().WpaSetCountryCode(countryCode) != WIFI_IDL_OPT_OK) {
                LOGE("WpaSetCountryCode() failed!");
            }
            LOGI("WpaSetCountryCode() succeed countryCode=%{public}s!", countryCode.c_str());
            break;
        }

        case WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT:
            break;

        case WIFI_SVR_CMD_STA_ENABLE_WIFI: {
            ret = HANDLED;
            LOGE("Wifi has already started! start Wifi failed!");
            /* Notify result to InterfaceService. */
            pStaStateMachine->NotifyResult(
                WifiInternalMsgCode::STA_OPEN_RES, static_cast<int>(OperateResState::OPEN_WIFI_OVERRIDE_OPEN_FAILED));
            break;
        }

        default:
            break;
    }

    return ret;
}

void StaStateMachine::SetCountryCode()
{
    SendMessage(WIFI_SVR_COM_STA_SET_COUNTRY_CODE);
}

/* --------------------------- state machine ApConnected State ------------------------------ */
StaStateMachine::ApConnectedState::ApConnectedState(StaStateMachine *staStateMachine) : State("ApConnectedState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::ApConnectedState::~ApConnectedState()
{}

void StaStateMachine::ApConnectedState::Enter()
{
    LOGI("ApConnectedState Enter function.");
    return;
}

void StaStateMachine::ApConnectedState::Exit()
{}

bool StaStateMachine::ApConnectedState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        /* The current state of StaStateMachine transfers to DisConnectingState when
         * receive the disconnecting message.
         */
        case WIFI_SVR_CMD_STA_DISCONNECT: {
            ret = HANDLED;
            pStaStateMachine->DisConnectProcess();
            break;
        }
        case CMD_SYNC_LINKINFO: {
            ret = HANDLED;
            pStaStateMachine->linkedInfo.rssi = msg->GetArg1();
            pStaStateMachine->linkedInfo.frequency = msg->GetArg2();
            pStaStateMachine->GetBandFromFreQuencies(pStaStateMachine->linkedInfo.frequency);
            WifiSettings::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo);
            std::string mgmt = msg->GetStringFromMessage();
            pStaStateMachine->SynchronousEncryptionModeAandBand(mgmt);
            break;
        }
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            ret = HANDLED;
            pStaStateMachine->StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
            LOGI("Stop clearing wpa block list");
            /* Save linkedinfo */
            pStaStateMachine->linkedInfo.networkId = msg->GetArg1();
            pStaStateMachine->linkedInfo.bssid = msg->GetStringFromMessage();
            WifiSettings::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo);

            break;
        }
        case CMD_GET_NETWORK_SPEED: {
            ret = HANDLED;
            pStaStateMachine->pNetSpeed->GetNetSpeed(
                pStaStateMachine->linkedInfo.rxLinkSpeed, pStaStateMachine->linkedInfo.txLinkSpeed); /* Obtains rate */
            WifiSettings::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo);
            pStaStateMachine->StartTimer(static_cast<int>(CMD_GET_NETWORK_SPEED), STA_NETWORK_SPEED_DELAY);
            break;
        }
        default:
            break;
    }
    return ret;
}

void StaStateMachine::SynchronousEncryptionModeAandBand(std::string mgmt)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config) != 0) {
        LOGE("GetDeviceConfig failed!");
    }
    config.band = linkedInfo.band;
    if (mgmt.find("WPA-PSK") != std::string::npos || mgmt.find("WPA2-PSK") != std::string::npos) {
        mgmt = "WPA-PSK";
        config.keyMgmt = mgmt;
    } else if (mgmt.find("EAP") != std::string::npos) {
        mgmt = "WPA-EAP";
        config.keyMgmt = mgmt;
    } else if (mgmt.find("SAE") != std::string::npos) {
        mgmt = "SAE";
        config.keyMgmt = mgmt;
    } else {
        if (mgmt.find("WEP") != std::string::npos) {
            WepEncryptionModeIndex(config);
        }
    }
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
}

void StaStateMachine::WepEncryptionModeIndex(WifiDeviceConfig &config)
{
    for (int i = 0; i < MAX_WEPKEYS_SIZE; i++) {
        if (config.wepKeys[i].size() != 0) {
            config.wepTxKeyIndex = i + 1;
        }
    }
}
void StaStateMachine::DisConnectProcess()
{
    if (WifiStaHalInterface::GetInstance().Disconnect() == WIFI_IDL_OPT_OK) {
        LOGI("Disconnect() succeed!");
        /* Save connection information to WifiSettings. */
        SaveLinkstate(ConnState::DISCONNECTED, DetailedState::DISCONNECTED);

        DisableNetwork(linkedInfo.networkId);

        /* Notify result to InterfaceService. */
        NotifyResult(
            WifiInternalMsgCode::STA_DISCONNECT_RES, static_cast<int>(OperateResState::DISCONNECT_DISCONNECTING));

        /* The current state of StaStateMachine transfers to DisconnectedState. */
        TransitionTo(pDisconnectedState);
    } else {
        NotifyResult(
            WifiInternalMsgCode::STA_DISCONNECT_RES, static_cast<int>(OperateResState::DISCONNECT_DISCONNECT_FAILED));
        LOGE("Disconnect() failed!");
    }
}

void StaStateMachine::GetBandFromFreQuencies(const int &freQuency)
{
    std::vector<int> freqs2G;
    std::vector<int> freqs5G;
    if ((WifiStaHalInterface::GetInstance().GetSupportFrequencies(BAND_ONE, freqs2G) == WIFI_IDL_OPT_OK)) {
        std::vector<int>::iterator it = find(freqs2G.begin(), freqs2G.end(), freQuency);
        if (it != freqs2G.end()) {
            linkedInfo.band = BAND_2_G;
            return;
        }
    } else {
        LOGE("GetSupportFrequencies 2.4Gband failed!\n");
    }

    if ((WifiStaHalInterface::GetInstance().GetSupportFrequencies(BAND_TWO, freqs5G) == WIFI_IDL_OPT_OK)) {
        std::vector<int>::iterator it = find(freqs5G.begin(), freqs5G.end(), freQuency);
        if (it != freqs5G.end()) {
            linkedInfo.band = BAND_5_G;
        } else {
            LOGE("frequency convert band failed!\n");
        }
    } else {
        LOGE("GetSupportFrequencies 5Gband failed!\n");
    }
}

/* --------------------------- state machine Wps State ------------------------------ */
StaStateMachine::WpsState::WpsState(StaStateMachine *staStateMachine) : State("WpsState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::WpsState::~WpsState()
{}

void StaStateMachine::WpsState::Enter()
{
    LOGI("WpsState Enter function.");
    return;
}

void StaStateMachine::WpsState::Exit()
{}

bool StaStateMachine::WpsState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_WPS_START_EVENT: {
            /* Wps starts successfully and Wait until the connection is complete. */
            break;
        }
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            ret = HANDLED;
            /* Stop clearing the Wpa_blocklist. */
            pStaStateMachine->StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));

            LOGI("WPS mode connect to a network!");
            pStaStateMachine->ConnectToNetworkProcess(msg);
            pStaStateMachine->SyncAllDeviceConfigs();
            /* Notify result to InterfaceService. */
            pStaStateMachine->NotifyResult(
                WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_AP_CONNECTED));
            pStaStateMachine->TransitionTo(pStaStateMachine->pObtainingIpState);
            break;
        }
        case WIFI_SVR_CMD_STA_STARTWPS: {
            ret = HANDLED;
            auto setup = static_cast<SetupMethod>(msg->GetArg1());
            /* Notify InterfaceService that wps has started successfully. */
            LOGE("WPS has already started, start wps failed!");
            if (setup == SetupMethod::PBC) {
                pStaStateMachine->NotifyResult(
                    WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::PBC_STARTED_ALREADY));
            } else if (setup == SetupMethod::DISPLAY) {
                pStaStateMachine->NotifyResult(
                    WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::PIN_STARTED_ALREADY));
            }
            break;
        }
        case WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT: {
            ret = HANDLED;
            LOGI("Wps PBC Overlap!");
            /* Notify InterfaceService that PBC is conflicting. */
            pStaStateMachine->NotifyResult(
                WifiInternalMsgCode::STA_START_WPS_RES, static_cast<int>(WpsStartState::START_PBC_FAILED_OVERLAP));
            pStaStateMachine->TransitionTo(pStaStateMachine->pDisconnectedState);
            break;
        }
        case WIFI_SVR_CMD_STA_CANCELWPS: {
            ret = HANDLED;
            pStaStateMachine->SyncAllDeviceConfigs();
            pStaStateMachine->DealCancelWpsCmd(msg);
            break;
        }
        default:
            break;
    }
    return ret;
}

void StaStateMachine::SyncAllDeviceConfigs()
{
    std::vector<WifiDeviceConfig> result;
    WifiIdlDeviceConfig idlConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(result) != -1) {
        for (std::vector<WifiDeviceConfig>::iterator it = result.begin(); it != result.end(); it++) {
            if (isWpsConnect == IsWpsConnected::WPS_CONNECTED && it->networkId == 0) {
                continue;
            }
            if (WifiStaHalInterface::GetInstance().GetNextNetworkId(it->networkId) == WIFI_IDL_OPT_OK) {
                LOGI("GetNextNetworkId succeed");
                idlConfig.networkId = it->networkId;
                idlConfig.ssid = it->ssid;
                idlConfig.psk = it->preSharedKey;
                idlConfig.keyMgmt = it->keyMgmt;
                idlConfig.priority = it->priority;
                idlConfig.scanSsid = it->hiddenSSID ? 1 : 0;
                idlConfig.eap = it->wifiEapConfig.eap;
                idlConfig.identity = it->wifiEapConfig.identity;
                idlConfig.password = it->wifiEapConfig.password;
                if (WifiStaHalInterface::GetInstance().SetDeviceConfig(it->networkId, idlConfig) != WIFI_IDL_OPT_OK) {
                    LOGE("SetDeviceConfig failed!");
                }
                LOGD("SetDeviceConfig succeed!");
            } else {
                LOGE("GetNextNetworkId failed!");
            }
            LOGD("networkId = %{public}d", it->networkId);
            WifiStaHalInterface::GetInstance().SaveDeviceConfig();
        }
        LOGD("Synchronizing network information!");
    } else {
        LOGE("The Device config in WifiSettings is empty!");
    }
}

/* --------------------------- state machine ObtainingIp State ------------------------------ */
StaStateMachine::ObtainingIpState::ObtainingIpState(StaStateMachine *staStateMachine) : State("ObtainingIpState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::ObtainingIpState::~ObtainingIpState()
{}

void StaStateMachine::ObtainingIpState::Enter()
{
    LOGI("ObtainingIpState Enter function.");

    WifiDeviceConfig config;
    AssignIpMethod assignMethod = AssignIpMethod::DHCP;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config);
    if (ret == 0) {
        assignMethod = config.wifiIpConfig.assignMethod;
    }

    if (config.wifiProxyconfig.configureMethod == ConfigureProxyMethod::MANUALCONFIGUE) {
        std::string hostName = config.wifiProxyconfig.manualProxyConfig.serverHostName;
        std::string noProxys = config.wifiProxyconfig.manualProxyConfig.exclusionObjectList;
        std::string port = std::to_string(config.wifiProxyconfig.manualProxyConfig.serverPort);
        if (!hostName.empty()) {
            IfConfig::GetInstance().SetProxy(false, hostName, port, noProxys, "");
        }
    }

    if (assignMethod == AssignIpMethod::STATIC) {
        pStaStateMachine->currentTpType = config.wifiIpConfig.staticIpAddress.ipAddress.address.family;
        if (!pStaStateMachine->ConfigStaticIpAddress(config.wifiIpConfig.staticIpAddress)) {
            LOGE("ConfigStaticIpAddress failed!.\n");
        }
    } else {
        pStaStateMachine->currentTpType = static_cast<int>(WifiSettings::GetInstance().GetDhcpIpType());
        pStaStateMachine->pDhcpServer->SignalDhcpThread(pStaStateMachine->currentTpType);
    }

    return;
}

void StaStateMachine::ObtainingIpState::Exit()
{}

bool StaStateMachine::ObtainingIpState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    LOGI("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return ret;
}

/* --- state machine ObtainingIp State functions ----- */
bool StaStateMachine::ConfigStaticIpAddress(StaticIpAddress &staticIpAddress)
{
    LOGI("Enter StaStateMachine::SetDhcpResultFromStatic.");

    DhcpResult result;

    switch (currentTpType) {
        case IPTYPE_IPV4: {
            result[0].isOptSuc = true;
            result[0].iptype = IPTYPE_IPV4;
            result[0].ip = staticIpAddress.ipAddress.address.GetIpv4Address();
            result[0].gateWay = staticIpAddress.gateway.GetIpv4Address();
            result[0].subnet = staticIpAddress.GetIpv4Mask();
            result[0].dns = staticIpAddress.dnsServer1.GetIpv4Address();
            result[0].dns2 = staticIpAddress.dnsServer2.GetIpv4Address();
            result[1].isOptSuc = false;
            break;
        }
        case IPTYPE_IPV6: {
            result[0].isOptSuc = false;

            result[1].isOptSuc = true;
            result[1].iptype = IPTYPE_IPV6;
            result[1].ip = staticIpAddress.ipAddress.address.GetIpv6Address();
            result[1].gateWay = staticIpAddress.gateway.GetIpv6Address();
            result[1].subnet = staticIpAddress.GetIpv6Mask();
            result[1].dns = staticIpAddress.dnsServer1.GetIpv6Address();
            result[1].dns2 = staticIpAddress.dnsServer2.GetIpv6Address();
            break;
        }
        case IPTYPE_MIX: {
            result[0].isOptSuc = true;
            result[0].iptype = IPTYPE_IPV4;
            result[0].ip = staticIpAddress.ipAddress.address.GetIpv4Address();
            result[0].gateWay = staticIpAddress.gateway.GetIpv4Address();
            result[0].subnet = staticIpAddress.GetIpv4Mask();
            result[0].dns = staticIpAddress.dnsServer1.GetIpv4Address();
            result[0].dns2 = staticIpAddress.dnsServer2.GetIpv4Address();

            result[1].isOptSuc = true;
            result[1].iptype = IPTYPE_IPV6;
            result[1].ip = staticIpAddress.ipAddress.address.GetIpv6Address();
            result[1].gateWay = staticIpAddress.gateway.GetIpv6Address();
            result[1].subnet = staticIpAddress.GetIpv6Mask();
            result[1].dns = staticIpAddress.dnsServer1.GetIpv6Address();
            result[1].dns2 = staticIpAddress.dnsServer2.GetIpv6Address();
            break;
        }

        default:
            return false;
    }

    HandleDhcpResult(result);
    return true;
}

void StaStateMachine::HandleDhcpResult(const DhcpResult &dhcpResult)
{
    LOGI("Enter HandleDhcpResult");
    bool isGetIpSuc = false;
    bool isSetIpSuc = false;

    /* number 2 is the number of ip_type。 */
    for (int index = 0; index < 2; index++) {
        LOGI("HandleDhcpResult:isOptSuc=%{public}d, iptype=%{public}d, ip=%s, gateway=%s, "
             "subnet=%s",
            dhcpResult[index].isOptSuc,
            dhcpResult[index].iptype,
            dhcpResult[index].ip.c_str(),
            dhcpResult[index].gateWay.c_str(),
            dhcpResult[index].subnet.c_str());
        if (dhcpResult[index].isOptSuc) {
            /* Configures network adapter. */
            if (index == 0) {
                linkedInfo.ipAddress = IpTools::ConvertIpv4Address(dhcpResult[index].ip);
                WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);
            }
            isGetIpSuc = true;
        }
    }

    /* Configures network adapter. */
    int ret = IfConfig::GetInstance().SetIfAddr(dhcpResult);
    if (ret == 0) {
        isSetIpSuc = true;
    }

    if (!isGetIpSuc) {
        SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
        statusId = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
        NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_NETWORK_DISABLED));
        LOGE("HandleDhcpResult get ip addr failed!");
        return;
    }

    if (!isSetIpSuc) {
        SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
        statusId = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
        NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_NETWORK_DISABLED));
        LOGE("HandleDhcpResult SetIfConfig failed!");
        return;
    } else {
        LOGI("HandleDhcpResult SetIfConfig succeed!");
        /* Update the uplink and downlink network rates periodically. */
        StartTimer(static_cast<int>(CMD_GET_NETWORK_SPEED), STA_NETWORK_SPEED_DELAY);
    }

    sleep(SLEEPTIME); /* Wait for the network adapter information to take effect. */

    /* Portal hotspot checking. */
    if (PortalHttpDetection() != 0) {
        pNetcheck->SignalNetCheckThread(currentTpType);
    }
    /* Check whether the Internet access is normal by ping command. */
}

void StaStateMachine::HandleNetCheckResult(StaNetState netState)
{
    LOGI("Enter HandleNetCheckResult");
    if (linkedInfo.connState == ConnState::DISCONNECTED) {
        LOGE("Network disconnected\n");
        return;
    }

    if (netState == StaNetState::NETWORK_STATE_WORKING) {
        LOGI("HandleNetCheckResult network state is working\n");
        /* Save connection information to WifiSettings. */
        SaveLinkstate(ConnState::CONNECTED, DetailedState::WORKING);
        statusId = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_NETWORK_ENABLED));
        /* The current state of StaStateMachine transfers to ConnectedState. */
        TransitionTo(pConnectedState);
    } else {
        LOGI("HandleNetCheckResult network state is notworking\n");
        SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
        statusId = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
        NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_NETWORK_DISABLED));
    }
}

int StaStateMachine::PortalHttpDetection()
{
    LOGI("EnterPortalHttpDetection");

    /* Detect portal hotspot and send message to InterfaceSeervice if result is yes. */
    HttpRequest httpRequest;
    std::string httpReturn;
    std::string httpMsg(DEFAULT_PORTAL_HTTPS_URL);

    if (httpRequest.HttpGet(httpMsg, httpReturn) == 0) {
        if (httpReturn.find("204") != std::string::npos) {
            LOGE("This network is not Portal AP!");
            return WIFI_OPT_FAILED;
        } else {
            /* Notify result to InterfaceService. */
            LOGI("This network is portal AP,need certification!");
            NotifyResult(WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_CHECK_PORTAL));
            return 0;
        }
    }
    LOGE("Portal check failed!");
    return WIFI_OPT_FAILED;
}

/* --------------------------- state machine Connected State ------------------------------ */
StaStateMachine::ConnectedState::ConnectedState(StaStateMachine *staStateMachine) : State("ConnectedState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::ConnectedState::~ConnectedState()
{}

void StaStateMachine::ConnectedState::Enter()
{
    LOGI("ConnectedState Enter function.");

    return;
}

void StaStateMachine::ConnectedState::Exit()
{
    LOGI("ConnectedState Exit function.");
}

bool StaStateMachine::ConnectedState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = HANDLED;
    LOGI("DefaultState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return ret;
}

/* --------------------------- state machine Roaming State ------------------------------ */
StaStateMachine::RoamingState::RoamingState(StaStateMachine *staStateMachine) : State("RoamingState")
{
    pStaStateMachine = staStateMachine;
}

StaStateMachine::RoamingState::~RoamingState()
{}

void StaStateMachine::RoamingState::Enter()
{
    LOGI("RoamingState Enter function.");
}

void StaStateMachine::RoamingState::Exit()
{}

bool StaStateMachine::RoamingState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_HANDLED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            ret = HANDLED;
            pStaStateMachine->ConnectToNetworkProcess(msg);
            /* Notify result to InterfaceService. */
            pStaStateMachine->NotifyResult(
                WifiInternalMsgCode::STA_CONNECT_RES, static_cast<int>(OperateResState::CONNECT_AP_CONNECTED));

            /* The current state of StaStateMachine transfers to ObtainingIpState. */
            pStaStateMachine->TransitionTo(pStaStateMachine->pObtainingIpState);
            break;
        }
        default:
            break;
    }

    return HANDLED;
}

void StaStateMachine::ConnectToNetworkProcess(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    
    lastNetworkId = msg->GetArg1();
    std::string bssid = msg->GetStringFromMessage();

    WifiDeviceConfig deviceConfig;
    int result = WifiSettings::GetInstance().GetDeviceConfig(lastNetworkId, deviceConfig);
    LOGI("Device config networkId = %{public}d", deviceConfig.networkId);

    LOGI("Connected to AP[networkid=%{public}d], obtaining ip...", lastNetworkId);
    /* Update wifi status. */
    WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED));

    /* Save connection information. */
    WifiIdlGetDeviceConfig config;
    config.networkId = lastNetworkId;
    config.param = "ssid";
    if (WifiStaHalInterface::GetInstance().GetDeviceConfig(config) != WIFI_IDL_OPT_OK) {
        LOGE("GetDeviceConfig failed!");
    }

    if (result == 0 && deviceConfig.bssid == bssid) {
        LOGI("Device config already exists.");
    } else {
        deviceConfig.networkId = lastNetworkId;
        deviceConfig.bssid = bssid;
        deviceConfig.ssid = config.value;
        deviceConfig.ssid.erase(0, 1);
        deviceConfig.ssid.erase(deviceConfig.ssid.length() - 1, 1);
        if (wpsState == SetupMethod::DISPLAY || wpsState == SetupMethod::PBC) {
            WifiSettings::GetInstance().AddWpsDeviceConfig(deviceConfig);
            isWpsConnect = IsWpsConnected::WPS_CONNECTED;
        } else {
            WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        }
        WifiSettings::GetInstance().SyncDeviceConfig();
        LOGD("Device ssid = %s", deviceConfig.ssid.c_str());
    }
    WifiSettings::GetInstance().SetDeviceState(lastNetworkId, static_cast<int>(WifiDeviceConfigStatus::CURRENT));
    LOGD("The network status is CURRENT:0.");
    linkedInfo.networkId = lastNetworkId;
    linkedInfo.bssid = bssid;
    linkedInfo.ssid = deviceConfig.ssid;
    linkedInfo.macAddress = deviceConfig.macAddress;
    lastLinkedInfo.bssid = bssid;
    lastLinkedInfo.macAddress = deviceConfig.macAddress;
    SetWifiLinkedInfo(lastNetworkId);
    SaveLinkstate(ConnState::OBTAINING_IPADDR, DetailedState::OBTAINING_IPADDR);
}

void StaStateMachine::SetWifiLinkedInfo(int networkId)
{
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        if (lastLinkedInfo.networkId != INVALID_NETWORK_ID) {
            /* Update connection information according to the last connecting information. */
            linkedInfo.networkId = lastLinkedInfo.networkId;
            linkedInfo.ssid = lastLinkedInfo.ssid;
            linkedInfo.bssid = lastLinkedInfo.bssid;
            linkedInfo.macAddress = lastLinkedInfo.macAddress;
            linkedInfo.rssi = lastLinkedInfo.rssi;
            linkedInfo.band = lastLinkedInfo.band;
            linkedInfo.frequency = lastLinkedInfo.frequency;
            linkedInfo.linkSpeed = lastLinkedInfo.linkSpeed;
            linkedInfo.ipAddress = lastLinkedInfo.ipAddress;
            linkedInfo.connState = lastLinkedInfo.connState;
            linkedInfo.ifHiddenSSID = lastLinkedInfo.ifHiddenSSID;
            linkedInfo.rxLinkSpeed = lastLinkedInfo.rxLinkSpeed;
            linkedInfo.txLinkSpeed = lastLinkedInfo.txLinkSpeed;
            linkedInfo.chload = lastLinkedInfo.chload;
            linkedInfo.snr = lastLinkedInfo.snr;
            linkedInfo.detailedState = lastLinkedInfo.detailedState;
        } else if (networkId != INVALID_NETWORK_ID) {
            linkedInfo.networkId = networkId;
            WifiDeviceConfig config;
            int ret = WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
            if (ret == 0) {
                /* Update connection information according to configuration. */
                linkedInfo.networkId = config.networkId;
                linkedInfo.ssid = config.ssid;
                linkedInfo.bssid = config.bssid;
                linkedInfo.band = config.band;
                linkedInfo.connState = ConnState::OBTAINING_IPADDR;
                linkedInfo.ifHiddenSSID = config.hiddenSSID;
                linkedInfo.detailedState = DetailedState::OBTAINING_IPADDR;

                lastLinkedInfo.networkId = config.networkId;
                lastLinkedInfo.ssid = config.ssid;
                lastLinkedInfo.bssid = config.bssid;
                lastLinkedInfo.band = config.band;
                lastLinkedInfo.connState = ConnState::OBTAINING_IPADDR;
                lastLinkedInfo.ifHiddenSSID = config.hiddenSSID;
                lastLinkedInfo.detailedState = DetailedState::OBTAINING_IPADDR;
            }
        }
    }
}

/* ------------------ state machine Comment function ----------------- */
void StaStateMachine::NotifyResult(int msgCode, int stateCode)
{
    LOGI("NotifyResult msgCode=%{public}d, stateCode=%{public}d.", msgCode, stateCode);

    WifiResponseMsgInfo notifyMsg;
    notifyMsg.msgCode = msgCode;
    if (msgCode == WifiInternalMsgCode::STA_CONNECT_RES || msgCode == WifiInternalMsgCode::STA_DISCONNECT_RES) {
        notifyMsg.params.linkedInfo = linkedInfo;
    } else if (msgCode == WifiInternalMsgCode::STA_START_WPS_RES) {
        notifyMsg.params.argInt = pinCode;
    }
    notifyMsg.params.result = stateCode;
    if (msgQueueUp != nullptr) {
        msgQueueUp->Push(notifyMsg);
    }
    return;
}

void StaStateMachine::SaveLinkstate(ConnState state, DetailedState detailState)
{
    linkedInfo.connState = state;
    linkedInfo.detailedState = detailState;
    lastLinkedInfo.connState = state;
    lastLinkedInfo.detailedState = detailState;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo);
}

void StaStateMachine::DisableNetwork(int networkId)
{
    if (WifiStaHalInterface::GetInstance().DisableNetwork(networkId) == WIFI_IDL_OPT_OK) {
        LOGI("DisableNetwork() succeed, networkId=%{public}d", networkId);

        if (WifiStaHalInterface::GetInstance().SaveDeviceConfig() == WIFI_IDL_OPT_OK) {
            LOGI("DisableNetwork-SaveDeviceConfig() succeed!");
        } else {
            LOGE("DisableNetwork-SaveDeviceConfig() failed!");
        }
    } else {
        LOGE("DisableNetwork() failed, networkId=%{public}d", networkId);
    }
}

void StaStateMachine::SetOperationalMode(int mode)
{
    SendMessage(WIFI_SVR_CMD_STA_OPERATIONAL_MODE, mode, 0);
}

bool StaStateMachine::SetTargetBssid(const WifiDeviceConfig &config, std::string &bssid)
{
    LOGI("enter SetTargetBssid![%s]\n", bssid.c_str());
    return true;
}

void StaStateMachine::MacAddressGenerate(std::string &strMac)
{
    char szMacStr[] = "0123456789abcdef";
    std::random_device rd;
    for (int i = 0; i < MAC_LENGTH; i++) {
        int rndnum = std::abs((int)rd());
        if (i != 1) {
            strMac.push_back(szMacStr[rndnum % RAND_SEED_16]);
        } else {
            strMac.push_back(szMacStr[MAC_STEP * (rndnum % RAND_SEED_8)]);
        }
        if ((i % MAC_STEP) != 0 && (i != MAC_LENGTH-1)) {
            strMac.push_back(':');
        }
    }
}

bool StaStateMachine::SetRandomMac(const int networkId)
{
    std::string strMac;
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig) == 0) {
        if (!deviceConfig.macAddress.empty()) {
            strMac = deviceConfig.macAddress;
        } else {
            MacAddressGenerate(strMac);
            deviceConfig.macAddress = strMac;
            WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
            WifiSettings::GetInstance().SyncDeviceConfig();
        }

        if (CheckMacFormat(strMac) == 0) {
            LOGI("Check MacAddress successfully.\n");
            if (WifiStaHalInterface::GetInstance().SetConnectMacAddr(strMac) != WIFI_IDL_OPT_OK) {
                LOGE("wlan0 set Mac [%s] failed.\n", strMac.c_str());
                return false;
            }
            return true;
        } else {
            LOGE("Check MacAddress error.\n");
            return false;
        }
    } else {
        LOGE("SetRandomMac GetDeviceConfig failed!");
        return false;
    }
}

int StaStateMachine::CheckMacFormat(const std::string &mac)
{
    int status;
    const std::string pattern = "^([A-Fa-f0-9]{2}[-,:]){5}[A-Fa-f0-9]{2}$";
    const int cflags = REG_EXTENDED | REG_NEWLINE;

    char ebuf[BUFFER_SIZE] = {0};
    regmatch_t pmatch[1];
    const size_t nmatch = 1;
    regex_t reg;

    status = regcomp(&reg, pattern.c_str(), cflags);
    if (status != 0) {
        regerror(status, &reg, ebuf, sizeof(ebuf));
        fprintf(stderr, "regcomp failed: %s , pattern: %s \n", ebuf, pattern.c_str());
        regfree(&reg);
        return -1;
    }

    status = regexec(&reg, mac.c_str(), nmatch, pmatch, 0);
    if (status != 0) {
        regerror(status, &reg, ebuf, sizeof(ebuf));
        LOGE("regexec failed.");
        regfree(&reg);
        return -1;
    }

    printf("[%s] match success.\n", __FUNCTION__);
    regfree(&reg);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS