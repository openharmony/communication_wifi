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
#include "provision_discovery_state.h"
#include "p2p_state_machine.h"
#include "wifi_p2p_temp_disc_event.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_logger.h"
#include "wifi_hisysevent.h"

DEFINE_WIFILOG_P2P_LABEL("ProvisionDiscoveryState");

namespace OHOS {
namespace Wifi {
ProvisionDiscoveryState::ProvisionDiscoveryState(P2pStateMachine &stateMachine, WifiP2pGroupManager &setGroupMgr,
    WifiP2pDeviceManager &setDeviceMgr)
    : State("ProvisionDiscoveryState"),
      p2pStateMachine(stateMachine),
      groupManager(setGroupMgr),
      deviceManager(setDeviceMgr)
{}
void ProvisionDiscoveryState::GoInState()
{
    WIFI_LOGI("             GoInState");
    Init();
    if (WifiErrorNo::WIFI_HAL_OPT_OK !=
        WifiP2PHalInterface::GetInstance().ProvisionDiscovery(p2pStateMachine.savedP2pConfig)) {
        WIFI_LOGE("Failed to invoke the provision discovery flow.");
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    }
}

void ProvisionDiscoveryState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
}

void ProvisionDiscoveryState::Init()
{
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DEVICE_DISCOVERS,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDiscoverPeer(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DISCOVER_SERVICES,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDiscServices(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_START_LISTEN,
        [this](InternalMessagePtr msg) { return this->ProcessCmdStartListen(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_PBC_RESP,
        [this](InternalMessagePtr msg) { return this->ProcessProvDiscPbcRspEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_ENTER_PIN,
        [this](InternalMessagePtr msg) { return this->ProcessProvDiscEnterPinEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_SHOW_PIN,
        [this](InternalMessagePtr msg) { return this->ProcessProvDiscShowPinEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_PROV_DISC_FAILURE,
        [this](InternalMessagePtr msg) { return this->ProcessProvDiscFailEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_CANCEL_CONNECT,
        [this](InternalMessagePtr msg) { return this->ProcessCmdCancelConnect(msg); }));
}

bool ProvisionDiscoveryState::ProcessCmdDiscoverPeer(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.BroadcastActionResult(P2pActionCallback::DiscoverDevices, ErrCode::WIFI_OPT_FAILED);
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessCmdDiscServices(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.BroadcastActionResult(P2pActionCallback::DiscoverServices, ErrCode::WIFI_OPT_FAILED);
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessCmdStartListen(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.BroadcastActionResult(P2pActionCallback::StartP2pListen, ErrCode::WIFI_OPT_FAILED);
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessProvDiscPbcRspEvt(InternalMessagePtr msg) const
{
    WifiP2pTempDiscEvent provDisc;
    if (!msg->GetMessageObj(provDisc)) {
        WIFI_LOGD("Invalid argument provDisc");
        return EXECUTED;
    }

    const WifiP2pDevice &device = provDisc.GetDevice();
    if (device.IsValid() && p2pStateMachine.savedP2pConfig.GetDeviceAddress() != device.GetDeviceAddress()) {
        WIFI_LOGD("error:Device mismatch");
        return EXECUTED;
    }

    if (p2pStateMachine.savedP2pConfig.GetWpsInfo().GetWpsMethod() == WpsMethod::WPS_METHOD_PBC) {
        p2pStateMachine.P2pConnectByShowingPin(p2pStateMachine.savedP2pConfig);
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupNegotiationState);
    }
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessProvDiscEnterPinEvt(InternalMessagePtr msg) const
{
    WifiP2pTempDiscEvent provDisc;

    if (!msg->GetMessageObj(provDisc)) {
        WIFI_LOGD("Invalid argument provDisc");
        return EXECUTED;
    }
    const WifiP2pDevice &device = provDisc.GetDevice();

    if (device.IsValid() && p2pStateMachine.savedP2pConfig.GetDeviceAddress() != device.GetDeviceAddress()) {
        WIFI_LOGD("error:Device mismatch");
        return EXECUTED;
    }

    if (p2pStateMachine.savedP2pConfig.GetWpsInfo().GetWpsMethod() == WpsMethod::WPS_METHOD_KEYPAD) {
        if (!p2pStateMachine.savedP2pConfig.GetWpsInfo().GetPin().empty()) {
            p2pStateMachine.P2pConnectByShowingPin(p2pStateMachine.savedP2pConfig);
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupNegotiationState);
        } else {
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pAuthorizingNegotiationRequestState);
        }
    }
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessProvDiscShowPinEvt(InternalMessagePtr msg) const
{
    WifiP2pTempDiscEvent provDisc;

    if (!msg->GetMessageObj(provDisc)) {
        WIFI_LOGD("Invalid argument provDisc");
        return EXECUTED;
    }
    const WifiP2pDevice &device = provDisc.GetDevice();

    if (!device.IsValid() || p2pStateMachine.savedP2pConfig.GetDeviceAddress() != device.GetDeviceAddress()) {
        WIFI_LOGD("error:Device mismatch");
        return EXECUTED;
    }

    if (p2pStateMachine.savedP2pConfig.GetWpsInfo().GetWpsMethod() == WpsMethod::WPS_METHOD_DISPLAY) {
        WpsInfo wps = p2pStateMachine.savedP2pConfig.GetWpsInfo();
        wps.SetPin(provDisc.GetPin());
        p2pStateMachine.savedP2pConfig.SetWpsInfo(wps);
        p2pStateMachine.P2pConnectByShowingPin(p2pStateMachine.savedP2pConfig);
        p2pStateMachine.NotifyUserInvitationSentMessage(provDisc.GetPin(), device.GetDeviceAddress());
        p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupNegotiationState);
    }
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessProvDiscFailEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv event: %{public}d", msg->GetMessageName());
    p2pStateMachine.DealGroupCreationFailed();
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool ProvisionDiscoveryState::ProcessCmdCancelConnect(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv event: %{public}d", msg->GetMessageName());
    WifiP2PHalInterface::GetInstance().CancelConnect();
    p2pStateMachine.DealGroupCreationFailed();
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    p2pStateMachine.BroadcastActionResult(P2pActionCallback::P2pCancelConnect, ErrCode::WIFI_OPT_SUCCESS);
    return EXECUTED;
}

bool ProvisionDiscoveryState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("fatal error!");
        return NOT_EXECUTED;
    }
    int msgName = msg->GetMessageName();
    auto iter = mProcessFunMap.find(static_cast<P2P_STATE_MACHINE_CMD>(msgName));
    if (iter == mProcessFunMap.end()) {
        return NOT_EXECUTED;
    }
    if ((iter->second)(msg)) {
        return EXECUTED;
    } else {
        return NOT_EXECUTED;
    }
}
}  // namespace Wifi
}  // namespace OHOS
