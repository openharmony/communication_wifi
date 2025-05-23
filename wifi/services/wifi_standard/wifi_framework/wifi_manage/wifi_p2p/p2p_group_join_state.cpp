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
#include "p2p_group_join_state.h"
#include "wifi_p2p_hal_interface.h"
#include "p2p_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_P2P_LABEL("P2pGroupJoinState");

namespace OHOS {
namespace Wifi {
P2pGroupJoinState::P2pGroupJoinState(
    P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr, WifiP2pDeviceManager &deviceMgr)
    : State("P2pGroupJoinState"), p2pStateMachine(stateMachine), groupManager(groupMgr), deviceManager(deviceMgr)
{}
void P2pGroupJoinState::GoInState()
{
    WIFI_LOGI("GoInState");
    p2pStateMachine.NotifyUserInvitationReceivedMessage();
    p2pStateMachine.StartTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_TIME_OUT),
        WSC_DIALOG_SELECT_TIMEOUT);
}

void P2pGroupJoinState::GoOutState()
{
    WIFI_LOGI("GoOutState");
    p2pStateMachine.StopTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_TIME_OUT));
}

bool P2pGroupJoinState::ExecuteStateMsg(InternalMessagePtr msg)
{
    switch (static_cast<P2P_STATE_MACHINE_CMD>(msg->GetMessageName())) {
        case P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_ACCEPT: {
            WIFI_LOGI("user accept.");
            const WpsInfo &wps = p2pStateMachine.savedP2pConfig.GetWpsInfo();
            if (wps.GetWpsMethod() == WpsMethod::WPS_METHOD_KEYPAD) {
                std::string inputPin;
                if (!msg->GetMessageObj(inputPin)) {
                    WIFI_LOGW("Failed to obtain the pin code.");
                    break;
                }
                WpsInfo wpsPin = wps;
                wpsPin.SetPin(inputPin);
                WIFI_LOGI("INPUT PIN: [%{private}s] ", wpsPin.GetPin().c_str());
                p2pStateMachine.savedP2pConfig.SetWpsInfo(wpsPin);
            }
            if (WifiErrorNo::WIFI_HAL_OPT_OK != WifiP2PHalInterface::GetInstance().P2pStopFind()) {
                WIFI_LOGE("Failed to stop find.");
            }
            StartPbc(wps);
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
            break;
        }
        case P2P_STATE_MACHINE_CMD::PEER_CONNECTION_USER_REJECT: {
            WIFI_LOGI("User(GO) rejected to join the group.");
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
            break;
        }
        case P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE: {
            p2pStateMachine.DelayMessage(msg);
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
            break;
        }
        case P2P_STATE_MACHINE_CMD::INTERNAL_CONN_USER_TIME_OUT: {
            p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupFormedState);
            break;
        }
        default:
            return NOT_EXECUTED;
    }
    return EXECUTED;
}

void P2pGroupJoinState::StartPbc(const WpsInfo &wps)
{
    const WifiP2pGroupInfo group = groupManager.GetCurrentGroup();
    std::string pin = wps.GetPin();
    std::string result;
    std::string address;
    if (wps.GetWpsMethod() == WpsMethod::WPS_METHOD_PBC) {
#ifdef HDI_WPA_INTERFACE_SUPPORT
        if (WifiErrorNo::WIFI_HAL_OPT_OK !=
            WifiP2PHalInterface::GetInstance().StartWpsPbc(group.GetInterface(),
                p2pStateMachine.savedP2pConfig.GetDeviceAddress())) {
#else
            if (WifiErrorNo::WIFI_HAL_OPT_OK !=
                WifiP2PHalInterface::GetInstance().StartWpsPbc(group.GetInterface(), pin)) {
#endif
                    WIFI_LOGE("WpsPbc operation failed.");
                }
    } else {
        if (WifiErrorNo::WIFI_HAL_OPT_OK !=
            WifiP2PHalInterface::GetInstance().StartWpsPin(group.GetInterface(), address, pin, result)) {
            WIFI_LOGE("WpsPin operation failed.");
        }
    }
}
} // namespace Wifi
} // namespace OHOS
