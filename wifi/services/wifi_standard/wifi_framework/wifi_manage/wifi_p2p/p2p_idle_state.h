/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_P2P_IDLE_STATE_H
#define OHOS_P2P_IDLE_STATE_H

#include "state.h"
#include "p2p_define.h"
#include "wifi_p2p_group_manager.h"
#include "wifi_p2p_device_manager.h"

namespace OHOS {
namespace Wifi {
#define RETRY_TIMEOUT 10
#define RETRY_MAX_NUM 9
#define RETRY_INTERVAL 500
#define P2P_REMOVE_DEVICE_TIMEOUT 300000
class P2pStateMachine;
class P2pIdleState : public State {
    FRIEND_GTEST(P2pIdleState);

public:
    /**
     * @Description Construct a new P2pIdleState object
     * @param None
     * @return None
     */
    P2pIdleState(P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr, WifiP2pDeviceManager &deviceMgr);

    /**
     * @Description Destroy the P2pIdleState object
     * @param None
     * @return None
     */
    ~P2pIdleState() = default;

    /**
     * @Description - Called when entering state
     * @param None
     * @return None
     */
    virtual void GoInState() override;

    /**
     * @Description - Called when exiting state
     * @param None
     * @return None
     */
    virtual void GoOutState() override;

    /**
     * @Description - Message Processing Function
     * @param msg - Message object pointer
     * @return - bool true:success   false:fail
     */
    virtual bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    /**
     * @Description Initialization
     * @param None
     * @return None
     */
    virtual void Init();

    /**
     * @Description Process the stop discover peer command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdStopDiscPeer(InternalMessagePtr msg) const;

    /**
     * @Description Process the connect command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdConnect(InternalMessagePtr msg) const;

    /**
     * @Description Process the provision discover pbc request message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessProvDiscPbcReqEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the provision discover enter pin message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessProvDiscEnterPinEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the negotiation request message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessNegotReqEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the provision discover show pin message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessProvDiscShowPinEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the create group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdCreateGroup(InternalMessagePtr msg) const;

    /**
     * @Description Process the remove group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdRemoveGroup(InternalMessagePtr msg) const;

    /**
     * @Description Process the delete group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdDeleteGroup(InternalMessagePtr msg) const;

    /**
     * @Description Process the group started message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupStartedEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the invitation received message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessInvitationReceivedEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the hid2d create group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdHid2dCreateGroup(InternalMessagePtr msg) const;

    /**
     * @Description Process the hid2d connect command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdHid2dConnect(InternalMessagePtr msg) const;

    /**
     * @Description Process p2p interface created event received by the state machine
     * @param msg - Message body sent by the state machine
     * @param @return - bool true:handle   false:not handle
     */
    virtual bool ProcessP2pIfaceCreatedEvt(InternalMessagePtr msg) const;

    virtual bool ProcessRemoveDevice(InternalMessagePtr msg) const;

    virtual bool RetryConnect(InternalMessagePtr msg) const;

    virtual bool ProcessCmdDisableRandomMac(InternalMessagePtr msg) const;
private:
    using ProcessFun = std::function<bool(InternalMessagePtr)> const;
    std::map<P2P_STATE_MACHINE_CMD, ProcessFun> mProcessFunMap;
    P2pStateMachine &p2pStateMachine;
    WifiP2pGroupManager &groupManager;
    WifiP2pDeviceManager &deviceManager;
    static int retryConnectCnt;
    static bool hasConnect;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_P2P_IDLE_STATE_H */
