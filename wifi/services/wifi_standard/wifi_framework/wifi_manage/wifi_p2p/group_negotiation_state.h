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
#ifndef OHOS_P2P_GROUP_NEGOTIATION_STATE_H
#define OHOS_P2P_GROUP_NEGOTIATION_STATE_H

#include "state.h"
#include "p2p_define.h"
#include "p2p_macro.h"
#include "wifi_p2p_device_manager.h"
#include "wifi_p2p_group_manager.h"

namespace OHOS {
namespace Wifi {
class P2pStateMachine;
class GroupNegotiationState : public State {
    FRIEND_GTEST(GroupNegotiationState);

public:
    /**
     * @Description Construct a new Group Negotiation State object
     * @param None
     * @return None
     */
    GroupNegotiationState(P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr,
        WifiP2pDeviceManager &deviceMgr);

    /**
     * @Description Destroy the Group Negotiation State object
     * @param None
     * @return None
     */
    ~GroupNegotiationState() = default;

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
     * @Description Process the negotiation success message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessNegotSucessEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the group formation success message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupFormationSuccessEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the group started message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupStartedEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the group formation fail message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupFormationFailEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the negotiation fail message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessNegotFailEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the invitation result message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessInvitationResultEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process the group removed message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupRemovedEvt(InternalMessagePtr msg) const;

    /**
     * @Description Process remvoe group message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdRemoveGroup(InternalMessagePtr msg) const;

    /**
     * @Description Initialization
     * @param None
     * @return None
     */
    virtual void Init();

    void DoDhcpInGroupStart(void) const;
private:
    using ProcessFun = bool (GroupNegotiationState::*)(InternalMessagePtr msg) const;
    std::map<P2P_STATE_MACHINE_CMD, ProcessFun> mProcessFunMap;
    P2pStateMachine &p2pStateMachine;
    WifiP2pGroupManager &groupManager;
    WifiP2pDeviceManager &deviceManager;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_P2P_GROUP_NEGOTIATION_STATE_H */
