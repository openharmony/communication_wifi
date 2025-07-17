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

#ifndef OHOS_P2P_GROUP_OPERATING_STATE_H
#define OHOS_P2P_GROUP_OPERATING_STATE_H

#include "state.h"
#include "p2p_define.h"
#include "wifi_error_no.h"
#include "wifi_p2p_group_manager.h"
#include "wifi_p2p_device_manager.h"
#include "ienhance_service.h"

namespace OHOS {
namespace Wifi {
class P2pStateMachine;
class P2pGroupOperatingState : public State {
    FRIEND_GTEST(P2pGroupOperatingState);

public:
    /* *
     * @Description Construct a new P2pGroupOperatingState object
     * @param None
     * @return None
     */
    P2pGroupOperatingState(P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr,
        WifiP2pDeviceManager &deviceMgr);

    /**
     * @Description Destroy the P2pGroupOperatingState object
     * @param None
     * @return None
     */
    ~P2pGroupOperatingState() = default;

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

    /**
     * @Description Set EnhanceService to p2p service
     *
     * @param enhanceService IEnhanceService object
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual void SetEnhanceService(IEnhanceService* enhanceService);

private:
    /**
     * @Description Initialization
     * @param None
     * @return None
     */
    virtual void Init();

    /**
     * @Description Process the create group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdCreateGroup(const InternalMessagePtr msg) const;

    /**
     * @Description Process the create group of rpt command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdCreateRptGroup(const InternalMessagePtr msg) const;

    /**
     * @Description Process the group started message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupStartedEvt(const InternalMessagePtr msg) const;

    /**
     * @Description Process the create group timeout message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCreateGroupTimeOut(const InternalMessagePtr msg) const;

    /**
     * @Description Process the group removed message received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessGroupRemovedEvt(const InternalMessagePtr msg) const;

    /**
     * @Description Process the disable command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdDisable(const InternalMessagePtr msg) const;

    /**
     * @Description Process the remove group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdRemoveGroup(const InternalMessagePtr msg) const;

    /**
     * @Description Process the delete group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdDeleteGroup(const InternalMessagePtr msg) const;

    /**
     * @Description Process the hid2d create group command received by the state machine
     * @param msg - Message body sent by the state machine
     * @return - bool true:handle   false:not handle
     */
    virtual bool ProcessCmdHid2dCreateGroup(const InternalMessagePtr msg) const;

    WifiErrorNo CreateGroupByConfig(int netId, const WifiP2pConfigInternal &config, int freq) const;

    int GetGroupFreq(WifiP2pConfigInternal &config) const;
private:
    using ProcessFun = std::function<bool(const InternalMessagePtr)> const;
    std::map<P2P_STATE_MACHINE_CMD, ProcessFun> mProcessFunMap;
    P2pStateMachine &p2pStateMachine;
    WifiP2pGroupManager &groupManager;
    WifiP2pDeviceManager &deviceManager;
    IEnhanceService *enhanceService_ = nullptr;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_P2P_GROUP_OPERATING_STATE_H */
