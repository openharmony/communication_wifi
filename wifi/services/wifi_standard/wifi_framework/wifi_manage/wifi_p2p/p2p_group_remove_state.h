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
#ifndef OHOS_P2P_GROUP_REMOVE_STATE_H
#define OHOS_P2P_GROUP_REMOVE_STATE_H

#include "state.h"
#include "p2p_define.h"
#include "p2p_macro.h"

namespace OHOS {
namespace Wifi {
class P2pStateMachine;
class P2pGroupRemoveState : public State {
    FRIEND_GTEST(P2pGroupRemoveState);

public:
    /**
     * @Description Construct a new P2pGroupRemoveState object
     * @param None
     * @return None
     */
    explicit P2pGroupRemoveState(P2pStateMachine &stateMachine);

    /**
     * @Description Destroy the P2pGroupRemoveState object
     * @param None
     * @return None
     */
    ~P2pGroupRemoveState() = default;

    /**
     * @Description - Called when entering state
     * @param None
     * @return None
     */
    void GoInState() override;

    /**
     * @Description - Called when exiting state
     * @param None
     * @return None
     */
    void GoOutState() override;

    /**
     * @Description - Message Processing Function
     * @param msg - Message object pointer
     * @return - bool true:success   false:fail
     */
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    P2pStateMachine &p2pStateMachine;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_P2P_INVITING_SATATE_H */
