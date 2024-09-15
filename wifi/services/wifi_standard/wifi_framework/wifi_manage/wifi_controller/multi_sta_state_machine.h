/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef MULTI_STA_STATE_MACHINE_H
#define MULTI_STA_STATE_MACHINE_H

#include "state.h"
#include "state_machine.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include <string>
#include "wifi_ap_msg.h"
#include "wifi_internal_msg.h"
#include "wifi_controller_define.h"

namespace OHOS {
namespace Wifi {
class MultiStaStateMachine : public StateMachine {
public:
    MultiStaStateMachine();
    ~MultiStaStateMachine();

    class IdleState : public State {
    public:
        explicit IdleState(MultiStaStateMachine *multiStaStateMachine);
        ~IdleState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        MultiStaStateMachine *pMultiStaStateMachine;
        void HandleStartInIdleState(InternalMessagePtr msg);
    };

    class DefaultState : public State {
    public:
        explicit DefaultState(MultiStaStateMachine *multiStaStateMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        MultiStaStateMachine *pMultiStaStateMachine;
    };

    class StartedState : public State {
    public:
        explicit StartedState(MultiStaStateMachine *multiStaStateMachine);
        ~StartedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        MultiStaStateMachine *pMultiStaStateMachine;
    };

public:
    ErrCode InitMultiStaStateMachine();
    ErrCode RegisterCallback(const MultiStaModeCallback &callbacks);

private:
    template <typename T>
    inline void ParsePointer(T *&pointer)
    {
        if (pointer != nullptr) {
            delete pointer;
            pointer = nullptr;
        }
    }

    template <typename T>
    inline ErrCode JudgmentEmpty(T *&pointer)
    {
        if (pointer == nullptr) {
            return WIFI_OPT_FAILED;
        }
        return WIFI_OPT_SUCCESS;
    }

    void BuildStateTree();
    ErrCode InitMultiStaStates();
    DefaultState *pDefaultState;
    IdleState *pIdleState;
    StartedState *pStartedState;
    MultiStaModeCallback mcb;
    static int mid;
    std::string ifaceName{""};
};
} // namespace Wifi
} // namespace OHOS
#endif