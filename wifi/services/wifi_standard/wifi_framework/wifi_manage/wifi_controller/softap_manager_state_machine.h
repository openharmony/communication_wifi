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

#ifndef SOFTAP_MANAGER_STATE_MACHINE_H
#define SOFTAP_MANAGER_STATE_MACHINE_H

#include "state.h"
#include "state_machine.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include <string>
#include "wifi_ap_msg.h"
#include "i_ap_service_callbacks.h"
#include "wifi_internal_msg.h"
#include "wifi_controller_define.h"

namespace OHOS {
namespace Wifi {
class SoftapManagerMachine : public StateMachine {
public:
    SoftapManagerMachine();
    ~SoftapManagerMachine();

    class IdleState : public State {
    public:
        explicit IdleState(SoftapManagerMachine *softapManagerMachine);
        ~IdleState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        SoftapManagerMachine *pSoftapManagerMachine;
        void HandleStartInIdleState(InternalMessage *msg);
    };

    class DefaultState : public State {
    public:
        explicit DefaultState(SoftapManagerMachine *softapManagerMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        SoftapManagerMachine *pSoftapManagerMachine;
    };

    class StartedState : public State {
    public:
        explicit StartedState(SoftapManagerMachine *softapManagerMachine);
        ~StartedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        SoftapManagerMachine *pSoftapManagerMachine;
    };

public:
    ErrCode InitSoftapManagerMachine();
    ErrCode RegisterCallback(const SoftApModeCallback &callbacks);

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
    ErrCode InitSoftapManagerStates();
    ErrCode TryToStartApService(int id);
    ErrCode AutoStartApService(int id);
    ErrCode AutoStopApService(int id);
    void StopSoftap();
    void IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType);
    DefaultState *pDefaultState;
    IdleState *pIdleState;
    StartedState *pStartedState;
    SoftApModeCallback mcb;
    static int mid;
    std::string ifaceName{""};
};
} // namespace Wifi
} // namespace OHOS
#endif