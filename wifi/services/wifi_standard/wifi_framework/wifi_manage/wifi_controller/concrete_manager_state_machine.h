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

#ifndef CONCRETE_MANAGER_STATE_MACHINE_H
#define CONCRETE_MANAGER_STATE_MACHINE_H

#include <string>
#include "state_machine.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include "sta_service_callback.h"
#include "iscan_service_callbacks.h"
#include "wifi_internal_msg.h"
#include "wifi_controller_define.h"
#include "wifi_service_manager.h"
#include "state.h"

namespace OHOS {
namespace Wifi {
class ConcreteMangerMachine : public StateMachine {
public:
    ConcreteMangerMachine();
    ~ConcreteMangerMachine();

    class IdleState : public State {
    public:
        explicit IdleState(ConcreteMangerMachine *concreteMangerMachine);
        ~IdleState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void HandleSwitchToConnectMode(InternalMessagePtr msg);
        void HandleSwitchToScanOnlyMode(InternalMessagePtr msg);
        void HandleStartInIdleState(InternalMessagePtr msg);
        void HandleSwitchToSemiActiveMode(InternalMessagePtr msg);
    };

    class DefaultState : public State {
    public:
        explicit DefaultState(ConcreteMangerMachine *concreteMangerMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
    };

    class ConnectState : public State {
    public:
        explicit ConnectState(ConcreteMangerMachine *concreteMangerMachine);
        ~ConnectState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void SwitchScanOnlyInConnectState();
        void SwitchSemiActiveInConnectState();
    };

    class ScanonlyState : public State {
    public:
        explicit ScanonlyState(ConcreteMangerMachine *concreteMangerMachine);
        ~ScanonlyState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void SwitchConnectInScanOnlyState();
        void SwitchSemiActiveInScanOnlyState();
    };

    class SemiActiveState : public State {
    public:
        explicit SemiActiveState(ConcreteMangerMachine *concreteMangerMachine);
        ~SemiActiveState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void SwitchConnectInSemiActiveState();
        void SwitchScanOnlyInSemiActiveState();
    };

public:
    ErrCode InitConcreteMangerMachine();
    void RegisterCallback(ConcreteModeCallback &callback);

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
    ErrCode InitConcreteMangerStates();
    void SetTargetRole(ConcreteManagerRole role);
    bool HandleCommonMessage(InternalMessagePtr msg);
    void CheckAndContinueToStopWifi(InternalMessagePtr msg);
    void HandleStaStop();
    void HandleStaStart();
    void HandleStaSemiActive();
    ErrCode SwitchSemiFromEnable();
    ErrCode SwitchEnableFromSemi();
    void ReportClose();
    void ClearIfaceName();
    void HandleSelfcureResetSta(InternalMessagePtr msg);

    DefaultState *pDefaultState;
    IdleState *pIdleState;
    ConnectState *pConnectState;
    ScanonlyState *pScanonlyState;
    SemiActiveState *pSemiActiveState;
    static int mTargetRole;
    ConcreteModeCallback mcb;
    static int mid;
    static std::string ifaceName;
};
} // namespace Wifi
} // namespace OHOS
#endif
