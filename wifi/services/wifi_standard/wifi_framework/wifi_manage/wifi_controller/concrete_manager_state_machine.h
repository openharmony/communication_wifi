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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void HandleSwitchToConnectOrMixMode(InternalMessage *msg);
        void HandleSwitchToScanOnlyMode(InternalMessage *msg);
        void HandleStartInIdleState(InternalMessage *msg);
    };

    class DefaultState : public State {
    public:
        explicit DefaultState(ConcreteMangerMachine *concreteMangerMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
    };

    class ConnectState : public State {
    public:
        explicit ConnectState(ConcreteMangerMachine *concreteMangerMachine);
        ~ConnectState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void SwitchScanOnlyInConnectState();
        void SwitchMixInConnectState();
    };

    class ScanonlyState : public State {
    public:
        explicit ScanonlyState(ConcreteMangerMachine *concreteMangerMachine);
        ~ScanonlyState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void SwitchConnectInScanOnlyState();
        void SwitchMixInScanOnlyState();
    };

    class MixState : public State {
    public:
        explicit MixState(ConcreteMangerMachine *concreteMangerMachine);
        ~MixState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        ConcreteMangerMachine *pConcreteMangerMachine;
        void SwitchConnectInMixState();
        void SwitchScanOnlyInMixState();
    };

public:
    ErrCode InitConcreteMangerMachine();
    void RegisterCallback(ConcreteModeCallback &callback);
    void SetTargetRole(ConcreteManagerRole role);

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

    static ErrCode AutoStopScanOnly(int instId);
    static ErrCode AutoStartScanOnly(int instId);
    static ErrCode AutoStopStaService(int instId);
    static ErrCode AutoStartStaService(int instId);
#ifdef FEATURE_SELF_CURE_SUPPORT
    static ErrCode StartSelfCureService(int instId);
#endif
    bool HandleCommonMessage(InternalMessage *msg);
    void checkAndContinueToStopWifi(InternalMessage *msg);
    void HandleStaStop();
    void HandleStaStart();
    void ReportClose();
    static void IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType);

    DefaultState *pDefaultState;
    IdleState *pIdleState;
    ConnectState *pConnectState;
    ScanonlyState *pScanonlyState;
    MixState *pMixState;
    static int mTargetRole;
    ConcreteModeCallback mcb;
    static int mid;
    static std::string ifaceName;
};
} // namespace Wifi
} // namespace OHOS
#endif