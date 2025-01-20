/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef RPT_MANAGER_STATE_MACHINE_H
#define RPT_MANAGER_STATE_MACHINE_H
#ifdef FEATURE_RPT_SUPPORT
#include "state.h"
#include "state_machine.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include <string>
#include "wifi_ap_msg.h"
#include "wifi_internal_msg.h"
#include "wifi_controller_define.h"
#include "ip2p_service_callbacks.h"

namespace OHOS::Wifi {

enum {
    P2P_BRIDGE_OFF,
    P2P_BRIDGE_ON
};

class RptManagerMachine : public StateMachine {
public:
    RptManagerMachine();
    ~RptManagerMachine();

    class DefaultState : public State {
    public:
        explicit DefaultState(RptManagerMachine *rptManagerMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        RptManagerMachine *pRptManagerMachine;
    };

    class IdleState : public State {
    public:
        explicit IdleState(RptManagerMachine *rptManagerMachine);
        ~IdleState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        RptManagerMachine *pRptManagerMachine;
    };

    class StartingState : public State {
    public:
        explicit StartingState(RptManagerMachine *rptManagerMachine);
        ~StartingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
        int retryCount = 0;
    private:
        void StartRpt();
        RptManagerMachine *pRptManagerMachine;
    };

    class P2pConflictState : public State {
    public:
        explicit P2pConflictState(RptManagerMachine *rptManagerMachine);
        ~P2pConflictState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
        int retryCount = 0;
    private:
        void RemoveP2pConflictGroup();
        RptManagerMachine *pRptManagerMachine;
    };

    class StartedState : public State {
    public:
        explicit StartedState(RptManagerMachine *rptManagerMachine);
        ~StartedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        RptManagerMachine *pRptManagerMachine;
    };

    class StoppingState : public State {
    public:
        explicit StoppingState(RptManagerMachine *rptManagerMachine);
        ~StoppingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        void StopRpt();
        RptManagerMachine *pRptManagerMachine;
    };

    class StoppedState : public State {
    public:
        explicit StoppedState(RptManagerMachine *rptManagerMachine);
        ~StoppedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        RptManagerMachine *pRptManagerMachine;
    };
public:
    ErrCode InitRptManagerMachine();
    ErrCode RegisterCallback(const RptModeCallback &callbacks);

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
    ErrCode InitRptManagerStates();
    WifiP2pConfig CreateRptConfig();

    void SetMacFilter(std::string mac);
    void InitBlockList();
    void AddBlockList(std::string mac);
    void DelBlockList(std::string mac);

    void BroadcastStationJoin(std::string mac);
    void BroadcastStationLeave(std::string mac);
    void BroadcastApState(int apState);

    DefaultState *pDefaultState;
    IdleState *pIdleState;
    StartingState *pStartingState;
    P2pConflictState *pP2pConflictState;
    StartedState *pStartedState;
    StoppingState *pStoppingState;
    StoppedState *pStoppedState;

    RptModeCallback mcb;
    static int mid;
};
} // namespace OHOS::Wifi
#endif
#endif