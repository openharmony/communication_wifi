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

#ifndef WIFICONTROLLER_WIFICONTROLLERMACHINE_H
#define WIFICONTROLLER_WIFICONTROLLERMACHINE_H

#include <string>
#include <vector>
#include "state.h"
#include "state_machine.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include "concrete_clientmode_manager.h"
#ifdef FEATURE_AP_SUPPORT
#include "softap_manager.h"
#endif

namespace OHOS {
namespace Wifi {
class WifiControllerMachine : public StateMachine {
public:
    WifiControllerMachine();
    ~WifiControllerMachine();

    class DisableState : public State {
    public:
        explicit DisableState(WifiControllerMachine *wifiControllerMachine);
        ~DisableState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        WifiControllerMachine *pWifiControllerMachine;
    };

    class EnableState : public State {
    public:
        explicit EnableState(WifiControllerMachine *wifiControllerMachine);
        ~EnableState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;
        void HandleStaStartFailure(int id);
        void HandleStaRemoved(InternalMessage *msg);
        void HandleAPServiceStartFail(int id);
        void HandleConcreteClientRemoved(InternalMessage *msg);
        
    private:
        void HandleApStart(int id);
        void HandleWifiToggleChangeInEnabledState(InternalMessage *msg);
#ifdef FEATURE_AP_SUPPORT
        void HandleSoftapToggleChangeInEnabledState(InternalMessage *msg);
        void HandleApRemoved(InternalMessage *msg);
#endif
        WifiControllerMachine *pWifiControllerMachine;
    };

    class DefaultState : public State {
    public:
        explicit DefaultState(WifiControllerMachine *wifiControllerMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        WifiControllerMachine *pWifiControllerMachine;
    };

public:
    ErrCode InitWifiControllerMachine();

    void RemoveConcreteManager(int id);
    void HandleStaClose(int id);
    void HandleStaStart(int id);
    void HandleConcreteStop(int id);
    void ClearWifiStartFailCount();
    void ClearApStartFailCount();
#ifdef FEATURE_AP_SUPPORT
    void RmoveSoftapManager(int id);
    void HandleSoftapStop(int id);
    void StartSoftapCloseTimer();
    void StopSoftapCloseTimer();
#endif

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
    ErrCode InitWifiStates();
    bool HasAnyConcreteManager();
    bool HasAnyManager();
    bool ConcreteIdExist(int id);
    void MakeConcreteManager(ConcreteManagerRole role, int id);
#ifdef FEATURE_AP_SUPPORT
    bool HasAnySoftApManager();
    bool SoftApIdExist(int id);
    void MakeSoftapManager(SoftApManager::Role role, int id);
    bool ShouldEnableSoftap();
    void StopAllSoftapManagers();
    void StopSoftapManager(int id);
    SoftApManager *GetSoftApManager(int id);
#endif
    bool ShouldEnableWifi();
    ConcreteManagerRole GetWifiRole();
    void StopAllConcreteManagers();
    void StopConcreteManager(int id);
    void SwitchRole(ConcreteManagerRole role);
    void HandleAirplaneOpen();
    void HandleAirplaneClose();
    static bool IsWifiEnable();
    static bool IsScanOnlyEnable();

#ifndef HDI_CHIP_INTERFACE_SUPPORT
    int mApidStopWifi;
#endif
    EnableState *pEnableState;
    DisableState *pDisableState;
    DefaultState *pDefaultState;
    std::vector<ConcreteClientModeManager *> concreteManagers;
    mutable std::mutex concreteManagerMutex;
    static int mWifiStartFailCount;
    static int mSoftapStartFailCount;
#ifdef FEATURE_AP_SUPPORT
    std::vector<SoftApManager *> softapManagers;
    mutable std::mutex softapManagerMutex;
    uint64_t stopSoftapTimerId_ {0};
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif // WIFICONTROLLER_WIFICONTROLLERMACHINE_H
