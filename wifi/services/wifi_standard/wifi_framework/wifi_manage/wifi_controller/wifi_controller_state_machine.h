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
#include "wifi_controller_managers_template.h"
#include "concrete_clientmode_manager.h"
#include "multi_sta_manager.h"
#ifdef FEATURE_AP_SUPPORT
#include "softap_manager.h"
#include "wifi_ap_msg.h"
#ifdef FEATURE_RPT_SUPPORT
#include "rpt_manager.h"
#endif
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
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        WifiControllerMachine *pWifiControllerMachine;
    };

    class EnableState : public State {
    public:
        explicit EnableState(WifiControllerMachine *wifiControllerMachine);
        ~EnableState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
        void HandleStaStartFailure(int id);
        void HandleStaRemoved(InternalMessagePtr msg);
        void HandleWifi2Removed(InternalMessagePtr msg);
        void HandleAPServiceStartFail(int id);
        void HandleConcreteClientRemoved(InternalMessagePtr msg);

    private:
        void HandleApStart(int id);
        bool HandleWifiToggleChangeForWlan1(int id, int isOpen);
        void HandleWifiToggleChangeInEnabledState(InternalMessagePtr msg);
#ifdef FEATURE_AP_SUPPORT
        void HandleSoftapToggleChangeInEnabledState(InternalMessagePtr msg);
        void HandleSoftapOpen(int id);
        void HandleSoftapClose(int id);
        void HandleApRemoved(InternalMessagePtr msg);
        void HandleApStop(InternalMessagePtr msg);
        bool HandleApMsg(InternalMessagePtr msg);
#ifdef FEATURE_RPT_SUPPORT
        void HandleRptStartFail(InternalMessagePtr msg);
        void HandleP2pStop(InternalMessagePtr msg);
#endif
#endif
        WifiControllerMachine *pWifiControllerMachine;
    };

    class DefaultState : public State {
    public:
        explicit DefaultState(WifiControllerMachine *wifiControllerMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        WifiControllerMachine *pWifiControllerMachine;
    };
public:
    ErrCode InitWifiControllerMachine();

    void HandleStaClose(int id);
    void HandleWifi2Close(int id);
    void HandleStaStartSuccess(int id);
    void HandleWifi2Start(int id);
    void HandleStaSemiActive(int id);
    void HandleConcreteStop(int id);
    void ClearWifiStartFailCount();
#ifdef FEATURE_AP_SUPPORT
    template <class T> void HandleHotspotStop(int id, HotspotMode THotspotMode, ManagerControl<T> &TManagers);
    void HandleSoftapStop(int id);
#ifdef FEATURE_RPT_SUPPORT
    bool ShouldUseRpt(int id);
    void HandleRptStop(int id);
    std::shared_ptr<RptManager> GetRptManager(int id);
#endif
#endif
    void ShutdownWifi(bool shutDownAp = true);
    void SelfcureResetWifi(int id);
    void IsLocalOnlyHotspot(bool isLohs);
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
    bool HasAnyManager();
    void MakeConcreteManager(ConcreteManagerRole role, int id);
    void MakeMultiStaManager(MultiStaManager::Role role, int instId);
#ifdef FEATURE_AP_SUPPORT
    void MakeHotspotManager(int id, bool startTimer = false);
    void MakeSoftapManager(SoftApManager::Role role, int id);
    HotspotMode CalculateHotspotMode(int id);
    bool ShouldEnableSoftap();
#ifdef FEATURE_RPT_SUPPORT
    void MakeRptManager(RptManager::Role role, int id);
#endif
#endif
    bool IsDisableWifiProhibitedByEdm(void);
    bool ShouldDisableWifi(InternalMessagePtr msg);
    bool ShouldEnableWifi(int id = 0);
    ConcreteManagerRole GetWifiRole();
    void SwitchRole(ConcreteManagerRole role);
    void HandleAirplaneOpen();
    void HandleAirplaneClose();
    static bool IsWifiEnable(int id = 0);
    static bool IsSemiWifiEnable();
    static bool IsScanOnlyEnable();

#ifndef HDI_CHIP_INTERFACE_SUPPORT
    std::atomic<int> mApidStopWifi;
#endif
    EnableState *pEnableState;
    DisableState *pDisableState;
    DefaultState *pDefaultState;
    ManagerControl<ConcreteClientModeManager> concreteManagers{CONCRETE_CMD_STOP};
    static int mWifiStartFailCount;
#ifdef FEATURE_AP_SUPPORT
#ifdef FEATURE_RPT_SUPPORT
    ManagerControl<RptManager> rptManagers{RPT_CMD_STOP};
#endif
    ManagerControl<SoftApManager> softApManagers{SOFTAP_CMD_STOP};
    HotspotMode hotspotMode {HotspotMode::NONE};
#endif
    ManagerControl<MultiStaManager> multiStaManagers{MULTI_STA_CMD_STOP};
    bool isLocalOnlyHotspot_ = false;
};
}  // namespace Wifi
}  // namespace OHOS
#endif // WIFICONTROLLER_WIFICONTROLLERMACHINE_H
