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

#ifndef OHOS_WIFI_PRO_STATE_MACHINE_H
#define OHOS_WIFI_PRO_STATE_MACHINE_H

#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "state_machine.h"
#include "wifi_pro_common.h"
#include "network_selection_manager.h"

namespace OHOS {
namespace Wifi {
class WifiProStateMachine : public StateMachine {
    FRIEND_GTEST(WifiProStateMachine);

public:
    explicit WifiProStateMachine(int32_t instId = 0);
    ~WifiProStateMachine();

    /**
     * @Description  Definition of DefaultState class in WifiProStateMachine.
     *
     */
    class DefaultState : public State {
    public:
        explicit DefaultState(WifiProStateMachine *pWifiProStateMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr };
        void HandleWifiProSwitchChanged(const InternalMessagePtr msg);
        void HandleRemoveBlockList(const InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of WifiProEnableState class in WifiProStateMachine.
     *
     */
    class WifiProEnableState : public State {
    public:
        explicit WifiProEnableState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiProEnableState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr };
        void TransitionNetState();
        void HandleWifiConnectStateChangedInEnable(const InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of WifiProDisabledState class in WifiProStateMachine.
     *
     */
    class WifiProDisabledState : public State {
    public:
        explicit WifiProDisabledState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiProDisabledState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr};
        void HandleWifiProSwitchChanged(const InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of WifiConnectedState class in WifiProStateMachine.
     *
     */
    class WifiConnectedState : public State {
    public:
        explicit WifiConnectedState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiConnectedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr };
        void InitConnectedState();
        void HandleHttpResultInConnected(const InternalMessagePtr msg);
        void HandleWifiConnectStateChangedInConnected(const InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of WifiDisconnectedState class in WifiProStateMachine.
     *
     */
    class WifiDisconnectedState : public State {
    public:
        explicit WifiDisconnectedState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiDisconnectedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr };
        void HandleWifiConnectStateChangedInDisconnected(const InternalMessagePtr msg);
        void HandleWifi2WifiFailedInDisconnected();
    };

    /**
     * @Description  Definition of WifiHasNetState class in WifiProStateMachine.
     *
     */
    class WifiHasNetState : public State {
    public:
        explicit WifiHasNetState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiHasNetState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr};
        int32_t rssiLevel2Or3ScanedCounter_ { 0 };
        int32_t rssiLevel0Or1ScanedCounter_ { 0 };
        void HandleCheckResultInHasNet(const NetworkSelectionResult &networkSelectionResult);
        void TryWifiHandoverPreferentially(const NetworkSelectionResult &networkSelectionResult);
        void TryWifiRoveOut(const NetworkSelectionResult &networkSelectionResult);
        void HandleWifiRoveOut(const NetworkSelectionResult &networkSelectionResult);
        void TryWifi2Wifi(const NetworkSelectionResult &networkSelectionResult);
        void HandleConnectStateChangedInHasNet(const InternalMessagePtr msg);
        void HandleRssiChangedInHasNet(const InternalMessagePtr msg);
        void HandleReuqestScanInHasNet(const InternalMessagePtr msg);
        void HandleScanResultInHasNet(const InternalMessagePtr msg);
        void TryStartScan(bool hasSwitchRecord, int32_t signalLevel);
        void HandleHttpResultInHasNet(const InternalMessagePtr msg);
        bool HandleWifiToWifi(int32_t switchReason, const NetworkSelectionResult &networkSelectionResult);
        bool TrySwitchWifiNetwork(const NetworkSelectionResult &networkSelectionResult);
        void WifiHasNetStateInit();
    };

    class WifiNoNetState : public State {
    public:
        explicit WifiNoNetState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiNoNetState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr };
        bool fullScan_ { false };
        void HandleWifiNoInternet(const InternalMessagePtr msg);
        bool HandleCheckResultInNoNet(const NetworkSelectionResult &networkSelectionResult);
        bool TryNoNetSwitch(const NetworkSelectionResult &networkSelectionResult);
        void HandleReuqestScanInNoNet(const InternalMessagePtr msg);
        void HandleHttpResultInNoNet(const InternalMessagePtr msg);
        void HandleNoNetChanged();
        void HandleConnectStateChangedInNoNet(const InternalMessagePtr msg);
    };

    class WifiPortalState : public State {
    public:
        explicit WifiPortalState(WifiProStateMachine *pWifiProStateMachine);
        ~WifiPortalState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiProStateMachine *pWifiProStateMachine_ { nullptr };
        void HandleHttpResultInPortal(const InternalMessagePtr msg);
        void HandleConnectStateChangedInPortalNet(const InternalMessagePtr msg);
    };

    ErrCode Initialize();

private:
    /**
     * @Description  Destruct state.
     *
     */
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

    /**
     * @Description  Build state tree
     *
     */
    void BuildStateTree();

    ErrCode InitWifiProStates();

private:
    int32_t instId_ { 0 };
    DefaultState *pDefaultState_ { nullptr };
    WifiProEnableState *pWifiProEnableState_ { nullptr };
    WifiProDisabledState *pWifiProDisabledState_ { nullptr };
    WifiConnectedState *pWifiConnectedState_ { nullptr };
    WifiDisconnectedState *pWifiDisConnectedState_ { nullptr };
    WifiHasNetState *pWifiHasNetState_ { nullptr };
    WifiNoNetState *pWifiNoNetState_ { nullptr };
    WifiPortalState *pWifiPortalState_ { nullptr };
    /* 0:unknow 1:singleAP 2:Mixed Type */
    int32_t duanBandHandoverType_ { 0 };
    int32_t wiFiNoInternetReason_ { 0 };
    bool disconnectToConnectedState_ { false };
    bool isWifiProEnabled_ { true }; // enabled by default, it should be assigned according to the settings.
    bool isWifiNoInternet_ { false };
    std::string badBssid_ { 0 };
    std::string badSsid_ { 0 };
    int32_t wifiSwitchReason_ { 0 };
    int32_t currentRssi_ { 0 };
    std::string currentBssid_;
    std::string currentSsid_;
    std::shared_ptr<WifiLinkedInfo> pCurrWifiInfo_ { nullptr };
    std::shared_ptr<WifiDeviceConfig> pCurrWifiDeviceConfig_ { nullptr };
    bool isWifi2WifiSwitching_ { false };
    bool isDisableWifiAutoSwitch_ { false };
    std::string targetBssid_ { "" };
    NetworkSelectionResult networkSelectionResult_;
    bool IsKeepCurrWifiConnected();
    bool IsReachWifiScanThreshold(int32_t signalLevel);
    bool HasWifiSwitchRecord();
    void RefreshConnectedNetWork();
    bool HasAvailableSsidToSwitch();
    void SetSwitchReason(WifiSwitchReason reason);
    bool IsSatisfiedWifiOperationCondition();
    bool IsDisableWifiAutoSwitch();
    void Wifi2WifiFinish();
    bool IsFullscreen();
    bool IsCallingInCs();
    void UpdateWifiSwitchTimeStamp();
    void HandleWifi2WifiSucsess(int64_t blackListTime);
    void HandleWifi2WifiFailed();
    void FastScan(std::vector<WifiScanInfo> &scanInfoList);
    void TrySelfCure(bool forceNoHttpCheck);
    bool FirstNoNetAndSelfCure();
};
} // namespace Wifi
} // namespace OHOS
#endif