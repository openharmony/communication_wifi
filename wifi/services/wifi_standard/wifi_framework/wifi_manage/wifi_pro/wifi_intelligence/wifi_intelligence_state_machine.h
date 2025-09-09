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

#ifndef OHOS_WIFI_INTELLIGENCE_STATE_MACHINE_H
#define OHOS_WIFI_INTELLIGENCE_STATE_MACHINE_H

#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "state_machine.h"
#include "ap_info_helper.h"

namespace OHOS {
namespace Wifi {
class WifiIntelligenceStateMachine : public StateMachine {
public:
    explicit WifiIntelligenceStateMachine(int32_t instId = 0);
    ~WifiIntelligenceStateMachine();

    /**
     * @Description  Definition of DefaultState class in WifiIntelligenceStateMachine.
     *
     */
    class DefaultState : public State {
    public:
        explicit DefaultState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine_ { nullptr };
        void HandlWifiConnectStateChange(InternalMessagePtr msg);
        void HandleWifiDisabled(InternalMessagePtr msg);
        void HandleWifiConfigurationChange(InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of InitialState class in WifiIntelligenceStateMachine.
     *
     */
    class InitialState : public State {
    public:
        explicit InitialState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~InitialState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine_ { nullptr };
    };

    /**
     * @Description  Definition of EnabledState class in WifiIntelligenceStateMachine.
     *
     */
    class EnabledState : public State {
    public:
        explicit EnabledState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~EnabledState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
    };

    /**
     * @Description  Definition of DisabledState class in WifiIntelligenceStateMachine.
     *
     */
    class DisabledState : public State {
    public:
        explicit DisabledState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~DisabledState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine_ { nullptr };
        std::vector<ApInfoData> FilterFromBlackList(std::vector<ApInfoData> &datas);
        void HandleWifiOpen(InternalMessagePtr msg);
        void HandleWifiFindTarget(InternalMessagePtr msg);
        void HandleMsgStateChange(InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of StopState class in WifiIntelligenceStateMachine.
     *
     */
    class StopState : public State {
    public:
        explicit StopState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~StopState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine_ { nullptr };
    };

    /**
     * @Description  Definition of DisconnectedState class in WifiIntelligenceStateMachine.
     *
     */
    class DisconnectedState : public State {
    public:
        explicit DisconnectedState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~DisconnectedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine_ { nullptr };
    };

    /**
     * @Description  Definition of ConnectedState class in WifiIntelligenceStateMachine.
     *
     */
    class ConnectedState : public State {
    public:
        explicit ConnectedState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~ConnectedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
        WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine_ { nullptr };
        void HandleWifiInternetChangeRes(const InternalMessagePtr msg);
    };

    /**
     * @Description  Definition of InternetReadyState class in WifiIntelligenceStateMachine.
     *
     */
    class InternetReadyState : public State {
    public:
        explicit InternetReadyState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~InternetReadyState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
    };

    /**
     * @Description  Definition of NoInternetState class in WifiIntelligenceStateMachine.
     *
     */
    class NoInternetState : public State {
    public:
        explicit NoInternetState(WifiIntelligenceStateMachine *pWifiIntelligenceStateMachine);
        ~NoInternetState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    private:
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

    ErrCode InitWifiIntelligenceStates();

private:
    int32_t instId_ { 0 };

    DefaultState *pDefaultState_ { nullptr };
    InitialState *pInitialState_ { nullptr };
    EnabledState *pEnabledState_ { nullptr };
    DisabledState *pDisabledState_ { nullptr };
    StopState *pStopState_ { nullptr };
    DisconnectedState *pDisconnectedState_ { nullptr };
    ConnectedState *pConnectedState_ { nullptr };
    InternetReadyState *pInternetReadyState_ { nullptr };
    NoInternetState *pNoInternetState_ { nullptr };

    std::string mTargetSsid_ { "" };
    std::string mTargetAuthType_ { "" };
    std::vector<ApInfoData> mTargetApInfoDatas_;
    int64_t mLastCellChangeScanTime_ { 0 };
    int64_t mLastScanPingpongTime_ { 0 };
    int32_t mScanPingpongNum_ { 0 };
    int32_t mScanTimes_ { 0 };
    bool mIsScanInShort_ { false };
    int32_t mScanType_ { 1 };
    bool mIsAutoOpenSearch_ { false };
    bool mIsScanning_ { false };
    bool ProcessScanResult(std::vector<WifiScanInfo> scanInfoList, std::string cellId);
    bool IsHasTargetAp(std::vector<WifiScanInfo> &scanInfoLis);
    bool IsInBlacklist(std::string bssid);
    void UpdateScanResult(InternalMessagePtr msg);
    void SetScanIntervel(int32_t scanType);
    void InitPunishParameter();
    void SetPingPongPunishTime();
    bool IsInPingpongPunishTime();
    bool FullScan();
    bool HandleScanResult(std::vector<WifiScanInfo> scanInfoList);
    bool IsInTargetAp(std::string bssid, std::string ssid);
    void InlineUpdateCellInfo(ApInfoData data, std::string cellId);
    bool IsInMonitorNearbyAp(const std::vector<WifiScanInfo>& scanInfoList);
    void StopScanAp();
};
}
}
#endif
