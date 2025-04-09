/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_SELF_CURE_STATE_MACHINE_H
#define OHOS_SELF_CURE_STATE_MACHINE_H

#include <condition_variable>
#include <mutex>
#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "state_machine.h"
#include "self_cure_common.h"
#include "self_cure_service_callback.h"
#include "sta_service_callback.h"
#include "ista_service.h"
#include "ip2p_service_callbacks.h"
#include "wifi_scan_msg.h"
#include "iself_cure_service.h"
#include "wifi_service_manager.h"
#include "wifi_msg.h"
#include <fcntl.h>
#include "arp_checker.h"
#include "self_cure_msg.h"
#include "wifi_common_util.h"
#include "wifi_net_observer.h"

namespace OHOS {
namespace Wifi {
constexpr int CURRENT_RSSI_INIT = -200;
constexpr int MAX_SELF_CURE_CNT_INVALID_IP = 3;
constexpr int VEC_POS_0 = 0;
constexpr int VEC_POS_1 = 1;
constexpr int VEC_POS_2 = 2;
constexpr int TRY_TIMES = 3;
constexpr int STATIC_IP_ADDR = 156;
constexpr int IP_ADDR_LIMIT = 255;
constexpr int IP_ADDR_SIZE = 4;
constexpr int NET_MASK_LENGTH = 24;
constexpr int SELF_CURE_FAILED_ONE_CNT = 1;
constexpr int SELF_CURE_FAILED_TWO_CNT = 2;
constexpr int SELF_CURE_FAILED_THREE_CNT = 3;
constexpr int SELF_CURE_FAILED_FOUR_CNT = 4;
constexpr int SELF_CURE_FAILED_FIVE_CNT = 5;
constexpr int SELF_CURE_FAILED_SIX_CNT = 6;
constexpr int SELF_CURE_FAILED_SEVEN_CNT = 7;
constexpr int DNS_FAILED_CNT = 2;

class SelfCureStateMachine : public StateMachine {
    FRIEND_GTEST(SelfCureStateMachine);

public:
    explicit SelfCureStateMachine(int instId = 0);
    ~SelfCureStateMachine();
    using selfCureSmHandleFunc = void (SelfCureStateMachine::*)(InternalMessagePtr msg);
    using SelfCureSmHandleFuncMap = std::map<int, selfCureSmHandleFunc>;

    /* *
     * @Description  Definition of DefaultState class in SelfCureStateMachine.
     *
     */
    class DefaultState : public State {
    public:
        explicit DefaultState(SelfCureStateMachine *selfCureStateMachine);
        ~DefaultState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
        void HandleDhcpOfferPacketRcv(const IpInfo &info);
        void HandleP2pEnhanceStateChange(int state);
    private:
        SelfCureStateMachine *pSelfCureStateMachine_;
    };

    /* *
     * @Description  Definition of ConnectedMonitorState class in SelfCureStateMachine.
     *
     */
    class ConnectedMonitorState : public State {
    public:
        explicit ConnectedMonitorState(SelfCureStateMachine *selfCureStateMachine);
        ~ConnectedMonitorState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
        using selfCureCmsHandleFunc = std::function<void(InternalMessagePtr msg)>;
        using SelfCureCmsHandleFuncMap = std::map<int, selfCureCmsHandleFunc>;

    private:
        SelfCureStateMachine *pSelfCureStateMachine_;
        int lastSignalLevel_ = -1;
        std::string lastConnectedBssid_;
        bool isMobileHotspot_ = false;
        bool isIpv4DnsEnabled_ = false;
        bool isGatewayInvalid_ = false;
        std::string configAuthType_ = "-1";
        bool isHasInternetRecently_ = false;
        bool isPortalUnthenEver_ = false;
        bool isUserSetStaticIpConfig_ = false;
        bool isWifiSwitchAllowed_ = false;
        int lastDnsFailedCnt_ = 0;
        SelfCureCmsHandleFuncMap selfCureCmsHandleFuncMap_;
        int InitSelfCureCmsHandleMap();
        void HandleResetupSelfCure(InternalMessagePtr msg);
        void HandlePeriodicArpDetection(InternalMessagePtr msg);
        void HandleNetworkConnect(InternalMessagePtr msg);
        void HandleNetworkDisconnect(InternalMessagePtr msg);
        void HandleRssiLevelChange(InternalMessagePtr msg);
        void TransitionToSelfCureState(int reason);
        void HandleArpDetectionFailed(InternalMessagePtr msg);
        bool SetupSelfCureMonitor();
        void UpdateInternetAccessHistory();
        void RequestReassocWithFactoryMac();
        void HandleInvalidIp(InternalMessagePtr msg);
        void HandleInternetFailedDetected(InternalMessagePtr msg);
        void HandleTcpQualityQuery(InternalMessagePtr msg);
        void HandleGatewayChanged(InternalMessagePtr msg);
        bool IsGatewayChanged();
        void HandleDnsFailedMonitor(InternalMessagePtr msg);
        bool IsNeedSelfCure();
    };

    /* *
     * @Description  Definition of DisconnectedMonitorState class in SelfCureStateMachine.
     *
     */
    class DisconnectedMonitorState : public State {
    public:
        explicit DisconnectedMonitorState(SelfCureStateMachine *selfCureStateMachine);
        ~DisconnectedMonitorState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        void HandleWifi7BlacklistRecover(InternalMessagePtr msg);
        void HandleWifi7WithoutMldBackoff(InternalMessagePtr msg);
        void HandleWifi7MldBackoff(InternalMessagePtr msg);
        void HandleNetworkConnectFailCount(InternalMessagePtr msg);
        SelfCureStateMachine *pSelfCureStateMachine_;
        bool isSetStaticIpConfig_ = false;
    };

    /* *
     * @Description  Definition of ConnectionSelfCureState class in SelfCureStateMachine.
     *
     */
    class ConnectionSelfCureState : public State {
    public:
        explicit ConnectionSelfCureState(SelfCureStateMachine *selfCureStateMachine);
        ~ConnectionSelfCureState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        SelfCureStateMachine *pSelfCureStateMachine_;
    };

    /* *
     * @Description  Definition of InternetSelfCureState class in SelfCureStateMachine.
     *
     */
    class InternetSelfCureState : public State {
    public:
        explicit InternetSelfCureState(SelfCureStateMachine *selfCureStateMachine);
        ~InternetSelfCureState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
        using selfCureIssHandleFunc = std::function<void(InternalMessagePtr msg)>;
        using SelfCureIssHandleFuncMap = std::map<int, selfCureIssHandleFunc>;

    private:
        SelfCureStateMachine *pSelfCureStateMachine_;
        int currentRssi_ = -1;
        std::string currentBssid_ = "";
        int selfCureFailedCounter_ = 0;
        int currentAbnormalType_ = -1;
        int currentSelfCureLevel_ = -1;
        int renewDhcpCount_ = -1;
        bool isHasInternetRecently_ = false;
        bool isPortalUnthenEver_ = false;
        bool isUserSetStaticIpConfig_ = false;
        int64_t lastHasInetTime_ = 0;
        bool isDelayedReassocSelfCure_ = false;
        bool isDelayedRandMacReassocSelfCure_ = false;
        bool isDelayedResetSelfCure_ = false;
        bool isSetStaticIp4InvalidIp_ = false;
        bool isConfigStaticIp4MultiDhcpServer_ = false;
        std::string unConflictedIp_ = "";
        int lastMultiGwSelfFailedType_ = -1;
        bool isUsedMultiGwSelfcure_ = false;
        std::string configAuthType_ = "";
        bool isFinalSelfCureUsed_ = false;
        std::vector<int> testedSelfCureLevel_;
        WifiSelfCureHistoryInfo selfCureHistoryInfo_;
        int selfCureForInvalidIpCnt_ = 0;
        SelfCureIssHandleFuncMap selfCureIssHandleFuncMap_;
        int InitSelfCureIssHandleMap();
        void HandleInternetFailedSelfCure(InternalMessagePtr msg);
        void HandleSelfCureWifiLink(InternalMessagePtr msg);
        void HandleNetworkDisconnected(InternalMessagePtr msg);
        void HandleInternetRecoveryConfirm(InternalMessagePtr msg);
        void HandleRssiChangedEvent(InternalMessagePtr msg);
        void HandleP2pDisconnected(InternalMessagePtr msg);
        void HandlePeriodicArpDetecte(InternalMessagePtr msg);
        void HandleArpFailedDetected(InternalMessagePtr msg);
        void HandleHttpReachableRecv(InternalMessagePtr msg);
        void HandleSelfCureResultFailed(InternalMessagePtr msg);
        void SelectSelfCureByFailedReason(int internetFailedType);
        int SelectBestSelfCureSolution(int internetFailedType);
        int SelectBestSelfCureSolutionExt(int internetFailedType);
        void SelfCureWifiLink(int requestCureLevel);
        bool SelectedSelfCureAcceptable();
        void SelfCureForRandMacReassoc(int requestCureLevel);
        void SelfCureForReset(int requestCureLevel);
        bool ConfirmInternetSelfCure(int currentCureLevel);
        void HandleConfirmInternetSelfCureFailed(int currentCureLevel);
        void HandleInternetFailedAndUserSetStaticIp(int internetFailedType);
        bool HasBeenTested(int cureLevel);
        void HandleHttpUnreachableFinally();
        void HandleHttpReachableAfterSelfCure(int currentCureLevel);
        void HandleSelfCureFailedForRandMacReassoc();
        void HandleRssiChanged();
        void HandleDelayedResetSelfCure();
        void SelfCureForInvalidIp();
        void SelfCureForReassoc(int requestCureLevel);
        void SelfcureForMultiGateway(InternalMessagePtr msg);
        bool IsNeedMultiGatewaySelfcure();
        void SelfCureForStaticIp(int requestCureLevel);
        void RequestUseStaticIpConfig(IpInfo &dhcpResult);
        IpInfo GetNextTestDhcpResults();
        IpInfo GetRecordDhcpResults();
        void InitCurrentGateway();
    };

    /* *
     * @Description  Definition of Wifi6SelfCureState class in SelfCureStateMachine.
     *
     */
    class Wifi6SelfCureState : public State {
    public:
        explicit Wifi6SelfCureState(SelfCureStateMachine *selfCureStateMachine);
        ~Wifi6SelfCureState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        SelfCureStateMachine *pSelfCureStateMachine_;
        int wifi6HtcArpDetectionFailedCnt_ = 0;
        int wifi6ArpDetectionFailedCnt_ = 0;
        int32_t internetValue_ = 0;
        bool isForceHttpCheck_ = true;
        void PeriodicWifi6WithHtcArpDetect(InternalMessagePtr msg);
        void PeriodicWifi6WithoutHtcArpDetect(InternalMessagePtr msg);
        void HandleWifi6WithHtcArpFail(InternalMessagePtr msg);
        void HandleWifi6WithoutHtcArpFail(InternalMessagePtr msg);
        void Wifi6ReassocSelfcure();
    };

    /* *
     * @Description  Definition of NoInternetState class in SelfCureStateMachine.
     *
     */
    class NoInternetState : public State {
    public:
        explicit NoInternetState(SelfCureStateMachine *selfCureStateMachine);
        ~NoInternetState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        void HandleArpFailedDetected(InternalMessagePtr msg);
        SelfCureStateMachine *pSelfCureStateMachine_;
    };

    ErrCode Initialize();
    void SetHttpMonitorStatus(bool isHttpReachable);
    bool IsSelfCureOnGoing();
    bool IsSelfCureL2Connecting();
    void StopSelfCureWifi(int32_t status);
    bool CheckSelfCureWifiResult(int event);
    void HandleP2pConnChanged(const WifiP2pLinkedInfo &info);
private:

    /* *
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

    /**
     * @Description  Build state tree
     *
     */
    void BuildStateTree();

    /**
     * @Description  Determine whether it is empty during initialization
     *
     */
    template <typename T>
    inline ErrCode JudgmentEmpty(T *&pointer)
    {
        if (pointer == nullptr) {
            return WIFI_OPT_FAILED;
        }
        return WIFI_OPT_SUCCESS;
    }

    /**
     * @Description  Initializing state of Self Cure.
     *
     */
    ErrCode InitSelfCureStates();
    int64_t GetNowMilliSeconds();
    void SendBlaListToDriver(int blaListType);
    std::string BlackListToString(std::map<std::string, WifiCategoryBlackListInfo> &map);
    std::string ParseWifiCategoryBlackListInfo(std::pair<std::string, WifiCategoryBlackListInfo> iter);
    bool AgeOutWifiCategoryBlack(int blaListType);
    void AgeOutWifiConnectFailList();
    int GetCurSignalLevel();
    bool IsHttpReachable();
    int GetLegalIpConfiguration(IpInfo &dhcpResults);
    bool CanArpReachable();
    bool DoSlowArpTest(const std::string& testIpAddr);
    bool IsIpAddressInvalid();
    bool IsUseFactoryMac();
    int GetBssidCounter(const std::vector<WifiScanInfo> &scanResults);
    bool IsNeedWifiReassocUseDeviceMac();
    bool IfP2pConnected();
    bool ShouldTransToWifi6SelfCure(InternalMessagePtr msg, std::string currConnectedBssid);
    int GetWifi7SelfCureType(int connectFailTimes, WifiLinkedInfo &info);
    void ShouldTransToWifi7SelfCure(WifiLinkedInfo &info);
    void HandleWifiBlackListUpdateMsg();
    int GetScanRssi(std::string currentBssid, const std::vector<WifiScanInfo> scanResults);
    int GetCurrentRssi();
    std::string GetCurrentBssid();
    bool IsWifi6Network(std::string currConnectedBssid);
    void PeriodicArpDetection();
    bool IsSuppOnCompletedState();
    bool IfPeriodicArpDetection();
    std::string GetAuthType();
    int GetIpAssignment(AssignIpMethod &ipAssignment);
    time_t GetLastHasInternetTime();
    uint32_t GetNetworkStatusHistory();
    std::string GetSelfCureHistoryInfo();
    int SetSelfCureHistoryInfo(const std::string selfCureHistory);
    int GetIsReassocWithFactoryMacAddress();
    int SetIsReassocWithFactoryMacAddress(int isReassocWithFactoryMacAddress);
    bool IsCustNetworkSelfCure();
    ErrCode GetCurrentWifiDeviceConfig(WifiDeviceConfig &config);
    void HandleNetworkConnected();
    bool UpdateConnSelfCureFailedHistory();
    void RecoverySoftAp();
    bool IsSoftApSsidSameWithWifi(const HotspotConfig& curApConfig);
    void CheckConflictIpForSoftAp();
    static bool IsEncryptedAuthType(const std::string authType);
    bool DoArpTest(std::string& ipAddress, std::string& gateway);
    void RequestArpConflictTest();
    bool IfMultiGateway();
    bool IsSettingsPage();
    bool IsMultiDhcpOffer();
    void ClearDhcpOffer();
    void CheckSelfCureConnectState();
    void CheckSelfCureReassocState();
    void UpdateSelfcureState(int currentCureLevel, bool isSelfCureOnGoing);
    void HandleSelfCureNormal();
    void HandleSelfCureException(int reasonCode);
    void StopSelfCureDelay(int status, int delay);
    void HandleSceStopSelfCure(int status);
    void SetSelfCureWifiTimeOut(SelfCureState wifiSelfCureState);
    void ResetSelfCureParam();
    void NotifySelfCureCompleted(int status);

private:
    SelfCureSmHandleFuncMap selfCureSmHandleFuncMap_;
    std::map<std::string, SelfCureServiceCallback> mSelfCureCallback_;
    DefaultState *pDefaultState_;
    ConnectedMonitorState *pConnectedMonitorState_;
    DisconnectedMonitorState *pDisconnectedMonitorState_;
    ConnectionSelfCureState *pConnectionSelfCureState_;
    InternetSelfCureState *pInternetSelfCureState_;
    Wifi6SelfCureState *pWifi6SelfCureState_;
    NoInternetState *pNoInternetState_;

    int instId_;
    bool isHttpReachable_ = false;
    int useWithRandMacAddress_ = 0;
    std::atomic<bool> isSelfCureOnGoing_ = false;
    std::atomic<bool> isP2pConnected_ = false;
    std::atomic<bool> isNotAllowSelfcure_ = true;
    int arpDetectionFailedCnt_ = 0;
    int selfCureReason_ = -1;
    int noTcpRxCounter_ = 0;
    uint32_t connectNetworkRetryCnt_ = 0;
    bool isInternetUnknown_ = false;
    int noAutoConnCounter_ = 0;
    int noAutoConnReason_ = -1;
    bool isStaticIpCureSuccess_ = false;
    bool isWifi6ArpSuccess_ = false;
    bool isHasTestWifi6Reassoc_ = false;
    bool isReassocSelfCureWithRealMacAddress_ = false;
    int64_t connectedTime_ = 0;
    std::mutex dhcpFailedBssidLock_;
    std::vector<std::string> dhcpFailedBssids_;
    std::vector<std::string> dhcpFailedConfigKeys_;
    std::map<std::string, int> autoConnectFailedNetworksRssi_;
    std::atomic<bool> isWifiBackground_ = false;
    sptr<NetStateObserver> mNetWorkDetect_;
    bool isP2pEnhanceConnected_ = false;
    bool isInternetFailureDetected_ = false;
    DetailedState selfCureNetworkLastState_ = DetailedState::IDLE;
    WifiState selfCureWifiLastState_ = WifiState::UNKNOWN;
    SelfCureState selfCureL2State_ = SelfCureState::SCE_WIFI_INVALID_STATE;
    std::mutex detectionMtx_;
    std::condition_variable detectionCond_;
};
} // namespace Wifi
} // namespace OHOS
#endif