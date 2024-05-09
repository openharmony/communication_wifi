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

namespace OHOS {
namespace Wifi {
constexpr int CURRENT_RSSI_INIT = -200;
constexpr int MAX_SELF_CURE_CNT_INVALID_IP = 3;
constexpr int VEC_POS_0 = 0;
constexpr int VEC_POS_1 = 1;
constexpr int VEC_POS_2 = 2;
constexpr int VEC_POS_3 = 3;
constexpr int TRY_TIMES = 3;
constexpr int STATIC_IP_ADDR = 156;
constexpr int IP_ADDR_LIMIT = 255;
constexpr int GET_NEXT_IP_MAC_CNT = 10;
constexpr int IP_ADDR_SIZE = 4;
constexpr int NET_MASK_LENGTH = 24;
constexpr int SELF_CURE_FAILED_ONE_CNT = 1;
constexpr int SELF_CURE_FAILED_TWO_CNT = 2;
constexpr int SELF_CURE_FAILED_THREE_CNT = 3;
constexpr int SELF_CURE_FAILED_FOUR_CNT = 4;
constexpr int SELF_CURE_FAILED_FIVE_CNT = 5;
constexpr int SELF_CURE_FAILED_SIX_CNT = 6;
constexpr int SELF_CURE_FAILED_SEVEN_CNT = 7;
constexpr int POS_DNS_FAILED_TS = 1;
constexpr int POS_RENEW_DHCP_FAILED_CNT = 2;
constexpr int POS_RENEW_DHCP_FAILED_TS = 3;
constexpr int POS_STATIC_IP_FAILED_CNT = 4;
constexpr int POS_STATIC_IP_FAILED_TS = 5;
constexpr int POS_REASSOC_FAILED_CNT = 6;
constexpr int POS_REASSOC_FAILED_TS = 7;
constexpr int POS_RANDMAC_FAILED_CNT = 8;
constexpr int POS_RANDMAC_FAILED_TS = 9;
constexpr int POS_RESET_FAILED_CNT = 10;
constexpr int POS_RESET_FAILED_TS = 11;
constexpr int POS_REASSOC_CONNECT_FAILED_CNT = 12;
constexpr int POS_REASSOC_CONNECT_FAILED_TS = 13;
constexpr int POS_RANDMAC_CONNECT_FAILED_CNT = 14;
constexpr int POS_RANDMAC_CONNECT_FAILED_TS = 15;
constexpr int POS_RESET_CONNECT_FAILED_CNT = 16;
constexpr int POS_RESET_CONNECT_FAILED_TS = 17;

class SelfCureStateMachine : public StateMachine {
    FRIEND_GTEST(SelfCureStateMachine);

public:
    explicit SelfCureStateMachine(int instId = 0);
    ~SelfCureStateMachine();
    using selfCureSmHandleFunc = void (SelfCureStateMachine::*)(InternalMessage *msg);
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
        bool ExecuteStateMsg(InternalMessage *msg) override;
    private:
        SelfCureStateMachine *pSelfCureStateMachine;
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
        bool ExecuteStateMsg(InternalMessage *msg) override;
        using selfCureCmsHandleFunc = void (SelfCureStateMachine::ConnectedMonitorState::*)(InternalMessage *msg);
        using SelfCureCmsHandleFuncMap = std::map<int, selfCureCmsHandleFunc>;

    private:
        SelfCureStateMachine *pSelfCureStateMachine;
        int lastSignalLevel = -1;
        std::string lastConnectedBssid;
        bool mobileHotspot = false;
        bool ipv4DnsEnabled = false;
        bool gatewayInvalid = false;
        std::string configAuthType = "-1";
        bool hasInternetRecently = false;
        bool portalUnthenEver = false;
        bool userSetStaticIpConfig = false;
        bool wifiSwitchAllowed = false;
        SelfCureCmsHandleFuncMap selfCureCmsHandleFuncMap;
        int InitSelfCureCmsHandleMap();
        void HandleResetupSelfCure(InternalMessage *msg);
        void HandlePeriodicArpDetection(InternalMessage *msg);
        void HandleNetworkConnect(InternalMessage *msg);
        void HandleNetworkDisconnect(InternalMessage *msg);
        void HandleRssiLevelChange(InternalMessage *msg);
        void TransitionToSelfCureState(int reason);
        void HandleArpDetectionFailed(InternalMessage *msg);
        bool SetupSelfCureMonitor();
        void UpdateInternetAccessHistory();
        void RequestReassocWithFactoryMac();
        void HandleInvalidIp(InternalMessage *msg);
        void HandleInternetFailedDetected(InternalMessage *msg);
        void IsWifi6SelfCureNeed(InternalMessage *msg);
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        SelfCureStateMachine *pSelfCureStateMachine;
        bool setStaticIpConfig = false;
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        SelfCureStateMachine *pSelfCureStateMachine;
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
        bool ExecuteStateMsg(InternalMessage *msg) override;
        using selfCureIssHandleFunc = void (SelfCureStateMachine::InternetSelfCureState::*)(InternalMessage *msg);
        using SelfCureIssHandleFuncMap = std::map<int, selfCureIssHandleFunc>;

    private:
        SelfCureStateMachine *pSelfCureStateMachine;
        int currentRssi = -1;
        std::string currentBssid = "";
        int selfCureFailedCounter = -1;
        int currentAbnormalType = -1;
        int lastSelfCureLevel = -1;
        int currentSelfCureLevel = -1;
        int renewDhcpCount = -1;
        bool hasInternetRecently = false;
        bool portalUnthenEver = false;
        bool userSetStaticIpConfig = false;
        uint64_t lastHasInetTimeMillis = 0;
        bool delayedReassocSelfCure = false;
        bool delayedRandMacReassocSelfCure = false;
        bool delayedResetSelfCure = false;
        bool setStaticIp4InvalidIp = false;
        bool isRenewDhcpTimeout = false;
        std::string unConflictedIp = "";
        int lastMultiGwSelfFailedType = -1;
        bool usedMultiGwSelfcure = false;
        std::string configAuthType = "";
        bool finalSelfCureUsed = false;
        std::vector<int> testedSelfCureLevel;
        WifiSelfCureHistoryInfo selfCureHistoryInfo;
        std::string currentGateway = "";
        int selfCureForInvalidIpCnt = 0;
        SelfCureIssHandleFuncMap selfCureIssHandleFuncMap;
        int InitSelfCureIssHandleMap();
        void HandleInternetFailedSelfCure(InternalMessage *msg);
        void HandleSelfCureWifiLink(InternalMessage *msg);
        void HandleNetworkDisconnected(InternalMessage *msg);
        void HandleInternetRecovery(InternalMessage *msg);
        void HandleRssiChangedEvent(InternalMessage *msg);
        void HandleP2pDisconnected(InternalMessage *msg);
        void HandlePeriodicArpDetecte(InternalMessage *msg);
        void HandleArpFailedDetected(InternalMessage *msg);
        void SelectSelfCureByFailedReason(int internetFailedType);
        int SelectBestSelfCureSolution(int internetFailedType);
        void SelfCureWifiLink(int requestCureLevel);
        bool SelectedSelfCureAcceptable();
        void SelfCureForRandMacReassoc();
        void HandleIpConfigCompleted();
        void HandleIpConfigCompletedAfterRenewDhcp();
        void HandleInternetRecoveryConfirm();
        bool ConfirmInternetSelfCure(int currentCureLevel);
        void HandleInternetFailedAndUserSetStaticIp(int internetFailedType);
        void HandleIpConfigTimeout();
        bool HasBeenTested(int cureLevel);
        void HandleHttpUnreachableFinally();
        void HandleHttpReachableAfterSelfCure(int currentCureLevel);
        void HandleSelfCureFailedForRandMacReassoc();
        void HandleRssiChanged();
        void HandleDelayedResetSelfCure();
        void SelfCureForRenewDhcp(int requestCureLevel);
        void SelfCureForInvalidIp();
        void SelfCureForReassoc(int requestCureLevel);
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        SelfCureStateMachine *pSelfCureStateMachine;
        int wifi6HtcArpDetectionFailedCnt = 0;
        int wifi6ArpDetectionFailedCnt = 0;
        void PeriodicWifi6WithHtcArpDetect(InternalMessage *msg);
        void PeriodicWifi6WithoutHtcArpDetect(InternalMessage *msg);
        void HandleWifi6WithHtcArpFail(InternalMessage *msg);
        void HandleWifi6WithoutHtcArpFail(InternalMessage *msg);
        void Wifi6ReassocSelfcure();
    };

    ErrCode Initialize();
    void SetHttpMonitorStatus(bool isHttpReachable);

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
    void SendBlaListToDriver();
    std::string BlackListToString(std::map<std::string, Wifi6BlackListInfo> &map);
    std::string ParseWifi6BlackListInfo(std::pair<std::string, Wifi6BlackListInfo> iter);
    void AgeOutWifi6Black(std::map<std::string, Wifi6BlackListInfo> &wifi6BlackListCache);
    int GetCurSignalLevel();
    bool IsHttpReachable();
    std::string TransVecToIpAddress(std::vector<uint32_t> vec);
    std::vector<uint32_t> TransIpAddressToVec(std::string addr);
    int GetLegalIpConfiguration(IpInfo &dhcpResults);
    bool CanArpReachable();
    bool DoSlowArpTest(std::string testIpAddr);
    std::string GetNextIpAddr(const std::string gateway, const std::string currentAddr,
                              std::vector<std::string> testedAddr);
    bool IsIpAddressInvalid();
    std::vector<std::string> TransStrToVec(std::string str, char c);
    bool IsUseFactoryMac();
    bool IsSameEncryptType(const std::string scanInfoKeymgmt, const std::string deviceKeymgmt);
    int GetBssidCounter(const std::vector<WifiScanInfo> &scanResults);
    bool IsNeedWifiReassocUseDeviceMac();
    int String2InternetSelfCureHistoryInfo(const std::string selfCureHistory, WifiSelfCureHistoryInfo &info);
    int SetSelfCureFailInfo(OHOS::Wifi::WifiSelfCureHistoryInfo &info, std::vector<std::string> histories, int cnt);
    int SetSelfCureConnectFailInfo(WifiSelfCureHistoryInfo &info, std::vector<std::string> histories, int cnt);
    bool IfP2pConnected();
    bool ShouldTransToWifi6SelfCure(InternalMessage *msg, std::string currConnectedBssid);
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
    WifiDeviceConfig GetCurrentWifiDeviceConfig();
    bool SelfCureAcceptable(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel);
    void HandleNetworkConnected();
    bool UpdateConnSelfCureFailedHistory();
    static bool IsEncryptedAuthType(const std::string authType);
    std::string GetCurrentGateway();
    bool DoArpTest(std::string ipAddress, std::string gateway);
    void RequestArpConflictTest();
    static void UpdateReassocAndResetHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                 bool success);
    static void UpdateSelfCureHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, bool success);
    static void UpdateSelfCureConnectHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                 bool success);
    void HandleP2pConnChanged(const WifiP2pLinkedInfo &info);
    bool IfMultiGateway();
    bool IsSettingsPage();

private:
    SelfCureSmHandleFuncMap selfCureSmHandleFuncMap;
    std::map<std::string, SelfCureServiceCallback> mSelfCureCallback;
    std::mutex mMutex;
    DefaultState *pDefaultState;
    ConnectedMonitorState *pConnectedMonitorState;
    DisconnectedMonitorState *pDisconnectedMonitorState;
    ConnectionSelfCureState *pConnectionSelfCureState;
    InternetSelfCureState *pInternetSelfCureState;
    Wifi6SelfCureState *pWifi6SelfCureState;

    int m_instId;
    bool mIsHttpReachable = false;
    int useWithRandMacAddress = 0;
    std::atomic<bool> selfCureOnGoing = false;
    std::atomic<bool> p2pConnected = false;
    std::atomic<bool> notAllowSelfcure = false;
    int arpDetectionFailedCnt = 0;
    int selfCureReason = -1;
    int noTcpRxCounter = 0;
    bool internetUnknown = false;
    std::map<std::string, IpInfo> dhcpOfferPackets;
    std::vector<std::string> dhcpResultsTestDone;
    int noAutoConnCounter = 0;
    int noAutoConnReason = -1;
    bool staticIpCureSuccess = false;
    bool isWifi6ArpSuccess = false;
    bool hasTestWifi6Reassoc = false;
    bool isReassocSelfCureWithRealMacAddress = false;
    uint64_t connectedTimeMills = 0;
    std::mutex dhcpFailedBssidLock;
    std::vector<std::string> dhcpFailedBssids;
    std::vector<std::string> dhcpFailedConfigKeys;
    std::map<std::string, int> autoConnectFailedNetworksRssi;
    std::atomic<bool> isWifiBackground = false;
};
} // namespace Wifi
} // namespace OHOS
#endif