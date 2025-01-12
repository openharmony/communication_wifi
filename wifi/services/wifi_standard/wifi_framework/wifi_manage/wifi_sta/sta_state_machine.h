/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_STATE_MACHINE_H
#define OHOS_WIFI_STATE_MACHINE_H

#include <regex.h>
#include <sys/types.h>
#include <fstream>
#include <vector>
#include <shared_mutex>
#include "wifi_internal_msg.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "state_machine.h"
#include "arp_checker.h"
#include "sta_service_callback.h"
#include "dhcp_c_api.h"
#include "sta_define.h"
#include "network_status_history_manager.h"
#include "wifi_native_struct.h"

#ifndef OHOS_ARCH_LITE
#include "want.h"
#include "wifi_net_agent.h"
#include "wifi_net_observer.h"
#include "sim_state_type.h"
#include "core_service_client.h"
#include "cellular_data_client.h"
#include "core_manager_inner.h"
#include "telephony_errors.h"
#include "ienhance_service.h"
#include "iself_cure_service.h"
#include "wifi_common_event_helper.h"
#endif

namespace OHOS {
namespace Wifi {
#ifndef OHOS_ARCH_LITE
using namespace OHOS::Telephony;
#endif
constexpr int STA_RENEWAL_MIN_TIME = 120;
constexpr int STREAM_TXPACKET_THRESHOLD = 0;
constexpr int STREAM_RXPACKET_THRESHOLD = 0;
constexpr int STA_AP_ROAMING_TIMEOUT = 15000; // 15s->15000 ms

constexpr int CMD_NETWORK_CONNECT_TIMEOUT = 0X01;
constexpr int CMD_SIGNAL_POLL = 0X02;
constexpr int CMD_START_NETCHECK = 0X03;
constexpr int CMD_START_GET_DHCP_IP_TIMEOUT = 0X04;
constexpr int CMD_AP_ROAMING_TIMEOUT_CHECK = 0X06;

constexpr int STA_NETWORK_CONNECTTING_DELAY = 20 * 1000;
constexpr int STA_SIGNAL_POLL_DELAY = 3 * 1000;
constexpr int STA_SIGNAL_START_GET_DHCP_IP_DELAY = 30 * 1000;

/* pincode length */
constexpr int PIN_CODE_LEN = 8;

/* DHCP timeout interval */
constexpr int DHCP_TIME = 15;
/* rssi thresholds */
constexpr int INVALID_RSSI_VALUE = -127;
constexpr int MAX_RSSI_VALUE = 200;
constexpr int SIGNAL_INFO = 256;
constexpr int RSSI_LEVEL_3 = 3;

/* 2.4g and 5g frequency thresholds */
constexpr int FREQ_2G_MIN = 2412;
constexpr int FREQ_2G_MAX = 2472;
constexpr int FREQ_5G_MIN = 5170;
constexpr int FREQ_5G_MAX = 5825;
constexpr int CHANNEL_14_FREQ = 2484;
constexpr int CHANNEL_14 = 14;
constexpr int CENTER_FREQ_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_5G_MIN = 34;

constexpr int MULTI_AP = 0;

/* Wpa3 selfcure failreason num*/
constexpr int WLAN_STATUS_AUTH_TIMEOUT = 16;
constexpr int MAC_AUTH_RSP2_TIMEOUT = 5201;
constexpr int MAC_AUTH_RSP4_TIMEOUT = 5202;
constexpr int MAC_ASSOC_RSP_TIMEOUT = 5203;
constexpr int DHCP_RENEW_FAILED = 4;
constexpr int DHCP_RENEW_TIMEOUT = 5;
constexpr int DHCP_LEASE_EXPIRED = 6;

constexpr unsigned int BIT_MLO_CONNECT = 0x80;

#define DNS_IP_ADDR_LEN 15
#define WIFI_FIRST_DNS_NAME "const.wifi.wifi_first_dns"
#define WIFI_SECOND_DNS_NAME "const.wifi.wifi_second_dns"

enum Wpa3ConnectFailReason {
    WPA3_AUTH_TIMEOUT,
    WPA3_ASSOC_TIMEOUT,
    WPA3_FAIL_REASON_MAX
};

enum class CoFeatureType {
    COFEATURE_TYPE_MLO = 0,
    COFEATURE_TYPE_WUR = 1,
};

typedef enum EnumDhcpReturnCode {
    DHCP_RESULT,
    DHCP_JUMP,
    DHCP_RENEW_FAIL,
    DHCP_IP_EXPIRED,
    DHCP_FAIL,
    DHCP_OFFER_REPORT,
} DhcpReturnCode;

inline const int DETECT_TYPE_DEFAULT = 0;
inline const int DETECT_TYPE_PERIODIC = 1;
inline const int DETECT_TYPE_CHECK_PORTAL_EXPERIED = 2;
inline const int PORTAL_EXPERIED_DETECT_MAX_COUNT = 2;
enum PortalState {
    UNCHECKED = 0,
    NOT_PORTAL,
    UNAUTHED,
    AUTHED,
    EXPERIED
};

const std::string WPA_BSSID_ANY = "any";

class StaStateMachine : public StateMachine {
    FRIEND_GTEST(StaStateMachine);
public:
    explicit StaStateMachine(int instId = 0);
    ~StaStateMachine();
    using staSmHandleFunc = std::function<void(InternalMessagePtr)>;
    using StaSmHandleFuncMap = std::map<int, staSmHandleFunc>;
    /**
     * @Description  Definition of member function of State base class in StaStateMachine.
     *
     */
    class RootState : public State {
    public:
        explicit RootState();
        ~RootState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;
    };
    /**
     * @Description : Definition of member function of InitState class in StaStateMachine.
     *
     */
    class InitState : public State {
    public:
        explicit InitState(StaStateMachine *staStateMachine);
        ~InitState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        void StartWifiProcess();
        void StopWifiProcess();
        void StartConnectEvent(InternalMessagePtr msg);
        void UpdateCountryCode(InternalMessagePtr msg);
        bool AllowAutoConnect();
        void HandleNetworkConnectionEvent(InternalMessagePtr msg);
        StaStateMachine *pStaStateMachine;
    };

    /**
     * @Description  Definition of member function of LinkState class in StaStateMachine.
     *
     */
    class LinkState : public State {
    public:
        explicit LinkState(StaStateMachine *staStateMachine);
        ~LinkState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        StaSmHandleFuncMap staSmHandleFuncMap;
        StaStateMachine *pStaStateMachine;
        int InitStaSMHandleMap();
        void StopWifiProcessInLinkState(InternalMessagePtr msg);
        void DealDisconnectEventInLinkState(InternalMessagePtr msg);
        void DealConnectTimeOutCmd(InternalMessagePtr msg);
        void DealNetworkRemoved(InternalMessagePtr msg);
        void DealWpaStateChange(InternalMessagePtr msg);
        void DealMloStateChange(InternalMessagePtr msg);
    };
    /**
     * @Description  Definition of member function of SeparatedState class in StaStateMachine.
     *
     */
    class SeparatedState : public State {
    public:
        explicit SeparatedState(StaStateMachine *staStateMachine);
        ~SeparatedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        StaStateMachine *pStaStateMachine;
        void DealReConnectCmdInSeparatedState(InternalMessagePtr msg);
    };
    /**
     * @Description  Definition of member function of ApLinkingState class in StaStateMachine.
     *
     */
    class ApLinkingState : public State {
    public:
        explicit ApLinkingState(StaStateMachine *staStateMachine);
        ~ApLinkingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        void HandleStaBssidChangedEvent(InternalMessagePtr msg);
        void DealWpaLinkFailEvent(InternalMessagePtr msg);
    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of ApLinkedState class in StaStateMachine.
     *
     */
    class ApLinkedState : public State {
    public:
        explicit ApLinkedState(StaStateMachine *staStateMachine);
        ~ApLinkedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        void HandleNetWorkConnectionEvent(InternalMessagePtr msg);
        void HandleStaBssidChangedEvent(InternalMessagePtr msg);
        void HandleLinkSwitchEvent(InternalMessagePtr msg);
        void DealStartRoamCmdInApLinkedState(InternalMessagePtr msg);

    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of GetIpState class in StaStateMachine.
     *
     */
    class GetIpState : public State {
    public:
        explicit GetIpState(StaStateMachine *staStateMachine);
        ~GetIpState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        bool IsPublicESS();
        bool IsProhibitUseCacheIp();
        void DealGetDhcpIpTimeout(InternalMessagePtr msg);
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of LinkedState class in StaStateMachine.
     *
     */
    class LinkedState : public State {
    public:
        explicit LinkedState(StaStateMachine *staStateMachine);
        ~LinkedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
#ifndef OHOS_ARCH_LITE
        void CheckIfRestoreWifi();
#endif
        void DhcpResultNotify(InternalMessagePtr msg);
        void NetDetectionNotify(InternalMessagePtr msg);
        void DealNetworkCheck(InternalMessagePtr msg);
        void UpdateWifi7WurInfo();
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of ApRoamingState class in StaStateMachine.
     *
     */
    class ApRoamingState : public State {
    public:
        explicit ApRoamingState(StaStateMachine *staStateMachine);
        ~ApRoamingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessagePtr msg) override;

    private:
        bool HandleNetworkConnectionEvent(InternalMessagePtr msg);
        void DealApRoamingStateTimeout(InternalMessagePtr msg);
        StaStateMachine *pStaStateMachine;
    };

    class DhcpResultNotify {
    public:
        /**
         * @Description : Construct a new dhcp result notify object
         *
         */
        explicit DhcpResultNotify(StaStateMachine *staStateMachine);

        /**
         * @Description : Destroy the dhcp result notify object
         *
         */
        ~DhcpResultNotify();

        /**
         * @Description : Get dhcp result of specified interface success notify asynchronously
         *
         * @param status - int
         * @param ifname - interface name,eg:wlan0
         * @param result - dhcp result
         */
        static void OnSuccess(int status, const char *ifname, DhcpResult *result);

        /**
         * @Description : Get dhcp offer result of specified interface success notify asynchronously
         *
         * @param status - int
         * @param ifname - interface name,eg:wlan0
         * @param result - dhcp offer
         */
        static void OnDhcpOffer(int status, const char *ifname, DhcpResult *result);

        /**
         * @Description : Get dhcp result of specified interface failed notify asynchronously
         *
         * @param status - int
         * @param ifname - interface name,eg:wlan0
         * @param reason - failed reason
         */
        static void OnFailed(int status, const char *ifname, const char *reason);
        void OnSuccessDhcpResult(int status, const char *ifname, DhcpResult *result);
        void OnFailedDhcpResult(int status, const char *ifname, const char *reason);
        void OnDhcpOfferResult(int status, const char *ifname, DhcpResult *result);
        void DealDhcpResult(int ipType);
        void DealDhcpResultFailed();
        void DealDhcpOfferResult();
    private:
        void TryToSaveIpV4Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result);
        void TryToSaveIpV4ResultExt(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result);
        void TryToSaveIpV6Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result);
        void TryToCloseDhcpClient(int iptype);
        void SaveDhcpResult(DhcpResult *dest, DhcpResult *source);
        void SaveDhcpResultExt(DhcpResult *dest, DhcpResult *source);
        void DhcpResultNotifyEvent(DhcpReturnCode result, int ipType = -1);
        static StaStateMachine *pStaStateMachineList[STA_INSTANCE_MAX_NUM];
        StaStateMachine *pStaStateMachine;
        std::mutex dhcpResultMutex;
        DhcpResult DhcpIpv4Result;
        DhcpResult DhcpIpv6Result;
        DhcpResult DhcpOfferInfo;
    };

public:
    /**
     * @Description  Initialize StaStateMachine
     *
     * @Return:  WIFI_OPT_SUCCESS - success  WIFI_OPT_FAILED - failed
     */
    ErrCode InitStaStateMachine();
    /**
     * @Description  Start roaming connection.
     *
     * @param bssid - the mac address of network(in)
     */
    void StartRoamToNetwork(std::string bssid);
    /**
     * @Description Register sta callback function
     *
     * @param callback - Callback function pointer storage structure
     */
    void RegisterStaServiceCallback(const StaServiceCallback &callback);

    /**
     * @Description unRegister sta callback function
     *
     * @param callback - Callback function pointer storage structure
     */
    void UnRegisterStaServiceCallback(const StaServiceCallback &callback);

    /**
     * @Description Reupdate net link info
     */
    void ReUpdateNetLinkInfo(const WifiDeviceConfig &config);

    /**
     * @Description On netmanager restart.
     */
    void OnNetManagerRestart(void);

    /**
     * @Description : start detect timer.
     * @param detectType - type of detect
     */
    void StartDetectTimer(int detectType);

    /**
     * @Description  start browser to login portal
     *
     */
    void HandlePortalNetworkPorcess();
    
    void SetPortalBrowserFlag(bool flag);
    void DealApRoamingStateTimeout(InternalMessagePtr msg);
    void DealHiLinkDataToWpa(InternalMessagePtr msg);
    void HilinkSetMacAddress(std::string &cmd);
    void DealWpaStateChange(InternalMessagePtr msg);
    void DealCsaChannelChanged(InternalMessagePtr msg);
#ifndef OHOS_ARCH_LITE
    void SetEnhanceService(IEnhanceService* enhanceService);
    void SetSelfCureService(ISelfCureService *selfCureService);
    void UpdateAcceptUnvalidatedState();
#endif
/* ------------------ state machine private function ----------------- */
private:
    /**
     * @Description  Destruct state.
     *
     */
    template<typename T>
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
    template<typename T>
    inline ErrCode JudgmentEmpty(T *&pointer)
    {
        if (pointer == nullptr) {
            return WIFI_OPT_FAILED;
        }
        return WIFI_OPT_SUCCESS;
    }

    bool SetMacToHal(const std::string &currentMac, const std::string &realMac, int instId);
   /**
     * @Description  Register dhcp client CallBack
     *
     * @Return:  DHCP_OPT_SUCCESS - success  DHCP_OPT_FAILED - failed
     */
    int RegisterDhcpCallBack();

    /**
     * @Description  Initializing state of Sta.
     *
     */
    ErrCode InitStaStates();
    /**
     * @Description  The process of initializing connected wifi information.
     *
     */
    void InitWifiLinkedInfo();

    /**
     * @Description  Convert the deviceConfig structure and set it to idl structure
     *
     * @param config -The Network info(in)
     * @param halDeviceConfig -The Network info(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode FillEapCfg(const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const;

    /**
     * @Description  Convert the deviceConfig structure and set it to wpa_supplicant
     *
     * @param config -The Network info(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode ConvertDeviceCfg(const WifiDeviceConfig &config, std::string bssid) const;

    /**
     * @Description  Save the current connected state into WifiLinkedInfo.
     *
     * @param state - current connecting state(in)
     * @param detailState - the current detail state of StaStateMachine.(in)
     */
    void SaveLinkstate(ConnState state, DetailedState detailState);

    /**
     * @Description  Save the disconnected reason.
     *
     * @param discReason - disconnected reason(in)
     */
    void SaveDiscReason(DisconnectedReason discReason);
    /**
     * @Description  Update wifi status and save connection information.
     *
     * @param bssid - the mac address of wifi(in)
     */
    void AfterApLinkedprocess(std::string bssid);

    /**
     * @Description  Start to connect to network.
     *
     * @param networkId - the networkId of network which is going to be connected.(in)
     * @param bssid - the bssid of network which is going to be connected.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode StartConnectToNetwork(int networkId, const std::string &bssid, int connTriggerMode);

    void SetAllowAutoConnectStatus(int32_t networkId, bool status);
 
    /**
     * @Description  Disconnect network
     *
     */
    void StartDisConnectToNetwork();

    /**
     * @Description  Configure static ipaddress.
     *
     * @param staticIpAddress- static ip address(in)
     */
    bool ConfigStaticIpAddress(StaticIpAddress &staticIpAddress);

    /**
     * @Description  the process of handling network check results.
     *
     * @param netState the state of connecting network(in)
     * @param portalUrl portal network redirection address
     */
    void HandleNetCheckResult(SystemNetWorkState netState, const std::string &portalUrl);

    /**
     * @Description  update portalState
     *
     * @param netState the state of connecting network(in)
     * @param updatePortalAuthTime need update portalAuthTime or not [out]
     */
    void UpdatePortalState(SystemNetWorkState netState, bool &updatePortalAuthTime);

    /**
     * @Description  start detection if portalState is expired
     */
    void PortalExpiredDetect();

    /**
     * @Description implementation of the network detection callback function
     *
     * @param netState the state of connecting network
     * @param url portal network redirection address
     */
    void NetStateObserverCallback(SystemNetWorkState netState, std::string url);

    /**
     * @Description  notification portal network.
     *
     */
    void PublishPortalNetworkNotification();

    /**
     * @Description : Update RSSI to LinkedInfo.
     *
     * @param  inRssi - Rssi get from SignalPoll Result
     */
    int UpdateLinkInfoRssi(int inRssi);

    /**
     * @Description : Deal SignalPoll Result.
     */
    void DealSignalPollResult();

    /**
     * @Description : Update RSSI to LinkedInfo and public rssi changed broadcast.
     *
     * @param  signalInfo - SignalPoll Result
     */
    void UpdateLinkRssi(const WifiSignalPollInfo &signalInfo);

    /**
     * @Description : Converting frequencies to channels.
     *
     */
    void ConvertFreqToChannel();

    /**
     * @Description : send packet direction to hisysevent
     *
     */
    void DealSignalPacketChanged(int txPackets, int rxPackets);

    /**
     * @Description  Connect to selected network.
     *
     * @param  msg - Message body received by the state machine[in]
     */
    void DealConnectToSelectedNetCmd(InternalMessagePtr msg);

    /**
     * @Description  Operations after the Connection Event is reported.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealConnectionEventInApLinkingState(InternalMessagePtr msg);

    /**
     * @Description  Operations after the Reassociate lead is issued
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealReassociateCmd(InternalMessagePtr msg);

    /**
     * @Description  set sta connect failed count
     *@Return void
     */
    void DealSetStaConnectFailedCount(int count, bool set);

    /**
     * @Description  Reassociate network.
     *
     */
    void ReassociateProcess();

    /**
     * @Description  Set value of randomMacInfo.
     *
     * @param deviceConfig - deviceConfig[in]
     * @param bssid - bssid[in]
     * @param deviceConfig - randomMacInfo[out]
     */
    void InitRandomMacInfo(const WifiDeviceConfig &deviceConfig, const std::string &bssid,
        WifiStoreRandomMac &randomMacInfo);

    /**
     * @Description  Set a random MAC address.
     *
     * @param networkId - network id[in]
     */
    bool SetRandomMac(int networkId, const std::string &bssid);

    /**
     * @Description  Generate a random MAC address.
     *
     * @param strMac - Randomly generated MAC address[out]
     */
    void MacAddressGenerate(WifiStoreRandomMac &randomMacInfo);

    /**
     * @Description  Compare the encryption mode of the current network with that of the network in the scanning result.
     *
     * @param scanInfoKeymgmt - Network encryption mode in the scanning result[in]
     * @param deviceKeymgmt - Encryption mode of the current network[in]
     */
    bool ComparedKeymgmt(const std::string scanInfoKeymgmt, const std::string deviceKeymgmt);

    /**
     * @Description : is wpa3 transition mode.
     *
     * @param ssid - ssid
     */
    bool IsWpa3Transition(std::string ssid, std::string bssid) const;

    /**
     * @Description : get wpa3 failreason connect fail count
     *
     * @param failreason - auth or assoc fail
     * @param ssid - ssid
     */
    int GetWpa3FailCount(int failreason, std::string ssid) const;

    /**
     * @Description : add wpa3 failreason connect fail count
     *
     * @param failreason - auth or assoc fail
     * @param ssid - ssid
     */
    void AddWpa3FailCount(int failreason, std::string ssid);

    /**
     * @Description : add wpa3 black map
     *
     * @param ssid - ssid
     */
    void AddWpa3BlackMap(std::string ssid);

    /**
     * @Description : is in wpa3 black map
     *
     * @param ssid - ssid
     */
    bool IsInWpa3BlackMap(std::string ssid) const;

    /**
     * @Description : wpa3 transition selfcure
     *
     * @param failreason - auth or assoc fail
     * @param networkId - networkId
     */
    void OnWifiWpa3SelfCure(int failreason, int networkId);
	
    /**
     * @Description : Deal screen state change event.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealScreenStateChangedEvent(InternalMessagePtr msg);

    /**
     * @Description set external sim
     *
     * @param ifName - port name(in)
     * @param eap - eap method(in)
     * @Return success: 0  fail: others
     */
    ErrCode SetExternalSim(const std::string ifName, const std::string &eap, int value) const;

    /**
     * @Description : should sta connect use factory mac address.
     *
     * @param networkId - networkId.
     */
    bool ShouldUseFactoryMac(const WifiDeviceConfig &deviceConfig);

    /**
     * @Description : Check Current Connect is used randomized mac or not.
     *
     * @param networkId - networkId.
     * @Return true: used randomized mac address.
     */
    bool CurrentIsRandomizedMac();

    /**
     * @Description : Check wpa report DisConnect reason is should stoptimer.
     *
     * @param reason - reason.
     * @Return true: need stop timer.
     */
    bool IsDisConnectReasonShouldStopTimer(int reason);

    /**
     * @Description : Hilink Save Data To Device Config.
     *
     */
    void HilinkSaveConfig(void);

    /**
     * @Description operation before dhcp
     */
    void HandlePreDhcpSetup();

    /**
     * @Description judge if specific network
     */
    bool IsSpecificNetwork();

    /**
     * @Description operation after dhcp
     */
    void HandlePostDhcpSetup();

    /**
     * @Description Get Wifi7 MLO link info.
     */
    void DealMloConnectionLinkInfo(void);

#ifndef OHOS_ARCH_LITE
    /**
     * @Description Get slot id.
     * @Return int32_t - 0:success, other value:failed
     */
    int32_t GetDataSlotId(int32_t slotId);

    /**
     * @Description Get card type.
     * @param cardType - card type
     * @Return int32_t - 0:success, other value:failed
     */
    int32_t GetCardType(CardType &cardType);

    /**
     * @Description Get default slot id.
     * @param slotId - slot id
     * @Return int32_t - 0 success, other value:failed
     */
    int32_t GetDefaultId(int32_t slotId);

    /**
     * @Description Get card state.
     * @param slotId - slot id
     * @Return int32_t - card state
     */
    int32_t GetSimCardState(int32_t slotId);

    /**
     * @Description verify simId.
     * @param simId - sim id
     * @Return int32_t - true: success, false: failed
     */
    bool IsValidSimId(int32_t simId);

    /**
     * @Description Check whether the SIM card is a multi-SIM card.
     * @Return int32_t - true: success, false: failed
     */
    bool IsMultiSimEnabled();

    /**
     * @Description sim authenticate
     * @param nonce - sim id
     * @Return int32_t - 0:success, other value:failed
     */
    std::string SimAkaAuth(const std::string &nonce, AuthType authType);

    /**
     * @Description Get SIM card authentication information.
     * @param param - authentication information
     * @Return int32_t - 0:success, other value:failed
     */
    std::string GetGsmAuthResponseWithLength(EapSimGsmAuthParam param);

    /**
     * @Description Get SIM card authentication information.
     * @param param - authentication information
     * @Return int32_t - 0:success, other value:failed
     */
    std::string GetGsmAuthResponseWithoutLength(EapSimGsmAuthParam param);

    /**
     * @Description sim authentication notify events
     *
     * @param msg: authentication data
     */
    void DealWpaEapSimAuthEvent(InternalMessagePtr msg);

    /**
     * @Description aka/aka' authentication Pre-process
     *
     */
    bool PreWpaEapUmtsAuthEvent();

    /**
     * @Description fill aka/aka' authentication request message
     *
     * @param param: authentication data
     */
    std::vector<uint8_t> FillUmtsAuthReq(EapSimUmtsAuthParam &param);

    /**
     * @Description fill aka/aka' authentication request message
     *
     * @param nonce: authentication data
     */
    std::string ParseAndFillUmtsAuthParam(std::vector<uint8_t> &nonce);

    /**
     * @Description Get aka/aka' card authentication information
     *
     * @param param: authentication data
     */
    std::string GetUmtsAuthResponse(EapSimUmtsAuthParam &param);

    /**
     * @Description aka/aka' authentication notify events
     *
     * @param msg: authentication data
     */
    void DealWpaEapUmtsAuthEvent(InternalMessagePtr msg);

    /**
     * @Description Subscribe system ability changed.
     */
    void SubscribeSystemAbilityChanged(void);

    /**
     * @Description save wificonfig for update mode.
     *
     * @param networkId - current connected networkId;
     */
    void SaveWifiConfigForUpdate(int networkId);
    void CloseNoInternetDialog();
    void SyncDeviceEverConnectedState(bool hasNet);
#endif // OHOS_ARCH_LITE
    bool IsNewConnectionInProgress();
    void StopDhcp();
    /**
     * @Description Replace empty dns
     */
    void ReplaceEmptyDns(DhcpResult *result);
    void InvokeOnStaConnChanged(OperateResState state, const WifiLinkedInfo &info);
    void InvokeOnStaStreamChanged(StreamDirection direction);
    void InvokeOnStaRssiLevelChanged(int level);
    void InvokeOnDhcpOfferReport(IpInfo ipInfo);
    WifiDeviceConfig getCurrentWifiDeviceConfig();
    void InsertOrUpdateNetworkStatusHistory(const NetworkStatus &networkStatus, bool updatePortalAuthTime);
    bool CanArpReachable();
    void AddRandomMacCure();
    ErrCode ConfigRandMacSelfCure(const int networkId);
#ifndef OHOS_ARCH_LITE
    void ShowPortalNitification();
    void UpdateWifiCategory();
    void SetSupportedWifiCategory();
#endif
    void SetConnectMethod(int connectMethod);
    void FillSuiteB192Cfg(WifiHalDeviceConfig &halDeviceConfig) const;
    void FillWapiCfg(const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const;
    void TransHalDeviceConfig(WifiHalDeviceConfig &halDeviceConfig, const WifiDeviceConfig &config) const;
    void SetRandomMacConfig(WifiStoreRandomMac &randomMacInfo, const WifiDeviceConfig &deviceConfig,
    std::string &currentMac);
    bool IsGoodSignalQuality();
    void AppendFastTransitionKeyMgmt(const WifiScanInfo &scanInfo, WifiHalDeviceConfig &halDeviceConfig) const;
    void ConvertSsidToOriginalSsid(const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const;
    void TryModifyPortalAttribute(SystemNetWorkState netState);
    void ChangePortalAttribute(bool isNeedChange, WifiDeviceConfig &config);
    void UpdateHiLinkAttribute();
private:
    std::shared_mutex m_staCallbackMutex;
    std::map<std::string, StaServiceCallback> m_staCallback;
    bool m_hilinkFlag = false;
    WifiDeviceConfig m_hilinkDeviceConfig;
#ifndef OHOS_ARCH_LITE
    bool hasNoInternetDialog_ = false;
    sptr<NetManagerStandard::NetSupplierInfo> NetSupplierInfo;
    sptr<NetStateObserver> m_NetWorkState;
    IEnhanceService *enhanceService_ = nullptr;        /* EnhanceService handle */
    ISelfCureService *selfCureService_ = nullptr;
#endif

    int targetNetworkId_;
    int lastSignalLevel_;
    std::string targetRoamBssid;
    int currentTpType;
    int getIpSucNum;
    int getIpFailNum;
    bool enableSignalPoll;
    bool isRoam;
    bool isCurrentRoaming_ = false;
    int64_t lastTimestamp;
    bool portalFlag;
    PortalState portalState;
    int detectNum;
    int portalExpiredDetectCount;
    bool mIsWifiInternetCHRFlag;
    bool networkStatusHistoryInserted;
    WifiLinkedInfo linkedInfo;
    DhcpResultNotify *pDhcpResultNotify;
    ClientCallBack dhcpclientCallBack_;
    DhcpClientReport dhcpClientReport_;
    InitState *pInitState;
    LinkState *pLinkState;
    SeparatedState *pSeparatedState;
    ApLinkingState *pApLinkingState;
    ApLinkedState *pApLinkedState;
    GetIpState *pGetIpState;
    LinkedState *pLinkedState;
    ApRoamingState *pApRoamingState;
    int m_instId;
    std::map<std::string, time_t> wpa3BlackMap;
    std::map<std::string, int> wpa3ConnectFailCountMapArray[WPA3_FAIL_REASON_MAX];
    std::string mPortalUrl;
    int mLastConnectNetId;      /* last request connect netword id */
    int mConnectFailedCnt;      /* mLastConnectNetId connect failed count */
};
}  // namespace Wifi
}  // namespace OHOS
#endif
