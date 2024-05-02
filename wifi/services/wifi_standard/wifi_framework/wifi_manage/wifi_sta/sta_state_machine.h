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
#include "wifi_idl_struct.h"

#ifndef OHOS_ARCH_LITE
#include "want.h"
#include "wifi_net_agent.h"
#include "wifi_net_observer.h"
#include "sim_state_type.h"
#include "core_service_client.h"
#include "cellular_data_client.h"
#include "core_manager_inner.h"
#include "telephony_errors.h"
#endif

namespace OHOS {
namespace Wifi {
#ifndef OHOS_ARCH_LITE
using namespace OHOS::Telephony;
#endif
constexpr int STA_CONNECT_MODE = 1;
constexpr int STA_SCAN_ONLY_MODE = 2;
constexpr int STA_CAN_ONLY_WITH_WIFI_OFF_MODE = 3;
constexpr int STA_DISABLED_MODE = 4;
constexpr int STA_RENEWAL_MIN_TIME = 120;
constexpr int STREAM_TXPACKET_THRESHOLD = 0;
constexpr int STREAM_RXPACKET_THRESHOLD = 0;
constexpr int STA_AP_ROAMING_TIMEOUT = 15000; // 15s->15000 ms

constexpr int CMD_NETWORK_CONNECT_TIMEOUT = 0X01;
constexpr int CMD_SIGNAL_POLL = 0X02;
constexpr int CMD_START_NETCHECK = 0X03;
constexpr int CMD_START_GET_DHCP_IP_TIMEOUT = 0X04;
constexpr int CMD_START_RENEWAL_TIMEOUT = 0X05;
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

/*
 * During the WPS PIN connection, the WPA_SUPPLICANT blocklist is cleared every 10 seconds
 * until the network connection is successful.
 */
constexpr int BLOCK_LIST_CLEAR_TIMER = 20 * 1000;

/* Wpa3 selfcure failreason num*/
constexpr int WLAN_STATUS_AUTH_TIMEOUT = 16;
constexpr int MAC_AUTH_RSP2_TIMEOUT = 5201;
constexpr int MAC_AUTH_RSP4_TIMEOUT = 5202;
constexpr int MAC_ASSOC_RSP_TIMEOUT = 5203;
constexpr int DHCP_RENEW_FAILED = 4;
constexpr int DHCP_RENEW_TIMEOUT = 5;

enum Wpa3ConnectFailReason {
    WPA3_AUTH_TIMEOUT,
    WPA3_ASSOC_TIMEOUT,
    WPA3_FAIL_REASON_MAX
};

const std::map<int, int> wpa3FailreasonMap {
    {WLAN_STATUS_AUTH_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_AUTH_RSP2_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_AUTH_RSP4_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_ASSOC_RSP_TIMEOUT, WPA3_ASSOC_TIMEOUT}
};

typedef enum EnumDhcpReturnCode {
    DHCP_RESULT,
    DHCP_JUMP,
    DHCP_RENEW_FAIL,
    DHCP_FAIL,
} DhcpReturnCode;

/* Signal levels are classified into: 0 1 2 3 4 ,the max is 4. */
constexpr int MAX_LEVEL = 4;
const std::string WPA_BSSID_ANY = "any";

class StaStateMachine : public StateMachine {
    FRIEND_GTEST(StaStateMachine);
public:
    explicit StaStateMachine(int instId = 0);
    ~StaStateMachine();
    using staSmHandleFunc = void (StaStateMachine::*)(InternalMessage *msg);
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
        bool ExecuteStateMsg(InternalMessage *msg) override;
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description : Definition of member function of WpaStartingState class in StaStateMachine.
     *
     */
    class WpaStartingState : public State {
    public:
        explicit WpaStartingState(StaStateMachine *staStateMachine);
        ~WpaStartingState() override;
        void InitWpsSettings();
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of WpaStartedState class in StaStateMachine.
     *
     */
    class WpaStartedState : public State {
    public:
        explicit WpaStartedState(StaStateMachine *staStateMachine);
        ~WpaStartedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of WpaStoppingState class in StaStateMachine.
     *
     */
    class WpaStoppingState : public State {
    public:
        explicit WpaStoppingState(StaStateMachine *staStateMachine);
        ~WpaStoppingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of SeparatingState class in StaStateMachine.
     *
     */
    class SeparatingState : public State {
    public:
        explicit SeparatingState();
        ~SeparatingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };
    /**
     * @Description  Definition of member function of WpsState class in StaStateMachine.
     *
     */
    class StaWpsState : public State {
    public:
        explicit StaWpsState(StaStateMachine *staStateMachine);
        ~StaWpsState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
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
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };

    class DhcpResultNotify {
    public:
        /**
         * @Description : Construct a new dhcp result notify object
         *
         */
        explicit DhcpResultNotify();

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
         * @Description : deal dhcp result
         *
         */
        void DealDhcpResult(int ipType);
#ifndef OHOS_ARCH_LITE
        /**
         * @Description : start renew timeout timer
         *
         */
        void StartRenewTimeout(int64_t interval);

        /**
         * @Description : stop renew timeout timer
         *
         */
        static void StopRenewTimeout();

        /**
         * @Description : deal renew timeout
         *
         */
        static void DealRenewTimeout();
#endif
        /**
         * @Description : Get dhcp result of specified interface failed notify asynchronously
         *
         * @param status - int
         * @param ifname - interface name,eg:wlan0
         * @param reason - failed reason
         */
        static void OnFailed(int status, const char *ifname, const char *reason);
        /**
         * @Description : deal dhcp result failed
         *
         */
        void DealDhcpResultFailed();
        static void SetStaStateMachine(StaStateMachine *staStateMachine);
        static void TryToSaveIpV4Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result);
        static void TryToSaveIpV4ResultExt(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result);
        static void TryToSaveIpV6Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result);
        static void TryToCloseDhcpClient(int iptype);
        static void SaveDhcpResult(DhcpResult *dest, DhcpResult *source);
        static void SaveDhcpResultExt(DhcpResult *dest, DhcpResult *source);
    private:
        static StaStateMachine *pStaStateMachine;
        static DhcpResult DhcpIpv4Result;
        static DhcpResult DhcpIpv6Result;
#ifndef OHOS_ARCH_LITE
        static uint64_t renewTimerId_;
#endif
    };

public:
    /**
     * @Description  Register dhcp client CallBack
     *
     * @Return:  DHCP_OPT_SUCCESS - success  DHCP_OPT_FAILED - failed
     */
    int RegisterCallBack();

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
     * @Description  if it is roaming now.
     */
    bool IsRoaming(void);
    /**
     * @Description  Connecting events
     *
     * @param networkId - the networkId of network which is going to be connected(in)
     * @param bssid - bssid - the mac address of wifi(in)
     */
    void OnNetworkConnectionEvent(int networkId, std::string bssid);
    /**
     * @Description  Disconnect events
     *
     * @param reason - the reason of wifi disconnection
     */
    void OnNetworkDisconnectEvent(int reason);
    /**
     * @Description  sta chr events
     *
     * @param state - the state of wifi sta
     */
    void OnNetworkHiviewEvent(int state);
    /**
     * @Description  Assoc events
     *
     * @param reason - the state of wifi assoc
     */
    void OnNetworkAssocEvent(int assocState, std::string bssid, StaStateMachine *pStaStateMachine);
    /**
     * @Description  Bssid change events
     *
     * @param reason: the reason of bssid changed(in)
     * @param bssid: the mac address of wifi(in)
     */
    void OnBssidChangedEvent(std::string reason, std::string bssid);
    /**
     * @Description  dhcp result notify events
     *
     * @param result: true-success, false-fail(in)
     */
    void OnDhcpResultNotifyEvent(DhcpReturnCode result, int ipType = -1);
    /**
     * @Description Register sta callback function
     *
     * @param callback - Callback function pointer storage structure
     */
    void RegisterStaServiceCallback(const StaServiceCallback &callback);

    /**
     * @Description  Convert the deviceConfig structure and set it to idl structure
     *
     * @param config -The Network info(in)
     * @param idlConfig -The Network info(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode FillEapCfg(const WifiDeviceConfig &config, WifiIdlDeviceConfig &idlConfig) const;

    /**
     * @Description  Convert the deviceConfig structure and set it to wpa_supplicant
     *
     * @param config -The Network info(in)
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode ConvertDeviceCfg(const WifiDeviceConfig &config) const;

    /**
     * @Description Get linked info.
     *
     * @param linkedInfo - linked info
     * @return int - operation result
     */
    int GetLinkedInfo(WifiLinkedInfo& linkedInfo);

    /**
     * @Description Reupdate net link info
     */
    void ReUpdateNetLinkInfo(const WifiDeviceConfig &config);

    /**
     * @Description On netmanager restart.
     */
    void OnNetManagerRestart(void);

     /**
     * @Description start dhcp renewal.
     *
     */
    void StartDhcpRenewal();

    /**
     * @Description : Deal renewal timeout.
     *
     */
    void DealRenewalTimeout(InternalMessage *msg);

    /**
     * @Description  start browser to login portal
     *
     */
    void HandlePortalNetworkPorcess();
    
    void SetPortalBrowserFlag(bool flag);
    /**
     * @Description renew dhcp.
     *
     */
    void RenewDhcp();
    int GetInstanceId();
    void DealApRoamingStateTimeout(InternalMessage *msg);
    void DealHiLinkDataToWpa(InternalMessage *msg);
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
     * @Description  The process of initializing the last connected wifi information.
     *
     */
    void InitLastWifiLinkedInfo();
    /**
     * @Description  Setting linkedInfo in case of when wpa connects
                     automatically there isn't any connection information.
     *
     * @param networkId - the nerworkId of network which is saved in the WifiLinkedInfo.(in)
     */
    void SetWifiLinkedInfo(int networkId);

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
     * @Description  Translate frequency to band(2.4G or 5G).
     *
     * @param freQuency -the frequency needed to be translted into band.(in)
     */
    void GetBandFromFreQuencies(const int &freQuency);

    /**
     * @Description  Processing after a success response is returned after Wi-Fi
                     is enabled successfully, such as setting the MAC address and
                     saving the connection information.
     *
     */
    void StartWifiProcess();

    /**
     * @Description  Update wifi status and save connection information.
     *
     * @param bssid - the mac address of wifi(in)
     */
    void ConnectToNetworkProcess(std::string bssid);

    /**
     * @Description On connect fail.
     *
     * @param networkId - the networkId of network which is going to be connected.(in)
     */
    void OnConnectFailed(int networkId);

    /**
     * @Description  Start to connect to network.
     *
     * @param networkId - the networkId of network which is going to be connected.(in)
     * @param bssid - the bssid of network which is going to be connected.
     * @Return success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
     */
    ErrCode StartConnectToNetwork(int networkId, const std::string &bssid);
 
    /**
     * @Description  Disconnect network
     *
     */
    void DisConnectProcess();

    /**
     * @Description  Disable wifi process.
     *
     */
    void StopWifiProcess();

    /**
     * @Description  Setting statemachine status during the process of enable or disable wifi.
     *
     * @param mode - operating mode(in)
     */
    void SetOperationalMode(int mode);
    void SetSuspendMode(bool enabled);
    void SetPowerMode(bool mode);
    void SetPowerSave(bool enabled);

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
     * @Description implementation of the network detection callback function
     *
     * @param netState the state of connecting network
     * @param url portal network redirection address
     */
    void NetStateObserverCallback(SystemNetWorkState netState, std::string url);

    /**
     * @Description  the process of handling arp check results.
     *
     * @param arpState - the state of arp proto(in)
     */
    void HandleArpCheckResult(StaArpState arpState);

    /**
     * @Description  the process of handling network check results.
     *
     * @param dnsState - the state of dns protol(in)
     */
    void HandleDnsCheckResult(StaDnsState dnsState);

    /**
     * @Description  notification portal network.
     *
     */
    void PublishPortalNetworkNotification();

    /**
     * @Description  Remove all device configurations before enabling WPS.
     *
     */
    void RemoveAllDeviceConfigs();

    /**
     * @Description  Initialize the connection state processing message map
     *
     */
    int InitStaSMHandleMap();

    /**
     * @Description : Deal SignalPoll Result.
     *
     * @param  msg - Message body received by the state machine[in]
     */
    void DealSignalPollResult(InternalMessage *msg);

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
    void DealConnectToSelectedNetCmd(InternalMessage *msg);

    /**
     * @Description : Ready to connect to the network selected by user.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealConnectToUserSelectedNetwork(InternalMessage *msg);

    /**
     * @Description  Operations after the disconnection Event is reported.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealDisconnectEvent(InternalMessage *msg);

    /**
     * @Description  Operations after the Connection Event is reported.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealConnectionEvent(InternalMessage *msg);

    /**
     * @Description  Operations after Disable specified network commands.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealConnectTimeOutCmd(InternalMessage *msg);

    /**
     * @Description  Operations after Clear blocklist is reported.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealWpaBlockListClearEvent(InternalMessage *msg);

    /**
     * @Description  Operations after StartWps commands.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealStartWpsCmd(InternalMessage *msg);

    /**
     * @Description  Operations after the Wps Connect TimeOut Event is reported.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealWpsConnectTimeOutEvent(InternalMessage *msg);

    /**
     * @Description  Cancel wps connection
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealCancelWpsCmd(InternalMessage *msg);

    /**
     * @Description  Reconnect network
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealReConnectCmd(InternalMessage *msg);

    /**
     * @Description  Operations after the Reassociate lead is issued
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealReassociateCmd(InternalMessage *msg);

    /**
     * @Description  Roaming connection.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealStartRoamCmd(InternalMessage *msg);

    /**
     * @Description  Operation after the password error is reported
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealWpaLinkFailEvent(InternalMessage *msg);

    /**
     * @Description  try to connect the saved network for three times
     *@Return true: try to reconnect  fail: try max
     */
    bool DealReconnectSavedNetwork();

    /**
     * @Description  set sta connect failed count
     *@Return void
     */
    void DealSetStaConnectFailedCount(int count, bool set);

    /**
     * @Description  Wps mode is ON
     *
     * @param msg - Message body received by the state machine[in]
     */
    void StartWpsMode(InternalMessage *msg);

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
     * @Description  check whether the current bssid are consistent.
     *
     * @param bssid - bssid
     */
    bool CheckRoamingBssidIsSame(std::string bssid);

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
     * @Description : Deal network check cmd.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealNetworkCheck(InternalMessage *msg);

    /**
     * @Description : Deal get dhcp ip timeout.
     *
     * @param msg - Message body received by the state machine[in]
     */
    void DealGetDhcpIpTimeout(InternalMessage *msg);

    /**
     * @Description : is wpa3 transition mode.
     *
     * @param ssid - ssid
     */
    bool IsWpa3Transition(std::string ssid) const;

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
    void DealScreenStateChangedEvent(InternalMessage *msg);

    /**
     * @Description set external sim
     *
     * @param ifName - port name(in)
     * @param eap - eap method(in)
     * @Return success: 0  fail: others
     */
    ErrCode SetExternalSim(const std::string ifName, const std::string &eap, int value) const;

    /**
     * @Description : Check Current DisConnect event is should retry.
     *
     * @param eventName - eventName.
     * @Return true: need retry.
     */
    bool IsStaDisConnectReasonShouldRetryEvent(int eventName);

    /**
     * @Description : Check wpa report DisConnect reason is should stoptimer.
     *
     * @param reason - reason.
     * @Return true: need stop timer.
     */
    bool IsDisConnectReasonShouldStopTimer(int reason);

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

#ifndef OHOS_ARCH_LITE
    /**
     * @Description Get slot id.
     * @Return int32_t - 0:success, other value:failed
     */
    int32_t GetDataSlotId();

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
    void DealWpaEapSimAuthEvent(InternalMessage *msg);

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
    void DealWpaEapUmtsAuthEvent(InternalMessage *msg);

    /**
     * @Description Get the SIM card ID.
     *
     */
    int32_t GetSimId();

    /**
     * @Description Set the SIM card ID.
     *
     * @param id - Sim card id
     */
    void SetSimId(int32_t simId);

    /**
     * @Description Subscribe system ability changed.
     */
    void SubscribeSystemAbilityChanged(void);
    /**
     * @Description Reupdate net supplier info
     */
    void ReUpdateNetSupplierInfo(sptr<NetManagerStandard::NetSupplierInfo> supplierInfo);

    /**
     * @Description save wificonfig for update mode.
     *
     * @param networkId - current connected networkId;
     */
    void SaveWifiConfigForUpdate(int networkId);
#endif // OHOS_ARCH_LITE

private:
    StaSmHandleFuncMap staSmHandleFuncMap;
    std::shared_mutex m_staCallbackMutex;
    std::map<std::string, StaServiceCallback> m_staCallback;
#ifndef OHOS_ARCH_LITE
    sptr<NetManagerStandard::NetSupplierInfo> NetSupplierInfo;
    sptr<NetStateObserver> m_NetWorkState;
#endif

    int lastNetworkId;
    int operationalMode;
    int targetNetworkId;
    int pinCode;
    SetupMethod wpsState;
    int lastSignalLevel;
    std::string targetRoamBssid;
    int currentTpType;
    IsWpsConnected isWpsConnect;
    int getIpSucNum;
    int getIpFailNum;
    bool enableSignalPoll;
    bool isRoam;
    int64_t lastTimestamp;
    bool portalFlag;
    bool networkStatusHistoryInserted;
    WifiLinkedInfo linkedInfo;
    WifiLinkedInfo lastLinkedInfo;
    DhcpResultNotify *pDhcpResultNotify;
    ClientCallBack clientCallBack;
    WifiPortalConf mUrlInfo;
    RootState *pRootState;
    InitState *pInitState;
    WpaStartingState *pWpaStartingState; /* Starting wpa_supplicant state. */
    WpaStartedState *pWpaStartedState;   /* Started wpa_supplicant state. */
    WpaStoppingState *pWpaStoppingState; /* Stopping wpa_supplicant state. */
    LinkState *pLinkState;
    SeparatingState *pSeparatingState;
    SeparatedState *pSeparatedState;
    ApLinkedState *pApLinkedState;
    StaWpsState *pWpsState;
    GetIpState *pGetIpState;
    LinkedState *pLinkedState;
    ApRoamingState *pApRoamingState;
    int m_instId;
    std::map<std::string, time_t> wpa3BlackMap;
    std::map<std::string, int> wpa3ConnectFailCountMapArray[WPA3_FAIL_REASON_MAX];
    std::string mPortalUrl;
    int mLastConnectNetId;      /* last request connect netword id */
    int mConnectFailedCnt;      /* mLastConnectNetId connect failed count */
    /**
     * @Description Replace empty dns
     */
    void ReplaceEmptyDns(DhcpResult *result);
    void InvokeOnStaOpenRes(OperateResState state);
    void InvokeOnStaCloseRes(OperateResState state);
    void InvokeOnStaConnChanged(OperateResState state, const WifiLinkedInfo &info);
    void InvokeOnWpsChanged(WpsStartState state, const int code);
    void InvokeOnStaStreamChanged(StreamDirection direction);
    void InvokeOnStaRssiLevelChanged(int level);
    WifiDeviceConfig getCurrentWifiDeviceConfig();
    void InsertOrUpdateNetworkStatusHistory(const NetworkStatus &networkStatus);
    bool CanArpReachable();
    ErrCode ConfigRandMacSelfCure(const int networkId);
#ifndef OHOS_ARCH_LITE
    int32_t StaStartAbility(OHOS::AAFwk::Want& want);
    void ShowPortalNitification();
#endif
    void SetConnectMethod(int connectMethod);
};
}  // namespace Wifi
}  // namespace OHOS
#endif
