/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "wifi_internal_msg.h"
#include "wifi_log.h"
#include "wifi_settings.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "state_machine.h"
#include "wifi_sta_hal_interface.h"
#include "sta_dhcp_server.h"
#include "sta_network_speed.h"
#include "sta_network_check.h"
#include "sta_define.h"

namespace OHOS {
namespace Wifi {
static const int STA_CONNECT_MODE = 1;
static const int STA_SCAN_ONLY_MODE = 2;
static const int STA_CAN_ONLY_WITH_WIFI_OFF_MODE = 3;
static const int STA_DISABLED_MODE = 4;
static const int CMD_START_WIFI_SUCCESS = 0x01;
static const int CMD_STOP_WIFI_SUCCESS = 0x02;
static const int CMD_CONNECT_NETWORK = 0x03;
static const int CMD_START_CONNECT_SELECTED_NETWORK = 0x04;
static const int CMD_DISCONNECT_NETWORK = 0X05;
static const int CMD_SYNC_LINKINFO = 0X06;
static const int CMD_GET_NETWORK_SPEED = 0X07;
static const int STA_NETWORK_SPEED_DELAY = 1 * 1000;
static const int CMD_NETWORK_CONNECT_TIMEOUT = 0X08;
static const int STA_NETWORK_CONNECTTING_DELAY = 60 * 1000;
static const int PIN_CODE_LEN = 8; /* pincode length */

/*
 * During the WPS PIN connection, the WPA_SUPPLICANT blocklist is cleared every 10 seconds
 * until the network connection is successful.
 */
static const int BLOCK_LIST_CLEAR_TIMER = 20 * 1000;

/* Signal levels are classified into: 0 1 2 3 4 ,the max is 4. */
static const int MAX_LEVEL = 4;
const std::string WPA_BSSID_ANY = "any";

class StaStateMachine : public StateMachine {
public:
    StaStateMachine();
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
        explicit InitState(StaStateMachine *pStaStateMachine);
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
        explicit WpaStartingState(StaStateMachine *pStaStateMachine);
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
        explicit WpaStartedState(StaStateMachine *pStaStateMachine);
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
        explicit WpaStoppingState(StaStateMachine *pStaStateMachine);
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
        explicit LinkState(StaStateMachine *pStaStateMachine);
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
        explicit SeparatedState(StaStateMachine *pStaStateMachine);
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
        explicit ApLinkedState(StaStateMachine *pStaStateMachine);
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
        explicit StaWpsState(StaStateMachine *pStaStateMachine);
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
        explicit GetIpState(StaStateMachine *pStaStateMachine);
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
        explicit LinkedState();
        ~LinkedState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;
    };
    /**
     * @Description  Definition of member function of ApRoamingState class in StaStateMachine.
     *
     */
    class ApRoamingState : public State {
    public:
        explicit ApRoamingState(StaStateMachine *pStaStateMachine);
        ~ApRoamingState() override;
        void GoInState() override;
        void GoOutState() override;
        bool ExecuteStateMsg(InternalMessage *msg) override;

    private:
        StaStateMachine *pStaStateMachine;
    };

public:
    /**
     * @Description  Initialize StaStateMachine
     *
     * @Return:  WIFI_OPT_SUCCESS - success  WIFI_OPT_FAILED - failed
     */
    ErrCode InitStaStateMachine();
    /**
     * @Description  Sets response queue with input queue
     *
     * @param pMsgQueueUp - response message information queue(in)
     */
    void SetResponseQueue(WifiMessageQueue<WifiResponseMsgInfo> *pMsgQueueUp);
    /**
     * @Description  Notify operating result to InterfaceService.
     *
     * @param msgCode - operating results code.(in)
     */
    void NotifyResult(int msgCode, int stateCode = 0);
    /**
     * @Description  Start roaming connection.
     *
     * @param bssid - the mac address of network(in)
     */
    void StartRoamToNetwork(std::string bssid);
    /**
     * @Description  Connecting events
     *
     * @param networkId - the networkId of network which is going to be connected(in)
     * @param bssid - bssid - the mac address of wifi(in)
     */
    void OnNetworkConnectionEvent(int networkId, std::string bssid);
    /**
     * @Description  Synchronize the linked information
     *
     * @param scanInfos - the results obtaining by scanning(in)
     */
    void SyncLinkInfo(const std::vector<WifiScanInfo> &scanInfos);
    /**
     * @Description  Set country code
     *
     */
    void SetCountryCode();

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
     * @Description  Translate frequency to band(2.4G or 5G).
     *
     * @param freQuency -the frequency needed to be translted into band.(in)
     */
    void GetBandFromFreQuencies(const int &freQuency);

    /**
     * @Description  Remove network configuration.
     *
     * @param msg -Internal message(in)
     */
    void RemoveDeviceConfigProcess(const InternalMessage *msg);
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
     * @param networkId - the networkId of selected network which is going to be connected(in)
     * @param bssid - the mac address of wifi(in)
     */
    void ConnectToNetworkProcess(InternalMessage *msg);

    /**
     * @Description  Start to connect to network.
     *
     * @param networkId - the networkId of network which is going to be connected.(in)
     */
    void StartConnectToNetwork(int networkId);
    /**
     * @Description  Disable network
     *
     * @param networkId - the networkId of network which is going to be disabled.(in)
     */
    void DisableNetwork(int networkId);
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
    void SetPowerSave(bool enabled);
    /**
     * @Description  Configure static ipaddress.
     *
     * @param staticIpAddress- static ip address(in)
     */
    bool ConfigStaticIpAddress(StaticIpAddress &staticIpAddress);
    int PortalHttpDetection();
    /**
     * @Description  Processing obtaining result of ip from dhcp.
     *
     * @param dhcpResult - the results needed to handle from dhcp(in)
     */
    void HandleDhcpResult(const DhcpResult &dhcpResult);
    /**
     * @Description  the process of handling network check results.
     *
     * @param netState - the state of connecting network(in)
     */
    void HandleNetCheckResult(StaNetState netState);
    /**
     * @Description  Remove all device configurations before enabling WPS.
     *
     */
    void RemoveAllDeviceConfigs();
    /**
     * @Description  Synchronize all networks saved in the configuration center to the WPA.
     *
     */
    void SyncAllDeviceConfigs();

    /**
     * @Description  Initialize the connection state processing message map
     *
     */
    int InitStaSMHandleMap();
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
    void DealWpaWrongPskEvent(InternalMessage *msg);
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
     * @Description  Synchronous Encryption Mode Aand Band
     *
     * @param mgmt - Encryption Mode[in]
     */
    void SynchronousEncryptionModeAandBand(std::string mgmt);
    /**
     * @Description  Set Wep Encryption Mode Index
     *
     * @param config - A Network[in]
     */
    void WepEncryptionModeIndex(WifiDeviceConfig &config);

    bool SetRandomMac(const int networkId);
    void MacAddressGenerate(std::string &strMac);
    int CheckMacFormat(const std::string &mac);

private:
    StaSmHandleFuncMap staSmHandleFuncMap;

    int statusId;
    int lastNetworkId;
    int operationalMode;
    int targetNetworkId;
    int pinCode;
    SetupMethod wpsState;
    int lastConnectToNetworkTimer; /* Time stamp of the last attempt to connect to
                                    * the network.
                                    */
    std::string targetRoamBssid;
    int currentTpType;
    IsWpsConnected isWpsConnect;
    WifiLinkedInfo linkedInfo;
    WifiLinkedInfo lastLinkedInfo;
    StaDhcpServer *pDhcpServer;
    StaNetWorkSpeed *pNetSpeed;
    StaNetworkCheck *pNetcheck;
    WifiMessageQueue<WifiResponseMsgInfo> *msgQueueUp; /* Uplink message queue. */

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
};
}  // namespace Wifi
}  // namespace OHOS
#endif
