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

#include <cstdio>
#include <chrono>
#include <random>
#include "sta_state_machine.h"
#include "if_config.h"
#include "ip_tools.h"
#include "mac_address.h"
#include "sta_monitor.h"
#include "wifi_battery_utils.h"
#include "wifi_common_util.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_protect_manager.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_hisysevent.h"
#include "wifi_config_center.h"
#include "wifi_chr_adapter.h"
#include "block_connect_service.h"
#include "wifi_randommac_helper.h"
#include "define.h"
#include "wifi_code_convert.h"
#ifndef OHOS_ARCH_LITE
#include <dlfcn.h>
#include "securec.h"
#include "wifi_app_state_aware.h"
#include "wifi_net_observer.h"
#include "wifi_system_timer.h"
#include "netsys_controller.h"
#ifdef WIFI_CONFIG_UPDATE
#include "wifi_config_update.h"
#endif
#ifdef WIFI_SECURITY_DETECT_ENABLE
#include "wifi_security_detect.h"
#endif
#include "wifi_notification_util.h"
#include "wifi_net_stats_manager.h"
#include "wifi_history_record_manager.h"
#endif // OHOS_ARCH_LITE

#include "wifi_channel_helper.h"
#ifndef OHOS_WIFI_STA_TEST
#else
#include "mock_dhcp_service.h"
#endif
#include "sta_define.h"
#include "ip_qos_monitor.h"
#include "wifi_country_code_manager.h"
#include "wifi_telephony_utils.h"
#include "network_interface.h"
#include "self_cure_utils.h"
#include "wifi_enhance_defs.h"

namespace OHOS {
namespace Wifi {
namespace {
constexpr const char* WIFI_IS_CONNECT_FROM_USER = "persist.wifi.is_connect_from_user";
constexpr int MAX_CHLOAD = 800;
}
DEFINE_WIFILOG_LABEL("StaStateMachine");
#define ANY_BSSID "any"
#define PORTAL_ACTION "ohos.want.action.awc"
#define PORTAL_ENTITY "entity.browser.hbct"
#define PORTAL_CHECK_TIME (10 * 60)
#define PORTAL_AUTH_EXPIRED_CHECK_TIME (2)
#define PORTAL_MILLSECOND 1000
#define WPA3_BLACKMAP_MAX_NUM 20
#define WPA3_BLACKMAP_RSSI_THRESHOLD (-70)
#define WPA3_CONNECT_FAIL_COUNT_THRESHOLD 2
#define TRANSFORMATION_TO_MBPS 10
#define DEFAULT_NUM_ARP_PINGS 3
#define MAX_ARP_CHECK_TIME 300
#define NETWORK 1
#define NO_NETWORK 0
#define DISCONNECTED_NETWORK 2
#define CONNECTED_NETWORK 3
#define WPA_DEFAULT_NETWORKID 0
#define SELF_CURE_FAC_MAC_REASSOC 2
#define SELF_CURE_RAND_MAC_REASSOC 3
#define USER_CONNECT "1"
#define AUTO_CONNECT "0"

#define CMD_BUFFER_SIZE 1024
#define GSM_AUTH_RAND_LEN 16
#define GSM_AUTH_CHALLENGE_SRES_LEN 4
#define GSM_AUTH_CHALLENGE_KC_LEN 8

#define MAX_SRES_STR_LEN (2 * GSM_AUTH_CHALLENGE_SRES_LEN)
#define MAX_KC_STR_LEN (2 * GSM_AUTH_CHALLENGE_KC_LEN)

#define UMTS_AUTH_TYPE_TAG 0xdb
#define UMTS_AUTS_TYPE_TAG 0xdc

#define UMTS_AUTH_CHALLENGE_RESULT_INDEX 0
#define UMTS_AUTH_CHALLENGE_DATA_START_IDNEX 1

#define UMTS_AUTH_CHALLENGE_RAND_LEN 16
#define UMTS_AUTH_CHALLENGE_AUTN_LEN 16
#define UMTS_AUTH_CHALLENGE_RES_LEN 8
#define UMTS_AUTH_CHALLENGE_CK_LEN 16
#define UMTS_AUTH_CHALLENGE_IK_LEN 16
#define UMTS_AUTH_CHALLENGE_AUTS_LEN 16

#define UMTS_AUTH_REQUEST_CONTENT_LEN (UMTS_AUTH_CHALLENGE_RAND_LEN + UMTS_AUTH_CHALLENGE_AUTN_LEN + 2)

// res[9] + ck[17] + ik[17] + unknown[9]
#define UMTS_AUTH_RESPONSE_CONENT_LEN 52

#define MAX_RES_STR_LEN (2 * UMTS_AUTH_CHALLENGE_RES_LEN)
#define MAX_CK_STR_LEN (2 * UMTS_AUTH_CHALLENGE_CK_LEN)
#define MAX_IK_STR_LEN (2 * UMTS_AUTH_CHALLENGE_IK_LEN)
#define MAX_RAND_STR_LEN (2 * UMTS_AUTH_CHALLENGE_RAND_LEN)
#define MAX_AUTN_STR_LEN (2 * UMTS_AUTH_CHALLENGE_AUTN_LEN)

constexpr int32_t MAX_NO_INTERNET_CNT = 3;
constexpr uint32_t PKT_DIR_RPT_CNT = 3;

const std::map<int, int> wpa3FailreasonMap {
    {WLAN_STATUS_AUTH_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_AUTH_RSP2_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_AUTH_RSP4_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_ASSOC_RSP_TIMEOUT, WPA3_ASSOC_TIMEOUT}
};

const std::map<int, int> portalEventValues = {
    {PortalState::NOT_PORTAL, HISYS_EVENT_PROTAL_STATE_NOT_PORTAL},
    {PortalState::UNAUTHED, HISYS_EVENT_PROTAL_STATE_PORTAL_UNVERIFIED},
    {PortalState::AUTHED, HISYS_EVENT_PROTAL_STATE_PORTAL_VERIFIED},
    {PortalState::EXPERIED, HISYS_EVENT_PROTAL_STATE_PORTAL_UNVERIFIED}
};

const std::vector<Wifi80211ReasonCode> g_fastReconnectWlanReasons = {
    Wifi80211ReasonCode::WLAN_REASON_UNSPECIFIED,
    Wifi80211ReasonCode::WLAN_REASON_PREV_AUTH_NOT_VALID,
    Wifi80211ReasonCode::WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA,
    Wifi80211ReasonCode::WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA,
    Wifi80211ReasonCode::WLAN_REASON_DISASSOC_LOW_ACK,
};

constexpr int32_t FAST_RECONNECT_INTERVAL_MIN = 10;
constexpr int32_t FAST_RECONNECT_INTERVAL_MAX = 60;
constexpr int32_t FAST_RECONNECT_DELAY_TIME_US = 100 * 1000;

StaStateMachine::StaStateMachine(int instId)
    : StateMachine("StaStateMachine"),
      targetNetworkId_(INVALID_NETWORK_ID),
      lastSignalLevel_(INVALID_SIGNAL_LEVEL), targetRoamBssid(WPA_BSSID_ANY), currentTpType(IPTYPE_IPV4),
      enableSignalPoll(true), isRoam(false),
      lastTimestamp(0), autoPullBrowserFlag(true), portalState(PortalState::UNCHECKED), detectNum(0),
      portalExpiredDetectCount(0), mIsWifiInternetCHRFlag(false), networkStatusHistoryInserted(false),
      pDhcpResultNotify(nullptr), pClosedState(nullptr), pInitState(nullptr),
      pLinkState(nullptr), pSeparatedState(nullptr), pApLinkingState(nullptr),
      pApLinkedState(nullptr), pGetIpState(nullptr),
      pLinkedState(nullptr), pApRoamingState(nullptr), mLastConnectNetId(INVALID_NETWORK_ID),
      mConnectFailedCnt(0)
{
    m_instId = instId;
}

StaStateMachine::~StaStateMachine()
{
    WIFI_LOGI("~StaStateMachine");
    StopHandlerThread();
    ParsePointer(pClosedState);
    ParsePointer(pInitState);
    ParsePointer(pLinkState);
    ParsePointer(pSeparatedState);
    ParsePointer(pApLinkingState);
    ParsePointer(pApLinkedState);
    ParsePointer(pGetIpState);
    ParsePointer(pLinkedState);
    ParsePointer(pApRoamingState);
    ParsePointer(pDhcpResultNotify);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    ParsePointer(wifiDataReportService_);
#endif
#endif
    {
        std::unique_lock<std::shared_mutex> lock(m_staCallbackMutex);
        m_staCallback.clear();
    }
}

/* ---------------------------Initialization functions------------------------------ */
ErrCode StaStateMachine::InitStaStateMachine()
{
    WIFI_LOGI("Enter InitStateMachine m_instId = %{public}d", m_instId);
    if (!InitialStateMachine("StaStateMachine")) {
        WIFI_LOGE("Initial StateMachine failed m_instId = %{public}d", m_instId);
        return WIFI_OPT_FAILED;
    }

    if (InitStaStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pClosedState);
    StartStateMachine();

#ifndef OHOS_ARCH_LITE
    NetSupplierInfo = std::make_unique<NetManagerStandard::NetSupplierInfo>().release();
    m_NetWorkState = sptr<NetStateObserver>(new NetStateObserver());
    if (m_NetWorkState == nullptr) {
        WIFI_LOGE("%{public}s m_NetWorkState is null", __func__);
        return WIFI_OPT_FAILED;
    }
    m_NetWorkState->SetNetStateCallback(
        [this](SystemNetWorkState netState, std::string url) { this->NetStateObserverCallback(netState, url); });
#ifdef EXTENSIBLE_AUTHENTICATION
    NetEapObserver::GetInstance().SetRegisterCustomEapCallback(
        [this](const std::string &regCmd) { this->RegisterCustomEapCallback(regCmd); });
    NetEapObserver::GetInstance().SetReplyCustomEapDataCallback(
        [this](int result, const std::string &strEapData) { this->ReplyCustomEapDataCallback(result, strEapData); });
#endif
#ifdef DYNAMIC_ADJUST_WIFI_POWER_SAVE
    bool isCharged = BatteryUtils::GetInstance().IsChargedPlugIn();
    WifiConfigCenter::GetInstance().SetNoChargerPlugModeState(isCharged ? MODE_STATE_CLOSE : MODE_STATE_OPEN);
#endif
#endif

    return WIFI_OPT_SUCCESS;
}

ErrCode StaStateMachine::InitStaStates()
{
    WIFI_LOGE("Enter InitStaStates\n");
    int tmpErrNumber;
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    wifiDataReportService_ = new (std::nothrow) WifiDataReportService(this, this->m_instId);
    if (wifiDataReportService_ == nullptr) {
        WIFI_LOGE("wifiDataReportService_ new failed");
        return WIFI_OPT_FAILED;
    }
#endif
#endif
    pClosedState = new (std::nothrow) ClosedState(this);
    tmpErrNumber = JudgmentEmpty(pClosedState);
    pInitState = new (std::nothrow) InitState(this);
    tmpErrNumber = JudgmentEmpty(pInitState);
    pLinkState = new (std::nothrow) LinkState(this);
    tmpErrNumber += JudgmentEmpty(pLinkState);
    pSeparatedState = new (std::nothrow) SeparatedState(this);
    tmpErrNumber += JudgmentEmpty(pSeparatedState);
    pApLinkingState = new (std::nothrow) ApLinkingState(this);
    tmpErrNumber += JudgmentEmpty(pApLinkingState);
    pApLinkedState = new (std::nothrow) ApLinkedState(this);
    tmpErrNumber += JudgmentEmpty(pApLinkedState);
    pGetIpState = new (std::nothrow) GetIpState(this);
    tmpErrNumber += JudgmentEmpty(pGetIpState);
    pLinkedState = new (std::nothrow) LinkedState(this);
    tmpErrNumber += JudgmentEmpty(pLinkedState);
    pApRoamingState = new (std::nothrow) ApRoamingState(this);
    tmpErrNumber += JudgmentEmpty(pApRoamingState);
    pApReConnectState = new (std::nothrow) ApReconnectState(this);
    tmpErrNumber += JudgmentEmpty(pApReConnectState);
    pDhcpResultNotify = new (std::nothrow) DhcpResultNotify(this);
    tmpErrNumber += JudgmentEmpty(pDhcpResultNotify);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitStaStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::BuildStateTree()
{
    StatePlus(pClosedState, nullptr); //father state to handle enable/disable
    StatePlus(pInitState, pClosedState); //father state to handle common event
    StatePlus(pLinkState, pInitState);  //father state to handle link
    StatePlus(pSeparatedState, pInitState); //disconnect state
    StatePlus(pApLinkingState, pLinkState); //L2 connecting
    StatePlus(pApLinkedState, pLinkState); //L2 connected
    StatePlus(pGetIpState, pApLinkedState); //L3 connecting to get ip
    StatePlus(pLinkedState, pApLinkedState); //L3 connected
    StatePlus(pApRoamingState, pApLinkedState); //roaming state
    StatePlus(pApReConnectState, pApLinkedState); //reconnect state
}

void StaStateMachine::InitWifiLinkedInfo()
{
    linkedInfo.networkId = INVALID_NETWORK_ID;
    linkedInfo.ssid = "";
    linkedInfo.bssid = "";
    linkedInfo.macAddress = "";
    linkedInfo.macType = 0;
    linkedInfo.rxLinkSpeed = 0;
    linkedInfo.txLinkSpeed = 0;
    linkedInfo.rssi = 0;
    linkedInfo.band = 0;
    linkedInfo.frequency = 0;
    linkedInfo.linkSpeed = 0;
    linkedInfo.ipAddress = 0;
    linkedInfo.connState = ConnState::DISCONNECTED;
    linkedInfo.ifHiddenSSID = false;
    linkedInfo.chload = 0;
    linkedInfo.snr = 0;
    linkedInfo.isDataRestricted = 0;
    linkedInfo.platformType = "";
    linkedInfo.portalUrl = "";
    linkedInfo.supplicantState = SupplicantState::DISCONNECTED;
    linkedInfo.detailedState = DetailedState::DISCONNECTED;
    linkedInfo.wifiLinkType = WifiLinkType::DEFAULT_LINK;
    linkedInfo.channelWidth = WifiChannelWidth::WIDTH_INVALID;
    linkedInfo.lastPacketDirection = 0;
    linkedInfo.lastRxPackets = 0;
    linkedInfo.lastTxPackets = 0;
    linkedInfo.isAncoConnected = 0;
    linkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
    linkedInfo.isMloConnected = false;
    linkedInfo.isWurEnable = false;
    linkedInfo.isHiLinkNetwork = 0;
    linkedInfo.disconnTriggerMode = DisconnState::DEFAULTSTAT;
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    linkedInfo.riskType = WifiRiskType::INVALID;
#endif
    std::vector<WifiLinkedInfo> emptyMloLinkInfo;
    WifiConfigCenter::GetInstance().SaveMloLinkedInfo(emptyMloLinkInfo, m_instId);
}


/* --------------------------- state machine Init State ------------------------------ */
StaStateMachine::ClosedState::ClosedState(StaStateMachine *staStateMachine)
    : State("ClosedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::ClosedState::~ClosedState()
{}

void StaStateMachine::ClosedState::GoInState()
{
    WIFI_LOGI("ClosedState GoInState function.");
    /* Initialize Connection Information. */
    pStaStateMachine->InitWifiLinkedInfo();
    return;
}

void StaStateMachine::ClosedState::GoOutState()
{
    WIFI_LOGI("ClosedState GoOutState function.");
    return;
}

bool StaStateMachine::ClosedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("ClosedState-msgCode=%{public}d is received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->m_instId);
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_ENABLE_STA: {
            ret = EXECUTED;
            StartWifiProcess();
            break;
        }
        case WIFI_SVR_CMD_STA_DISABLE_STA:{
            ret = EXECUTED;
            StopWifiProcess();
            break;
        }
        case WIFI_SVR_CMD_STA_FOLD_STATUS_NOTIFY_EVENT: {
            ret = EXECUTED;
            SaveFoldStatus(msg);
            break;
        }
        case WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT: {
            ret = EXECUTED;
            DealScreenStateChangedEvent(msg);
            break;
        }
        case WIFI_AUDIO_STATE_CHANGED_NOTIFY_EVENT: {
            ret = EXECUTED;
            pStaStateMachine->DealAudioStateChangedEvent(msg);
            break;
        }
#ifndef OHOS_ARCH_LITE
        case WIFI_SVR_CMD_STA_FOREGROUND_APP_CHANGED_EVENT: {
            ret = EXECUTED;
            pStaStateMachine->HandleForegroundAppChangedAction(msg);
            break;
        }
#endif
        default:
            WIFI_LOGD("InitState-msgCode=%d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

#ifdef READ_MAC_FROM_OEM
ErrCode StaStateMachine::ClosedState::GetRealMacAddressFromOemInfo()
{
    WIFI_LOGI("GetStaDeviceMacAddress oeminfo enter, %{public}d", pStaStateMachine->m_instId);
    auto GetWifiOeminfoMac = []() {
        WIFI_LOGI("read mac from oem");
        std::string oemMac = "";
        int nvPhynumMacWifiNumber = 193;
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->ReadNvInfo(nvPhynumMacWifiNumber, oemMac);
        }
        return oemMac;
    };
 
    std::string realMacAddressWlan0;
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddressWlan0, INSTID_WLAN0);
    if (pStaStateMachine->m_instId == INSTID_WLAN1) {
        std::string realMacAddressWlan1;
        WifiSettings::GetInstance().GetRealMacAddress(realMacAddressWlan1, INSTID_WLAN1);
        if (realMacAddressWlan1.empty() || realMacAddressWlan1 != realMacAddressWlan0) {
            WifiSettings::GetInstance().SetRealMacAddress(realMacAddressWlan0, INSTID_WLAN1);
        }
        WifiConfigCenter::GetInstance().SetMacAddress(realMacAddressWlan1, INSTID_WLAN1);
        return WIFI_OPT_SUCCESS;
    }
 
    bool isFromHal = false;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
    std::string mac = wifiOemMac_ == ""? GetWifiOeminfoMac() : wifiOemMac_;
    if (mac.empty()) {
        WIFI_LOGE("GetStaDeviceMacAddress from oeminfo failed, try to Get from hal!");
        if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(mac, ifaceName)) != WIFI_HAL_OPT_OK) {
            WIFI_LOGE("GetStaDeviceMacAddress from hal failed!");
        }
        isFromHal = true;
    }
    wifiOemMac_ = mac;
    WifiConfigCenter::GetInstance().SetMacAddress(mac, pStaStateMachine->m_instId);
    if ((!isFromHal && (realMacAddressWlan0.empty() || realMacAddressWlan0 != mac)) ||
        (isFromHal && realMacAddressWlan0.empty())) {
        WifiSettings::GetInstance().SetRealMacAddress(mac, pStaStateMachine->m_instId);
    }
    return WIFI_OPT_SUCCESS;
}
#endif
 
ErrCode StaStateMachine::ClosedState::GetRealMacAddressFromHal()
{
    WIFI_LOGI("GetRealMacAddressFromHal enter!");
    std::string mac;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(mac, ifaceName))
        == WIFI_HAL_OPT_OK) {
        WifiConfigCenter::GetInstance().SetMacAddress(mac, pStaStateMachine->m_instId);
        std::string realMacAddress;
        WifiSettings::GetInstance().GetRealMacAddress(realMacAddress, pStaStateMachine->m_instId);
        if (realMacAddress.empty()) {
            WifiSettings::GetInstance().SetRealMacAddress(mac, pStaStateMachine->m_instId);
        }
        return WIFI_OPT_SUCCESS;
    } else {
        WIFI_LOGI("GetStaDeviceMacAddress failed!");
        return WIFI_OPT_FAILED;
    }
}

void StaStateMachine::ClosedState::StartWifiProcess()
{
    if (WifiStaHalInterface::GetInstance().WpaAutoConnect(false) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("The automatic Wpa connection is disabled failed.");
    }
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    WIFI_LOGI("set suspend mode to chip when wifi started, screenState: %{public}d", screenState);
    if (pStaStateMachine->m_instId == INSTID_WLAN0) {
        if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE)
            != WIFI_HAL_OPT_OK) {
            WIFI_LOGE("%{public}s WpaSetSuspendMode failed!", __FUNCTION__);
        }
    }
    /* Sets the MAC address of WifiSettings. */
#ifdef READ_MAC_FROM_OEM
    GetRealMacAddressFromOemInfo();
#else
    GetRealMacAddressFromHal();
#endif

#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("Register netsupplier %{public}d", pStaStateMachine->m_instId);
    WifiNetAgent::GetInstance().OnStaMachineWifiStart(pStaStateMachine->m_instId);
#endif

    pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
}

void StaStateMachine::ClosedState::StopWifiProcess()
{
#ifndef OHOS_ARCH_LITE
    WifiNetAgent::GetInstance().UnregisterNetSupplier(pStaStateMachine->m_instId);
    if (pStaStateMachine->m_NetWorkState != nullptr) {
        pStaStateMachine->m_NetWorkState->StopNetStateObserver(pStaStateMachine->m_NetWorkState);
    }
    if (pStaStateMachine->hasNoInternetDialog_) {
        pStaStateMachine->CloseNoInternetDialog();
    }
#endif
    WifiChrUtils::GetInstance().ClearSignalPollInfoArray();
    WifiConfigCenter::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, pStaStateMachine->m_instId);
}

void StaStateMachine::ClosedState::SaveFoldStatus(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("SaveFoldStatus, msg is nullptr");
        return;
    }
    pStaStateMachine->foldStatus_ = msg->GetParam1();
}

void StaStateMachine::ClosedState::DealScreenStateChangedEvent(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealScreenStateChangedEvent InternalMessage msg is null.");
        return;
    }

    int screenState = msg->GetParam1();
    WIFI_LOGI("ClosedState::DealScreenStateChangedEvent, Receive msg: screenState=%{public}d", screenState);
    if (screenState == MODE_STATE_OPEN) {
        pStaStateMachine->enableSignalPoll = true;
    } else {
        if (pStaStateMachine->isAudioOn_ == AUDIO_OFF) {
            pStaStateMachine->enableSignalPoll = false;
        } else {
            pStaStateMachine->enableSignalPoll = true;
        }
    }
}

/* --------------------------- state machine Init State ------------------------------ */
StaStateMachine::InitState::InitState(StaStateMachine *staStateMachine)
    : State("InitState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::InitState::~InitState()
{}

void StaStateMachine::InitState::GoInState()
{
    WIFI_LOGI("InitState GoInState function.");
    /* Initialize Connection Information. */
    pStaStateMachine->InitWifiLinkedInfo();
    return;
}

void StaStateMachine::InitState::GoOutState()
{
    WIFI_LOGI("InitState GoOutState function.");
    return;
}

bool StaStateMachine::InitState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("InitState-msgCode=%{public}d is received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->m_instId);
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_UPDATE_COUNTRY_CODE: {
            ret = EXECUTED;
            UpdateCountryCode(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_CONNECT_NETWORK:
        case WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK: {
            ret = EXECUTED;
            StartConnectEvent(msg);
            break;
        }
        case WIFI_SVR_COM_STA_ENABLE_HILINK:
        case WIFI_SVR_COM_STA_HILINK_DELIVER_MAC:
        case WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS: {
            ret = EXECUTED;
            pStaStateMachine->DealHiLinkDataToWpa(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            ret = EXECUTED;
            HandleNetworkConnectionEvent(msg);
            break;
        }
        default:
            WIFI_LOGD("InitState-msgCode=%d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

void StaStateMachine::InitState::UpdateLinkedInfoAfterConnect(const std::string& bssid)
{
    pStaStateMachine->linkedInfo.networkId = pStaStateMachine->targetNetworkId_;
    pStaStateMachine->AfterApLinkedprocess(bssid);
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    pStaStateMachine->UpdateRiskTypeAttribute();
#endif
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
    // Reset signal level when first start signal poll
    pStaStateMachine->lastSignalLevel_ = INVALID_SIGNAL_LEVEL;
    pStaStateMachine->DealSignalPollResult();

#ifndef OHOS_ARCH_LITE
    pStaStateMachine->SaveWifiConfigForUpdate(pStaStateMachine->targetNetworkId_);
    pStaStateMachine->UpdateLinkedInfoFromScanInfo();
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    pStaStateMachine->DealMloConnectionLinkInfo();
    WifiConfigCenter::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, pStaStateMachine->m_instId);
    pStaStateMachine->mConnectFailedCnt = 0;
}

void StaStateMachine::InitState::SwitchToNextStateAfterConnect()
{
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->enhanceService_ != nullptr &&
        pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_DHCP_REQUIRED,
            pStaStateMachine->m_instId) == MultiLinkDefs::DHCP_IGNORE) {
        WIFI_LOGE("ignore dhcp, SwitchState");
        pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
        return;
    }
#endif
    pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
}

void StaStateMachine::InitState::HandleNetworkConnectionEvent(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("HandleNetWorkConnectionEvent, msg is nullptr.\n");
        return;
    }
    WIFI_LOGI("enter HandleNetWorkConnectionEvent m_instId = %{public}d", pStaStateMachine->m_instId);
    std::string bssid = msg->GetStringFromMessage();
    pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    if (pStaStateMachine->m_hilinkFlag) {
        pStaStateMachine->HilinkSaveConfig();
    }
    WifiDeviceConfig deviceConfig;
    int networkId = pStaStateMachine->targetNetworkId_;
    int instId = pStaStateMachine->m_instId;
    if (networkId == INVALID_NETWORK_ID ||
        WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig, instId) != 0) {
        WIFI_LOGE("%{public}s can not find config for networkId = %{public}d", __FUNCTION__, networkId);
        WifiStaHalInterface::GetInstance().Disconnect(WifiConfigCenter::GetInstance().GetStaIfaceName(instId));
        pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
        return;
    }
    if (pStaStateMachine->CurrentIsRandomizedMac()) {
        WifiSettings::GetInstance().SetDeviceRandomizedMacSuccessEver(networkId);
    }

    UpdateLinkedInfoAfterConnect(bssid);
    SwitchToNextStateAfterConnect();
}

void StaStateMachine::InitState::UpdateCountryCode(InternalMessagePtr msg)
{
#ifndef OHOS_ARCH_LITE
    std::string wifiCountryCode = msg->GetStringFromMessage();
    if (wifiCountryCode.empty()) {
        return;
    }
    WifiErrorNo result = WifiSupplicantHalInterface::GetInstance().WpaSetCountryCode(wifiCountryCode);
    if (result == WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGI("update wifi country code sucess, wifiCountryCode=%{public}s", wifiCountryCode.c_str());
        return;
    }
    WIFI_LOGE("update wifi country code fail, wifiCountryCode=%{public}s, ret=%{public}d",
        wifiCountryCode.c_str(), result);
#endif
}

bool StaStateMachine::InitState::AllowAutoConnect()
{
    if (pStaStateMachine->linkedInfo.connState == ConnState::CONNECTING || pStaStateMachine->isCurrentRoaming_) {
        return false;
    }
    if (pStaStateMachine->linkedInfo.supplicantState == SupplicantState::ASSOCIATING ||
        pStaStateMachine->linkedInfo.supplicantState == SupplicantState::ASSOCIATED ||
        pStaStateMachine->linkedInfo.supplicantState == SupplicantState::AUTHENTICATING ||
        pStaStateMachine->linkedInfo.supplicantState == SupplicantState::FOUR_WAY_HANDSHAKE ||
        pStaStateMachine->linkedInfo.supplicantState == SupplicantState::GROUP_HANDSHAKE) {
        return false;
    }

    if (pStaStateMachine->m_hilinkFlag) {
        WIFI_LOGI("HiLink is active, refuse auto connect\n");
        return false;
    }
    return true;
}

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
bool StaStateMachine::InitState::RestrictedByMdm(WifiDeviceConfig &config)
{
    WIFI_LOGI("Enter RestrictedByMdm");
    if (WifiSettings::GetInstance().FindWifiBlockListConfig(config.ssid, config.bssid, 0)) {
        pStaStateMachine->DealMdmRestrictedConnect(config);
        return true;
    }
    if (!WifiSettings::GetInstance().WhetherSetWhiteListConfig() || config.bssid.empty()) {
        return false;
    }
    if (!WifiSettings::GetInstance().FindWifiWhiteListConfig(config.ssid, config.bssid, 0)) {
        pStaStateMachine->DealMdmRestrictedConnect(config);
        return true;
    }
    return false;
}
#endif

void StaStateMachine::InitState::DealHiddenSsidConnectMiss(int networkId)
{
    WifiLinkedInfo linkInfo = pStaStateMachine->linkedInfo;
    linkInfo.networkId = networkId;
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_MISS_MATCH, linkInfo);
    WifiSettings::GetInstance().SetUserConnectChoice(networkId);
}

void StaStateMachine::InitState::StartConnectEvent(InternalMessagePtr msg)
{
    WIFI_LOGI("enter StartConnectEvent m_instId = %{public}d\n", pStaStateMachine->m_instId);
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return;
    }
    int networkId = msg->GetParam1();
    int connTriggerMode = msg->GetParam2();
    auto bssid = msg->GetStringFromMessage();
    pStaStateMachine->linkedInfo.connTriggerMode = connTriggerMode;

    if (NotAllowConnectToNetwork(networkId, bssid, connTriggerMode)) {
        return;
    }
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->m_instId == INSTID_WLAN0 && connTriggerMode != NETWORK_SELECTED_BY_GENELINK &&
        pStaStateMachine->enhanceService_ != nullptr) {
        pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::NOTIFY_QUIT_DUAL_WLAN, 0);
        WIFI_LOGI("notify enhance service quit dual_wlan mode");
    }
#endif
    if (pStaStateMachine->StartConnectToNetwork(networkId, bssid, connTriggerMode) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Connect to network failed: %{public}d.\n", networkId);
        pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::FAILED);
        pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_ENABLE_NETWORK_FAILED,
            pStaStateMachine->linkedInfo);
        pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
        return;
    }
    pStaStateMachine->SwitchState(pStaStateMachine->pApLinkingState);
    return;
}

bool StaStateMachine::InitState::NotAllowConnectToNetwork(int networkId, const std::string& bssid, int connTriggerMode)
{
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->isWaitForReconnect_ || (pStaStateMachine->enhanceService_ != nullptr &&
        pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_RECONNECT_ALLOWED,
            pStaStateMachine->m_instId) == MultiLinkDefs::ALLOW_IN_CONN_STATE)) {
        WIFI_LOGI("skip NotAllowConnectToNetwork in dual_wlan mode m_instId=%{public}d", pStaStateMachine->m_instId);
        return false;
    }
#endif
    if (networkId == pStaStateMachine->targetNetworkId_) {
        WIFI_LOGI("This network is connecting and does not need to be reconnected m_instId = %{public}d",
            pStaStateMachine->m_instId);
        return true;
    }
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, pStaStateMachine->m_instId) != 0) {
        WIFI_LOGE("GetDeviceConfig failed, networkId = %{public}d", networkId);
        return true;
    }

    if (networkId == pStaStateMachine->linkedInfo.networkId && connTriggerMode != NETWORK_SELECTED_BY_SELFCURE &&
        connTriggerMode != NETWORK_SELECTED_BY_MDM &&
        pStaStateMachine->linkedInfo.connState != ConnState::DISCONNECTING) {
        WIFI_LOGI("This network is connected and does not need to be reconnected m_instId = %{public}d",
            pStaStateMachine->m_instId);
        return true;
    }

    if (connTriggerMode == NETWORK_SELECTED_BY_AUTO && !AllowAutoConnect()) {
        WIFI_LOGI("SupplicantState is TransientState, refuse auto connect");
        return true;
    }

    if (config.hiddenSSID && NotExistInScanList(config) &&
        !pStaStateMachine->selfCureService_->IsSelfCureL2Connecting()) {
        DealHiddenSsidConnectMiss(networkId);
        return true;
    }

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    if (pStaStateMachine->WhetherRestrictedByMdm(config.ssid, config.bssid, !config.bssid.empty())) {
        WIFI_LOGI("NotAllowConnectToNetwork, RestrictedByMdm");
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(config.networkId,
            DisabledReason::DISABLED_MDM_RESTRICTED);
        pStaStateMachine->ReportMdmRestrictedEvent(config.ssid, config.bssid, "BLOCK_LIST");
        return true;
    }
#endif

    return false;
}

bool StaStateMachine::InitState::NotExistInScanList(WifiDeviceConfig &config)
{
    WIFI_LOGI("NotExistInScanList, networkId = %{public}d, ssid = %{public}s, km = %{public}s.",
        config.networkId, SsidAnonymize(config.ssid).c_str(), (config.keyMgmt).c_str());
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    std::string scanMgmt = "";
    for (auto item : scanInfoList) {
        item.GetDeviceMgmt(scanMgmt);
        if (item.ssid == config.ssid && WifiSettings::GetInstance().InKeyMgmtBitset(config, scanMgmt)) {
            return false;
        }
    }
    return true;
}

/* --------------------------- state machine link State ------------------------------ */
StaStateMachine::LinkState::LinkState(StaStateMachine *staStateMachine)
    : State("LinkState"), pStaStateMachine(staStateMachine)
{
    InitStaSMHandleMap();
}

StaStateMachine::LinkState::~LinkState()
{}

void StaStateMachine::LinkState::GoInState()
{
    WIFI_LOGI("LinkState GoInState function.");
    return;
}

void StaStateMachine::LinkState::GoOutState()
{
    WIFI_LOGI("LinkState GoOutState function.");
    pStaStateMachine->linkedInfo.supplicantState = SupplicantState::DISCONNECTED;
    return;
}

bool StaStateMachine::LinkState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    WIFI_LOGD("LinkState ExecuteStateMsg function:msgName=[%{public}d]. m_instId=%{public}d\n",
        msg->GetMessageName(), pStaStateMachine->m_instId);
    auto iter = staSmHandleFuncMap.find(msg->GetMessageName());
    if (iter != staSmHandleFuncMap.end()) {
        (iter->second)(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

/* -- state machine Connect State Message processing function -- */
int StaStateMachine::LinkState::InitStaSMHandleMap()
{
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealDisconnectEventInLinkState(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK] = [this](InternalMessagePtr msg) {
        return this->pStaStateMachine->DealReassociateCmd(msg);
    };
    staSmHandleFuncMap[WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT] = [this](InternalMessagePtr msg) {
        return this->pStaStateMachine->DealScreenStateChangedEvent(msg);
    };
#ifndef OHOS_ARCH_LITE
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT] = [this](InternalMessagePtr msg) {
        return this->pStaStateMachine->DealWpaEapSimAuthEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT] = [this](InternalMessagePtr msg) {
        return this->pStaStateMachine->DealWpaEapUmtsAuthEvent(msg);
    };
#ifdef EXTENSIBLE_AUTHENTICATION
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_CUSTOM_AUTH_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaCustomEapAuthEvent(msg);
    };
#endif
#endif
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaStateChange(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_MLO_WORK_STATE_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealMloStateChange(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_COM_STA_NETWORK_REMOVED] = [this](InternalMessagePtr msg) {
        return this->DealNetworkRemoved(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_DISABLE_STA] = [this](InternalMessagePtr msg) {
        return this->StopWifiProcessInLinkState(msg);
    };
    staSmHandleFuncMap[CMD_NETWORK_CONNECT_TIMEOUT] = [this](InternalMessagePtr msg) {
        return this->DealConnectTimeOutCmd(msg);
    };
    return WIFI_OPT_SUCCESS;
}

bool StaStateMachine::IsNewConnectionInProgress()
{
    int currentLinkedId = linkedInfo.networkId;
    int targetId = targetNetworkId_;
    if (targetId == INVALID_NETWORK_ID) {
        return false;
    }
    std::string targetSsid = "";
    // Get the target network's SSID, can get empty result if it is hillink network
    if (!m_hilinkFlag) {
        WifiDeviceConfig config;
        if (WifiSettings::GetInstance().GetDeviceConfig(targetId, config, m_instId) != 0) {
            WIFI_LOGE("GetDeviceConfig failed, targetId = %{public}d", targetId);
            return false;
        }
        targetSsid = config.ssid;
    }

    // When connecting to another network while already connected, the old network will first
    // disconnect before the new connection can begin.
    bool isConnectingWhileAlreadyConnected =
            currentLinkedId != INVALID_NETWORK_ID && currentLinkedId != targetId;
    // 2 simultaneous connections happen back-to-back.
    std::string disconnectingSsid = linkedInfo.ssid;
    bool isConnectingToAnotherNetwork = (disconnectingSsid != targetSsid);
    // Check if Genelink feature is enabled
    bool isGenelink = false;
#ifndef OHOS_ARCH_LITE
    if (enhanceService_ != nullptr) {
        isGenelink = (enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_FEATURE_ENABLED,
            0) == MultiLinkDefs::FEATURE_ENABLED);
    }
#endif
    bool result = isConnectingWhileAlreadyConnected || isConnectingToAnotherNetwork || isGenelink;
    WIFI_LOGI("Enter IsNewConnectionInProgress targetId = %{public}d currentLinkedId = %{public}d"
        " disconnectingSsid = %{public}s, targetSsid = %{public}s, isGenelink = %{public}d, result = %{public}d",
        targetId, currentLinkedId, SsidAnonymize(disconnectingSsid).c_str(),
        SsidAnonymize(targetSsid).c_str(), isGenelink, static_cast<int>(result));
    return result;
}

void StaStateMachine::LinkState::DealWpaCustomEapAuthEvent(InternalMessagePtr msg)
{
#ifdef EXTENSIBLE_AUTHENTICATION
    if (msg == nullptr) {
        LOGE("%{public}s InternalMessage msg is null.", __func__);
        return;
    }

    WpaEapData wpaEapData = {0};
    msg->GetMessageObj(wpaEapData);
    NetEapObserver::GetInstance().NotifyWpaEapInterceptInfo(wpaEapData);
    LOGI("%{public}s code=%{public}d, type=%{public}d, msgId:%{public}d success", __func__, wpaEapData.code,
        wpaEapData.type, wpaEapData.msgId);
#endif
}

bool StaStateMachine::LinkState::NeedIgnoreDisconnectEvent(int reason, const std::string &bssid)
{
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->enhanceService_ == nullptr || pStaStateMachine->m_instId != INSTID_WLAN0) {
        return false;
    }

    if (pStaStateMachine->selfCureService_ != nullptr && pStaStateMachine->selfCureService_->IsSelfCureOnGoing()) {
        WIFI_LOGI("self cure going, dont ignroe disconnect event");
        return false;
    }
    if (TryFastReconnect(reason, bssid)) {
        return true;
    }
    if (pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_IGNORE_DISCONN_REQUIRED,
        pStaStateMachine->m_instId) == MultiLinkDefs::IGNORE_DISCONNECT) {
        pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::NOTIFY_CHAIN_DISCONNECTED,
            pStaStateMachine->m_instId);
        WIFI_LOGI("ignore disconnect event in genelink mode");
        return true;
    }
#endif
    return false;
}

bool StaStateMachine::LinkState::TryFastReconnect(int reason, const std::string &bssid)
{
    if (std::find(g_fastReconnectWlanReasons.begin(), g_fastReconnectWlanReasons.end(),
        static_cast<Wifi80211ReasonCode>(reason)) == g_fastReconnectWlanReasons.end()) {
        return false;
    }
    if (WifiSettings::GetInstance().GetSignalLevel(pStaStateMachine->linkedInfo.rssi,
        pStaStateMachine->linkedInfo.band, pStaStateMachine->m_instId) < RSSI_LEVEL_2) {
        WIFI_LOGI("%{public}s signal level less 2", __FUNCTION__);
        return false;
    }
    WifiDeviceConfig wifiDeviceConfig = pStaStateMachine->getCurrentWifiDeviceConfig();
    int32_t disconnectInterval = static_cast<int32_t>(time(nullptr) - wifiDeviceConfig.lastConnectTime);
    int32_t fastConnectInterval = pStaStateMachine->enableSignalPoll ?
        FAST_RECONNECT_INTERVAL_MIN : FAST_RECONNECT_INTERVAL_MAX;
    if (disconnectInterval <= fastConnectInterval) {
        WIFI_LOGI("%{public}s cannot fast reconnect, disconnect interval:%{public}d", __FUNCTION__, disconnectInterval);
        return false;
    }
    WifiScanParams params;
    params.freqs.push_back(pStaStateMachine->linkedInfo.frequency);
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(pStaStateMachine->m_instId);
    if (pScanService != nullptr &&
        pScanService->ScanWithParam(params, true, ScanType::SCAN_TYPE_FAST_RECONNECT) == WIFI_OPT_SUCCESS) {
        usleep(FAST_RECONNECT_DELAY_TIME_US); // wait 100ms for single channel scan callback
        if (pStaStateMachine->StartConnectToNetwork(pStaStateMachine->linkedInfo.networkId, bssid,
            NETWORK_SELECTED_BY_FAST_RECONNECT) == WIFI_OPT_SUCCESS) {
            WIFI_LOGI("%{public}s try to fast reconnect, networkId:%{public}d, bssid:%{public}s",
                __FUNCTION__, pStaStateMachine->linkedInfo.networkId, MacAnonymize(bssid).c_str());
            return true;
        }
    }
    WIFI_LOGW("%{public}s scan or connect fail", __FUNCTION__);
    return false;
}

void StaStateMachine::LinkState::DealDisconnectEventInLinkState(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is null");
        return;
    }
    int reason = msg->GetParam1();
    int locallyGenerated = msg->GetParam2();
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("Enter DealDisconnectEventInLinkState m_instId = %{public}d reason:%{public}d, bssid:%{public}s",
        pStaStateMachine->m_instId, reason, MacAnonymize(bssid).c_str());

    if (NeedIgnoreDisconnectEvent(reason, bssid)) {
        pStaStateMachine->SwitchState(pStaStateMachine->pApReConnectState);
        return;
    }

    pStaStateMachine->mIsWifiInternetCHRFlag = false;
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->hasNoInternetDialog_) {
        pStaStateMachine->CloseNoInternetDialog();
    }
#endif
    if (!WifiConfigCenter::GetInstance().GetWifiSelfcureReset()) {
        WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(false);
    }
    WifiChrUtils::GetInstance().ClearSignalPollInfoArray();
    EnhanceWriteWifiLinkTypeHiSysEvent(pStaStateMachine->linkedInfo.ssid, -1, "DISCONNECT");
    if (!pStaStateMachine->IsNewConnectionInProgress()) {
        pStaStateMachine->linkedInfo.disconnTriggerMode = DisconnState::DISCONNECTED;
        bool shouldStopTimer = pStaStateMachine->IsDisConnectReasonShouldStopTimer(reason);
        if (shouldStopTimer) {
            pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
        }
        int curNetworkId = (pStaStateMachine->linkedInfo.networkId == INVALID_NETWORK_ID) ?
            pStaStateMachine->targetNetworkId_ : pStaStateMachine->linkedInfo.networkId;
        BlockConnectService::GetInstance().UpdateNetworkSelectStatusForWpa(curNetworkId,
            DisabledReason::DISABLED_DISASSOC_REASON, reason);
        if (BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, reason, locallyGenerated)) {
            BlockConnectService::GetInstance().UpdateNetworkSelectStatus(curNetworkId,
                DisabledReason::DISABLED_CONSECUTIVE_FAILURES);
        }
        EnhanceWriteWifiAbnormalDisconnectHiSysEvent(reason, locallyGenerated);
        pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
    } else { //connecting to another network while already connected
        pStaStateMachine->mPortalUrl = "";
        pStaStateMachine->StopDhcp(true, true);
        // Update net supplier info to disable network
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->NetSupplierInfo != nullptr) {
        pStaStateMachine->NetSupplierInfo->isAvailable_ = false;
        pStaStateMachine->NetSupplierInfo->ident_ = "";
        WIFI_LOGI("On disconnect update net supplier info\n");
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(pStaStateMachine->NetSupplierInfo,
            pStaStateMachine->m_instId);
    }
#endif
        ConnState currentState = pStaStateMachine->linkedInfo.connState;
        DetailedState currentDetailState = pStaStateMachine->linkedInfo.detailedState;
        pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::DISCONNECTED);
        pStaStateMachine->linkedInfo.disconnTriggerMode = DisconnState::SWITCHING;
        pStaStateMachine->InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED,
            pStaStateMachine->linkedInfo);
        pStaStateMachine->InitWifiLinkedInfo();
        // Avoid overwriting the state in the connecting,
        // because the state in the connecting needs to restrict connections initiated by automatic network selection.
        pStaStateMachine->SaveLinkstate(currentState, currentDetailState);
        WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
    }
    return;
}

void StaStateMachine::LinkState::StopWifiProcessInLinkState(InternalMessagePtr msg)
{
    WIFI_LOGI("Enter StaStateMachine::StopWifiProcessInLinkState m_instId = %{public}d\n", pStaStateMachine->m_instId);
    EnhanceWriteWifiLinkTypeHiSysEvent(pStaStateMachine->linkedInfo.ssid, -1, "DISCONNECT");
    pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_WIFI_DISABLED,
        WifiDisconnectReason::DISCONNECT_BY_NO_REASON);
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->enhanceService_ != nullptr) {
        pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::NOTIFY_STA_DISABLE,
            pStaStateMachine->m_instId);
    }
#endif
    WifiStaHalInterface::GetInstance().Disconnect(
        WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId));
    pStaStateMachine->DelayMessage(msg);
    pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
}

void StaStateMachine::LinkState::DealNetworkRemoved(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealNetworkRemoved InternalMessage msg is null.");
        return;
    }
    int networkId = msg->GetParam1();
    WIFI_LOGI("DealNetworkRemoved networkid = %{public}d linkinfo.networkid = %{public}d targetNetworkId_ = %{public}d",
        networkId, pStaStateMachine->linkedInfo.networkId, pStaStateMachine->targetNetworkId_);
    if (pStaStateMachine->linkedInfo.networkId == networkId || pStaStateMachine->targetNetworkId_ == networkId) {
        std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
        WIFI_LOGI("Enter StartDisConnectToNetwork ifaceName:%{public}s!", ifaceName.c_str());
        pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_NETWORK_REMOVED,
            WifiDisconnectReason::DISCONNECT_BY_NO_REASON);
        WifiStaHalInterface::GetInstance().Disconnect(ifaceName);
    }
    return;
}
void StaStateMachine::LinkState::DealWpaStateChange(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealWpaStateChange InternalMessage msg is null.");
        return;
    }
    int status = msg->GetParam1();
    WIFI_LOGI("DealWpaStateChange status: %{public}d", status);
    if (static_cast<SupplicantState>(status) == SupplicantState::ASSOCIATING) {
        std::string ssid = msg->GetStringFromMessage();
        if (ssid.length() != 0 && !WifiCodeConvertUtil::IsUtf8(ssid)) {
            pStaStateMachine->linkedInfo.ssid = WifiCodeConvertUtil::GbkToUtf8(ssid);
        } else {
            pStaStateMachine->linkedInfo.ssid = ssid;
        }
        pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATING, pStaStateMachine->linkedInfo);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
            static_cast<int>(WifiOperateState::STA_ASSOCIATING));
        WIFI_LOGI("DealWpaStateChange ASSOCIATING:ssid = %{public}s",
            SsidAnonymize(pStaStateMachine->linkedInfo.ssid).c_str());
    } else if (static_cast<SupplicantState>(status) == SupplicantState::ASSOCIATED) {
        pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATED, pStaStateMachine->linkedInfo);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
            static_cast<int>(WifiOperateState::STA_ASSOCIATED));
    }
    pStaStateMachine->linkedInfo.supplicantState = static_cast<SupplicantState>(status);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
}

void StaStateMachine::LinkState::DealMloStateChange(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        LOGE("DealMloStateChange InternalMessage msg is null.");
        return;
    }

    MloStateParam param = {0};
    msg->GetMessageObj(param);
    uint8_t feature = param.feature;
    uint8_t state = param.state;
    uint16_t reasonCode = param.reasonCode;
    pStaStateMachine->DealSignalPollResult();
    if (feature == CoFeatureType::COFEATURE_TYPE_MLO) {
        if (pStaStateMachine->linkedInfo.wifiLinkType == WifiLinkType::WIFI7_EMLSR &&
            static_cast<int32_t>(state) != WifiLinkType::WIFI7_EMLSR) {
            pStaStateMachine->linkedInfo.wifiLinkType = static_cast<WifiLinkType>(state);
            pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_EMLSR_END, pStaStateMachine->linkedInfo);
            EnhanceWriteEmlsrExitReasonHiSysEvent(pStaStateMachine->linkedInfo.ssid, static_cast<int>(reasonCode));
        }
        if (static_cast<int32_t>(state) == WifiLinkType::WIFI7_EMLSR) {
            pStaStateMachine->linkedInfo.wifiLinkType = static_cast<WifiLinkType>(state);
            pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_EMLSR_START,
                pStaStateMachine->linkedInfo);
            pStaStateMachine->DealMloLinkSignalPollResult();
        }
        pStaStateMachine->linkedInfo.wifiLinkType = static_cast<WifiLinkType>(state);
        EnhanceWriteWifiLinkTypeHiSysEvent(pStaStateMachine->linkedInfo.ssid,
            pStaStateMachine->linkedInfo.wifiLinkType, "MLO_STATE_CHANGED");
#ifndef OHOS_ARCH_LITE
        if (pStaStateMachine->enhanceService_ != nullptr) {
            pStaStateMachine->enhanceService_->OnWifiLinkTypeChanged(pStaStateMachine->linkedInfo.wifiLinkType);
        }
#endif
    }
    if (feature == CoFeatureType::COFEATURE_TYPE_WUR) {
        if (state == WurState::WUR_ENABLE) {
            pStaStateMachine->linkedInfo.isWurEnable = true;
        } else {
            pStaStateMachine->linkedInfo.isWurEnable = false;
        }
#ifndef OHOS_ARCH_LITE
        if (pStaStateMachine->enhanceService_ != nullptr) {
            pStaStateMachine->enhanceService_->NotifyWurState(state, reasonCode);
        }
#endif
    }

    LOGI("DealMloStateChange wifiLinkType=%{public}d isWurEnable=%{public}d reasonCode=%{public}u",
        pStaStateMachine->linkedInfo.wifiLinkType, pStaStateMachine->linkedInfo.isWurEnable, reasonCode);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
}

void StaStateMachine::LinkState::DealConnectTimeOutCmd(InternalMessagePtr msg)
{
    WIFI_HILOG_COMM_WARN("enter DealConnectTimeOutCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nul\n");
    }
    EnhanceWriteAssocFailHiSysEvent("WPA_TIMEOUT");
    if (pStaStateMachine->targetNetworkId_ == pStaStateMachine->mLastConnectNetId) {
        pStaStateMachine->mConnectFailedCnt++;
    }
    pStaStateMachine->DealSetStaConnectFailedCount(1, false);
    WifiConfigCenter::GetInstance().SetConnectTimeoutBssid(pStaStateMachine->linkedInfo.bssid,
        pStaStateMachine->m_instId);
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_TIMEOUT);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING_TIMEOUT, pStaStateMachine->linkedInfo);
    pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
}

void StaStateMachine::StopDhcp(bool isStopV4, bool isStopV6)
{
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    StopTimer(static_cast<int>(CMD_START_NETCHECK));
    WIFI_LOGI("StopDhcp, isStopV4: %{public}d, isStopV6: %{public}d", isStopV4, isStopV6);
    pDhcpResultNotify->Clear();
    if (isStopV4) {
        StopDhcpClient(ifname.c_str(), false, true);
#ifdef OHOS_ARCH_LITE
        IfConfig::GetInstance().FlushIpAddr(WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), IPTYPE_IPV4);
#endif
    }
    if (isStopV6) {
        StopDhcpClient(ifname.c_str(), true, false);
    }
    HandlePostDhcpSetup();
}

bool StaStateMachine::SetRandomMac(WifiDeviceConfig &deviceConfig, const std::string &bssid)
{
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    std::string currentMac;
    std::string realMac;
    WifiSettings::GetInstance().GetRealMacAddress(realMac, m_instId);
    if (deviceConfig.wifiPrivacySetting == WifiPrivacyConfig::DEVICEMAC ||
        WifiSettings::GetInstance().IsRandomMacDisabled() || ShouldUseFactoryMac(deviceConfig)) {
        currentMac = realMac;
    } else {
        WifiStoreRandomMac randomMacInfo;
        InitRandomMacInfo(deviceConfig, bssid, randomMacInfo);
        if (!MacAddress::IsValidMac(deviceConfig.macAddress) || deviceConfig.macAddress == realMac) {
            WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
            if (MacAddress::IsValidMac(randomMacInfo.randomMac) && randomMacInfo.randomMac != realMac) {
                currentMac = randomMacInfo.randomMac;
            } else {
                SetRandomMacConfig(randomMacInfo, deviceConfig, currentMac);
                WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
            }
        } else if (IsPskEncryption(deviceConfig.keyMgmt)) {
            WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
            if (MacAddress::IsValidMac(randomMacInfo.randomMac) && randomMacInfo.randomMac != realMac) {
                currentMac = randomMacInfo.randomMac;
            } else {
                randomMacInfo.randomMac = deviceConfig.macAddress;
                currentMac = randomMacInfo.randomMac;
                WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
            }
        } else {
            currentMac = deviceConfig.macAddress;
        }
    }
    if (!SetMacToHal(currentMac, realMac, m_instId)) {
        return false;
    }
    deviceConfig.macAddress = currentMac;
    if (!WifiSettings::GetInstance().IsRandomMacDisabled()) {
        deviceConfig.wifiPrivacySetting =
            (currentMac == realMac) ? WifiPrivacyConfig::DEVICEMAC : WifiPrivacyConfig::RANDOMMAC;
    }
    WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    LOGI("SetRandomMac wifiPrivacySetting:%{public}d,ssid:%{public}s,keyMgmt:%{public}s,macAddress:%{public}s",
        deviceConfig.wifiPrivacySetting, SsidAnonymize(deviceConfig.ssid).c_str(), deviceConfig.keyMgmt.c_str(),
        MacAnonymize(deviceConfig.macAddress).c_str());
#endif
    return true;
}

/* --------------------------- state machine Disconnected State ------------------------------ */
StaStateMachine::SeparatedState::SeparatedState(StaStateMachine *staStateMachine)
    : State("SeparatedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::SeparatedState::~SeparatedState()
{}

void StaStateMachine::SeparatedState::GoInState()
{
    pStaStateMachine->SetConnectMethod(NETWORK_SELECTED_BY_UNKNOWN);
    pStaStateMachine->StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    pStaStateMachine->wifiDataReportService_->ReportApConnEventInfo(ConnReportReason::CONN_DISCONNECTED,
        pStaStateMachine->linkedInfo.networkId);
#endif
#endif
    pStaStateMachine->StopDhcp(true, true);
    pStaStateMachine->isRoam = false;
    pStaStateMachine->mPortalUrl = "";
    // Update net supplier info to disable network
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->NetSupplierInfo != nullptr) {
        pStaStateMachine->NetSupplierInfo->isAvailable_ = false;
        pStaStateMachine->NetSupplierInfo->ident_ = "";
        WIFI_LOGI("On disconnect update net supplier info\n");
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(pStaStateMachine->NetSupplierInfo,
            pStaStateMachine->m_instId);
    }
#endif
    /* Callback result to InterfaceService. */
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::DISCONNECTED);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, pStaStateMachine->linkedInfo);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_EMLSR_END, pStaStateMachine->linkedInfo);
    /* clear connection information. */
    pStaStateMachine->InitWifiLinkedInfo();
    pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    pStaStateMachine->linkSwitchDetectingFlag_ = false;
#ifdef FEATURE_SELF_CURE_SUPPORT
    if ((pStaStateMachine->selfCureService_ != nullptr &&
        !pStaStateMachine->selfCureService_->IsSelfCureL2Connecting())) {
        pStaStateMachine->noInternetAccessCnt_ = 0;
        pStaStateMachine->StopTimer(CMD_NO_INTERNET_TIMEOUT);
    }
#endif
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
    WifiConfigCenter::GetInstance().SetMacAddress("", pStaStateMachine->m_instId);
    EnhanceWriteIsInternetHiSysEvent(DISCONNECTED_NETWORK);
    WIFI_LOGI("SeparatedState GoInState function.");
    return;
}

void StaStateMachine::SeparatedState::GoOutState()
{
    WIFI_LOGI("SeparatedState GoOutState function.");
    return;
}

bool StaStateMachine::SeparatedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("SeparatedState-msgCode=%{public}d received. m_instId=%{public}d\n", msg->GetMessageName(),
        pStaStateMachine->m_instId);
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT: {
            ret = EXECUTED;
            break;
        }
        case WIFI_SVR_CMD_STA_ENABLE_STA: {
            ret = EXECUTED;
            WIFI_LOGE("Wifi has already started!");
            break;
        }
        case WIFI_SVR_CMD_STA_DISABLE_STA: {
            pStaStateMachine->DelayMessage(msg);
            pStaStateMachine->SwitchState(pStaStateMachine->pClosedState);
            ret = EXECUTED;
            break;
        }
        case WIFI_SVR_CMD_STA_RECONNECT_NETWORK: {
            ret = EXECUTED;
            DealReConnectCmdInSeparatedState(msg);
            break;
        }
        case WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT: {
            ret = EXECUTED;
            pStaStateMachine->DealScreenStateChangedEvent(msg);
            break;
        }
        default:
            break;
    }

    return ret;
}

void StaStateMachine::SeparatedState::DealReConnectCmdInSeparatedState(InternalMessagePtr msg)
{
    WIFI_LOGI("enter DealReConnectCmdInSeparatedState.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }
    pStaStateMachine->targetNetworkId_ = pStaStateMachine->mLastConnectNetId;
    if (WifiStaHalInterface::GetInstance().Reconnect() == WIFI_HAL_OPT_OK) {
        pStaStateMachine->DealSetStaConnectFailedCount(0, true);
        WIFI_LOGI("StaStateMachine ReConnect successfully!");
        pStaStateMachine->SwitchState(pStaStateMachine->pApLinkingState);
    } else {
        pStaStateMachine->DealSetStaConnectFailedCount(1, false);
        WIFI_LOGE("ReConnect failed!");
    }
}


/* --------------------------- state machine ApConnecting State ------------------------------ */
StaStateMachine::ApLinkingState::ApLinkingState(StaStateMachine *staStateMachine)
    : State("ApLinkingState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::ApLinkingState::~ApLinkingState()
{}

void StaStateMachine::ApLinkingState::GoInState()
{
    WIFI_LOGI("ApLinkingState GoInState function.");
    pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    pStaStateMachine->StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    pStaStateMachine->SaveLinkstate(ConnState::CONNECTING, DetailedState::CONNECTING);
    pStaStateMachine->networkStatusHistoryInserted = false;
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING, pStaStateMachine->linkedInfo);
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
        static_cast<int>(WifiOperateState::STA_CONNECTING));
    return;
}

void StaStateMachine::ApLinkingState::GoOutState()
{
    WIFI_LOGI("ApLinkingState GoOutState function.");
    return;
}

bool StaStateMachine::ApLinkingState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGD("ApLinkingState-msgCode=%{public}d received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->m_instId);
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DISCONNECT: {
            ret = EXECUTED;
            pStaStateMachine->StartDisConnectToNetwork();
            break;
        }
        case WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT: {
            ret = EXECUTED;
            HandleStaBssidChangedEvent(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT:
        case WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT:
        case WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT: {
            ret = EXECUTED;
            DealWpaLinkFailEvent(msg);
            break;
        }
        default:
            break;
    }
    return ret;
}

void StaStateMachine::ApLinkingState::HandleStaBssidChangedEvent(InternalMessagePtr msg)
{
    std::string reason = msg->GetStringFromMessage();
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("ApLinkingState reveived bssid changed event, reason:%{public}s,bssid:%{public}s.\n",
        reason.c_str(), MacAnonymize(bssid).c_str());
    if (strcmp(reason.c_str(), "ASSOC_COMPLETE") != 0) {
        WIFI_LOGE("Bssid change not for ASSOC_COMPLETE, do nothing.");
        return;
    }
    pStaStateMachine->linkedInfo.bssid = bssid;
    pStaStateMachine->UpdateHiLinkAttribute();
#ifndef OHOS_ARCH_LITE
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    pStaStateMachine->DealMloConnectionLinkInfo();
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
    /* BSSID change is not received during roaming, only set BSSID */
    if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid,
        WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId)) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("SetBssid return fail.");
    }
}

void StaStateMachine::ApLinkingState::DealWpaLinkPasswdWrongFailEvent(InternalMessagePtr msg)
{
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("ApLinkingState reveived wpa passwd wrong event, bssid:%{public}s.\n", MacAnonymize(bssid).c_str());
    if (bssid != "") {
        pStaStateMachine->linkedInfo.bssid = bssid;
    }
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_WRONG_PWD);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::PASSWORD_ERROR);
    if (BlockConnectService::GetInstance().IsWrongPassword(pStaStateMachine->targetNetworkId_)) {
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(pStaStateMachine->targetNetworkId_,
            DisabledReason::DISABLED_BY_WRONG_PASSWORD);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
        pStaStateMachine->wifiDataReportService_->ReportApConnEventInfo(ConnReportReason::CONN_WRONG_PASSWORD,
            pStaStateMachine->targetNetworkId_);
#endif
#endif
    } else {
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(pStaStateMachine->targetNetworkId_,
            DisabledReason::DISABLED_AUTHENTICATION_FAILURE);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
        pStaStateMachine->wifiDataReportService_->ReportApConnEventInfo(ConnReportReason::CONN_AUTHENTICATION_FAILURE,
            pStaStateMachine->targetNetworkId_);
#endif
#endif
    }
#ifndef OHOS_ARCH_LITE
    BlockConnectService::GetInstance().NotifyWifiConnFailedInfo(pStaStateMachine->targetNetworkId_,
        pStaStateMachine->linkedInfo.bssid, DisabledReason::DISABLED_AUTHENTICATION_FAILURE);
#endif
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_PASSWORD_WRONG,
        pStaStateMachine->linkedInfo);
    return;
}

void StaStateMachine::ApLinkingState::DealWpaLinkFullConnectFailEvent(InternalMessagePtr msg)
{
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_FULL);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_FULL);
    BlockConnectService::GetInstance().UpdateNetworkSelectStatus(pStaStateMachine->targetNetworkId_,
        DisabledReason::DISABLED_ASSOCIATION_REJECTION);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    pStaStateMachine->wifiDataReportService_->ReportApConnEventInfo(ConnReportReason::CONN_ASSOCIATION_FULL,
        pStaStateMachine->targetNetworkId_);
#endif
#endif
    pStaStateMachine->AddRandomMacCure();
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTION_FULL,
        pStaStateMachine->linkedInfo);
    return;
}

void StaStateMachine::ApLinkingState::DealWpaLinkAssocRejectFailEvent(InternalMessagePtr msg)
{
    pStaStateMachine->linkedInfo.bssid = msg->GetStringFromMessage();
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_REJECTED);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_REJECT);
    BlockConnectService::GetInstance().UpdateNetworkSelectStatus(pStaStateMachine->targetNetworkId_,
        DisabledReason::DISABLED_ASSOCIATION_REJECTION);
#ifndef OHOS_ARCH_LITE
    BlockConnectService::GetInstance().NotifyWifiConnFailedInfo(pStaStateMachine->targetNetworkId_,
        pStaStateMachine->linkedInfo.bssid, DisabledReason::DISABLED_ASSOCIATION_REJECTION);
#ifdef WIFI_DATA_REPORT_ENABLE
    pStaStateMachine->wifiDataReportService_->ReportApConnEventInfo(ConnReportReason::CONN_ASSOCIATION_REJECTION,
        pStaStateMachine->targetNetworkId_);
#endif
#endif
    pStaStateMachine->AddRandomMacCure();
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTION_REJECT,
        pStaStateMachine->linkedInfo);
    return;
}

void StaStateMachine::ApLinkingState::DealWpaLinkFailEvent(InternalMessagePtr msg)
{
    WIFI_LOGW("enter DealWpaLinkFailEvent.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return;
    }
    if (pStaStateMachine->IsNewConnectionInProgress()) {
        return;
    }
    pStaStateMachine->DealSetStaConnectFailedCount(1, false);
    int eventName = msg->GetMessageName();
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
    switch (eventName) {
        case WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT:
            DealWpaLinkPasswdWrongFailEvent(msg);
            break;
        case WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT:
            DealWpaLinkFullConnectFailEvent(msg);
            break;
        case WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT:
            DealWpaLinkAssocRejectFailEvent(msg);
            break;
        default:
            WIFI_LOGW("DealWpaLinkFailEvent unhandled %{public}d", eventName);
            return;
    }
    pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
}

/* --------------------------- state machine ApConnected State ------------------------------ */
StaStateMachine::ApLinkedState::ApLinkedState(StaStateMachine *staStateMachine)
    : State("ApLinkedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::ApLinkedState::~ApLinkedState()
{}

void StaStateMachine::ApLinkedState::GoInState()
{
    WIFI_LOGI("ApLinkedState GoInState function.");
    pStaStateMachine->SetConnectMethod(pStaStateMachine->connectMethod_);
    if ((WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_CLOSE) &&
        (pStaStateMachine->isAudioOn_ == AUDIO_OFF)) {
        pStaStateMachine->enableSignalPoll = false;
    } else {
        pStaStateMachine->enableSignalPoll = true;
    }
    if (!NetworkInterface::UpdateTcpMem()) {
        WIFI_LOGE("UpdateTcpMem() failed!");
    }
    return;
}

void StaStateMachine::ApLinkedState::GoOutState()
{
    WIFI_LOGI("ApLinkedState GoOutState function.");
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_NETWORK_NORELATED;
    pStaStateMachine->lastInternetIconStatus_ = SystemNetWorkState::NETWORK_DEFAULT_STATE;
    return;
}

bool StaStateMachine::ApLinkedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGD("ApLinkedState-msgCode=%{public}d received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->m_instId);
    bool ret = EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DISCONNECT:
            pStaStateMachine->StartDisConnectToNetwork();
            break;
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            HandleNetWorkConnectionEvent(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT: {
            HandleStaBssidChangedEvent(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_LINK_SWITCH_EVENT:
            HandleLinkSwitchEvent(msg);
            break;
        case CMD_SIGNAL_POLL:
            pStaStateMachine->DealSignalPollResult();
            break;
        case CMD_LINK_SWITCH_DETECT_TIMEOUT:
            pStaStateMachine->linkSwitchDetectingFlag_ = false;
            break;
#ifndef OHOS_ARCH_LITE
        case WIFI_SVR_CMD_STA_FOREGROUND_APP_CHANGED_EVENT:
            pStaStateMachine->HandleForegroundAppChangedAction(msg);
            break;
#endif
        case WIFI_SVR_COM_STA_START_ROAM:
            DealStartRoamCmdInApLinkedState(msg);
            break;
        case WIFI_SVR_CMD_STA_CSA_CHANNEL_SWITCH_EVENT:
            DealCsaChannelChanged(msg);
            break;
        default:
            ret = HandleExtMsg(msg);
            break;
    }
    return ret;
}

bool StaStateMachine::ApLinkedState::HandleExtMsg(InternalMessagePtr msg)
{
    bool ret = EXECUTED;
    switch (msg->GetMessageName()) {
        case CMD_NO_INTERNET_TIMEOUT:
            DealNoInternetTimeout();
            break;
        case WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT:
        case WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT:
        case WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT: {
            ret = EXECUTED;
            DealWpaLinkFailEventInApLinked(msg);
            break;
        }
        default:
            ret = NOT_EXECUTED;
            break;
    }
    return ret;
}

void StaStateMachine::ApLinkedState::HandleNetWorkConnectionEvent(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("HandleNetWorkConnectionEvent, msg is nullptr.\n");
        return;
    }
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("ApLinkedState reveived network connection event,bssid:%{public}s, ignore it.\n",
        MacAnonymize(bssid).c_str());
    pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
#ifndef OHOS_ARCH_LITE
    pStaStateMachine->UpdateLinkedInfoFromScanInfo();
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    pStaStateMachine->DealSignalPollResult();
    pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
    if (!pStaStateMachine->CanArpReachable()) {
        WIFI_LOGI("Arp not reachable, start to dhcp.");
        WriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::ROAMING_ABNORMAL));
        pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
    } else {
        WIFI_LOGI("Arp reachable, stay in linked state.");
    }
}

void StaStateMachine::ApLinkedState::HandleStaBssidChangedEvent(InternalMessagePtr msg)
{
    std::string reason = msg->GetStringFromMessage();
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("ApLinkedState received bssid changed event, reason:%{public}s,bssid:%{public}s.\n",
        reason.c_str(), MacAnonymize(bssid).c_str());
    if (strcmp(reason.c_str(), "ASSOC_COMPLETE") != 0) {
        WIFI_LOGE("Bssid change not for ASSOC_COMPLETE, do nothing.");
        return;
    }
    // do not switch to roaming state when it is not directed to roam by framework
    pStaStateMachine->linkedInfo.bssid = bssid;
    pStaStateMachine->UpdateHiLinkAttribute();
    pStaStateMachine->UpdateLinkedBssid(bssid);
#ifndef OHOS_ARCH_LITE
    pStaStateMachine->ResetWifi7WurInfo();
    pStaStateMachine->UpdateLinkedInfoFromScanInfo();
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    pStaStateMachine->DealSignalPollResult();
    pStaStateMachine->DealMloConnectionLinkInfo();
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
        pStaStateMachine->m_instId) != 0) {
        WIFI_LOGE("GetDeviceConfig failed, networkId = %{public}d", pStaStateMachine->linkedInfo.networkId);
        return;
    }
    if (pStaStateMachine->WhetherRestrictedByMdm(config.ssid, config.bssid, true)) {
        pStaStateMachine->ReportMdmRestrictedEvent(config.ssid, config.bssid, "BLOCK_LIST");
        pStaStateMachine->DealMdmRestrictedConnect(config);
        return;
    }
#endif
}

void StaStateMachine::ApLinkedState::HandleLinkSwitchEvent(InternalMessagePtr msg)
{
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("%{public}s enter, bssid:%{public}s, current linkedBssid: %{public}s",
        __FUNCTION__, MacAnonymize(bssid).c_str(), MacAnonymize(pStaStateMachine->linkedInfo.bssid).c_str());
    if (bssid == pStaStateMachine->linkedInfo.bssid) {
        return;
    }
    pStaStateMachine->linkSwitchDetectingFlag_ = true;
    pStaStateMachine->StopTimer(CMD_LINK_SWITCH_DETECT_TIMEOUT);
    pStaStateMachine->StartTimer(CMD_LINK_SWITCH_DETECT_TIMEOUT, STA_LINK_SWITCH_DETECT_DURATION);
    pStaStateMachine->AfterApLinkedprocess(bssid);
    pStaStateMachine->UpdateLinkedInfoFromScanInfo();
    pStaStateMachine->SetSupportedWifiCategory();
    pStaStateMachine->DealSignalPollResult();
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
}


void StaStateMachine::ApLinkedState::DealStartRoamCmdInApLinkedState(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is null", __FUNCTION__);
        return;
    }
    EnhanceWriteConnectTypeHiSysEvent(NETWORK_SELECTED_BY_ROAM);
    std::string bssid = msg->GetStringFromMessage();
    pStaStateMachine->targetRoamBssid = bssid;
    pStaStateMachine->linkSwitchDetectingFlag_ = false;
    WIFI_LOGI("%{public}s current bssid:%{public}s, target bssid:%{public}s,", __FUNCTION__,
        MacAnonymize(pStaStateMachine->linkedInfo.bssid).c_str(),
        MacAnonymize(pStaStateMachine->targetRoamBssid).c_str());
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
    if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, pStaStateMachine->targetRoamBssid, ifaceName)
        != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("%{public}s set roam target bssid fail", __FUNCTION__);
        return;
    }
    if (WifiStaHalInterface::GetInstance().Reassociate(ifaceName) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("%{public}s START_ROAM-ReAssociate() failed!", __FUNCTION__);
        return;
    }
    WIFI_LOGI("%{public}s START_ROAM-ReAssociate() succeeded!", __FUNCTION__);
    /* Start roaming */
    /* Only handle active roaming */
    pStaStateMachine->SwitchState(pStaStateMachine->pApRoamingState);
}

void StaStateMachine::ApLinkedState::DealCsaChannelChanged(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is null", __FUNCTION__);
        return;
    }
    int newFrq = msg->GetParam1();
    WIFI_LOGI("%{public}s update freq from %{public}d to %{public}d", __FUNCTION__,
        pStaStateMachine->linkedInfo.frequency, newFrq);
    if (newFrq == pStaStateMachine->linkedInfo.frequency) {
        return;
    }
    pStaStateMachine->linkedInfo.frequency = newFrq;
    pStaStateMachine->DealSignalPollResult();
    // trigger wifi connection broadcast to notify sta channel has changed for p2penhance
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
}

void StaStateMachine::ApLinkedState::DealNoInternetTimeout()
{
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->m_NetWorkState) {
        pStaStateMachine->m_NetWorkState->StartWifiDetection();
    }
#endif
}

void StaStateMachine::ApLinkedState::DealWpaLinkFailEventInApLinked(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealWpaLinkFailEventInApLinked InternalMessage msg is null.");
        return;
    }
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("DealWpaLinkFailEventInApLinked bssid=%{public}s,targetRoamBssid=%{public}s,"
        "isCurrentRoaming_=%{public}d", MacAnonymize(bssid).c_str(),
        MacAnonymize(pStaStateMachine->targetRoamBssid).c_str(), pStaStateMachine->isCurrentRoaming_);
    if (pStaStateMachine->isCurrentRoaming_ && bssid == pStaStateMachine->targetRoamBssid) {
        switch (msg->GetMessageName()) {
            case WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT: {
                pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_ROAMING_FAIL,
                    RoamingResultType::TYPE_ROAMING_PASSWD_WRONG);
                break;
            }
            case WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT: {
                pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_ROAMING_FAIL,
                    RoamingResultType::TYPE_ROAMING_FULL_CONNECT);
                break;
            }
            case WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT: {
                pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_ROAMING_FAIL,
                    RoamingResultType::TYPE_ROAMING_ASSOC_REJECT);
                break;
            }
            default:
                break;
        }
    }
    if (!pStaStateMachine->isCurrentRoaming_ ||  bssid == pStaStateMachine->targetRoamBssid) {
        pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
    }
}

void StaStateMachine::StartDisConnectToNetwork()
{
    WIFI_LOGI("Enter StartDisConnectToNetwork m_instId:%{public}d!", m_instId);
    /* Save connection information to WifiSettings. */
    SaveLinkstate(ConnState::DISCONNECTING, DetailedState::DISCONNECTING);
    InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTING, linkedInfo);
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().Disconnect(ifaceName) == WIFI_HAL_OPT_OK) {
        WIFI_LOGI("Disconnect() succeed!");
        WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID, ifaceName);
    } else {
        SaveLinkstate(ConnState::DISCONNECTING, DetailedState::FAILED);
        InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECT_FAILED, linkedInfo);
        WIFI_LOGE("Disconnect() failed m_instId:%{public}d!", m_instId);
    }
}

int StaStateMachine::RegisterDhcpCallBack()
{
    dhcpclientCallBack_.OnIpSuccessChanged = DhcpResultNotify::OnSuccess;
    dhcpclientCallBack_.OnIpFailChanged = DhcpResultNotify::OnFailed;
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    DhcpErrorCode dhcpRet = RegisterDhcpClientCallBack(ifname.c_str(), &dhcpclientCallBack_);
    if (dhcpRet != DHCP_SUCCESS) {
        WIFI_LOGE("RegisterDhcpClientCallBack failed. dhcpRet=%{public}d", dhcpRet);
        return DHCP_FAILED;
    }
    dhcpClientReport_.OnDhcpClientReport = DhcpResultNotify::OnDhcpOffer;
    RegisterDhcpClientReportCallBack(ifname.c_str(), &dhcpClientReport_);
    WIFI_LOGI("RegisterDhcpClientCallBack ok");
    return DHCP_SUCCESS;
}
/* --------------------------- state machine GetIp State ------------------------------ */
StaStateMachine::GetIpState::GetIpState(StaStateMachine *staStateMachine)
    : State("GetIpState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::GetIpState::~GetIpState()
{}

void StaStateMachine::GetIpState::GoInState()
{
    WIFI_HILOG_COMM_INFO("GetIpState GoInState function. m_instId=%{public}d", pStaStateMachine->m_instId);
#ifdef WIFI_DHCP_DISABLED
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::WORKING);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_ENABLED, pStaStateMachine->linkedInfo);
    pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
    return;
#endif
    pStaStateMachine->StopDhcp(false, true); // stop previous dhcp ipv6 first
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->NetSupplierInfo != nullptr) {
        pStaStateMachine->NetSupplierInfo->isAvailable_ = true;
        pStaStateMachine->NetSupplierInfo->isRoaming_ = pStaStateMachine->isRoam;
        pStaStateMachine->NetSupplierInfo->ident_ =
            WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
        WIFI_LOGI("On connect update net supplier info\n");
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(pStaStateMachine->NetSupplierInfo,
            pStaStateMachine->m_instId);
    }
#endif
    /* Callback result to InterfaceService. */
    pStaStateMachine->SaveLinkstate(ConnState::CONNECTING, DetailedState::OBTAINING_IPADDR);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP, pStaStateMachine->linkedInfo);
    WifiDeviceConfig config;
    AssignIpMethod assignMethod = AssignIpMethod::DHCP;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
        pStaStateMachine->m_instId);
    if (ret == 0) {
        assignMethod = config.wifiIpConfig.assignMethod;
    }
    bool isStaticIpv6 = false;
    bool isStaticIpv4 = false;
    // static ipv6 does not need dhcp
    WifiDeviceConfig wificonfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, wificonfig,
        pStaStateMachine->m_instId) == 0 && wificonfig.wifiIpConfig.assignMethod ==  AssignIpMethod::STATIC) {
        if (wificonfig.wifiIpConfig.staticIpAddress.ipAddress.address.family == 1) {
            WIFI_LOGI("Static IPv6 stop DHCP for ipv6.\n");
            isStaticIpv6 = true;
        } else if (wificonfig.wifiIpConfig.staticIpAddress.ipAddress.address.family == 0) {
            WIFI_LOGI("Static IPv4 stop DHCP for ipv4.\n");
            isStaticIpv4 = true;
        }
    }

    HandleStaticIpv6(isStaticIpv6);

    if (assignMethod == AssignIpMethod::STATIC) {
        pStaStateMachine->currentTpType = config.wifiIpConfig.staticIpAddress.ipAddress.address.family;
        if (!pStaStateMachine->ConfigStaticIpAddress(config.wifiIpConfig.staticIpAddress)) {
            pStaStateMachine->InvokeOnStaConnChanged(
                OperateResState::CONNECT_NETWORK_DISABLED, pStaStateMachine->linkedInfo);
            pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_DHCP_FAIL,
                DhcpFailType::TYPE_CONFIG_STATIC_IP_ADDRESS_FAIL);
            pStaStateMachine->StartDisConnectToNetwork();
            WIFI_HILOG_COMM_ERROR("ConfigstaticIpAddress failed!\n");
        }
    }
    pStaStateMachine->HandlePreDhcpSetup();

    bool isIpv6Disabled = SelfCureUtils::GetInstance().HasIpv6Disabled() &&
        (pStaStateMachine->m_instId == INSTID_WLAN1);
    if (isIpv6Disabled) {
        WIFI_LOGI("IPv6 wlan0 is disabled by selfcure and m_instId=%{public}d", pStaStateMachine->m_instId);
    }
    /* start dhcp */
    do {
        int dhcpRet;
        std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
        pStaStateMachine->currentTpType = static_cast<int>(
            WifiSettings::GetInstance().GetDhcpIpType(pStaStateMachine->m_instId));

        RouterConfig config;
        if (strncpy_s(config.bssid, sizeof(config.bssid),
            pStaStateMachine->linkedInfo.bssid.c_str(), pStaStateMachine->linkedInfo.bssid.size()) == EOK) {
            config.prohibitUseCacheIp = IsProhibitUseCacheIp();
        }
        config.isStaticIpv4 = isStaticIpv4;
        config.bIpv6 = !isStaticIpv6 && !isIpv6Disabled;
        config.bSpecificNetwork = pStaStateMachine->IsSpecificNetwork();
        if (strncpy_s(config.ifname, sizeof(config.ifname), ifname.c_str(), ifname.length()) != EOK) {
            break;
        }
        config.bIpv4 = true;
        pStaStateMachine->RegisterDhcpCallBack();
        dhcpRet = StartDhcpClient(config);
        LOGI("StartDhcpClient type:%{public}d dhcpRet:%{public}d isRoam:%{public}d m_instId=%{public}d" \
            "IsSpecificNetwork %{public}d", pStaStateMachine->currentTpType, dhcpRet, pStaStateMachine->isRoam,
            pStaStateMachine->m_instId, config.bSpecificNetwork);
        if (dhcpRet == 0) {
            // start timer to deal with dhcp timeout when not static ip
            if (!isStaticIpv4 && !isStaticIpv6) {
                WIFI_LOGI("StartTimer CMD_START_GET_DHCP_IP_TIMEOUT 30s");
                pStaStateMachine->StartTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT),
                    STA_SIGNAL_START_GET_DHCP_IP_DELAY);
            }
            return;
        }
    } while (0);
    EnhanceWriteDhcpFailHiSysEvent("START_DHCP_CLIENT_FAIL");
    WIFI_HILOG_COMM_ERROR("Dhcp connection failed, isRoam:%{public}d", pStaStateMachine->isRoam);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::OBTAINING_IPADDR_FAIL);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP_FAILED,
        pStaStateMachine->linkedInfo);
    if (!pStaStateMachine->isRoam) {
        pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_DHCP_FAIL,
            DhcpFailType::TYPE_DHCP_CONNECTION_FAIL);
        pStaStateMachine->StartDisConnectToNetwork();
    }
    return;
}

void StaStateMachine::GetIpState::GoOutState()
{
    WIFI_LOGI("GetIpState GoOutState function.");
    pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    pStaStateMachine->HandlePostDhcpSetup();
}

bool StaStateMachine::GetIpState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    bool ret = NOT_EXECUTED;
    WIFI_LOGI("GetIpState-msgCode=%{public}d received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->m_instId);
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT: {
            ret = EXECUTED;
            int result = msg->GetParam1();
            int ipType = msg->GetParam2();
            WIFI_HILOG_COMM_INFO("GetIpState, get ip result:%{public}d, ipType = %{public}d, m_instId = %{public}d\n",
                result, ipType, pStaStateMachine->m_instId);
            DealDhcpResultNotify(result, ipType);
            break;
        }
        case CMD_START_GET_DHCP_IP_TIMEOUT: {
            ret = EXECUTED;
            DealGetDhcpIpv4Timeout(msg);
            break;
        }
        case CMD_IPV6_DELAY_TIMEOUT: {
            ret = EXECUTED;
            pStaStateMachine->pDhcpResultNotify->DealDhcpJump();
            break;
        }
        default:
            break;
    }
    return ret;
}

void StaStateMachine::GetIpState::DealDhcpResultNotify(int result, int ipType) const
{
    switch (result) {
        case DhcpReturnCode::DHCP_RESULT: {
            pStaStateMachine->pDhcpResultNotify->DealDhcpResult(ipType);
            break;
        }
        case DhcpReturnCode::DHCP_JUMP: {
            pStaStateMachine->pDhcpResultNotify->DealDhcpJump();
            break;
        }
        case DhcpReturnCode::DHCP_FAIL: {
            pStaStateMachine->pDhcpResultNotify->DealDhcpIpv4ResultFailed();
            break;
        }
        case DhcpReturnCode::DHCP_OFFER_REPORT: {
            pStaStateMachine->pDhcpResultNotify->DealDhcpOfferResult();
            break;
        }
        default:
            break;
    }
}

void StaStateMachine::GetIpState::HandleStaticIpv6(bool isStaticIpv6)
{
#ifndef OHOS_ARCH_LITE
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
    if (isStaticIpv6) {
        NetManagerStandard::NetsysController::GetInstance().SetIpv6PrivacyExtensions(ifName, 1);
        NetManagerStandard::NetsysController::GetInstance().SetEnableIpv6(ifName, 1);
        NetManagerStandard::NetsysController::GetInstance().SetIpv6AutoConf(ifName, 0);
        WIFI_LOGI("Static IPv6 set enable ipv6 and disable ipv6 autoconf.\n");
    } else {
        NetManagerStandard::NetsysController::GetInstance().SetIpv6AutoConf(ifName, 1);
        WIFI_LOGI("Non-Static IPv6 set enable ipv6 autoconf.\n");
    }
#endif
}

void StaStateMachine::GetIpState::DealGetDhcpIpv4Timeout(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealGetDhcpIpv4Timeout InternalMessage msg is null.");
        return;
    }
    WIFI_HILOG_COMM_INFO("StopTimer CMD_START_GET_DHCP_IP_TIMEOUT DealGetDhcpIpv4Timeout");
    BlockConnectService::GetInstance().UpdateNetworkSelectStatus(pStaStateMachine->targetNetworkId_,
                                                                 DisabledReason::DISABLED_DHCP_FAILURE);
    BlockConnectService::GetInstance().NotifyWifiConnFailedInfo(pStaStateMachine->targetNetworkId_,
        pStaStateMachine->linkedInfo.bssid, DisabledReason::DISABLED_DHCP_FAILURE);
    pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_DHCP_FAIL,
        DhcpFailType::TYPE_GET_IP_TIMEOUT);
    pStaStateMachine->StartDisConnectToNetwork();
    EnhanceWriteDhcpFailHiSysEvent("DHCP_TIMEOUT");
}

bool StaStateMachine::GetIpState::IsPublicESS()
{
    constexpr int32_t BSS_NUM_MIN = 3;
    std::vector<WifiScanInfo> scanResults;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    if (scanResults.empty()) {
        WIFI_LOGI("IsPublicESS scanResults is empty");
        return false;
    }

    WifiLinkedInfo wifiLinkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(wifiLinkedInfo);
    std::string currentSsid = wifiLinkedInfo.ssid;
    if (currentSsid.empty()) {
        WIFI_LOGI("IsPublicESS currentSsid is empty");
        return false;
    }

    std::string capabilities = "";
    for (WifiScanInfo result : scanResults) {
        if (currentSsid == result.ssid) {
            capabilities = result.capabilities;
            break;
        }
    }
    if (capabilities.empty()) {
        WIFI_LOGI("IsPublicESS capabilities is empty");
        return false;
    }

    int32_t counter = 0;
    for (WifiScanInfo nextResult : scanResults) {
        if (currentSsid == nextResult.ssid && (strcmp(capabilities.c_str(), nextResult.capabilities.c_str()) == 0)) {
            counter += 1;
        }
    }
    WIFI_LOGI("IsPublicESS counter is %{public}d", counter);
    return counter >= BSS_NUM_MIN;
}

bool StaStateMachine::GetIpState::IsProhibitUseCacheIp()
{
    if (IsPublicESS()) {
        return true;
    }

    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
        pStaStateMachine->m_instId);
    if (config.keyMgmt == KEY_MGMT_WEP) {
        WIFI_LOGE("current keyMgmt is WEP, not use cache ip if dhcp timeout");
        return true;
    }
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->enhanceService_ != nullptr) {
        if (pStaStateMachine->enhanceService_->IsCustomNetwork(config)) {
            WIFI_LOGE("current network not use cache ip if dhcp timeout");
            return true;
        }
    }
#endif
    int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(
        pStaStateMachine->linkedInfo.rssi, pStaStateMachine->linkedInfo.band, pStaStateMachine->m_instId);
    if (currentSignalLevel < RSSI_LEVEL_3) {
        WIFI_LOGE("current rssi level is less than 3");
        return true;
    }
    return false;
}

void StaStateMachine::ReplaceEmptyDns(DhcpResult *result)
{
    if (result == nullptr) {
        WIFI_LOGE("Enter ReplaceEmptyDns::result is nullptr");
        return;
    }
    std::string strDns1 = result->strOptDns1;
    std::string strDns2 = result->strOptDns2;
    char wifiFirstDns[DNS_IP_ADDR_LEN + 1] = { 0 };
    char wifiSecondDns[DNS_IP_ADDR_LEN + 1] = { 0 };
    if (GetParamValue(WIFI_FIRST_DNS_NAME, 0, wifiFirstDns, DNS_IP_ADDR_LEN) <= 0) {
        WIFI_LOGE("ReplaceEmptyDns Get wifiFirstDns error");
        return;
    }
    if (GetParamValue(WIFI_SECOND_DNS_NAME, 0, wifiSecondDns, DNS_IP_ADDR_LEN) <= 0) {
        WIFI_LOGE("ReplaceEmptyDns Get wifiSecondDns error");
        return;
    }
    std::string strWifiFirstDns(wifiFirstDns);
    if (strDns1.empty()) {
        WIFI_LOGI("Enter ReplaceEmptyDns::dns1 is null");
        if (strDns2 == strWifiFirstDns) {
            if (strcpy_s(result->strOptDns1, INET_ADDRSTRLEN, wifiSecondDns) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns1 strcpy_s wifiSecondDns failed!");
            }
        } else {
            if (strcpy_s(result->strOptDns1, INET_ADDRSTRLEN, wifiFirstDns) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns1 strcpy_s wifiFirstDns failed!");
            }
        }
    }
    if (strDns2.empty()) {
        WIFI_LOGI("Enter ReplaceEmptyDns::dns2 is null");
        if (strDns1 == strWifiFirstDns) {
            if (strcpy_s(result->strOptDns2, INET_ADDRSTRLEN, wifiSecondDns) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns2 strcpy_s wifiSecondDns failed!");
            }
        } else {
            if (strcpy_s(result->strOptDns2, INET_ADDRSTRLEN, wifiFirstDns) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns2 strcpy_s wifiFirstDns failed!");
            }
        }
    }
}

/* --- state machine GetIp State functions ----- */
bool StaStateMachine::ConfigStaticIpAddress(StaticIpAddress &staticIpAddress)
{
    WIFI_LOGI("Enter StaStateMachine::SetDhcpResultFromStatic.");
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    DhcpResult result;
    switch (currentTpType) {
        case IPTYPE_IPV4: {
            result.iptype = IPTYPE_IPV4;
            if (strcpy_s(result.strOptClientId, DHCP_MAX_FILE_BYTES,
                staticIpAddress.ipAddress.address.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.gateway.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, DHCP_MAX_FILE_BYTES, staticIpAddress.GetIpv4Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer1.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer2.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            ReplaceEmptyDns(&result);
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            break;
        }
        case IPTYPE_IPV6: {
            result.iptype = IPTYPE_IPV6;
            if (strcpy_s(result.strOptClientId, DHCP_MAX_FILE_BYTES,
                staticIpAddress.ipAddress.address.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.gateway.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, DHCP_MAX_FILE_BYTES, staticIpAddress.GetIpv6Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer1.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer2.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            break;
        }
        case IPTYPE_MIX: {
            result.iptype = IPTYPE_IPV4;
            if (strcpy_s(result.strOptClientId, DHCP_MAX_FILE_BYTES,
                staticIpAddress.ipAddress.address.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.gateway.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, DHCP_MAX_FILE_BYTES,
                staticIpAddress.GetIpv4Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer1.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer2.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            if (strcpy_s(result.strOptClientId, DHCP_MAX_FILE_BYTES,
                staticIpAddress.ipAddress.address.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.gateway.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, DHCP_MAX_FILE_BYTES, staticIpAddress.GetIpv6Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer1.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, DHCP_MAX_FILE_BYTES,
                staticIpAddress.dnsServer2.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            break;
        }

        default:
            WIFI_LOGE("Invalid currentTpType: %{public}d", currentTpType);
            return false;
    }
    return true;
}

void StaStateMachine::HandlePortalNetworkPorcess()
{
#ifndef OHOS_ARCH_LITE
    if (mPortalUrl.empty()) {
        WIFI_LOGE("portal uri is nullptr\n");
    }
    if (!m_NetWorkState) {
        WIFI_LOGE("m_NetWorkState is nullptr\n");
        return;
    }
    int netId = m_NetWorkState->GetWifiNetId();
    int deviceType = WifiConfigCenter::GetInstance().GetDeviceType();
    if (enhanceService_ != nullptr) {
        mPortalUrl = enhanceService_->CheckPortalNet(linkedInfo.ssid, mPortalUrl);
    }
    RecordPortalInfo();
#ifndef SUPPORT_PORTAL_LOGIN
    AAFwk::Want want;
    want.SetParam("netId", netId);
    std::string bundle = WifiSettings::GetInstance().GetPackageName("BROWSER_BUNDLE");
    want.SetAction(PORTAL_ACTION);
    want.SetUri(mPortalUrl);
    want.AddEntity(PORTAL_ENTITY);
    want.SetBundle(bundle);
    WIFI_LOGI("want browser wifi netId is %{public}d, deviceType is %{public}d", netId, deviceType);
    OHOS::ErrCode err = WifiNotificationUtil::GetInstance().StartAbility(want);
    if (err != ERR_OK) {
        WIFI_LOGI("want browser StartAbility is failed %{public}d", err);
        EnhanceWriteBrowserFailedForPortalHiSysEvent(err, mPortalUrl);
        err = StartPortalLogin(netId, mPortalUrl, deviceType);
    }
#else
    OHOS::ErrCode err = StartPortalLogin(netId, mPortalUrl, deviceType);
#endif
#endif
    WifiConfigCenter::GetInstance().SetBrowserState(err == ERR_OK);
}

OHOS::ErrCode StaStateMachine::StartPortalLogin(int netId, std::string url, int deviceType)
{
    AAFwk::Want want;
    want.SetParam("netId", netId);
    want.SetElementName("com.wifiservice.portallogin", "EntryAbility");
    want.SetParam("url", url);
    want.SetParam("shouldShowBrowseItem", deviceType != ProductDeviceType::TV);
    WIFI_LOGI("portal login wifi netId is %{public}d, deviceType is %{public}d", netId, deviceType);
    OHOS::ErrCode err = WifiNotificationUtil::GetInstance().StartAbility(want);
    if (err != ERR_OK) {
        WIFI_LOGE("want portal login StartAbility is failed %{public}d", err);
        EnhanceWriteBrowserFailedForPortalHiSysEvent(err, url);
    }
    return err;
}
 
void StaStateMachine::RecordPortalInfo()
{
    std::string wifiCountryCode;
    WifiCountryCodeManager::GetInstance().GetWifiCountryCode(wifiCountryCode);
    bool isCN = wifiCountryCode == DEFAULT_REGION;
 
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    bool isEverConnected = WifiSettings::GetInstance().GetDeviceEverConnected(linkedInfo.networkId);
 
    WritePortalInfoHiSysEvent(isCN, isEverConnected);
}

void StaStateMachine::SetPortalBrowserFlag(bool flag)
{
    autoPullBrowserFlag = flag;
    mIsWifiInternetCHRFlag = false;
    if (!WifiConfigCenter::GetInstance().GetWifiSelfcureReset()) {
        WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(false);
    }
    if (!flag) {
        portalState = PortalState::UNCHECKED;
    }
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::ShowPortalNitification()
{
    WifiDeviceConfig wifiDeviceConfig = getCurrentWifiDeviceConfig();
    bool hasInternetEver =
        NetworkStatusHistoryManager::HasInternetEverByHistory(wifiDeviceConfig.networkStatusHistory);
    if (hasInternetEver) {
        WifiNotificationUtil::GetInstance().PublishWifiNotification(
            WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
            WifiNotificationStatus::WIFI_PORTAL_TIMEOUT);
    } else {
        std::string bundle = WifiSettings::GetInstance().GetPackageName("SETTINGS");
        if (WifiAppStateAware::GetInstance().IsForegroundApp(bundle)) {
            WifiNotificationUtil::GetInstance().PublishWifiNotification(
                WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
                WifiNotificationStatus::WIFI_PORTAL_CONNECTED);
            autoPullBrowserFlag = false;
        } else {
            WifiNotificationUtil::GetInstance().PublishWifiNotification(
                WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
                WifiNotificationStatus::WIFI_PORTAL_FOUND);
        }
    }
}
#endif

void StaStateMachine::StartDetectTimer(int detectType)
{
    if (detectType == DETECT_TYPE_PERIODIC) {
        /* Obtains the current time, accurate to milliseconds. */
        struct timespec curTime = {0, 0};
        if (clock_gettime(CLOCK_BOOTTIME, &curTime) != 0) {
            WIFI_LOGE("HandleNetCheckResult clock_gettime failed.");
            return;
        }
        int64_t nowTime = static_cast<int64_t>(curTime.tv_sec) * PORTAL_MILLSECOND +
            curTime.tv_nsec / (PORTAL_MILLSECOND * PORTAL_MILLSECOND);
        if (nowTime - lastTimestamp > PORTAL_CHECK_TIME * PORTAL_MILLSECOND) {
            detectNum++;
            StartTimer(static_cast<int>(CMD_START_NETCHECK), PORTAL_CHECK_TIME * PORTAL_MILLSECOND);
            lastTimestamp = nowTime;
        }
    } else if (detectType == DETECT_TYPE_DEFAULT) {
        StartTimer(static_cast<int>(CMD_START_NETCHECK), 0);
    } else if (detectType == DETECT_TYPE_CHECK_PORTAL_EXPERIED) {
        StartTimer(static_cast<int>(CMD_START_NETCHECK), PORTAL_AUTH_EXPIRED_CHECK_TIME * PORTAL_MILLSECOND);
    }
}

void StaStateMachine::PortalExpiredDetect()
{
    if (portalState == PortalState::EXPERIED) {
        if (portalExpiredDetectCount < PORTAL_EXPERIED_DETECT_MAX_COUNT) {
            portalExpiredDetectCount++;
            StartDetectTimer(DETECT_TYPE_CHECK_PORTAL_EXPERIED);
        } else if (portalExpiredDetectCount == PORTAL_EXPERIED_DETECT_MAX_COUNT) {
            portalExpiredDetectCount = 0;
            auto config = getCurrentWifiDeviceConfig();
            EnhanceWritePortalAuthExpiredHisysevent(static_cast<int>(SystemNetWorkState::NETWORK_IS_PORTAL),
                detectNum, config.lastConnectTime, config.portalAuthTime, false);
        }
    }
}

void StaStateMachine::GetDetectNetState(OperateResState &state)
{
    state = lastCheckNetState_;
}

void StaStateMachine::UpdatePortalState(SystemNetWorkState netState, bool &updatePortalAuthTime)
{
    if (netState == SystemNetWorkState::NETWORK_IS_WORKING) {
        if (portalState == PortalState::UNCHECKED) {
            auto config = getCurrentWifiDeviceConfig();
            portalState = config.isPortal ? PortalState::AUTHED : PortalState::NOT_PORTAL;
        } else if (portalState == PortalState::UNAUTHED || portalState == PortalState::EXPERIED) {
            portalState = PortalState::AUTHED;
            updatePortalAuthTime = true;
        }
    } else if (netState == SystemNetWorkState::NETWORK_IS_PORTAL) {
        if (portalState == PortalState::UNCHECKED) {
            portalState = PortalState::UNAUTHED;
        } else if (portalState == PortalState::AUTHED || portalState == PortalState::NOT_PORTAL) {
            portalState = PortalState::EXPERIED;
            portalExpiredDetectCount = 0;
        }
        PortalExpiredDetect();
    }
    EnhanceWritePortalStateHiSysEvent(portalEventValues.count(portalState) > 0 ?
        portalEventValues.at(portalState) : HISYS_EVENT_DEFAULT_VALUE);
}

void StaStateMachine::NetStateObserverCallback(SystemNetWorkState netState, std::string url)
{
    SendMessage(WIFI_SVR_CMD_STA_NET_DETECTION_NOTIFY_EVENT, netState, 0, url);
#ifndef OHOS_ARCH_LITE
    if (enhanceService_ == nullptr) {
        WIFI_LOGE("NetStateObserverCallback, enhanceService is null");
        return;
    }
    enhanceService_->NotifyInternetState(static_cast<int>(netState));
#endif
}

void StaStateMachine::RegisterCustomEapCallback(const std::string &regCmd) //netType:regSize:reg1:reg2
{
#ifdef EXTENSIBLE_AUTHENTICATION
    const int preNumberCount = 2;
    auto CheckStrEapData = [regCmd](const std::string &data) -> bool {
        if (data.empty()) {
            WIFI_LOGI("%{public}s regCmd is empty", __func__);
            return false;
        }
        std::vector<std::string> vecEapDatas = GetSplitInfo(data, ":");
        if (vecEapDatas.size() < 2) {
            WIFI_LOGI("%{public}s regCmd invalid, regCmd[%{public}s]", __func__, regCmd.c_str());
            return false;
        }
        if (static_cast<int>(CheckDataToUint(vecEapDatas[0])) != static_cast<int>(NetManagerStandard::NetType::WLAN0)) {
            WIFI_LOGI("%{public}s netType not WLAN0, regCmd[%{public}s]", __func__, regCmd.c_str());
            return false;
        }
        if (CheckDataToUint(vecEapDatas[1]) + preNumberCount != vecEapDatas.size()) {
            WIFI_LOGI("%{public}s reg eapdata size error, regCmd[%{public}s]", __func__, regCmd.c_str());
            return false;
        }
        return true;
    };
    if (!CheckStrEapData(regCmd)) {
        WIFI_LOGI("%{public}s regcmd error, regCmd[%{public}s]", __func__, regCmd.c_str());
        return;
    }
    std::string cmd = "EXT_AUTH_REG ";
    cmd += regCmd;
    WIFI_LOGI("%{public}s regCmd:%{public}s", __func__, cmd.c_str());
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("%{public}s: failed to send the message, Custom Eap cmd: %{private}s", __func__, cmd.c_str());
        return;
    }
#endif
}

void StaStateMachine::ReplyCustomEapDataCallback(int result, const std::string &strEapData)
{
#ifdef EXTENSIBLE_AUTHENTICATION
    std::string cmd = "EXT_AUTH_DATA ";
    cmd += std::to_string(result);
    cmd += std::string(":");
    cmd += strEapData;
    WIFI_LOGI("%{public}s, reply result:%{public}d", __func__, result);
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("%{public}s: failed to send the message", __func__);
        return;
    }
#endif
}

void StaStateMachine::HandleNetCheckResult(SystemNetWorkState netState, const std::string &portalUrl)
{
    WIFI_LOGD("Enter HandleNetCheckResult, netState:%{public}d screen:%{public}d "
        "oldPortalState:%{public}d chrFlag:%{public}d.",
        netState, enableSignalPoll, portalState, mIsWifiInternetCHRFlag);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGE("connState is NOT in connected state, connState:%{public}d\n", linkedInfo.connState);
        EnhanceWriteIsInternetHiSysEvent(NO_NETWORK);
        return;
    }
    if (!portalUrl.empty()) {
        mPortalUrl = portalUrl;
    }
    bool isTxRxGoodButNoInternet = false;
    /*when detect result is NETWORK_NOTWORKING but tx rx is good, considered as NETWORK_IS_WORKING*/
    if (netState == SystemNetWorkState::NETWORK_NOTWORKING &&
        IpQosMonitor::GetInstance().GetTxRxStatus() &&
        WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_OPEN) {
        WIFI_LOGI("net detection result is NETWORK_NOTWORKING but tx rx is good, considered as NETWORK_IS_WORKING");
        netState = SystemNetWorkState::NETWORK_IS_WORKING;
        isTxRxGoodButNoInternet = true;
    }
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (selfCureService_ != nullptr) {
        selfCureService_->NotifyTxRxGoodButNoInternet(isTxRxGoodButNoInternet);
    }
#endif
    bool updatePortalAuthTime = false;
    if (netState == SystemNetWorkState::NETWORK_IS_WORKING) {
        HandleNetCheckResultIsWorking(netState, updatePortalAuthTime);
    } else if (netState == SystemNetWorkState::NETWORK_IS_PORTAL) {
        HandleNetCheckResultIsPortal(netState, updatePortalAuthTime);
    } else {
        HandleNetCheckResultIsNotWorking(netState);
    }
#ifndef OHOS_ARCH_LITE
    SyncDeviceEverConnectedState(true);
#endif
    autoPullBrowserFlag = true;
    TryModifyPortalAttribute(netState);
    HandleInternetAccessChanged(netState);
}

void StaStateMachine::HandleNetCheckResultIsWorking(SystemNetWorkState netState, bool updatePortalAuthTime)
{
    if (lastCheckNetState_ != OperateResState::CONNECT_NETWORK_ENABLED) {
        WifiCommonEventHelper::PublishNetCheckResultChange(netState, "WorkingNetwork");
    }
    mIsWifiInternetCHRFlag = false;
    UpdatePortalState(netState, updatePortalAuthTime);
    /* Save connection information to WifiSettings. */
    EnhanceWriteIsInternetHiSysEvent(NETWORK);
    WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(false);
    SaveLinkstate(ConnState::CONNECTED, DetailedState::WORKING);
    InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_ENABLED, linkedInfo);
    lastCheckNetState_ = OperateResState::CONNECT_NETWORK_ENABLED;
    InsertOrUpdateNetworkStatusHistory(NetworkStatus::HAS_INTERNET, updatePortalAuthTime);
    if (getCurrentWifiDeviceConfig().isPortal) {
        StartDetectTimer(DETECT_TYPE_PERIODIC);
    }
    mPortalUrl = "";
#ifndef OHOS_ARCH_LITE
    UpdateAcceptUnvalidatedState();
    WifiNotificationUtil::GetInstance().CancelWifiNotification(
        WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID);
    if (hasNoInternetDialog_) {
        CloseNoInternetDialog();
    }
#endif
}

void StaStateMachine::HandleNetCheckResultIsPortal(SystemNetWorkState netState, bool updatePortalAuthTime)
{
    if (lastCheckNetState_ != OperateResState::CONNECT_CHECK_PORTAL) {
        WifiCommonEventHelper::PublishNetCheckResultChange(netState, "PortalNetwork");
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    UpdatePortalState(netState, updatePortalAuthTime);
    /* The tv doesn't need to publish the portal login page when connecting to a Hilink router without internet. */
    if (GetDeviceType() != ProductDeviceType::TV) {
        PublishPortalNitificationAndLogin();
    }
    bool isHomeAp = false;
    bool isHomeRouter = false;
#ifndef OHOS_ARCH_LITE
    isHomeAp = WifiHistoryRecordManager::GetInstance().IsHomeAp(linkedInfo.bssid);
    isHomeRouter = WifiHistoryRecordManager::GetInstance().IsHomeRouter(mPortalUrl);
#endif
    EnhanceWriteIsInternetHiSysEvent(NO_NETWORK);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config, m_instId);
    WIFI_LOGD("%{public}s, isHiLinkNetwork : %{public}d isHomeAp : %{public}d isHomeRouter : %{public}d keyMgmt : "
              "%{public}s", __func__, linkedInfo.isHiLinkNetwork, isHomeAp, isHomeRouter, config.keyMgmt.c_str());
    if ((InternalHiLinkNetworkToBool(linkedInfo.isHiLinkNetwork) || isHomeAp || isHomeRouter)
        && config.keyMgmt != KEY_MGMT_NONE) {
        // Change the value of PORTAL in networkStatusHistory to NO_INTERNET
        WifiDeviceConfig wifiDeviceConfig = getCurrentWifiDeviceConfig();
        NetworkStatusHistoryManager::ModifyAllHistoryRecord(wifiDeviceConfig.networkStatusHistory,
            NetworkStatus::PORTAL, NetworkStatus::NO_INTERNET);
        WifiSettings::GetInstance().AddDeviceConfig(wifiDeviceConfig);
        WifiSettings::GetInstance().SyncDeviceConfig();

        InsertOrUpdateNetworkStatusHistory(NetworkStatus::NO_INTERNET, false);
        SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
        InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_DISABLED, linkedInfo);
        if (!mIsWifiInternetCHRFlag) {
            EnhanceWriteWifiAccessIntFailedHiSysEvent(1, NetworkFailReason::DNS_STATE_UNREACHABLE, 1, "");
            mIsWifiInternetCHRFlag = true;
        }
    } else {
        if (GetDeviceType() == ProductDeviceType::TV) {
            PublishPortalNitificationAndLogin();
        }
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::PORTAL, false);
        SaveLinkstate(ConnState::CONNECTED, DetailedState::CAPTIVE_PORTAL_CHECK);
        InvokeOnStaConnChanged(OperateResState::CONNECT_CHECK_PORTAL, linkedInfo);
    }
    lastCheckNetState_ = OperateResState::CONNECT_CHECK_PORTAL;
}

void StaStateMachine::HandleNetCheckResultIsNotWorking(SystemNetWorkState netState)
{
    if (lastCheckNetState_ != OperateResState::CONNECT_NETWORK_DISABLED) {
        WifiCommonEventHelper::PublishNetCheckResultChange(netState, "NotWorkingNetwork");
    }
    EnhanceWriteIsInternetHiSysEvent(NO_NETWORK);
#ifndef OHOS_ARCH_LITE
    SyncDeviceEverConnectedState(false);
#endif
    SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
    InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_DISABLED, linkedInfo);
    lastCheckNetState_ = OperateResState::CONNECT_NETWORK_DISABLED;
    InsertOrUpdateNetworkStatusHistory(NetworkStatus::NO_INTERNET, false);
// if wifipro is open, wifipro will notify selfcure no internet, if not, sta should notify
#ifndef FEATURE_WIFI_PRO_SUPPORT
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (selfCureService_ != nullptr) {
        selfCureService_->NotifyInternetFailureDetected(false);
    }
#endif
#endif
}

void StaStateMachine::PublishPortalNitificationAndLogin()
{
#ifndef OHOS_ARCH_LITE
    if (m_instId != INSTID_WLAN0) {
        WIFI_LOGI("%{public}s not allow publish, m_instId:%{public}d", __func__, m_instId);
        return;
    }
    if (!WifiConfigCenter::GetInstance().IsAllowPopUp()) {
        return;
    }
    if (selfCureService_ != nullptr && selfCureService_->IsSelfCureOnGoing()) {
        WIFI_LOGI("%{public}s not allow publish, SelfCureOnGoing", __func__);
        return;
    }
    if (lastCheckNetState_ == OperateResState::CONNECT_NETWORK_ENABLED) {
        WIFI_LOGI("%{public}s not allow publish, lastCheckNetState:%{public}d, recheck", __func__, lastCheckNetState_);
        StartDetectTimer(DETECT_TYPE_DEFAULT);
        portalReCheck_ = true;
        return;
    }
    if (lastCheckNetState_ == OperateResState::CONNECT_CHECK_PORTAL && !portalReCheck_) {
        return;
    }
    WIFI_LOGI("%{public}s, ShowPortalNitification recheck %{public}d", __func__, portalReCheck_);
    ShowPortalNitification();
    portalReCheck_ = false;
#endif
    if (!autoPullBrowserFlag) {
        HandlePortalNetworkPorcess();
        autoPullBrowserFlag = true;
    }
}

void StaStateMachine::TryModifyPortalAttribute(SystemNetWorkState netState)
{
    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config, m_instId);
    if (linkedInfo.networkId == INVALID_NETWORK_ID || ret != 0 || !config.isPortal ||
        config.keyMgmt == KEY_MGMT_NONE) {
        return;
    }
    bool needChangePortalFlag = false;
    bool isHomeAp = false;
    bool isHomeRouter = false;
#ifndef OHOS_ARCH_LITE
    isHomeAp = WifiHistoryRecordManager::GetInstance().IsHomeAp(linkedInfo.bssid);
    isHomeRouter = WifiHistoryRecordManager::GetInstance().IsHomeRouter(mPortalUrl);
#endif
    bool isPortalByHistory = NetworkStatusHistoryManager::IsPortalByHistory(config.networkStatusHistory);
    switch (netState) {
        case SystemNetWorkState::NETWORK_NOTWORKING:
            if (isPortalByHistory) {
                WIFI_LOGI("%{public}s, no internet and has portal status in history, not modify", __func__);
                break;
            }
            needChangePortalFlag = true;
            break;
        case SystemNetWorkState::NETWORK_IS_WORKING:
            if (!InternalHiLinkNetworkToBool(linkedInfo.isHiLinkNetwork) && !isHomeAp && !isHomeRouter) {
                WIFI_LOGI("%{public}s, has internet and not hilink/homeAp/homeRouter network, not modify", __func__);
                break;
            }
            if (isPortalByHistory) {
                WIFI_LOGI("%{public}s, has internet and has portal status in history, not modify", __func__);
                break;
            }
            needChangePortalFlag = true;
            break;
        case SystemNetWorkState::NETWORK_IS_PORTAL:
            if (!InternalHiLinkNetworkToBool(linkedInfo.isHiLinkNetwork) && !isHomeAp && !isHomeRouter) {
                WIFI_LOGI("%{public}s, portal and not hilink/homeAp/homeRouter network, not modify", __func__);
                break;
            }
            needChangePortalFlag = true;
            break;
        default:
            break;
    }
    ChangePortalAttribute(needChangePortalFlag, config);
}

void StaStateMachine::ChangePortalAttribute(bool isNeedChange, WifiDeviceConfig &config)
{
    if (!isNeedChange) {
        return;
    }
    WIFI_LOGI("change the value of the portal attribute to false, bssid=%{public}s",
        MacAnonymize(config.bssid).c_str());
    config.isPortal = false;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::SyncDeviceEverConnectedState(bool hasNet)
{
    if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE
        || !WifiConfigCenter::GetInstance().IsAllowPopUp()
        || !WifiConfigCenter::GetInstance().IsAllowPcPopUp()) {
        WIFI_LOGI("factory version or device type no need to pop up diag");
        return;
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    std::string settings = WifiSettings::GetInstance().GetPackageName("SETTINGS");
    if (!WifiSettings::GetInstance().GetDeviceEverConnected(networkId)) {
        if (!hasNet) {
            /*If it is the first time to connect and no network status, a pop-up window is displayed.*/
            WifiNotificationUtil::GetInstance().ShowSettingsDialog(WifiDialogType::CDD, settings);
            hasNoInternetDialog_ = true;
        }
        WifiSettings::GetInstance().SetDeviceEverConnected(networkId);
        WIFI_LOGI("First connection, Set DeviceEverConnected true, network is %{public}d", networkId);
        WifiSettings::GetInstance().SyncDeviceConfig();
    }
}
#endif

#ifndef OHOS_ARCH_LITE
void StaStateMachine::UpdateAcceptUnvalidatedState()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    if (WifiSettings::GetInstance().GetAcceptUnvalidated(networkId)) {
        WIFI_LOGI("network is recover, change the value of AcceptUnvalidated to false");
        WifiSettings::GetInstance().SetAcceptUnvalidated(networkId, false);
        WifiSettings::GetInstance().SyncDeviceConfig();
    }
}
#endif

#ifndef OHOS_ARCH_LITE
void StaStateMachine::CloseNoInternetDialog()
{
    bool sendsuccess = WifiCommonEventHelper::PublishNotAvailableDialog();
    hasNoInternetDialog_ = false;
    WIFI_LOGI("Notification cancellation SettingsDialog is %{public}d", sendsuccess);
}
#endif
/* --------------------------- state machine Connected State ------------------------------ */
StaStateMachine::LinkedState::LinkedState(StaStateMachine *staStateMachine)
    : State("LinkedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::LinkedState::~LinkedState()
{}

void StaStateMachine::LinkedState::GoInState()
{
    if (pStaStateMachine == nullptr) {
        return;
    }
    WIFI_LOGI("LinkedState GoInState function. m_instId = %{public}d", pStaStateMachine->m_instId);
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
        static_cast<int>(WifiOperateState::STA_CONNECTED));
    EnhanceWriteWifiLinkTypeHiSysEvent(pStaStateMachine->linkedInfo.ssid,
        pStaStateMachine->linkedInfo.wifiLinkType, "CONNECT");
#ifndef OHOS_ARCH_LITE
    CheckIfRestoreWifi();
#endif
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->m_NetWorkState != nullptr) {
        pStaStateMachine->m_NetWorkState->StartNetStateObserver(pStaStateMachine->m_NetWorkState);
        pStaStateMachine->lastTimestamp = 0;
        pStaStateMachine->StartDetectTimer(DETECT_TYPE_DEFAULT);
    }
#endif
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    pStaStateMachine->wifiDataReportService_->ReportApConnEventInfo(ConnReportReason::CONN_SUC_START,
        pStaStateMachine->targetNetworkId_);
#endif
#endif
    pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    WifiSettings::GetInstance().SetDeviceAfterConnect(pStaStateMachine->linkedInfo.networkId,
        pStaStateMachine->linkedInfo.rssi);
    WifiSettings::GetInstance().ClearAllNetworkConnectChoice();
    BlockConnectService::GetInstance().EnableNetworkSelectStatus(pStaStateMachine->linkedInfo.networkId);
#ifndef OHOS_ARCH_LITE
    BlockConnectService::GetInstance().ReleaseUnusableBssidSet();
    BlockConnectService::GetInstance().ReleaseDhcpFailBssidSet();
#endif
    WifiSettings::GetInstance().SyncDeviceConfig();
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
#ifdef DYNAMIC_ADJUST_WIFI_POWER_SAVE
    DealWifiPowerSaveWhenWifiConnected();
#endif
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("Start requesting GRS network detection");
    if (!GrsNetworkProbe()) {
        WIFI_LOGD("Detection cannot be obtained or the detection has failed.");
    }
#endif
    return;
}

void StaStateMachine::LinkedState::GoOutState()
{
    WIFI_LOGI("LinkedState GoOutState function.");
}

bool StaStateMachine::LinkedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("msg is nullptr.");
        return false;
    }

    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT: {
            ret = EXECUTED;
            DhcpResultNotify(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_NET_DETECTION_NOTIFY_EVENT: {
            ret = EXECUTED;
            NetDetectionNotify(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_PORTAL_BROWSE_NOTIFY_EVENT: {
            ret = EXECUTED;
            pStaStateMachine->HandlePortalNetworkPorcess();
            break;
        }
        case CMD_START_NETCHECK : {
            ret = EXECUTED;
            DealNetworkCheck(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_FOLD_STATUS_NOTIFY_EVENT: {
            ret = EXECUTED;
            FoldStatusNotify(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_REDHCP: {
            ret = EXECUTED;
            WIFI_LOGI("recv redhcp command");
            pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
            break;
        }
        default:
            ret = ProcessMessageByMacros(msg);
            break;
    }

    return ret;
}

bool StaStateMachine::LinkedState::ProcessMessageByMacros(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("msg is nullptr.");
        return false;
    }

    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
#ifdef DYNAMIC_ADJUST_WIFI_POWER_SAVE
        case WIFI_BATTERY_STATE_CHANGED_NOTIFY_EVENT: {
            ret = EXECUTED;
            DealWifiPowerSaveWhenBatteryStatusNotify(msg);
            break;
        }
        case WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT: {
            ret = EXECUTED;
            DealWifiPowerSaveWhenScreenStatusNotify(msg);
            break;
        }
#endif
#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
        case WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT: {
            ret = EXECUTED;
            int wpaState = msg->GetParam1();
            WIFI_LOGI("Report wpaState = %{public}d", wpaState);
            if (wpaState == static_cast<int>(SupplicantState::COMPLETED)) {
                pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED,
                    pStaStateMachine->linkedInfo);
            }
            break;
        }
#endif
        default:
            break;
    }

    return ret;
}

#ifndef OHOS_ARCH_LITE
bool StaStateMachine::LinkedState::GrsNetworkProbe()
{
    if (pStaStateMachine->enhanceService_ != nullptr) {
        return pStaStateMachine->enhanceService_->GrsProbe();
    } else {
        return false;
    }
}
#endif

void StaStateMachine::LinkedState::DhcpResultNotify(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }

    int result = msg->GetParam1();
    int ipType = msg->GetParam2();
    WIFI_HILOG_COMM_INFO("LinkedState, result:%{public}d, ipType = %{public}d\n", result, ipType);
    if (result == DhcpReturnCode::DHCP_RENEW_FAIL) {
        pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    } else if (result == DhcpReturnCode::DHCP_RESULT) {
        pStaStateMachine->pDhcpResultNotify->DealDhcpResult(ipType);
    } else if (result == DhcpReturnCode::DHCP_IP_EXPIRED) {
        pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_DHCP_FAIL,
            DhcpFailType::TYPE_IP_EXPIRED);
        pStaStateMachine->StartDisConnectToNetwork();
    } else if (result == DhcpReturnCode::DHCP_OFFER_REPORT) {
        pStaStateMachine->pDhcpResultNotify->DealDhcpOfferResult();
    }
}

void StaStateMachine::LinkedState::FoldStatusNotify(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    pStaStateMachine->foldStatus_ = msg->GetParam1();
    if (pStaStateMachine->foldStatus_ == HALF_FOLD) {
        isExpandUpdateRssi_ = true;
        pStaStateMachine->StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
        pStaStateMachine->DealSignalPollResult();
    } else if (pStaStateMachine->foldStatus_ == EXPAND) {
        isExpandUpdateRssi_ = false;
    } else {
        isExpandUpdateRssi_ = true;
    }
}

#ifdef DYNAMIC_ADJUST_WIFI_POWER_SAVE
void StaStateMachine::LinkedState::DealWifiPowerSaveWhenBatteryStatusNotify(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    int noChargerPlugModeState = msg->GetParam1();
    if (noChargerPlugModeState == MODE_STATE_CLOSE) {
        WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(false, pStaStateMachine->m_instId);
    } else if (noChargerPlugModeState == MODE_STATE_OPEN) {
        WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(true, pStaStateMachine->m_instId);
    } else {
        WIFI_LOGE("noChargerPlugModeState is %{public}d", noChargerPlugModeState);
    }
}

void StaStateMachine::LinkedState::DealWifiPowerSaveWhenScreenStatusNotify(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    int screenState = msg->GetParam1();
    bool isCharged = WifiConfigCenter::GetInstance().GetNoChargerPlugModeState() == MODE_STATE_CLOSE;
    WIFI_LOGI("notify screenstate = %{public}d, isCharged = %{public}d", screenState, isCharged);
    if (screenState == MODE_STATE_OPEN) {
        WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(!isCharged, pStaStateMachine->m_instId);
    } else if (screenState == MODE_STATE_CLOSE) {
        WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(true, pStaStateMachine->m_instId);
    } else {
        WIFI_LOGE("unexpected screen state");
    }
    pStaStateMachine->DealScreenStateChangedEvent(msg);
}

void StaStateMachine::LinkedState::DealWifiPowerSaveWhenWifiConnected()
{
    bool isCharged = WifiConfigCenter::GetInstance().GetNoChargerPlugModeState() == MODE_STATE_CLOSE;
    if (!isCharged) {
        WIFI_LOGI("no charge when wifi connected");
        return;
    }
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    if (screenState == MODE_STATE_OPEN) {
        WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(false, pStaStateMachine->m_instId);
    }
}
#endif

void StaStateMachine::LinkedState::UpdateExpandOffset()
{
    if (!isExpandUpdateRssi_) {
        expandRssi_ = pStaStateMachine->linkedInfo.rssi;
        rssiOffset_ = expandRssi_ - halfFoldRssi_;
    }
    if (rssiOffset_ < RSSI_OFFSET_MIN) {
        rssiOffset_ = RSSI_OFFSET_MIN;
    } else if (rssiOffset_ >= RSSI_OFFSET_MAX) {
        rssiOffset_ = RSSI_OFFSET_MAX;
    }
    isExpandUpdateRssi_ = true;
}
void StaStateMachine::LinkedState::NetDetectionNotify(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }

    SystemNetWorkState netstate = (SystemNetWorkState)msg->GetParam1();
    std::string url;
    if (!msg->GetMessageObj(url)) {
        WIFI_LOGW("Failed to obtain portal url.");
    }
    WIFI_HILOG_COMM_INFO("netdetection, netstate:%{public}d url:%{private}s\n", netstate, url.c_str());
    UpdateNetDetectHistory(netstate);
    pStaStateMachine->HandleNetCheckResult(netstate, url);
}

void StaStateMachine::LinkedState::UpdateNetDetectHistory(EnumNetWorkState networkState)
{
    if (WifiSettings::GetInstance().GetSignalLevel(pStaStateMachine->linkedInfo.rssi,
        pStaStateMachine->linkedInfo.band, pStaStateMachine->m_instId) < RSSI_LEVEL_2) {
        WIFI_LOGD("%{public}s signal level less 2", __FUNCTION__);
        return;
    }
    WifiDeviceConfig config = pStaStateMachine->getCurrentWifiDeviceConfig();
    if (config.networkId == INVALID_NETWORK_ID) {
        WIFI_LOGW("%{public}s fail to get deviceconfig", __FUNCTION__);
        return;
    }
    if (config.dualStackNetState != -1 && config.ipv4OnlyNetState != -1) {
        WIFI_LOGD("%{public}s only update firt connect netDetect record", __FUNCTION__);
        return;
    }
    IpInfo ipInfo;
    IpV6Info ipv6Info;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, pStaStateMachine->m_instId);
    WifiConfigCenter::GetInstance().GetIpv6Info(ipv6Info, pStaStateMachine->m_instId);
    if (ipInfo.ipAddress != 0 && !ipv6Info.globalIpV6Address.empty()) {
        config.dualStackNetState = static_cast<int>(networkState);
    } else if (ipInfo.ipAddress != 0 && ipv6Info.globalIpV6Address.empty()) {
        config.ipv4OnlyNetState = static_cast<int>(networkState);
    } else {
        WIFI_LOGD("%{public}s ip not found", __FUNCTION__);
        return;
    }
    WIFI_LOGI("%{public}s DualStack:%{public}d, Ipv4Only:%{public}d", __FUNCTION__,
        config.dualStackNetState, config.ipv4OnlyNetState);
    if (static_cast<EnumNetWorkState>(config.dualStackNetState) == EnumNetWorkState::NETWORK_NOTWORKING &&
        static_cast<EnumNetWorkState>(config.ipv4OnlyNetState) == EnumNetWorkState::NETWORK_IS_WORKING) {
        if (pStaStateMachine->selfCureService_ != nullptr) {
            WIFI_LOGI("%{public}s disable ipv6", __FUNCTION__);
            pStaStateMachine->selfCureService_->NotifyIpv6FailureDetected(true);
            pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK);
        }
    }
    WifiSettings::GetInstance().AddDeviceConfig(config);
}

void StaStateMachine::LinkedState::DealNetworkCheck(InternalMessagePtr msg)
{
    WIFI_LOGD("enter DealNetworkCheck.\n");
    if (msg == nullptr || pStaStateMachine->enableSignalPoll == false) {
        WIFI_LOGE("detection screen state [%{public}d].", pStaStateMachine->enableSignalPoll);
        return;
    }
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->m_NetWorkState) {
        pStaStateMachine->m_NetWorkState->StartWifiDetection();
    }
#endif
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::LinkedState::CheckIfRestoreWifi()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    if (WifiSettings::GetInstance().GetAcceptUnvalidated(networkId)) {
        WIFI_LOGI("The user has chosen to use the current WiFi.");
        WifiNetAgent::GetInstance().RestoreWifiConnection();
    }
}
#endif

void StaStateMachine::HilinkSetMacAddress(std::string &cmd)
{
    std::string::size_type begPos = 0;
    if ((begPos = cmd.find("=")) == std::string::npos) {
        WIFI_LOGI("HilinkSetMacAddress() cmd not find =");
        return;
    }
    std::string macAddress = cmd.substr(begPos + 1);
    if (macAddress.empty()) {
        WIFI_LOGI("HilinkSetMacAddress() macAddress is empty");
        return;
    }

    m_hilinkDeviceConfig.macAddress = macAddress;
    std::string realMacAddress = "";

    WifiSettings::GetInstance().GetRealMacAddress(realMacAddress, m_instId);
    m_hilinkDeviceConfig.wifiPrivacySetting = (macAddress == realMacAddress ?
        WifiPrivacyConfig::DEVICEMAC : WifiPrivacyConfig::RANDOMMAC);
    WIFI_LOGI("HilinkSetMacAddress() wifiPrivacySetting= %{public}d realMacAddress= %{public}s",
        m_hilinkDeviceConfig.wifiPrivacySetting, MacAnonymize(realMacAddress).c_str());

    return;
}

void StaStateMachine::DealHiLinkDataToWpa(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealHiLinkDataToWpa InternalMessage msg is null.");
        return;
    }
    WIFI_LOGI("DealHiLinkDataToWpa=%{public}d received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case WIFI_SVR_COM_STA_ENABLE_HILINK: {
            m_hilinkDeviceConfig.bssidType = msg->GetParam1();
            bool uiFlag = msg->GetParam2();
            m_hilinkDeviceConfig.ssid = msg->GetStringFromMessage();
            m_hilinkDeviceConfig.bssid = msg->GetStringFromMessage();
            m_hilinkDeviceConfig.keyMgmt = msg->GetStringFromMessage();
            std::string cmd = msg->GetStringFromMessage();
            WIFI_LOGI("DealEnableHiLinkHandshake start shell uiflag = %{public}d, cmd = %{public}s",
                static_cast<int>(uiFlag), MacAnonymize(cmd).c_str());
            WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd);
            break;
        }
        case WIFI_SVR_COM_STA_HILINK_DELIVER_MAC: {
            std::string cmd;
            msg->GetMessageObj(cmd);
            HilinkSetMacAddress(cmd);
            connectMethod_ = NETWORK_SELECTED_BY_HILINK;
            WIFI_LOGI("DealHiLinkMacDeliver start shell cmd, cmd = %{public}s", MacAnonymize(cmd).c_str());
            WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd);
            break;
        }
        case WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS: {
            WIFI_LOGI("DealHiLinkTriggerWps start ClearDeviceConfig");
            WifiStaHalInterface::GetInstance().ClearDeviceConfig(
                WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId));
            WIFI_LOGI("DealHiLinkTriggerWps SPECIAL_CONNECTED");
            InvokeOnStaConnChanged(OperateResState::SPECIAL_CONNECTED, linkedInfo);
            WIFI_LOGI("DealHiLinkTriggerWps start startWpsPbc");
            std::string bssid;
            msg->GetMessageObj(bssid);
            WifiHalWpsConfig config;
            config.anyFlag = 0;
            config.multiAp = 0;
            config.bssid = bssid;
            WifiStaHalInterface::GetInstance().StartWpsPbcMode(config);
            m_hilinkFlag = true;
            targetNetworkId_ = UNKNOWN_HILINK_NETWORK_ID;
            break;
        }
        default:
            return;
    }
}

void StaStateMachine::DealWpaStateChange(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        LOGE("DealWpaStateChange InternalMessage msg is null.");
        return;
    }
    int status = msg->GetParam1();
    LOGI("DealWpaStateChange status: %{public}d", status);
    linkedInfo.supplicantState = static_cast<SupplicantState>(status);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
}
/* --------------------------- state machine Roaming State ------------------------------ */
StaStateMachine::ApRoamingState::ApRoamingState(StaStateMachine *staStateMachine)
    : State("ApRoamingState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::ApRoamingState::~ApRoamingState()
{}

void StaStateMachine::ApRoamingState::GoInState()
{
    WIFI_LOGI("ApRoamingState GoInState function. start aproaming timer!");
    pStaStateMachine->isCurrentRoaming_ = true;
    pStaStateMachine->StartTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK), STA_AP_ROAMING_TIMEOUT);
}

void StaStateMachine::ApRoamingState::GoOutState()
{
    WIFI_LOGI("ApRoamingState GoOutState function. stop aproaming timer!");
    pStaStateMachine->isCurrentRoaming_ = false;
    pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
}

bool StaStateMachine::ApRoamingState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("ApRoamingState, reveived msgCode=%{public}d msg. m_instId = %{public}d",
        msg->GetMessageName(), pStaStateMachine->m_instId);
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            WIFI_LOGI("ApRoamingState, receive WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT event.");
            ret = HandleNetworkConnectionEvent(msg);
            break;
        }
        case CMD_AP_ROAMING_TIMEOUT_CHECK: {
            ret = EXECUTED;
            DealApRoamingStateTimeout(msg);
            break;
        }
        default:
            WIFI_LOGI("ApRoamingState-msgCode=%d not handled.", msg->GetMessageName());
            break;
    }
    return ret;
}

void StaStateMachine::ApRoamingState::DealApRoamingStateTimeout(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealApRoamingStateTimeout InternalMessage msg is null.");
        return;
    }
    WIFI_HILOG_COMM_INFO("DealApRoamingStateTimeout StopTimer aproaming timer");
    pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_ROAMING_FAIL,
        RoamingResultType::TYPE_ROAMING_TIMEOUT);
    pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
    pStaStateMachine->StartDisConnectToNetwork();
    pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
}

bool StaStateMachine::ApRoamingState::HandleNetworkConnectionEvent(InternalMessagePtr msg)
{
    bool ret = EXECUTED;
    std::string bssid = msg->GetStringFromMessage();
    pStaStateMachine->isRoam = true;
    pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
    pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    pStaStateMachine->AfterApLinkedprocess(bssid);
    if (!pStaStateMachine->CanArpReachable()) {
        WIFI_LOGI("Arp is not reachable");
        WriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::ROAMING_ABNORMAL));
        /* The current state of StaStateMachine transfers to GetIpState. */
        pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
    } else {
        WIFI_LOGI("Arp is reachable");
        pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
    }
    return ret;
}

/* --------------------------- state machine ReconnectState State ------------------------------ */
StaStateMachine::ApReconnectState::ApReconnectState(StaStateMachine *staStateMachine)
    : State("ApReconnectState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::ApReconnectState::~ApReconnectState()
{}

void StaStateMachine::ApReconnectState::GoInState()
{
    WIFI_LOGI("ApReconnectState GoInState function. start reconnect timer!");
    pStaStateMachine->isWaitForReconnect_ = true;
    pStaStateMachine->StartTimer(static_cast<int>(CMD_AP_RECONN_TIMEOUT_CHECK), STA_AP_RECONNECT_TIMEOUT);
}

void StaStateMachine::ApReconnectState::GoOutState()
{
    WIFI_LOGI("ApReconnectState GoOutState function. stop reconnect timer!");
    pStaStateMachine->isWaitForReconnect_ = false;
    pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_RECONN_TIMEOUT_CHECK));
}

bool StaStateMachine::ApReconnectState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("ApReconnectState, reveived msgCode=%{public}d msg. m_instId = %{public}d",
        msg->GetMessageName(), pStaStateMachine->m_instId);
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case CMD_AP_RECONN_TIMEOUT_CHECK:
            ret = EXECUTED;
#ifndef OHOS_ARCH_LITE
            if (pStaStateMachine->enhanceService_ != nullptr) {
                pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::NOTIFY_DELAY_DISCONNECTED,
                    pStaStateMachine->m_instId);
            }
#endif
            pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
            break;
        case WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT:
        case WIFI_SVR_CMD_STA_DISCONNECT:
            WIFI_LOGI("Ignore STA_DISCONNECT in ApReconnectState");
            ret = EXECUTED;
            break;
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT:
            if (!pStaStateMachine->CanArpReachable() && pStaStateMachine->enhanceService_ != nullptr &&
                pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_RECONNECT_ALLOWED,
                pStaStateMachine->m_instId) != MultiLinkDefs::ALLOW_IN_CONN_STATE) {
                WIFI_LOGI("ApReconnectState arp is not reachable");
                pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
            } else {
                WIFI_LOGI("ApReconnectState arp is reachable");
                pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
            }
            ret = EXECUTED;
            [[fallthrough]];
        default:
            WIFI_LOGI("ApReconnectState-msgCode=%{public}d not handled.", msg->GetMessageName());
            break;
    }
    return ret;
}

bool StaStateMachine::CanArpReachable()
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddress, m_instId);
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, m_instId);
    std::string ipAddress = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (ipInfo.gateway == 0) {
#ifdef OHOS_ARCH_LITE
        if (enhanceService_ != nullptr && enhanceService_->GenelinkInterface(
            MultiLinkDefs::QUERY_GATEWAY_REQUIRED, m_instId) == MultiLinkDefs::GATEWAY_IGNORE) {
            WIFI_LOGI("ignore empty gateway in dual wlan.");
            return true;
        }
#else
        WIFI_LOGI("gateway is empty");
#endif
        return false;
    }
    uint64_t arpRtt = 0;
    std::string gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    for (int i = 0; i < DEFAULT_NUM_ARP_PINGS; i++) {
        if (arpChecker.DoArpCheck(MAX_ARP_CHECK_TIME, true, arpRtt)) {
            EnhanceWriteArpInfoHiSysEvent(arpRtt, 0);
            return true;
        }
    }
    EnhanceWriteArpInfoHiSysEvent(arpRtt, 1);
    return false;
}

ErrCode StaStateMachine::ConfigRandMacSelfCure(const int networkId)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
        WIFI_LOGE("GetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    if (config.isReassocSelfCureWithFactoryMacAddress == SELF_CURE_FAC_MAC_REASSOC) {
        config.wifiPrivacySetting = WifiPrivacyConfig::DEVICEMAC;
    } else if (config.isReassocSelfCureWithFactoryMacAddress == SELF_CURE_RAND_MAC_REASSOC) {
        config.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
    }
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::AfterApLinkedprocess(std::string bssid)
{
    WIFI_LOGI("AfterApLinkedprocess, Receive bssid=%{public}s m_instId = %{public}d",
        MacAnonymize(bssid).c_str(), m_instId);
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, deviceConfig, m_instId) != 0) {
        WIFI_LOGE("%{public}s cannot find config for networkId = %{public}d", __FUNCTION__, linkedInfo.networkId);
        StartDisConnectToNetwork();
        return;
    }
    deviceConfig.bssid = bssid;
    WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();

    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, ANY_BSSID, ifaceName);

    std::string macAddr;
    std::string realMacAddr;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddr, m_instId);
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddr, m_instId);

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    if (WhetherRestrictedByMdm(deviceConfig.ssid, deviceConfig.bssid, true)) {
        ReportMdmRestrictedEvent(deviceConfig.ssid, deviceConfig.bssid, "BLOCK_LIST");
        DealMdmRestrictedConnect(deviceConfig);
        return;
    }
#endif

    linkedInfo.ssid = deviceConfig.ssid;
    linkedInfo.bssid = bssid;
    linkedInfo.macType = (macAddr == realMacAddr ?
        static_cast<int>(WifiPrivacyConfig::DEVICEMAC) : static_cast<int>(WifiPrivacyConfig::RANDOMMAC));
    linkedInfo.macAddress = macAddr;
    linkedInfo.ifHiddenSSID = deviceConfig.hiddenSSID;
    WifiConfigCenter::GetInstance().SetWifiLinkedStandardAndMaxSpeed(linkedInfo);
}

void StaStateMachine::EnableScreenOffSignalPoll(int delayTime)
{
    enableSignalPoll = true;
    lastSignalLevel_ = INVALID_SIGNAL_LEVEL; // Reset signal level when first start signal poll
    staSignalPollDelayTime_ = delayTime;
    StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
    StartTimer(static_cast<int>(CMD_SIGNAL_POLL), 0);
}

void StaStateMachine::DealScreenStateChangedEvent(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealScreenStateChangedEvent InternalMessage msg is null.");
        return;
    }

    int screenState = msg->GetParam1();
    WIFI_LOGI("DealScreenStateChangedEvent, Receive msg: screenState=%{public}d", screenState);
    if (screenState == MODE_STATE_OPEN) {
        enableSignalPoll = true;
        lastSignalLevel_ = INVALID_SIGNAL_LEVEL;   // Reset signal level when first start signal poll
        StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
        StartTimer(static_cast<int>(CMD_SIGNAL_POLL), 0);
        StartDetectTimer(DETECT_TYPE_DEFAULT);
    }
    if (screenState == MODE_STATE_CLOSE) {
        if (isAudioOn_ == AUDIO_ON_VOIP) {
            EnableScreenOffSignalPoll(STA_SIGNAL_POLL_DELAY_WITH_TASK);
            WIFI_LOGI("DealScreenOffPoll, screen off voip start");
        } else if (isAudioOn_ == AUDIO_ON_AUDIO) {
            EnableScreenOffSignalPoll(STA_SIGNAL_POLL_DELAY);
            WIFI_LOGI("DealScreenOffPoll, screen off audio start");
        } else {
            enableSignalPoll = false;
            StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
            WIFI_LOGI("DealScreenOffPoll, screen off poll stop");
        }
        StopTimer(static_cast<int>(CMD_START_NETCHECK));
    }
#ifndef OHOS_ARCH_LITE
    WifiProtectManager::GetInstance().HandleScreenStateChanged(screenState == MODE_STATE_OPEN);
#endif
    if (m_instId == INSTID_WLAN0) {
        if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE)
            != WIFI_HAL_OPT_OK) {
            WIFI_LOGE("WpaSetSuspendMode failed!");
        }
    }
    return;
}

void StaStateMachine::DealAudioStateChangedEvent(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealScreenOffPoll InternalMessage msg is null.");
        return;
    }
    int isAudioOn = msg->GetParam1();
    WIFI_LOGI("DealScreenOffPoll, Receive msg: isAudioOn=%{public}d", isAudioOn);
    isAudioOn_ = isAudioOn;
    if (WifiConfigCenter::GetInstance().GetScreenState() == MODE_STATE_CLOSE) {
        if (isAudioOn_ == AUDIO_OFF) {
            enableSignalPoll = false;
            staSignalPollDelayTime_ = STA_SIGNAL_POLL_DELAY;
        } else if (isAudioOn_ == AUDIO_ON_VOIP) {
            EnableScreenOffSignalPoll(STA_SIGNAL_POLL_DELAY_WITH_TASK);
        } else if (isAudioOn_ == AUDIO_ON_AUDIO) {
            EnableScreenOffSignalPoll(STA_SIGNAL_POLL_DELAY);
        }
    }
#ifndef OHOS_ARCH_LITE
    if (enhanceService_ == nullptr) {
        WIFI_LOGE("%{public}s enhanceService NULL", __FUNCTION__);
        return;
    }
    bool isAudioScene = isAudioOn_ != AUDIO_OFF ? true : false;
    enhanceService_->NotifyAudioSceneChanged(isAudioScene);
#endif
}

void StaStateMachine::ResetWifi7WurInfo()
{
    linkedInfo.isWurEnable = false;
}

void StaStateMachine::DhcpResultNotify::SaveDhcpResult(DhcpResult *dest, DhcpResult *source)
{
    if (dest == nullptr || source == nullptr) {
        WIFI_LOGE("SaveDhcpResult dest or source is nullptr.");
        return;
    }

    dest->iptype = source->iptype;
    dest->isOptSuc = source->isOptSuc;
    dest->uOptLeasetime = source->uOptLeasetime;
    dest->uAddTime = source->uAddTime;
    dest->uGetTime = source->uGetTime;
    dest->ipv6LifeTime.validLifeTime = source->ipv6LifeTime.validLifeTime;
    dest->ipv6LifeTime.prefLifeTime = source->ipv6LifeTime.prefLifeTime;
    dest->ipv6LifeTime.routerLifeTime = source->ipv6LifeTime.routerLifeTime;
    if (strcpy_s(dest->strOptClientId, DHCP_MAX_FILE_BYTES, source->strOptClientId) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptClientId strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptServerId, DHCP_MAX_FILE_BYTES, source->strOptServerId) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptServerId strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptSubnet, DHCP_MAX_FILE_BYTES, source->strOptSubnet) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptSubnet strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptDns1, DHCP_MAX_FILE_BYTES, source->strOptDns1) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptDns1 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptDns2, DHCP_MAX_FILE_BYTES, source->strOptDns2) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptDns2 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptRouter1, DHCP_MAX_FILE_BYTES, source->strOptRouter1) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptRouter1 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptRouter2, DHCP_MAX_FILE_BYTES, source->strOptRouter2) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptRouter2 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptVendor, DHCP_MAX_FILE_BYTES, source->strOptVendor) != EOK) {
        WIFI_LOGE("SaveDhcpResult strOptVendor strcpy_s failed!");
        return;
    }
    WIFI_LOGI("SaveDhcpResult ok, ipType:%{public}d", dest->iptype);
    StaStateMachine::DhcpResultNotify::SaveDhcpResultExt(dest, source);
}

void StaStateMachine::DhcpResultNotify::SaveDhcpResultExt(DhcpResult *dest, DhcpResult *source)
{
    if (dest == nullptr || source == nullptr) {
        WIFI_LOGE("SaveDhcpResultExt dest or source is nullptr.");
        return;
    }
    if (strcpy_s(dest->strOptLinkIpv6Addr, DHCP_MAX_FILE_BYTES, source->strOptLinkIpv6Addr) != EOK) {
        WIFI_LOGE("SaveDhcpResultExt strOptLinkIpv6Addr strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptRandIpv6Addr, DHCP_MAX_FILE_BYTES, source->strOptRandIpv6Addr) != EOK) {
        WIFI_LOGE("SaveDhcpResultExt strOptRandIpv6Addr strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptLocalAddr1, DHCP_MAX_FILE_BYTES, source->strOptLocalAddr1) != EOK) {
        WIFI_LOGE("SaveDhcpResultExt strOptLocalAddr1 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptLocalAddr2, DHCP_MAX_FILE_BYTES, source->strOptLocalAddr2) != EOK) {
        WIFI_LOGE("SaveDhcpResultExt strOptLocalAddr2 strcpy_s failed!");
        return;
    }
    if (source->dnsList.dnsNumber >= 0 && source->dnsList.dnsNumber <= DHCP_DNS_MAX_NUMBER) {
        dest->dnsList.dnsNumber = 0;
        for (uint32_t i = 0; i < source->dnsList.dnsNumber; i++) {
            if (memcpy_s(dest->dnsList.dnsAddr[i], DHCP_LEASE_DATA_MAX_LEN, source->dnsList.dnsAddr[i],
                DHCP_LEASE_DATA_MAX_LEN -1) != EOK) {
                WIFI_LOGE("SaveDhcpResultExt memcpy_s failed! i:%{public}d", i);
            } else {
                dest->dnsList.dnsNumber++;
            }
        }
        WIFI_LOGI("SaveDhcpResultExt destDnsNumber:%{public}d sourceDnsNumber:%{public}d", dest->dnsList.dnsNumber,
            source->dnsList.dnsNumber);
    }

    if (source->addrList.addrNumber >= 0 && source->addrList.addrNumber <= DHCP_ADDR_MAX_NUMBER) {
        dest->addrList.addrNumber = 0;
        for (uint32_t i = 0; i < source->addrList.addrNumber; i++) {
            if (memcpy_s(dest->addrList.addr[i], DHCP_ADDR_DATA_MAX_LEN, source->addrList.addr[i],
                DHCP_ADDR_DATA_MAX_LEN -1) != EOK) {
                WIFI_LOGE("SaveDhcpResultExt addrList memcpy_s failed! i:%{public}d", i);
            } else {
                dest->addrList.addrType[i] = source->addrList.addrType[i];
                dest->addrList.addrNumber++;
            }
        }
        WIFI_LOGI("SaveDhcpResultExt destAddrNumber:%{public}d sourceAddrNumber:%{public}d", dest->addrList.addrNumber,
            source->addrList.addrNumber);
    }
    WIFI_LOGI("SaveDhcpResultExt ok, ipType:%{public}d", dest->iptype);
}

/* ------------------ state machine dhcp callback function ----------------- */
StaStateMachine* StaStateMachine::DhcpResultNotify::pStaStateMachineList[STA_INSTANCE_MAX_NUM] = {nullptr};

StaStateMachine::DhcpResultNotify::DhcpResultNotify(StaStateMachine *staStateMachine)
{
    // Save the instance of StaStateMachine to the static array.
    pStaStateMachineList[staStateMachine->m_instId] = staStateMachine;
    // Save the instance of StaStateMachine to the member variable.
    pStaStateMachine = staStateMachine;
}
StaStateMachine::DhcpResultNotify::~DhcpResultNotify()
{
}

void StaStateMachine::DhcpResultNotify::OnSuccess(int status, const char *ifname, DhcpResult *result)
{
    if (ifname == nullptr || result == nullptr) {
        WIFI_LOGE("StaStateMachine DhcpResultNotify OnSuccess ifname or result is nullptr.");
        return;
    }
    for (int instId = 0; instId < STA_INSTANCE_MAX_NUM; instId++) {
        if (pStaStateMachineList[instId] != nullptr
            && strcmp(ifname, WifiConfigCenter::GetInstance().GetStaIfaceName(instId).c_str()) == 0) {
            pStaStateMachineList[instId]->pDhcpResultNotify->OnSuccessDhcpResult(status, ifname, result);
        }
    }
}

void StaStateMachine::DhcpResultNotify::OnSuccessDhcpResult(int status, const char *ifname, DhcpResult *result)
{
    if (ifname == nullptr || result == nullptr || pStaStateMachine == nullptr) {
        WIFI_LOGE("StaStateMachine DhcpResultNotify OnSuccess ifname or result is nullptr.");
        return;
    }
    WIFI_HILOG_COMM_INFO("Enter Sta DhcpResultNotify OnSuccess. ifname=[%{public}s] status=[%{public}d]",
        ifname, status);
    WIFI_LOGI("iptype=%{public}d, isOptSuc=%{public}d, clientip =%{private}s, \
        serverip=%{private}s, subnet=%{private}s", result->iptype, result->isOptSuc,
        result->strOptClientId,  result->strOptServerId, result->strOptSubnet);
    WIFI_LOGI("gateway1=%{private}s, gateway2=%{private}s, strDns1=%{private}s, strDns2=%{private}s, \
        strVendor=%{public}s, uOptLeasetime=%{public}d, uAddTime=%{public}d, uGetTime=%{public}d, \
        currentTpType=%{public}d", result->strOptRouter1, result->strOptRouter2, result->strOptDns1,
        result->strOptDns2, result->strOptVendor, result->uOptLeasetime, result->uAddTime,
        result->uGetTime, pStaStateMachine->currentTpType);

    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_DHCP),
        static_cast<int>(WifiOperateState::STA_DHCP_SUCCESS));
    if (result->iptype == 0) { /* 0-ipv4,1-ipv6 */
        WIFI_LOGI("StopTimer CMD_START_GET_DHCP_IP_TIMEOUT OnSuccess");
        pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
        {
            std::unique_lock<std::mutex> lock(dhcpResultMutex);
            SaveDhcpResult(&DhcpIpv4Result, result);
            isDhcpIpv4Success = true;
        }
    } else {
        std::unique_lock<std::mutex> lock(dhcpResultMutex);
        SaveDhcpResult(&DhcpIpv6Result, result);
    }
    DhcpResultNotifyEvent(DhcpReturnCode::DHCP_RESULT, result->iptype);
}

void StaStateMachine::DhcpResultNotify::OnDhcpOffer(int status, const char *ifname, DhcpResult *result)
{
    if (ifname == nullptr || result == nullptr) {
        WIFI_LOGE("StaStateMachine DhcpResultNotify OnDhcpOffer ifname or result is nullptr.");
        return;
    }
    for (int instId = 0; instId < STA_INSTANCE_MAX_NUM; instId++) {
        if (pStaStateMachineList[instId] != nullptr
            && strcmp(ifname, WifiConfigCenter::GetInstance().GetStaIfaceName(instId).c_str()) == 0) {
            pStaStateMachineList[instId]->pDhcpResultNotify->OnDhcpOfferResult(status, ifname, result);
        }
    }
}

void StaStateMachine::DhcpResultNotify::OnDhcpOfferResult(int status, const char *ifname, DhcpResult *result)
{
    if (ifname == nullptr || pStaStateMachine == nullptr) {
        WIFI_LOGE("StaStateMachine DhcpResultNotify OnDhcpOfferResult ifname or result is nullptr.");
        return;
    }
    WIFI_LOGI("DhcpResultNotify TYPE_DHCP_OFFER");
    {
        std::unique_lock<std::mutex> lock(dhcpResultMutex);
        SaveDhcpResult(&DhcpOfferInfo, result);
    }
    DhcpResultNotifyEvent(DhcpReturnCode::DHCP_OFFER_REPORT, result->iptype);
}

void StaStateMachine::DhcpResultNotify::DealDhcpResult(int ipType)
{
    DhcpResult *result = nullptr;
    IpInfo ipInfo;
    IpV6Info ipv6Info;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, pStaStateMachine->m_instId);
    WifiConfigCenter::GetInstance().GetIpv6Info(ipv6Info, pStaStateMachine->m_instId);
    if (ipType == 0) { /* 0-ipv4,1-ipv6 */
        {
            std::unique_lock<std::mutex> lock(dhcpResultMutex);
            result = &(StaStateMachine::DhcpResultNotify::DhcpIpv4Result);
            TryToSaveIpV4Result(ipInfo, ipv6Info, result);
        }
        IpCacheInfo ipCacheInfo;
        std::string ssid = pStaStateMachine->linkedInfo.ssid;
        std::string bssid = pStaStateMachine->linkedInfo.bssid;
        if ((strncpy_s(ipCacheInfo.ssid, SSID_MAX_LEN, ssid.c_str(), ssid.length()) == EOK) &&
            (strncpy_s(ipCacheInfo.bssid, MAC_ADDR_MAX_LEN, bssid.c_str(), bssid.length()) == EOK)) {
            DealWifiDhcpCache(WIFI_DHCP_CACHE_ADD, ipCacheInfo);
        }
    } else {
        std::unique_lock<std::mutex> lock(dhcpResultMutex);
        result = &(StaStateMachine::DhcpResultNotify::DhcpIpv6Result);
        TryToSaveIpV6Result(ipInfo, ipv6Info, result);
    }
    TryToJumpToConnectedState(result->iptype);

    WifiDeviceConfig config;
    AssignIpMethod assignMethod = AssignIpMethod::DHCP;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
        pStaStateMachine->m_instId);
    if (ret == 0) {
        assignMethod = config.wifiIpConfig.assignMethod;
    }
    WIFI_LOGI("DhcpResultNotify OnSuccess, uLeaseTime=%{public}d %{public}d %{public}d m_instId = %{public}d",
        result->uOptLeasetime, assignMethod, pStaStateMachine->currentTpType, pStaStateMachine->m_instId);
    return;
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV4ResultExt(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        WIFI_LOGE("TryToSaveIpV4ResultExt result nullptr.");
        return;
    }
    ipInfo.ipAddress = IpTools::ConvertIpv4Address(result->strOptClientId);
    ipInfo.gateway = IpTools::ConvertIpv4Address(result->strOptRouter1);
    ipInfo.netmask = IpTools::ConvertIpv4Address(result->strOptSubnet);
    ipInfo.primaryDns = IpTools::ConvertIpv4Address(result->strOptDns1);
    ipInfo.secondDns = IpTools::ConvertIpv4Address(result->strOptDns2);
    ipInfo.serverIp = IpTools::ConvertIpv4Address(result->strOptServerId);
    ipInfo.leaseDuration = result->uOptLeasetime;
    ipInfo.dnsAddr.clear();
    if (ipInfo.primaryDns != 0) {
        ipInfo.dnsAddr.push_back(ipInfo.primaryDns);
    }
    if (ipInfo.secondDns != 0) {
        ipInfo.dnsAddr.push_back(ipInfo.secondDns);
    }
    if (result->dnsList.dnsNumber >= 0 && result->dnsList.dnsNumber <= DHCP_DNS_MAX_NUMBER) {
        for (uint32_t i = 0; i < result->dnsList.dnsNumber; i++) {
            unsigned int ipv4Address = IpTools::ConvertIpv4Address(result->dnsList.dnsAddr[i]);
            if (std::find(ipInfo.dnsAddr.begin(), ipInfo.dnsAddr.end(), ipv4Address) != ipInfo.dnsAddr.end()) {
                WIFI_LOGD("TryToSaveIpV4ResultExt dnsAddr already exists, skip it.");
                continue;
            }
            ipInfo.dnsAddr.push_back(ipv4Address);
        }
    }
    WifiConfigCenter::GetInstance().SaveIpInfo(ipInfo, pStaStateMachine->m_instId);
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV4Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        WIFI_LOGE("TryToSaveIpV4Result resultis nullptr.");
        return;
    }

    if (!((IpTools::ConvertIpv4Address(result->strOptClientId) == ipInfo.ipAddress) &&
        (IpTools::ConvertIpv4Address(result->strOptRouter1) == ipInfo.gateway))) {
        if (result->iptype == 0) {  /* 0-ipv4,1-ipv6 */
            TryToSaveIpV4ResultExt(ipInfo, ipv6Info, result);
            pStaStateMachine->linkedInfo.ipAddress = IpTools::ConvertIpv4Address(result->strOptClientId);
            /* If not phone hotspot, set .isDataRestricted = 0. */
            std::string strVendor = result->strOptVendor;
            std::string ipAddress = result->strOptClientId;
            int maskLength = IpTools::GetMaskLength(result->strOptSubnet);
            pStaStateMachine->linkedInfo.isDataRestricted =
                (strVendor.find("ANDROID_METERED") == std::string::npos &&
                strVendor.find("OPEN_HARMONY") == std::string::npos) ? 0 : 1;
            if (!pStaStateMachine->linkedInfo.isDataRestricted) {
                pStaStateMachine->linkedInfo.isDataRestricted =
                    (strVendor.find("hostname:") != std::string::npos &&
                    ipAddress.find("172.20.10.") != std::string::npos &&
                    maskLength >= HOTSPOT_SUBNETMASK_MIN_LENGTH);
            }
            pStaStateMachine->linkedInfo.platformType = strVendor;
            WIFI_LOGI("WifiLinkedInfo.isDataRestricted = %{public}d, WifiLinkedInfo.platformType = %{public}s",
                pStaStateMachine->linkedInfo.isDataRestricted, pStaStateMachine->linkedInfo.platformType.c_str());
            WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo,
                pStaStateMachine->m_instId);
            EnhanceWriteDhcpInfoHiSysEvent(ipInfo, ipv6Info);
#ifndef OHOS_ARCH_LITE
            WIFI_HILOG_COMM_INFO("TryToSaveIpV4Result Update NetLink info, strYourCli=%{private}s, \
                strSubnet=%{private}s, strRouter1=%{private}s, strDns1=%{private}s, strDns2=%{private}s",
                IpAnonymize(result->strOptClientId).c_str(), IpAnonymize(result->strOptSubnet).c_str(),
                IpAnonymize(result->strOptRouter1).c_str(), IpAnonymize(result->strOptDns1).c_str(),
                IpAnonymize(result->strOptDns2).c_str());
            WIFI_LOGI("On dhcp success update net linke info");
            WifiDeviceConfig config;
            WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
                pStaStateMachine->m_instId);
            WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(ipInfo, ipv6Info, config.wifiProxyconfig,
                pStaStateMachine->m_instId);
#endif
        }
#ifdef OHOS_ARCH_LITE
        IfConfig::GetInstance().SetIfDnsAndRoute(result, result->iptype, pStaStateMachine->m_instId);
#endif
    } else {
        WIFI_LOGI("TryToSaveIpV4Result not UpdateNetLinkInfo");
    }
}

bool StaStateMachine::DhcpResultNotify::IsIpv6AllZero(const std::string &ipv6)
{
    if (ipv6.empty()) {
        return false;
    }
    if (ipv6 == "0") {
        return true;
    }
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ipv6.c_str(), &addr) != 1) {
        return false;
    }
    unsigned char orResult = 0;
    constexpr int ipv6ByteLen = 16;
    for (int i = 0; i < ipv6ByteLen; ++i) {
        orResult |= addr.s6_addr[i];
    }
    return orResult == 0;
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV6ResultExt(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        WIFI_LOGE("TryToSaveIpV6ResultExt result nullptr.");
        return;
    }
    if (!ipv6Info.linkIpV6Address.empty()) {
        ipv6Info.IpAddrMap[ipv6Info.linkIpV6Address] = static_cast<int>(AddrTypeIpV6::ADDR_TYPE_LINK_LOCAL);
    }
    if (!ipv6Info.globalIpV6Address.empty()) {
        ipv6Info.IpAddrMap[ipv6Info.globalIpV6Address] = static_cast<int>(AddrTypeIpV6::ADDR_TYPE_GLOBAL);
    }
    if (!ipv6Info.randGlobalIpV6Address.empty()) {
        ipv6Info.IpAddrMap[ipv6Info.randGlobalIpV6Address] = static_cast<int>(AddrTypeIpV6::ADDR_TYPE_RANDOM_GLOBAL);
    }
    if (!ipv6Info.uniqueLocalAddress1.empty()) {
        ipv6Info.IpAddrMap[ipv6Info.uniqueLocalAddress1] = static_cast<int>(AddrTypeIpV6::ADDR_TYPE_UNIQUE_LOCAL_1);
    }
    if (!ipv6Info.uniqueLocalAddress2.empty()) {
        ipv6Info.IpAddrMap[ipv6Info.uniqueLocalAddress2] = static_cast<int>(AddrTypeIpV6::ADDR_TYPE_UNIQUE_LOCAL_2);
    }
    if (ipv6Info.primaryDns.length() > 0 && !IsIpv6AllZero(ipv6Info.primaryDns)) {
        ipv6Info.dnsAddr.push_back(ipv6Info.primaryDns);
    }
    if (ipv6Info.secondDns.length() > 0 && !IsIpv6AllZero(ipv6Info.secondDns)) {
        ipv6Info.dnsAddr.push_back(ipv6Info.secondDns);
    }
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV6Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        WIFI_LOGE("TryToSaveIpV6Result resultis nullptr.");
        return;
    }
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine->enhanceService_ != nullptr &&
        pStaStateMachine->enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_DHCP_REQUIRED,
            pStaStateMachine->m_instId) == MultiLinkDefs::DHCP_IGNORE) {
        WIFI_LOGI("TryToSaveIpV6Result return in dual wlan.");
        return;
    }
#endif
    ipv6Info.linkIpV6Address = result->strOptLinkIpv6Addr;
    ipv6Info.globalIpV6Address = result->strOptClientId;
    ipv6Info.randGlobalIpV6Address = result->strOptRandIpv6Addr;
    ipv6Info.gateway = result->strOptRouter1;
    ipv6Info.netmask = result->strOptSubnet;
    ipv6Info.primaryDns = result->strOptDns1;
    ipv6Info.secondDns = result->strOptDns2;
    ipv6Info.uniqueLocalAddress1 = result->strOptLocalAddr1;
    ipv6Info.uniqueLocalAddress2 = result->strOptLocalAddr2;
    ipv6Info.validLifeTime = result->ipv6LifeTime.validLifeTime;
    ipv6Info.preferredLifeTime = result->ipv6LifeTime.prefLifeTime;
    ipv6Info.routerLifeTime = result->ipv6LifeTime.routerLifeTime;
    ipv6Info.dnsAddr.clear();
    ipv6Info.IpAddrMap.clear();
    TryToSaveIpV6ResultExt(ipInfo, ipv6Info, result);
    if (result->dnsList.dnsNumber <= DHCP_DNS_MAX_NUMBER) {
        for (uint32_t i = 0; i < result->dnsList.dnsNumber; i++) {
            std::string dns = result->dnsList.dnsAddr[i];
            if (IsIpv6AllZero(dns)) {
                continue;
            }
            if (std::find(ipv6Info.dnsAddr.begin(), ipv6Info.dnsAddr.end(), dns) == ipv6Info.dnsAddr.end()) {
                ipv6Info.dnsAddr.push_back(dns);
            }
        }
        WIFI_LOGI("TryToSaveIpV6Result ipv6Info dnsAddr size:%{public}zu", ipv6Info.dnsAddr.size());
    }
    if (result->addrList.addrNumber <= DHCP_ADDR_MAX_NUMBER) {
        for (uint32_t i = 0; i < result->addrList.addrNumber; i++) {
            ipv6Info.IpAddrMap[result->addrList.addr[i]] = result->addrList.addrType[i];
        }
        WIFI_LOGI("TryToSaveIpV6Result ipv6Info IpAddrMap size:%{public}zu", ipv6Info.IpAddrMap.size());
    }
    WifiConfigCenter::GetInstance().SaveIpV6Info(ipv6Info, pStaStateMachine->m_instId);
    WIFI_LOGI("SaveIpV6 Info complete.");
    UpdateNetLinkInfoForIpV6(ipInfo, ipv6Info);
}

void StaStateMachine::DhcpResultNotify::UpdateNetLinkInfoForIpV6(IpInfo &ipInfo, IpV6Info &ipv6Info)
{
#ifndef OHOS_ARCH_LITE
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
        pStaStateMachine->m_instId);
    if (ipv6Info.IpAddrMap.size() != 1 ||
        ipv6Info.IpAddrMap.begin()->second != static_cast<int>(AddrTypeIpV6::ADDR_TYPE_LINK_LOCAL)) {
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(ipInfo, ipv6Info, config.wifiProxyconfig,
            pStaStateMachine->m_instId);
    }
    EnhanceWriteDhcpInfoHiSysEvent(ipInfo, ipv6Info);
#endif
}

void StaStateMachine::DhcpResultNotify::DealDhcpJump()
{
    WIFI_LOGI("DhcpResultNotify DealDhcpJump");
    EnhanceWriteIsInternetHiSysEvent(CONNECTED_NETWORK);
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
    pStaStateMachine->InvokeOnStaConnChanged(
        OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
    /* Delay to wait for the network adapter information to take effect. */
    pStaStateMachine->DealSetStaConnectFailedCount(0, true);
    pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
}

void StaStateMachine::DhcpResultNotify::DhcpResultNotifyEvent(DhcpReturnCode result, int ipType)
{
    InternalMessagePtr msg = pStaStateMachine->CreateMessage();
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.\n");
        return;
    }

    msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
    msg->SetParam1(result);
    msg->SetParam2(ipType);
    pStaStateMachine->SendMessage(msg);
}

void StaStateMachine::DhcpResultNotify::TryToJumpToConnectedState(int iptype)
{
    if (isDhcpIpv4Success) {
        //if get Ipv4 result jump to connected state
        WIFI_LOGI("TryToJumpToConnectedState, ipv4 success, jump to connected state");
        pStaStateMachine->StopTimer(static_cast<int>(CMD_IPV6_DELAY_TIMEOUT));
        DhcpResultNotifyEvent(DhcpReturnCode::DHCP_JUMP);
    } else if (iptype == 1 && !isDhcpIpv6Success) {
        IpV6Info ipv6Info;
        WifiConfigCenter::GetInstance().GetIpv6Info(ipv6Info, pStaStateMachine->m_instId);
        // if get ipv6 global address, start delay timer to jump to connected state
        if (!ipv6Info.globalIpV6Address.empty() || !ipv6Info.randGlobalIpV6Address.empty()) {
            isDhcpIpv6Success = true;
            pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
            pStaStateMachine->StopTimer(static_cast<int>(CMD_IPV6_DELAY_TIMEOUT));
            WIFI_LOGI("TryToJumpToConnectedState, start CMD_IPV6_DELAY_TIMEOUT timer");
            pStaStateMachine->StartTimer(static_cast<int>(CMD_IPV6_DELAY_TIMEOUT), IPV6_DELAY_TIME);
        }
    }
}

void StaStateMachine::DhcpResultNotify::OnFailed(int status, const char *ifname, const char *reason)
{
    if (ifname == nullptr || reason == nullptr) {
        WIFI_LOGE("StaStateMachine DhcpResultNotify OnFailed ifname or reason is nullptr.");
        return;
    }
    for (int instId = 0; instId < STA_INSTANCE_MAX_NUM; instId++) {
        if (pStaStateMachineList[instId] != nullptr
            && strcmp(ifname, WifiConfigCenter::GetInstance().GetStaIfaceName(instId).c_str()) == 0) {
            pStaStateMachineList[instId]->pDhcpResultNotify->OnFailedDhcpResult(status, ifname, reason);
        }
    }
}

void StaStateMachine::DhcpResultNotify::OnFailedDhcpResult(int status, const char *ifname, const char *reason)
{
    // for dhcp: 4-DHCP_OPT_RENEW_FAILED  5-DHCP_OPT_RENEW_TIMEOUT
    if ((status == DHCP_RENEW_FAILED) || (status == DHCP_RENEW_TIMEOUT)) {
        WIFI_LOGI("DhcpResultNotify::OnFailed, ifname[%{public}s], status[%{public}d], reason[%{public}s]",
            ifname, status, reason);
        DhcpResultNotifyEvent(DhcpReturnCode::DHCP_RENEW_FAIL);
        return;
    }
    if (status == DHCP_LEASE_EXPIRED) {
        DhcpResultNotifyEvent(DhcpReturnCode::DHCP_IP_EXPIRED);
        return;
    }
    WIFI_LOGI("Enter DhcpResultNotify::OnFailed. ifname=%{public}s, status=%{public}d, reason=%{public}s",
        ifname, status, reason);
    EnhanceWriteDhcpFailHiSysEvent("DHCP_FAIL", status);
    DhcpResultNotifyEvent(DhcpReturnCode::DHCP_FAIL);
}

void StaStateMachine::DhcpResultNotify::DealDhcpIpv4ResultFailed()
{
    pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    if (isDhcpIpv6Success) {
        WIFI_LOGI("DhcpResultNotify DealDhcpIpv4ResultFailed, but ipv6 success, so jump to connected state");
        pStaStateMachine->StopTimer(static_cast<int>(CMD_IPV6_DELAY_TIMEOUT));
        DhcpResultNotifyEvent(DhcpReturnCode::DHCP_JUMP);
        return;
    }
    BlockConnectService::GetInstance().UpdateNetworkSelectStatus(pStaStateMachine->linkedInfo.networkId,
        DisabledReason::DISABLED_DHCP_FAILURE);
    BlockConnectService::GetInstance().NotifyWifiConnFailedInfo(pStaStateMachine->targetNetworkId_,
        pStaStateMachine->linkedInfo.bssid, DisabledReason::DISABLED_DHCP_FAILURE);

    WIFI_HILOG_COMM_INFO("DhcpResultNotify OnFailed type: %{public}d", pStaStateMachine->currentTpType);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP_FAILED,
        pStaStateMachine->linkedInfo);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::OBTAINING_IPADDR_FAIL);
    pStaStateMachine->NotifyWifiDisconnectReason(WifiDisconnectReason::DISCONNECT_BY_DHCP_FAIL,
        DhcpFailType::TYPE_DEAL_IPV4_RESULT_FAIL);
    pStaStateMachine->StartDisConnectToNetwork();
}

void StaStateMachine::DhcpResultNotify::DealDhcpOfferResult()
{
    WIFI_LOGI("DhcpResultNotify DealDhcpOfferResult enter");
    IpInfo ipInfo;
    {
        std::unique_lock<std::mutex> lock(dhcpResultMutex);
        ipInfo.ipAddress = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptClientId);
        ipInfo.gateway = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptRouter1);
        ipInfo.netmask = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptSubnet);
        ipInfo.primaryDns = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptDns1);
        ipInfo.secondDns = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptDns2);
        ipInfo.serverIp = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptServerId);
        ipInfo.leaseDuration = DhcpOfferInfo.uOptLeasetime;
        ipInfo.dnsAddr.clear();
        if (ipInfo.primaryDns != 0) {
            ipInfo.dnsAddr.push_back(ipInfo.primaryDns);
        }
        if (ipInfo.secondDns != 0) {
            ipInfo.dnsAddr.push_back(ipInfo.secondDns);
        }
        if (DhcpOfferInfo.dnsList.dnsNumber >= 0 && DhcpOfferInfo.dnsList.dnsNumber <= DHCP_DNS_MAX_NUMBER) {
            for (uint32_t i = 0; i < DhcpOfferInfo.dnsList.dnsNumber; i++) {
                uint32_t ipv4Address = IpTools::ConvertIpv4Address(DhcpOfferInfo.dnsList.dnsAddr[i]);
                if (std::find(ipInfo.dnsAddr.begin(), ipInfo.dnsAddr.end(), ipv4Address) != ipInfo.dnsAddr.end()) {
                    WIFI_LOGD("DealDhcpOfferResult dnsAddr already exists, skip it.");
                    continue;
                }
                ipInfo.dnsAddr.push_back(ipv4Address);
            }
        }
    }
    pStaStateMachine->InvokeOnDhcpOfferReport(ipInfo);
}

void StaStateMachine::DhcpResultNotify::Clear()
{
    std::unique_lock<std::mutex> lock(dhcpResultMutex);
    ClearDhcpResult(&DhcpIpv4Result);
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().SaveIpInfo(ipInfo, pStaStateMachine->m_instId);
    ClearDhcpResult(&DhcpIpv6Result);
    IpV6Info ipV6Info;
    WifiConfigCenter::GetInstance().SaveIpV6Info(ipV6Info, pStaStateMachine->m_instId);
    ClearDhcpResult(&DhcpOfferInfo);
    isDhcpIpv4Success = false;
    isDhcpIpv6Success = false;
    WIFI_LOGI("Clear all DHCP results for StaStateMachine instance %{public}d",
        pStaStateMachine->m_instId);
}

void StaStateMachine::DhcpResultNotify::ClearDhcpResult(DhcpResult *result)
{
    if (result == nullptr) {
        return;
    }
    memset_s(result, sizeof(DhcpResult), 0, sizeof(DhcpResult));
}

/* ------------------ state machine Commont function ----------------- */
ErrCode StaStateMachine::FillEapCfg(const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const
{
    halDeviceConfig.eapConfig.eap = config.wifiEapConfig.eap;
    halDeviceConfig.eapConfig.phase2Method = static_cast<int>(config.wifiEapConfig.phase2Method);
    halDeviceConfig.eapConfig.identity = config.wifiEapConfig.identity;
    halDeviceConfig.eapConfig.anonymousIdentity = config.wifiEapConfig.anonymousIdentity;
    if (memcpy_s(halDeviceConfig.eapConfig.password, sizeof(halDeviceConfig.eapConfig.password),
        config.wifiEapConfig.password.c_str(), config.wifiEapConfig.password.length()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy the content", __func__);
        return WIFI_OPT_FAILED;
    }
    halDeviceConfig.eapConfig.caCertPath = config.wifiEapConfig.caCertPath;
    halDeviceConfig.eapConfig.caCertAlias = config.wifiEapConfig.caCertAlias;
    halDeviceConfig.eapConfig.clientCert = config.wifiEapConfig.clientCert;
    if (memcpy_s(halDeviceConfig.eapConfig.certPassword, sizeof(halDeviceConfig.eapConfig.certPassword),
        config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword)) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy the content", __func__);
        return WIFI_OPT_FAILED;
    }
    halDeviceConfig.eapConfig.privateKey = config.wifiEapConfig.privateKey;
    halDeviceConfig.eapConfig.altSubjectMatch = config.wifiEapConfig.altSubjectMatch;
    halDeviceConfig.eapConfig.domainSuffixMatch = config.wifiEapConfig.domainSuffixMatch;
    halDeviceConfig.eapConfig.realm = config.wifiEapConfig.realm;
    halDeviceConfig.eapConfig.plmn = config.wifiEapConfig.plmn;
    halDeviceConfig.eapConfig.eapSubId = config.wifiEapConfig.eapSubId;
    return WIFI_OPT_SUCCESS;
}

ErrCode StaStateMachine::SetExternalSim(const std::string ifName, const std::string &eap, int value) const
{
    if ((eap != EAP_METHOD_SIM) &&
        (eap != EAP_METHOD_AKA) &&
        (eap != EAP_METHOD_AKA_PRIME)) {
        return WIFI_OPT_SUCCESS;
    }

    WIFI_LOGI("%{public}s ifName: %{public}s, eap: %{public}s, value: %{public}d",
        __func__, ifName.c_str(), eap.c_str(), value);
    char cmd[CMD_BUFFER_SIZE] = { 0 };
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "set external_sim %d", value) < 0) {
        WIFI_LOGE("StaStateMachine::ConvertDeviceCfg: failed to snprintf_s");
        return WIFI_OPT_FAILED;
    }

    if (WifiStaHalInterface::GetInstance().ShellCmd(ifName, cmd) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("%{public}s: failed to set StaShellCmd, cmd:%{private}s", __func__, cmd);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::FillSuiteB192Cfg(WifiHalDeviceConfig &halDeviceConfig) const
{
    if (halDeviceConfig.keyMgmt.find("WPA-EAP-SUITE-B-192") != std::string::npos) {
        halDeviceConfig.allowedProtocols = 0x02; // RSN
        halDeviceConfig.allowedPairwiseCiphers = 0x20; // GCMP-256
        halDeviceConfig.allowedGroupCiphers = 0x20; // GCMP-256
        halDeviceConfig.isRequirePmf = true;
        halDeviceConfig.allowedGroupMgmtCiphers = 0x4; // BIP-GMAC-256
    }
}

void StaStateMachine::FillWapiCfg(const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const
{
    if ((strcmp(config.keyMgmt.c_str(), KEY_MGMT_WAPI_CERT.c_str()) != 0) &&
        (strcmp(config.keyMgmt.c_str(), KEY_MGMT_WAPI_PSK.c_str()) != 0)) {
        WIFI_LOGI("wapiPskType is not wapi_cert nor wapi_psk");
        return;
    }
    halDeviceConfig.wapiPskType = config.wifiWapiConfig.wapiPskType;
    halDeviceConfig.wapiAsCertData = config.wifiWapiConfig.wapiAsCertData;
    halDeviceConfig.wapiUserCertData = config.wifiWapiConfig.wapiUserCertData;
    halDeviceConfig.allowedProtocols = 0x10; // WAPI
    halDeviceConfig.allowedPairwiseCiphers = 0x40; // SMS4
    halDeviceConfig.allowedGroupCiphers = 0x40; // SMS4
    halDeviceConfig.wepKeyIdx = -1;
    return;
}

void StaStateMachine::TransHalDeviceConfig(WifiHalDeviceConfig &halDeviceConfig, const WifiDeviceConfig &config) const
{
    halDeviceConfig.ssid = config.ssid;
    halDeviceConfig.bssid = config.bssid;
    halDeviceConfig.psk = config.preSharedKey;
    halDeviceConfig.keyMgmt = config.keyMgmt;
    halDeviceConfig.priority = config.priority;
    halDeviceConfig.scanSsid = config.hiddenSSID ? 1 : 0;
    FillEapCfg(config, halDeviceConfig);
    FillSuiteB192Cfg(halDeviceConfig);
    halDeviceConfig.wepKeyIdx = config.wepTxKeyIndex;
    FillWapiCfg(config, halDeviceConfig);
}

void StaStateMachine::AppendFastTransitionKeyMgmt(
    const WifiScanInfo &scanInfo, WifiHalDeviceConfig &halDeviceConfig) const
{
    if (scanInfo.capabilities.find("FT/EAP") != std::string::npos) {
        halDeviceConfig.keyMgmt.append(" FT-EAP ");
    } else if (scanInfo.capabilities.find("FT/PSK") != std::string::npos) {
        halDeviceConfig.keyMgmt.append(" FT-PSK ");
    } else {
        WIFI_LOGI("No need append ft keyMgmt!");
    }
}

void StaStateMachine::ConvertSsidToOriginalSsid(
    const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const
{
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    if (!halDeviceConfig.bssid.empty()) {
        for (auto &scanInfo : scanInfoList) {
            if (halDeviceConfig.bssid == scanInfo.bssid) {
                AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);
                halDeviceConfig.ssid = scanInfo.oriSsid;
                WIFI_LOGI("BssidMatchConvertSsid back to oriSsid:%{public}s, keyMgmt:%{public}s",
                    SsidAnonymize(halDeviceConfig.ssid).c_str(), halDeviceConfig.keyMgmt.c_str());
                return;
            }
        }
    }
    for (auto &scanInfo : scanInfoList) {
        std::string deviceKeyMgmt;
        scanInfo.GetDeviceMgmt(deviceKeyMgmt);
        if (config.ssid == scanInfo.ssid
            && ((deviceKeyMgmt == "WPA-PSK+SAE" && deviceKeyMgmt.find(config.keyMgmt) != std::string::npos)
                || (config.keyMgmt == deviceKeyMgmt))) { // only supports WPA-PSK+SAE, handle specially here
            AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);
            halDeviceConfig.ssid = scanInfo.oriSsid;
            WIFI_LOGI("ConvertSsidToOriginalSsid back to oriSsid:%{public}s, keyMgmt:%{public}s",
                SsidAnonymize(halDeviceConfig.ssid).c_str(), halDeviceConfig.keyMgmt.c_str());
            break;
        }
    }
}

std::string StaStateMachine::GetSuitableKeyMgmtForWpaMixed(const WifiDeviceConfig &config,
    const std::string &bssid) const
{
    std::vector<WifiScanInfo> scanInfoList;
    std::vector<std::string> candidateKeyMgmtList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    for (auto scanInfo : scanInfoList) {
        // bssid.empty or match scanInfo's bssid
        if (config.ssid == scanInfo.ssid && (bssid.empty() || bssid == scanInfo.bssid)) {
            std::string deviceKeyMgmt;
            scanInfo.GetDeviceMgmt(deviceKeyMgmt);
            if (WifiSettings::GetInstance().InKeyMgmtBitset(config, deviceKeyMgmt)) {
                WifiSettings::GetInstance().GetAllSuitableEncryption(config, deviceKeyMgmt, candidateKeyMgmtList);
                break;
            }
        }
    }
    if (candidateKeyMgmtList.empty()) {
        return config.keyMgmt;
    }
    for (auto keyMgmt : candidateKeyMgmtList) {
        if (keyMgmt == KEY_MGMT_SAE) {
            return KEY_MGMT_SAE;
        }
    }
    return KEY_MGMT_WPA_PSK;
}

ErrCode StaStateMachine::ConvertDeviceCfg(WifiDeviceConfig &config, std::string& apBssid, std::string& ifaceName)
{
    WIFI_LOGI("Enter ConvertDeviceCfg.\n");
    WifiHalDeviceConfig halDeviceConfig;
    TransHalDeviceConfig(halDeviceConfig, config);
    if (strcmp(config.keyMgmt.c_str(), "WEP") == 0) {
        /* for wep */
        halDeviceConfig.authAlgorithms = 0x02;
    }
    halDeviceConfig.bssid = apBssid;

    if (config.keyMgmt == KEY_MGMT_WPA_PSK || config.keyMgmt == KEY_MGMT_SAE) {
        halDeviceConfig.keyMgmt = GetSuitableKeyMgmtForWpaMixed(config, halDeviceConfig.bssid);
        if (config.keyMgmt != halDeviceConfig.keyMgmt) {
            config.keyMgmt = halDeviceConfig.keyMgmt;
            WifiSettings::GetInstance().AddDeviceConfig(config);
            WifiSettings::GetInstance().SyncDeviceConfig();
        }
    }

    halDeviceConfig.isRequirePmf = halDeviceConfig.keyMgmt == KEY_MGMT_SAE;
    if (halDeviceConfig.isRequirePmf) {
        halDeviceConfig.allowedProtocols = 0x02; // RSN
        halDeviceConfig.allowedPairwiseCiphers = 0x2c; // CCMP|GCMP|GCMP-256
        halDeviceConfig.allowedGroupCiphers = 0x2c; // CCMP|GCMP|GCMP-256
    }

    for (int i = 0; i < HAL_MAX_WEPKEYS_SIZE; i++) {
        halDeviceConfig.wepKeys[i] = config.wepKeys[i];
    }
    WIFI_LOGI("ConvertDeviceCfg SetDeviceConfig selected network ssid=%{public}s, bssid=%{public}s, instId=%{public}d",
        SsidAnonymize(halDeviceConfig.ssid).c_str(), MacAnonymize(halDeviceConfig.bssid).c_str(), m_instId);
    ConvertSsidToOriginalSsid(config, halDeviceConfig);
    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(WPA_DEFAULT_NETWORKID, halDeviceConfig, ifaceName) !=
        WIFI_HAL_OPT_OK) {
        WIFI_LOGE("ConvertDeviceCfg SetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    if (SetExternalSim("wlan0", halDeviceConfig.eapConfig.eap, WIFI_EAP_OPEN_EXTERNAL_SIM)) {
        WIFI_LOGE("StaStateMachine::ConvertDeviceCfg: failed to set external_sim");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::SaveDiscReason(DisconnectedReason discReason)
{
    WifiConfigCenter::GetInstance().SaveDisconnectedReason(discReason, m_instId);
}

void StaStateMachine::SaveLinkstate(ConnState state, DetailedState detailState)
{
    linkedInfo.connState = state;
    linkedInfo.detailedState = detailState;
    linkedInfo.isAncoConnected = WifiConfigCenter::GetInstance().GetWifiConnectedMode(m_instId);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::OnNetManagerRestart(void)
{
    WIFI_LOGI("OnNetManagerRestart()");
    WifiNetAgent::GetInstance().OnStaMachineNetManagerRestart(NetSupplierInfo, m_instId);
}

void StaStateMachine::ReUpdateNetLinkInfo(const WifiDeviceConfig &config)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    WIFI_LOGI("ReUpdateNetLinkInfo, detailedState:%{public}d, connState:%{public}d",
        linkedInfo.detailedState, linkedInfo.connState);
    if ((linkedInfo.connState == ConnState::CONNECTED) && (linkedInfo.ssid == config.ssid) &&
        (linkedInfo.bssid == config.bssid)) {
        IpInfo wifiIpInfo;
        WifiConfigCenter::GetInstance().GetIpInfo(wifiIpInfo, m_instId);
        IpV6Info wifiIpV6Info;
        WifiConfigCenter::GetInstance().GetIpv6Info(wifiIpV6Info, m_instId);
        WifiDeviceConfig config;
        WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config, m_instId);
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(wifiIpInfo,
            wifiIpV6Info, config.wifiProxyconfig, m_instId);
    }
}

void StaStateMachine::SaveWifiConfigForUpdate(int networkId)
{
#ifdef WIFI_CONFIG_UPDATE
    WIFI_LOGI("Enter SaveWifiConfigForUpdate.");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) == -1) {
        WIFI_LOGE("SaveWifiConfigForUpdate, get current config failed.");
        return;
    }
    WifiConfigUpdate mWifiConfigUpdate;
    if (config.keyMgmt != KEY_MGMT_WEP) {
        mWifiConfigUpdate.SaveWifiConfig(config.ssid.c_str(), config.keyMgmt.c_str(), config.preSharedKey.c_str());
    } else {
        mWifiConfigUpdate.SaveWifiConfig(config.ssid.c_str(), config.keyMgmt.c_str(), config.wepKeys[0].c_str());
    }
#endif
}
#endif

void StaStateMachine::HandlePreDhcpSetup()
{
    WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(false, m_instId);
    if (m_instId == INSTID_WLAN0) {
        WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(false);
    }
}

bool StaStateMachine::IsSpecificNetwork()
{
#ifndef OHOS_ARCH_LITE
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config, m_instId);
    if (enhanceService_ == nullptr) {
        WIFI_LOGE("IsSpecificNetwork, enhanceService is null");
        return false;
    }
    return enhanceService_->IsSpecificNetwork(config);
#else
    return false;
#endif
}

void StaStateMachine::HandlePostDhcpSetup()
{
    WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(true, m_instId);
    if (m_instId == INSTID_WLAN0) {
        int screenState = WifiConfigCenter::GetInstance().GetScreenState();
        WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE);
    }
}

WifiDeviceConfig StaStateMachine::getCurrentWifiDeviceConfig()
{
    WIFI_LOGI("getCurrentWifiDeviceConfig, networkId %{public}d.", linkedInfo.networkId);
    WifiDeviceConfig wifiDeviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, wifiDeviceConfig, m_instId);
    return wifiDeviceConfig;
}

void StaStateMachine::InsertOrUpdateNetworkStatusHistory(const NetworkStatus &networkStatus,
    bool updatePortalAuthTime)
{
    WifiDeviceConfig wifiDeviceConfig = getCurrentWifiDeviceConfig();
    if (networkStatusHistoryInserted) {
        auto lastStatus = NetworkStatusHistoryManager::GetLastNetworkStatus(wifiDeviceConfig.networkStatusHistory);
        int screenState = WifiConfigCenter::GetInstance().GetScreenState();
        if (networkStatus == NetworkStatus::NO_INTERNET && (lastStatus == NetworkStatus::HAS_INTERNET ||
            screenState == MODE_STATE_CLOSE)) {
            WIFI_LOGI("No updated, current network status is %{public}d, last network status:%{public}d, "
                "screen state:%{public}d.",
                static_cast<int>(networkStatus), static_cast<int>(lastStatus), screenState);
        } else if (IsGoodSignalQuality() || (networkStatus == NetworkStatus::HAS_INTERNET) ||
            (networkStatus == NetworkStatus::PORTAL)) {
            NetworkStatusHistoryManager::Update(wifiDeviceConfig.networkStatusHistory, networkStatus);
            WIFI_LOGI("After updated, current network status history is %{public}s.",
                      NetworkStatusHistoryManager::ToString(wifiDeviceConfig.networkStatusHistory).c_str());
        } else {
            WIFI_LOGI("No updated, current network status history is %{public}s.",
                NetworkStatusHistoryManager::ToString(wifiDeviceConfig.networkStatusHistory).c_str());
        }
    } else {
        NetworkStatusHistoryManager::Insert(wifiDeviceConfig.networkStatusHistory, networkStatus);
        networkStatusHistoryInserted = true;
        WIFI_LOGI("After inserted, current network status history is %{public}s.",
                  NetworkStatusHistoryManager::ToString(wifiDeviceConfig.networkStatusHistory).c_str());
    }
    if (updatePortalAuthTime) {
        auto now = time(nullptr);
        wifiDeviceConfig.portalAuthTime = now;
    }
    if (networkStatus == NetworkStatus::PORTAL) {
        wifiDeviceConfig.isPortal = true;
        wifiDeviceConfig.noInternetAccess = true;
    }
    if (networkStatus == NetworkStatus::HAS_INTERNET) {
        wifiDeviceConfig.lastHasInternetTime = time(0);
        wifiDeviceConfig.noInternetAccess = false;
        WifiConfigCenter::GetInstance().GetIpInfo(wifiDeviceConfig.lastDhcpResult, m_instId);
    }
    if (networkStatus == NetworkStatus::NO_INTERNET && IsGoodSignalQuality()) {
        wifiDeviceConfig.noInternetAccess = true;
    }
    WifiSettings::GetInstance().AddDeviceConfig(wifiDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
}

void StaStateMachine::SetConnectMethod(int connectMethod)
{
    if (m_instId != INSTID_WLAN0) {
        WIFI_LOGI("instId:%{public}d, no need to set connect method.", m_instId);
        return;
    }
    std::string isConnectFromUser = "-1";
    switch (connectMethod) {
        case NETWORK_SELECTED_BY_AUTO:
            isConnectFromUser = AUTO_CONNECT;
            break;
        case NETWORK_SELECTED_BY_HILINK:
        case NETWORK_SELECTED_BY_USER:
            isConnectFromUser = USER_CONNECT;
            break;
        case NETWORK_SELECTED_BY_RETRY:
            break;
        default:
            break;
    }
    int ret = SetParamValue(WIFI_IS_CONNECT_FROM_USER, isConnectFromUser.c_str());
    std::string retStr = (ret == 0) ? "success" : ("fail,ret="+std::to_string(ret));
    WIFI_LOGI("SetConnectMethod %{public}s,connectMethod:%{public}d",
        retStr.c_str(), connectMethod);
    return;
}

bool StaStateMachine::IsGoodSignalQuality()
{
    const WifiLinkedInfo singalInfo = linkedInfo;
    bool isGoodSignal = true;
    int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(singalInfo.rssi, singalInfo.band, m_instId);
    if (currentSignalLevel <= RSSI_LEVEL_2) {
        isGoodSignal = false;
    }
    if (singalInfo.chload >= MAX_CHLOAD) {
        isGoodSignal = false;
    }
    return isGoodSignal;
}

void StaStateMachine::DealMloConnectionLinkInfo()
{
    if (linkedInfo.supportedWifiCategory != WifiCategory::WIFI7
        && linkedInfo.supportedWifiCategory != WifiCategory::WIFI7_PLUS) {
        WIFI_LOGD("%{public}s not support wifi7", __FUNCTION__);
        return;
    }
    if (!linkedInfo.isMloConnected) {
        WIFI_LOGI("%{public}s not support mlo connect", __FUNCTION__);
        return;
    }
    std::vector<WifiLinkedInfo> mloLinkedInfo;
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().GetConnectionMloLinkedInfo(ifname, mloLinkedInfo) != 0) {
        WIFI_LOGI("%{public}s GetConnectionMloLinkedInfo from wpas fail", __FUNCTION__);
        return;
    }
    WifiConfigCenter::GetInstance().SaveMloLinkedInfo(mloLinkedInfo, m_instId);
    WifiConfigCenter::GetInstance().SetMloWifiLinkedMaxSpeed(m_instId);
}

void StaStateMachine::UpdateLinkedBssid(std::string &bssid)
{
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WIFI_LOGI("linked bssid changed, %{public}s", MacAnonymize(bssid).c_str());
    WifiConfigCenter::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
        bssid, "");
#endif
    return;
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::UpdateLinkedInfoFromScanInfo()
{
    WIFI_LOGD("UpdateLinkedInfoFromScanInfo");
    std::vector<InterScanInfo> scanInfos;
    if (WifiStaHalInterface::GetInstance().QueryScanInfos(
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), scanInfos) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("WifiStaHalInterface::GetInstance().GetScanInfos failed.");
    }
    int chipsetCategory = static_cast<int>(WifiCategory::DEFAULT);
    if (WifiStaHalInterface::GetInstance().GetChipsetCategory(
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), chipsetCategory) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("GetChipsetCategory failed.\n");
    }
    int chipsetFeatrureCapability = 0;
    if (WifiStaHalInterface::GetInstance().GetChipsetWifiFeatrureCapability(
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), chipsetFeatrureCapability) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("GetChipsetWifiFeatrureCapability failed.\n");
    }
    
    for (auto iter = scanInfos.begin(); iter != scanInfos.end(); iter++) {
        if (enhanceService_ != nullptr) {
            WifiCategory category = enhanceService_->GetWifiCategory(iter->infoElems,
                chipsetCategory, chipsetFeatrureCapability);
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->RecordWifiCategory(iter->bssid, category);
        }

        if (iter->bssid == linkedInfo.bssid) {
            linkedInfo.channelWidth = iter->channelWidth;
            LOGI("centerFrequency0:%{public}d, centerFrequency1:%{public}d.",
                iter->centerFrequency0, iter->centerFrequency1);
            if ((iter->centerFrequency0 != 0) && (linkedInfo.centerFrequency0 != iter->centerFrequency0)) {
                linkedInfo.centerFrequency0 = iter->centerFrequency0;
            }
            if ((iter->centerFrequency1 != 0) && (linkedInfo.centerFrequency1 != iter->centerFrequency1)) {
                linkedInfo.centerFrequency1 = iter->centerFrequency1;
            }
        }
    }
}

void StaStateMachine::SetSupportedWifiCategory()
{
    if (m_instId != INSTID_WLAN0) {
        return;
    }
    if (linkedInfo.bssid.empty()) {
        WIFI_LOGE("%{public}s linked bssid is empty", __FUNCTION__);
        return;
    }
    WifiCategory category =
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetWifiCategoryRecord(linkedInfo.bssid);
    linkedInfo.supportedWifiCategory = category;
    if (category == WifiCategory::WIFI7 || category == WifiCategory::WIFI7_PLUS) {
        int chipsetFeatrureCapability = 0;
        if (WifiStaHalInterface::GetInstance().GetChipsetWifiFeatrureCapability(
            WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), chipsetFeatrureCapability) != WIFI_HAL_OPT_OK) {
            WIFI_LOGE("%{public}s GetChipsetWifiFeatrureCapability failed.", __FUNCTION__);
            return;
        }
        if (static_cast<unsigned int>(chipsetFeatrureCapability) & BIT_MLO_CONNECT) {
            WIFI_LOGD("%{public}s MLO linked", __FUNCTION__);
            linkedInfo.isMloConnected = true;
        } else {
            linkedInfo.isMloConnected = false;
        }
    } else {
        linkedInfo.isMloConnected = false;
    }
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    WIFI_LOGI("%{public}s supportedWifiCategory:%{public}d, isMloConnected:%{public}d, isHiLinkPro:%{public}d",
        __FUNCTION__, static_cast<int>(linkedInfo.supportedWifiCategory),
        linkedInfo.isMloConnected, linkedInfo.isHiLinkProNetwork);
}

void StaStateMachine::OnEnhanceServiceStaEvent(int eventId, int param)
{
    if (eventId == MultiLinkDefs::CBK_EVENT_REDHCP) {
        SendMessage(WIFI_SVR_CMD_STA_REDHCP);
    }
}

void StaStateMachine::SetEnhanceService(IEnhanceService* enhanceService)
{
    enhanceService_ = enhanceService;
    RegisterEnhanceServiceStaCallback();
}

void StaStateMachine::SetSelfCureService(ISelfCureService *selfCureService)
{
    selfCureService_ = selfCureService;
}

void StaStateMachine::RegisterEnhanceServiceStaCallback()
{
    if (enhanceService_ == nullptr || m_instId != INSTID_WLAN0) {
        return;
    }
    staEnhanceCallback_.OnGenelinkEvent = [this](int eventId, int param) {
        this->OnEnhanceServiceStaEvent(eventId, param);
    };
    enhanceService_->RegisterStaEnhanceCallback(staEnhanceCallback_);
}

void StaStateMachine::UnRegisterEnhanceServiceStaCallback()
{
    if (enhanceService_ == nullptr || m_instId != INSTID_WLAN0) {
        return;
    }
    staEnhanceCallback_.OnGenelinkEvent = nullptr;
    enhanceService_->RegisterStaEnhanceCallback(staEnhanceCallback_);
}

#endif

int setRssi(int rssi)
{
    if (rssi < INVALID_RSSI_VALUE) {
        rssi = INVALID_RSSI_VALUE;
    }

    if (rssi > MAX_RSSI_VALUE) {
        rssi = MAX_RSSI_VALUE;
    }
    return rssi;
}

int StaStateMachine::UpdateLinkInfoRssi(int inRssi)
{
    int outRssi = 0;
    if (inRssi > INVALID_RSSI_VALUE && inRssi < MAX_RSSI_VALUE) {
        if (inRssi > 0) {
            outRssi = setRssi((inRssi - SIGNAL_INFO));
        } else {
            outRssi = setRssi(inRssi);
        }
    } else {
        outRssi = INVALID_RSSI_VALUE;
    }
    return outRssi;
}

void StaStateMachine::DealSignalPacketChangedByTime(WifiSignalPollInfo &signalInfo)
{
    if (staSignalPollDelayTime_ == STA_SIGNAL_POLL_DELAY_WITH_TASK) {
        if (pktDirCnt_ % PKT_DIR_RPT_CNT == 0) {
            DealSignalPacketChanged(signalInfo.txPackets, signalInfo.rxPackets);
        }
        pktDirCnt_++;
    } else {
        DealSignalPacketChanged(signalInfo.txPackets, signalInfo.rxPackets);
        pktDirCnt_ = 0;
    }
}

void StaStateMachine::DealSignalPollResult()
{
    WifiSignalPollInfo signalInfo;
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().GetConnectSignalInfo(
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), linkedInfo.bssid, signalInfo);
    if (ret != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("GetConnectSignalInfo return fail: %{public}d.", ret);
        return;
    }
    DealMloLinkSignalPollResult();
    if (signalInfo.frequency > 0) {
        linkedInfo.frequency = signalInfo.frequency;
    }
    ConvertFreqToChannel();
    if (foldStatus_ == HALF_FOLD) {
        pLinkedState->halfFoldRssi_ = signalInfo.signal;
        WIFI_LOGI("rssiOffset_: %{public}d, halfFoldRssi_: %{public}d, foldStatus_: %{public}d\n",
            pLinkedState->rssiOffset_, pLinkedState->halfFoldRssi_, foldStatus_);
        if (pLinkedState->halfFoldRssi_ + pLinkedState->rssiOffset_ < 0) {
            pLinkedState->halfFoldUpdateRssi_ = pLinkedState->halfFoldRssi_ + pLinkedState->rssiOffset_;
        } else {
            pLinkedState->halfFoldUpdateRssi_ = pLinkedState->halfFoldRssi_;
        }
        UpdateLinkRssi(signalInfo, pLinkedState->halfFoldUpdateRssi_);
    } else {
        UpdateLinkRssi(signalInfo);
    }

    if (signalInfo.txrate > 0) {
        linkedInfo.txLinkSpeed = signalInfo.txrate / TRANSFORMATION_TO_MBPS;
        linkedInfo.linkSpeed = signalInfo.txrate / TRANSFORMATION_TO_MBPS;
    }

    if (signalInfo.rxrate > 0) {
        linkedInfo.rxLinkSpeed = signalInfo.rxrate / TRANSFORMATION_TO_MBPS;
    }

    linkedInfo.snr = signalInfo.snr;
    linkedInfo.chload = signalInfo.chload;
    signalInfo.timeStamp = GetCurrentTimeSeconds();
    if (linkedInfo.wifiStandard == WIFI_MODE_UNDEFINED) {
        WifiConfigCenter::GetInstance().SetWifiLinkedStandardAndMaxSpeed(linkedInfo);
    }
    pLinkedState->UpdateExpandOffset();
    WifiChrUtils::GetInstance().AddSignalPollInfoArray(signalInfo);
    LogSignalInfo(signalInfo);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    wifiDataReportService_->ReportQoeInfo(signalInfo, ConnReportReason::CONN_SUC_KEEP, linkedInfo.networkId);
#endif
#endif
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    DealSignalPacketChangedByTime(signalInfo);
    JudgeEnableSignalPoll(signalInfo);
}

void StaStateMachine::DealMloLinkSignalPollResult()
{
    if (linkedInfo.wifiLinkType != WifiLinkType::WIFI7_EMLSR) {
        WIFI_LOGD("%{public}s current linkType is not EMLSR", __FUNCTION__);
        return;
    }
    std::vector<WifiMloSignalInfo> mloSignalInfo;
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().GetConnectionMloSignalInfo(ifName, mloSignalInfo) != WIFI_HAL_OPT_OK ||
        mloSignalInfo.size() != WIFI_MAX_MLO_LINK_NUM) {
        return;
    }
    std::vector<WifiLinkedInfo> mloLinkedInfo;
    if (WifiConfigCenter::GetInstance().GetMloLinkedInfo(mloLinkedInfo, m_instId) < 0) {
        WIFI_LOGE("%{public}s get mlo linkInfo fail", __FUNCTION__);
        return;
    }
    for (auto &linkInfo : mloLinkedInfo) {
        bool isLinkedMatch = false;
        for (auto signalInfo : mloSignalInfo) {
            if (signalInfo.linkId != linkInfo.linkId) {
                continue;
            }
            isLinkedMatch = true;
            int rssi = UpdateLinkInfoRssi(signalInfo.rssi);
            WIFI_LOGI("MloSignalPollResult ssid:%{public}s, bssid:%{public}s, linkId:%{public}d, rssi: %{public}d,"
                "fre: %{public}d, txSpeed: %{public}d, rxSpeed: %{public}d, deltaTxPackets: %{public}d, deltaRxPackets:"
                "%{public}d", SsidAnonymize(linkedInfo.ssid).c_str(), MacAnonymize(linkInfo.bssid).c_str(),
                linkInfo.linkId, rssi, signalInfo.frequency, signalInfo.txLinkSpeed, signalInfo.rxLinkSpeed,
                signalInfo.txPackets - linkInfo.lastTxPackets, signalInfo.rxPackets - linkInfo.lastRxPackets);

            linkInfo.rssi = rssi;
            linkInfo.frequency = signalInfo.frequency;
            linkInfo.linkSpeed = signalInfo.txLinkSpeed;
            linkInfo.txLinkSpeed = signalInfo.txLinkSpeed;
            linkInfo.rxLinkSpeed = signalInfo.rxLinkSpeed;
            linkInfo.lastTxPackets = signalInfo.txPackets;
            linkInfo.lastRxPackets = signalInfo.rxPackets;
        }
        if (!isLinkedMatch) {
            WIFI_LOGE("%{public}s linkId:%{public}d not match", __FUNCTION__, linkInfo.linkId);
            return;
        }
    }
    WifiConfigCenter::GetInstance().SaveMloLinkedInfo(mloLinkedInfo, m_instId);
}

void StaStateMachine::JudgeEnableSignalPoll(WifiSignalPollInfo &signalInfo)
{
#ifndef OHOS_ARCH_LITE
    if (enhanceService_ != nullptr) {
        enhanceService_->SetEnhanceSignalPollInfo(signalInfo);
    }
#endif
    EnhanceWriteLinkInfoHiSysEvent(lastSignalLevel_, linkedInfo.rssi, linkedInfo.band, linkedInfo.linkSpeed);
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnWifiHalSignalInfoChange != nullptr) {
            callBackItem.second.OnWifiHalSignalInfoChange(signalInfo);
        }
        if (callBackItem.second.OnSignalPollReport != nullptr && linkedInfo.wifiLinkType != WifiLinkType::WIFI7_EMLSR) {
            callBackItem.second.OnSignalPollReport(linkedInfo.bssid, lastSignalLevel_, m_instId);
        }
    }
    if (enableSignalPoll) {
        WIFI_LOGD("SignalPoll, StartTimer for SIGNAL_POLL.\n");
        StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
        StartTimer(static_cast<int>(CMD_SIGNAL_POLL), staSignalPollDelayTime_, MsgLogLevel::LOG_D);
    }
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::HandleForegroundAppChangedAction(InternalMessagePtr msg)
{
    AppExecFwk::AppStateData appStateData;
    if (!msg->GetMessageObj(appStateData)) {
        WIFI_LOGE("Failed to obtain appStateData information");
        return;
    }
    if (appStateData.state == static_cast<int>(AppExecFwk::AppProcessState::APP_STATE_FOREGROUND) &&
        appStateData.isFocused) {
        curForegroundAppBundleName_ = appStateData.bundleName;
        std::string sceneboardBundle = WifiSettings::GetInstance().GetPackageName("SCENEBOARD_BUNDLE");
        if (curForegroundAppBundleName_ != "" && sceneboardBundle != "" &&
            curForegroundAppBundleName_ != sceneboardBundle) {
            staSignalPollDelayTime_ = STA_SIGNAL_POLL_DELAY_WITH_TASK;
        } else {
            staSignalPollDelayTime_ = STA_SIGNAL_POLL_DELAY;
        }
    }
}
#endif

void StaStateMachine::UpdateLinkRssi(const WifiSignalPollInfo &signalInfo, int foldStateRssi)
{
    if (linkSwitchDetectingFlag_) {
        WIFI_LOGI("%{public}s link switch detecting, not update rssi", __FUNCTION__);
        return;
    }
    int curRssi = signalInfo.signal;
    std::vector<WifiLinkedInfo> mloLinkedInfo;
    if (linkedInfo.wifiLinkType == WifiLinkType::WIFI7_EMLSR &&
        WifiConfigCenter::GetInstance().GetMloLinkedInfo(mloLinkedInfo, m_instId) == 0) {
        for (auto& info : mloLinkedInfo) {
            if (info.rssi > curRssi) {
                curRssi = info.rssi;
            }
        }
        WIFI_LOGD("%{public}s signalInfoRssi: %{public}d, maxRssi: %{public}d",
            __FUNCTION__, signalInfo.signal, curRssi);
    }

    int currentSignalLevel = 0;
    if (foldStateRssi != INVALID_RSSI_VALUE) {
        linkedInfo.rssi = setRssi(foldStateRssi);
    } else if (curRssi > INVALID_RSSI_VALUE && curRssi < MAX_RSSI_VALUE) {
        if (curRssi > 0) {
            linkedInfo.rssi = setRssi((curRssi - SIGNAL_INFO));
        } else {
            linkedInfo.rssi = setRssi(curRssi);
        }
    } else {
        linkedInfo.rssi = INVALID_RSSI_VALUE;
    }

    if (linkedInfo.rssi != INVALID_RSSI_VALUE) {
        currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band, m_instId);
        if (currentSignalLevel != lastSignalLevel_) {
            WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
            InvokeOnStaRssiLevelChanged(linkedInfo.rssi);
            lastSignalLevel_ = currentSignalLevel;
        }
    }

    linkedInfo.c0Rssi = UpdateLinkInfoRssi(signalInfo.c0Rssi);
    linkedInfo.c1Rssi = UpdateLinkInfoRssi(signalInfo.c1Rssi);
}

void StaStateMachine::DealSignalPacketChanged(int txPackets, int rxPackets)
{
    int send = txPackets - linkedInfo.lastTxPackets;
    int received = rxPackets - linkedInfo.lastRxPackets;
    int direction = 0;
    if (send > STREAM_TXPACKET_THRESHOLD) {
        direction |= static_cast<int>(StreamDirection::STREAM_DIRECTION_UP);
    }
    if (received > STREAM_RXPACKET_THRESHOLD) {
        direction |= static_cast<int>(StreamDirection::STREAM_DIRECTION_DOWN);
    }
    if (direction != linkedInfo.lastPacketDirection) {
        WriteWifiSignalHiSysEvent(direction, txPackets, rxPackets);
        InvokeOnStaStreamChanged(static_cast<StreamDirection>(direction));
    }
    linkedInfo.lastPacketDirection = direction;
    linkedInfo.lastRxPackets = rxPackets;
    linkedInfo.lastTxPackets = txPackets;
}

void StaStateMachine::ConvertFreqToChannel()
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config, m_instId) != 0) {
        WIFI_LOGE("GetDeviceConfig failed!");
        return;
    }
    int lastBand = linkedInfo.band;
    config.frequency = linkedInfo.frequency;
    if (linkedInfo.frequency >= FREQ_2G_MIN && linkedInfo.frequency <= FREQ_2G_MAX) {
        config.band = linkedInfo.band = static_cast<int>(BandType::BAND_2GHZ);
        config.channel = (linkedInfo.frequency - FREQ_2G_MIN) / CENTER_FREQ_DIFF + CHANNEL_2G_MIN;
    } else if (linkedInfo.frequency == CHANNEL_14_FREQ) {
        config.channel = CHANNEL_14;
    } else if (linkedInfo.frequency >= FREQ_5G_MIN && linkedInfo.frequency <= FREQ_5G_MAX) {
        config.band = linkedInfo.band = static_cast<int>(BandType::BAND_5GHZ);
        config.channel = (linkedInfo.frequency - FREQ_5G_MIN) / CENTER_FREQ_DIFF + CHANNEL_5G_MIN;
    }
    if (lastBand != linkedInfo.band) {
        WriteWifiBandHiSysEvent(linkedInfo.band);
    }
    WifiSettings::GetInstance().AddDeviceConfig(config);
    return;
}

bool StaStateMachine::CurrentIsRandomizedMac()
{
    std::string curMacAddress = "";
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(curMacAddress, ifaceName)) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("CurrentIsRandomizedMac GetStaDeviceMacAddress failed!");
        return false;
    }
    std::string realMacAddress = "";
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddress, m_instId);
    WIFI_LOGI("CurrentIsRandomizedMac curMacAddress:%{public}s realMacAddress:%{public}s",
        MacAnonymize(curMacAddress).c_str(), MacAnonymize(realMacAddress).c_str());
    return curMacAddress != realMacAddress;
}

void StaStateMachine::HilinkSaveConfig(void)
{
    WIFI_LOGI("enter HilinkSaveConfig");
    WifiDeviceConfig outConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(m_hilinkDeviceConfig.ssid, m_hilinkDeviceConfig.keyMgmt,
        outConfig, m_instId) == 0) {
        m_hilinkDeviceConfig.networkId = outConfig.networkId;
    } else {
        m_hilinkDeviceConfig.networkId = WifiSettings::GetInstance().GetNextNetworkId();
    }
    targetNetworkId_ = m_hilinkDeviceConfig.networkId;
    WifiSettings::GetInstance().SetKeyMgmtBitset(m_hilinkDeviceConfig);
    WifiStaHalInterface::GetInstance().GetPskPassphrase("wlan0", m_hilinkDeviceConfig.preSharedKey);
    m_hilinkDeviceConfig.version = -1;
    if (!WifiSettings::GetInstance().EncryptionDeviceConfig(m_hilinkDeviceConfig)) {
        WIFI_LOGE("HilinkSaveConfig EncryptionDeviceConfig failed");
    }
    WifiSettings::GetInstance().AddDeviceConfig(m_hilinkDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    WifiSettings::GetInstance().SetUserConnectChoice(targetNetworkId_);

    WifiConfigCenter::GetInstance().SetMacAddress(m_hilinkDeviceConfig.macAddress, m_instId);
    m_hilinkFlag = false;
}

static constexpr int DIS_REASON_DISASSOC_STA_HAS_LEFT = 8;

bool StaStateMachine::IsDisConnectReasonShouldStopTimer(int reason)
{
    return reason == DIS_REASON_DISASSOC_STA_HAS_LEFT;
}

void StaStateMachine::AddRandomMacCure()
{
    if (targetNetworkId_ == mLastConnectNetId) {
        mConnectFailedCnt++;
    }
}

void StaStateMachine::DealSetStaConnectFailedCount(int count, bool set)
{
    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId_, config, m_instId);
    if (ret != 0) {
        WIFI_LOGW("DealSetStaConnectFailedCount get device[%{public}d] config failed.\n", targetNetworkId_);
        return;
    }
    if (set) {
        WifiSettings::GetInstance().SetDeviceConnFailedCount(config.bssid, DEVICE_CONFIG_INDEX_BSSID,
            count);
    } else {
        WifiSettings::GetInstance().IncreaseDeviceConnFailedCount(config.bssid, DEVICE_CONFIG_INDEX_BSSID,
            count);
    }
}

void StaStateMachine::DealReassociateCmd(InternalMessagePtr msg)
{
    WIFI_LOGI("enter DealReassociateCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    EnhanceWriteConnectTypeHiSysEvent(NETWORK_SELECTED_BY_REASSOC);
    if (linkedInfo.isMloConnected && WifiStaHalInterface::GetInstance().SetBssid(
        WPA_DEFAULT_NETWORKID, linkedInfo.bssid,
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId)) == WIFI_HAL_OPT_OK) {
        WIFI_LOGI("Reassociate to same bssid for wifi7 mlo!\n");
    }
    if (WifiStaHalInterface::GetInstance().Reassociate(ifaceName) == WIFI_HAL_OPT_OK) {
        /* Callback result to InterfaceService */
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATING, linkedInfo);
        WIFI_LOGD("StaStateMachine ReAssociate successfully!");
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
        StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    } else {
        WIFI_LOGE("ReAssociate failed!");
    }
}

void StaStateMachine::UserSelectConnectToNetwork(WifiDeviceConfig& deviceConfig, std::string& apBssid)
{
    if (!deviceConfig.userSelectBssid.empty()) {
        WIFI_LOGI("SetBssid userSelectBssid=%{public}s", MacAnonymize(deviceConfig.userSelectBssid).c_str());
        apBssid = deviceConfig.userSelectBssid;
    } else {
        std::string autoSelectBssid;
        std::unique_ptr<NetworkSelectionManager> networkSelectionManager = std::make_unique<NetworkSelectionManager>();
        networkSelectionManager->SelectNetworkWithSsid(deviceConfig, autoSelectBssid);
        WIFI_LOGI("SetBssid autoSelectBssid=%{public}s", MacAnonymize(autoSelectBssid).c_str());
        apBssid = autoSelectBssid;
    }
    deviceConfig.userSelectBssid = "";
    WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return;
}

ErrCode StaStateMachine::StartConnectToNetwork(int networkId, const std::string & bssid, int connTriggerMode)
{
    if (m_instId == INSTID_WLAN0 && ConfigRandMacSelfCure(networkId) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ConfigRandMacSelfCure failed!");
        return WIFI_OPT_FAILED;
    }
    if (connTriggerMode == NETWORK_SELECTED_BY_USER) {
        BlockConnectService::GetInstance().EnableNetworkSelectStatus(networkId);
#ifdef WIFI_SECURITY_DETECT_ENABLE
        WifiSecurityDetect::GetInstance().SetChangeNetworkid(networkId);
#endif
        WifiSettings::GetInstance().SetUserConnectChoice(networkId);
    }
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig, m_instId) != 0) {
        WIFI_LOGE("StartConnectToNetwork get GetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    if (connTriggerMode == NETWORK_SELECTED_BY_USER && !HasMultiBssidAp(deviceConfig)) {
        BlockConnectService::GetInstance().ReleaseUnusableBssidSet();
    }
#endif
    targetNetworkId_ = networkId;
    linkSwitchDetectingFlag_ = false;
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    if (deviceConfig.wifiPrivacySetting == WifiPrivacyConfig::RANDOMMAC &&
        WifiSettings::GetInstance().IsRandomMacDisabled(m_instId)) {
        ReportMdmRestrictedEvent(deviceConfig.ssid, deviceConfig.bssid, "MDM_RESTRICTED");
    }
#endif
    std::string apBssid = bssid;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (apBssid.empty()) {
        // user select connect
        UserSelectConnectToNetwork(deviceConfig, apBssid);
    } else {
        WIFI_LOGI("SetBssid bssid=%{public}s", MacAnonymize(apBssid).c_str());
    }
    if (connTriggerMode != NETWORK_SELECTED_BY_FAST_RECONNECT) {
        SetRandomMac(deviceConfig, apBssid);
    }
    WIFI_LOGI("StartConnectToNetwork SetRandomMac targetNetworkId_:%{public}d, bssid:%{public}s", targetNetworkId_,
        MacAnonymize(apBssid).c_str());
    EnhanceWriteWifiConnectionInfoHiSysEvent(networkId);
    EnhanceWriteConnectTypeHiSysEvent(connTriggerMode, deviceConfig.lastConnectTime <= 0);
    EnhanceWriteStaConnectIface(ifaceName);
    WifiStaHalInterface::GetInstance().ClearDeviceConfig(ifaceName);
    int wpaNetworkId = WPA_DEFAULT_NETWORKID;
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().GetNextNetworkId(wpaNetworkId, ifaceName);
    if (ret != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("StartConnectToNetwork GetNextNetworkId failed!");
        WriteAssocFailHiSysEvent("GetNextNetworkId failed", static_cast<int>(ret));
        return WIFI_OPT_FAILED;
    }
    ConvertDeviceCfg(deviceConfig, apBssid, ifaceName);
#ifndef OHOS_ARCH_LITE
#ifdef WIFI_DATA_REPORT_ENABLE
    wifiDataReportService_->InitReportApAllInfo();
#endif
#endif
    if (WifiStaHalInterface::GetInstance().Connect(WPA_DEFAULT_NETWORKID, ifaceName) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Connect failed!");
        InvokeOnStaConnChanged(OperateResState::CONNECT_SELECT_NETWORK_FAILED, linkedInfo);
        return WIFI_OPT_FAILED;
    }
    connectMethod_ = connTriggerMode;
    WifiConfigCenter::GetInstance().EnableNetwork(networkId, connTriggerMode == NETWORK_SELECTED_BY_USER, m_instId);
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::MacAddressGenerate(WifiStoreRandomMac &randomMacInfo)
{
    WIFI_LOGD("enter MacAddressGenerate\n");
    constexpr int arraySize = 4;
    constexpr int macBitSize = 12;
    constexpr int firstBit = 1;
    constexpr int lastBit = 11;
    constexpr int two = 2;
    constexpr int hexBase = 16;
    constexpr int octBase = 8;
    int ret = 0;
    char strMacTmp[arraySize] = {0};
    std::mt19937_64 gen(std::chrono::high_resolution_clock::now().time_since_epoch().count()
        + std::hash<std::string>{}(randomMacInfo.peerBssid) + std::hash<std::string>{}(randomMacInfo.preSharedKey));
    for (int i = 0; i < macBitSize; i++) {
        if (i != firstBit) {
            std::uniform_int_distribution<> distribution(0, hexBase - 1);
            ret = sprintf_s(strMacTmp, arraySize, "%x", distribution(gen));
        } else {
            std::uniform_int_distribution<> distribution(0, octBase - 1);
            ret = sprintf_s(strMacTmp, arraySize, "%x", two * distribution(gen));
        }
        if (ret == -1) {
            WIFI_LOGE("StaStateMachine::MacAddressGenerate failed, sprintf_s return -1!\n");
        }
        randomMacInfo.randomMac += strMacTmp;
        if ((i % two) != 0 && (i != lastBit)) {
            randomMacInfo.randomMac.append(":");
        }
    }
}

int StaStateMachine::GetWpa3FailCount(int failreason, std::string ssid) const
{
    if (failreason < 0 || failreason >= WPA3_FAIL_REASON_MAX) {
        WIFI_LOGE("GetWpa3FailCount, Err failreason");
        return 0;
    }
    auto iter = wpa3ConnectFailCountMapArray[failreason].find(ssid);
    if (iter == wpa3ConnectFailCountMapArray[failreason].end()) {
        WIFI_LOGI("GetWpa3FailCount, no failreason count");
        return 0;
    }
    WIFI_LOGI("GetWpa3FailCount, failreason=%{public}d, count=%{public}d",
        failreason, iter->second);
    return iter->second;
}

void StaStateMachine::AddWpa3FailCount(int failreason, std::string ssid)
{
    if (failreason < 0 || failreason >= WPA3_FAIL_REASON_MAX) {
        WIFI_LOGE("AddWpa3FailCount, Err failreason");
        return;
    }
    auto iter = wpa3ConnectFailCountMapArray[failreason].find(ssid);
    if (iter == wpa3ConnectFailCountMapArray[failreason].end()) {
        WIFI_LOGI("AddWpa3FailCount, new failreason count");
        wpa3ConnectFailCountMapArray[failreason].insert(std::make_pair(ssid, 1));
    } else {
        WIFI_LOGI("AddWpa3FailCount, existed failreason count");
        iter->second = iter->second + 1;
    }
}

void StaStateMachine::AddWpa3BlackMap(std::string ssid)
{
    if (wpa3BlackMap.size() == WPA3_BLACKMAP_MAX_NUM) {
        auto iter = wpa3BlackMap.begin();
        auto oldestIter = wpa3BlackMap.begin();
        for (; iter != wpa3BlackMap.end(); iter++) {
            if (iter->second < oldestIter->second) {
                oldestIter = iter;
            }
        }
        WIFI_LOGI("AddWpa3BlackMap, map full, delete oldest");
        wpa3BlackMap.erase(oldestIter);
    }
    WIFI_LOGI("AddWpa3BlackMap success");
    wpa3BlackMap.insert(std::make_pair(ssid, time(0)));
}

bool StaStateMachine::IsInWpa3BlackMap(std::string ssid) const
{
    auto iter = wpa3BlackMap.find(ssid);
    if (iter != wpa3BlackMap.end()) {
        WIFI_LOGI("check is InWpa3BlackMap");
        return true;
    }
    return false;
}

void StaStateMachine::OnWifiWpa3SelfCure(int failreason, int networkId)
{
    WifiDeviceConfig config;
    int failCountReason = 0;

    WIFI_LOGI("OnWifiWpa3SelfCure Enter.");
    auto iter = wpa3FailreasonMap.find(failreason);
    if (iter == wpa3FailreasonMap.end()) {
        WIFI_LOGE("OnWifiWpa3SelfCure, Invalid fail reason");
        return;
    }
    failCountReason = iter->second;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) == -1) {
        WIFI_LOGE("OnWifiWpa3SelfCure, get deviceconfig failed");
        return;
    }
    if (!IsWpa3Transition(config.ssid, config.bssid)) {
        WIFI_LOGE("OnWifiWpa3SelfCure, is not wpa3 transition");
        return;
    }
    if (linkedInfo.rssi <= WPA3_BLACKMAP_RSSI_THRESHOLD) {
        WIFI_LOGE("OnWifiWpa3SelfCure, rssi less then -70");
        return;
    }
    if (config.lastConnectTime > 0) {
        WIFI_LOGE("OnWifiWpa3SelfCure, has ever connected");
        return;
    }
    AddWpa3FailCount(failCountReason, config.ssid);
    if (GetWpa3FailCount(failCountReason, config.ssid) < WPA3_CONNECT_FAIL_COUNT_THRESHOLD) {
        WIFI_LOGI("OnWifiWpa3SelfCure, fail count not enough.");
        return;
    }
    AddWpa3BlackMap(config.ssid);
    StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    SendMessage(WIFI_SVR_CMD_STA_CONNECT_NETWORK, networkId, NETWORK_SELECTED_BY_USER);
}

bool StaStateMachine::IsWpa3Transition(std::string ssid, std::string bssid) const
{
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    for (auto scanInfo : scanInfoList) {
        if (ssid != scanInfo.ssid) {
            continue;
        }
        if (bssid.empty()) {
            if (scanInfo.capabilities.find("PSK+SAE") != std::string::npos) {
                LOGI("IsWpa3Transition, check is transition ");
                return true;
            }
        } else {
            if ((bssid == scanInfo.bssid) &&
                (scanInfo.capabilities.find("PSK+SAE") != std::string::npos)) {
                LOGI("IsWpa3Transition, check is transition bssid same");
                return true;
            }
        }
    }
    return false;
}

void StaStateMachine::InitRandomMacInfo(const WifiDeviceConfig &deviceConfig, const std::string &bssid,
    WifiStoreRandomMac &randomMacInfo)
{
    randomMacInfo.ssid = deviceConfig.ssid;
    randomMacInfo.keyMgmt = deviceConfig.keyMgmt;
    randomMacInfo.preSharedKey = deviceConfig.preSharedKey;

    if (!bssid.empty()) {
        randomMacInfo.peerBssid = bssid;
    } else {
        std::vector<WifiScanInfo> scanInfoList;
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
        for (auto scanInfo : scanInfoList) {
            std::string deviceKeyMgmt;
            scanInfo.GetDeviceMgmt(deviceKeyMgmt);
            if ((deviceConfig.ssid == scanInfo.ssid) && deviceKeyMgmt.find(deviceConfig.keyMgmt) != std::string::npos) {
                randomMacInfo.peerBssid = scanInfo.bssid;
                break;
            }
        }
    }
    if (randomMacInfo.peerBssid.empty()) {
        LOGI("scanInfo has no target wifi and bssid is empty!");
    }
}

static constexpr int STA_CONNECT_RANDOMMAC_MAX_FAILED_COUNT = 2;

bool StaStateMachine::ShouldUseFactoryMac(const WifiDeviceConfig &deviceConfig)
{
    if (deviceConfig.keyMgmt == KEY_MGMT_NONE) {
        return false;
    }
    if (mLastConnectNetId != deviceConfig.networkId) {
        mLastConnectNetId = deviceConfig.networkId;
        mConnectFailedCnt = 0;
    }
    WIFI_LOGI("ShouldUseFactoryMac mLastConnectNetId:%{public}d networkId:%{public}d mConnectFailedCnt:%{public}d",
        mLastConnectNetId, deviceConfig.networkId, mConnectFailedCnt);
    if (mConnectFailedCnt >= STA_CONNECT_RANDOMMAC_MAX_FAILED_COUNT && !deviceConfig.randomizedMacSuccessEver) {
        return true;
    }
    return false;
}

void StaStateMachine::SetRandomMacConfig(WifiStoreRandomMac &randomMacInfo, const WifiDeviceConfig &deviceConfig,
    std::string &currentMac)
{
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    std::string macAddress;
    std::string deviceConfigKey = deviceConfig.ssid + deviceConfig.keyMgmt;
    int ret = WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(deviceConfigKey, macAddress);
    if (ret != 0) {
        ret = WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(deviceConfigKey, macAddress);
    }
    if (ret != 0) {
        WIFI_LOGI("%{public}s Failed to generate MAC address from huks even after retrying."
            "Using locally generated MAC address instead.", __func__);
        WifiRandomMacHelper::GenerateRandomMacAddress(macAddress);
    }
    randomMacInfo.randomMac = macAddress;
    currentMac = randomMacInfo.randomMac;
    WIFI_LOGI("%{public}s: generate a random mac, randomMac:%{public}s, ssid:%{public}s, peerbssid:%{public}s",
        __func__, MacAnonymize(randomMacInfo.randomMac).c_str(), SsidAnonymize(randomMacInfo.ssid).c_str(),
        MacAnonymize(randomMacInfo.peerBssid).c_str());
#endif
}

bool StaStateMachine::SetMacToHal(const std::string &currentMac, const std::string &realMac, int instId)
{
    std::string lastMac;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(instId);
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(lastMac, ifaceName)) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("%{public}s randommac, GetStaDeviceMacAddress failed!", __func__);
        return false;
    }
    bool isRealMac = currentMac == realMac;
    WIFI_LOGI("%{public}s, randommac, use %{public}s mac to connect, currentMac:%{public}s, lastMac:%{public}s",
        __func__, isRealMac ? "factory" : "random", MacAnonymize(currentMac).c_str(), MacAnonymize(lastMac).c_str());
    std::string actualConfiguredMac = currentMac;
    if (!isRealMac && instId == 1) {
        if (!WifiRandomMacHelper::GetWifi2RandomMac(actualConfiguredMac)) {
            actualConfiguredMac = realMac;
        }
        WIFI_LOGI("%{public}s wifi2 actualConfiguredMac: %{public}s", __func__,
            MacAnonymize(actualConfiguredMac).c_str());
    }
    if (MacAddress::IsValidMac(actualConfiguredMac.c_str())) {
        // always set mac to hal to update drivers mac
        // In the subsequent evolution, will set a pure random mac in disconneting process. and don't duplicate set mac
        // when start connect
#ifndef OHOS_ARCH_LITE
        if (enhanceService_ != nullptr &&
            enhanceService_->GenelinkInterface(MultiLinkDefs::QUERY_RANDOM_MAC_REQUIRED,
                instId) == MultiLinkDefs::RANDOM_MAC_NOT_USED) {
            WIFI_LOGE("no need set random mac instId = %{public}d", instId);
            return true;
        }
#endif
        if (WifiStaHalInterface::GetInstance().SetConnectMacAddr(
            WifiConfigCenter::GetInstance().GetStaIfaceName(instId), actualConfiguredMac) != WIFI_HAL_OPT_OK) {
                WIFI_LOGE("set Mac [%{public}s] failed", MacAnonymize(actualConfiguredMac).c_str());
                return false;
            }
        WifiConfigCenter::GetInstance().SetMacAddress(actualConfiguredMac, instId);
        return true;
    } else {
        WIFI_LOGE("%{public}s randommac, Check MacAddress error", __func__);
        return false;
    }
}

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
void StaStateMachine::DealMdmRestrictedConnect(WifiDeviceConfig &config)
{
    WIFI_HILOG_COMM_INFO("WIFI Disconnect by MdmRestricted");
    SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_MDM_BLOCKLIST_FAIL);
    BlockConnectService::GetInstance().UpdateNetworkSelectStatus(config.networkId,
        DisabledReason::DISABLED_MDM_RESTRICTED);
    AddRandomMacCure();
    InvokeOnStaConnChanged(OperateResState::CONNECT_ENABLE_NETWORK_FAILED,
        linkedInfo);
    StartDisConnectToNetwork();
}

bool StaStateMachine::WhetherRestrictedByMdm(const std::string &ssid, const std::string &bssid, bool checkBssid)
{
    if (checkBssid) {
        return WifiSettings::GetInstance().FindWifiBlockListConfig(ssid, bssid, 0) ||
        (WifiSettings::GetInstance().WhetherSetWhiteListConfig() &&
        !WifiSettings::GetInstance().FindWifiWhiteListConfig(ssid, bssid, 0));
    } else {
        if (WifiSettings::GetInstance().FindWifiBlockListConfig(ssid, bssid, 0)) {
            return true;
        }
        if (!WifiSettings::GetInstance().WhetherSetWhiteListConfig() || bssid.empty()) {
            return false;
        }
        if (!WifiSettings::GetInstance().FindWifiWhiteListConfig(ssid, bssid)) {
            return true;
        }
        return false;
    }
}

void StaStateMachine::ReportMdmRestrictedEvent(const std::string &ssid, const std::string &bssid,
    const std::string &restrictedType)
{
    int uid = GetCallingUid();
    std::string bundleName = "";
    GetBundleNameByUid(uid, bundleName);
    MdmRestrictedInfo mdmInfo;
    mdmInfo.ssid = ssid;
    mdmInfo.bssid = bssid;
    mdmInfo.restrictedType = restrictedType;
    mdmInfo.uid = uid;
    mdmInfo.bundleName = bundleName;
    WriteMdmHiSysEvent(mdmInfo);
}
#endif

void StaStateMachine::StartConnectToBssid(const int32_t networkId, std::string bssid, int32_t type)
{
    InternalMessagePtr msg = CreateMessage();
    if (msg == nullptr) {
        return;
    }
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
        WIFI_LOGE("GetDeviceConfig failed, networkId = %{public}d", networkId);
        return;
    }
    if (WifiSettings::GetInstance().FindWifiBlockListConfig(config.ssid, config.bssid, 0)) {
        return;
    }
    if (WifiSettings::GetInstance().WhetherSetWhiteListConfig() &&
        !WifiSettings::GetInstance().FindWifiWhiteListConfig(config.ssid, config.bssid, 0)) {
        return;
    }
#endif
#ifndef OHOS_ARCH_LITE
    if (m_instId == INSTID_WLAN0 && type != NETWORK_SELECTED_BY_GENELINK &&
        enhanceService_ != nullptr) {
        enhanceService_->GenelinkInterface(MultiLinkDefs::NOTIFY_QUIT_DUAL_WLAN, 0);
        WIFI_LOGI("notify enhance service quit dual_wlan mode");
    }
#endif
    msg->SetMessageName(WIFI_SVR_COM_STA_START_ROAM);
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

#ifndef OHOS_ARCH_LITE
bool StaStateMachine::IsValidSimId(int32_t simId)
{
    if (simId > 0) {
        return true;
    }
    return false;
}


/* Calculate SRES and KC as 2G authentication.
 * Protocol: 3GPP TS 31.102 2G_authentication
 * Request messge: [Length][RAND1][Length][RAND2]...[Length][RANDn]
 * Response messge: [SRES Length][SRES][KC Length][Cipher Key Kc]
*/
std::string StaStateMachine::GetGsmAuthResponseWithLength(EapSimGsmAuthParam param)
{
    int i = 0;
    std::string authRsp;
    uint8_t randArray[GSM_AUTH_RAND_LEN] = { 0 };

    WIFI_LOGI("%{public}s size:%{public}zu", __func__, param.rands.size());
    for (auto iter = param.rands.begin(); iter != param.rands.end(); ++iter) {
        // data pre-processing
        if (memset_s(randArray, sizeof(randArray), 0x0, sizeof(randArray)) != EOK) {
            WIFI_LOGE("%{public}s: memset_s is failed", __func__);
            return "";
        }
        char tmpRand[MAX_RAND_STR_LEN + 1] = { 0 };
        if (strncpy_s(tmpRand, sizeof(tmpRand), (*iter).c_str(), (*iter).length()) != EOK) {
            WIFI_LOGE("%{public}s: failed to copy", __func__);
            return "";
        }
        WIFI_LOGD("%{public}s rand[%{public}d]: %{private}s, tmpRand: %{private}s",
            __func__, i, (*iter).c_str(), tmpRand);

        // converting a hexadecimal character string to an array
        int ret = HexString2Byte(tmpRand, randArray, sizeof(randArray));
        if (ret != 0) {
            WIFI_LOGE("%{public}s: failed to convert a hexadecimal character string to integer", __func__);
            return "";
        }
        std::vector<uint8_t> randVec;
        randVec.push_back(sizeof(randArray));
        for (size_t j = 0; j < sizeof(randArray); j++) {
            randVec.push_back(randArray[j]);
        }

        // encode data and initiate a challenge request
        std::string base64Challenge = EncodeBase64(randVec);
        WifiDeviceConfig deviceConfig;
        WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId_, deviceConfig, m_instId);
        std::string response = WifiTelephonyUtils::SimAkaAuth(
            base64Challenge, WifiTelephonyUtils::AuthType::SIM_TYPE, deviceConfig.wifiEapConfig.eapSubId);
        if (response.empty()) {
            WIFI_LOGE("%{public}s: fail to sim authentication", __func__);
            return "";
        }
        WIFI_LOGD("telephony response: %{private}s", response.c_str());

        // decode data: data format is [SRES Length][SRES][KC Length][Cipher Key Kc]
        std::vector<uint8_t> nonce;
        if (!DecodeBase64(response, nonce)) {
            WIFI_LOGE("%{public}s: failed to decode sim authentication, size:%{public}zu", __func__, nonce.size());
            return "";
        }

        // [SRES Length]: the length is 4 bytes
        uint8_t sresLen = nonce[0];
        if (sresLen >= nonce.size()) {
            WIFI_LOGE("%{public}s: invalid length, sresLen: %{public}d, size: %{public}zu",
                __func__, sresLen, nonce.size());
            return "";
        }

        // [SRES]
        int offset = 1; // offset [SRES Length]
        char sresBuf[MAX_SRES_STR_LEN + 1] = { 0 };
        Byte2HexString(&nonce[offset], sresLen, sresBuf, sizeof(sresBuf));
        WIFI_LOGD("%{public}s sresLen: %{public}d, sresBuf: %{private}s", __func__, sresLen, sresBuf);

        // [KC Length]: the length is 8 bytes
        size_t kcOffset = 1 + sresLen; // offset [SRES Length][SRES]
        if (kcOffset >= nonce.size()) {
            WIFI_LOGE("%{public}s: invalid kcOffset: %{public}zu", __func__, kcOffset);
            return "";
        }
        uint8_t kcLen = nonce[kcOffset];
        if ((kcLen + kcOffset) >= nonce.size()) {
            WIFI_LOGE("%{public}s: invalid kcLen: %{public}d, kcOffset: %{public}zu", __func__, kcLen, kcOffset);
            return "";
        }

        // [Cipher Key Kc]
        char kcBuf[MAX_KC_STR_LEN + 1] = {0};
        Byte2HexString(&nonce[kcOffset + 1], kcLen, kcBuf, sizeof(kcBuf));
        WIFI_LOGD("%{public}s kcLen:%{public}d, kcBuf:%{private}s", __func__, kcLen, kcBuf);

        // strcat request message
        if (i == 0) {
            authRsp += std::string(kcBuf) + ":" + std::string(sresBuf);
        } else {
            authRsp += ":" + std::string(kcBuf) + ":" + std::string(sresBuf);
        }
        i++;
    }
    WIFI_LOGD("%{public}s authRsp: %{private}s, len: %{public}zu", __func__, authRsp.c_str(), authRsp.length());
    return authRsp;
}

/* Calculate SRES and KC as 2G authentication.
 * Protocol: 3GPP TS 11.11  2G_authentication
 * Request messge: [RAND1][RAND2]...[RANDn]
 * Response messge: [SRES][Cipher Key Kc]
*/
std::string StaStateMachine::GetGsmAuthResponseWithoutLength(EapSimGsmAuthParam param)
{
    int i = 0;
    std::string authRsp;
    uint8_t randArray[GSM_AUTH_RAND_LEN];

    WIFI_LOGI("%{public}s size: %{public}zu", __func__, param.rands.size());
    for (auto iter = param.rands.begin(); iter != param.rands.end(); ++iter) {
        // data pre-processing
        if (memset_s(randArray, sizeof(randArray), 0x0, sizeof(randArray)) != EOK) {
            WIFI_LOGE("%{public}s: memset_s is failed", __func__);
            return "";
        }
        char tmpRand[MAX_RAND_STR_LEN + 1] = { 0 };
        if (strncpy_s(tmpRand, sizeof(tmpRand), (*iter).c_str(), (*iter).length()) != EOK) {
            WIFI_LOGE("%{public}s: failed to copy", __func__);
            return "";
        }

        // converting a hexadecimal character string to an array
        int ret = HexString2Byte(tmpRand, randArray, sizeof(randArray));
        if (ret != 0) {
            WIFI_LOGE("%{public}s: fail to data conversion", __func__);
            return "";
        }

        std::vector<uint8_t> randVec;
        for (size_t j = 0; j < sizeof(randArray); j++) {
            randVec.push_back(randArray[j]);
        }

        // encode data and initiate a challenge request
        std::string base64Challenge = EncodeBase64(randVec);
        WifiDeviceConfig deviceConfig;
        WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId_, deviceConfig, m_instId);
        std::string response = WifiTelephonyUtils::SimAkaAuth(
            base64Challenge, WifiTelephonyUtils::AuthType::SIM_TYPE, deviceConfig.wifiEapConfig.eapSubId);
        if (response.empty()) {
            WIFI_LOGE("%{public}s: fail to authenticate", __func__);
            return "";
        }
        WIFI_LOGD("telephony response: %{private}s", response.c_str());

        // data format: [SRES][Cipher Key Kc]
        std::vector<uint8_t> nonce;
        if (!DecodeBase64(response, nonce)) {
            WIFI_LOGE("%{public}s: failed to decode sim authentication, size:%{public}zu", __func__, nonce.size());
            return "";
        }

        if (GSM_AUTH_CHALLENGE_SRES_LEN + GSM_AUTH_CHALLENGE_KC_LEN != nonce.size()) {
            WIFI_LOGE("%{public}s: invalid length, size: %{public}zu", __func__, nonce.size());
            return "";
        }

        // [SRES]
        std::string sres;
        char sresBuf[MAX_SRES_STR_LEN + 1] = {0};
        Byte2HexString(&nonce[0], GSM_AUTH_CHALLENGE_SRES_LEN, sresBuf, sizeof(sresBuf));

        // [Cipher Key Kc]
        size_t kcOffset = GSM_AUTH_CHALLENGE_SRES_LEN;
        if (kcOffset >= nonce.size()) {
            WIFI_LOGE("%{public}s: invalid length, kcOffset: %{public}zu", __func__, kcOffset);
            return "";
        }

        std::string kc;
        char kcBuf[MAX_KC_STR_LEN + 1] = {0};
        Byte2HexString(&nonce[kcOffset], GSM_AUTH_CHALLENGE_KC_LEN, kcBuf, sizeof(kcBuf));

        // strcat request message
        if (i == 0) {
            authRsp += std::string(kcBuf) + ":" + std::string(sresBuf);
        } else {
            authRsp += ":" + std::string(kcBuf) + ":" + std::string(sresBuf);
        }
        i++;
    }
    WIFI_LOGI("%{public}s authReq: %{private}s, len: %{public}zu", __func__, authRsp.c_str(), authRsp.length());
    return authRsp;
}

bool StaStateMachine::PreWpaEapUmtsAuthEvent()
{
    WifiDeviceConfig deviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId_, deviceConfig, m_instId);
    return WifiTelephonyUtils::IsSupportCardType(deviceConfig.wifiEapConfig.eapSubId);
}

std::vector<uint8_t> StaStateMachine::FillUmtsAuthReq(EapSimUmtsAuthParam &param)
{
    // request data format: [RAND LENGTH][RAND][AUTN LENGTH][AUTN]
    std::vector<uint8_t> inputChallenge;

    // rand hexadecimal string convert to binary
    char rand[MAX_RAND_STR_LEN + 1] = { 0 };
    if (strncpy_s(rand, sizeof(rand), param.rand.c_str(), param.rand.length()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy rand", __func__);
        return inputChallenge;
    }
    uint8_t randArray[UMTS_AUTH_CHALLENGE_RAND_LEN];
    int32_t ret = HexString2Byte(rand, randArray, sizeof(randArray));
    if (ret != 0) {
        WIFI_LOGE("%{public}s: failed to convert to rand", __func__);
        return inputChallenge;
    }

    // [RAND LENGTH]: rand length
    inputChallenge.push_back(sizeof(randArray));

    // [RAND]: rand data
    for (size_t i = 0; i < sizeof(randArray); i++) {
        inputChallenge.push_back(randArray[i]);
    }

    // autn hexadecimal string convert to binary
    char autn[MAX_AUTN_STR_LEN + 1] = { 0 };
    if (strncpy_s(autn, sizeof(autn), param.autn.c_str(), param.autn.length()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy autn", __func__);
        return inputChallenge;
    }
    uint8_t autnArray[UMTS_AUTH_CHALLENGE_RAND_LEN];
    ret = HexString2Byte(autn, autnArray, sizeof(autnArray));
    if (ret != 0) {
        WIFI_LOGE("%{public}s: failed to convert to autn", __func__);
        return inputChallenge;
    }

    // [AUTN LENGTH]: autn length
    inputChallenge.push_back(sizeof(autnArray));

    // [AUTN]: autn data
    for (size_t i = 0; i < sizeof(autnArray); i++) {
        inputChallenge.push_back(autnArray[i]);
    }
    return inputChallenge;
}

std::string StaStateMachine::ParseAndFillUmtsAuthParam(std::vector<uint8_t> &nonce)
{
    std::string authReq;
    uint8_t tag = nonce[UMTS_AUTH_CHALLENGE_RESULT_INDEX]; // nonce[0]: the 1st byte is authentication type
    if (tag == UMTS_AUTH_TYPE_TAG) {
        char nonceBuf[UMTS_AUTH_RESPONSE_CONENT_LEN * 2 + 1] = { 0 }; // length of auth data
        Byte2HexString(&nonce[0], UMTS_AUTH_RESPONSE_CONENT_LEN, nonceBuf, sizeof(nonceBuf));
        WIFI_LOGD("Raw Response: %{private}s", nonceBuf);

        authReq = "UMTS-AUTH:";

        // res
        uint8_t resLen = nonce[UMTS_AUTH_CHALLENGE_DATA_START_IDNEX]; // nonce[1]: the 2nd byte is the length of res
        int resOffset = UMTS_AUTH_CHALLENGE_DATA_START_IDNEX + 1;
        std::string res;
        char resBuf[MAX_RES_STR_LEN + 1] = { 0 };
        /* nonce[2]~nonce[9]: the 3rd byte ~ 10th byte is res data */
        Byte2HexString(&nonce[resOffset], resLen, resBuf, sizeof(resBuf));
        WIFI_LOGD("%{public}s resLen: %{public}d, resBuf: %{private}s", __func__, resLen, resBuf);

        // ck
        int ckOffset = resOffset + resLen;
        uint8_t ckLen = nonce[ckOffset]; // nonce[10]: the 11th byte is ck length
        std::string ck;
        char ckBuf[MAX_CK_STR_LEN + 1] = { 0 };

        /* nonce[11]~nonce[26]: the 12th byte ~ 27th byte is ck data */
        Byte2HexString(&nonce[ckOffset + 1], ckLen, ckBuf, sizeof(ckBuf));
        WIFI_LOGD("ckLen: %{public}d, ckBuf:%{private}s", ckLen, ckBuf);

        // ik
        int ikOffset = ckOffset + ckLen + 1;
        uint8_t ikLen = nonce[ikOffset]; // nonce[27]: the 28th byte is the length of ik
        std::string ik;
        char ikBuf[MAX_IK_STR_LEN + 1] = { 0 };
        /* nonce[28]~nonce[43]: the 29th byte ~ 44th byte is ck data */
        Byte2HexString(&nonce[ikOffset + 1], ikLen, ikBuf, sizeof(ikBuf));
        WIFI_LOGD("ikLen: %{public}d, ikBuf:%{private}s", ikLen, ikBuf);

        std::string authRsp = std::string(ikBuf) + ":" + std::string(ckBuf) + ":" + std::string(resBuf);
        authReq += authRsp;
        WIFI_LOGD("%{public}s ik: %{private}s, ck: %{private}s, res: %{private}s, authRsp: %{private}s",
            __func__, ikBuf, ckBuf, resBuf, authRsp.c_str());
    } else {
        authReq = "UMTS-AUTS:";

        // auts
        uint8_t autsLen = nonce[UMTS_AUTH_CHALLENGE_DATA_START_IDNEX];
        WIFI_LOGD("autsLen: %{public}d", autsLen);
        int offset = UMTS_AUTH_CHALLENGE_DATA_START_IDNEX + 1;
        std::string auts;
        char autsBuf[MAX_AUTN_STR_LEN + 1] = { 0 };
        Byte2HexString(&nonce[offset], autsLen, autsBuf, sizeof(autsBuf));
        WIFI_LOGD("%{public}s auts: %{private}s", __func__, auts.c_str());

        std::string authRsp = auts;
        authReq += authRsp;
        WIFI_LOGD("%{public}s authRsp: %{private}s", __func__, authRsp.c_str());
    }
    return authReq;
}

std::string StaStateMachine::GetUmtsAuthResponse(EapSimUmtsAuthParam &param)
{
    // request data format: [RAND LENGTH][RAND][AUTN LENGTH][AUTN]
    std::vector<uint8_t> inputChallenge = FillUmtsAuthReq(param);
    if (inputChallenge.size() != UMTS_AUTH_REQUEST_CONTENT_LEN) {
        return "";
    }
    std::string challenge = EncodeBase64(inputChallenge);
    WifiDeviceConfig deviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId_, deviceConfig, m_instId);
    return WifiTelephonyUtils::SimAkaAuth(
        challenge, WifiTelephonyUtils::AuthType::AKA_TYPE, deviceConfig.wifiEapConfig.eapSubId);
}

void StaStateMachine::DealWpaEapSimAuthEvent(InternalMessagePtr msg)
{
    if (msg == NULL) {
        WIFI_LOGE("%{public}s: msg is null", __func__);
        return;
    }

    EapSimGsmAuthParam param;
    msg->GetMessageObj(param);
    WIFI_LOGI("%{public}s size: %{public}zu", __func__, param.rands.size());

    std::string cmd = "GSM-AUTH:";
    if (param.rands.size() <= 0) {
        WIFI_LOGE("%{public}s: invalid rands", __func__);
        return;
    }

    std::string authRsp = GetGsmAuthResponseWithLength(param);
    if (authRsp.empty()) {
        authRsp = GetGsmAuthResponseWithoutLength(param);
        if (authRsp.empty()) {
            WIFI_LOGE("failed to sim authentication");
            return;
        }
    }

    cmd += authRsp;
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("%{public}s: failed to send the message, authReq: %{private}s", __func__, cmd.c_str());
        return;
    }
    WIFI_LOGD("%{public}s: success to send the message, authReq: %{private}s", __func__, cmd.c_str());
}

void StaStateMachine::DealWpaEapUmtsAuthEvent(InternalMessagePtr msg)
{
    if (msg == NULL) {
        WIFI_LOGE("%{public}s: msg is null", __func__);
        return;
    }

    EapSimUmtsAuthParam param;
    msg->GetMessageObj(param);
    if (param.rand.empty() || param.autn.empty()) {
        WIFI_LOGE("invalid rand = %{public}zu or autn = %{public}zu", param.rand.length(), param.autn.length());
        return;
    }

    WIFI_LOGD("%{public}s rand: %{private}s, autn: %{private}s", __func__, param.rand.c_str(), param.autn.c_str());

    if (!PreWpaEapUmtsAuthEvent()) {
        return;
    }

    // get challenge information
    std::string response = GetUmtsAuthResponse(param);
    if (response.empty()) {
        WIFI_LOGE("response is empty");
        return;
    }

    // parse authentication information
    std::vector<uint8_t> nonce;
    if (!DecodeBase64(response, nonce)) {
        WIFI_LOGE("%{public}s: failed to decode aka authentication, size:%{public}zu", __func__, nonce.size());
        return;
    }

    // data format: [0xdb][RES Length][RES][CK Length][CK][IK Length][IK]
    uint8_t tag = nonce[UMTS_AUTH_CHALLENGE_RESULT_INDEX];
    if ((tag != UMTS_AUTH_TYPE_TAG) && (tag != UMTS_AUTS_TYPE_TAG)) {
        WIFI_LOGE("%{public}s: unsupport type: 0x%{public}02x", __func__, tag);
        return;
    }

    WIFI_LOGI("tag: 0x%{public}02x", tag);

    // request authentication to wpa
    std::string reqCmd = ParseAndFillUmtsAuthParam(nonce);
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", reqCmd) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("%{public}s: failed to send the message, authReq: %{private}s", __func__, reqCmd.c_str());
        return;
    }
    WIFI_LOGD("%{public}s: success to send the message, authReq: %{private}s", __func__, reqCmd.c_str());
}
#endif

/* ------------------ state machine call back ----------------- */
void StaStateMachine::RegisterStaServiceCallback(const StaServiceCallback &callback)
{
    WIFI_LOGI("RegisterStaServiceCallback, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::shared_mutex> lock(m_staCallbackMutex);
    m_staCallback.insert_or_assign(callback.callbackModuleName, callback);
}

void StaStateMachine::UnRegisterStaServiceCallback(const StaServiceCallback &callback)
{
    WIFI_LOGI("UnRegisterStaServiceCallback, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::shared_mutex> lock(m_staCallbackMutex);
    m_staCallback.erase(callback.callbackModuleName);
}

void StaStateMachine::InvokeOnStaConnChanged(OperateResState state, const WifiLinkedInfo &info)
{
#ifndef OHOS_ARCH_LITE
    if (selfCureService_ != nullptr) {
        if ((state == OperateResState::DISCONNECT_DISCONNECTED) || (state == OperateResState::CONNECT_AP_CONNECTED)
            || (state == OperateResState::CONNECT_CONNECTION_REJECT)) {
            selfCureService_->CheckSelfCureWifiResult(SCE_EVENT_NET_INFO_CHANGED);
        }
        if (selfCureService_->IsSelfCureL2Connecting() && info.detailedState != DetailedState::CONNECTED) {
            WIFI_LOGI("selfcure ignore network state changed");
            return;
        }
    }
#endif
    {
        std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
        for (const auto &callBackItem : m_staCallback) {
            if (callBackItem.second.OnStaConnChanged != nullptr) {
                callBackItem.second.OnStaConnChanged(state, info, m_instId);
            }
        }
    }
    switch (state) {
        case OperateResState::CONNECT_AP_CONNECTED:
            WriteWifiConnectionHiSysEvent(static_cast<int>(WifiConnectionType::CONNECT), "");
            if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
                WifiNetStatsManager::GetInstance().StartNetStats();
#endif
            }
            break;
        case OperateResState::DISCONNECT_DISCONNECTED:
            WriteWifiConnectionHiSysEvent(static_cast<int>(WifiConnectionType::DISCONNECT), "");
            if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
                WifiNetStatsManager::GetInstance().StopNetStats();
#endif
            }
            break;
        default:
            break;
    }
}

void StaStateMachine::InvokeOnStaStreamChanged(StreamDirection direction)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnStaStreamChanged != nullptr) {
            callBackItem.second.OnStaStreamChanged(direction, m_instId);
        }
    }
}

void StaStateMachine::InvokeOnStaRssiLevelChanged(int level)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
#ifndef OHOS_ARCH_LITE
    if (selfCureService_ != nullptr) {
        if (selfCureService_->IsSelfCureL2Connecting()) {
            WIFI_LOGI("selfcure ignore rssi changed");
            return;
        }
    }
#endif
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnStaRssiLevelChanged != nullptr) {
            callBackItem.second.OnStaRssiLevelChanged(level, m_instId);
        }
    }
}

void StaStateMachine::InvokeOnDhcpOfferReport(IpInfo ipInfo)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnDhcpOfferReport != nullptr) {
            callBackItem.second.OnDhcpOfferReport(ipInfo, m_instId);
        }
    }
}

void StaStateMachine::InvokeOnInternetAccessChanged(SystemNetWorkState internetAccessStatus)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnInternetAccessChange != nullptr) {
            callBackItem.second.OnInternetAccessChange(static_cast<int32_t>(internetAccessStatus), m_instId);
        }
    }
}

void StaStateMachine::HandleInternetAccessChanged(SystemNetWorkState internetAccessStatus)
{
    WIFI_LOGI("HandleInternetAccessChanged internetAccessStatus: %{public}d, lastInternetAccessStatus: %{public}d,"
        "noInternetAccessCnt_: %{public}d", internetAccessStatus, lastInternetIconStatus_, noInternetAccessCnt_);
    if (internetAccessStatus == SystemNetWorkState::NETWORK_IS_WORKING) {
        noInternetAccessCnt_ = 0;
        StopTimer(CMD_NO_INTERNET_TIMEOUT);
    }

    if (internetAccessStatus == SystemNetWorkState::NETWORK_NOTWORKING &&
        lastInternetIconStatus_ == SystemNetWorkState::NETWORK_IS_WORKING) {
        noInternetAccessCnt_++;
        if (noInternetAccessCnt_ < MAX_NO_INTERNET_CNT) {
            StopTimer(CMD_NO_INTERNET_TIMEOUT);
            StartTimer(CMD_NO_INTERNET_TIMEOUT, STA_NO_INTERNET_TIMEOUT);
            return;
        } else if (noInternetAccessCnt_ == MAX_NO_INTERNET_CNT) {
            StopTimer(CMD_NO_INTERNET_TIMEOUT);
        }
        if (lastSignalLevel_ <= RSSI_LEVEL_3) {
            WIFI_LOGW("HandleInternetAccessChanged, signal level less 3");
            return;
        }
#ifdef FEATURE_SELF_CURE_SUPPORT
        if ((selfCureService_ != nullptr && !selfCureService_->IsWifiSelfcureDone())) {
            WIFI_LOGW("HandleInternetAccessChanged, selfcure is not finish");
            return;
        }
#endif
    }

    if (lastInternetIconStatus_ == internetAccessStatus) {
        return;
    }
    lastInternetIconStatus_ = internetAccessStatus;
    InvokeOnInternetAccessChanged(internetAccessStatus);
}

void StaStateMachine::UpdateHiLinkAttribute()
{
    std::vector<WifiScanInfo> wifiScanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(wifiScanInfoList);
    for (auto iter = wifiScanInfoList.begin(); iter != wifiScanInfoList.end(); ++iter) {
        if (iter->bssid == linkedInfo.bssid) {
            linkedInfo.isHiLinkNetwork = iter->isHiLinkNetwork;
            linkedInfo.isHiLinkProNetwork = iter->isHiLinkProNetwork;
            WIFI_LOGI("set hilink=%{public}d, bssid=%{public}s", iter->isHiLinkNetwork,
                MacAnonymize(linkedInfo.bssid).c_str());
            break;
        }
    }
}
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
void StaStateMachine::UpdateRiskTypeAttribute()
{
    std::vector<WifiScanInfo> wifiScanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(wifiScanInfoList);
    for (auto iter = wifiScanInfoList.begin(); iter != wifiScanInfoList.end(); ++iter) {
        if (iter->bssid == linkedInfo.bssid) {
            linkedInfo.riskType = iter->riskType;
            break;
        }
    }
}
#endif
void StaStateMachine::LogSignalInfo(WifiSignalPollInfo &signalInfo)
{
    WIFI_LOGI("SignalPoll,bssid:%{public}s,ssid:%{public}s,networkId:%{public}d,band:%{public}d,freq:%{public}d,"
        "rssi:%{public}d,noise:%{public}d,chload:%{public}d,snr:%{public}d,ulDelay:%{public}d,txLinkSpeed:%{public}d,"
        "rxLinkSpeed:%{public}d,txBytes:%{public}u,rxBytes:%{public}u,txFailed:%{public}d,txPackets:%{public}d,"
        "rxPackets:%{public}d,wifiCategory:%{public}d, wifiLinkType:%{public}d,GetWifiStandard:%{public}d,"
        "rxmax:%{public}d,txmax:%{public}d,connState:%{public}d,detState:%{public}d,lastSignal:%{public}d,"
        "chloadSelf:%{public}d,c0Rssi:%{public}d,c1Rssi:%{public}d", MacAnonymize(linkedInfo.bssid).c_str(),
        SsidAnonymize(linkedInfo.ssid).c_str(), linkedInfo.networkId, linkedInfo.band, signalInfo.frequency,
        signalInfo.signal, signalInfo.noise, signalInfo.chload, signalInfo.snr, signalInfo.ulDelay, signalInfo.txrate,
        signalInfo.rxrate, signalInfo.txBytes, signalInfo.rxBytes, signalInfo.txFailed, signalInfo.txPackets,
        signalInfo.rxPackets, static_cast<int>(linkedInfo.supportedWifiCategory),
        static_cast<int>(linkedInfo.wifiLinkType), linkedInfo.wifiStandard, linkedInfo.maxSupportedRxLinkSpeed,
        linkedInfo.maxSupportedTxLinkSpeed, linkedInfo.connState, linkedInfo.detailedState, lastSignalLevel_,
        signalInfo.chloadSelf, signalInfo.c0Rssi, signalInfo.c1Rssi);
}

int32_t StaStateMachine::GetTargetNetworkId()
{
    return targetNetworkId_;
}

bool StaStateMachine::HasMultiBssidAp(const WifiDeviceConfig &config)
{
    std::vector<WifiScanInfo> wifiScanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(wifiScanInfoList);
    int32_t bssidCount = 0;
    for (auto iter = wifiScanInfoList.begin(); iter != wifiScanInfoList.end(); ++iter) {
        std::string deviceKeyMgmt;
        iter->GetDeviceMgmt(deviceKeyMgmt);
        if (iter->ssid == config.ssid && WifiSettings::GetInstance().InKeyMgmtBitset(config, deviceKeyMgmt)) {
            bssidCount++;
        }
        if (bssidCount > 1) {
            return true;
        }
    }
    return false;
}

void StaStateMachine::NotifyWifiDisconnectReason(const int reason, const int subReason)
{
    if (enhanceService_ != nullptr) {
        enhanceService_->NotifyWifiDisconnectReason(reason, subReason);
    }
}
} // namespace Wifi
} // namespace OHOS
