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
#include "log_helper.h"
#include "mac_address.h"
#include "sta_monitor.h"
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_protect_manager.h"
#include "wifi_settings.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_hisysevent.h"
#include "wifi_config_center.h"
#include "wifi_hisysevent.h"
#ifndef OHOS_ARCH_LITE
#include <dlfcn.h>
#include "ability_manager_ipc_interface_code.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "wifi_app_state_aware.h"
#include "wifi_net_observer.h"
#include "wifi_system_timer.h"
#include "wifi_notification_util.h"
#endif // OHOS_ARCH_LITE

#ifndef OHOS_WIFI_STA_TEST
#else
#include "mock_dhcp_service.h"
#endif
namespace OHOS {
namespace Wifi {
namespace {
constexpr int DEFAULT_INVAL_VALUE = -1;
const std::u16string ABILITY_MGR_DESCRIPTOR = u"ohos.aafwk.AbilityManager";
constexpr const char* WIFI_IS_CONNECT_FROM_USER = "persist.wifi.is_connect_from_user";
}
DEFINE_WIFILOG_LABEL("StaStateMachine");
#define PBC_ANY_BSSID "any"
#define FIRST_DNS "8.8.8.8"
#define SECOND_DNS "180.76.76.76"
#define PORTAL_ACTION "ohos.want.action.viewData"
#define PORTAL_ENTITY "entity.browser.hbct"
#define BROWSER_BUNDLE "com.huawei.hmos.browser"
#define SETTINGS_BUNDLE "com.huawei.hmos.settings"
#define PORTAL_CHECK_TIME (10 * 60)
#define PORTAL_MILLSECOND  1000
#define WPA3_BLACKMAP_MAX_NUM 20
#define WPA3_BLACKMAP_RSSI_THRESHOLD (-70)
#define WPA3_CONNECT_FAIL_COUNT_THRESHOLD 2
#define WPA_CB_ASSOCIATING 3
#define WPA_CB_CONNECTED 1
#define WPA_CB_ASSOCIATED 4
#define TRANSFORMATION_TO_MBPS 10
#define DEFAULT_NUM_ARP_PINGS 3
#define MAX_ARP_CHECK_TIME 300
#define NETWORK 1
#define NO_NETWORK 0
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

static bool g_isHilinkFlag = false;

StaStateMachine::StaStateMachine(int instId)
    : StateMachine("StaStateMachine"),
      lastNetworkId(INVALID_NETWORK_ID),
      operationalMode(STA_CONNECT_MODE),
      targetNetworkId(INVALID_NETWORK_ID),
      pinCode(0),
      wpsState(SetupMethod::INVALID),
      lastSignalLevel(-1),
      targetRoamBssid(WPA_BSSID_ANY),
      currentTpType(IPTYPE_IPV4),
      isWpsConnect(IsWpsConnected::WPS_INVALID),
      getIpSucNum(0),
      getIpFailNum(0),
      enableSignalPoll(true),
      isRoam(false),
      lastTimestamp(0),
      portalFlag(true),
      networkStatusHistoryInserted(false),
      pDhcpResultNotify(nullptr),
      pRootState(nullptr),
      pInitState(nullptr),
      pWpaStartingState(nullptr),
      pWpaStartedState(nullptr),
      pWpaStoppingState(nullptr),
      pLinkState(nullptr),
      pSeparatingState(nullptr),
      pSeparatedState(nullptr),
      pApLinkedState(nullptr),
      pWpsState(nullptr),
      pGetIpState(nullptr),
      pLinkedState(nullptr),
      pApRoamingState(nullptr),
      m_instId(instId),
      mLastConnectNetId(INVALID_NETWORK_ID),
      mConnectFailedCnt(0)
{
}

StaStateMachine::~StaStateMachine()
{
    WIFI_LOGI("~StaStateMachine");
    StopHandlerThread();
    ParsePointer(pRootState);
    ParsePointer(pInitState);
    ParsePointer(pWpaStartingState);
    ParsePointer(pWpaStartedState);
    ParsePointer(pWpaStoppingState);
    ParsePointer(pLinkState);
    ParsePointer(pSeparatingState);
    ParsePointer(pSeparatedState);
    ParsePointer(pApLinkedState);
    ParsePointer(pWpsState);
    ParsePointer(pGetIpState);
    ParsePointer(pLinkedState);
    ParsePointer(pApRoamingState);
    ParsePointer(pDhcpResultNotify);
    {
        std::unique_lock<std::shared_mutex> lock(m_staCallbackMutex);
        m_staCallback.clear();
    }
}

/* ---------------------------Initialization functions------------------------------ */
ErrCode StaStateMachine::InitStaStateMachine()
{
    WIFI_LOGI("Enter InitStaStateMachine.\n");
    if (!InitialStateMachine("StaStateMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (InitStaStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pInitState);
    StartStateMachine();
    InitStaSMHandleMap();
    WifiSettings::GetInstance().GetPortalUri(mUrlInfo);
#ifndef OHOS_ARCH_LITE
    NetSupplierInfo = std::make_unique<NetManagerStandard::NetSupplierInfo>().release();
    m_NetWorkState = sptr<NetStateObserver>(new NetStateObserver());
    m_NetWorkState->SetNetStateCallback(
        std::bind(&StaStateMachine::NetStateObserverCallback, this, std::placeholders::_1, std::placeholders::_2));
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode StaStateMachine::InitStaStates()
{
    WIFI_LOGE("Enter InitStaStates\n");
    int tmpErrNumber;
    pRootState = new (std::nothrow)RootState();
    tmpErrNumber = JudgmentEmpty(pRootState);
    pInitState = new (std::nothrow)InitState(this);
    tmpErrNumber += JudgmentEmpty(pInitState);
    pWpaStartingState = new (std::nothrow)WpaStartingState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStartingState);
    pWpaStartedState = new (std::nothrow)WpaStartedState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStartedState);
    pWpaStoppingState = new (std::nothrow)WpaStoppingState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStoppingState);
    pLinkState = new (std::nothrow)LinkState(this);
    tmpErrNumber += JudgmentEmpty(pLinkState);
    pSeparatingState = new (std::nothrow)SeparatingState();
    tmpErrNumber += JudgmentEmpty(pSeparatingState);
    pSeparatedState = new (std::nothrow)SeparatedState(this);
    tmpErrNumber += JudgmentEmpty(pSeparatedState);
    pApLinkedState = new (std::nothrow)ApLinkedState(this);
    tmpErrNumber += JudgmentEmpty(pApLinkedState);
    pWpsState = new (std::nothrow)StaWpsState(this);
    tmpErrNumber += JudgmentEmpty(pWpsState);
    pGetIpState = new (std::nothrow)GetIpState(this);
    tmpErrNumber += JudgmentEmpty(pGetIpState);
    pLinkedState = new (std::nothrow)LinkedState(this);
    tmpErrNumber += JudgmentEmpty(pLinkedState);
    pApRoamingState = new (std::nothrow)ApRoamingState(this);
    tmpErrNumber += JudgmentEmpty(pApRoamingState);
    pDhcpResultNotify = new (std::nothrow)DhcpResultNotify();
    tmpErrNumber += JudgmentEmpty(pDhcpResultNotify);
    if (tmpErrNumber != 0) {
        WIFI_LOGE("InitStaStates some one state is null\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
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
    linkedInfo.detailedState = DetailedState::DISCONNECTED;
    linkedInfo.channelWidth = WifiChannelWidth::WIDTH_INVALID;
    linkedInfo.lastPacketDirection = 0;
    linkedInfo.lastRxPackets = 0;
    linkedInfo.lastTxPackets = 0;
    linkedInfo.retryedConnCount = 0;
    linkedInfo.isAncoConnected = 0;
}

void StaStateMachine::InitLastWifiLinkedInfo()
{
    lastLinkedInfo.networkId = INVALID_NETWORK_ID;
    lastLinkedInfo.ssid = "";
    lastLinkedInfo.bssid = "";
    lastLinkedInfo.macAddress = "";
    linkedInfo.macType = 0;
    lastLinkedInfo.rxLinkSpeed = 0;
    lastLinkedInfo.txLinkSpeed = 0;
    lastLinkedInfo.rssi = 0;
    lastLinkedInfo.band = 0;
    lastLinkedInfo.frequency = 0;
    lastLinkedInfo.linkSpeed = 0;
    lastLinkedInfo.ipAddress = 0;
    lastLinkedInfo.connState = ConnState::DISCONNECTED;
    lastLinkedInfo.ifHiddenSSID = false;
    lastLinkedInfo.chload = 0;
    lastLinkedInfo.snr = 0;
    linkedInfo.isDataRestricted = 0;
    linkedInfo.platformType = "";
    linkedInfo.portalUrl = "";
    lastLinkedInfo.lastPacketDirection = 0;
    lastLinkedInfo.lastRxPackets = 0;
    lastLinkedInfo.lastTxPackets = 0;
    lastLinkedInfo.detailedState = DetailedState::DISCONNECTED;
    linkedInfo.retryedConnCount = 0;
}

void StaStateMachine::BuildStateTree()
{
    StatePlus(pRootState, nullptr);
    StatePlus(pInitState, pRootState);
    StatePlus(pWpaStartingState, pRootState);
    StatePlus(pWpaStartedState, pRootState);
    StatePlus(pLinkState, pWpaStartedState);
    StatePlus(pSeparatingState, pLinkState);
    StatePlus(pSeparatedState, pLinkState);
    StatePlus(pApLinkedState, pLinkState);
    StatePlus(pGetIpState, pApLinkedState);
    StatePlus(pLinkedState, pApLinkedState);
    StatePlus(pApRoamingState, pApLinkedState);
    StatePlus(pWpsState, pLinkState);
    StatePlus(pWpaStoppingState, pRootState);
}

void StaStateMachine::RegisterStaServiceCallback(const StaServiceCallback &callback)
{
    WIFI_LOGI("RegisterStaServiceCallback, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::shared_mutex> lock(m_staCallbackMutex);
    m_staCallback.insert_or_assign(callback.callbackModuleName, callback);
}

void StaStateMachine::InvokeOnStaOpenRes(OperateResState state)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnStaOpenRes != nullptr) {
            callBackItem.second.OnStaOpenRes(state, m_instId);
        }
    }
}

void StaStateMachine::InvokeOnStaCloseRes(OperateResState state)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnStaCloseRes != nullptr) {
            callBackItem.second.OnStaCloseRes(state, m_instId);
        }
    }
}

void StaStateMachine::InvokeOnStaConnChanged(OperateResState state, const WifiLinkedInfo &info)
{
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
            WriteWifiConnectionHiSysEvent(WifiConnectionType::CONNECT, "");
            break;
        case OperateResState::DISCONNECT_DISCONNECTED:
            WriteWifiConnectionHiSysEvent(WifiConnectionType::DISCONNECT, "");
            break;
        default:
            break;
    }
}

void StaStateMachine::InvokeOnWpsChanged(WpsStartState state, const int code)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnWpsChanged != nullptr) {
            callBackItem.second.OnWpsChanged(state, code, m_instId);
        }
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
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnStaRssiLevelChanged != nullptr) {
            callBackItem.second.OnStaRssiLevelChanged(level, m_instId);
        }
    }
}

/* --------------------------- state machine root state ------------------------------ */
StaStateMachine::RootState::RootState() : State("RootState")
{}

StaStateMachine::RootState::~RootState()
{}

void StaStateMachine::RootState::GoInState()
{
    WIFI_LOGI("RootState GoInState function.");
    return;
}

void StaStateMachine::RootState::GoOutState()
{
    WIFI_LOGI("RootState GoOutState function.");
    return;
}

bool StaStateMachine::RootState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("RootState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_UPDATE_COUNTRY_CODE: {
#ifndef OHOS_ARCH_LITE
            ret = EXECUTED;
            std::string wifiCountryCode = msg->GetStringFromMessage();
            if (wifiCountryCode.empty()) {
                break;
            }
            WifiErrorNo result = WifiSupplicantHalInterface::GetInstance().WpaSetCountryCode(wifiCountryCode);
            if (result == WifiErrorNo::WIFI_IDL_OPT_OK) {
                WIFI_LOGI("update wifi country code sucess, wifiCountryCode=%{public}s", wifiCountryCode.c_str());
                break;
            }
            WIFI_LOGE("update wifi country code fail, wifiCountryCode=%{public}s, ret=%{public}d",
                wifiCountryCode.c_str(), result);
#endif
            break;
        }
        default:
            WIFI_LOGI("RootState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
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
    return;
}

void StaStateMachine::InitState::GoOutState()
{
    WIFI_LOGI("InitState GoOutState function.");
    return;
}

bool StaStateMachine::InitState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("InitState-msgCode=%{public}d is received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_ENABLE_WIFI: {
            ret = EXECUTED;
            pStaStateMachine->operationalMode = msg->GetParam1();
            pStaStateMachine->StartWifiProcess();
            break;
        }

        case WIFI_SVR_CMD_STA_OPERATIONAL_MODE:
            break;

        default:
            WIFI_LOGI("InitState-msgCode=%d not handled.\n", msg->GetMessageName());
            break;
    }
    return ret;
}

ErrCode StaStateMachine::FillEapCfg(const WifiDeviceConfig &config, WifiIdlDeviceConfig &idlConfig) const
{
    idlConfig.eapConfig.eap = config.wifiEapConfig.eap;
    idlConfig.eapConfig.phase2Method = static_cast<int>(config.wifiEapConfig.phase2Method);
    idlConfig.eapConfig.identity = config.wifiEapConfig.identity;
    idlConfig.eapConfig.anonymousIdentity = config.wifiEapConfig.anonymousIdentity;
    if (memcpy_s(idlConfig.eapConfig.password, sizeof(idlConfig.eapConfig.password),
        config.wifiEapConfig.password.c_str(), config.wifiEapConfig.password.length()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy the content", __func__);
        return WIFI_OPT_FAILED;
    }
    idlConfig.eapConfig.caCertPath = config.wifiEapConfig.caCertPath;
    idlConfig.eapConfig.caCertAlias = config.wifiEapConfig.caCertAlias;
    idlConfig.eapConfig.clientCert = config.wifiEapConfig.clientCert;
    if (memcpy_s(idlConfig.eapConfig.certPassword, sizeof(idlConfig.eapConfig.certPassword),
        config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword)) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy the content", __func__);
        return WIFI_OPT_FAILED;
    }
    idlConfig.eapConfig.privateKey = config.wifiEapConfig.privateKey;
    idlConfig.eapConfig.altSubjectMatch = config.wifiEapConfig.altSubjectMatch;
    idlConfig.eapConfig.domainSuffixMatch = config.wifiEapConfig.domainSuffixMatch;
    idlConfig.eapConfig.realm = config.wifiEapConfig.realm;
    idlConfig.eapConfig.plmn = config.wifiEapConfig.plmn;
    idlConfig.eapConfig.eapSubId = config.wifiEapConfig.eapSubId;
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

    if (WifiStaHalInterface::GetInstance().ShellCmd(ifName, cmd) != WIFI_IDL_OPT_OK) {
        WIFI_LOGI("%{public}s: failed to set StaShellCmd, cmd:%{private}s", __func__, cmd);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaStateMachine::ConvertDeviceCfg(const WifiDeviceConfig &config) const
{
    LOGI("Enter ConvertDeviceCfg.\n");
    WifiIdlDeviceConfig idlConfig;
    idlConfig.ssid = config.ssid;
    idlConfig.bssid = config.bssid;
    idlConfig.psk = config.preSharedKey;
    idlConfig.keyMgmt = config.keyMgmt;
    idlConfig.priority = config.priority;
    idlConfig.scanSsid = config.hiddenSSID ? 1 : 0;
    FillEapCfg(config, idlConfig);
    idlConfig.wepKeyIdx = config.wepTxKeyIndex;
    if (strcmp(config.keyMgmt.c_str(), "WEP") == 0) {
        /* for wep */
        idlConfig.authAlgorithms = 0x02;
    }

    if (IsWpa3Transition(config.ssid)) {
        if (IsInWpa3BlackMap(config.ssid)) {
            idlConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        } else {
            idlConfig.keyMgmt = KEY_MGMT_SAE;
        }
        idlConfig.isRequirePmf = false;
    }

    if (config.keyMgmt.find("SAE") != std::string::npos) {
        idlConfig.isRequirePmf = true;
    }

    if (idlConfig.keyMgmt.find("SAE") != std::string::npos) {
        idlConfig.allowedProtocols = 0x02; // RSN
        idlConfig.allowedPairwiseCiphers = 0x2c; // CCMP|GCMP|GCMP-256
        idlConfig.allowedGroupCiphers = 0x2c; // CCMP|GCMP|GCMP-256
    }

    for (int i = 0; i < MAX_WEPKEYS_SIZE; i++) {
        idlConfig.wepKeys[i] = config.wepKeys[i];
    }
    LOGI("ConvertDeviceCfg SetDeviceConfig selected network ssid=%{public}s, bssid=%{public}s",
        SsidAnonymize(idlConfig.ssid).c_str(), MacAnonymize(idlConfig.bssid).c_str());
    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(WPA_DEFAULT_NETWORKID, idlConfig) != WIFI_IDL_OPT_OK) {
        LOGE("ConvertDeviceCfg SetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }

    if (SetExternalSim("wlan0", idlConfig.eapConfig.eap, WIFI_EAP_OPEN_EXTERNAL_SIM)) {
        LOGE("StaStateMachine::ConvertDeviceCfg: failed to set external_sim");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::StartWifiProcess()
{
    WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING), m_instId);
    InvokeOnStaOpenRes(OperateResState::OPEN_WIFI_OPENING);
    int res = WifiStaHalInterface::GetInstance().StartWifi(WifiSettings::GetInstance().GetStaIfaceName());
    if (res == static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGI("Start wifi successfully!");
        if (WifiStaHalInterface::GetInstance().WpaAutoConnect(false) != WIFI_IDL_OPT_OK) {
            WIFI_LOGI("The automatic Wpa connection is disabled failed.");
        }
        int screenState = WifiSettings::GetInstance().GetScreenState();
        WIFI_LOGI("set suspend mode to chip when wifi started, screenState: %{public}d", screenState);
        if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE)
            != WIFI_IDL_OPT_OK) {
            WIFI_LOGE("%{public}s WpaSetSuspendMode failed!", __FUNCTION__);
        }

        /* callback the InterfaceService that wifi is enabled successfully. */
        WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED), m_instId);
        InvokeOnStaOpenRes(OperateResState::OPEN_WIFI_SUCCEED);
        /* Sets the MAC address of WifiSettings. */
        std::string mac;
        if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(mac)) == WIFI_IDL_OPT_OK) {
            WifiSettings::GetInstance().SetMacAddress(mac, m_instId);
            std::string realMacAddress;
            WifiSettings::GetInstance().GetRealMacAddress(realMacAddress, m_instId);
            if (realMacAddress.empty()) {
                WifiSettings::GetInstance().SetRealMacAddress(mac, m_instId);
            }
        } else {
            WIFI_LOGI("GetStaDeviceMacAddress failed!");
        }
#ifndef OHOS_ARCH_LITE
        WIFI_LOGI("Register netsupplier");
        WifiNetAgent::GetInstance().OnStaMachineWifiStart();
#endif
        /* Initialize Connection Information. */
        InitWifiLinkedInfo();
        InitLastWifiLinkedInfo();
        WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
        WifiSettings::GetInstance().ReloadDeviceConfig();
        /* The current state of StaStateMachine transfers to SeparatedState after
         * enable supplicant.
         */
        SwitchState(pSeparatedState);
    } else {
        /* Notify the InterfaceService that wifi is failed to enable wifi. */
        LOGE("StartWifi failed, and errcode is %d.", res);
        WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), m_instId);
        WifiSettings::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, m_instId);
        InvokeOnStaOpenRes(OperateResState::OPEN_WIFI_FAILED);
    }
}

/* --------------------------- state machine WpaStarting State ------------------------------ */
StaStateMachine::WpaStartingState::WpaStartingState(StaStateMachine *staStateMachine)
    : State("WpaStartingState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::WpaStartingState::~WpaStartingState()
{}

void StaStateMachine::WpaStartingState::InitWpsSettings()
{
    WIFI_LOGI("WpaStartingState InitWpsSettings function.");
    return;
}

void StaStateMachine::WpaStartingState::GoInState()
{
    WIFI_LOGI("WpaStartingState GoInState function.");
    return;
}

void StaStateMachine::WpaStartingState::GoOutState()
{
    LOGI("WpaStartingState GoOutState function.");
    return;
}

bool StaStateMachine::WpaStartingState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_SUP_CONNECTION_EVENT: {
            ret = EXECUTED;
            pStaStateMachine->SwitchState(pStaStateMachine->pWpaStartedState);
            break;
        }
        default:
            break;
    }
    return ret;
}

/* --------------------------- state machine WpaStarted State ------------------------------ */
StaStateMachine::WpaStartedState::WpaStartedState(StaStateMachine *staStateMachine)
    : State("WpaStartedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::WpaStartedState::~WpaStartedState()
{}

void StaStateMachine::WpaStartedState::GoInState()
{
    WIFI_LOGI("WpaStartedState GoInState function.");
    if (pStaStateMachine->operationalMode == STA_CONNECT_MODE) {
        pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
    } else if (pStaStateMachine->operationalMode == STA_DISABLED_MODE) {
        pStaStateMachine->SwitchState(pStaStateMachine->pWpaStoppingState);
    }
    return;
}
void StaStateMachine::WpaStartedState::GoOutState()
{
    WIFI_LOGI("WpaStartedState GoOutState function.");
    return;
}

bool StaStateMachine::WpaStartedState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGI("msg is nullptr");
        return false;
    }

    WIFI_LOGI("WpaStartedState ExecuteStateMsg-msgCode:%{public}d.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DISABLE_WIFI: {
            ret = EXECUTED;
            pStaStateMachine->StopWifiProcess();
            break;
        }

        default:
            break;
    }
    return ret;
}

void StaStateMachine::StopWifiProcess()
{
    WIFI_LOGI("Enter StaStateMachine::StopWifiProcess.\n");
#ifndef OHOS_ARCH_LITE
    WifiNetAgent::GetInstance().UnregisterNetSupplier();
    m_NetWorkState->StopNetStateObserver(m_NetWorkState);
#endif
    WIFI_LOGI("Stop wifi is in process...\n");
    WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), m_instId);
    InvokeOnStaCloseRes(OperateResState::CLOSE_WIFI_CLOSING);
    StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
    WIFI_LOGI("StopTimer CMD_START_RENEWAL_TIMEOUT StopWifiProcess");
#ifndef OHOS_ARCH_LITE
    StaStateMachine::DhcpResultNotify::StopRenewTimeout();
#else
    StopTimer(static_cast<int>(CMD_START_RENEWAL_TIMEOUT));
#endif
    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    if (currentTpType == IPTYPE_IPV4) {
        StopDhcpClient(ifname.c_str(), false);
    } else {
        StopDhcpClient(ifname.c_str(), true);
    }
    isRoam = false;
    WifiSettings::GetInstance().SetMacAddress("", m_instId);

    IpInfo ipInfo;
    WifiSettings::GetInstance().SaveIpInfo(ipInfo, m_instId);
    IpV6Info ipV6Info;
    WifiSettings::GetInstance().SaveIpV6Info(ipV6Info, m_instId);
#ifdef OHOS_ARCH_LITE
    IfConfig::GetInstance().FlushIpAddr(WifiSettings::GetInstance().GetStaIfaceName(), IPTYPE_IPV4);
#endif

    ConnState curConnState = linkedInfo.connState;
    WIFI_LOGI("current connect state is %{public}d\n", curConnState);
    std::string ssid = linkedInfo.ssid;
    /* clear connection information. */
    InitWifiLinkedInfo();
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    if (curConnState == ConnState::CONNECTING || curConnState == ConnState::AUTHENTICATING
        || curConnState == ConnState::OBTAINING_IPADDR ||curConnState == ConnState::CONNECTED) {
        /* Callback result to InterfaceService. */
        linkedInfo.ssid = ssid;
        InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
        linkedInfo.ssid = "";
    }

    if (WifiStaHalInterface::GetInstance().StopWifi() == WIFI_IDL_OPT_OK) {
        /* Callback result to InterfaceService. */
        WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), m_instId);
        InvokeOnStaCloseRes(OperateResState::CLOSE_WIFI_SUCCEED);
        WIFI_LOGI("Stop WifiProcess successfully!");
        /* The current state of StaStateMachine transfers to InitState. */
        SwitchState(pInitState);
    } else {
        WIFI_LOGE("StopWifiProcess failed.");
        WifiSettings::GetInstance().SetWifiState(static_cast<int>(WifiState::UNKNOWN), m_instId);
        InvokeOnStaCloseRes(OperateResState::CLOSE_WIFI_FAILED);
    }

    WifiSettings::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, m_instId);
}

/* --------------------------- state machine WpaStopping State ------------------------------ */
StaStateMachine::WpaStoppingState::WpaStoppingState(StaStateMachine *staStateMachine)
    : State("WpaStoppingState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::WpaStoppingState::~WpaStoppingState()
{}

void StaStateMachine::WpaStoppingState::GoInState()
{
    WIFI_LOGI("WpaStoppingState GoInState function.");
    pStaStateMachine->SwitchState(pStaStateMachine->pInitState);
    return;
}

void StaStateMachine::WpaStoppingState::GoOutState()
{
    WIFI_LOGI("WpaStoppingState GoOutState function.");
    return;
}

bool StaStateMachine::WpaStoppingState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_EXECUTED;
    WIFI_LOGI("WpaStoppingState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return ret;
}

/* --------------------------- state machine link State ------------------------------ */
StaStateMachine::LinkState::LinkState(StaStateMachine *staStateMachine)
    : State("LinkState"), pStaStateMachine(staStateMachine)
{}

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
    return;
}

bool StaStateMachine::LinkState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }
    LOGD("LinkState ExecuteStateMsg function:msgName=[%{public}d].\n", msg->GetMessageName());
    auto iter = pStaStateMachine->staSmHandleFuncMap.find(msg->GetMessageName());
    if (iter != pStaStateMachine->staSmHandleFuncMap.end()) {
        (pStaStateMachine->*(iter->second))(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

/* -- state machine Connect State Message processing function -- */
int StaStateMachine::InitStaSMHandleMap()
{
    staSmHandleFuncMap[CMD_SIGNAL_POLL] = &StaStateMachine::DealSignalPollResult;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CONNECT_NETWORK] = &StaStateMachine::DealConnectToUserSelectedNetwork;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK] = &StaStateMachine::DealConnectToUserSelectedNetwork;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT] = &StaStateMachine::DealDisconnectEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT] = &StaStateMachine::DealConnectionEvent;
    staSmHandleFuncMap[CMD_NETWORK_CONNECT_TIMEOUT] = &StaStateMachine::DealConnectTimeOutCmd;
    staSmHandleFuncMap[WPA_BLOCK_LIST_CLEAR_EVENT] = &StaStateMachine::DealWpaBlockListClearEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_STARTWPS] = &StaStateMachine::DealStartWpsCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET] = &StaStateMachine::DealWpsConnectTimeOutEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CANCELWPS] = &StaStateMachine::DealCancelWpsCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_RECONNECT_NETWORK] = &StaStateMachine::DealReConnectCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK] = &StaStateMachine::DealReassociateCmd;
    staSmHandleFuncMap[WIFI_SVR_COM_STA_START_ROAM] = &StaStateMachine::DealStartRoamCmd;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT] = &StaStateMachine::DealWpaLinkFailEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT] = &StaStateMachine::DealWpaLinkFailEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT] = &StaStateMachine::DealWpaLinkFailEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_REPORT_DISCONNECT_REASON_EVENT] = &StaStateMachine::DealWpaLinkFailEvent;
    staSmHandleFuncMap[CMD_START_NETCHECK] = &StaStateMachine::DealNetworkCheck;
    staSmHandleFuncMap[CMD_START_GET_DHCP_IP_TIMEOUT] = &StaStateMachine::DealGetDhcpIpTimeout;
    staSmHandleFuncMap[CMD_START_RENEWAL_TIMEOUT] = &StaStateMachine::DealRenewalTimeout;
    staSmHandleFuncMap[WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT] = &StaStateMachine::DealScreenStateChangedEvent;
    staSmHandleFuncMap[CMD_AP_ROAMING_TIMEOUT_CHECK] = &StaStateMachine::DealApRoamingStateTimeout;
#ifndef OHOS_ARCH_LITE
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT] = &StaStateMachine::DealWpaEapSimAuthEvent;
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT] = &StaStateMachine::DealWpaEapUmtsAuthEvent;
#endif
    staSmHandleFuncMap[WIFI_SVR_COM_STA_ENABLE_HILINK] = &StaStateMachine::DealHiLinkDataToWpa;
    staSmHandleFuncMap[WIFI_SVR_COM_STA_HILINK_DELIVER_MAC] = &StaStateMachine::DealHiLinkDataToWpa;
    staSmHandleFuncMap[WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS] = &StaStateMachine::DealHiLinkDataToWpa;
    return WIFI_OPT_SUCCESS;
}

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

void StaStateMachine::DealSignalPollResult(InternalMessage *msg)
{
    LOGD("enter SignalPoll.");
    if (msg == nullptr) {
        LOGE("msg is nullptr.");
        return;
    }
    WifiWpaSignalInfo signalInfo;
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().GetConnectSignalInfo(
        WifiSettings::GetInstance().GetStaIfaceName(), linkedInfo.bssid, signalInfo);
    if (ret != WIFI_IDL_OPT_OK) {
        LOGE("GetConnectSignalInfo return fail: %{public}d.", ret);
        return;
    }
    LOGI("SignalPoll, bssid:%{public}s, freq:%{public}d, rssi:%{public}d, noise:%{public}d, "
        "chload:%{public}d, snr:%{public}d, ulDelay:%{public}d, txLinkSpeed:%{public}d, rxLinkSpeed:%{public}d, "
        "txBytes:%{public}d, rxBytes:%{public}d, txFailed:%{public}d, txPackets:%{public}d, rxPackets:%{public}d.",
        MacAnonymize(linkedInfo.bssid).c_str(), signalInfo.frequency, signalInfo.signal, signalInfo.noise,
        signalInfo.chload, signalInfo.snr, signalInfo.ulDelay, signalInfo.txrate, signalInfo.rxrate, signalInfo.txBytes,
        signalInfo.rxBytes, signalInfo.txFailed, signalInfo.txPackets, signalInfo.rxPackets);

    if (signalInfo.frequency > 0) {
        linkedInfo.frequency = signalInfo.frequency;
    }
    ConvertFreqToChannel();
    if (signalInfo.signal > INVALID_RSSI_VALUE && signalInfo.signal < MAX_RSSI_VALUE) {
        if (signalInfo.signal > 0) {
            linkedInfo.rssi = setRssi((signalInfo.signal - SIGNAL_INFO));
        } else {
            linkedInfo.rssi = setRssi(signalInfo.signal);
        }
        int currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band, m_instId);
        LOGI("SignalPoll, networkId:%{public}d, ssid:%{public}s, rssi:%{public}d, band:%{public}d, "
            "connState:%{public}d, detailedState:%{public}d, currentSignal:%{public}d, lastSignal:%{public}d.\n",
            linkedInfo.networkId, SsidAnonymize(linkedInfo.ssid).c_str(), linkedInfo.rssi, linkedInfo.band,
            linkedInfo.connState, linkedInfo.detailedState, currentSignalLevel, lastSignalLevel);
        if (currentSignalLevel != lastSignalLevel) {
            WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
            InvokeOnStaRssiLevelChanged(linkedInfo.rssi);
            lastSignalLevel = currentSignalLevel;
        }
    } else {
        linkedInfo.rssi = INVALID_RSSI_VALUE;
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
    if (linkedInfo.wifiStandard == WIFI_MODE_UNDEFINED) {
        WifiSettings::GetInstance().SetWifiLinkedStandardAndMaxSpeed(linkedInfo);
    }
    LOGD("SignalPoll GetWifiStandard:%{public}d, bssid:%{public}s rxmax:%{public}d txmax:%{public}d.",
         linkedInfo.wifiStandard, MacAnonymize(linkedInfo.bssid).c_str(), linkedInfo.maxSupportedRxLinkSpeed,
         linkedInfo.maxSupportedTxLinkSpeed);
    WriteLinkInfoHiSysEvent(lastSignalLevel, linkedInfo.rssi, linkedInfo.band, linkedInfo.linkSpeed);
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    DealSignalPacketChanged(signalInfo.txPackets, signalInfo.rxPackets);

    if (enableSignalPoll) {
        WIFI_LOGD("SignalPoll, StartTimer for SIGNAL_POLL.\n");
        StartTimer(static_cast<int>(CMD_SIGNAL_POLL), STA_SIGNAL_POLL_DELAY);
    }
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
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config) != 0) {
        LOGE("GetDeviceConfig failed!");
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

void StaStateMachine::OnConnectFailed(int networkId)
{
    WIFI_LOGE("Connect to network failed: %{public}d.\n", networkId);
    SaveLinkstate(ConnState::DISCONNECTED, DetailedState::FAILED);
    InvokeOnStaConnChanged(OperateResState::CONNECT_ENABLE_NETWORK_FAILED, linkedInfo);
    InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
}

void StaStateMachine::DealConnectToUserSelectedNetwork(InternalMessage *msg)
{
    LOGD("enter DealConnectToUserSelectedNetwork.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return;
    }

    int networkId = msg->GetParam1();
    int connTriggerMode = msg->GetParam2();
    auto bssid = msg->GetStringFromMessage();
    if (connTriggerMode != NETWORK_SELECTED_BY_RETRY) {
        linkedInfo.retryedConnCount = 0;
    }
    WriteWifiConnectionInfoHiSysEvent(networkId);
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGE("GetDeviceConfig failed!");
        return;
    }
    if (networkId == linkedInfo.networkId) {
        if (linkedInfo.connState == ConnState::CONNECTED && config.isReassocSelfCureWithFactoryMacAddress == 0) {
            InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, linkedInfo);
            WIFI_LOGI("This network is in use and does not need to be reconnected.\n");
            return;
        }
        if (linkedInfo.connState == ConnState::CONNECTING &&
            linkedInfo.detailedState == DetailedState::OBTAINING_IPADDR) {
            WIFI_LOGI("This network is connecting and does not need to be reconnected.\n");
            return;
        }
    }

    std::string connectType = config.lastConnectTime <= 0 ? "FIRST_CONNECT" :
        connTriggerMode == NETWORK_SELECTED_BY_AUTO ? "AUTO_CONNECT" :
        connTriggerMode == NETWORK_SELECTED_BY_USER ? "SELECT_CONNECT" : "";
    if (!connectType.empty()) {
        WirteConnectTypeHiSysEvent(connectType);
    }

    /* Save connection information. */
    SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    SaveLinkstate(ConnState::CONNECTING, DetailedState::CONNECTING);
    networkStatusHistoryInserted = false;
    /* Callback result to InterfaceService. */
    InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING, linkedInfo);

    if (StartConnectToNetwork(networkId, bssid) != WIFI_OPT_SUCCESS) {
        OnConnectFailed(networkId);
        return;
    }
    SetConnectMethod(connTriggerMode);
    /* Sets network status. */
    WifiSettings::GetInstance().EnableNetwork(networkId, connTriggerMode == NETWORK_SELECTED_BY_USER, m_instId);
    WifiSettings::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::ENABLED, false);
}

void StaStateMachine::DealConnectTimeOutCmd(InternalMessage *msg)
{
    LOGW("enter DealConnectTimeOutCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nul\n");
    }

    if (linkedInfo.connState == ConnState::CONNECTED) {
        WIFI_LOGE("Currently connected and do not process timeout.\n");
        return;
    }
    if (targetNetworkId == mLastConnectNetId) {
        mConnectFailedCnt++;
    }
    WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID);
    linkedInfo.retryedConnCount++;
    DealSetStaConnectFailedCount(1, false);
    std::string ssid = linkedInfo.ssid;
    WifiSettings::GetInstance().SetConnectTimeoutBssid(linkedInfo.bssid, m_instId);
    InitWifiLinkedInfo();
    SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_TIMEOUT);
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    linkedInfo.ssid = ssid;
    InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING_TIMEOUT, linkedInfo);
    InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
    linkedInfo.ssid = "";
}

bool StaStateMachine::CheckRoamingBssidIsSame(std::string bssid)
{
    WifiLinkedInfo linkedInfo;
    GetLinkedInfo(linkedInfo);
    WIFI_LOGI("CheckRoamingBssidIsSame bssid = %{public}s linkedinfo.bssid = %{public}s connState = %{public}d",
              MacAnonymize(bssid).c_str(), MacAnonymize(linkedInfo.bssid).c_str(), linkedInfo.connState);
    /* P2P affects STA, causing problems or incorrect data updates */
    if ((linkedInfo.connState == ConnState::CONNECTED) &&
        (linkedInfo.bssid != bssid) && (!IsRoaming())) {
        WIFI_LOGE("Sta ignored the event for bssid is mismatch, isRoam:%{public}d.", IsRoaming());
        return true;
    }

    return false;
}

static void HilinkSetPskToConfig(int networkId)
{
    WIFI_LOGI("enter HilinkSetPskToConfig networkId:%{public}d", networkId);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    if (g_isHilinkFlag && config.preSharedKey.empty()) {
        WifiStaHalInterface::GetInstance().GetPskPassphrase("wlan0", config.preSharedKey);
        config.version = -1;
        if (!WifiSettings::GetInstance().EncryptionDeviceConfig(config)) {
            LOGE("HilinkSetPskToConfig EncryptionDeviceConfig failed");
        }
    }
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
    g_isHilinkFlag = false;
}

bool StaStateMachine::CurrentIsRandomizedMac()
{
    std::string curMacAddress = "";
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(curMacAddress)) != WIFI_IDL_OPT_OK) {
        LOGE("CurrentIsRandomizedMac GetStaDeviceMacAddress failed!");
        return false;
    }
    std::string realMacAddress = "";
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddress, m_instId);
    WIFI_LOGI("CurrentIsRandomizedMac curMacAddress:%{public}s realMacAddress:%{public}s",
        MacAnonymize(curMacAddress).c_str(), MacAnonymize(realMacAddress).c_str());
    return curMacAddress != realMacAddress;
}

void StaStateMachine::DealConnectionEvent(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealConnectionEvent, msg is nullptr.\n");
        return;
    }
    std::string bssid = msg->GetStringFromMessage();
    if (CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("DealConnectionEvent inconsistent bssid in connecter");
        return;
    }
    WIFI_LOGI("enter DealConnectionEvent");
    if (CurrentIsRandomizedMac()) {
        WifiSettings::GetInstance().SetDeviceRandomizedMacSuccessEver(targetNetworkId);
    }
    WifiSettings::GetInstance().SetDeviceAfterConnect(targetNetworkId);
    WifiSettings::GetInstance().SetDeviceState(targetNetworkId, (int)WifiDeviceConfigStatus::ENABLED, false);
    WifiSettings::GetInstance().SyncDeviceConfig();
#ifndef OHOS_ARCH_LITE
    HilinkSetPskToConfig(targetNetworkId);
    SaveWifiConfigForUpdate(targetNetworkId);
#endif
    /* Stop clearing the Wpa_blocklist. */
    StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    ConnectToNetworkProcess(bssid);
    StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    StartTimer(static_cast<int>(CMD_SIGNAL_POLL), 0);

    if (wpsState != SetupMethod::INVALID) {
        wpsState = SetupMethod::INVALID;
    }
#ifndef OHOS_ARCH_LITE
    if (NetSupplierInfo != nullptr) {
        NetSupplierInfo->isAvailable_ = true;
        NetSupplierInfo->isRoaming_ = isRoam;
        WIFI_LOGI("On connect update net supplier info\n");
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(NetSupplierInfo);
    }
#endif
    /* Callback result to InterfaceService. */
    InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP, linkedInfo);

    if (WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(false) != WIFI_IDL_OPT_OK) {
        LOGE("DealConnectionEvent WpaSetPowerMode() failed!");
    }
    mConnectFailedCnt = 0;
    /* The current state of StaStateMachine transfers to GetIpState. */
    SwitchState(pGetIpState);
    WifiSettings::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, m_instId);
}

void StaStateMachine::DealDisconnectEvent(InternalMessage *msg)
{
    LOGI("Enter DealDisconnectEvent.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }
    if (wpsState != SetupMethod::INVALID) {
        WIFI_LOGE("wpsState is INVALID\n");
        return;
    }
    std::string bssid;
    msg->GetMessageObj(bssid);
    if (CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("DealDisconnectEvent inconsistent bssid in connecter");
        return;
    }
#ifndef OHOS_ARCH_LITE
    if (NetSupplierInfo != nullptr) {
        NetSupplierInfo->isAvailable_ = false;
        WIFI_LOGI("On disconnect update net supplier info\n");
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(NetSupplierInfo);
    }
#endif
    StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
    StopTimer(static_cast<int>(CMD_START_NETCHECK));
    WIFI_LOGI("StopTimer CMD_START_RENEWAL_TIMEOUT DealDisconnectEvent");
#ifndef OHOS_ARCH_LITE
    StaStateMachine::DhcpResultNotify::StopRenewTimeout();
#else
    StopTimer(static_cast<int>(CMD_START_RENEWAL_TIMEOUT));
#endif
    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    if (currentTpType == IPTYPE_IPV4) {
        StopDhcpClient(ifname.c_str(), false);
    } else {
        StopDhcpClient(ifname.c_str(), true);
    }
    getIpSucNum = 0;
    getIpFailNum = 0;
    isRoam = false;

    IpInfo ipInfo;
    WifiSettings::GetInstance().SaveIpInfo(ipInfo, m_instId);
    IpV6Info ipV6Info;
    WifiSettings::GetInstance().SaveIpV6Info(ipV6Info, m_instId);
#ifdef OHOS_ARCH_LITE
    IfConfig::GetInstance().FlushIpAddr(WifiSettings::GetInstance().GetStaIfaceName(), IPTYPE_IPV4);
#endif
    /* Initialize connection information. */
    std::string ssid = linkedInfo.ssid;
    InitWifiLinkedInfo();
    if (lastLinkedInfo.detailedState == DetailedState::CONNECTING) {
        linkedInfo.networkId = lastLinkedInfo.networkId;
        linkedInfo.ssid = lastLinkedInfo.ssid;
        linkedInfo.connState = ConnState::CONNECTING;
        linkedInfo.detailedState = DetailedState::CONNECTING;
        WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    } else {
        WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    }
    linkedInfo.ssid = ssid;
    /* Callback result to InterfaceService. */
    InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
    linkedInfo.ssid = "";
    SwitchState(pSeparatedState);
    return;
}

static constexpr int DIS_REASON_DISASSOC_STA_HAS_LEFT = 8;

bool StaStateMachine::IsDisConnectReasonShouldStopTimer(int reason)
{
    return reason == DIS_REASON_DISASSOC_STA_HAS_LEFT;
}

bool StaStateMachine::IsStaDisConnectReasonShouldRetryEvent(int eventName)
{
    return eventName == WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT ||
        eventName == WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT;
}

void StaStateMachine::DealWpaLinkFailEvent(InternalMessage *msg)
{
    LOGW("enter DealWpaLinkFailEvent.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return;
    }
    DealSetStaConnectFailedCount(1, false);
    int eventName = msg->GetMessageName();
    if (IsStaDisConnectReasonShouldRetryEvent(eventName) && DealReconnectSavedNetwork()) {
        return;
    }
    bool shouldStopTimer = true;
    if (eventName == WIFI_SVR_CMD_STA_REPORT_DISCONNECT_REASON_EVENT) {
        std::string bssid = msg->GetStringFromMessage();
        int reason = msg->GetIntFromMessage();
        WIFI_LOGI("DealWpaLinkFailEvent reason:%{public}d, bssid:%{public}s", reason, MacAnonymize(bssid).c_str());
        shouldStopTimer = IsDisConnectReasonShouldStopTimer(reason);
    }
    if (shouldStopTimer) {
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    }
    std::string ssid = linkedInfo.ssid;
    InitWifiLinkedInfo();
    linkedInfo.ssid = ssid;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    switch (eventName) {
        case WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT:
            SaveDiscReason(DisconnectedReason::DISC_REASON_WRONG_PWD);
            SaveLinkstate(ConnState::DISCONNECTED, DetailedState::PASSWORD_ERROR);
            InvokeOnStaConnChanged(OperateResState::CONNECT_PASSWORD_WRONG, linkedInfo);
            InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
            break;
        case WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT:
            WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID);
            SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_FULL);
            SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_FULL);
            InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTION_FULL, linkedInfo);
            InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
            break;
        case WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT:
            WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID);
            SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_REJECTED);
            SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_REJECT);
            InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTION_REJECT, linkedInfo);
            InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
            break;
        default:
            LOGW("DealWpaLinkFailEvent unhandled %{public}d", eventName);
            break;
    }
    linkedInfo.ssid = "";
}

bool StaStateMachine::DealReconnectSavedNetwork()
{
    if (targetNetworkId == mLastConnectNetId) {
        mConnectFailedCnt++;
    }
    linkedInfo.retryedConnCount++;
    if (linkedInfo.retryedConnCount < MAX_RETRY_COUNT) {
        SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK,
            targetNetworkId, NETWORK_SELECTED_BY_RETRY);
        WIFI_LOGW("DealConnectTimeOutCmd retry connect to saved network.\n");
        return true;
    }
    return false;
}

void StaStateMachine::DealSetStaConnectFailedCount(int count, bool set)
{
    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    if (ret != 0) {
        WIFI_LOGW("DealConnectTimeOutCmd get device[%{public}d] config failed.\n", targetNetworkId);
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

void StaStateMachine::DealReConnectCmd(InternalMessage *msg)
{
    LOGI("enter DealReConnectCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }

    if (linkedInfo.connState == ConnState::CONNECTED) {
        WIFI_LOGE("Network is already connected, ignore the re-connect command!\n");
        return;
    }

    if (WifiStaHalInterface::GetInstance().Reconnect() == WIFI_IDL_OPT_OK) {
        DealSetStaConnectFailedCount(0, true);
        WIFI_LOGI("StaStateMachine ReConnect successfully!");
        /* Callback result to InterfaceService */
        InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING, linkedInfo);
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
        StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    } else {
        linkedInfo.retryedConnCount++;
        DealSetStaConnectFailedCount(1, false);
        WIFI_LOGE("ReConnect failed!");
    }
}

void StaStateMachine::DealReassociateCmd(InternalMessage *msg)
{
    LOGI("enter DealReassociateCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }
    WirteConnectTypeHiSysEvent("REASSOC");
    if (WifiStaHalInterface::GetInstance().Reassociate() == WIFI_IDL_OPT_OK) {
        /* Callback result to InterfaceService */
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATING, linkedInfo);
        WIFI_LOGD("StaStateMachine ReAssociate successfully!");
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
        StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    } else {
        WIFI_LOGE("ReAssociate failed!");
    }
}

void StaStateMachine::DealStartWpsCmd(InternalMessage *msg)
{
    WIFI_LOGI("enter DealStartWpsCmd\n");
    if (msg == nullptr) {
        return;
    }

    if (WifiStaHalInterface::GetInstance().ClearDeviceConfig() != WIFI_IDL_OPT_OK) {
        LOGE("ClearDeviceConfig() failed!");
        return;
    }

    StartWpsMode(msg);
    if ((wpsState == SetupMethod::DISPLAY) || (wpsState == SetupMethod::KEYPAD)) {
        WIFI_LOGW("Clear WPA block list every ten second!");
        SendMessage(WPA_BLOCK_LIST_CLEAR_EVENT);
    }
}

void StaStateMachine::StartWpsMode(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    /*
     * Make judgement to wps configuration information: the function will exit if
     * the result is fail, then else continue to chose the Wps starting mode. The
     * current state of StaStateMachine transfers to WpsState after Wps code start
     * successfully.
     */
    WifiIdlWpsConfig wpsParam;
    WpsConfig wpsConfig;
    wpsConfig.setup = static_cast<SetupMethod>(msg->GetParam1());
    wpsConfig.pin = msg->GetStringFromMessage();
    wpsConfig.bssid = msg->GetStringFromMessage();
    if (wpsConfig.bssid.length() == 0 || wpsConfig.bssid == PBC_ANY_BSSID) {
        wpsParam.anyFlag = 1;
        wpsParam.bssid = PBC_ANY_BSSID;
    } else {
        wpsParam.anyFlag = 0;
        wpsParam.bssid = wpsConfig.bssid;
    }
    wpsParam.multiAp = MULTI_AP;
    WIFI_LOGI("wpsConfig  setup = %{public}d", wpsConfig.setup);
    WIFI_LOGI("wpsParam.AnyFlag = %{public}d, wpsParam.mulitAp = %{public}d, wpsParam.bssid = %{public}s",
        wpsParam.anyFlag,
        wpsParam.multiAp,
        MacAnonymize(wpsParam.bssid).c_str());

    if (wpsConfig.setup == SetupMethod::PBC) {
        if (WifiStaHalInterface::GetInstance().StartWpsPbcMode(wpsParam) == WIFI_IDL_OPT_OK) {
            wpsState = wpsConfig.setup;
            WIFI_LOGD("StartWpsPbcMode() succeed!");
            /* Callback result to InterfaceService. */
            InvokeOnWpsChanged(WpsStartState::START_PBC_SUCCEED, pinCode);
            SwitchState(pWpsState);
        } else {
            LOGE("StartWpsPbcMode() failed!");
            InvokeOnWpsChanged(WpsStartState::START_PBC_FAILED, pinCode);
        }
    } else if (wpsConfig.setup == SetupMethod::DISPLAY) {
        if (WifiStaHalInterface::GetInstance().StartWpsPinMode(wpsParam, pinCode) == WIFI_IDL_OPT_OK) {
            wpsState = wpsConfig.setup;
            /* Callback result to InterfaceService. */
            InvokeOnWpsChanged(WpsStartState::START_PIN_SUCCEED, pinCode);
            WIFI_LOGD("StartWpsPinMode() succeed!  pincode: %d", pinCode);
            SwitchState(pWpsState);
        } else {
            WIFI_LOGE("StartWpsPinMode() failed!");
            InvokeOnWpsChanged(WpsStartState::START_PIN_FAILED, pinCode);
        }
    } else if (wpsConfig.setup == SetupMethod::KEYPAD) {
        if (WifiStaHalInterface::GetInstance().StartWpsPinMode(wpsParam, pinCode) == WIFI_IDL_OPT_OK) {
            wpsState = wpsConfig.setup;
            /* Callback result to InterfaceService. */
            InvokeOnWpsChanged(WpsStartState::START_AP_PIN_SUCCEED, pinCode);
            SwitchState(pWpsState);
        } else {
            LOGE("StartWpsPinMode() failed.");
            InvokeOnWpsChanged(WpsStartState::START_AP_PIN_FAILED, pinCode);
        }
    } else {
        LOGE("Start Wps failed!");
        InvokeOnWpsChanged(WpsStartState::START_WPS_FAILED, pinCode);
    }
}

void StaStateMachine::DealWpaBlockListClearEvent(InternalMessage *msg)
{
    if (msg != nullptr) {
        WIFI_LOGE("enter DealWpaBlockListClearEvent\n");
    }
    if (WifiStaHalInterface::GetInstance().WpaBlocklistClear() != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("Clearing the Wpa_blocklist failed\n");
    }
    StartTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT), BLOCK_LIST_CLEAR_TIMER);
    WIFI_LOGI("Clearing the Wpa_blocklist.\n");
}

void StaStateMachine::DealWpsConnectTimeOutEvent(InternalMessage *msg)
{
    WIFI_LOGW("enter DealWpsConnectTimeOutEvent\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr!\n");
        return;
    }
    int failreason = msg->GetParam1();
    if (failreason > 0) {
        DisConnectProcess();
        OnWifiWpa3SelfCure(failreason, targetNetworkId);
    }
    DealCancelWpsCmd(msg);

    /* Callback InterfaceService that WPS time out. */
    InvokeOnWpsChanged(WpsStartState::WPS_TIME_OUT, pinCode);
    SwitchState(pSeparatedState);
}

void StaStateMachine::DealCancelWpsCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }

    StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    isWpsConnect = IsWpsConnected::WPS_INVALID;
    if (WifiStaHalInterface::GetInstance().StopWps() == WIFI_IDL_OPT_OK) {
        WIFI_LOGI("CancelWps succeed!");
        /* Callback result to InterfaceService that stop Wps connection successfully. */
        if (wpsState == SetupMethod::PBC) {
            InvokeOnWpsChanged(WpsStartState::STOP_PBC_SUCCEED, pinCode);
        } else if (wpsState == SetupMethod::DISPLAY) {
            InvokeOnWpsChanged(WpsStartState::STOP_PIN_SUCCEED, pinCode);
        } else if (wpsState == SetupMethod::KEYPAD) {
            InvokeOnWpsChanged(WpsStartState::STOP_AP_PIN_SUCCEED, pinCode);
        }
        if (wpsState != SetupMethod::INVALID) {
            wpsState = SetupMethod::INVALID;

            if (WifiStaHalInterface::GetInstance().EnableNetwork(WPA_DEFAULT_NETWORKID) == WIFI_IDL_OPT_OK) {
                WIFI_LOGI("EnableNetwork success!");
            } else {
                WIFI_LOGE("EnableNetwork failed");
            }
        }
    } else {
        WIFI_LOGE("CancelWps failed!");
        if (wpsState == SetupMethod::PBC) {
            InvokeOnWpsChanged(WpsStartState::STOP_PBC_FAILED, pinCode);
        } else if (wpsState == SetupMethod::DISPLAY) {
            InvokeOnWpsChanged(WpsStartState::STOP_PIN_FAILED, pinCode);
        } else if (wpsState == SetupMethod::KEYPAD) {
            InvokeOnWpsChanged(WpsStartState::STOP_AP_PIN_FAILED, pinCode);
        }
    }
    SwitchState(pSeparatedState);
}

void StaStateMachine::DealStartRoamCmd(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }

    WIFI_LOGI("enter DealStartRoamCmd\n");
    std::string bssid = msg->GetStringFromMessage();
    /* GetDeviceConfig from Configuration center. */
    WifiDeviceConfig network;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, network);

    /* Setting the network. */
    WifiIdlDeviceConfig idlConfig;
    idlConfig.networkId = linkedInfo.networkId;
    idlConfig.ssid = linkedInfo.ssid;
    idlConfig.bssid = bssid;
    idlConfig.psk = network.preSharedKey;
    idlConfig.keyMgmt = network.keyMgmt;
    idlConfig.priority = network.priority;
    idlConfig.scanSsid = network.hiddenSSID ? 1 : 0;
    FillEapCfg(network, idlConfig);
    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(linkedInfo.networkId, idlConfig) != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("DealStartRoamCmd SetDeviceConfig() failed!");
        return;
    }
    WIFI_LOGD("DealStartRoamCmd  SetDeviceConfig() succeed!");

    /* Save to Configuration center. */
    network.bssid = bssid;
    WifiSettings::GetInstance().AddDeviceConfig(network);
    WifiSettings::GetInstance().SyncDeviceConfig();

    /* Save linkedinfo */
    linkedInfo.bssid = bssid;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);

    if (WifiStaHalInterface::GetInstance().Reassociate() != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("START_ROAM-ReAssociate() failed!");
    }
    WIFI_LOGI("START_ROAM-ReAssociate() succeeded!");
    /* Start roaming */
    SwitchState(pApRoamingState);
}

ErrCode StaStateMachine::StartConnectToNetwork(int networkId, const std::string & bssid)
{
    if (ConfigRandMacSelfCure(networkId) != WIFI_OPT_SUCCESS) {
        LOGE("ConfigRandMacSelfCure failed!");
        return WIFI_OPT_FAILED;
    }
    targetNetworkId = networkId;
    SetRandomMac(targetNetworkId, bssid);
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig) != 0) {
        LOGE("StartConnectToNetwork get GetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    WifiStaHalInterface::GetInstance().ClearDeviceConfig();
    int wpaNetworkId = INVALID_NETWORK_ID;
    if (WifiStaHalInterface::GetInstance().GetNextNetworkId(wpaNetworkId) != WIFI_IDL_OPT_OK) {
        LOGE("StartConnectToNetwork GetNextNetworkId failed!");
        return WIFI_OPT_FAILED;
    }
    ConvertDeviceCfg(deviceConfig);
    if (bssid.empty()) {
        // user select connect
        LOGI("SetBssid userSelectBssid=%{public}s", MacAnonymize(deviceConfig.userSelectBssid).c_str());
        WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, deviceConfig.userSelectBssid);
        deviceConfig.userSelectBssid = "";
        WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        WifiSettings::GetInstance().SyncDeviceConfig();
    } else {
        // auto connect
        LOGI("SetBssid bssid=%{public}s", MacAnonymize(bssid).c_str());
        WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid);
    }
    if (WifiStaHalInterface::GetInstance().EnableNetwork(WPA_DEFAULT_NETWORKID) != WIFI_IDL_OPT_OK) {
        LOGE("EnableNetwork() failed!");
        return WIFI_OPT_FAILED;
    }

    if (WifiStaHalInterface::GetInstance().Connect(WPA_DEFAULT_NETWORKID) != WIFI_IDL_OPT_OK) {
        LOGE("Connect failed!");
        InvokeOnStaConnChanged(OperateResState::CONNECT_SELECT_NETWORK_FAILED, linkedInfo);
        return WIFI_OPT_FAILED;
    }
    StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
        static_cast<int>(WifiOperateState::STA_CONNECTING));
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::MacAddressGenerate(WifiStoreRandomMac &randomMacInfo)
{
    LOGD("enter MacAddressGenerate\n");
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
            LOGE("StaStateMachine::MacAddressGenerate failed, sprintf_s return -1!\n");
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
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) == -1) {
        WIFI_LOGE("OnWifiWpa3SelfCure, get deviceconfig failed");
        return;
    }
    if (!IsWpa3Transition(config.ssid)) {
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

bool StaStateMachine::IsWpa3Transition(std::string ssid) const
{
    std::vector<WifiScanInfo> scanInfoList;
    WifiSettings::GetInstance().GetScanInfoList(scanInfoList);
    for (auto scanInfo : scanInfoList) {
        if ((ssid == scanInfo.ssid) &&
            (scanInfo.capabilities.find("PSK+SAE") != std::string::npos)) {
            LOGI("IsWpa3Transition, check is transition");
            return true;
        }
    }
    return false;
}

bool StaStateMachine::ComparedKeymgmt(const std::string scanInfoKeymgmt, const std::string deviceKeymgmt)
{
    if (deviceKeymgmt == "WPA-PSK") {
        return scanInfoKeymgmt.find("PSK") != std::string::npos;
    } else if (deviceKeymgmt == "WPA-EAP") {
        return scanInfoKeymgmt.find("EAP") != std::string::npos;
    } else if (deviceKeymgmt == "SAE") {
        return scanInfoKeymgmt.find("SAE") != std::string::npos;
    } else if (deviceKeymgmt == "NONE") {
        return (scanInfoKeymgmt.find("PSK") == std::string::npos) &&
               (scanInfoKeymgmt.find("EAP") == std::string::npos) && (scanInfoKeymgmt.find("SAE") == std::string::npos);
    } else {
        return false;
    }
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
        WifiSettings::GetInstance().GetScanInfoList(scanInfoList);
        for (auto scanInfo : scanInfoList) {
            if ((deviceConfig.ssid == scanInfo.ssid) &&
                (ComparedKeymgmt(scanInfo.capabilities, deviceConfig.keyMgmt))) {
                randomMacInfo.peerBssid = scanInfo.bssid;
                break;
            }
        }
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

bool StaStateMachine::SetRandomMac(int networkId, const std::string &bssid)
{
    LOGD("enter SetRandomMac.");
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig) != 0) {
        LOGE("SetRandomMac : GetDeviceConfig failed!");
        return false;
    }
    std::string lastMac;
    std::string currentMac;
    if (deviceConfig.wifiPrivacySetting == WifiPrivacyConfig::DEVICEMAC || ShouldUseFactoryMac(deviceConfig)) {
        WifiSettings::GetInstance().GetRealMacAddress(currentMac, m_instId);
    } else {
        WifiStoreRandomMac randomMacInfo;
        InitRandomMacInfo(deviceConfig, bssid, randomMacInfo);

        if (randomMacInfo.peerBssid.empty()) {
            LOGE("scanInfo has no target wifi and bssid is empty!");
            return false;
        }

        WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
        if (randomMacInfo.randomMac.empty()) {
            /* Sets the MAC address of WifiSettings. */
            std::string macAddress;
            WifiSettings::GetInstance().GenerateRandomMacAddress(macAddress);
            randomMacInfo.randomMac = macAddress;
            LOGI("%{public}s: generate a random mac, randomMac:%{public}s, ssid:%{public}s, peerbssid:%{public}s",
                __func__, MacAnonymize(randomMacInfo.randomMac).c_str(), SsidAnonymize(randomMacInfo.ssid).c_str(),
                MacAnonymize(randomMacInfo.peerBssid).c_str());
            WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
        } else {
            LOGI("%{public}s: randomMac:%{public}s, ssid:%{public}s, peerbssid:%{public}s",
                __func__, MacAnonymize(randomMacInfo.randomMac).c_str(), SsidAnonymize(randomMacInfo.ssid).c_str(),
                MacAnonymize(randomMacInfo.peerBssid).c_str());
        }
        currentMac = randomMacInfo.randomMac;
    }

    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(lastMac)) != WIFI_IDL_OPT_OK) {
        LOGE("GetStaDeviceMacAddress failed!");
        return false;
    }

    LOGI("%{public}s, currentMac:%{public}s, lastMac:%{public}s",
        __func__, MacAnonymize(currentMac).c_str(), MacAnonymize(lastMac).c_str());
    if (MacAddress::IsValidMac(currentMac.c_str())) {
        if (lastMac != currentMac) {
            if (WifiStaHalInterface::GetInstance().SetConnectMacAddr(
                WifiSettings::GetInstance().GetStaIfaceName(), currentMac) != WIFI_IDL_OPT_OK) {
                LOGE("set Mac [%{public}s] failed.", MacAnonymize(currentMac).c_str());
                return false;
            }
        }
        WifiSettings::GetInstance().SetMacAddress(currentMac, m_instId);
        deviceConfig.macAddress = currentMac;
        WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        WifiSettings::GetInstance().SyncDeviceConfig();
    } else {
        LOGE("Check MacAddress error.");
        return false;
    }
#endif
    return true;
}

void StaStateMachine::StartRoamToNetwork(std::string bssid)
{
    InternalMessage *msg = CreateMessage();
    if (msg == nullptr) {
        return;
    }

    msg->SetMessageName(WIFI_SVR_COM_STA_START_ROAM);
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

bool StaStateMachine::IsRoaming(void)
{
    return isRoam;
}

void StaStateMachine::OnNetworkConnectionEvent(int networkId, std::string bssid)
{
    InternalMessage *msg = CreateMessage();
    if (msg == nullptr) {
        LOGE("msg is nullptr.\n");
        return;
    }

    msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
    msg->SetParam1(networkId);
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

void StaStateMachine::OnNetworkDisconnectEvent(int reason)
{
    WriteWifiAbnormalDisconnectHiSysEvent(reason);
}

void StaStateMachine::OnNetworkAssocEvent(int assocState, std::string bssid, StaStateMachine *pStaStateMachine)
{
    if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("OnNetworkAssocEvent inconsistent bssid in connecter");
        return;
    }
    if (assocState == WPA_CB_ASSOCIATING) {
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATING, linkedInfo);
    } else {
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATED, linkedInfo);
    }
}

void StaStateMachine::OnNetworkHiviewEvent(int state)
{
    if (state == WPA_CB_ASSOCIATING) {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
            static_cast<int>(WifiOperateState::STA_ASSOCIATING));
    } else if (state == WPA_CB_ASSOCIATED) {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
            static_cast<int>(WifiOperateState::STA_ASSOCIATED));
    }
}

void StaStateMachine::OnBssidChangedEvent(std::string reason, std::string bssid)
{
    InternalMessage *msg = CreateMessage();
    if (msg == nullptr) {
        LOGE("msg is nullptr.\n");
        return;
    }

    msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
    msg->AddStringMessageBody(reason);
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

void StaStateMachine::OnDhcpResultNotifyEvent(DhcpReturnCode result, int ipType)
{
    InternalMessage *msg = CreateMessage();
    if (msg == nullptr) {
        LOGE("msg is nullptr.\n");
        return;
    }

    msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
    msg->SetParam1(result);
    msg->SetParam2(ipType);
    SendMessage(msg);
}

#ifndef OHOS_ARCH_LITE
int32_t StaStateMachine::GetDataSlotId()
{
    auto slotId = CellularDataClient::GetInstance().GetDefaultCellularDataSlotId();
    if (slotId < 0 || slotId >= CoreServiceClient::GetInstance().GetMaxSimCount()) {
        LOGE("failed to get default slotId, slotId:%{public}d", slotId);
        return -1;
    }
    LOGI("slotId: %{public}d", slotId);
    return slotId;
}

int32_t StaStateMachine::GetCardType(CardType &cardType)
{
    return CoreServiceClient::GetInstance().GetCardType(GetDataSlotId(), cardType);
}

int32_t StaStateMachine::GetDefaultId(int32_t slotId)
{
    LOGI("StaStateMachine::GetDefaultId in, slotId: %{public}d", slotId);
    if (slotId == WIFI_INVALID_SIM_ID) {
        return GetDataSlotId();
    }
    return slotId;
}

int32_t StaStateMachine::GetSimCardState(int32_t slotId)
{
    LOGI("StaStateMachine::GetSimCardState in, slotId: %{public}d", slotId);
    slotId = GetDefaultId(slotId);
    LOGI("slotId: %{public}d", slotId);
    SimState simState = SimState::SIM_STATE_UNKNOWN;
    int32_t result = CoreServiceClient::GetInstance().GetSimState(slotId, simState);
    if (result != WIFI_OPT_SUCCESS) {
        LOGE("StaStateMachine::GetSimCardState result:%{public}d, simState:%{public}d", result, simState);
        return static_cast<int32_t>(simState);
    }
    LOGI("StaStateMachine::GetSimCardState out, simState:%{public}d", simState);
    return static_cast<int32_t>(simState);
}

bool StaStateMachine::IsValidSimId(int32_t simId)
{
    if (simId > 0) {
        return true;
    }
    return false;
}

bool StaStateMachine::IsMultiSimEnabled() {
    int32_t simCount = CoreServiceClient::GetInstance().GetMaxSimCount();
    LOGI("StaStateMachine::IsMultiSimEnabled simCount:%{public}d", simCount);
    if (simCount > 1) {
        return true;
    }
    return false;
}

std::string StaStateMachine::SimAkaAuth(const std::string &nonce, AuthType authType)
{
    LOGD("StaStateMachine::SimAkaAuth in, authType:%{public}d, nonce:%{private}s", authType, nonce.c_str());
    auto slotId = GetDataSlotId();
    SimAuthenticationResponse response;
    int32_t result = CoreServiceClient::GetInstance().SimAuthentication(slotId, authType, nonce, response);
    if (result != WIFI_OPT_SUCCESS) {
        LOGE("StaStateMachine::SimAkaAuth: errCode=%{public}d", result);
        return "";
    }
    return response.response;
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

    LOGI("%{public}s size:%{public}zu", __func__, param.rands.size());
    for (auto iter = param.rands.begin(); iter != param.rands.end(); ++iter) {
        // data pre-processing
        memset_s(randArray, sizeof(randArray), 0x0, sizeof(randArray));
        char tmpRand[MAX_RAND_STR_LEN + 1] = { 0 };
        if (strncpy_s(tmpRand, sizeof(tmpRand), (*iter).c_str(), (*iter).length()) != EOK) {
            LOGE("%{public}s: failed to copy", __func__);
            return "";
        }
        LOGD("%{public}s rand[%{public}d]: %{private}s, tmpRand: %{private}s",
            __func__, i, (*iter).c_str(), tmpRand);

        // converting a hexadecimal character string to an array
        int ret = HexString2Byte(tmpRand, randArray, sizeof(randArray));
        if (ret != 0) {
            LOGE("%{public}s: failed to convert a hexadecimal character string to integer", __func__);
            return "";
        }
        std::vector<uint8_t> randVec;
        randVec.push_back(sizeof(randArray));
        for (size_t j = 0; j < sizeof(randArray); j++) {
            randVec.push_back(randArray[j]);
        }

        // encode data and initiate a challenge request
        std::string base64Challenge = EncodeBase64(randVec);
        std::string response = SimAkaAuth(base64Challenge, SIM_AUTH_EAP_SIM_TYPE);
        if (response.empty()) {
            LOGE("%{public}s: fail to sim authentication", __func__);
            return "";
        }
        LOGD("telephony response: %{private}s", response.c_str());

        // decode data: data format is [SRES Length][SRES][KC Length][Cipher Key Kc]
        std::vector<uint8_t> nonce;
        if (!DecodeBase64(response, nonce)) {
            LOGE("%{public}s: failed to decode sim authentication, size:%{public}zu", __func__, nonce.size());
            return "";
        }

        // [SRES Length]: the length is 4 bytes
        uint8_t sresLen = nonce[0];
        if (sresLen >= nonce.size()) {
            LOGE("%{public}s: invalid length, sresLen: %{public}d, size: %{public}zu",
                __func__, sresLen, nonce.size());
            return "";
        }

        // [SRES]
        int offset = 1; // offset [SRES Length]
        char sresBuf[MAX_SRES_STR_LEN + 1] = { 0 };
        Byte2HexString(&nonce[offset], sresLen, sresBuf, sizeof(sresBuf));
        LOGD("%{public}s sresLen: %{public}d, sresBuf: %{private}s", __func__, sresLen, sresBuf);

        // [KC Length]: the length is 8 bytes
        size_t kcOffset = 1 + sresLen; // offset [SRES Length][SRES]
        if (kcOffset >= nonce.size()) {
            LOGE("%{public}s: invalid kcOffset: %{public}zu", __func__, kcOffset);
            return "";
        }
        uint8_t kcLen = nonce[kcOffset];
        if ((kcLen + kcOffset) >= nonce.size()) {
            LOGE("%{public}s: invalid kcLen: %{public}d, kcOffset: %{public}zu", __func__, kcLen, kcOffset);
            return "";
        }

        // [Cipher Key Kc]
        char kcBuf[MAX_KC_STR_LEN + 1] = {0};
        Byte2HexString(&nonce[kcOffset + 1], kcLen, kcBuf, sizeof(kcBuf));
        LOGD("%{public}s kcLen:%{public}d, kcBuf:%{private}s", __func__, kcLen, kcBuf);

        // strcat request message
        if (i == 0) {
            authRsp +=  std::string(kcBuf) + ":" + std::string(sresBuf);
        } else {
            authRsp +=  ":" + std::string(kcBuf) + ":" + std::string(sresBuf);
        }
        i++;
    }
    LOGD("%{public}s authRsp: %{private}s, len: %{public}zu", __func__, authRsp.c_str(), authRsp.length());
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

    LOGI("%{public}s size: %{public}zu", __func__, param.rands.size());
    for (auto iter = param.rands.begin(); iter != param.rands.end(); ++iter) {
        // data pre-processing
        memset_s(randArray, sizeof(randArray), 0x0, sizeof(randArray));
        char tmpRand[MAX_RAND_STR_LEN + 1] = { 0 };
        if (strncpy_s(tmpRand, sizeof(tmpRand), (*iter).c_str(), (*iter).length()) != EOK) {
            LOGE("%{public}s: failed to copy", __func__);
            return "";
        }
        LOGD("%{public}s rand[%{public}d]: %{public}s, tmpRand: %{public}s", __func__, i, (*iter).c_str(), tmpRand);

        // converting a hexadecimal character string to an array
        int ret = HexString2Byte(tmpRand, randArray, sizeof(randArray));
        if (ret != 0) {
            LOGE("%{public}s: fail to data conversion", __func__);
            return "";
        }

        std::vector<uint8_t> randVec;
        for (size_t j = 0; j < sizeof(randArray); j++) {
            randVec.push_back(randArray[j]);
        }

        // encode data and initiate a challenge request
        std::string base64Challenge = EncodeBase64(randVec);
        std::string response = SimAkaAuth(base64Challenge, SIM_AUTH_EAP_SIM_TYPE);
        if (response.empty()) {
            LOGE("%{public}s: fail to authenticate", __func__);
            return "";
        }
        LOGD("telephony response: %{private}s", response.c_str());

        // data format: [SRES][Cipher Key Kc]
        std::vector<uint8_t> nonce;
        if (!DecodeBase64(response, nonce)) {
            LOGE("%{public}s: failed to decode sim authentication, size:%{public}zu", __func__, nonce.size());
            return "";
        }

        if (GSM_AUTH_CHALLENGE_SRES_LEN + GSM_AUTH_CHALLENGE_KC_LEN != nonce.size()) {
            LOGE("%{public}s: invalid length, size: %{public}zu", __func__, nonce.size());
            return "";
        }

        // [SRES]
        std::string sres;
        char sresBuf[MAX_SRES_STR_LEN + 1] = {0};
        Byte2HexString(&nonce[0], GSM_AUTH_CHALLENGE_SRES_LEN, sresBuf, sizeof(sresBuf));

        // [Cipher Key Kc]
        size_t kcOffset = GSM_AUTH_CHALLENGE_SRES_LEN;
        if (kcOffset >= nonce.size()) {
            LOGE("%{public}s: invalid length, kcOffset: %{public}zu", __func__, kcOffset);
            return "";
        }

        std::string kc;
        char kcBuf[MAX_KC_STR_LEN + 1] = {0};
        Byte2HexString(&nonce[kcOffset], GSM_AUTH_CHALLENGE_KC_LEN, kcBuf, sizeof(kcBuf));

        // strcat request message
        if (i == 0) {
            authRsp +=  std::string(kcBuf) + ":" + std::string(sresBuf);
        } else {
            authRsp +=  ":" + std::string(kcBuf) + ":" + std::string(sresBuf);
        }
        i++;
    }
    LOGI("%{public}s authReq: %{private}s, len: %{public}zu", __func__, authRsp.c_str(), authRsp.length());
    return authRsp;
}

bool StaStateMachine::PreWpaEapUmtsAuthEvent()
{
    CardType cardType;
    int32_t ret = GetCardType(cardType);
    if (ret != 0) {
        LOGE("failed to get cardType: %{public}d", ret);
        return false;
    }
    if (cardType == CardType::SINGLE_MODE_SIM_CARD) {
        LOGE("invalid cardType: %{public}d", cardType);
        return false;
    }
    return true;
}

std::vector<uint8_t> StaStateMachine::FillUmtsAuthReq(EapSimUmtsAuthParam &param)
{
    // request data format: [RAND LENGTH][RAND][AUTN LENGTH][AUTN]
    std::vector<uint8_t> inputChallenge;

    // rand hexadecimal string convert to binary
    char rand[MAX_RAND_STR_LEN + 1] = { 0 };
    if (strncpy_s(rand, sizeof(rand), param.rand.c_str(), param.rand.length()) != EOK) {
        LOGE("%{public}s: failed to copy rand", __func__);
        return inputChallenge;
    }
    uint8_t randArray[UMTS_AUTH_CHALLENGE_RAND_LEN];
    int32_t ret = HexString2Byte(rand, randArray, sizeof(randArray));
    if (ret != 0) {
        LOGE("%{public}s: failed to convert to rand", __func__);
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
        LOGE("%{public}s: failed to copy autn", __func__);
        return inputChallenge;
    }
    uint8_t autnArray[UMTS_AUTH_CHALLENGE_RAND_LEN];
    ret = HexString2Byte(autn, autnArray, sizeof(autnArray));
    if (ret != 0) {
        LOGE("%{public}s: failed to convert to autn", __func__);
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
        LOGD("Raw Response: %{private}s", nonceBuf);

        authReq = "UMTS-AUTH:";

        // res
        uint8_t resLen = nonce[UMTS_AUTH_CHALLENGE_DATA_START_IDNEX]; // nonce[1]: the 2nd byte is the length of res
        int resOffset = UMTS_AUTH_CHALLENGE_DATA_START_IDNEX + 1;
        std::string res;
        char resBuf[MAX_RES_STR_LEN + 1] = { 0 };
        /* nonce[2]~nonce[9]: the 3rd byte ~ 10th byte is res data */
        Byte2HexString(&nonce[resOffset], resLen, resBuf, sizeof(resBuf));
        LOGD("%{public}s resLen: %{public}d, resBuf: %{private}s", __func__, resLen, resBuf);

        // ck
        int ckOffset = resOffset + resLen;
        uint8_t ckLen = nonce[ckOffset]; // nonce[10]: the 11th byte is ck length
        std::string ck;
        char ckBuf[MAX_CK_STR_LEN + 1] = { 0 };

        /* nonce[11]~nonce[26]: the 12th byte ~ 27th byte is ck data */
        Byte2HexString(&nonce[ckOffset + 1], ckLen, ckBuf, sizeof(ckBuf));
        LOGD("ckLen: %{public}d, ckBuf:%{private}s", ckLen, ckBuf);

        // ik
        int ikOffset = ckOffset + ckLen + 1;
        uint8_t ikLen = nonce[ikOffset]; // nonce[27]: the 28th byte is the length of ik
        std::string ik;
        char ikBuf[MAX_IK_STR_LEN + 1] = { 0 };
        /* nonce[28]~nonce[43]: the 29th byte ~ 44th byte is ck data */
        Byte2HexString(&nonce[ikOffset + 1], ikLen, ikBuf, sizeof(ikBuf));
        LOGD("ikLen: %{public}d, ikBuf:%{private}s", ikLen, ikBuf);

        std::string authRsp = std::string(ikBuf) + ":" + std::string(ckBuf) + ":" + std::string(resBuf);
        authReq += authRsp;
        LOGD("%{public}s ik: %{private}s, ck: %{private}s, res: %{private}s, authRsp: %{private}s",
            __func__, ikBuf, ckBuf, resBuf, authRsp.c_str());
    } else {
        authReq = "UMTS-AUTS:";

        // auts
        uint8_t autsLen = nonce[UMTS_AUTH_CHALLENGE_DATA_START_IDNEX];
        LOGD("autsLen: %{public}d", autsLen);
        int offset = UMTS_AUTH_CHALLENGE_DATA_START_IDNEX + 1;
        std::string auts;
        char autsBuf[MAX_AUTN_STR_LEN + 1] = { 0 };
        Byte2HexString(&nonce[offset], autsLen, autsBuf, sizeof(autsBuf));
        LOGD("%{public}s auts: %{private}s", __func__, auts.c_str());

        std::string authRsp = auts;
        authReq += authRsp;
        LOGD("%{public}s authRsp: %{private}s", __func__, authRsp.c_str());
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
    return SimAkaAuth(challenge, SIM_AUTH_EAP_AKA_TYPE);
}

void StaStateMachine::DealWpaEapSimAuthEvent(InternalMessage *msg)
{
    if (msg == NULL) {
        LOGE("%{public}s: msg is null", __func__);
        return;
    }

    EapSimGsmAuthParam param;
    msg->GetMessageObj(param);
    LOGI("%{public}s size: %{public}zu", __func__, param.rands.size());

    std::string cmd = "GSM-AUTH:";
    if (param.rands.size() <= 0) {
        LOGE("%{public}s: invalid rands", __func__);
        return;
    }

    std::string authRsp = GetGsmAuthResponseWithLength(param);
    if (authRsp.empty()) {
        authRsp = GetGsmAuthResponseWithoutLength(param);
        if (authRsp.empty()) {
            LOGE("failed to sim authentication");
            return;
        }
    }

    cmd += authRsp;
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd) != WIFI_IDL_OPT_OK) {
        LOGI("%{public}s: failed to send the message, authReq: %{private}s", __func__, cmd.c_str());
        return;
    }
    LOGD("%{public}s: success to send the message, authReq: %{private}s", __func__, cmd.c_str());
}

void StaStateMachine::DealWpaEapUmtsAuthEvent(InternalMessage *msg)
{
    if (msg == NULL) {
        LOGE("%{public}s: msg is null", __func__);
        return;
    }

    EapSimUmtsAuthParam param;
    msg->GetMessageObj(param);
    if (param.rand.empty() || param.autn.empty()) {
        LOGE("invalid rand = %{public}zu or autn = %{public}zu", param.rand.length(), param.autn.length());
        return;
    }

    LOGD("%{public}s rand: %{private}s, autn: %{private}s", __func__, param.rand.c_str(), param.autn.c_str());

    if (!PreWpaEapUmtsAuthEvent()) {
        return;
    }

    // get challenge information
    std::string response = GetUmtsAuthResponse(param);
    if (response.empty()) {
        LOGE("response is empty");
        return;
    }

    // parse authentication information
    std::vector<uint8_t> nonce;
    if (!DecodeBase64(response, nonce)) {
        LOGE("%{public}s: failed to decode aka authentication, size:%{public}zu", __func__, nonce.size());
        return;
    }

    // data format: [0xdb][RES Length][RES][CK Length][CK][IK Length][IK]
    uint8_t tag = nonce[UMTS_AUTH_CHALLENGE_RESULT_INDEX];
    if ((tag != UMTS_AUTH_TYPE_TAG) && (tag != UMTS_AUTS_TYPE_TAG)) {
        LOGE("%{public}s: unsupport type: 0x%{public}02x", __func__, tag);
        return;
    }

    LOGI("tag: 0x%{public}02x", tag);

    // request authentication to wpa
    std::string reqCmd = ParseAndFillUmtsAuthParam(nonce);
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", reqCmd) != WIFI_IDL_OPT_OK) {
        LOGI("%{public}s: failed to send the message, authReq: %{private}s", __func__, reqCmd.c_str());
        return;
    }
    LOGD("%{public}s: success to send the message, authReq: %{private}s", __func__, reqCmd.c_str());
}
#endif

/* --------------------------- state machine Separating State ------------------------------ */
StaStateMachine::SeparatingState::SeparatingState() : State("SeparatingState")
{}

StaStateMachine::SeparatingState::~SeparatingState()
{}

void StaStateMachine::SeparatingState::GoInState()
{
    WIFI_LOGI("SeparatingState GoInState function.");
    return;
}

void StaStateMachine::SeparatingState::GoOutState()
{
    WIFI_LOGI("SeparatingState GoOutState function.");
}

bool StaStateMachine::SeparatingState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_EXECUTED;
    WIFI_LOGI("SeparatingState-msgCode=%{public}d not handled.\n", msg->GetMessageName());
    return ret;
}

/* --------------------------- state machine Disconnected State ------------------------------ */
StaStateMachine::SeparatedState::SeparatedState(StaStateMachine *staStateMachine)
    : State("SeparatedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::SeparatedState::~SeparatedState()
{}

void StaStateMachine::SeparatedState::GoInState()
{
    if (pStaStateMachine != nullptr) {
        pStaStateMachine->SetConnectMethod(NETWORK_SELECTED_BY_UNKNOWN);
    }
    WIFI_LOGI("SeparatedState GoInState function.");
    return;
}

void StaStateMachine::SeparatedState::GoOutState()
{
    WIFI_LOGI("SeparatedState GoOutState function.");
    return;
}

bool StaStateMachine::SeparatedState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("SeparatedState-msgCode=%{public}d received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT: {
            std::string bssid;
            msg->GetMessageObj(bssid);
            if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
                WIFI_LOGE("SeparatedState inconsistent bssid in connecter");
                return false;
            }
            break;
        }

        case WIFI_SVR_CMD_STA_ENABLE_WIFI: {
            ret = EXECUTED;
            WIFI_LOGE("Wifi has already started! start Wifi failed!");
            /* Callback result to InterfaceService. */
            pStaStateMachine->InvokeOnStaOpenRes(OperateResState::OPEN_WIFI_OVERRIDE_OPEN_FAILED);
            break;
        }

        default:
            break;
    }

    return ret;
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
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
        static_cast<int>(WifiOperateState::STA_CONNECTED));
    return;
}

void StaStateMachine::ApLinkedState::GoOutState()
{
    WIFI_LOGI("ApLinkedState GoOutState function.");
    return;
}

bool StaStateMachine::ApLinkedState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGD("ApLinkedState-msgCode=%{public}d received.\n", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        /* The current state of StaStateMachine transfers to SeparatingState when
         * receive the Separating message.
         */
        case WIFI_SVR_CMD_STA_DISCONNECT: {
            ret = EXECUTED;
            pStaStateMachine->DisConnectProcess();
            break;
        }
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            ret = EXECUTED;
            std::string bssid = msg->GetStringFromMessage();
            if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
                WIFI_LOGE("ApLinkedState inconsistent bssid in connecter");
                return false;
            }
            pStaStateMachine->StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
            WIFI_LOGI("Stop clearing wpa block list");
            /* Save linkedinfo */
            pStaStateMachine->linkedInfo.networkId = pStaStateMachine->targetNetworkId;
            pStaStateMachine->linkedInfo.bssid = bssid;
            WifiSettings::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->GetInstanceId());

            break;
        }
        case WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT: {
            ret = EXECUTED;
            std::string reason = msg->GetStringFromMessage();
            std::string bssid = msg->GetStringFromMessage();
            WIFI_LOGI("ApLinkedState reveived bssid changed event, reason:%{public}s,bssid:%{public}s.\n",
                reason.c_str(), MacAnonymize(bssid).c_str());
            if (strcmp(reason.c_str(), "ASSOC_COMPLETE") != 0) {
                WIFI_LOGE("Bssid change not for ASSOC_COMPLETE, do nothing.");
                return false;
            }
            pStaStateMachine->linkedInfo.bssid = bssid;
            WifiSettings::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->m_instId);
            /* BSSID change is not received during roaming, only set BSSID */
            if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid) != WIFI_IDL_OPT_OK) {
                WIFI_LOGE("SetBssid return fail.");
                return false;
            }
            break;
        }
        default:
            break;
    }
    return ret;
}

void StaStateMachine::DisConnectProcess()
{
    WIFI_LOGI("Enter DisConnectProcess!");
    InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTING, linkedInfo);
    if (WifiStaHalInterface::GetInstance().Disconnect() == WIFI_IDL_OPT_OK) {
        WIFI_LOGI("Disconnect() succeed!");
        mPortalUrl = "";
#ifndef OHOS_ARCH_LITE
        if (NetSupplierInfo != nullptr) {
            NetSupplierInfo->isAvailable_ = false;
            WIFI_LOGI("Disconnect process update netsupplierinfo");
            WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(NetSupplierInfo);
        }
#endif
        WIFI_LOGI("Disconnect update wifi status");
        /* Save connection information to WifiSettings. */
        SaveLinkstate(ConnState::DISCONNECTED, DetailedState::DISCONNECTED);
        WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID);

        getIpSucNum = 0;
        /* The current state of StaStateMachine transfers to SeparatedState. */
        SwitchState(pSeparatedState);
    } else {
        SaveLinkstate(ConnState::DISCONNECTING, DetailedState::FAILED);
        InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECT_FAILED, linkedInfo);
        WIFI_LOGE("Disconnect() failed!");
    }
}

/* --------------------------- state machine Wps State ------------------------------ */
StaStateMachine::StaWpsState::StaWpsState(StaStateMachine *staStateMachine)
    : State("StaWpsState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::StaWpsState::~StaWpsState()
{}

void StaStateMachine::StaWpsState::GoInState()
{
    WIFI_LOGI("WpsState GoInState function.");
    return;
}

void StaStateMachine::StaWpsState::GoOutState()
{
    WIFI_LOGI("WpsState GoOutState function.");
}

bool StaStateMachine::StaWpsState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_WPS_START_EVENT: {
            /* Wps starts successfully and Wait until the connection is complete. */
            break;
        }
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            ret = EXECUTED;
            std::string bssid = msg->GetStringFromMessage();
            if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
                WIFI_LOGE("StaWpsState inconsistent bssid in connecter");
                return false;
            }
            /* Stop clearing the Wpa_blocklist. */
            pStaStateMachine->StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));

            WIFI_LOGI("WPS mode connect to a network!");
            pStaStateMachine->ConnectToNetworkProcess(bssid);
            /* Callback result to InterfaceService. */
            pStaStateMachine->SaveLinkstate(ConnState::CONNECTING, DetailedState::OBTAINING_IPADDR);
            pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP,
                pStaStateMachine->linkedInfo);
            pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
            break;
        }
        case WIFI_SVR_CMD_STA_STARTWPS: {
            ret = EXECUTED;
            auto setup = static_cast<SetupMethod>(msg->GetParam1());
            /* Callback InterfaceService that wps has started successfully. */
            WIFI_LOGE("WPS has already started, start wps failed!");
            if (setup == SetupMethod::PBC) {
                pStaStateMachine->InvokeOnWpsChanged(WpsStartState::PBC_STARTED_ALREADY,
                    pStaStateMachine->pinCode);
            } else if ((setup == SetupMethod::DISPLAY) || (setup == SetupMethod::KEYPAD)) {
                pStaStateMachine->InvokeOnWpsChanged(WpsStartState::PIN_STARTED_ALREADY,
                    pStaStateMachine->pinCode);
            }
            break;
        }
        case WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT: {
            ret = EXECUTED;
            WIFI_LOGI("Wps PBC Overlap!");
            /* Callback InterfaceService that PBC is conflicting. */
            pStaStateMachine->InvokeOnWpsChanged(WpsStartState::START_PBC_FAILED_OVERLAP,
                pStaStateMachine->pinCode);
            pStaStateMachine->SwitchState(pStaStateMachine->pSeparatedState);
            break;
        }
        case WIFI_SVR_CMD_STA_CANCELWPS: {
            ret = EXECUTED;
            pStaStateMachine->DealCancelWpsCmd(msg);
            break;
        }
        default:
            break;
    }
    return ret;
}

int StaStateMachine::RegisterCallBack()
{
    clientCallBack.OnIpSuccessChanged = DhcpResultNotify::OnSuccess;
    clientCallBack.OnIpFailChanged = DhcpResultNotify::OnFailed;
    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    DhcpErrorCode dhcpRet = RegisterDhcpClientCallBack(ifname.c_str(), &clientCallBack);
    if (dhcpRet != DHCP_SUCCESS) {
        WIFI_LOGE("RegisterDhcpClientCallBack failed. dhcpRet=%{public}d", dhcpRet);
        return DHCP_FAILED;
    }
    LOGI("RegisterDhcpClientCallBack ok");
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
    WIFI_LOGI("GetIpState GoInState function.");
#ifdef WIFI_DHCP_DISABLED
    SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    SaveLinkstate(ConnState::CONNECTED, DetailedState::WORKING);
    InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_ENABLED, linkedInfo);
    SwitchState(pLinkedState);
    return;
#endif
    pStaStateMachine->getIpSucNum = 0;
    WifiDeviceConfig config;
    AssignIpMethod assignMethod = AssignIpMethod::DHCP;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config);
    if (ret == 0) {
        assignMethod = config.wifiIpConfig.assignMethod;
    }

    pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(pStaStateMachine);
    if (assignMethod == AssignIpMethod::STATIC) {
        pStaStateMachine->currentTpType = config.wifiIpConfig.staticIpAddress.ipAddress.address.family;
        if (!pStaStateMachine->ConfigStaticIpAddress(config.wifiIpConfig.staticIpAddress)) {
            pStaStateMachine->InvokeOnStaConnChanged(
                OperateResState::CONNECT_NETWORK_DISABLED, pStaStateMachine->linkedInfo);
            pStaStateMachine->DisConnectProcess();
            LOGE("ConfigstaticIpAddress failed!\n");
        }
        return;
    }
    do {
        int result = pStaStateMachine->RegisterCallBack();
        if (result != DHCP_SUCCESS) {
            WIFI_LOGE("RegisterCallBack failed!");
            break;
        }
        int dhcpRet;
        std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
        pStaStateMachine->currentTpType = static_cast<int>(WifiSettings::GetInstance().GetDhcpIpType());

        RouterConfig config;
        if (strncpy_s(config.bssid, sizeof(config.bssid),
            pStaStateMachine->linkedInfo.bssid.c_str(), pStaStateMachine->linkedInfo.bssid.size()) == EOK) {
            SetConfiguration(ifname.c_str(), config);
        }
        if (pStaStateMachine->currentTpType == IPTYPE_IPV4) {
            dhcpRet = StartDhcpClient(ifname.c_str(), false);
        } else {
            dhcpRet = StartDhcpClient(ifname.c_str(), true);
        }
        LOGI("StartDhcpClient type:%{public}d dhcpRet:%{public}d isRoam:%{public}d", pStaStateMachine->currentTpType,
            dhcpRet, pStaStateMachine->isRoam);
        if (dhcpRet == 0) {
            LOGI("StartTimer CMD_START_GET_DHCP_IP_TIMEOUT 30s");
            pStaStateMachine->StartTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT),
                STA_SIGNAL_START_GET_DHCP_IP_DELAY);
            return;
        }
    } while (0);
    WIFI_LOGE("Dhcp connection failed, isRoam:%{public}d", pStaStateMachine->isRoam);
    pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::OBTAINING_IPADDR_FAIL);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP_FAILED,
        pStaStateMachine->linkedInfo);
    if (!pStaStateMachine->isRoam) {
        pStaStateMachine->DisConnectProcess();
    }
    return;
}

void StaStateMachine::GetIpState::GoOutState()
{
    WIFI_LOGI("GetIpState GoOutState function.");
    pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
}

bool StaStateMachine::GetIpState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_EXECUTED;
    WIFI_LOGI("GetIpState-msgCode=%{public}d received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT: {
            ret = EXECUTED;
            int result = msg->GetParam1();
            int ipType = msg->GetParam2();
            WIFI_LOGI("GetIpState, get ip result:%{public}d, ipType = %{public}d\n", result, ipType);
            switch (result) {
                case DhcpReturnCode::DHCP_RESULT: {
                    pStaStateMachine->pDhcpResultNotify->DealDhcpResult(ipType);
                    break;
                }
                case DhcpReturnCode::DHCP_JUMP: {
                    pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
                    break;
                }
                case DhcpReturnCode::DHCP_FAIL: {
                    pStaStateMachine->pDhcpResultNotify->DealDhcpResultFailed();
                    break;
                }
                default:
                    break;
            }
            break;
        }
        default:
            break;
    }

    return ret;
}

void StaStateMachine::ReplaceEmptyDns(DhcpResult *result)
{
    if (result == nullptr) {
        WIFI_LOGE("Enter ReplaceEmptyDns::result is nullptr");
        return;
    }
    std::string strDns1 = result->strOptDns1;
    std::string strDns2 = result->strOptDns2;
    if (strDns1.empty()) {
        WIFI_LOGI("Enter ReplaceEmptyDns::dns1 is null");
        if (strDns2 == FIRST_DNS) {
            if (strcpy_s(result->strOptDns1, INET_ADDRSTRLEN, SECOND_DNS) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns1 strcpy_s SECOND_DNS failed!");
            }
        } else {
            if (strcpy_s(result->strOptDns1, INET_ADDRSTRLEN, FIRST_DNS) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns1 strcpy_s FIRST_DNS failed!");
            }
        }
    }
    if (strDns2.empty()) {
        WIFI_LOGI("Enter ReplaceEmptyDns::dns2 is null");
        if (strDns1 == FIRST_DNS) {
            if (strcpy_s(result->strOptDns2, INET_ADDRSTRLEN, SECOND_DNS) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns2 strcpy_s SECOND_DNS failed!");
            }
        } else {
            if (strcpy_s(result->strOptDns2, INET_ADDRSTRLEN, FIRST_DNS) != EOK) {
                WIFI_LOGE("ReplaceEmptyDns strDns2 strcpy_s SECOND_DNS failed!");
            }
        }
    }
}

/* --- state machine GetIp State functions ----- */
bool StaStateMachine::ConfigStaticIpAddress(StaticIpAddress &staticIpAddress)
{
    WIFI_LOGI("Enter StaStateMachine::SetDhcpResultFromStatic.");
    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    DhcpResult result;
    switch (currentTpType) {
        case IPTYPE_IPV4: {
            result.iptype = IPTYPE_IPV4;
            if (strcpy_s(result.strOptClientId, INET_ADDRSTRLEN,
                staticIpAddress.ipAddress.address.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, INET_ADDRSTRLEN,
                staticIpAddress.gateway.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, INET_ADDRSTRLEN, staticIpAddress.GetIpv4Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer1.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer2.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            ReplaceEmptyDns(&result);
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            break;
        }
        case IPTYPE_IPV6: {
            result.iptype = IPTYPE_IPV6;
            if (strcpy_s(result.strOptClientId, INET_ADDRSTRLEN,
                staticIpAddress.ipAddress.address.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, INET_ADDRSTRLEN,
                staticIpAddress.gateway.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, INET_ADDRSTRLEN, staticIpAddress.GetIpv6Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer1.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer2.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            break;
        }
        case IPTYPE_MIX: {
            result.iptype = IPTYPE_IPV4;
            if (strcpy_s(result.strOptClientId, INET_ADDRSTRLEN,
                staticIpAddress.ipAddress.address.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, INET_ADDRSTRLEN,
                staticIpAddress.gateway.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, INET_ADDRSTRLEN,
                staticIpAddress.GetIpv4Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer1.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer2.GetIpv4Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns2 strcpy_s failed!");
            }
            pDhcpResultNotify->OnSuccess(1, ifname.c_str(), &result);
            if (strcpy_s(result.strOptClientId, INET_ADDRSTRLEN,
                staticIpAddress.ipAddress.address.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptClientId strcpy_s failed!");
            }
            if (strcpy_s(result.strOptRouter1, INET_ADDRSTRLEN,
                staticIpAddress.gateway.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptRouter1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptSubnet, INET_ADDRSTRLEN, staticIpAddress.GetIpv6Mask().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptSubnet strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns1, INET_ADDRSTRLEN,
                staticIpAddress.dnsServer1.GetIpv6Address().c_str()) != EOK) {
                WIFI_LOGE("ConfigStaticIpAddress strOptDns1 strcpy_s failed!");
            }
            if (strcpy_s(result.strOptDns2, INET_ADDRSTRLEN,
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
    WIFI_LOGI("portal uri is %{public}s\n", mPortalUrl.c_str());
    int netId = m_NetWorkState->GetWifiNetId();
    AAFwk::Want want;
    want.SetAction(PORTAL_ACTION);
    want.SetUri(mPortalUrl);
    want.AddEntity(PORTAL_ENTITY);
    want.SetBundle(BROWSER_BUNDLE);
    want.SetParam("netId", netId);
    WIFI_LOGI("wifi netId is %{public}d", netId);
    OHOS::ErrCode err = StaStartAbility(want);
    if (err != ERR_OK) {
        WIFI_LOGI("StartAbility is failed %{public}d", err);
        WriteBrowserFailedForPortalHiSysEvent(err, mPortalUrl);
    }
#endif
}

void StaStateMachine::SetPortalBrowserFlag(bool flag)
{
    portalFlag = flag;
}

#ifndef OHOS_ARCH_LITE
int32_t StaStateMachine::StaStartAbility(OHOS::AAFwk::Want& want)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        WIFI_LOGE("systemAbilityManager is nullptr");
        return -1;
    }
    sptr<IRemoteObject> remote = systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remote == nullptr) {
        WIFI_LOGE("remote is nullptr");
        return -1;
    }

    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    if (!data.WriteInterfaceToken(ABILITY_MGR_DESCRIPTOR)) {
        return -1;
    }
    if (!data.WriteParcelable(&want)) {
        WIFI_LOGE("want write failed.");
        return -1;
    }
 
    if (!data.WriteInt32(DEFAULT_INVAL_VALUE)) {
        WIFI_LOGE("userId write failed.");
        return -1;
    }
 
    if (!data.WriteInt32(DEFAULT_INVAL_VALUE)) {
        WIFI_LOGE("requestCode write failed.");
        return -1;
    }
    uint32_t task =  static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::START_ABILITY);
    error = remote->SendRequest(task, data, reply, option);
    if (error != NO_ERROR) {
        WIFI_LOGE("Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

void StaStateMachine::ShowPortalNitification()
{
    WifiDeviceConfig wifiDeviceConfig = getCurrentWifiDeviceConfig();
    bool hasInternetEver =
        NetworkStatusHistoryManager::HasInternetEverByHistory(wifiDeviceConfig.networkStatusHistory);
    if (hasInternetEver) {
        WifiBannerNotification::GetInstance().PublishWifiNotification(
            WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
            WifiNotificationStatus::WIFI_PORTAL_TIMEOUT);
    } else {
        if (WifiAppStateAware::GetInstance().IsForegroundApp(SETTINGS_BUNDLE)) {
            WifiBannerNotification::GetInstance().PublishWifiNotification(
                WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
                WifiNotificationStatus::WIFI_PORTAL_CONNECTED);
            portalFlag = false;
        } else {
            WifiBannerNotification::GetInstance().PublishWifiNotification(
                WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
                WifiNotificationStatus::WIFI_PORTAL_FOUND);
        }
    }
}
#endif

void StaStateMachine::NetStateObserverCallback(SystemNetWorkState netState, std::string url)
{
    SendMessage(WIFI_SVR_CMD_STA_NET_DETECTION_NOTIFY_EVENT, netState, 0, url);
}

void StaStateMachine::HandleNetCheckResult(SystemNetWorkState netState, const std::string &portalUrl)
{
    WIFI_LOGI("Enter HandleNetCheckResult, netState:%{public}d screen:%{public}d.", netState, enableSignalPoll);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGE("connState is NOT in connected state, connState:%{public}d\n", linkedInfo.connState);
        WriteIsInternetHiSysEvent(NO_NETWORK);
        return;
    }
    mPortalUrl = portalUrl;
    /* Obtains the current time, accurate to milliseconds. */
    struct timespec curTime = {0, 0};
    if (clock_gettime(CLOCK_BOOTTIME, &curTime) != 0) {
        WIFI_LOGE("HandleNetCheckResult clock_gettime failed.");
        return;
    }
    int64_t nowTime = static_cast<int64_t>(curTime.tv_sec) * PORTAL_MILLSECOND +
        curTime.tv_nsec / (PORTAL_MILLSECOND * PORTAL_MILLSECOND);

    if (netState == SystemNetWorkState::NETWORK_IS_WORKING) {
        /* Save connection information to WifiSettings. */
        WriteIsInternetHiSysEvent(NETWORK);
        WritePortalStateHiSysEvent(portalFlag ? HISYS_EVENT_PROTAL_STATE_PORTAL_VERIFIED
                                              : HISYS_EVENT_PROTAL_STATE_NOT_PORTAL);
        SaveLinkstate(ConnState::CONNECTED, DetailedState::WORKING);
        InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_ENABLED, linkedInfo);
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::HAS_INTERNET);
        if (nowTime - lastTimestamp > PORTAL_CHECK_TIME * PORTAL_MILLSECOND) {
            StartTimer(static_cast<int>(CMD_START_NETCHECK), PORTAL_CHECK_TIME * PORTAL_MILLSECOND);
            lastTimestamp = nowTime;
        }
#ifndef OHOS_ARCH_LITE
        WifiBannerNotification::GetInstance().CancelWifiNotification(
            WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID);
#endif
    } else if (netState == SystemNetWorkState::NETWORK_IS_PORTAL) {
        WifiLinkedInfo linkedInfo;
        GetLinkedInfo(linkedInfo);
#ifndef OHOS_ARCH_LITE
        if (linkedInfo.detailedState != DetailedState::CAPTIVE_PORTAL_CHECK) {
            ShowPortalNitification();
        }
#endif
        if (portalFlag == false) {
            WriteIsInternetHiSysEvent(NO_NETWORK);
            WritePortalStateHiSysEvent(HISYS_EVENT_PROTAL_STATE_PORTAL_UNVERIFIED);
            HandlePortalNetworkPorcess();
            portalFlag = true;
        }
        WriteIsInternetHiSysEvent(NETWORK);
        SaveLinkstate(ConnState::CONNECTED, DetailedState::CAPTIVE_PORTAL_CHECK);
        InvokeOnStaConnChanged(OperateResState::CONNECT_CHECK_PORTAL, linkedInfo);
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::PORTAL);
        if (nowTime - lastTimestamp > PORTAL_CHECK_TIME * PORTAL_MILLSECOND) {
            StartTimer(static_cast<int>(CMD_START_NETCHECK), PORTAL_CHECK_TIME * PORTAL_MILLSECOND);
            lastTimestamp = nowTime;
        }
    } else {
        WriteIsInternetHiSysEvent(NO_NETWORK);
        SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
        InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_DISABLED, linkedInfo);
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::NO_INTERNET);
    }
}

void StaStateMachine::HandleArpCheckResult(StaArpState arpState)
{
}

void StaStateMachine::HandleDnsCheckResult(StaDnsState dnsState)
{
}

/* --------------------------- state machine Connected State ------------------------------ */
StaStateMachine::LinkedState::LinkedState(StaStateMachine *staStateMachine)
    : State("LinkedState"), pStaStateMachine(staStateMachine)
{}

StaStateMachine::LinkedState::~LinkedState()
{}

void StaStateMachine::LinkedState::GoInState()
{
    WIFI_LOGI("LinkedState GoInState function.");
#ifndef OHOS_ARCH_LITE
    if (pStaStateMachine != nullptr && pStaStateMachine->m_NetWorkState != nullptr) {
        pStaStateMachine->m_NetWorkState->StartNetStateObserver(pStaStateMachine->m_NetWorkState);
        pStaStateMachine->lastTimestamp = 0;
    }
#endif
    return;
}

void StaStateMachine::LinkedState::GoOutState()
{
    WIFI_LOGI("LinkedState GoOutState function.");
}

bool StaStateMachine::LinkedState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGI("msg is nullptr.");
        return false;
    }

    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT: {
            ret = EXECUTED;
            std::string reason = msg->GetStringFromMessage();
            std::string bssid = msg->GetStringFromMessage();
            WIFI_LOGI("reveived bssid changed event, reason:%{public}s,bssid:%{public}s.\n",
                reason.c_str(), MacAnonymize(bssid).c_str());
            if (strcmp(reason.c_str(), "ASSOC_COMPLETE") != 0) {
                WIFI_LOGE("Bssid change not for ASSOC_COMPLETE, do nothing.");
                return false;
            }
            if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid) != WIFI_IDL_OPT_OK) {
                WIFI_LOGE("SetBssid return fail.");
                return false;
            }
            pStaStateMachine->isRoam = true;
            /* The current state of StaStateMachine transfers to pApRoamingState. */
            pStaStateMachine->SwitchState(pStaStateMachine->pApRoamingState);
            break;
        }
        case WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT: {
            ret = EXECUTED;
            int result = msg->GetParam1();
            int ipType = msg->GetParam2();
            WIFI_LOGI("LinkedState, result:%{public}d, ipType = %{public}d\n", result, ipType);
            if (result == DhcpReturnCode::DHCP_RENEW_FAIL) {
                pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
            } else if (result == DhcpReturnCode::DHCP_RESULT) {
                pStaStateMachine->pDhcpResultNotify->DealDhcpResult(ipType);
            }
            break;
        }
        case WIFI_SVR_CMD_STA_NET_DETECTION_NOTIFY_EVENT: {
            ret = EXECUTED;
            SystemNetWorkState netstate = (SystemNetWorkState)msg->GetParam1();
            std::string url;
            if (!msg->GetMessageObj(url)) {
                WIFI_LOGW("Failed to obtain portal url.");
            }
            WIFI_LOGI("netdetection, netstate:%{public}d url:%{public}s\n", netstate, url.c_str());
            pStaStateMachine->HandleNetCheckResult(netstate, url);
            break;
        }
        default:
            WIFI_LOGD("NOT handle this event!");
            break;
    }

    return ret;
}

void StaStateMachine::DealApRoamingStateTimeout(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("DealApRoamingStateTimeout InternalMessage msg is null.");
        return;
    }
    LOGI("DealApRoamingStateTimeout StopTimer aproaming timer");
    StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
    DisConnectProcess();
}

void StaStateMachine::DealHiLinkDataToWpa(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("DealHiLinkDataToWpa InternalMessage msg is null.");
        return;
    }
    WIFI_LOGI("DealHiLinkDataToWpa=%{public}d received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case WIFI_SVR_COM_STA_ENABLE_HILINK: {
            int networkId = msg->GetParam1();
            if (networkId != INVALID_NETWORK_ID) {
                targetNetworkId = networkId;
            }
            std::string cmd;
            msg->GetMessageObj(cmd);
            LOGI("DealEnableHiLinkHandshake start shell cmd = %{public}s networkId = %{public}d",
                MacAnonymize(cmd).c_str(), networkId);
            WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd);
            break;
        }
        case WIFI_SVR_COM_STA_HILINK_DELIVER_MAC: {
            std::string mac;
            msg->GetMessageObj(mac);
            LOGI("DealHiLinkMacDeliver start shell cmd, mac = %{public}s", MacAnonymize(mac).c_str());
            WifiStaHalInterface::GetInstance().ShellCmd("wlan0", mac);
            break;
        }
        case WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS: {
            LOGI("DealHiLinkTriggerWps start ClearDeviceConfig");
            WifiStaHalInterface::GetInstance().ClearDeviceConfig();

            LOGI("DealHiLinkTriggerWps SPECIAL_CONNECTED");
            InvokeOnStaConnChanged(OperateResState::SPECIAL_CONNECTED, linkedInfo);

            LOGI("DealHiLinkTriggerWps start startWpsPbc");
            std::string bssid;
            msg->GetMessageObj(bssid);
            WifiIdlWpsConfig config;
            config.anyFlag = 0;
            config.multiAp = 0;
            config.bssid = bssid;
            WifiStaHalInterface::GetInstance().StartWpsPbcMode(config);
            g_isHilinkFlag = true;
            break;
        }
        default:
            return;
    }
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
    pStaStateMachine->StartTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK), STA_AP_ROAMING_TIMEOUT);
}

void StaStateMachine::ApRoamingState::GoOutState()
{
    WIFI_LOGI("ApRoamingState GoOutState function. stop aproaming timer!");
    pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
}

bool StaStateMachine::ApRoamingState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("ApRoamingState, reveived msgCode=%{public}d msg.", msg->GetMessageName());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            WIFI_LOGI("ApRoamingState, receive WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT event.");
            ret = EXECUTED;
            std::string bssid = msg->GetStringFromMessage();
            if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
                WIFI_LOGE("ApRoamingState inconsistent bssid in connecter");
                return false;
            }
            pStaStateMachine->isRoam = true;
            pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
            pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
            pStaStateMachine->ConnectToNetworkProcess(bssid);
            /* Notify result to InterfaceService. */
            pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATED,
                pStaStateMachine->linkedInfo);
            if (!pStaStateMachine->CanArpReachable()) {
                WIFI_LOGI("Arp is not reachable");
                pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP,
                    pStaStateMachine->linkedInfo);
                /* The current state of StaStateMachine transfers to GetIpState. */
                pStaStateMachine->SwitchState(pStaStateMachine->pGetIpState);
            } else {
                WIFI_LOGI("Arp is reachable");
                pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
                pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED,
                    pStaStateMachine->linkedInfo);
                pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
            }
            break;
        }
        case WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT: {
            WIFI_LOGI("ApRoamingState, receive WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT event.");
            std::string bssid;
            msg->GetMessageObj(bssid);
            if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
                WIFI_LOGE("ApRoamingState inconsistent bssid in connecter");
                return false;
            }
            pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
            pStaStateMachine->DisConnectProcess();
            break;
        }
        default:
            WIFI_LOGI("ApRoamingState-msgCode=%d not handled.", msg->GetMessageName());
            break;
    }

    return ret;
}

bool StaStateMachine::CanArpReachable()
{
    ArpChecker arpChecker;
    std::string macAddress;
    WifiSettings::GetInstance().GetMacAddress(macAddress, m_instId);
    IpInfo ipInfo;
    WifiSettings::GetInstance().GetIpInfo(ipInfo, m_instId);
    std::string ipAddress = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ifName = WifiSettings::GetInstance().GetStaIfaceName();
    if (ipInfo.gateway == 0) {
        WIFI_LOGI("gateway is empty");
        return false;
    }
    uint64_t arpRtt = 0;
    std::string gateway = IpTools::ConvertIpv4Address(ipInfo.gateway);
    arpChecker.Start(ifName, macAddress, ipAddress, gateway);
    for (int i = 0; i < DEFAULT_NUM_ARP_PINGS; i++) {
        if (arpChecker.DoArpCheck(MAX_ARP_CHECK_TIME, true, arpRtt)) {
            WriteArpInfoHiSysEvent(arpRtt, 0);
            return true;
        }
    }
    WriteArpInfoHiSysEvent(arpRtt, 1);
    return false;
}

ErrCode StaStateMachine::ConfigRandMacSelfCure(const int networkId)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        LOGE("GetDeviceConfig failed!");
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

void StaStateMachine::ConnectToNetworkProcess(std::string bssid)
{
    WIFI_LOGI("ConnectToNetworkProcess, Receive bssid=%{public}s", MacAnonymize(bssid).c_str());
    if ((wpsState == SetupMethod::DISPLAY) || (wpsState == SetupMethod::PBC) || (wpsState == SetupMethod::KEYPAD)) {
        targetNetworkId = WPA_DEFAULT_NETWORKID;
    }
    WifiDeviceConfig deviceConfig;
    int result = WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, deviceConfig);
    WIFI_LOGD("Device config networkId = %{public}d", deviceConfig.networkId);

    if (result == 0 && deviceConfig.bssid == bssid) {
        LOGI("Device Configuration already exists.");
    } else {
        deviceConfig.bssid = bssid;
        if ((wpsState == SetupMethod::DISPLAY) || (wpsState == SetupMethod::PBC) || (wpsState == SetupMethod::KEYPAD)) {
            /* Save connection information. */
            WifiIdlGetDeviceConfig config;
            config.networkId = WPA_DEFAULT_NETWORKID;
            config.param = "ssid";
            if (WifiStaHalInterface::GetInstance().GetDeviceConfig(config) != WIFI_IDL_OPT_OK) {
                LOGE("GetDeviceConfig failed!");
            }

            deviceConfig.networkId = WPA_DEFAULT_NETWORKID;
            deviceConfig.bssid = bssid;
            deviceConfig.ssid = config.value;
            /* Remove the double quotation marks at the head and tail. */
            deviceConfig.ssid.erase(0, 1);
            deviceConfig.ssid.erase(deviceConfig.ssid.length() - 1, 1);
            WifiSettings::GetInstance().AddWpsDeviceConfig(deviceConfig);
            isWpsConnect = IsWpsConnected::WPS_CONNECTED;
        } else {
            WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        }
        WifiSettings::GetInstance().SyncDeviceConfig();
        WIFI_LOGD("Device ssid = %s", SsidAnonymize(deviceConfig.ssid).c_str());
    }

    std::string macAddr;
    std::string realMacAddr;
    WifiSettings::GetInstance().GetMacAddress(macAddr, m_instId);
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddr, m_instId);
    linkedInfo.networkId = targetNetworkId;
    linkedInfo.bssid = bssid;
    linkedInfo.ssid = deviceConfig.ssid;
    linkedInfo.macType = (macAddr == realMacAddr ?
        static_cast<int>(WifiPrivacyConfig::DEVICEMAC) : static_cast<int>(WifiPrivacyConfig::RANDOMMAC));
    linkedInfo.macAddress = macAddr;
    linkedInfo.ifHiddenSSID = deviceConfig.hiddenSSID;
    lastLinkedInfo.bssid = bssid;
    lastLinkedInfo.macType = static_cast<int>(deviceConfig.wifiPrivacySetting);
    lastLinkedInfo.macAddress = deviceConfig.macAddress;
    lastLinkedInfo.ifHiddenSSID = deviceConfig.hiddenSSID;
    SetWifiLinkedInfo(targetNetworkId);
    SaveLinkstate(ConnState::CONNECTING, DetailedState::OBTAINING_IPADDR);
}

void StaStateMachine::SetWifiLinkedInfo(int networkId)
{
    WIFI_LOGI("SetWifiLinkedInfo, linkedInfo.networkId=%{public}d, lastLinkedInfo.networkId=%{public}d",
        linkedInfo.networkId, lastLinkedInfo.networkId);
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        if (lastLinkedInfo.networkId != INVALID_NETWORK_ID) {
            /* Update connection information according to the last connecting information. */
            linkedInfo.retryedConnCount = 0;
            linkedInfo.networkId = lastLinkedInfo.networkId;
            linkedInfo.ssid = lastLinkedInfo.ssid;
            linkedInfo.bssid = lastLinkedInfo.bssid;
            linkedInfo.macAddress = lastLinkedInfo.macAddress;
            linkedInfo.rssi = lastLinkedInfo.rssi;
            linkedInfo.band = lastLinkedInfo.band;
            linkedInfo.frequency = lastLinkedInfo.frequency;
            linkedInfo.linkSpeed = lastLinkedInfo.linkSpeed;
            linkedInfo.ipAddress = lastLinkedInfo.ipAddress;
            linkedInfo.connState = lastLinkedInfo.connState;
            linkedInfo.ifHiddenSSID = lastLinkedInfo.ifHiddenSSID;
            linkedInfo.rxLinkSpeed = lastLinkedInfo.rxLinkSpeed;
            linkedInfo.txLinkSpeed = lastLinkedInfo.txLinkSpeed;
            linkedInfo.chload = lastLinkedInfo.chload;
            linkedInfo.snr = lastLinkedInfo.snr;
            linkedInfo.isDataRestricted = lastLinkedInfo.isDataRestricted;
            linkedInfo.platformType = lastLinkedInfo.platformType;
            linkedInfo.portalUrl = lastLinkedInfo.portalUrl;
            linkedInfo.detailedState = lastLinkedInfo.detailedState;
            linkedInfo.isAncoConnected = lastLinkedInfo.isAncoConnected;
        } else if (networkId != INVALID_NETWORK_ID) {
            linkedInfo.retryedConnCount = 0;
            linkedInfo.networkId = networkId;
            WifiDeviceConfig config;
            int ret = WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
            if (ret == 0) {
                /* Update connection information according to configuration. */
                linkedInfo.networkId = config.networkId;
                linkedInfo.ssid = config.ssid;
                linkedInfo.bssid = config.bssid;
                linkedInfo.band = config.band;
                linkedInfo.connState = ConnState::CONNECTING;
                linkedInfo.ifHiddenSSID = config.hiddenSSID;
                linkedInfo.detailedState = DetailedState::OBTAINING_IPADDR;

                lastLinkedInfo.networkId = config.networkId;
                lastLinkedInfo.ssid = config.ssid;
                lastLinkedInfo.bssid = config.bssid;
                lastLinkedInfo.band = config.band;
                lastLinkedInfo.connState = ConnState::CONNECTING;
                lastLinkedInfo.ifHiddenSSID = config.hiddenSSID;
                lastLinkedInfo.detailedState = DetailedState::OBTAINING_IPADDR;
            }
        }
        WriteWifiBandHiSysEvent(linkedInfo.band);
    }
}

void StaStateMachine::DealNetworkCheck(InternalMessage *msg)
{
    LOGD("enter DealNetworkCheck.\n");
    if (msg == nullptr) {
        LOGE("InternalMessage msg is null.");
        return;
    }
#ifndef OHOS_ARCH_LITE
    m_NetWorkState->StartWifiDetection();
#endif
}

void StaStateMachine::DealGetDhcpIpTimeout(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("DealGetDhcpIpTimeout InternalMessage msg is null.");
        return;
    }
    LOGI("StopTimer CMD_START_GET_DHCP_IP_TIMEOUT DealGetDhcpIpTimeout");
    StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    DisConnectProcess();
}

void StaStateMachine::DealScreenStateChangedEvent(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealScreenStateChangedEvent InternalMessage msg is null.");
        return;
    }

    int screenState = msg->GetParam1();
    WIFI_LOGI("DealScreenStateChangedEvent, Receive msg: screenState=%{public}d", screenState);
    if (screenState == MODE_STATE_OPEN) {
        enableSignalPoll = true;
        StartTimer(static_cast<int>(CMD_SIGNAL_POLL), 0);
    }

    if (screenState == MODE_STATE_CLOSE) {
        enableSignalPoll = false;
        StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
    }
#ifndef OHOS_ARCH_LITE
    WifiProtectManager::GetInstance().HandleScreenStateChanged(screenState == MODE_STATE_OPEN);
#endif
    if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE)
        != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("WpaSetSuspendMode failed!");
    }
    return;
}

void StaStateMachine::DhcpResultNotify::SaveDhcpResult(DhcpResult *dest, DhcpResult *source)
{
    if (dest == nullptr || source == nullptr) {
        LOGE("SaveDhcpResult dest or source is nullptr.");
        return;
    }

    dest->iptype = source->iptype;
    dest->isOptSuc = source->isOptSuc;
    dest->uOptLeasetime = source->uOptLeasetime;
    dest->uAddTime = source->uAddTime;
    dest->uGetTime = source->uGetTime;
    if (strcpy_s(dest->strOptClientId, DHCP_MAX_FILE_BYTES, source->strOptClientId) != EOK) {
        LOGE("SaveDhcpResult strOptClientId strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptServerId, DHCP_MAX_FILE_BYTES, source->strOptServerId) != EOK) {
        LOGE("SaveDhcpResult strOptServerId strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptSubnet, DHCP_MAX_FILE_BYTES, source->strOptSubnet) != EOK) {
        LOGE("SaveDhcpResult strOptSubnet strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptDns1, DHCP_MAX_FILE_BYTES, source->strOptDns1) != EOK) {
        LOGE("SaveDhcpResult strOptDns1 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptDns2, DHCP_MAX_FILE_BYTES, source->strOptDns2) != EOK) {
        LOGE("SaveDhcpResult strOptDns2 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptRouter1, DHCP_MAX_FILE_BYTES, source->strOptRouter1) != EOK) {
        LOGE("SaveDhcpResult strOptRouter1 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptRouter2, DHCP_MAX_FILE_BYTES, source->strOptRouter2) != EOK) {
        LOGE("SaveDhcpResult strOptRouter2 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptVendor, DHCP_MAX_FILE_BYTES, source->strOptVendor) != EOK) {
        LOGE("SaveDhcpResult strOptVendor strcpy_s failed!");
        return;
    }
    LOGI("SaveDhcpResult ok, ipType:%{public}d", dest->iptype);
    StaStateMachine::DhcpResultNotify::SaveDhcpResultExt(dest, source);
}

void StaStateMachine::DhcpResultNotify::SaveDhcpResultExt(DhcpResult *dest, DhcpResult *source)
{
    if (dest == nullptr || source == nullptr) {
        LOGE("SaveDhcpResultExt dest or source is nullptr.");
        return;
    }
    if (strcpy_s(dest->strOptLinkIpv6Addr, DHCP_MAX_FILE_BYTES, source->strOptLinkIpv6Addr) != EOK) {
        LOGE("SaveDhcpResultExt strOptLinkIpv6Addr strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptRandIpv6Addr, DHCP_MAX_FILE_BYTES, source->strOptRandIpv6Addr) != EOK) {
        LOGE("SaveDhcpResultExt strOptRandIpv6Addr strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptLocalAddr1, DHCP_MAX_FILE_BYTES, source->strOptLocalAddr1) != EOK) {
        LOGE("SaveDhcpResultExt strOptLocalAddr1 strcpy_s failed!");
        return;
    }
    if (strcpy_s(dest->strOptLocalAddr2, DHCP_MAX_FILE_BYTES, source->strOptLocalAddr2) != EOK) {
        LOGE("SaveDhcpResultExt strOptLocalAddr2 strcpy_s failed!");
        return;
    }
    if (source->dnsList.dnsNumber > 0) {
        dest->dnsList.dnsNumber = 0;
        for (uint32_t i = 0; i < source->dnsList.dnsNumber; i++) {
            if (memcpy_s(dest->dnsList.dnsAddr[i], DHCP_LEASE_DATA_MAX_LEN, source->dnsList.dnsAddr[i],
                DHCP_LEASE_DATA_MAX_LEN -1) != EOK) {
                LOGE("SaveDhcpResultExt memcpy_s failed! i:%{public}d", i);
            } else {
                dest->dnsList.dnsNumber++;
            }
        }
        LOGI("SaveDhcpResultExt destDnsNumber:%{public}d sourceDnsNumber:%{public}d", dest->dnsList.dnsNumber,
            source->dnsList.dnsNumber);
    }
    LOGI("SaveDhcpResultExt ok, ipType:%{public}d", dest->iptype);
}

/* ------------------ state machine dhcp callback function ----------------- */
StaStateMachine* StaStateMachine::DhcpResultNotify::pStaStateMachine = nullptr;
DhcpResult StaStateMachine::DhcpResultNotify::DhcpIpv4Result;
DhcpResult StaStateMachine::DhcpResultNotify::DhcpIpv6Result;
#ifndef OHOS_ARCH_LITE
uint64_t StaStateMachine::DhcpResultNotify::renewTimerId_;
#endif
StaStateMachine::DhcpResultNotify::DhcpResultNotify()
{
}

StaStateMachine::DhcpResultNotify::~DhcpResultNotify()
{
}

void StaStateMachine::DhcpResultNotify::SetStaStateMachine(StaStateMachine *staStateMachine)
{
    StaStateMachine::DhcpResultNotify::pStaStateMachine = staStateMachine;
}

void StaStateMachine::DhcpResultNotify::OnSuccess(int status, const char *ifname, DhcpResult *result)
{
    if (ifname == nullptr || result == nullptr || pStaStateMachine == nullptr) {
        LOGE("StaStateMachine DhcpResultNotify OnSuccess ifname or result is nullptr.");
        return;
    }
    LOGI("Enter Sta DhcpResultNotify OnSuccess. ifname=[%{public}s] status=[%{public}d]", ifname, status);
    LOGI("iptype=%{public}d, isOptSuc=%{public}d, clientip =%{private}s, serverip=%{private}s, subnet=%{private}s",
        result->iptype, result->isOptSuc, result->strOptClientId,  result->strOptServerId, result->strOptSubnet);
    LOGI("gateway1=%{private}s, gateway2=%{private}s, strDns1=%{private}s, strDns2=%{private}s, strVendor=%{public}s, \
        uOptLeasetime=%{public}d, uAddTime=%{public}d, uGetTime=%{public}d, currentTpType=%{public}d",
        result->strOptRouter1, result->strOptRouter2, result->strOptDns1, result->strOptDns2, result->strOptVendor,
        result->uOptLeasetime, result->uAddTime, result->uGetTime, pStaStateMachine->currentTpType);

    WriteWifiConnectFailedEventHiSysEvent(static_cast<int>(WifiOperateState::STA_DHCP_SUCCESS));
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_DHCP),
        static_cast<int>(WifiOperateState::STA_DHCP_SUCCESS));
    if (result->iptype == 0) { /* 0-ipv4,1-ipv6 */
        LOGI("StopTimer CMD_START_GET_DHCP_IP_TIMEOUT OnSuccess");
        pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
        StaStateMachine::DhcpResultNotify::SaveDhcpResult(&(StaStateMachine::DhcpResultNotify::DhcpIpv4Result), result);
    } else {
        StaStateMachine::DhcpResultNotify::SaveDhcpResult(&(StaStateMachine::DhcpResultNotify::DhcpIpv6Result), result);
    }
    pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_RESULT, result->iptype);
}

#ifndef OHOS_ARCH_LITE

void StaStateMachine::DhcpResultNotify::DealRenewTimeout(void)
{
    WIFI_LOGI("DealRenewTimeout start");
    StaStateMachine::DhcpResultNotify::StopRenewTimeout();
    pStaStateMachine->SendMessage(CMD_START_RENEWAL_TIMEOUT);

    return;
}

static void RenewTimeOutCallback(void)
{
    WIFI_LOGI("RenewTimeOutCallback start");
    StaStateMachine::DhcpResultNotify::DealRenewTimeout();

    return;
}

void StaStateMachine::DhcpResultNotify::StartRenewTimeout(int64_t interval)
{
    WIFI_LOGE("DhcpResultNotify::StartRenewTimeout.");
    StaStateMachine::DhcpResultNotify::StopRenewTimeout();
    std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, false, false);
    wifiSysTimer->SetCallbackInfo(RenewTimeOutCallback);
    renewTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
    int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    MiscServices::TimeServiceClient::GetInstance()->StartTimer(renewTimerId_, currentTime + interval);

    return;
}
#endif

void StaStateMachine::DhcpResultNotify::DealDhcpResult(int ipType)
{
    DhcpResult *result = nullptr;
    IpInfo ipInfo;
    IpV6Info ipv6Info;
    WifiSettings::GetInstance().GetIpInfo(ipInfo, pStaStateMachine->GetInstanceId());
    WifiSettings::GetInstance().GetIpv6Info(ipv6Info, pStaStateMachine->GetInstanceId());
    if (ipType == 0) { /* 0-ipv4,1-ipv6 */
        result = &(StaStateMachine::DhcpResultNotify::DhcpIpv4Result);
        TryToSaveIpV4Result(ipInfo, ipv6Info, result);
    } else {
        result = &(StaStateMachine::DhcpResultNotify::DhcpIpv6Result);
        TryToSaveIpV6Result(ipInfo, ipv6Info, result);
    }
    TryToCloseDhcpClient(result->iptype);

    WifiDeviceConfig config;
    AssignIpMethod assignMethod = AssignIpMethod::DHCP;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config);
    if (ret == 0) {
        assignMethod = config.wifiIpConfig.assignMethod;
    }
    LOGI("DhcpResultNotify OnSuccess, uLeaseTime=%{public}d %{public}d %{public}d", result->uOptLeasetime, assignMethod,
        pStaStateMachine->currentTpType);
    if ((assignMethod == AssignIpMethod::DHCP) && (result->uOptLeasetime > 0) &&
        (pStaStateMachine->currentTpType != IPTYPE_IPV6)) {
        if (result->uOptLeasetime < STA_RENEWAL_MIN_TIME) {
            result->uOptLeasetime = STA_RENEWAL_MIN_TIME;
        }
        int64_t interval = result->uOptLeasetime / 2 * TIME_USEC_1000; // s->ms
        LOGI("StartTimer CMD_START_RENEWAL_TIMEOUT uOptLeasetime=%{public}d", result->uOptLeasetime);
#ifndef OHOS_ARCH_LITE
        StartRenewTimeout(interval);
#else
        pStaStateMachine->StartTimer(static_cast<int>(CMD_START_RENEWAL_TIMEOUT), interval);
#endif
    }

    if (WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(true) != WIFI_IDL_OPT_OK) {
        LOGE("DhcpResultNotify OnSuccess WpaSetPowerMode() failed!");
    }
    return;
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV4ResultExt(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        LOGE("TryToSaveIpV4ResultExt result nullptr.");
        return;
    }
    ipInfo.ipAddress = IpTools::ConvertIpv4Address(result->strOptClientId);
    ipInfo.gateway = IpTools::ConvertIpv4Address(result->strOptRouter1);
    ipInfo.netmask = IpTools::ConvertIpv4Address(result->strOptSubnet);
    ipInfo.primaryDns = IpTools::ConvertIpv4Address(result->strOptDns1);
    ipInfo.secondDns = IpTools::ConvertIpv4Address(result->strOptDns2);
    ipInfo.serverIp = IpTools::ConvertIpv4Address(result->strOptServerId);
    ipInfo.leaseDuration = result->uOptLeasetime;
    if (result->dnsList.dnsNumber > 0) {
        ipInfo.dnsAddr.clear();
        for (uint32_t i = 0; i < result->dnsList.dnsNumber; i++) {
            unsigned int ipv4Address = IpTools::ConvertIpv4Address(result->dnsList.dnsAddr[i]);
            ipInfo.dnsAddr.push_back(ipv4Address);
        }
    }
    WifiSettings::GetInstance().SaveIpInfo(ipInfo);
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV4Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        LOGE("TryToSaveIpV4Result resultis nullptr.");
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
            pStaStateMachine->linkedInfo.isDataRestricted = 
                (strVendor.find("ANDROID_METERED") == std::string::npos && 
                strVendor.find("OPEN_HARMONY") == std::string::npos) ? 0 : 1;
            if (!pStaStateMachine->linkedInfo.isDataRestricted) {
                pStaStateMachine->linkedInfo.isDataRestricted =
                    (strVendor.find("hostname:") != std::string::npos &&
                    ipAddress.find("172.20.10.") != std::string::npos);
            }
            pStaStateMachine->linkedInfo.platformType = strVendor;
            WIFI_LOGI("WifiLinkedInfo.isDataRestricted = %{public}d, WifiLinkedInfo.platformType = %{public}s",
                pStaStateMachine->linkedInfo.isDataRestricted, pStaStateMachine->linkedInfo.platformType.c_str());
            WifiSettings::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo);
#ifndef OHOS_ARCH_LITE
            LOGI("TryToSaveIpV4Result Update NetLink info, strYourCli=%{private}s, strSubnet=%{private}s, \
                strRouter1=%{private}s, strDns1=%{private}s, strDns2=%{private}s",
                IpAnonymize(result->strOptClientId).c_str(), IpAnonymize(result->strOptSubnet).c_str(),
                IpAnonymize(result->strOptRouter1).c_str(), IpAnonymize(result->strOptDns1).c_str(),
                IpAnonymize(result->strOptDns2).c_str());
            WIFI_LOGI("On dhcp success update net linke info");
            WifiDeviceConfig config;
            WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config);
            WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(ipInfo, ipv6Info, config.wifiProxyconfig,
                pStaStateMachine->GetInstanceId());
#endif
        }
#ifdef OHOS_ARCH_LITE
        IfConfig::GetInstance().SetIfDnsAndRoute(result, result->iptype, pStaStateMachine->GetInstanceId());
#endif
    } else {
        LOGI("TryToSaveIpV4Result not UpdateNetLinkInfo");
    }
}

void StaStateMachine::DhcpResultNotify::TryToSaveIpV6Result(IpInfo &ipInfo, IpV6Info &ipv6Info, DhcpResult *result)
{
    if (result == nullptr) {
        LOGE("TryToSaveIpV6Result resultis nullptr.");
        return;
    }
    
    if ((ipv6Info.globalIpV6Address != result->strOptClientId) ||
        (ipv6Info.randGlobalIpV6Address != result->strOptRandIpv6Addr) ||
        (ipv6Info.uniqueLocalAddress1 != result->strOptLocalAddr1) ||
        (ipv6Info.uniqueLocalAddress2 != result->strOptLocalAddr2) ||
        (ipv6Info.gateway != result->strOptRouter1)) {
        ipv6Info.linkIpV6Address = result->strOptLinkIpv6Addr;
        ipv6Info.globalIpV6Address = result->strOptClientId;
        ipv6Info.randGlobalIpV6Address = result->strOptRandIpv6Addr;
        ipv6Info.gateway = result->strOptRouter1;
        ipv6Info.netmask = result->strOptSubnet;
        ipv6Info.primaryDns = result->strOptDns1;
        ipv6Info.secondDns = result->strOptDns2;
        ipv6Info.uniqueLocalAddress1 = result->strOptLocalAddr1;
        ipv6Info.uniqueLocalAddress2 = result->strOptLocalAddr2;
        if (result->dnsList.dnsNumber > 0) {
            ipv6Info.dnsAddr.clear();
            for (uint32_t i = 0; i < result->dnsList.dnsNumber; i++) {
                ipv6Info.dnsAddr.push_back(result->dnsList.dnsAddr[i]);
            }
            LOGI("TryToSaveIpV6Result ipv6Info dnsAddr size:%{public}zu", ipv6Info.dnsAddr.size());
        }
        WifiSettings::GetInstance().SaveIpV6Info(ipv6Info, pStaStateMachine->GetInstanceId());
        WIFI_LOGI("SaveIpV6 addr=%{private}s, linkaddr=%{private}s, randaddr=%{private}s, gateway=%{private}s, "
            "mask=%{private}s, dns=%{private}s, dns2=%{private}s",
            ipv6Info.globalIpV6Address.c_str(), ipv6Info.linkIpV6Address.c_str(),
            ipv6Info.randGlobalIpV6Address.c_str(), ipv6Info.gateway.c_str(), ipv6Info.netmask.c_str(),
            ipv6Info.primaryDns.c_str(), ipv6Info.secondDns.c_str());
#ifndef OHOS_ARCH_LITE
        WifiDeviceConfig config;
        WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config);
        WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(ipInfo, ipv6Info, config.wifiProxyconfig,
            pStaStateMachine->GetInstanceId());
#endif
    } else {
        LOGI("TryToSaveIpV6Result not UpdateNetLinkInfo");
    }
}

void StaStateMachine::DhcpResultNotify::TryToCloseDhcpClient(int iptype)
{
    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    if (iptype == 1) {
        LOGI("TryToCloseDhcpClient iptype ipv6 return");
        return;
    }

    WIFI_LOGI("TryToCloseDhcpClient, getIpSucNum=%{public}d, isRoam=%{public}d",
        pStaStateMachine->getIpSucNum, pStaStateMachine->isRoam);
    pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_JUMP);
    if (pStaStateMachine->getIpSucNum == 0 || pStaStateMachine->isRoam) {
        pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
        pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
        pStaStateMachine->InvokeOnStaConnChanged(
            OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
        /* Delay to wait for the network adapter information to take effect. */
        pStaStateMachine->StartTimer(static_cast<int>(CMD_START_NETCHECK), 0);
        pStaStateMachine->DealSetStaConnectFailedCount(0, true);
    }
    pStaStateMachine->getIpSucNum++;
    LOGI("TryToCloseDhcpClient, getIpSucNum=%{public}d", pStaStateMachine->getIpSucNum);
}

void StaStateMachine::DhcpResultNotify::OnFailed(int status, const char *ifname, const char *reason)
{
    // for dhcp: 4-DHCP_OPT_RENEW_FAILED  5-DHCP_OPT_RENEW_TIMEOUT
    if ((status == DHCP_RENEW_FAILED) || (status == DHCP_RENEW_TIMEOUT)) {
        LOGI("DhcpResultNotify::OnFailed, ifname[%{public}s], status[%{public}d], reason[%{public}s]", ifname, status,
            reason);
        pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_RENEW_FAIL);
        return;
    }
    LOGI("Enter DhcpResultNotify::OnFailed. ifname=%{public}s, status=%{public}d, reason=%{public}s, state=%{public}d",
        ifname, status, reason, static_cast<int>(pStaStateMachine->linkedInfo.detailedState));
    WriteWifiConnectFailedEventHiSysEvent(static_cast<int>(WifiOperateState::STA_DHCP_FAIL));
    pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_FAIL);
}

void StaStateMachine::DhcpResultNotify::DealDhcpResultFailed()
{
    pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));

    LOGI("DhcpResultNotify OnFailed type: %{public}d, sucNum: %{public}d, failNum: %{public}d, isRoam: %{public}d",
        pStaStateMachine->currentTpType, pStaStateMachine->getIpSucNum,
        pStaStateMachine->getIpFailNum, pStaStateMachine->isRoam);

    if (pStaStateMachine->getIpFailNum == 0) {
        pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP_FAILED,
            pStaStateMachine->linkedInfo);
        pStaStateMachine->DisConnectProcess();
        pStaStateMachine->SaveLinkstate(ConnState::DISCONNECTED, DetailedState::OBTAINING_IPADDR_FAIL);
        pStaStateMachine->InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED,
            pStaStateMachine->linkedInfo);
    }
    pStaStateMachine->getIpFailNum++;
}


/* ------------------ state machine Comment function ----------------- */
void StaStateMachine::SaveDiscReason(DisconnectedReason discReason)
{
    WifiSettings::GetInstance().SaveDisconnectedReason(discReason, m_instId);
}

void StaStateMachine::SaveLinkstate(ConnState state, DetailedState detailState)
{
    linkedInfo.connState = state;
    linkedInfo.detailedState = detailState;
    lastLinkedInfo.connState = state;
    lastLinkedInfo.detailedState = detailState;
    linkedInfo.isAncoConnected = WifiConfigCenter::GetInstance().GetWifiConnectedMode(m_instId);
    lastLinkedInfo.isAncoConnected = linkedInfo.isAncoConnected;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
}

int StaStateMachine::GetLinkedInfo(WifiLinkedInfo& linkedInfo)
{
    return WifiSettings::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
}

void StaStateMachine::SetOperationalMode(int mode)
{
    SendMessage(WIFI_SVR_CMD_STA_OPERATIONAL_MODE, mode, 0);
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::OnNetManagerRestart(void)
{
    LOGI("OnNetManagerRestart()");
    int state = WifiSettings::GetInstance().GetWifiState(m_instId);
    if (state != static_cast<int>(WifiState::ENABLED)) {
        return;
    }
    WifiNetAgent::GetInstance().OnStaMachineNetManagerRestart(NetSupplierInfo, m_instId);
}

void StaStateMachine::ReUpdateNetSupplierInfo(sptr<NetManagerStandard::NetSupplierInfo> supplierInfo)
{
    LOGI("ReUpdateNetSupplierInfo()");
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    if ((linkedInfo.detailedState == DetailedState::NOTWORKING) && (linkedInfo.connState == ConnState::CONNECTED)) {
        if (supplierInfo != nullptr) {
            TimeStats timeStats("Call UpdateNetSupplierInfo");
            WifiNetAgent::GetInstance().UpdateNetSupplierInfo(supplierInfo);
        }
    }
}

void StaStateMachine::ReUpdateNetLinkInfo(const WifiDeviceConfig &config)
{
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    LOGI("ReUpdateNetLinkInfo, detailedState:%{public}d, connState:%{public}d",
        linkedInfo.detailedState, linkedInfo.connState);
    if ((linkedInfo.connState == ConnState::CONNECTED) && (linkedInfo.ssid == config.ssid) &&
        (linkedInfo.bssid == config.bssid)) {
        IpInfo wifiIpInfo;
        WifiSettings::GetInstance().GetIpInfo(wifiIpInfo, m_instId);
        IpV6Info wifiIpV6Info;
        WifiSettings::GetInstance().GetIpv6Info(wifiIpV6Info, m_instId);
        WifiDeviceConfig config;
        WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config);
        WifiNetAgent::GetInstance().UpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, config.wifiProxyconfig, m_instId);
    }
}

void StaStateMachine::SaveWifiConfigForUpdate(int networkId)
{
    WIFI_LOGI("Enter SaveWifiConfigForUpdate.");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) == -1) {
        WIFI_LOGE("SaveWifiConfigForUpdate, get current config failed.");
        return;
    }
}

void StaStateMachine::DhcpResultNotify::StopRenewTimeout()
{
    if (StaStateMachine::DhcpResultNotify::renewTimerId_ == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(StaStateMachine::DhcpResultNotify::renewTimerId_);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(StaStateMachine::DhcpResultNotify::renewTimerId_);
    StaStateMachine::DhcpResultNotify::renewTimerId_ = 0;

    return;
}

#endif

void StaStateMachine::DealRenewalTimeout(InternalMessage *msg)
{
#ifdef OHOS_ARCH_LITE
    if (msg == nullptr) {
        LOGE("DealRenewalTimeout InternalMessage msg is null.");
        return;
    }
    LOGI("StopTimer CMD_START_RENEWAL_TIMEOUT DealRenewalTimeout");
    StopTimer(static_cast<int>(CMD_START_RENEWAL_TIMEOUT));
#endif
    StartDhcpRenewal(); // start renewal
}

void StaStateMachine::StartDhcpRenewal()
{
    WIFI_LOGI("enter StartDhcpRenewal!");
    WifiLinkedInfo linkedInfo;
    GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGE("StartDhcpRenewal network is not connected, connState:%{public}d", linkedInfo.connState);
        return;
    }

    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    int dhcpRet = RenewDhcpClient(ifname.c_str());
    if (dhcpRet != 0) {
        WIFI_LOGE("StartDhcpRenewal dhcp renew failed, dhcpRet:%{public}d", dhcpRet);
    } else {
        WIFI_LOGI("StartDhcpRenewal dhcp renew success.");
    }
}

WifiDeviceConfig StaStateMachine::getCurrentWifiDeviceConfig()
{
    WifiDeviceConfig wifiDeviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, wifiDeviceConfig);
    return wifiDeviceConfig;
}

void StaStateMachine::InsertOrUpdateNetworkStatusHistory(const NetworkStatus &networkStatus)
{
    WifiDeviceConfig wifiDeviceConfig = getCurrentWifiDeviceConfig();
    if (networkStatusHistoryInserted) {
        NetworkStatusHistoryManager::Update(wifiDeviceConfig.networkStatusHistory, networkStatus);
        WIFI_LOGI("After updated, current network status history is %{public}s.",
                  NetworkStatusHistoryManager::ToString(wifiDeviceConfig.networkStatusHistory).c_str());
    } else {
        NetworkStatusHistoryManager::Insert(wifiDeviceConfig.networkStatusHistory, networkStatus);
        networkStatusHistoryInserted = true;
        WIFI_LOGI("After inserted, current network status history is %{public}s.",
                  NetworkStatusHistoryManager::ToString(wifiDeviceConfig.networkStatusHistory).c_str());
    }
    if (networkStatus == NetworkStatus::PORTAL) {
        wifiDeviceConfig.isPortal = true;
        wifiDeviceConfig.noInternetAccess = true;
    }
    if (networkStatus == NetworkStatus::HAS_INTERNET) {
        wifiDeviceConfig.lastHasInternetTime = time(0);
        wifiDeviceConfig.noInternetAccess = false;
    }
    if (networkStatus == NetworkStatus::NO_INTERNET) {
        wifiDeviceConfig.noInternetAccess = true;
    }
    WifiSettings::GetInstance().AddDeviceConfig(wifiDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
}

void StaStateMachine::RenewDhcp()
{
    WIFI_LOGI("enter RenewDhcp!");
    WifiLinkedInfo linkedInfo;
    GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGE("StartDhcpRenewal network is not connected, connState:%{public}d", linkedInfo.connState);
        return;
    }
    std::string ifname = WifiSettings::GetInstance().GetStaIfaceName();
    int dhcpRet = RenewDhcpClient(ifname.c_str());
    if (dhcpRet != 0) {
        WIFI_LOGE("StartDhcpRenewal dhcp renew failed, dhcpRet:%{public}d", dhcpRet);
    } else {
        WIFI_LOGI("StartDhcpRenewal dhcp renew success.");
    }
}

int StaStateMachine::GetInstanceId()
{
    return m_instId;
}

void StaStateMachine::SetConnectMethod(int connectMethod)
{
    std::string isConnectFromUser = "-1";
    switch (connectMethod) {
        case NETWORK_SELECTED_BY_AUTO:
            isConnectFromUser = AUTO_CONNECT;
            break;
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
} // namespace Wifi
} // namespace OHOS
