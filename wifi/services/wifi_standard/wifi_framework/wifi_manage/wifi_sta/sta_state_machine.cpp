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
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_hisysevent.h"
#include "wifi_config_center.h"
#include "wifi_hisysevent.h"
#include "block_connect_service.h"
#include "wifi_randommac_helper.h"
#include "define.h"
#ifndef OHOS_ARCH_LITE
#include <dlfcn.h>
#include "securec.h"
#include "wifi_app_state_aware.h"
#include "wifi_net_observer.h"
#include "wifi_system_timer.h"
#include "wifi_notification_util.h"
#include "wifi_net_stats_manager.h"
#endif // OHOS_ARCH_LITE

#include "wifi_channel_helper.h"
#ifndef OHOS_WIFI_STA_TEST
#else
#include "mock_dhcp_service.h"
#endif
namespace OHOS {
namespace Wifi {
namespace {
constexpr const char* WIFI_IS_CONNECT_FROM_USER = "persist.wifi.is_connect_from_user";
constexpr int MAX_CHLOAD = 800;
}
DEFINE_WIFILOG_LABEL("StaStateMachine");
#define PBC_ANY_BSSID "any"
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
#define UMTS_AUTH_RESPONSE_CONTENT_LEN 52

#define MAX_RES_STR_LEN (2 * UMTS_AUTH_CHALLENGE_RES_LEN)
#define MAX_CK_STR_LEN (2 * UMTS_AUTH_CHALLENGE_CK_LEN)
#define MAX_IK_STR_LEN (2 * UMTS_AUTH_CHALLENGE_IK_LEN)
#define MAX_RAND_STR_LEN (2 * UMTS_AUTH_CHALLENGE_RAND_LEN)
#define MAX_AUTN_STR_LEN (2 * UMTS_AUTH_CHALLENGE_AUTN_LEN)

const std::map<int, int> wpa3FailreasonMap {
    {WLAN_STATUS_AUTH_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_AUTH_RSP2_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_AUTH_RSP4_TIMEOUT, WPA3_AUTH_TIMEOUT},
    {MAC_ASSOC_RSP_TIMEOUT, WPA3_ASSOC_TIMEOUT}
};

StaStateMachine::StaStateMachine(int instId)
    : StateMachine("StaStateMachine"), lastNetworkId(INVALID_NETWORK_ID), operationalMode(STA_CONNECT_MODE),
      targetNetworkId(INVALID_NETWORK_ID), pinCode(0), wpsState(SetupMethod::INVALID),
      lastSignalLevel_(INVALID_SIGNAL_LEVEL), targetRoamBssid(WPA_BSSID_ANY), currentTpType(IPTYPE_IPV4),
      isWpsConnect(IsWpsConnected::WPS_INVALID), getIpSucNum(0), getIpFailNum(0), enableSignalPoll(true), isRoam(false),
      lastTimestamp(0), portalFlag(true), portalState(PortalState::UNCHECKED), detectNum(0),
      portalExpiredDetectCount(0), mIsWifiInternetCHRFlag(false), networkStatusHistoryInserted(false),
      pDhcpResultNotify(nullptr), pRootState(nullptr), pInitState(nullptr), pWpaStartingState(nullptr),
      pWpaStartedState(nullptr), pWpaStoppingState(nullptr), pLinkState(nullptr), pSeparatingState(nullptr),
      pSeparatedState(nullptr), pApLinkedState(nullptr), pWpsState(nullptr), pGetIpState(nullptr),
      pLinkedState(nullptr), pApRoamingState(nullptr), mLastConnectNetId(INVALID_NETWORK_ID),
      mConnectFailedCnt(0)
{
    m_instId = instId;
}

StaStateMachine::~StaStateMachine()
{
    WIFI_LOGI("~StaStateMachine");
    StopWifiProcess();
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
    WIFI_LOGI("Enter InitStateMachine m_instId = %{public}d", m_instId);
    if (!InitialStateMachine("StaStateMachine")) {
        WIFI_LOGE("Initial StateMachine failed m_instId = %{public}d", m_instId);
        return WIFI_OPT_FAILED;
    }

    if (InitStaStates() == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    BuildStateTree();
    SetFirstState(pInitState);
    StartStateMachine();
    InitStaSMHandleMap();
    if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        NetSupplierInfo = std::make_unique<NetManagerStandard::NetSupplierInfo>().release();
        m_NetWorkState = sptr<NetStateObserver>(new NetStateObserver());
        m_NetWorkState->SetNetStateCallback(
            [this](SystemNetWorkState netState, std::string url) { this->NetStateObserverCallback(netState, url); });
#endif
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaStateMachine::InitStaStates()
{
    WIFI_LOGE("Enter InitStaStates\n");
    int tmpErrNumber;
    pRootState = new (std::nothrow) RootState();
    tmpErrNumber = JudgmentEmpty(pRootState);
    pInitState = new (std::nothrow) InitState(this);
    tmpErrNumber += JudgmentEmpty(pInitState);
    pWpaStartingState = new (std::nothrow) WpaStartingState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStartingState);
    pWpaStartedState = new (std::nothrow) WpaStartedState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStartedState);
    pWpaStoppingState = new (std::nothrow) WpaStoppingState(this);
    tmpErrNumber += JudgmentEmpty(pWpaStoppingState);
    pLinkState = new (std::nothrow) LinkState(this);
    tmpErrNumber += JudgmentEmpty(pLinkState);
    pSeparatingState = new (std::nothrow) SeparatingState();
    tmpErrNumber += JudgmentEmpty(pSeparatingState);
    pSeparatedState = new (std::nothrow) SeparatedState(this);
    tmpErrNumber += JudgmentEmpty(pSeparatedState);
    pApLinkedState = new (std::nothrow) ApLinkedState(this);
    tmpErrNumber += JudgmentEmpty(pApLinkedState);
    pWpsState = new (std::nothrow) StaWpsState(this);
    tmpErrNumber += JudgmentEmpty(pWpsState);
    pGetIpState = new (std::nothrow) GetIpState(this);
    tmpErrNumber += JudgmentEmpty(pGetIpState);
    pLinkedState = new (std::nothrow) LinkedState(this);
    tmpErrNumber += JudgmentEmpty(pLinkedState);
    pApRoamingState = new (std::nothrow) ApRoamingState(this);
    tmpErrNumber += JudgmentEmpty(pApRoamingState);
    pDhcpResultNotify = new (std::nothrow) DhcpResultNotify();
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
    linkedInfo.supplicantState = SupplicantState::DISCONNECTED;
    linkedInfo.detailedState = DetailedState::DISCONNECTED;
    linkedInfo.channelWidth = WifiChannelWidth::WIDTH_INVALID;
    linkedInfo.lastPacketDirection = 0;
    linkedInfo.lastRxPackets = 0;
    linkedInfo.lastTxPackets = 0;
    linkedInfo.isAncoConnected = 0;
    linkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
    linkedInfo.isMloConnected = false;
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
    lastLinkedInfo.supplicantState = SupplicantState::DISCONNECTED;
    lastLinkedInfo.detailedState = DetailedState::DISCONNECTED;
    linkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
    linkedInfo.isMloConnected = false;
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

void StaStateMachine::UnRegisterStaServiceCallback(const StaServiceCallback &callback)
{
    WIFI_LOGI("UnRegisterStaServiceCallback, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::shared_mutex> lock(m_staCallbackMutex);
    m_staCallback.erase(callback.callbackModuleName);
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
            if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
                WifiNetStatsManager::GetInstance().StartNetStats();
#endif
            }
            break;
        case OperateResState::DISCONNECT_DISCONNECTED:
            WriteWifiConnectionHiSysEvent(WifiConnectionType::DISCONNECT, "");
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

void StaStateMachine::InvokeOnDhcpOfferReport(IpInfo ipInfo)
{
    std::shared_lock<std::shared_mutex> lock(m_staCallbackMutex);
    for (const auto &callBackItem : m_staCallback) {
        if (callBackItem.second.OnDhcpOfferReport != nullptr) {
            callBackItem.second.OnDhcpOfferReport(ipInfo, m_instId);
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

bool StaStateMachine::RootState::ExecuteStateMsg(InternalMessagePtr msg)
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
            if (result == WifiErrorNo::WIFI_HAL_OPT_OK) {
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

bool StaStateMachine::InitState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("InitState-msgCode=%{public}d is received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->GetInstanceId());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_ENABLE_STA: {
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
    } else if (scanInfo.capabilities.find("FT/SAE") != std::string::npos) {
        halDeviceConfig.keyMgmt.append(" FT-SAE ");
    } else {
        LOGI("No need append ft keyMgmt!");
    }
}

void StaStateMachine::ConvertSsidToOriginalSsid(
    const WifiDeviceConfig &config, WifiHalDeviceConfig &halDeviceConfig) const
{
    std::vector<WifiScanInfo> scanInfoList;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    for (auto &scanInfo : scanInfoList) {
        std::string deviceKeyMgmt;
        scanInfo.GetDeviceMgmt(deviceKeyMgmt);
        if (config.ssid == scanInfo.ssid
            && ((deviceKeyMgmt == "WPA-PSK+SAE" && deviceKeyMgmt.find(config.keyMgmt) != std::string::npos)
                || (config.keyMgmt == deviceKeyMgmt))) { // 混合加密目前只支持WPA-PSK+SAE，此处特殊处理
            AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);
            halDeviceConfig.ssid = scanInfo.oriSsid;
            LOGI("ConvertSsidToOriginalSsid back to oriSsid:%{public}s, keyMgmt:%{public}s",
                SsidAnonymize(halDeviceConfig.ssid).c_str(), halDeviceConfig.keyMgmt.c_str());
            break;
        }
    }
}

ErrCode StaStateMachine::ConvertDeviceCfg(const WifiDeviceConfig &config) const
{
    LOGI("Enter ConvertDeviceCfg.\n");
    WifiHalDeviceConfig halDeviceConfig;
    TransHalDeviceConfig(halDeviceConfig, config);
    if (strcmp(config.keyMgmt.c_str(), "WEP") == 0) {
        /* for wep */
        halDeviceConfig.authAlgorithms = 0x02;
    }

    if (IsWpa3Transition(config.ssid)) {
        if (IsInWpa3BlackMap(config.ssid)) {
            halDeviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        } else {
            halDeviceConfig.keyMgmt = KEY_MGMT_SAE;
        }
        halDeviceConfig.isRequirePmf = false;
    }

    if (config.keyMgmt.find("SAE") != std::string::npos) {
        halDeviceConfig.isRequirePmf = true;
    }

    if (halDeviceConfig.keyMgmt.find("SAE") != std::string::npos) {
        halDeviceConfig.allowedProtocols = 0x02; // RSN
        halDeviceConfig.allowedPairwiseCiphers = 0x2c; // CCMP|GCMP|GCMP-256
        halDeviceConfig.allowedGroupCiphers = 0x2c; // CCMP|GCMP|GCMP-256
    }

    for (int i = 0; i < HAL_MAX_WEPKEYS_SIZE; i++) {
        halDeviceConfig.wepKeys[i] = config.wepKeys[i];
    }
    LOGI("ConvertDeviceCfg SetDeviceConfig selected network ssid=%{public}s, bssid=%{public}s, instId=%{public}d",
        SsidAnonymize(halDeviceConfig.ssid).c_str(), MacAnonymize(halDeviceConfig.bssid).c_str(), m_instId);
    ConvertSsidToOriginalSsid(config, halDeviceConfig);

    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(WPA_DEFAULT_NETWORKID, halDeviceConfig, ifaceName) !=
        WIFI_HAL_OPT_OK) {
        LOGE("ConvertDeviceCfg SetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }

    if (SetExternalSim("wlan0", halDeviceConfig.eapConfig.eap, WIFI_EAP_OPEN_EXTERNAL_SIM)) {
        LOGE("StaStateMachine::ConvertDeviceCfg: failed to set external_sim");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaStateMachine::StartWifiProcess()
{
    if (WifiStaHalInterface::GetInstance().WpaAutoConnect(false) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("The automatic Wpa connection is disabled failed.");
    }
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    WIFI_LOGI("set suspend mode to chip when wifi started, screenState: %{public}d", screenState);
    if (m_instId == INSTID_WLAN0) {
        if (WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE)
            != WIFI_HAL_OPT_OK) {
            WIFI_LOGE("%{public}s WpaSetSuspendMode failed!", __FUNCTION__);
        }
    }
    /* Sets the MAC address of WifiSettings. */
    std::string mac;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(mac, ifaceName)) == WIFI_HAL_OPT_OK) {
        WifiConfigCenter::GetInstance().SetMacAddress(mac, m_instId);
        std::string realMacAddress;
        WifiSettings::GetInstance().GetRealMacAddress(realMacAddress, m_instId);
        if (realMacAddress.empty()) {
            WifiSettings::GetInstance().SetRealMacAddress(mac, m_instId);
        }
    } else {
        WIFI_LOGI("GetStaDeviceMacAddress failed!");
    }

    if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        WIFI_LOGI("Register netsupplier");
        WifiNetAgent::GetInstance().OnStaMachineWifiStart();
#endif
    }
    /* Initialize Connection Information. */
    InitWifiLinkedInfo();
    InitLastWifiLinkedInfo();
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    /* The current state of StaStateMachine transfers to SeparatedState after
     * enable supplicant.
     */
    SwitchState(pSeparatedState);
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

bool StaStateMachine::WpaStartingState::ExecuteStateMsg(InternalMessagePtr msg)
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

bool StaStateMachine::WpaStartedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        LOGI("msg is nullptr");
        return false;
    }

    WIFI_LOGI("WpaStartedState ExecuteStateMsg-msgCode:%{public}d m_instId = %{public}d\n",
        msg->GetMessageName(), pStaStateMachine->GetInstanceId());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DISABLE_STA: {
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
    WIFI_LOGI("Enter StaStateMachine::StopWifiProcess m_instId = %{public}d\n", m_instId);
    if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        WifiNetAgent::GetInstance().UnregisterNetSupplier();
        if (m_NetWorkState != nullptr) {
            m_NetWorkState->StopNetStateObserver(m_NetWorkState);
        }
#endif
        std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);

        if (currentTpType == IPTYPE_IPV4) {
            StopDhcpClient(ifaceName.c_str(), false);
        } else {
            StopDhcpClient(ifaceName.c_str(), true);
        }

        IpInfo ipInfo;
        WifiConfigCenter::GetInstance().SaveIpInfo(ipInfo, m_instId);
        IpV6Info ipV6Info;
        WifiConfigCenter::GetInstance().SaveIpV6Info(ipV6Info, m_instId);
#ifdef OHOS_ARCH_LITE
        IfConfig::GetInstance().FlushIpAddr(WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), IPTYPE_IPV4);
#endif
    }

    WIFI_LOGI("Stop wifi is in process... m_instId = %{public}d", m_instId);
    StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
    isRoam = false;
    mPortalUrl = "";
    WifiConfigCenter::GetInstance().SetMacAddress("", m_instId);

    ConnState curConnState = linkedInfo.connState;
    WIFI_LOGI("current connect state is %{public}d m_instId = %{public}d\n", curConnState, m_instId);
    std::string ssid = linkedInfo.ssid;
    /* clear connection information. */
    InitWifiLinkedInfo();
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    if (curConnState == ConnState::CONNECTING || curConnState == ConnState::AUTHENTICATING ||
        curConnState == ConnState::OBTAINING_IPADDR || curConnState == ConnState::CONNECTED) {
        WifiStaHalInterface::GetInstance().Disconnect(WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId));
        /* Callback result to InterfaceService. */
        linkedInfo.ssid = ssid;
        InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
        linkedInfo.ssid = "";
    }
    SwitchState(pInitState);
    WifiConfigCenter::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, m_instId);
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

bool StaStateMachine::WpaStoppingState::ExecuteStateMsg(InternalMessagePtr msg)
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

bool StaStateMachine::LinkState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }
    LOGD("LinkState ExecuteStateMsg function:msgName=[%{public}d]. m_instId=%{public}d\n",
        msg->GetMessageName(), pStaStateMachine->GetInstanceId());
    auto iter = pStaStateMachine->staSmHandleFuncMap.find(msg->GetMessageName());
    if (iter != pStaStateMachine->staSmHandleFuncMap.end()) {
        (iter->second)(msg);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

/* -- state machine Connect State Message processing function -- */
int StaStateMachine::InitStaSMHandleMap()
{
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CONNECT_NETWORK] = [this](InternalMessagePtr msg) {
        return this->DealConnectToUserSelectedNetwork(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK] = [this](InternalMessagePtr msg) {
        return this->DealConnectToUserSelectedNetwork(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealDisconnectEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealConnectionEvent(msg);
    };
    staSmHandleFuncMap[CMD_NETWORK_CONNECT_TIMEOUT] = [this](InternalMessagePtr msg) {
        return this->DealConnectTimeOutCmd(msg);
    };
    staSmHandleFuncMap[WPA_BLOCK_LIST_CLEAR_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaBlockListClearEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_STARTWPS] = [this](InternalMessagePtr msg) {
        return this->DealStartWpsCmd(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET] = [this](InternalMessagePtr msg) {
        return this->DealWpsConnectTimeOutEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CANCELWPS] = [this](InternalMessagePtr msg) {
        return this->DealCancelWpsCmd(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_RECONNECT_NETWORK] = [this](InternalMessagePtr msg) {
        return this->DealReConnectCmd(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK] = [this](InternalMessagePtr msg) {
        return this->DealReassociateCmd(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_COM_STA_START_ROAM] = [this](InternalMessagePtr msg) {
        return this->DealStartRoamCmd(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaLinkFailEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaLinkFailEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaLinkFailEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_REPORT_DISCONNECT_REASON_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaLinkFailEvent(msg);
    };
    staSmHandleFuncMap[CMD_START_NETCHECK] = [this](InternalMessagePtr msg) { return this->DealNetworkCheck(msg); };
    staSmHandleFuncMap[CMD_START_GET_DHCP_IP_TIMEOUT] = [this](InternalMessagePtr msg) {
        return this->DealGetDhcpIpTimeout(msg);
    };
    staSmHandleFuncMap[WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealScreenStateChangedEvent(msg);
    };
    staSmHandleFuncMap[CMD_AP_ROAMING_TIMEOUT_CHECK] = [this](InternalMessagePtr msg) {
        return this->DealApRoamingStateTimeout(msg);
    };
#ifndef OHOS_ARCH_LITE
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaEapSimAuthEvent(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaEapUmtsAuthEvent(msg);
    };
#endif
    staSmHandleFuncMap[WIFI_SVR_COM_STA_ENABLE_HILINK] = [this](InternalMessagePtr msg) {
        return this->DealHiLinkDataToWpa(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_CSA_CHANNEL_SWITCH_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealCsaChannelChanged(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_COM_STA_HILINK_DELIVER_MAC] = [this](InternalMessagePtr msg) {
        return this->DealHiLinkDataToWpa(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS] = [this](InternalMessagePtr msg) {
        return this->DealHiLinkDataToWpa(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT] = [this](InternalMessagePtr msg) {
        return this->DealWpaStateChange(msg);
    };
    staSmHandleFuncMap[WIFI_SVR_COM_STA_NETWORK_REMOVED] = [this](InternalMessagePtr msg) {
        return this->DealNetworkRemoved(msg);
    };
    return WIFI_OPT_SUCCESS;
}

int SetRssi(int rssi)
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
            outRssi = SetRssi((inRssi - SIGNAL_INFO));
        } else {
            outRssi = SetRssi(inRssi);
        }
    } else {
        outRssi = INVALID_RSSI_VALUE;
    }
    return outRssi;
}

void StaStateMachine::DealSignalPollResult()
{
    LOGD("enter SignalPoll.");
    WifiHalWpaSignalInfo signalInfo;
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().GetConnectSignalInfo(
        WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), linkedInfo.bssid, signalInfo);
    if (ret != WIFI_HAL_OPT_OK) {
        LOGE("GetConnectSignalInfo return fail: %{public}d.", ret);
        return;
    }
    if (signalInfo.frequency > 0) {
        linkedInfo.frequency = signalInfo.frequency;
    }
    ConvertFreqToChannel();
    UpdateLinkRssi(signalInfo);
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
        WifiConfigCenter::GetInstance().SetWifiLinkedStandardAndMaxSpeed(linkedInfo);
    }

    LOGI("SignalPoll,bssid:%{public}s,ssid:%{public}s,networkId:%{public}d,band:%{public}d,freq:%{public}d,"
        "rssi:%{public}d,noise:%{public}d,chload:%{public}d,snr:%{public}d,ulDelay:%{public}d,txLinkSpeed:%{public}d,"
        "rxLinkSpeed:%{public}d,txBytes:%{public}d,rxBytes:%{public}d,txFailed:%{public}d,txPackets:%{public}d,"
        "rxPackets:%{public}d,GetWifiStandard:%{public}d,rxmax:%{public}d,txmax:%{public}d,connState:%{public}d,"
        "detState:%{public}d,lastSignal:%{public}d,chloadSelf:%{public}d,c0Rssi:%{public}d,c1Rssi:%{public}d",
        MacAnonymize(linkedInfo.bssid).c_str(), SsidAnonymize(linkedInfo.ssid).c_str(), linkedInfo.networkId,
        linkedInfo.band, signalInfo.frequency, signalInfo.signal, signalInfo.noise, signalInfo.chload, signalInfo.snr,
        signalInfo.ulDelay, signalInfo.txrate, signalInfo.rxrate, signalInfo.txBytes, signalInfo.rxBytes,
        signalInfo.txFailed, signalInfo.txPackets, signalInfo.rxPackets, linkedInfo.wifiStandard,
        linkedInfo.maxSupportedRxLinkSpeed, linkedInfo.maxSupportedTxLinkSpeed, linkedInfo.connState,
        linkedInfo.detailedState, lastSignalLevel_, signalInfo.chloadSelf, signalInfo.c0Rssi, signalInfo.c1Rssi);

    WriteLinkInfoHiSysEvent(lastSignalLevel_, linkedInfo.rssi, linkedInfo.band, linkedInfo.linkSpeed);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    DealSignalPacketChanged(signalInfo.txPackets, signalInfo.rxPackets);

    if (enableSignalPoll) {
        WIFI_LOGD("SignalPoll, StartTimer for SIGNAL_POLL.\n");
        StopTimer(static_cast<int>(CMD_SIGNAL_POLL));
        StartTimer(static_cast<int>(CMD_SIGNAL_POLL), STA_SIGNAL_POLL_DELAY);
    }
}

void StaStateMachine::UpdateLinkRssi(const WifiHalWpaSignalInfo &signalInfo)
{
    int currentSignalLevel = 0;
    if (signalInfo.signal > INVALID_RSSI_VALUE && signalInfo.signal < MAX_RSSI_VALUE) {
        if (signalInfo.signal > 0) {
            linkedInfo.rssi = SetRssi((signalInfo.signal - SIGNAL_INFO));
        } else {
            linkedInfo.rssi = SetRssi(signalInfo.signal);
        }
        currentSignalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band, m_instId);
        if (currentSignalLevel != lastSignalLevel_) {
            WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
            InvokeOnStaRssiLevelChanged(linkedInfo.rssi);
            lastSignalLevel_ = currentSignalLevel;
        }
    } else {
        linkedInfo.rssi = INVALID_RSSI_VALUE;
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

void StaStateMachine::DealConnectToUserSelectedNetwork(InternalMessagePtr msg)
{
    LOGI("enter DealConnectToUserSelectedNetwork m_instId = %{public}d\n", m_instId);
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return;
    }
    int networkId = msg->GetParam1();
    int connTriggerMode = msg->GetParam2();
    auto bssid = msg->GetStringFromMessage();
    if (connTriggerMode == NETWORK_SELECTED_BY_USER) {
        BlockConnectService::GetInstance().EnableNetworkSelectStatus(networkId);
    }
    WriteWifiConnectionInfoHiSysEvent(networkId);
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
        LOGE("GetDeviceConfig failed!");
        return;
    }
    if (networkId == linkedInfo.networkId) {
        if (linkedInfo.connState == ConnState::CONNECTED && config.isReassocSelfCureWithFactoryMacAddress == 0) {
            InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, linkedInfo);
            WIFI_LOGI("This network is in use and does not need to be reconnected m_istId = %{public}d", m_instId);
            return;
        }
        if (linkedInfo.connState == ConnState::CONNECTING &&
            linkedInfo.detailedState == DetailedState::OBTAINING_IPADDR) {
            WIFI_LOGI("This network is connecting and does not need to be reconnected m_instId = %{public}d",
                m_instId);
            return;
        }
    }

    std::string connectType = config.lastConnectTime <= 0 ? "FIRST_CONNECT" :
        connTriggerMode == NETWORK_SELECTED_BY_AUTO ? "AUTO_CONNECT" :
        connTriggerMode == NETWORK_SELECTED_BY_USER ? "SELECT_CONNECT" : "";
    if (!connectType.empty()) {
        WirteConnectTypeHiSysEvent(connectType);
    }
    SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    SaveLinkstate(ConnState::CONNECTING, DetailedState::CONNECTING);
    networkStatusHistoryInserted = false;
    InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING, linkedInfo);
    if (StartConnectToNetwork(networkId, bssid) != WIFI_OPT_SUCCESS) {
        OnConnectFailed(networkId);
        return;
    }
    if (connTriggerMode == NETWORK_SELECTED_BY_USER) {
        WifiConfigCenter::GetInstance().EnableNetwork(networkId, true, m_instId);
        WifiSettings::GetInstance().SetUserConnectChoice(networkId);
    }
    WifiSettings::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::ENABLED, false);
}

void StaStateMachine::DealConnectTimeOutCmd(InternalMessagePtr msg)
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
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID, ifaceName);
    DealSetStaConnectFailedCount(1, false);
    std::string ssid = linkedInfo.ssid;
    WifiConfigCenter::GetInstance().SetConnectTimeoutBssid(linkedInfo.bssid, m_instId);
    InitWifiLinkedInfo();
    SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_TIMEOUT);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
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

bool StaStateMachine::CurrentIsRandomizedMac()
{
    std::string curMacAddress = "";
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(curMacAddress, ifaceName)) != WIFI_HAL_OPT_OK) {
        LOGE("CurrentIsRandomizedMac GetStaDeviceMacAddress failed!");
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

    WifiSettings::GetInstance().SetUserConnectChoice(m_hilinkDeviceConfig.networkId);
    targetNetworkId = m_hilinkDeviceConfig.networkId;

    WifiStaHalInterface::GetInstance().GetPskPassphrase("wlan0", m_hilinkDeviceConfig.preSharedKey);
    m_hilinkDeviceConfig.version = -1;
    if (!WifiSettings::GetInstance().EncryptionDeviceConfig(m_hilinkDeviceConfig)) {
        LOGE("HilinkSaveConfig EncryptionDeviceConfig failed");
    }
    WifiSettings::GetInstance().AddDeviceConfig(m_hilinkDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();

    WifiConfigCenter::GetInstance().SetMacAddress(m_hilinkDeviceConfig.macAddress, m_instId);
    m_hilinkFlag = false;
}

void StaStateMachine::DealConnectionEvent(InternalMessagePtr msg)
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
    if (m_hilinkFlag) {
        HilinkSaveConfig();
    }
    WIFI_LOGI("enter DealConnectionEvent m_instId = %{public}d", m_instId);
    if (CurrentIsRandomizedMac()) {
        WifiSettings::GetInstance().SetDeviceRandomizedMacSuccessEver(targetNetworkId);
    }
#ifndef OHOS_ARCH_LITE
    SaveWifiConfigForUpdate(targetNetworkId);
#endif
    /* Stop clearing the Wpa_blocklist. */
    StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    ConnectToNetworkProcess(bssid);
    StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    if (wpsState != SetupMethod::INVALID) {
        wpsState = SetupMethod::INVALID;
    }
    WIFI_LOGI("enter state machine change to ip state m_instId = %{public}d", m_instId);
    if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        if (NetSupplierInfo != nullptr) {
            NetSupplierInfo->isAvailable_ = true;
            NetSupplierInfo->isRoaming_ = isRoam;
            NetSupplierInfo->ident_ = std::to_string(linkedInfo.networkId);
            WIFI_LOGI("On connect update net supplier info\n");
            WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(NetSupplierInfo);
        }
#endif
        /* Callback result to InterfaceService. */
        InvokeOnStaConnChanged(OperateResState::CONNECT_OBTAINING_IP, linkedInfo);
        mConnectFailedCnt = 0;
        /* The current state of StaStateMachine transfers to GetIpState. */
        SwitchState(pGetIpState);
    } else {
        mConnectFailedCnt = 0;
        SwitchState(pLinkedState);
    }
    WifiConfigCenter::GetInstance().SetUserLastSelectedNetworkId(INVALID_NETWORK_ID, m_instId);
}

void StaStateMachine::DealDisconnectEvent(InternalMessagePtr msg)
{
    LOGI("Enter DealDisconnectEvent m_instId = %{public}d", m_instId);
    if (msg == nullptr || wpsState != SetupMethod::INVALID) {
        WIFI_LOGE("msg is null or wpsState is INVALID, wpsState:%{public}d", static_cast<int>(wpsState));
        return;
    }
    std::string bssid;
    msg->GetMessageObj(bssid);
    if (CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("DealDisconnectEvent inconsistent bssid in connecter");
        return;
    }

    StopTimer(static_cast<int>(CMD_SIGNAL_POLL));

    if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        if (NetSupplierInfo != nullptr) {
            NetSupplierInfo->isAvailable_ = false;
            NetSupplierInfo->ident_ = "";
            WIFI_LOGI("On disconnect update net supplier info\n");
            WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(NetSupplierInfo);
        }
#endif
        StopTimer(static_cast<int>(CMD_START_NETCHECK));
        std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
        if (currentTpType == IPTYPE_IPV4) {
            StopDhcpClient(ifname.c_str(), false);
        } else {
            StopDhcpClient(ifname.c_str(), true);
        }
        HandlePostDhcpSetup();
        getIpSucNum = 0;
        getIpFailNum = 0;

        IpInfo ipInfo;
        WifiConfigCenter::GetInstance().SaveIpInfo(ipInfo, m_instId);
        IpV6Info ipV6Info;
        WifiConfigCenter::GetInstance().SaveIpV6Info(ipV6Info, m_instId);
#ifdef OHOS_ARCH_LITE
        IfConfig::GetInstance().FlushIpAddr(WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId), IPTYPE_IPV4);
#endif
    }

    isRoam = false;
    mPortalUrl = "";
    /* Initialize connection information. */
    std::string ssid = linkedInfo.ssid;
    InitWifiLinkedInfo();
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
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

void StaStateMachine::AddRandomMacCure()
{
    if (targetNetworkId == mLastConnectNetId) {
        mConnectFailedCnt++;
    }
}

void StaStateMachine::DealWpaLinkFailEvent(InternalMessagePtr msg)
{
    LOGW("enter DealWpaLinkFailEvent.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return;
    }
    DealSetStaConnectFailedCount(1, false);
    int eventName = msg->GetMessageName();
    bool shouldStopTimer = true;
    if (eventName == WIFI_SVR_CMD_STA_REPORT_DISCONNECT_REASON_EVENT) {
        std::string bssid = msg->GetStringFromMessage();
        int reason = msg->GetIntFromMessage();
        WIFI_LOGI("DealWpaLinkFailEvent reason:%{public}d, bssid:%{public}s", reason, MacAnonymize(bssid).c_str());
        shouldStopTimer = IsDisConnectReasonShouldStopTimer(reason);
        BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
            DisabledReason::DISABLED_DISASSOC_REASON, reason);
        if (BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, reason)) {
            BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
                DisabledReason::DISABLED_CONSECUTIVE_FAILURES);
        }
    } else {
        std::string ssid = linkedInfo.ssid;
        InitWifiLinkedInfo();
        linkedInfo.ssid = ssid;
        WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
    }
    if (shouldStopTimer) {
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    }
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    switch (eventName) {
        case WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT:
            SaveDiscReason(DisconnectedReason::DISC_REASON_WRONG_PWD);
            SaveLinkstate(ConnState::DISCONNECTED, DetailedState::PASSWORD_ERROR);
            InvokeOnStaConnChanged(OperateResState::CONNECT_PASSWORD_WRONG, linkedInfo);
            InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
            if (BlockConnectService::GetInstance().IsWrongPassword(targetNetworkId)) {
                BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
                    DisabledReason::DISABLED_BY_WRONG_PASSWORD);
            } else {
                BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
                    DisabledReason::DISABLED_AUTHENTICATION_FAILURE);
            }
            break;
        case WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT:
            WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID, ifaceName);
            SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_FULL);
            SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_FULL);
            InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTION_FULL, linkedInfo);
            InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
            BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
                DisabledReason::DISABLED_ASSOCIATION_REJECTION);
            AddRandomMacCure();
            break;
        case WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT:
            WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID, ifaceName);
            SaveDiscReason(DisconnectedReason::DISC_REASON_CONNECTION_REJECTED);
            SaveLinkstate(ConnState::DISCONNECTED, DetailedState::CONNECTION_REJECT);
            InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTION_REJECT, linkedInfo);
            InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, linkedInfo);
            BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
                DisabledReason::DISABLED_ASSOCIATION_REJECTION);
            AddRandomMacCure();
            break;
        default:
            LOGW("DealWpaLinkFailEvent unhandled %{public}d", eventName);
            return;
    }
    linkedInfo.ssid = "";
}

void StaStateMachine::DealSetStaConnectFailedCount(int count, bool set)
{
    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config, m_instId);
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

void StaStateMachine::DealReConnectCmd(InternalMessagePtr msg)
{
    LOGI("enter DealReConnectCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }

    if (linkedInfo.connState == ConnState::CONNECTED) {
        WIFI_LOGE("Network is already connected, ignore the re-connect command!\n");
        return;
    }

    if (WifiStaHalInterface::GetInstance().Reconnect() == WIFI_HAL_OPT_OK) {
        DealSetStaConnectFailedCount(0, true);
        WIFI_LOGI("StaStateMachine ReConnect successfully!");
        /* Callback result to InterfaceService */
        InvokeOnStaConnChanged(OperateResState::CONNECT_CONNECTING, linkedInfo);
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
        StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    } else {
        DealSetStaConnectFailedCount(1, false);
        WIFI_LOGE("ReConnect failed!");
    }
}

void StaStateMachine::DealReassociateCmd(InternalMessagePtr msg)
{
    LOGI("enter DealReassociateCmd.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }
    WirteConnectTypeHiSysEvent("REASSOC");
    if (WifiStaHalInterface::GetInstance().Reassociate() == WIFI_HAL_OPT_OK) {
        /* Callback result to InterfaceService */
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATING, linkedInfo);
        WIFI_LOGD("StaStateMachine ReAssociate successfully!");
        StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
        StartTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT), STA_NETWORK_CONNECTTING_DELAY);
    } else {
        WIFI_LOGE("ReAssociate failed!");
    }
}

void StaStateMachine::DealStartWpsCmd(InternalMessagePtr msg)
{
    WIFI_LOGI("enter DealStartWpsCmd\n");
    if (msg == nullptr) {
        return;
    }

    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().ClearDeviceConfig(ifaceName) != WIFI_HAL_OPT_OK) {
        LOGE("ClearDeviceConfig() failed!");
        return;
    }

    StartWpsMode(msg);
    if ((wpsState == SetupMethod::DISPLAY) || (wpsState == SetupMethod::KEYPAD)) {
        WIFI_LOGW("Clear WPA block list every ten second!");
        SendMessage(WPA_BLOCK_LIST_CLEAR_EVENT);
    }
}

void StaStateMachine::StartWpsMode(InternalMessagePtr msg)
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
    WifiHalWpsConfig wpsParam;
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
        if (WifiStaHalInterface::GetInstance().StartWpsPbcMode(wpsParam) == WIFI_HAL_OPT_OK) {
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
        if (WifiStaHalInterface::GetInstance().StartWpsPinMode(wpsParam, pinCode) == WIFI_HAL_OPT_OK) {
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
        if (WifiStaHalInterface::GetInstance().StartWpsPinMode(wpsParam, pinCode) == WIFI_HAL_OPT_OK) {
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

void StaStateMachine::DealWpaBlockListClearEvent(InternalMessagePtr msg)
{
    if (msg != nullptr) {
        WIFI_LOGE("enter DealWpaBlockListClearEvent\n");
    }
    if (WifiStaHalInterface::GetInstance().WpaBlocklistClear() != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Clearing the Wpa_blocklist failed\n");
    }
    StartTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT), BLOCK_LIST_CLEAR_TIMER);
    WIFI_LOGI("Clearing the Wpa_blocklist.\n");
}

void StaStateMachine::DealWpsConnectTimeOutEvent(InternalMessagePtr msg)
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

void StaStateMachine::DealCancelWpsCmd(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is null\n");
    }

    StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    isWpsConnect = IsWpsConnected::WPS_INVALID;
    if (WifiStaHalInterface::GetInstance().StopWps() == WIFI_HAL_OPT_OK) {
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
            std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
            if (WifiStaHalInterface::GetInstance().EnableNetwork(WPA_DEFAULT_NETWORKID, ifaceName)
                == WIFI_HAL_OPT_OK) {
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

void StaStateMachine::DealStartRoamCmd(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("%{public}s msg is null", __FUNCTION__);
        return;
    }
    std::string bssid = msg->GetStringFromMessage();
    targetRoamBssid = bssid;
    WIFI_LOGI("%{public}s target bssid:%{public}s,", __FUNCTION__, MacAnonymize(linkedInfo.bssid).c_str());
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, targetRoamBssid, ifaceName)
        != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("%{public}s set roam target bssid fail", __FUNCTION__);
        return;
    }
    if (WifiStaHalInterface::GetInstance().Reassociate() != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("%{public}s START_ROAM-ReAssociate() failed!", __FUNCTION__);
        return;
    }
    WIFI_LOGI("%{public}s START_ROAM-ReAssociate() succeeded!", __FUNCTION__);
    /* Start roaming */
    SwitchState(pApRoamingState);
}

ErrCode StaStateMachine::StartConnectToNetwork(int networkId, const std::string & bssid)
{
    if (m_instId == INSTID_WLAN0) {
        if (ConfigRandMacSelfCure(networkId) != WIFI_OPT_SUCCESS) {
            LOGE("ConfigRandMacSelfCure failed!");
            return WIFI_OPT_FAILED;
        }
    }

    targetNetworkId = networkId;
    SetRandomMac(targetNetworkId, bssid);
    LOGI("StartConnectToNetwork SetRandomMac targetNetworkId:%{public}d, bssid:%{public}s", targetNetworkId,
        MacAnonymize(bssid).c_str());
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig, m_instId) != 0) {
        LOGE("StartConnectToNetwork get GetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    WifiStaHalInterface::GetInstance().ClearDeviceConfig(ifaceName);
    int wpaNetworkId = INVALID_NETWORK_ID;
    if (WifiStaHalInterface::GetInstance().GetNextNetworkId(wpaNetworkId, ifaceName) != WIFI_HAL_OPT_OK) {
        LOGE("StartConnectToNetwork GetNextNetworkId failed!");
        return WIFI_OPT_FAILED;
    }
    ConvertDeviceCfg(deviceConfig);
    if (bssid.empty()) {
        // user select connect
        LOGI("SetBssid userSelectBssid=%{public}s", MacAnonymize(deviceConfig.userSelectBssid).c_str());
        WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, deviceConfig.userSelectBssid, ifaceName);
        deviceConfig.userSelectBssid = "";
        WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        WifiSettings::GetInstance().SyncDeviceConfig();
    } else {
        // auto connect
        LOGI("SetBssid bssid=%{public}s", MacAnonymize(bssid).c_str());
        WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid, ifaceName);
    }
    if (WifiStaHalInterface::GetInstance().EnableNetwork(WPA_DEFAULT_NETWORKID, ifaceName) != WIFI_HAL_OPT_OK) {
        LOGE("EnableNetwork() failed!");
        return WIFI_OPT_FAILED;
    }

    if (WifiStaHalInterface::GetInstance().Connect(WPA_DEFAULT_NETWORKID, ifaceName) != WIFI_HAL_OPT_OK) {
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
            ret = sprintf_s(strMacTmp, arraySize - 1, "%x", distribution(gen));
        } else {
            std::uniform_int_distribution<> distribution(0, octBase - 1);
            ret = sprintf_s(strMacTmp, arraySize - 1, "%x", two * distribution(gen));
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
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) == -1) {
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
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanInfoList);
    for (auto scanInfo : scanInfoList) {
        if ((ssid == scanInfo.ssid) &&
            (scanInfo.capabilities.find("PSK+SAE") != std::string::npos)) {
            LOGI("IsWpa3Transition, check is transition");
            return true;
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
    LOGI("%{public}s: generate a random mac, randomMac:%{public}s, ssid:%{public}s, peerbssid:%{public}s",
        __func__, MacAnonymize(randomMacInfo.randomMac).c_str(), SsidAnonymize(randomMacInfo.ssid).c_str(),
        MacAnonymize(randomMacInfo.peerBssid).c_str());
#endif
}

bool StaStateMachine::SetMacToHal(const std::string &currentMac, const std::string &realMac, int instId)
{
    std::string lastMac;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(instId);
    if ((WifiStaHalInterface::GetInstance().GetStaDeviceMacAddress(lastMac, ifaceName)) != WIFI_HAL_OPT_OK) {
        LOGE("%{public}s randommac, GetStaDeviceMacAddress failed!", __func__);
        return false;
    }
    bool isRealMac = currentMac == realMac;
    LOGI("%{public}s, randommac, use %{public}s mac to connect, currentMac:%{public}s, lastMac:%{public}s", __func__,
        isRealMac ? "factory" : "random", MacAnonymize(currentMac).c_str(), MacAnonymize(lastMac).c_str());
    std::string actualConfiguredMac = currentMac;
    if (!isRealMac && instId == 1) {
        if (!WifiRandomMacHelper::GetWifi2RandomMac(actualConfiguredMac)) {
            actualConfiguredMac = realMac;
        }
        LOGI("%{public}s wifi2 actualConfiguredMac: %{public}s", __func__, MacAnonymize(actualConfiguredMac).c_str());
    }
    if (MacAddress::IsValidMac(actualConfiguredMac.c_str())) {
        if (lastMac != actualConfiguredMac) {
            if (WifiStaHalInterface::GetInstance().SetConnectMacAddr(
                WifiConfigCenter::GetInstance().GetStaIfaceName(instId), actualConfiguredMac) != WIFI_HAL_OPT_OK) {
                    LOGE("set Mac [%{public}s] failed", MacAnonymize(actualConfiguredMac).c_str());
                    return false;
                }
        }
        WifiConfigCenter::GetInstance().SetMacAddress(actualConfiguredMac, instId);
        return true;
    } else {
        LOGE("%{public}s randommac, Check MacAddress error", __func__);
        return false;
    }
}

bool StaStateMachine::SetRandomMac(int networkId, const std::string &bssid)
{
    LOGD("enter SetRandomMac.");
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, deviceConfig, m_instId) != 0) {
        LOGE("SetRandomMac : GetDeviceConfig failed!");
        return false;
    }
    std::string currentMac;
    std::string realMac;
    WifiSettings::GetInstance().GetRealMacAddress(realMac, m_instId);
    LOGD("%{public}s realMac is %{public}s", __func__, MacAnonymize(realMac).c_str());
    if (deviceConfig.wifiPrivacySetting == WifiPrivacyConfig::DEVICEMAC || ShouldUseFactoryMac(deviceConfig)) {
        currentMac = realMac;
    } else {
        WifiStoreRandomMac randomMacInfo;
        InitRandomMacInfo(deviceConfig, bssid, randomMacInfo);
        if (randomMacInfo.peerBssid.empty()) {
            LOGE("scanInfo has no target wifi and bssid is empty!");
            return false;
        }
        LOGI("%{public}s randommac, ssid:%{public}s keyMgmt:%{public}s macAddress:%{public}s",
            __func__, SsidAnonymize(deviceConfig.ssid).c_str(), deviceConfig.keyMgmt.c_str(),
            MacAnonymize(deviceConfig.macAddress).c_str());
        if (!MacAddress::IsValidMac(deviceConfig.macAddress) || deviceConfig.macAddress == realMac) {
            WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
            if (MacAddress::IsValidMac(randomMacInfo.randomMac) && randomMacInfo.randomMac != realMac) {
                currentMac = randomMacInfo.randomMac;
            } else {
                SetRandomMacConfig(randomMacInfo, deviceConfig, currentMac);
                WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
            }
        } else if (IsPskEncryption(deviceConfig.keyMgmt)) {
            randomMacInfo.randomMac = deviceConfig.macAddress;
            currentMac = randomMacInfo.randomMac;
            WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
        } else {
            currentMac = deviceConfig.macAddress;
        }
    }
    if (SetMacToHal(currentMac, realMac, m_instId)) {
        deviceConfig.macAddress = currentMac;
        WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        WifiSettings::GetInstance().SyncDeviceConfig();
    } else {
        return false;
    }
#endif
    return true;
}

void StaStateMachine::StartRoamToNetwork(std::string bssid)
{
    InternalMessagePtr msg = CreateMessage();
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
    InternalMessagePtr msg = CreateMessage();
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
    mIsWifiInternetCHRFlag = false;
    WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(false);
    WriteWifiAbnormalDisconnectHiSysEvent(reason);
}

void StaStateMachine::OnNetworkAssocEvent(int assocState, std::string bssid, StaStateMachine *pStaStateMachine)
{
    if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("OnNetworkAssocEvent inconsistent bssid in connecter");
        return;
    }
    if (assocState == HAL_WPA_CB_ASSOCIATING) {
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATING, linkedInfo);
    } else {
        InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATED, linkedInfo);
    }
}

void StaStateMachine::OnNetworkHiviewEvent(int state)
{
    if (state == HAL_WPA_CB_ASSOCIATING) {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
            static_cast<int>(WifiOperateState::STA_ASSOCIATING));
    } else if (state == HAL_WPA_CB_ASSOCIATED) {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
            static_cast<int>(WifiOperateState::STA_ASSOCIATED));
    }
}

void StaStateMachine::OnBssidChangedEvent(std::string reason, std::string bssid)
{
    InternalMessagePtr msg = CreateMessage();
    if (msg == nullptr) {
        LOGE("msg is nullptr.\n");
        return;
    }
    if (strcmp(reason.c_str(), "LINK_SWITCH") == 0) {
        msg->SetMessageName(WIFI_SVR_CMD_STA_LINK_SWITCH_EVENT);
    } else {
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg->AddStringMessageBody(reason);
    }
    msg->AddStringMessageBody(bssid);
    SendMessage(msg);
}

void StaStateMachine::OnDhcpResultNotifyEvent(DhcpReturnCode result, int ipType)
{
    InternalMessagePtr msg = CreateMessage();
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
int32_t StaStateMachine::GetDataSlotId(int32_t slotId)
{
    int32_t simCount = CoreServiceClient::GetInstance().GetMaxSimCount();
    if (slotId >= 0 && slotId < simCount) {
        LOGI("slotId: %{public}d, simCount:%{public}d", slotId, simCount);
        return slotId;
    }
    auto slotDefaultID = CellularDataClient::GetInstance().GetDefaultCellularDataSlotId();
    if (slotDefaultID < 0 || slotDefaultID >= simCount) {
        LOGE("failed to get default slotId, slotId:%{public}d", slotDefaultID);
        return -1;
    }
    LOGI("slotId: %{public}d", slotDefaultID);
    return slotDefaultID;
}

int32_t StaStateMachine::GetCardType(CardType &cardType)
{
    WifiDeviceConfig deviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, deviceConfig, m_instId);
    return CoreServiceClient::GetInstance().GetCardType(GetDataSlotId(deviceConfig.wifiEapConfig.eapSubId),
        cardType);
}

int32_t StaStateMachine::GetDefaultId(int32_t slotId)
{
    LOGI("StaStateMachine::GetDefaultId in, slotId: %{public}d", slotId);
    if (slotId == WIFI_INVALID_SIM_ID) {
        return GetDataSlotId(slotId);
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

bool StaStateMachine::IsMultiSimEnabled()
{
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
    WifiDeviceConfig deviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, deviceConfig, m_instId);
    auto slotId = GetDataSlotId(deviceConfig.wifiEapConfig.eapSubId);
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
            authRsp += std::string(kcBuf) + ":" + std::string(sresBuf);
        } else {
            authRsp += ":" + std::string(kcBuf) + ":" + std::string(sresBuf);
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
            authRsp += std::string(kcBuf) + ":" + std::string(sresBuf);
        } else {
            authRsp += ":" + std::string(kcBuf) + ":" + std::string(sresBuf);
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
        constexpr size_t nonceBufSize = 2 * UMTS_AUTH_RESPONSE_CONTENT_LEN + 1;
        char nonceBuf[nonceBufSize] = { 0 }; // length of auth data
        Byte2HexString(&nonce[0], UMTS_AUTH_RESPONSE_CONTENT_LEN, nonceBuf, sizeof(nonceBuf));
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

void StaStateMachine::DealWpaEapSimAuthEvent(InternalMessagePtr msg)
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
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd) != WIFI_HAL_OPT_OK) {
        LOGI("%{public}s: failed to send the message, authReq: %{private}s", __func__, cmd.c_str());
        return;
    }
    LOGD("%{public}s: success to send the message, authReq: %{private}s", __func__, cmd.c_str());
}

void StaStateMachine::DealWpaEapUmtsAuthEvent(InternalMessagePtr msg)
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
    if (WifiStaHalInterface::GetInstance().ShellCmd("wlan0", reqCmd) != WIFI_HAL_OPT_OK) {
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

bool StaStateMachine::SeparatingState::ExecuteStateMsg(InternalMessagePtr msg)
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

bool StaStateMachine::SeparatedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("SeparatedState-msgCode=%{public}d received. m_instId=%{public}d\n", msg->GetMessageName(),
        pStaStateMachine->GetInstanceId());
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

        case WIFI_SVR_CMD_STA_ENABLE_STA: {
            ret = EXECUTED;
            WIFI_LOGE("Wifi has already started!");
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
    return;
}

void StaStateMachine::ApLinkedState::GoOutState()
{
    WIFI_LOGI("ApLinkedState GoOutState function.");
    return;
}

bool StaStateMachine::ApLinkedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGD("ApLinkedState-msgCode=%{public}d received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->GetInstanceId());
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
            HandleNetWorkConnectionEvent(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT: {
            ret = EXECUTED;
            HandleStaBssidChangedEvent(msg);
            break;
        }
        case WIFI_SVR_CMD_STA_LINK_SWITCH_EVENT:
            ret = EXECUTED;
            HandleLinkSwitchEvent(msg);
            break;
        case CMD_SIGNAL_POLL:
            ret = EXECUTED;
            pStaStateMachine->DealSignalPollResult();
            break;
        default:
            break;
    }
    return ret;
}

void StaStateMachine::ApLinkedState::HandleNetWorkConnectionEvent(InternalMessagePtr msg)
{
    std::string bssid = msg->GetStringFromMessage();
    if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("ApLinkedState inconsistent bssid in connecter");
        return;
    }
    pStaStateMachine->StopTimer(static_cast<int>(WPA_BLOCK_LIST_CLEAR_EVENT));
    WIFI_LOGI("Stop clearing wpa block list");
    /* Save linkedinfo */
    pStaStateMachine->linkedInfo.networkId = pStaStateMachine->targetNetworkId;
    pStaStateMachine->linkedInfo.bssid = bssid;
#ifndef OHOS_ARCH_LITE
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    WifiConfigCenter::GetInstance().SaveLinkedInfo(
        pStaStateMachine->linkedInfo, pStaStateMachine->GetInstanceId());
}

void StaStateMachine::ApLinkedState::HandleStaBssidChangedEvent(InternalMessagePtr msg)
{
    std::string reason = msg->GetStringFromMessage();
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("ApLinkedState reveived bssid changed event, reason:%{public}s,bssid:%{public}s.\n",
        reason.c_str(), MacAnonymize(bssid).c_str());
    if (strcmp(reason.c_str(), "ASSOC_COMPLETE") != 0) {
        WIFI_LOGE("Bssid change not for ASSOC_COMPLETE, do nothing.");
        return;
    }
    pStaStateMachine->linkedInfo.bssid = bssid;
#ifndef OHOS_ARCH_LITE
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->GetInstanceId());
    /* BSSID change is not received during roaming, only set BSSID */
    if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid,
        WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->GetInstanceId())) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("SetBssid return fail.");
    }
}

void StaStateMachine::ApLinkedState::HandleLinkSwitchEvent(InternalMessagePtr msg)
{
    std::string bssid = msg->GetStringFromMessage();
    WIFI_LOGI("%{public}s enter, bssid:%{public}s", __FUNCTION__, MacAnonymize(bssid).c_str());
    pStaStateMachine->linkedInfo.bssid = bssid;
#ifndef OHOS_ARCH_LITE
    pStaStateMachine->SetSupportedWifiCategory();
#endif
    WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo, pStaStateMachine->GetInstanceId());
    pStaStateMachine->DealSignalPollResult();  // update freq info
    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, deviceConfig) != 0) {
        WIFI_LOGE("%{public}s cnanot find config for networkId = %{public}d", __FUNCTION__,
            pStaStateMachine->linkedInfo.networkId);
        return;
    }
    pStaStateMachine->UpdateDeviceConfigAfterWifiConnected(deviceConfig, bssid);
}

void StaStateMachine::DisConnectProcess()
{
    WIFI_LOGI("Enter DisConnectProcess m_instId:%{public}d!", m_instId);
    InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECTING, linkedInfo);
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().Disconnect(ifaceName) == WIFI_HAL_OPT_OK) {
        WIFI_LOGI("Disconnect() succeed!");
        if (m_instId == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
            if (NetSupplierInfo != nullptr) {
                NetSupplierInfo->isAvailable_ = false;
                NetSupplierInfo->ident_ = "";
                WIFI_LOGI("Disconnect process update netsupplierinfo");
                WifiNetAgent::GetInstance().OnStaMachineUpdateNetSupplierInfo(NetSupplierInfo);
            }
#endif
        }
        WIFI_LOGI("Disconnect update wifi status");
        /* Save connection information to WifiSettings. */
        SaveLinkstate(ConnState::DISCONNECTED, DetailedState::DISCONNECTED);
        WIFI_LOGI("Enter DisConnectProcess DisableNetwork ifaceName:%{public}s!", ifaceName.c_str());
        WifiStaHalInterface::GetInstance().DisableNetwork(WPA_DEFAULT_NETWORKID, ifaceName);

        getIpSucNum = 0;
        /* The current state of StaStateMachine transfers to SeparatedState. */
        SwitchState(pSeparatedState);
    } else {
        SaveLinkstate(ConnState::DISCONNECTING, DetailedState::FAILED);
        InvokeOnStaConnChanged(OperateResState::DISCONNECT_DISCONNECT_FAILED, linkedInfo);
        WIFI_LOGE("Disconnect() failed m_instId:%{public}d!", m_instId);
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

bool StaStateMachine::StaWpsState::ExecuteStateMsg(InternalMessagePtr msg)
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
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    DhcpErrorCode dhcpRet = RegisterDhcpClientCallBack(ifname.c_str(), &clientCallBack);
    if (dhcpRet != DHCP_SUCCESS) {
        WIFI_LOGE("RegisterDhcpClientCallBack failed. dhcpRet=%{public}d", dhcpRet);
        return DHCP_FAILED;
    }
    dhcpClientReport_.OnDhcpClientReport = DhcpResultNotify::OnDhcpOfferResult;
    RegisterDhcpClientReportCallBack(ifname.c_str(), &dhcpClientReport_);
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
    WIFI_LOGI("GetIpState GoInState function. m_instId=%{public}d", pStaStateMachine->GetInstanceId());
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
    int ret = WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config,
        pStaStateMachine->GetInstanceId());
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
    pStaStateMachine->HandlePreDhcpSetup();
    do {
        int result = pStaStateMachine->RegisterCallBack();
        if (result != DHCP_SUCCESS) {
            WIFI_LOGE("RegisterCallBack failed!");
            break;
        }
        int dhcpRet;
        std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->GetInstanceId());
        pStaStateMachine->currentTpType = static_cast<int>(WifiSettings::GetInstance().GetDhcpIpType());

        RouterConfig config;
        if (strncpy_s(config.bssid, sizeof(config.bssid),
            pStaStateMachine->linkedInfo.bssid.c_str(), pStaStateMachine->linkedInfo.bssid.size()) == EOK) {
            config.prohibitUseCacheIp = IsProhibitUseCacheIp();
            SetConfiguration(ifname.c_str(), config);
        }

        if (pStaStateMachine->currentTpType == IPTYPE_IPV4) {
            dhcpRet = StartDhcpClient(ifname.c_str(), false);
        } else {
            dhcpRet = StartDhcpClient(ifname.c_str(), true);
        }
        LOGI("StartDhcpClient type:%{public}d dhcpRet:%{public}d isRoam:%{public}d m_instId=%{public}d",
            pStaStateMachine->currentTpType, dhcpRet, pStaStateMachine->isRoam, pStaStateMachine->GetInstanceId());
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
    pStaStateMachine->HandlePostDhcpSetup();
}

bool StaStateMachine::GetIpState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    bool ret = NOT_EXECUTED;
    WIFI_LOGI("GetIpState-msgCode=%{public}d received. m_instId = %{public}d\n", msg->GetMessageName(),
        pStaStateMachine->GetInstanceId());
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT: {
            ret = EXECUTED;
            int result = msg->GetParam1();
            int ipType = msg->GetParam2();
            WIFI_LOGI("GetIpState, get ip result:%{public}d, ipType = %{public}d, m_instId = %{public}d\n",
                result, ipType, pStaStateMachine->GetInstanceId());
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
                case DhcpReturnCode::DHCP_OFFER_REPORT: {
                    pStaStateMachine->pDhcpResultNotify->DealDhcpOfferResult();
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
        pStaStateMachine->GetInstanceId());
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
        pStaStateMachine->linkedInfo.rssi, pStaStateMachine->linkedInfo.band, pStaStateMachine->GetInstanceId());
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
    if (mPortalUrl.empty()) {
        WIFI_LOGE("portal uri is nullptr\n");
    }
    if (!m_NetWorkState) {
        WIFI_LOGE("m_NetWorkState is nullptr\n");
        return;
    }
    int netId = m_NetWorkState->GetWifiNetId();
    std::string bundle;
    std::map<std::string, std::string> variableMap;
    if (WifiSettings::GetInstance().GetVariableMap(variableMap) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetVariableMap failed");
    }
    if (variableMap.find("BROWSER_BUNDLE") != variableMap.end()) {
        bundle = variableMap["BROWSER_BUNDLE"];
    }
    AAFwk::Want want;
    want.SetAction(PORTAL_ACTION);
    want.SetUri(mPortalUrl);
    want.AddEntity(PORTAL_ENTITY);
    want.SetBundle(bundle);
    want.SetParam("netId", netId);
    WIFI_LOGI("wifi netId is %{public}d", netId);
    OHOS::ErrCode err = WifiNotificationUtil::GetInstance().StartAbility(want);
    if (err != ERR_OK) {
        WIFI_LOGI("StartAbility is failed %{public}d", err);
        WriteBrowserFailedForPortalHiSysEvent(err, mPortalUrl);
    }
#endif
}

void StaStateMachine::SetPortalBrowserFlag(bool flag)
{
    portalFlag = flag;
    mIsWifiInternetCHRFlag = false;
    WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(false);
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
        std::map<std::string, std::string> variableMap;
        std::string bundle;
        if (WifiSettings::GetInstance().GetVariableMap(variableMap) != 0) {
            WIFI_LOGE("WifiSettings::GetInstance().GetVariableMap failed");
        }
        if (variableMap.find("SETTINGS") != variableMap.end()) {
            bundle = variableMap["SETTINGS"];
        }
        if (WifiAppStateAware::GetInstance().IsForegroundApp(bundle)) {
            WifiNotificationUtil::GetInstance().PublishWifiNotification(
                WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID, linkedInfo.ssid,
                WifiNotificationStatus::WIFI_PORTAL_CONNECTED);
            portalFlag = false;
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
            WritePortalAuthExpiredHisysevent(static_cast<int>(SystemNetWorkState::NETWORK_IS_PORTAL),
                detectNum, config.lastConnectTime, config.portalAuthTime, false);
        }
    }
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
}

void StaStateMachine::NetStateObserverCallback(SystemNetWorkState netState, std::string url)
{
    SendMessage(WIFI_SVR_CMD_STA_NET_DETECTION_NOTIFY_EVENT, netState, 0, url);
}

void StaStateMachine::HandleNetCheckResult(SystemNetWorkState netState, const std::string &portalUrl)
{
    WIFI_LOGD("Enter HandleNetCheckResult, netState:%{public}d screen:%{public}d "
        "oldPortalState:%{public}d chrFlag:%{public}d.",
        netState, enableSignalPoll, portalState, mIsWifiInternetCHRFlag);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGE("connState is NOT in connected state, connState:%{public}d\n", linkedInfo.connState);
        WriteIsInternetHiSysEvent(NO_NETWORK);
        return;
    }
    if (!portalUrl.empty()) {
        mPortalUrl = portalUrl;
    }
    bool updatePortalAuthTime = false;
    if (netState == SystemNetWorkState::NETWORK_IS_WORKING) {
        mIsWifiInternetCHRFlag = false;
        UpdatePortalState(netState, updatePortalAuthTime);
        /* Save connection information to WifiSettings. */
        WriteIsInternetHiSysEvent(NETWORK);
        WritePortalStateHiSysEvent(portalFlag ? HISYS_EVENT_PROTAL_STATE_PORTAL_VERIFIED
                                              : HISYS_EVENT_PROTAL_STATE_NOT_PORTAL);
        WifiConfigCenter::GetInstance().SetWifiSelfcureResetEntered(false);
        SaveLinkstate(ConnState::CONNECTED, DetailedState::WORKING);
        InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_ENABLED, linkedInfo);
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::HAS_INTERNET, updatePortalAuthTime);
        if (getCurrentWifiDeviceConfig().isPortal) {
            StartDetectTimer(DETECT_TYPE_PERIODIC);
        }
        mPortalUrl = "";
#ifndef OHOS_ARCH_LITE
        UpdateAcceptUnvalidatedState();
        WifiNotificationUtil::GetInstance().CancelWifiNotification(
            WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID);
#endif
    } else if (netState == SystemNetWorkState::NETWORK_IS_PORTAL) {
        WifiLinkedInfo linkedInfo;
        GetLinkedInfo(linkedInfo);
        UpdatePortalState(netState, updatePortalAuthTime);
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
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::PORTAL, false);
    } else {
        WriteIsInternetHiSysEvent(NO_NETWORK);
#ifndef OHOS_ARCH_LITE
        SyncDeviceEverConnectedState(false);
#endif
        if (!mIsWifiInternetCHRFlag &&
            (portalState == PortalState::UNCHECKED || portalState == PortalState::NOT_PORTAL) &&
            WifiConfigCenter::GetInstance().GetWifiSelfcureResetEntered()) {
            const int httpOpt = 1;
            WriteWifiAccessIntFailedHiSysEvent(httpOpt, StaDnsState::DNS_STATE_UNREACHABLE);
            mIsWifiInternetCHRFlag = true;
        }
        SaveLinkstate(ConnState::CONNECTED, DetailedState::NOTWORKING);
        InvokeOnStaConnChanged(OperateResState::CONNECT_NETWORK_DISABLED, linkedInfo);
        InsertOrUpdateNetworkStatusHistory(NetworkStatus::NO_INTERNET, false);
    }
#ifndef OHOS_ARCH_LITE
    SyncDeviceEverConnectedState(true);
#endif
    portalFlag = true;
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::SyncDeviceEverConnectedState(bool hasNet)
{
    if (IsFactoryMode()) {
        WIFI_LOGI("factory version, no need to pop up diag");
        return;
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    std::map<std::string, std::string> variableMap;
    std::string settings;
    if (WifiSettings::GetInstance().GetVariableMap(variableMap) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetVariableMap failed");
    }
    if (variableMap.find("SETTINGS") != variableMap.end()) {
        settings = variableMap["SETTINGS"];
    }
    if (!WifiSettings::GetInstance().GetDeviceEverConnected(networkId)) {
        if (!hasNet) {
            /*If it is the first time to connect and no network status, a pop-up window is displayed.*/
            WifiNotificationUtil::GetInstance().ShowSettingsDialog(WifiDialogType::CDD, settings);
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
    WIFI_LOGI("LinkedState GoInState function. m_instId = %{public}d", pStaStateMachine->GetInstanceId());
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
        static_cast<int>(WifiOperateState::STA_CONNECTED));
    if (pStaStateMachine->GetInstanceId() == INSTID_WLAN0) {
#ifndef OHOS_ARCH_LITE
        if (pStaStateMachine != nullptr && pStaStateMachine->m_NetWorkState != nullptr) {
            pStaStateMachine->m_NetWorkState->StartNetStateObserver(pStaStateMachine->m_NetWorkState);
            pStaStateMachine->lastTimestamp = 0;
            pStaStateMachine->StartDetectTimer(DETECT_TYPE_DEFAULT);
        }
#endif
    }
    WifiSettings::GetInstance().SetDeviceAfterConnect(pStaStateMachine->linkedInfo.networkId);
    WifiSettings::GetInstance().ClearAllNetworkConnectChoice();
    WifiSettings::GetInstance().SetDeviceState(pStaStateMachine->linkedInfo.networkId,
        static_cast<int32_t>(WifiDeviceConfigStatus::ENABLED), false);
    WifiSettings::GetInstance().SyncDeviceConfig();
    pStaStateMachine->SaveDiscReason(DisconnectedReason::DISC_REASON_DEFAULT);
    pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, pStaStateMachine->linkedInfo);
    return;
}

void StaStateMachine::LinkedState::GoOutState()
{
    WIFI_LOGI("LinkedState GoOutState function.");
}

void StaStateMachine::LinkedState::DhcpResultNotify(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is nullptr.");
        return;
    }
    int result = msg->GetParam1();
    int ipType = msg->GetParam2();
    WIFI_LOGI("LinkedState, result:%{public}d, ipType = %{public}d\n", result, ipType);
    if (result == DhcpReturnCode::DHCP_RENEW_FAIL) {
        pStaStateMachine->StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    } else if (result == DhcpReturnCode::DHCP_RESULT) {
        pStaStateMachine->pDhcpResultNotify->DealDhcpResult(ipType);
    } else if (result == DhcpReturnCode::DHCP_IP_EXPIRED) {
        pStaStateMachine->DisConnectProcess();
    } else if (result == DhcpReturnCode::DHCP_OFFER_REPORT) {
        pStaStateMachine->pDhcpResultNotify->DealDhcpOfferResult();
    }
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
    WIFI_LOGI("netdetection, netstate:%{public}d url:%{private}s\n", netstate, url.c_str());
    pStaStateMachine->HandleNetCheckResult(netstate, url);
}

bool StaStateMachine::LinkedState::ExecuteStateMsg(InternalMessagePtr msg)
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
            std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->GetInstanceId());
            if (WifiStaHalInterface::GetInstance().SetBssid(WPA_DEFAULT_NETWORKID, bssid, ifaceName)
                != WIFI_HAL_OPT_OK) {
                WIFI_LOGE("SetBssid return fail.");
                return false;
            }
            pStaStateMachine->isRoam = true;
            pStaStateMachine->linkedInfo.bssid = bssid;
#ifndef OHOS_ARCH_LITE
            pStaStateMachine->UpdateWifiCategory();
            pStaStateMachine->SetSupportedWifiCategory();
#endif
            WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo,
                pStaStateMachine->GetInstanceId());
            /* The current state of StaStateMachine transfers to pApRoamingState. */
            pStaStateMachine->SwitchState(pStaStateMachine->pApRoamingState);
            break;
        }
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
            WIFI_LOGI("LinkedState, recv StartPortalCertification!");
            pStaStateMachine->HandlePortalNetworkPorcess();
            break;
        }
        default:
            WIFI_LOGD("NOT handle this event!");
            break;
    }

    return ret;
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

void StaStateMachine::DealApRoamingStateTimeout(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        LOGE("DealApRoamingStateTimeout InternalMessage msg is null.");
        return;
    }
    LOGI("DealApRoamingStateTimeout StopTimer aproaming timer");
    StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
    DisConnectProcess();
}

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
        LOGE("DealHiLinkDataToWpa InternalMessage msg is null.");
        return;
    }
    WIFI_LOGI("DealHiLinkDataToWpa=%{public}d received.\n", msg->GetMessageName());
    switch (msg->GetMessageName()) {
        case WIFI_SVR_COM_STA_ENABLE_HILINK: {
            m_hilinkDeviceConfig.bssidType = msg->GetParam1();
            m_hilinkDeviceConfig.ssid = msg->GetStringFromMessage();
            m_hilinkDeviceConfig.bssid = msg->GetStringFromMessage();
            m_hilinkDeviceConfig.keyMgmt = msg->GetStringFromMessage();
            std::string cmd = msg->GetStringFromMessage();
            LOGI("DealEnableHiLinkHandshake start shell cmd = %{public}s", MacAnonymize(cmd).c_str());
            WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd);
            break;
        }
        case WIFI_SVR_COM_STA_HILINK_DELIVER_MAC: {
            std::string cmd;
            msg->GetMessageObj(cmd);
            HilinkSetMacAddress(cmd);
            LOGI("DealHiLinkMacDeliver start shell cmd, cmd = %{public}s", MacAnonymize(cmd).c_str());
            WifiStaHalInterface::GetInstance().ShellCmd("wlan0", cmd);
            break;
        }
        case WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS: {
            LOGI("DealHiLinkTriggerWps start ClearDeviceConfig");
            WifiStaHalInterface::GetInstance().ClearDeviceConfig(
                WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId));

            LOGI("DealHiLinkTriggerWps SPECIAL_CONNECTED");
            InvokeOnStaConnChanged(OperateResState::SPECIAL_CONNECTED, linkedInfo);

            LOGI("DealHiLinkTriggerWps start startWpsPbc");
            std::string bssid;
            msg->GetMessageObj(bssid);
            WifiHalWpsConfig config;
            config.anyFlag = 0;
            config.multiAp = 0;
            config.bssid = bssid;
            WifiStaHalInterface::GetInstance().StartWpsPbcMode(config);
            m_hilinkFlag = true;
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

void StaStateMachine::DealNetworkRemoved(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("DealNetworkRemoved InternalMessage msg is null.");
        return;
    }
    int networkId = 0;
    networkId = msg->GetParam1();
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    WIFI_LOGI("DealNetworkRemoved networkid = %{public}d linkinfo.networkid = %{public}d targetNetworkId = %{public}d",
        networkId, linkedInfo.networkId, targetNetworkId);
    if ((linkedInfo.networkId == networkId) ||
        ((targetNetworkId == networkId) && (linkedInfo.connState == ConnState::CONNECTING))) {
        std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
        WIFI_LOGI("Enter DisConnectProcess ifaceName:%{public}s!", ifaceName.c_str());
        WifiStaHalInterface::GetInstance().Disconnect(ifaceName);
    }
 
    return;
}

void StaStateMachine::DealCsaChannelChanged(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        LOGE("%{public}s InternalMessage msg is null", __FUNCTION__);
        return;
    }
    int newFreq = msg->GetParam1();
    WIFI_LOGI("%{public}s update freq from %{public}d to %{public}d", __FUNCTION__, linkedInfo.frequency, newFreq);
    linkedInfo.frequency = newFreq;
    // trigger wifi connection broadcast to notify sta channel has changed for p2penhance
    InvokeOnStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, linkedInfo);
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

bool StaStateMachine::ApRoamingState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return false;
    }

    WIFI_LOGI("ApRoamingState, reveived msgCode=%{public}d msg. m_instId = %{public}d",
        msg->GetMessageName(), pStaStateMachine->GetInstanceId());
    bool ret = NOT_EXECUTED;
    switch (msg->GetMessageName()) {
        case WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT: {
            WIFI_LOGI("ApRoamingState, receive WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT event.");
            ret = HandleNetworkConnectionEvent(msg);
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

bool StaStateMachine::ApRoamingState::HandleNetworkConnectionEvent(InternalMessagePtr msg)
{
    bool ret = EXECUTED;
    std::string bssid = msg->GetStringFromMessage();
    if (pStaStateMachine->CheckRoamingBssidIsSame(bssid)) {
        WIFI_LOGE("ApRoamingState inconsistent bssid in connecter m_instId = %{public}d",
            pStaStateMachine->GetInstanceId());
        ret = NOT_EXECUTED;
    }
    pStaStateMachine->isRoam = true;
    pStaStateMachine->StopTimer(static_cast<int>(CMD_AP_ROAMING_TIMEOUT_CHECK));
    pStaStateMachine->StopTimer(static_cast<int>(CMD_NETWORK_CONNECT_TIMEOUT));
    pStaStateMachine->ConnectToNetworkProcess(bssid);
    /* Notify result to InterfaceService. */
    pStaStateMachine->InvokeOnStaConnChanged(OperateResState::CONNECT_ASSOCIATED,
        pStaStateMachine->linkedInfo);
    if (pStaStateMachine->GetInstanceId() == INSTID_WLAN0) {
        if (!pStaStateMachine->CanArpReachable()) {
            WIFI_LOGI("Arp is not reachable");
            WriteWifiSelfcureHisysevent(static_cast<int>(WifiSelfcureType::ROAMING_ABNORMAL));
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
    } else {
        pStaStateMachine->SwitchState(pStaStateMachine->pLinkedState);
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
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) != 0) {
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

void StaStateMachine::GetDeviceCfgInfo(const std::string &bssid, WifiDeviceConfig &deviceConfig)
{
    WifiHalGetDeviceConfig config;
    config.networkId = WPA_DEFAULT_NETWORKID;
    config.param = "ssid";
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().GetDeviceConfig(config, ifaceName) != WIFI_HAL_OPT_OK) {
        WIFI_LOGI("GetDeviceConfig failed!");
    }
    deviceConfig.networkId = WPA_DEFAULT_NETWORKID;
    deviceConfig.bssid = bssid;
    deviceConfig.ssid = config.value;
    /* Remove the double quotation marks at the head and tail. */
    deviceConfig.ssid.erase(0, 1);
    if (!deviceConfig.ssid.empty()) {
        deviceConfig.ssid.erase(deviceConfig.ssid.length() - 1, 1);
    }
}

void StaStateMachine::ConnectToNetworkProcess(std::string bssid)
{
    WIFI_LOGI("ConnectToNetworkProcess, Receive bssid=%{public}s m_instId = %{public}d",
        MacAnonymize(bssid).c_str(), m_instId);
    if ((wpsState == SetupMethod::DISPLAY) || (wpsState == SetupMethod::PBC) || (wpsState == SetupMethod::KEYPAD)) {
        targetNetworkId = WPA_DEFAULT_NETWORKID;
    }

    WifiDeviceConfig deviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, deviceConfig, m_instId) != 0) {
        WIFI_LOGE("%{public}s cnanot find config for networkId = %{public}d", __FUNCTION__, targetNetworkId);
    }
    LOGI("%{public}s: networkId: %{public}d, ssid: %{public}s, keyMgmt: %{public}s, preSharedKeyLen:%{public}d",
        __FUNCTION__, deviceConfig.networkId, SsidAnonymize(deviceConfig.ssid).c_str(), deviceConfig.keyMgmt.c_str(),
        static_cast<int>(deviceConfig.preSharedKey.length()));
    UpdateDeviceConfigAfterWifiConnected(deviceConfig, bssid);

    std::string macAddr;
    std::string realMacAddr;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddr, m_instId);
    WifiSettings::GetInstance().GetRealMacAddress(realMacAddr, m_instId);
    linkedInfo.networkId = targetNetworkId;
    linkedInfo.bssid = bssid;
#ifndef OHOS_ARCH_LITE
    SetSupportedWifiCategory();
#endif
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

    lastSignalLevel_ = INVALID_SIGNAL_LEVEL;   // Reset signal level when first start signal poll
    DealSignalPollResult();
    SaveLinkstate(ConnState::CONNECTING, DetailedState::OBTAINING_IPADDR);
}

void StaStateMachine::UpdateDeviceConfigAfterWifiConnected(WifiDeviceConfig &deviceConfig, const std::string &bssid)
{
    if (deviceConfig.bssid == bssid) {
        LOGI("Device Configuration already exists.");
    } else {
        deviceConfig.bssid = bssid;
        if ((wpsState == SetupMethod::DISPLAY) || (wpsState == SetupMethod::PBC) || (wpsState == SetupMethod::KEYPAD)) {
            /* Save connection information. */
            GetDeviceCfgInfo(bssid, deviceConfig);
            WifiSettings::GetInstance().AddWpsDeviceConfig(deviceConfig);
            isWpsConnect = IsWpsConnected::WPS_CONNECTED;
        } else {
            WifiSettings::GetInstance().AddDeviceConfig(deviceConfig);
        }
        WifiSettings::GetInstance().SyncDeviceConfig();
        WIFI_LOGD("Device ssid = %s", SsidAnonymize(deviceConfig.ssid).c_str());
    }
}

void StaStateMachine::SetWifiLinkedInfo(int networkId)
{
    WIFI_LOGI("SetWifiLinkedInfo, linkedInfo.networkId=%{public}d, lastLinkedInfo.networkId=%{public}d",
        linkedInfo.networkId, lastLinkedInfo.networkId);
    if (linkedInfo.networkId == INVALID_NETWORK_ID) {
        if (lastLinkedInfo.networkId != INVALID_NETWORK_ID) {
            /* Update connection information according to the last connecting information. */
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
            linkedInfo.networkId = networkId;
            WifiDeviceConfig config;
            int ret = WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId);
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

void StaStateMachine::DealNetworkCheck(InternalMessagePtr msg)
{
    LOGD("enter DealNetworkCheck.\n");
    if (msg == nullptr || enableSignalPoll == false) {
        LOGE("detection screen state [%{public}d].", enableSignalPoll);
        return;
    }
#ifndef OHOS_ARCH_LITE
    if (m_NetWorkState) {
        m_NetWorkState->StartWifiDetection();
    }
#endif
}

void StaStateMachine::DealGetDhcpIpTimeout(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        LOGE("DealGetDhcpIpTimeout InternalMessage msg is null.");
        return;
    }
    LOGI("StopTimer CMD_START_GET_DHCP_IP_TIMEOUT DealGetDhcpIpTimeout");
    BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId,
                                                                 DisabledReason::DISABLED_DHCP_FAILURE);
    StopTimer(static_cast<int>(CMD_START_GET_DHCP_IP_TIMEOUT));
    DisConnectProcess();
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
        != WIFI_HAL_OPT_OK) {
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
DhcpResult StaStateMachine::DhcpResultNotify::DhcpOfferInfo;

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

void StaStateMachine::DhcpResultNotify::OnDhcpOfferResult(int status, const char *ifname, DhcpResult *result)
{
    LOGI("DhcpResultNotify TYPE_DHCP_OFFER");
    StaStateMachine::DhcpResultNotify::SaveDhcpResult(&DhcpOfferInfo, result);
    pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_OFFER_REPORT, result->iptype);
}

void StaStateMachine::DhcpResultNotify::DealDhcpResult(int ipType)
{
    DhcpResult *result = nullptr;
    IpInfo ipInfo;
    IpV6Info ipv6Info;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, pStaStateMachine->GetInstanceId());
    WifiConfigCenter::GetInstance().GetIpv6Info(ipv6Info, pStaStateMachine->GetInstanceId());
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
    LOGI("DhcpResultNotify OnSuccess, uLeaseTime=%{public}d %{public}d %{public}d m_instId = %{public}d",
        result->uOptLeasetime, assignMethod, pStaStateMachine->currentTpType, pStaStateMachine->GetInstanceId());
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
    WifiConfigCenter::GetInstance().SaveIpInfo(ipInfo);
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
            WifiConfigCenter::GetInstance().SaveLinkedInfo(pStaStateMachine->linkedInfo);
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
        (ipv6Info.gateway != result->strOptRouter1) || (ipv6Info.linkIpV6Address != result->strOptLinkIpv6Addr)) {
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
        WifiConfigCenter::GetInstance().SaveIpV6Info(ipv6Info, pStaStateMachine->GetInstanceId());
        WIFI_LOGI("SaveIpV6 addr=%{private}s, linkaddr=%{private}s, randaddr=%{private}s, gateway=%{private}s, "
            "mask=%{private}s, dns=%{private}s, dns2=%{private}s",
            ipv6Info.globalIpV6Address.c_str(), ipv6Info.linkIpV6Address.c_str(),
            ipv6Info.randGlobalIpV6Address.c_str(), ipv6Info.gateway.c_str(), ipv6Info.netmask.c_str(),
            ipv6Info.primaryDns.c_str(), ipv6Info.secondDns.c_str());
#ifndef OHOS_ARCH_LITE
        WifiDeviceConfig config;
        WifiSettings::GetInstance().GetDeviceConfig(pStaStateMachine->linkedInfo.networkId, config);
        if (!ipv6Info.primaryDns.empty()) {
            WifiNetAgent::GetInstance().OnStaMachineUpdateNetLinkInfo(ipInfo, ipv6Info, config.wifiProxyconfig,
                pStaStateMachine->GetInstanceId());
        }
#endif
    } else {
        LOGI("TryToSaveIpV6Result not UpdateNetLinkInfo");
    }
}

void StaStateMachine::DhcpResultNotify::TryToCloseDhcpClient(int iptype)
{
    std::string ifname = WifiConfigCenter::GetInstance().GetStaIfaceName(pStaStateMachine->m_instId);
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
    if (status == DHCP_LEASE_EXPIRED) {
        pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_IP_EXPIRED);
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

void StaStateMachine::DhcpResultNotify::DealDhcpOfferResult()
{
    LOGI("DhcpResultNotify DealDhcpOfferResult enter");
    IpInfo ipInfo;
    ipInfo.ipAddress = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptClientId);
    ipInfo.gateway = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptRouter1);
    ipInfo.netmask = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptSubnet);
    ipInfo.primaryDns = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptDns1);
    ipInfo.secondDns = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptDns2);
    ipInfo.serverIp = IpTools::ConvertIpv4Address(DhcpOfferInfo.strOptServerId);
    ipInfo.leaseDuration = DhcpOfferInfo.uOptLeasetime;
    if (DhcpOfferInfo.dnsList.dnsNumber > 0) {
        ipInfo.dnsAddr.clear();
        for (uint32_t i = 0; i < DhcpOfferInfo.dnsList.dnsNumber; i++) {
            uint32_t ipv4Address = IpTools::ConvertIpv4Address(DhcpOfferInfo.dnsList.dnsAddr[i]);
            ipInfo.dnsAddr.push_back(ipv4Address);
        }
    }

    pStaStateMachine->InvokeOnDhcpOfferReport(ipInfo);
}
/* ------------------ state machine Comment function ----------------- */
void StaStateMachine::SaveDiscReason(DisconnectedReason discReason)
{
    WifiConfigCenter::GetInstance().SaveDisconnectedReason(discReason, m_instId);
}

void StaStateMachine::SaveLinkstate(ConnState state, DetailedState detailState)
{
    linkedInfo.connState = state;
    linkedInfo.detailedState = detailState;
    lastLinkedInfo.connState = state;
    lastLinkedInfo.detailedState = detailState;
    linkedInfo.isAncoConnected = WifiConfigCenter::GetInstance().GetWifiConnectedMode(m_instId);
    lastLinkedInfo.isAncoConnected = linkedInfo.isAncoConnected;
    WifiConfigCenter::GetInstance().SaveLinkedInfo(linkedInfo, m_instId);
}

int StaStateMachine::GetLinkedInfo(WifiLinkedInfo& linkedInfo)
{
    return WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
}

void StaStateMachine::SetOperationalMode(int mode)
{
    SendMessage(WIFI_SVR_CMD_STA_OPERATIONAL_MODE, mode, 0);
}

#ifndef OHOS_ARCH_LITE
void StaStateMachine::OnNetManagerRestart(void)
{
    LOGI("OnNetManagerRestart()");
    if (m_instId == INSTID_WLAN0) {
        WifiNetAgent::GetInstance().OnStaMachineNetManagerRestart(NetSupplierInfo, m_instId);
    }
}

void StaStateMachine::ReUpdateNetLinkInfo(const WifiDeviceConfig &config)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    LOGI("ReUpdateNetLinkInfo, detailedState:%{public}d, connState:%{public}d",
        linkedInfo.detailedState, linkedInfo.connState);
    if ((linkedInfo.connState == ConnState::CONNECTED) && (linkedInfo.ssid == config.ssid) &&
        (linkedInfo.bssid == config.bssid)) {
        IpInfo wifiIpInfo;
        WifiConfigCenter::GetInstance().GetIpInfo(wifiIpInfo, m_instId);
        IpV6Info wifiIpV6Info;
        WifiConfigCenter::GetInstance().GetIpv6Info(wifiIpV6Info, m_instId);
        WifiDeviceConfig config;
        WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config, m_instId);
        if (m_instId == INSTID_WLAN0) {
            WifiNetAgent::GetInstance().UpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, config.wifiProxyconfig, m_instId);
        }
    }
}

void StaStateMachine::SaveWifiConfigForUpdate(int networkId)
{
    WIFI_LOGI("Enter SaveWifiConfigForUpdate.");
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config, m_instId) == -1) {
        WIFI_LOGE("SaveWifiConfigForUpdate, get current config failed.");
        return;
    }
}
#endif

void StaStateMachine::HandlePreDhcpSetup()
{
    WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(false);
    WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(false);
}

void StaStateMachine::HandlePostDhcpSetup()
{
    WifiSupplicantHalInterface::GetInstance().WpaSetPowerMode(true);
    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    WifiSupplicantHalInterface::GetInstance().WpaSetSuspendMode(screenState == MODE_STATE_CLOSE);
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
    if (networkStatus == NetworkStatus::NO_INTERNET) {
        wifiDeviceConfig.noInternetAccess = true;
    }
    WifiSettings::GetInstance().AddDeviceConfig(wifiDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
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

bool StaStateMachine::IsGoodSignalQuality()
{
    const WifiLinkedInfo singalInfo = linkedInfo;
    bool isGoodSignal = true;
    if (WifiChannelHelper::GetInstance().IsValid5GHz(singalInfo.frequency)) {
        if (singalInfo.rssi <= RSSI_LEVEL_1_5G) {
            isGoodSignal = false;
        }
    } else {
        if (singalInfo.rssi <= RSSI_LEVEL_1_2G) {
            isGoodSignal = false;
        }
    }
    if (singalInfo.chload >= MAX_CHLOAD) {
        isGoodSignal = false;
    }
    return isGoodSignal;
}
#ifndef OHOS_ARCH_LITE
void StaStateMachine::UpdateWifiCategory()
{
    WIFI_LOGI("UpdateWifiCategory");
    std::vector<InterScanInfo> scanInfos;
    if (WifiStaHalInterface::GetInstance().QueryScanInfos(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), scanInfos) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("WifiStaHalInterface::GetInstance().GetScanInfos failed.");
    }
    int chipsetCategory = static_cast<int>(WifiCategory::DEFAULT);
    if (WifiStaHalInterface::GetInstance().GetChipsetCategory(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), chipsetCategory) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("GetChipsetCategory failed.\n");
    }
    int chipsetFeatrureCapability = 0;
    if (WifiStaHalInterface::GetInstance().GetChipsetWifiFeatrureCapability(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), chipsetFeatrureCapability) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("GetChipsetWifiFeatrureCapability failed.\n");
    }
    if (enhanceService_ != nullptr) {
        for (auto iter = scanInfos.begin(); iter != scanInfos.end(); iter++) {
            WifiCategory category = enhanceService_->GetWifiCategory(iter->infoElems,
                chipsetCategory, chipsetFeatrureCapability);
            WifiConfigCenter::GetInstance().GetWifiScanConfig()->RecordWifiCategory(iter->bssid, category);
        }
    }
}

void StaStateMachine::SetSupportedWifiCategory()
{
    if (m_instId != 0) {
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
            WifiConfigCenter::GetInstance().GetStaIfaceName(), chipsetFeatrureCapability) != WIFI_HAL_OPT_OK) {
            WIFI_LOGE("%{public}s GetChipsetWifiFeatrureCapability failed.", __FUNCTION__);
            return;
        }
        if (static_cast<unsigned int>(chipsetFeatrureCapability) & BIT_MLO_CONNECT) {
            WIFI_LOGD("%{public}s MLO linked", __FUNCTION__);
            linkedInfo.isMloConnected = true;
        } else {
            linkedInfo.isMloConnected = false;
        }
    }
    WIFI_LOGI("%{public}s supportedWifiCategory:%{public}d, isMloConnected:%{public}d", __FUNCTION__,
        static_cast<int>(linkedInfo.supportedWifiCategory), linkedInfo.isMloConnected);
}

void StaStateMachine::SetEnhanceService(IEnhanceService* enhanceService)
{
    enhanceService_ = enhanceService;
}
#endif
} // namespace Wifi
} // namespace OHOS
