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

#include "self_cure_service.h"
#include "self_cure_service_callback.h"
#include "self_cure_utils.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "ip_qos_monitor.h"

DEFINE_WIFILOG_LABEL("SelfCureService");

namespace OHOS {
namespace Wifi {
inline constexpr int32_t P2P_ENHANCE_BC_CONNECT_SUCC = 4;
inline constexpr int32_t P2P_ENHANCE_BC_DESTROYED = 10;
SelfCureService::SelfCureService(int instId) : pSelfCureStateMachine(nullptr), m_instId(instId)
{
    WIFI_LOGI("SelfCureService::SelfCureService()");
    RegisterP2pEnhanceCallback();
}

SelfCureService::~SelfCureService()
{
    WIFI_LOGI("SelfCureService::~SelfCureService");
    if (pSelfCureStateMachine != nullptr) {
        delete pSelfCureStateMachine;
        pSelfCureStateMachine = nullptr;
    }
    SelfCureUtils::GetInstance().UnRegisterDnsResultCallback();
}

ErrCode SelfCureService::InitSelfCureService()
{
    WIFI_LOGI("Enter InitSelfCureService.\n");
    pSelfCureStateMachine = new (std::nothrow) SelfCureStateMachine(m_instId);
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("Alloc pSelfCureStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pSelfCureStateMachine->Initialize() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitSelfCureStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    SelfCureUtils::GetInstance().RegisterDnsResultCallback();
    return WIFI_OPT_SUCCESS;
}

void SelfCureService::HandleRssiLevelChanged(int rssi)
{
    WIFI_LOGD("HandleRssiLevelChanged, %{public}d.\n", rssi);
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    InternalMessagePtr msg = pSelfCureStateMachine->CreateMessage();
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return;
    }
    msg->SetMessageName(WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT);
    msg->SetParam1(rssi);
    pSelfCureStateMachine->SendMessage(msg);
}

void SelfCureService::SetTxRxGoodButNoInternet(bool isTxRxGoodButNoInternet)
{
    WIFI_LOGI("SetTxRxGoodButNoInternet: %{public}d", isTxRxGoodButNoInternet);
    isTxRxGoodButNoInternet_ = isTxRxGoodButNoInternet;
}

void SelfCureService::HandleStaConnChanged(OperateResState state, const WifiLinkedInfo &info)
{
    if (isTxRxGoodButNoInternet_ && state == OperateResState::CONNECT_NETWORK_ENABLED) {
        state = OperateResState::CONNECT_NETWORK_DISABLED;
    }
    WIFI_LOGD("self cure wifi connection state change, state = %{public}d", state);
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }

    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD, info);
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        isTxRxGoodButNoInternet_ = false;
        pSelfCureStateMachine->SetHttpMonitorStatus(false);
        pSelfCureStateMachine->SendMessage(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD, info);
        if (lastState == OperateResState::CONNECT_OBTAINING_IP) {
            pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI7_DISCONNECT_COUNT, lastWifiLinkedInfo);
        }
        IpQosMonitor::GetInstance().ResetTxRxProperty();
        lastNetworkState_ = OperateResState::DISCONNECT_DISCONNECTED;
    } else if (state == OperateResState::CONNECT_OBTAINING_IP) {
        lastWifiLinkedInfo = info;
    } else if (state == OperateResState::CONNECT_NETWORK_DISABLED) {
        pSelfCureStateMachine->SetHttpMonitorStatus(false);
        if (lastNetworkState_ != state && IsWifiSelfcureDone()) {
            SelfCureUtils::GetInstance().ReportNoInternetChrEvent();
        }
        lastNetworkState_ = state;
    } else if (state == OperateResState::CONNECT_NETWORK_ENABLED || state == OperateResState::CONNECT_CHECK_PORTAL) {
        pSelfCureStateMachine->SetHttpMonitorStatus(true);
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_HTTP_REACHABLE_RCV, info);
        lastNetworkState_ = state == OperateResState::CONNECT_NETWORK_ENABLED ?
            OperateResState::CONNECT_NETWORK_ENABLED : lastNetworkState_;
    } else if (state == OperateResState::CONNECT_CONNECTION_REJECT) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_WIFI7_DISCONNECT_COUNT, info);
    }
    lastState = state;
}

void SelfCureService::HandleDhcpOfferReport(const IpInfo &ipInfo)
{
    WIFI_LOGD("Enter HandleDhcpOfferReport.");
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->SendMessage(WIFI_CURE_DHCP_OFFER_PKT_RCV, ipInfo);
}

void SelfCureService::NotifyInternetFailureDetected(int forceNoHttpCheck)
{
    WIFI_LOGI("Enter NotifyInternetFailureDetected.");
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, 0, forceNoHttpCheck);
}

void SelfCureService::NotifyP2pConnectStateChanged(const WifiP2pLinkedInfo &info)
{
    WIFI_LOGI("Enter NotifyP2pConnectStateChanged, state is %{public}d", info.GetConnectState());
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->HandleP2pConnChanged(info);
}

bool SelfCureService::IsSelfCureOnGoing()
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return false;
    }
    return pSelfCureStateMachine->IsSelfCureOnGoing();
}

bool SelfCureService::IsSelfCureL2Connecting()
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return false;
    }
    return pSelfCureStateMachine->IsSelfCureL2Connecting();
}

void SelfCureService::StopSelfCureWifi(int32_t status)
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->StopSelfCureWifi(status);
}

bool SelfCureService::CheckSelfCureWifiResult(int event)
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return false;
    }
    return pSelfCureStateMachine->CheckSelfCureWifiResult(event);
}

bool SelfCureService::IsWifiSelfcureDone()
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return false;
    }
    return pSelfCureStateMachine->IsWifiSelfcureDone();
}

void SelfCureService::RegisterP2pEnhanceCallback()
{
    P2pEnhanceCallback p2pEnhanceStateChangeCallback = [this](const std::string &ifName, int32_t state,
        int32_t frequency) {
            this->P2pEnhanceStateChange(ifName, state, frequency);
    };
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("RegisterP2pEnhanceCallback get pEnhanceService failed!");
        return;
    }
    ErrCode ret = pEnhanceService->RegisterP2pEnhanceCallback(WIFI_SERVICE_SELFCURE, p2pEnhanceStateChangeCallback);
    WIFI_LOGI("RegisterP2pEnhanceCallback result %{public}d", ret);
}

void SelfCureService::P2pEnhanceStateChange(const std::string &ifName, int32_t state, int32_t frequency)
{
    WIFI_LOGI("P2pEnhanceStateChange, state %{public}d", state);
    int32_t p2pEnhanceState = -1;
    if (state == P2P_ENHANCE_BC_CONNECT_SUCC) {
        p2pEnhanceState = 1;
    } else if (state == P2P_ENHANCE_BC_DESTROYED) {
        p2pEnhanceState = 0;
    } else {
        WIFI_LOGD("No need to handle the state");
    }
    if ((lastP2pEnhanceState_ != p2pEnhanceState) && (p2pEnhanceState != -1)) {
        lastP2pEnhanceState_ = p2pEnhanceState;
        if (pSelfCureStateMachine == nullptr) {
            WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
            return;
        }
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_P2P_ENHANCE_STATE_CHANGED, p2pEnhanceState);
        WifiConfigCenter::GetInstance().SetP2pEnhanceState(p2pEnhanceState);
    }
}

bool SelfCureService::NotifyIpv6FailureDetected()
{
    WIFI_LOGI("Enter NotifyIpv6FailureDetected");
    // Check WiFi connection state, only handle IPv6 failure when connected
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGI("WiFi not connected, ignore IPv6 failure");
        return false;
    }

    if (SelfCureUtils::GetInstance().HasIpv6Disabled()) {
        WIFI_LOGI("IPv6 already disabled, ignore IPv6 failure");
        return false;
    }

    // Check if static IPv6 is configured
    WifiDeviceConfig wificonfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, wificonfig, m_instId) == 0 &&
        wificonfig.wifiIpConfig.assignMethod ==  AssignIpMethod::STATIC &&
        wificonfig.wifiIpConfig.staticIpAddress.ipAddress.address.family == 1) {
        WIFI_LOGI("Static IPv6 configured, ignore IPv6 failure");
        return false;
    }

    int currentRssi = linkedInfo.rssi;
    // Check if RSSI is too low
    if (currentRssi < MIN_VAL_LEVEL_3_5) {
        WIFI_LOGI("RSSI too low (%{public}d), ignore IPv6 failure", currentRssi);
        return false;
    }

    // Check if the system supports IPv6 self-cure functionality
    if (!SelfCureUtils::GetInstance().IsIpv6SelfCureSupported()) {
        WIFI_LOGI("IPv6 self-cure not supported, ignore IPv6 failure");
        return false;
    }

    // Disable IPv6 to avoid potential connection issues
    bool result = SelfCureUtils::GetInstance().DisableIpv6();
    if (result) {
        WIFI_LOGI("IPv6 disabled successfully due to connection failure");
        return true;
    } else {
        WIFI_LOGE("Failed to disable IPv6");
    }
    return false;
}
} //namespace Wifi
} //namespace OHOS