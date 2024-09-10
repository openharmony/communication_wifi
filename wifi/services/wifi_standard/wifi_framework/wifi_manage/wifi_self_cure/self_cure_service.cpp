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
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "netsys_controller.h"
#include "net_conn_client.h"
#include "net_handle.h"

DEFINE_WIFILOG_LABEL("SelfCureService");

namespace OHOS {
namespace Wifi {
constexpr int32_t P2P_ENHANCE_BC_CONNECT_SUCC = 4;
constexpr int32_t P2P_ENHANCE_BC_DESTROYED = 10;
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
    UnRegisterP2pEnhanceCallback();
    UnRegisterDnsResultCallback();
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
    RegisterDnsResultCallback();
    return WIFI_OPT_SUCCESS;
}

void SelfCureService::RegisterSelfCureServiceCallback(const std::vector<SelfCureServiceCallback> &callbacks) const
{
    WIFI_LOGI("Enter RegisterSelfCureServiceCallback.");
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
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

void SelfCureService::HandleP2pConnChanged(const WifiP2pLinkedInfo &info)
{
    WIFI_LOGD("self cure p2p connection state change, connectState = %{public}d", info.GetConnectState());
}


void SelfCureService::HandleStaConnChanged(OperateResState state, const WifiLinkedInfo &info)
{
    WIFI_LOGD("self cure wifi connection state change, state = %{public}d", state);
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD, info);
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD, info);
    } else if (state == OperateResState::CONNECT_NETWORK_DISABLED) {
        pSelfCureStateMachine->SetHttpMonitorStatus(false);
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, 0, 1, info);
    } else if (state == OperateResState::CONNECT_NETWORK_ENABLED || state == OperateResState::CONNECT_CHECK_PORTAL) {
        pSelfCureStateMachine->SetHttpMonitorStatus(true);
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_HTTP_REACHABLE_RCV, info);
    }
}

void SelfCureService::HandleStaOpened()
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return;
    }
    pSelfCureStateMachine->SendMessage(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
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

bool SelfCureService::IsSelfCureOnGoing()
{
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("%{public}s pSelfCureStateMachine is null.", __FUNCTION__);
        return false;
    }
    return pSelfCureStateMachine->IsSelfCureOnGoing();
}

void SelfCureService::RegisterP2pEnhanceCallback()
{
    using namespace std::placeholders;
    p2pEnhanceStateChange_ = std::bind(&SelfCureService::P2pEnhanceStateChange, this, _1, _2);
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("RegisterP2pEnhanceCallback get pEnhanceService failed!");
        return;
    }
    ErrCode ret = pEnhanceService->RegisterP2pEnhanceCallback(p2pEnhanceStateChange_);
    WIFI_LOGI("RegisterP2pEnhanceCallback result %{public}d", ret);
}

void SelfCureService::UnRegisterP2pEnhanceCallback()
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("UnRegisterP2pEnhanceCallback get pEnhanceService failed!");
        return;
    }
    pEnhanceService->UnRegisterP2pEnhanceCallback();
}

void SelfCureService::P2pEnhanceStateChange(const std::string &ifName, int32_t state)
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

int32_t SelfCureService::GetWifiNetId()
{
    std::list<sptr<NetManagerStandard::NetHandle>> netList;
    int32_t ret = NetManagerStandard::NetConnClient::GetInstance().GetAllNets(netList);
    if (ret != 0) {
        return 0;
    }
 
    for (auto iter : netList) {
        NetManagerStandard::NetAllCapabilities netAllCap;
        NetManagerStandard::NetConnClient::GetInstance().GetNetCapabilities(*iter, netAllCap);
        if (netAllCap.bearerTypes_.count(NetManagerStandard::BEARER_WIFI) > 0) {
            return iter->GetNetId();
        }
    }
    return 0;
}
 
void SelfCureService::RegisterDnsResultCallback()
{
    dnsResultCallback_ = std::make_unique<SelfCureDnsResultCallback>(*this).release();
    int32_t regDnsResult =
        NetManagerStandard::NetsysController::GetInstance().RegisterDnsResultCallback(dnsResultCallback_, 0);
    WIFI_LOGI("RegisterDnsResultCallback result = %{public}d", regDnsResult);
}
 
void SelfCureService::UnRegisterDnsResultCallback()
{
    WIFI_LOGI("UnRegisterDnsResultCallback");
    if (dnsResultCallback_ != nullptr) {
        NetManagerStandard::NetsysController::GetInstance().UnregisterDnsResultCallback(dnsResultCallback_);
    }
}
 
void SelfCureService::DnsFailedCount(int dnsFailCount)
{
    if (dnsFailCount <= 0) {
        return;
    }
    pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_DNS_FAILED_REPORT, dnsFailCount);
}
 
int32_t SelfCureService::SelfCureDnsResultCallback::OnDnsResultReport(uint32_t size,
    const std::list<NetsysNative::NetDnsResultReport> netDnsResultReport)
{
    int32_t wifiNetId = selfCureService_.GetWifiNetId();
     WIFI_LOGD("OnDnsResultReport,size is: %{public}d, wifiNetId is %{public}d", static_cast<int>(netDnsResultReport.size()), wifiNetId);
    for (auto &it : netDnsResultReport) {
        if (wifiNetId > 0 && wifiNetId == static_cast<int32_t>(it.netid_)) {
            if (it.queryresult_ != 0) {
                selfCureService_.DnsFailedCount(dnsFailCount);
                break;
            }
        }
    }
    return 0;
}
} //namespace Wifi
} //namespace OHOS