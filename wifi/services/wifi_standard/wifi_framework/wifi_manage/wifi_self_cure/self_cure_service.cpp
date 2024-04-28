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
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("SelfCureService");

namespace OHOS {
namespace Wifi {
SelfCureService::SelfCureService(int instId) : pSelfCureStateMachine(nullptr), m_instId(instId) {}

SelfCureService::~SelfCureService()
{
    WIFI_LOGI("SelfCureService::~SelfCureService");
    if (pSelfCureStateMachine != nullptr) {
        delete pSelfCureStateMachine;
        pSelfCureStateMachine = nullptr;
    }
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
    return WIFI_OPT_SUCCESS;
}

void SelfCureService::RegisterSelfCureServiceCallback(const std::vector<SelfCureServiceCallback> &callbacks) const
{
    WIFI_LOGI("Enter RegisterSelfCureServiceCallback.");
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("pSelfCureStateMachine is null.\n");
        return;
    }
}

void SelfCureService::HandleRssiLevelChanged(int rssi)
{
    WIFI_LOGI("HandleRssiLevelChanged, %{public}d.\n", rssi);
    if (pSelfCureStateMachine == nullptr) {
        WIFI_LOGE("pSelfCureStateMachine is null.\n");
        return;
    }
    InternalMessage *msg = pSelfCureStateMachine->CreateMessage();
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
        WIFI_LOGE("pSelfCureStateMachine is null.\n");
        return;
    }
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD, info);
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        pSelfCureStateMachine->SendMessage(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD, info);
    } else if (state == OperateResState::CONNECT_NETWORK_DISABLED) {
        pSelfCureStateMachine->SetHttpMonitorStatus(false);
        pSelfCureStateMachine->SendMessage(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED, info);
    } else if (state == OperateResState::CONNECT_NETWORK_ENABLED || state == OperateResState::CONNECT_CHECK_PORTAL) {
        pSelfCureStateMachine->SetHttpMonitorStatus(true);
    }
}
} //namespace Wifi
} //namespace OHOS