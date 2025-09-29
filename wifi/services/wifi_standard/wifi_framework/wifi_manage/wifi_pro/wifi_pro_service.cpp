/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include <memory>
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_pro_service.h"
#include "wifi_pro_utils.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"

#ifndef FALLTHROUGH_INTENDED
#define FALLTHROUGH_INTENDED [[clang::fallthrough]]  // NOLINT
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiProService");

WifiProService::WifiProService(int32_t instId)
    : instId_(instId)
{
    WIFI_LOGI("Enter WifiProService");
}

WifiProService::~WifiProService()
{
    WIFI_LOGI("Enter ~WifiProService");
}

ErrCode WifiProService::InitWifiProService()
{
    WIFI_LOGI("Enter InitWifiProService.");
    pWifiProStateMachine_ = std::make_shared<WifiProStateMachine>(instId_);
    if (pWifiProStateMachine_ == nullptr) {
        WIFI_LOGE("Alloc WifiProStateMachine failed.");
        return WIFI_OPT_FAILED;
    }
    if (pWifiProStateMachine_->Initialize() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Init WifiProStateMachine failed.");
        return WIFI_OPT_FAILED;
    }
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    if (instId_ == INSTID_WLAN0) {
        pWifiIntelligenceStateMachine_ = std::make_shared<WifiIntelligenceStateMachine>(instId_);
        if (pWifiIntelligenceStateMachine_ == nullptr) {
            WIFI_LOGE("Alloc WifiIntelligenceStateMachine failed.");
            return WIFI_OPT_FAILED;
        }
        if (pWifiIntelligenceStateMachine_->Initialize() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Init WifiIntelligenceStateMachine failed.");
            return WIFI_OPT_FAILED;
        }
    }
#endif
    return WIFI_OPT_SUCCESS;
}

void WifiProService::HandleStaConnChanged(OperateResState state, const WifiLinkedInfo &linkedInfo)
{
    WIFI_LOGD("WifiProService wifi connection state change, state:%{public}d,connState:%{public}d,"
        "supplicantState:%{public}d.", state, linkedInfo.connState, static_cast<int32_t>(linkedInfo.supplicantState));
    if (pWifiProStateMachine_ == nullptr) {
        WIFI_LOGE("%{public}s pWifiProStateMachine_ is null.", __FUNCTION__);
        return;
    }

    switch (state) {
        case OperateResState::CONNECT_AP_CONNECTED:
            FALLTHROUGH_INTENDED;
        case OperateResState::DISCONNECT_DISCONNECTED:
            NotifyWifiConnectStateChanged(state, linkedInfo);
            break;
        case OperateResState::CONNECT_CHECK_PORTAL:
            FALLTHROUGH_INTENDED;
        case OperateResState::CONNECT_NETWORK_DISABLED:
            FALLTHROUGH_INTENDED;
        case OperateResState::CONNECT_NETWORK_ENABLED:
            NotifyCheckWifiInternetResult(state);
            break;
        case OperateResState::CONNECT_ENABLE_NETWORK_FAILED:
            FALLTHROUGH_INTENDED;
        case OperateResState::CONNECT_CONNECTING_TIMEOUT:
            FALLTHROUGH_INTENDED;
        case OperateResState::CONNECT_CONNECTION_REJECT:
            FALLTHROUGH_INTENDED;
        case OperateResState::CONNECT_PASSWORD_WRONG:
            FALLTHROUGH_INTENDED;
        case OperateResState::CONNECT_OBTAINING_IP_FAILED:
            NotifyWifi2WifiFailed(state);
            break;
        case OperateResState::CONNECT_EMLSR_START:
        case OperateResState::CONNECT_EMLSR_END:
            NotifyWifiEmlsrStateChanged(state, linkedInfo);
            break;
        default:
            break;
    }
}

void WifiProService::NotifyWifi2WifiFailed(OperateResState state)
{
    WIFI_LOGI("NotifyWifi2WifiFailed: wifi2wifi failed");
    pWifiProStateMachine_->SendMessage(EVENT_WIFI2WIFI_FAILED, static_cast<int32_t>(state));
}

void WifiProService::NotifyWifiConnectStateChanged(OperateResState state, const WifiLinkedInfo &linkedInfo)
{
    WIFI_LOGI("NotifyWifiConnectStateChanged: ssid:%{public}s, bssid:%{public}s",
        MacAnonymize(linkedInfo.ssid).c_str(), MacAnonymize(linkedInfo.bssid).c_str());
    pWifiProStateMachine_->SendMessage(EVENT_WIFI_CONNECT_STATE_CHANGED, static_cast<int32_t>(state),
        linkedInfo.networkId, linkedInfo);
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_WIFI_CONNECT_STATE_CHANGED, static_cast<int32_t>(state));
    }
#endif
}

void WifiProService::NotifyCheckWifiInternetResult(OperateResState state)
{
    WIFI_LOGD("NotifyCheckWifiInternetResult: wifi internet result:%{public}d", static_cast<int32_t>(state));
    pWifiProStateMachine_->SendMessage(EVENT_CHECK_WIFI_INTERNET_RESULT, static_cast<int32_t>(state));
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_CHECK_WIFI_INTERNET_RESULT, static_cast<int32_t>(state));
    }
#endif
}

void WifiProService::HandleRssiLevelChanged(int32_t rssi)
{
    WIFI_LOGD("HandleRssiLevelChanged, %{public}d.", rssi);
    if (pWifiProStateMachine_ == nullptr) {
        WIFI_LOGE("%{public}s pWifiProStateMachine_ is null.", __FUNCTION__);
        return;
    }

    pWifiProStateMachine_->SendMessage(EVENT_WIFI_RSSI_CHANGED, rssi);
}

void WifiProService::HandleScanResult(const std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGD("Enter HandleScanResult.");
    if (pWifiProStateMachine_ == nullptr) {
        WIFI_LOGE("%{public}s pWifiProStateMachine_ is null.", __FUNCTION__);
        return;
    }
    if (WifiConfigCenter::GetInstance().GetWifiMidState(instId_) == WifiOprMidState::RUNNING) {
        pWifiProStateMachine_->SendMessage(EVENT_HANDLE_SCAN_RESULT, scanInfos);
    }
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_HANDLE_SCAN_RESULT, scanInfos);
    }
#endif
}

void WifiProService::HandleQoeReport(const NetworkLagType &networkLagType, const NetworkLagInfo &networkLagInfo)
{
    if (pWifiProStateMachine_ == nullptr) {
        WIFI_LOGE("%{public}s pWifiProStateMachine_ is null.", __FUNCTION__);
        return;
    }
    switch (networkLagType) {
        case NetworkLagType::WIFIPRO_QOE_SLOW:
            pWifiProStateMachine_->SendMessage(EVENT_QOE_APP_SLOW);
            break;
        default:
            break;
    }
    InternalMessagePtr msg = pWifiProStateMachine_->CreateMessage(EVENT_QOE_REPORT);
    msg->SetMessageObj(networkLagInfo);
    msg->msgLogLevel_ = MsgLogLevel::LOG_D;
    pWifiProStateMachine_->SendMessage(msg);
}
void WifiProService::HandleWifiHalSignalInfoChange(const WifiSignalPollInfo &wifiSignalPollInfo)
{
    if (pWifiProStateMachine_ == nullptr) {
        WIFI_LOGE("%{public}s pWifiProStateMachine_ is null.", __FUNCTION__);
        return;
    }
    InternalMessagePtr msg = pWifiProStateMachine_->CreateMessage(EVENT_SIGNAL_INFO_CHANGE);
    msg->SetMessageObj(wifiSignalPollInfo);
    msg->msgLogLevel_ = MsgLogLevel::LOG_D;
    pWifiProStateMachine_->SendMessage(msg);
}

void WifiProService::NotifyWifiEmlsrStateChanged(OperateResState state, const WifiLinkedInfo &linkedInfo)
{
    pWifiProStateMachine_->SendMessage(EVENT_EMLSR_STATE_CHANGED, static_cast<int32_t>(state), linkedInfo.networkId,
        linkedInfo);
}
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
void WifiProService::OnScreenStateChanged(int32_t screenState)
{
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        if (screenState == MODE_STATE_OPEN) {
            pWifiIntelligenceStateMachine_->SendMessage(EVENT_SCREEN_ON, screenState);
        } else if (screenState == MODE_STATE_CLOSE) {
            pWifiIntelligenceStateMachine_->SendMessage(EVENT_SCREEN_OFF, screenState);
        }
    }
}

void WifiProService::OnCellInfoUpdated()
{
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_CELL_STATE_CHANGE);
    }
}

void WifiProService::OnWifiStateOpen(int32_t state)
{
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_WIFI_ENABLED, state);
    }
}

void WifiProService::OnWifiStateClose(int32_t state)
{
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_WIFI_DISABLED, state);
    }
}

void WifiProService::OnWifiDeviceConfigChange(int32_t status, const WifiDeviceConfig &config, bool isRemoveAll)
{
    if (pWifiIntelligenceStateMachine_ != nullptr) {
        pWifiIntelligenceStateMachine_->SendMessage(EVENT_CONFIGURATION_CHANGED, status, isRemoveAll, config);
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS