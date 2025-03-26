/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_sta_manager.h"
#include "magic_enum.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_hisysevent.h"
#include "wifi_protect_manager.h"
#include "wifi_system_timer.h"
#ifdef FEATURE_STA_SUPPORT
#include "wifi_country_code_manager.h"
#endif
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "dhcp_c_api.h"
#include "block_connect_service.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_sa_manager.h"
#include "wifi_notification_util.h"
#endif

DEFINE_WIFILOG_LABEL("WifiStaManager");

namespace OHOS {
namespace Wifi {
WifiStaManager::WifiStaManager()
{
    WIFI_LOGI("create WifiStaManager");
    InitStaCallback();
}

StaServiceCallback& WifiStaManager::GetStaCallback()
{
    return mStaCallback;
}

#ifndef OHOS_ARCH_LITE
static void UnloadStaSaTimerCallback()
{
#ifdef DYNAMIC_UNLOAD_SA
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_CLOSE_DHCP_SA);
#endif
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_DEVICE_ABILITY_ID);
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
}

static void SatelliteTimerCallback()
{
    WIFI_LOGI("It's time for satellite timer.");
    WifiManager::GetInstance().GetWifiTogglerManager()->SetSatelliteStartState(false);
    WifiManager::GetInstance().GetWifiStaManager()->StopSatelliteTimer();
}

void WifiStaManager::StopUnloadStaSaTimer(void)
{
    WIFI_LOGI("StopUnloadStaSaTimer! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
    std::unique_lock<std::mutex> lock(unloadStaSaTimerMutex);
    if (unloadStaSaTimerId == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(unloadStaSaTimerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(unloadStaSaTimerId);
    unloadStaSaTimerId = 0;
    return;
}

void WifiStaManager::StartUnloadStaSaTimer(void)
{
    WIFI_LOGI("StartUnloadStaSaTimer! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
    std::unique_lock<std::mutex> lock(unloadStaSaTimerMutex);
    if (unloadStaSaTimerId == 0) {
        std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, true, false);
        wifiSysTimer->SetCallbackInfo(UnloadStaSaTimerCallback);
        unloadStaSaTimerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
        int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
        MiscServices::TimeServiceClient::GetInstance()->StartTimer(unloadStaSaTimerId,
            currentTime + TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("StartUnloadStaSaTimer success! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
    }
    return;
}
#endif

void WifiStaManager::CloseStaService(int instId)
{
    WIFI_LOGI("close sta service");
#ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close sta SA!");
        return;
    }
    StartUnloadStaSaTimer();
#endif
    return;
}

void WifiStaManager::StaCloseDhcpSa(void)
{
#ifdef DYNAMIC_UNLOAD_SA
    int state = WifiConfigCenter::GetInstance().GetHotspotState(0);
    if (state == static_cast<int>(ApState::AP_STATE_CLOSED)) {
        StopDhcpdServerSa();
    }
    StopDhcpdClientSa();
#endif
}

void WifiStaManager::InitStaCallback(void)
{
    using namespace std::placeholders;
    mStaCallback.callbackModuleName = "WifiStaManager";
    mStaCallback.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
    mStaCallback.OnWpsChanged = [this](WpsStartState state, const int pinCode, int instId) {
        this->DealWpsChanged(state, pinCode, instId);
    };
    mStaCallback.OnStaStreamChanged = [this](StreamDirection direction, int instId) {
        this->DealStreamChanged(direction, instId);
    };
    mStaCallback.OnStaRssiLevelChanged = [this](int rssi, int instId) { this->DealRssiChanged(rssi, instId); };
    mStaCallback.OnAutoSelectNetworkRes = [this](int networkId, int instId) {
        this->DealAutoSelectNetworkChanged(networkId, instId);
    };
    return;
}

void WifiStaManager::DealStaOpened(int instId)
{
#ifdef FEATURE_STA_SUPPORT
    WifiCountryCodeManager::GetInstance().DealStaOpened(instId);
#endif
    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId)) {
        WIFI_LOGI("DealStaOpenRes: wifi scan only state notify scan result!");
        IScanSerivceCallbacks &scanCallback = WifiManager::GetInstance().GetWifiScanManager()->GetScanCallback();
        scanCallback.OnScanFinishEvent(static_cast<int>(ScanHandleNotify::SCAN_OK), instId);
    }
#ifdef DYNAMIC_UNLOAD_SA
    if (instId == 0) {
        StopUnloadStaSaTimer();
    }
#endif
}

void WifiStaManager::DealStaStopped(int instId)
{
#ifdef FEATURE_STA_SUPPORT
    WifiCountryCodeManager::GetInstance().DealStaStopped(instId);
#endif
#ifdef DYNAMIC_UNLOAD_SA
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_SERVICE_CLOSE, instId);
#endif
    BlockConnectService::GetInstance().DealStaStopped(instId);
}

void WifiStaManager::PublishWifiOperateStateHiSysEvent(OperateResState state)
{
    switch (state) {
        case OperateResState::DISCONNECT_DISCONNECTED:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
                static_cast<int>(WifiOperateState::STA_DISCONNECTED));
            break;
        case OperateResState::CONNECT_CONNECTION_FULL:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
                static_cast<int>(WifiOperateState::STA_ASSOC_FULL_REJECT));
            break;
        case OperateResState::CONNECT_OBTAINING_IP:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_DHCP),
                static_cast<int>(WifiOperateState::STA_DHCP));
            break;
        default:
            break;
        }
    return;
}

void WifiStaManager::NotifyScanForStaConnChanged(OperateResState state, int instId)
{
    if (state == OperateResState::CONNECT_CONNECTING || state == OperateResState::CONNECT_AP_CONNECTED ||
        state == OperateResState::DISCONNECT_DISCONNECTING || state == OperateResState::DISCONNECT_DISCONNECTED ||
        state == OperateResState::CONNECT_OBTAINING_IP || state == OperateResState::CONNECT_ASSOCIATING ||
        state == OperateResState::CONNECT_ASSOCIATED || state == OperateResState::CONNECT_NETWORK_ENABLED ||
        state == OperateResState::CONNECT_NETWORK_DISABLED || state == OperateResState::SPECIAL_CONNECTED ||
        state == OperateResState::CONNECT_MISS_MATCH) {
        if (WifiConfigCenter::GetInstance().GetScanMidState(instId) == WifiOprMidState::RUNNING) {
            IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
            if (pService != nullptr) {
                pService->OnClientModeStatusChanged(static_cast<int>(state));
            }
        }
    }
}

static void HandleStaDisconnected(int instId)
{
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        if (WifiManager::GetInstance().GetWifiTogglerManager() == nullptr) {
            WIFI_LOGE("GetWifiTogglerManager failed!");
            return;
        }
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(instId);
        if (curState == WifiOprMidState::RUNNING) {
            WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, instId);
        }
#ifdef FEATURE_RPT_SUPPORT
        if (WifiManager::GetInstance().GetRptInterface(instId) == nullptr) {
            WIFI_LOGE("GetRptInterface failed!");
            return;
        }
        if (WifiManager::GetInstance().GetRptInterface(instId)->IsRptRunning()) {
            WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, instId);
        }
#endif
    }
}

void WifiStaManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    WIFI_LOGD("Enter, DealStaConnChanged, state: %{public}d!, message:%{public}s\n", static_cast<int>(state),
        magic_enum::Enum2Name(state).c_str());
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        WifiConfigCenter::GetInstance().UpdateLinkedInfo(instId);
        WifiConfigCenter::GetInstance().SetLastConnStaFreq(info.frequency);
    }

    bool isReport = true;
    int reportStateNum = static_cast<int>(ConvertConnStateInternal(state, isReport));
    if (isReport) {
        WifiEventCallbackMsg cbMsg;
        cbMsg.msgCode = WIFI_CBK_MSG_CONNECTION_CHANGE;
        cbMsg.msgData = reportStateNum;
        cbMsg.linkInfo = info;
        cbMsg.id = instId;
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }
    NotifyScanForStaConnChanged(state, instId);
    PublishWifiOperateStateHiSysEvent(state);
    if (info.connState == ConnState::AUTHENTICATING)
    {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_AUTH),
            static_cast<int>(WifiOperateState::STA_AUTHING));
    }
#ifdef FEATURE_HPF_SUPPORT
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        int screenState = WifiConfigCenter::GetInstance().GetScreenState();
        WifiManager::GetInstance().InstallPacketFilterProgram(screenState, instId);
    }
#endif
#ifndef OHOS_ARCH_LITE
    bool isConnected = (info.connState == CONNECTED) ? true : false;
    WifiProtectManager::GetInstance().UpdateWifiClientConnected(isConnected);
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        WifiNotificationUtil::GetInstance().CancelWifiNotification(
            WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID);
        HandleStaDisconnected(instId);
    }
#endif
    return;
}

void WifiStaManager::DealWpsChanged(WpsStartState state, const int pinCode, int instId)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_WPS_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(state);
    cbMsg.id = instId;
    cbMsg.pinCode = std::to_string(pinCode);
    unsigned int len = cbMsg.pinCode.length();
    if (len < 8) { /* Fill in 8 digits. */
        cbMsg.pinCode = std::string(8 - len, '0') + cbMsg.pinCode;
    }
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiStaManager::DealStreamChanged(StreamDirection direction, int instId)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STREAM_DIRECTION;
    cbMsg.msgData = static_cast<int>(direction);
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiStaManager::DealRssiChanged(int rssi, int instId)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_RSSI_CHANGE;
    cbMsg.msgData = rssi;
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiStaManager::DealAutoSelectNetworkChanged(int networkId, int instId)
{
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
    if (pService != nullptr) {
        pService->OnAutoConnectStateChanged(networkId != -1);
    }
    return;
}

#ifndef OHOS_ARCH_LITE
void WifiStaManager::StopSatelliteTimer(void)
{
    WIFI_LOGI("StopSatelliteTimer! satelliteTimerId:%{public}u", satelliteTimerId);
    std::unique_lock<std::mutex> lock(satelliteTimerMutex);
    if (satelliteTimerId == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(satelliteTimerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(satelliteTimerId);
    satelliteTimerId = 0;
    return;
}

void WifiStaManager::StartSatelliteTimer(void)
{
    std::unique_lock<std::mutex> lock(satelliteTimerMutex);
    std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, true, false);
    wifiSysTimer->SetCallbackInfo(SatelliteTimerCallback);
    satelliteTimerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
    int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    MiscServices::TimeServiceClient::GetInstance()->StartTimer(satelliteTimerId,
        currentTime + TIMEOUT_STOP_SATELLITE);
    WIFI_LOGI("StartSatelliteTimer success! satelliteTimerId:%{public}u", satelliteTimerId);
    return;
}
#endif
}  // namespace Wifi
}  // namespace OHOS
