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
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
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
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_DEVICE_ABILITY_ID);
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
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
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
    auto &ins =  WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaClose(instId);
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime(instId);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#ifdef FEATURE_P2P_SUPPORT
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("CloseStaService, current p2p state: %{public}d", p2pState);
    if (p2pState == WifiOprMidState::RUNNING) {
        WifiManager::GetInstance().GetWifiP2pManager()->AutoStopP2pService();
    }
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SELFCURE, instId);
#endif
#ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close sta SA!");
        return;
    }
    if (WifiConfigCenter::GetInstance().GetPowerSleepState() == MODE_STATE_OPEN) {
        StopUnloadStaSaTimer();
        return;
    }
    StartUnloadStaSaTimer();
#endif
    return;
}

void WifiStaManager::InitStaCallback(void)
{
    using namespace std::placeholders;
    mStaCallback.callbackModuleName = "WifiStaManager";
    mStaCallback.OnStaOpenRes = std::bind(&WifiStaManager::DealStaOpenRes, this, _1, _2);
    mStaCallback.OnStaCloseRes = std::bind(&WifiStaManager::DealStaCloseRes, this, _1, _2);
    mStaCallback.OnStaConnChanged = std::bind(&WifiStaManager::DealStaConnChanged, this, _1, _2, _3);
    mStaCallback.OnWpsChanged = std::bind(&WifiStaManager::DealWpsChanged, this, _1, _2, _3);
    mStaCallback.OnStaStreamChanged = std::bind(&WifiStaManager::DealStreamChanged, this, _1, _2);
    mStaCallback.OnStaRssiLevelChanged = std::bind(&WifiStaManager::DealRssiChanged, this, _1, _2);
    return;
}

void WifiStaManager::ForceStopWifi(int instId)
{
    WIFI_LOGI("Enter ForceStopWifi");
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr || (pService->DisableWifi() != WIFI_OPT_SUCCESS)) {
        WIFI_LOGE("service is null or disable wifi failed.");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        WifiEventCallbackMsg cbMsg;
        cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
        cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
        cbMsg.id = instId;
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
#ifdef FEATURE_SELF_CURE_SUPPORT
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SELFCURE, instId);
#endif
        return;
    }
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("In force stop wifi, state: %{public}d", static_cast<int>(curState));
    WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::CLOSED, instId);
}

void WifiStaManager::DealStaOpenRes(OperateResState state, int instId)
{
    WIFI_LOGD("Enter DealStaOpenRes: %{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::OPEN_WIFI_OPENING) {
        cbMsg.msgData = static_cast<int>(WifiState::ENABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENING));
        mLastWifiOpenState = static_cast<int>(state);
        return;
    }
    if ((state == OperateResState::OPEN_WIFI_FAILED) || (state == OperateResState::OPEN_WIFI_DISABLED)) {
        WIFI_LOGE("DealStaOpenRes:wifi open failed!");
        WifiOprMidState apstate = WifiConfigCenter::GetInstance().GetApMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::OPEN_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(apstate));
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        DealStaCloseRes(state, instId);
        return;
    }
    WIFI_LOGI("DealStaOpenRes:wifi open successfully!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
    WifiConfigCenter::GetInstance().SetStaLastRunState(true, instId);
    auto &ins =  WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaStart(instId);
    cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    if ((state == OperateResState::OPEN_WIFI_SUCCEED) &&
        (mLastWifiOpenState == static_cast<int>(WifiOperateState::STA_OPENING))) {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENED));
        mLastWifiOpenState = static_cast<int>(state);
    }
    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId)) {
        WIFI_LOGI("DealStaOpenRes: wifi scan only state notify scan result!");
        IScanSerivceCallbacks &scanCallback = WifiManager::GetInstance().GetWifiScanManager()->GetScanCallback();
        scanCallback.OnScanFinishEvent(static_cast<int>(ScanHandleNotify::SCAN_OK), instId);
    }
#ifdef FEATURE_P2P_SUPPORT
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("DealStaOpenRes, current p2p state:%{public}d", p2pState);
    if (p2pState == WifiOprMidState::CLOSED) {
        WifiManager::GetInstance().GetWifiP2pManager()->AutoStartP2pService();
    }
#endif
    return;
}

void WifiStaManager::DealStaCloseRes(OperateResState state, int instId)
{
    WIFI_LOGD("Enter DealStaCloseRes: %{public}d", static_cast<int>(state));
#ifndef OHOS_ARCH_LITE
    WifiProtectManager::GetInstance().UpdateWifiClientConnected(false);
#endif
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::CLOSE_WIFI_CLOSING) {
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiConnectFailedEventHiSysEvent(static_cast<int>(WifiOperateState::STA_CLOSING));
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_FAILED) {
        WIFI_LOGI("DealStaCloseRes: broadcast wifi close failed event!");
        WifiOprMidState apstate = WifiConfigCenter::GetInstance().GetApMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::CLOSE_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(apstate));
        ForceStopWifi(instId);
        cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }

    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_SERVICE_CLOSE, instId);
    return;
}

void WifiStaManager::PublishWifiOperateStateHiSysEvent(OperateResState state)
{
    switch (state) {
        case OperateResState::DISCONNECT_DISCONNECTED:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
                static_cast<int>(WifiOperateState::STA_DISCONNECTED));
            break;
        case OperateResState::CONNECT_ASSOCIATING:
            WriteWifiConnectFailedEventHiSysEvent(static_cast<int>(WifiOperateState::STA_ASSOCIATING));
            break;
        case OperateResState::CONNECT_ASSOCIATED:
            WriteWifiConnectFailedEventHiSysEvent(static_cast<int>(WifiOperateState::STA_ASSOCIATED));
            break;
        case OperateResState::CONNECT_CONNECTION_FULL:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
                static_cast<int>(WifiOperateState::STA_ASSOC_FULL_REJECT));
            break;
        case OperateResState::CONNECT_OBTAINING_IP:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_DHCP),
                static_cast<int>(WifiOperateState::STA_DHCP));
            break;
        case OperateResState::DISCONNECT_DISCONNECTING:
        case OperateResState::CONNECT_CONNECTING_TIMEOUT:
            WriteWifiConnectFailedEventHiSysEvent(static_cast<int>(WifiOperateState::STA_DISCONNECT));
            break;
        default:
            break;
        }
    return;
}

void WifiStaManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    WIFI_LOGI("Enter, DealStaConnChanged, state: %{public}d!, message:%{public}s\n", static_cast<int>(state),
        magic_enum::Enum2Name(state).c_str());
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

    if (state == OperateResState::CONNECT_CONNECTING || state == OperateResState::CONNECT_AP_CONNECTED ||
        state == OperateResState::DISCONNECT_DISCONNECTING || state == OperateResState::DISCONNECT_DISCONNECTED ||
        state == OperateResState::CONNECT_OBTAINING_IP || state == OperateResState::CONNECT_ASSOCIATING ||
        state == OperateResState::CONNECT_ASSOCIATED || state == OperateResState::CONNECT_NETWORK_ENABLED ||
        state == OperateResState::CONNECT_NETWORK_DISABLED || state == OperateResState::SPECIAL_CONNECTED) {
        if (WifiConfigCenter::GetInstance().GetScanMidState(instId) == WifiOprMidState::RUNNING) {
            IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
            if (pService != nullptr) {
                pService->OnClientModeStatusChanged(static_cast<int>(state));
            }
        }
    }
    PublishWifiOperateStateHiSysEvent(state);
    if (info.connState == ConnState::AUTHENTICATING)
    {
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_AUTH),
            static_cast<int>(WifiOperateState::STA_AUTHING));
    }
#ifdef FEATURE_HPF_SUPPORT
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        int screenState = WifiSettings::GetInstance().GetScreenState();
        WifiManager::GetInstance().InstallPacketFilterProgram(screenState, instId);
    }
#endif
#ifndef OHOS_ARCH_LITE
    bool isConnected = (info.connState == CONNECTED) ? true : false;
    WifiProtectManager::GetInstance().UpdateWifiClientConnected(isConnected);
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        WifiBannerNotification::GetInstance().CancelWifiNotification(
            WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID);
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
    int len = cbMsg.pinCode.length();
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
}  // namespace Wifi
}  // namespace OHOS