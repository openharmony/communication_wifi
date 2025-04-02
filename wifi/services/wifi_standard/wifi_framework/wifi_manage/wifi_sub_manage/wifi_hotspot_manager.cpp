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

#ifdef FEATURE_AP_SUPPORT
#include "wifi_ap_msg.h"
#include "wifi_hotspot_manager.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_common_event_helper.h"
#include "wifi_system_timer.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "dhcp_c_api.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_sa_manager.h"
#endif

DEFINE_WIFILOG_LABEL("WifiHotspotManager");

namespace OHOS {
namespace Wifi {
WifiHotspotManager::WifiHotspotManager()
{
    WIFI_LOGI("create WifiHotspotManager");
    InitApCallback();
}

IApServiceCallbacks& WifiHotspotManager::GetApCallback()
{
    return mApCallback;
}

#ifndef OHOS_ARCH_LITE
static void UnloadHotspotSaTimerCallback()
{
#ifdef DYNAMIC_UNLOAD_SA
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::AP_CLOSE_DHCP_SA);
#endif
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_HOTSPOT_ABILITY_ID);
    WifiManager::GetInstance().GetWifiHotspotManager()->StopUnloadApSaTimer();
}

void WifiHotspotManager::StopUnloadApSaTimer(void)
{
    WIFI_LOGI("StopUnloadApSaTimer! unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
    std::unique_lock<std::mutex> lock(unloadHotspotSaTimerMutex);
    if (unloadHotspotSaTimerId == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(unloadHotspotSaTimerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(unloadHotspotSaTimerId);
    unloadHotspotSaTimerId = 0;
    return;
}

void WifiHotspotManager::StartUnloadApSaTimer(void)
{
    WIFI_LOGI("StartUnloadApSaTimer! unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
    std::unique_lock<std::mutex> lock(unloadHotspotSaTimerMutex);
    if (unloadHotspotSaTimerId == 0) {
        std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, true, false);
        wifiSysTimer->SetCallbackInfo(UnloadHotspotSaTimerCallback);
        unloadHotspotSaTimerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
        int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
        MiscServices::TimeServiceClient::GetInstance()->StartTimer(unloadHotspotSaTimerId,
            currentTime + TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("RegisterUnloadHotspotSaTimer success! unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
    }
    return;
}
#endif

void WifiHotspotManager::ApCloseDhcpSa(void)
{
#ifdef DYNAMIC_UNLOAD_SA
    int state = WifiConfigCenter::GetInstance().GetP2pState();
    if (state == static_cast<int>(P2pState::P2P_STATE_CLOSED)) {
        StopDhcpdServerSa();
    }
#endif
}

void WifiHotspotManager::CloseApService(int id)
{
    WIFI_LOGI("close %{public}d ap service", id);
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, id);
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, id);
    WifiConfigCenter::GetInstance().SetHotspotState(static_cast<int>(ApState::AP_STATE_CLOSED), id);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->SendMessage(CMD_AP_STOPPED, id);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(ApState::AP_STATE_CLOSED);
    cbMsg.id = id;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    std::string msg = std::string("OnHotspotStateChanged") + std::string("id = ") + std::to_string(id);
    HotspotMode mode = WifiConfigCenter::GetInstance().GetHotspotMode();
    WifiCommonEventHelper::PublishHotspotStateChangedEvent("HotspotMode", static_cast<int>(mode),
        static_cast<int>(ApState::AP_STATE_CLOSED), msg);
#ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close ap SA!");
        return;
    }
    StartUnloadApSaTimer();
#endif
    return;
}

void WifiHotspotManager::InitApCallback(void)
{
    using namespace std::placeholders;
    mApCallback.callbackModuleName = "WifiHotspotManager";
    mApCallback.OnApStateChangedEvent =
        [this](ApState state, int id) { this->DealApStateChanged(state, id); };
    mApCallback.OnHotspotStaJoinEvent =
        [this](const StationInfo &info, int id) { this->DealApGetStaJoin(info, id); };
    mApCallback.OnHotspotStaLeaveEvent =
        [this](const StationInfo &info, int id) { this->DealApGetStaLeave(info, id); };
    return;
}

void WifiHotspotManager::DealApStateChanged(ApState state, int id)
{
    WIFI_LOGE("%{public}s, state: %{public}d!", __func__, state);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(state);
    cbMsg.id = id;
    if (state == ApState::AP_STATE_IDLE) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, id);
        WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::AP_SERVICE_CLOSE);
    }
    if (state == ApState::AP_STATE_STARTED) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, id);
        auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
        ins->SendMessage(CMD_AP_START, id);
    }
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);

    std::string msg = std::string("OnHotspotStateChanged") + std::string("id = ") + std::to_string(id);
    HotspotMode mode = WifiConfigCenter::GetInstance().GetHotspotMode();
    WifiCommonEventHelper::PublishHotspotStateChangedEvent("HotspotMode", static_cast<int>(mode), (int)state, msg);
    return;
}

void WifiHotspotManager::DealApGetStaJoin(const StationInfo &info, int id)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_JOIN;
    cbMsg.staInfo = info;
    cbMsg.id = id;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    std::string msg = std::string("ApStaJoined") + std::string("id = ") + std::to_string(id);
    WifiCommonEventHelper::PublishApStaJoinEvent(0, msg);
    return;
}

void WifiHotspotManager::DealApGetStaLeave(const StationInfo &info, int id)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE;
    cbMsg.staInfo = info;
    cbMsg.id = id;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    std::string msg = std::string("ApStaLeaved") + std::string("id = ") + std::to_string(id);
    WifiCommonEventHelper::PublishApStaLeaveEvent(0, msg);
    return;
}

}  // namespace Wifi
}  // namespace OHOS
#endif