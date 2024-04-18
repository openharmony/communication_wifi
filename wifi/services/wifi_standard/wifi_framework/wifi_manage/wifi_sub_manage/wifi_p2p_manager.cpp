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

#ifdef FEATURE_P2P_SUPPORT
#include "wifi_p2p_manager.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_common_event_helper.h"
#include "wifi_system_timer.h"
#include "wifi_hisysevent.h"
#include "p2p_define.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#include "wifi_sa_manager.h"
#endif
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

DEFINE_WIFILOG_LABEL("WifiP2pManager");

namespace OHOS {
namespace Wifi {
WifiP2pManager::WifiP2pManager()
{
    WIFI_LOGI("create WifiP2pManager");
    InitP2pCallback();
}

IP2pServiceCallbacks& WifiP2pManager::GetP2pCallback(void)
{
    return mP2pCallback;
}

ErrCode WifiP2pManager::AutoStartP2pService()
{
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("AutoStartP2pService, current p2p state:%{public}d", p2pState);
    if (p2pState != WifiOprMidState::CLOSED) {
        if (p2pState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }

#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateP2pIface(
        std::bind(&WifiP2pManager::IfaceDestoryCallback, this, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("AutoStartP2pService, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiSettings::GetInstance().SetP2pIfaceName(ifaceName);
#endif

    if (!WifiConfigCenter::GetInstance().SetP2pMidState(p2pState, WifiOprMidState::OPENING)) {
        WIFI_LOGE("AutoStartP2pService, set p2p mid state opening failed!");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }

    ErrCode ret = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_P2P) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_P2P);
            break;
        }
        IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_P2P);
            break;
        }
        ret = pService->RegisterP2pServiceCallbacks(mP2pCallback);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register p2p service callback failed!");
            break;
        }

        ret = pService->EnableP2p();
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service EnableP2p failed, ret %{public}d!", static_cast<int>(ret));
            break;
        }
    } while (false);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_P2P);
        return ret;
    }
#ifndef OHOS_ARCH_LITE
    StopUnloadP2PSaTimer();
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pManager::AutoStopP2pService()
{
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("AutoStopP2pService, current p2p state:%{public}d", p2pState);
    if (p2pState != WifiOprMidState::RUNNING) {
        if (p2pState == WifiOprMidState::OPENING) {
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }

    if (!WifiConfigCenter::GetInstance().SetP2pMidState(p2pState, WifiOprMidState::CLOSING)) {
        WIFI_LOGE("AutoStopP2pService, set p2p mid state opening failed!");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopP2pService, Instance get p2p service is null!");
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_P2P);
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }

    ErrCode ret = pService->DisableP2p();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable p2p failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING);
        return ret;
    }

    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
static void UnloadP2PSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_P2P_ABILITY_ID);
    WifiManager::GetInstance().GetWifiP2pManager()->StopUnloadP2PSaTimer();
}

void WifiP2pManager::StopUnloadP2PSaTimer(void)
{
    WIFI_LOGI("StopUnloadP2PSaTimer! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
    std::unique_lock<std::mutex> lock(unloadP2PSaTimerMutex);
    if (unloadP2PSaTimerId == 0) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(unloadP2PSaTimerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(unloadP2PSaTimerId);
    unloadP2PSaTimerId = 0;
    return;
}

void WifiP2pManager::StartUnloadP2PSaTimer(void)
{
    WIFI_LOGI("StartUnloadP2PSaTimer! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
    std::unique_lock<std::mutex> lock(unloadP2PSaTimerMutex);
    if (unloadP2PSaTimerId == 0) {
        std::shared_ptr<WifiSysTimer> wifiSysTimer = std::make_shared<WifiSysTimer>(false, 0, true, false);
        wifiSysTimer->SetCallbackInfo(UnloadP2PSaTimerCallback);
        unloadP2PSaTimerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(wifiSysTimer);
        int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
        MiscServices::TimeServiceClient::GetInstance()->StartTimer(unloadP2PSaTimerId,
            currentTime + TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("StartUnloadP2PSaTimer success! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
    }
    return;
}
#endif

void WifiP2pManager::CloseP2pService(void)
{
    WIFI_LOGD("close p2p service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_P2P);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
    WifiSettings::GetInstance().SetP2pState(static_cast<int>(P2pState::P2P_STATE_CLOSED));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(P2pState::P2P_STATE_CLOSED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!ifaceName.empty()) {
        DelayedSingleton<HalDeviceManager>::GetInstance()->RemoveP2pIface(ifaceName);
        ifaceName.clear();
        WifiSettings::GetInstance().SetP2pIfaceName("");
    }
#endif
#ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close p2p SA!");
        return;
    }
    StartUnloadP2PSaTimer();
#endif
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState();
    WIFI_LOGI("CloseP2pService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::OPENING || staState == WifiOprMidState::RUNNING) {
        AutoStartP2pService();
    }
    return;
}

void WifiP2pManager::InitP2pCallback(void)
{
    using namespace std::placeholders;
    mP2pCallback.callbackModuleName = "P2pManager";
    mP2pCallback.OnP2pStateChangedEvent = std::bind(&WifiP2pManager::DealP2pStateChanged, this, _1);
    mP2pCallback.OnP2pPeersChangedEvent = std::bind(&WifiP2pManager::DealP2pPeersChanged, this, _1);
    mP2pCallback.OnP2pServicesChangedEvent = std::bind(&WifiP2pManager::DealP2pServiceChanged, this, _1);
    mP2pCallback.OnP2pConnectionChangedEvent = std::bind(&WifiP2pManager::DealP2pConnectionChanged, this, _1);
    mP2pCallback.OnP2pThisDeviceChangedEvent = std::bind(&WifiP2pManager::DealP2pThisDeviceChanged, this, _1);
    mP2pCallback.OnP2pDiscoveryChangedEvent = std::bind(&WifiP2pManager::DealP2pDiscoveryChanged, this, _1);
    mP2pCallback.OnP2pGroupsChangedEvent = std::bind(&WifiP2pManager::DealP2pGroupsChanged, this);
    mP2pCallback.OnP2pActionResultEvent = std::bind(&WifiP2pManager::DealP2pActionResult, this, _1, _2);
    mP2pCallback.OnConfigChangedEvent = std::bind(&WifiP2pManager::DealConfigChanged, this, _1, _2, _3);
    mP2pCallback.OnP2pGcJoinGroupEvent = std::bind(&WifiP2pManager::DealP2pGcJoinGroup, this, _1);
    mP2pCallback.OnP2pGcLeaveGroupEvent = std::bind(&WifiP2pManager::DealP2pGcLeaveGroup, this, _1);
    return;
}

void WifiP2pManager::DealP2pStateChanged(P2pState state)
{
    WIFI_LOGI("DealP2pStateChanged, state: %{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(state);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    if (state == P2pState::P2P_STATE_IDLE) {
        WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::P2P_SERVICE_CLOSE);
    }
    if (state == P2pState::P2P_STATE_STARTED) {
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState();
        WIFI_LOGI("DealP2pStateChanged, current sta state:%{public}d", staState);
        if (staState == WifiOprMidState::CLOSING || staState == WifiOprMidState::CLOSED) {
            AutoStopP2pService();
        }
    }
    if (state == P2pState::P2P_STATE_CLOSED) {
        bool ret = WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        if (ret) {
            WIFI_LOGE("P2p start failed, stop wifi!");
            WifiSettings::GetInstance().SetWifiToggledState(false);
            WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(0, 0);
            cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
            cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
            WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        }
    }
    WifiCommonEventHelper::PublishP2pStateChangedEvent((int)state, "OnP2pStateChanged");
    return;
}

void WifiP2pManager::DealP2pPeersChanged(const std::vector<WifiP2pDevice> &vPeers)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_PEER_CHANGE;
    cbMsg.device = vPeers;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pPeersStateChangedEvent(vPeers.size(), "OnP2pPeersChanged");
    return;
}

void WifiP2pManager::DealP2pServiceChanged(const std::vector<WifiP2pServiceInfo> &vServices)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_SERVICE_CHANGE;
    cbMsg.serviceInfo = vServices;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiP2pManager::DealP2pConnectionChanged(const WifiP2pLinkedInfo &info)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CONNECT_CHANGE;
    cbMsg.p2pInfo = info;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pConnStateEvent((int)info.GetConnectState(), "OnP2pConnectStateChanged");
    WifiP2pGroupInfo group;
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return;
    }
    ErrCode errCode = pService->GetCurrentGroup(group);
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get current group info failed!");
        return;
    }
    WriteWifiP2pStateHiSysEvent(group.GetInterface(), (int32_t)info.IsGroupOwner(), (int32_t)info.GetConnectState());
    if (info.GetConnectState() == P2pConnectedState::P2P_CONNECTED) {
        WriteP2pKpiCountHiSysEvent(static_cast<int>(P2P_CHR_EVENT::CONN_SUC_CNT));
    }
    return;
}

void WifiP2pManager::DealP2pThisDeviceChanged(const WifiP2pDevice &info)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_THIS_DEVICE_CHANGE;
    cbMsg.p2pDevice = info;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pCurrentDeviceStateChangedEvent(
        (int)info.GetP2pDeviceStatus(), "OnP2pThisDeviceChanged");
    return;
}

void WifiP2pManager::DealP2pDiscoveryChanged(bool bState)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_DISCOVERY_CHANGE;
    cbMsg.msgData = static_cast<int>(bState);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiP2pManager::DealP2pGroupsChanged() __attribute__((no_sanitize("cfi")))
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_PERSISTENT_GROUPS_CHANGE;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pGroupStateChangedEvent(0, "OnP2pGroupStateChanged");
    return;
}

void WifiP2pManager::DealP2pActionResult(P2pActionCallback action, ErrCode code)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_ACTION_RESULT;
    cbMsg.p2pAction = action;
    cbMsg.msgData = static_cast<int>(code);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiP2pManager::DealP2pGcJoinGroup(const GcInfo &info)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_GC_JOIN_GROUP;
    cbMsg.gcInfo = info;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiP2pManager::DealP2pGcLeaveGroup(const GcInfo &info)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_GC_LEAVE_GROUP;
    cbMsg.gcInfo = info;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiP2pManager::DealConfigChanged(CfgType type, char* data, int dataLen)
{
    if (data == nullptr || dataLen <= 0) {
        return;
    }
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CFG_CHANGE;
    CfgInfo* cfgInfoPtr = new (std::nothrow) CfgInfo();
    if (cfgInfoPtr == nullptr) {
        WIFI_LOGE("DealConfigChanged: new CfgInfo failed");
        return;
    }
    cfgInfoPtr->type = type;
    char* cfgData = new (std::nothrow) char[dataLen];
    if (cfgData == nullptr) {
        WIFI_LOGE("DealConfigChanged: new data failed");
        delete cfgInfoPtr;
        return;
    }
    if (memcpy_s(cfgData, dataLen, data, dataLen) != EOK) {
        WIFI_LOGE("DealConfigChanged: memcpy_s failed");
        delete cfgInfoPtr;
        delete[] cfgData;
        return;
    }
    cfgInfoPtr->data = cfgData;
    cfgInfoPtr->dataLen = dataLen;
    cbMsg.cfgInfo = cfgInfoPtr;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiP2pManager::IfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    WIFI_LOGI("IfaceDestoryCallback, ifaceName:%{public}s, ifaceType:%{public}d",
        destoryIfaceName.c_str(), createIfaceType);
    if (destoryIfaceName == ifaceName) {
        ifaceName.clear();
        WifiSettings::GetInstance().SetP2pIfaceName("");
    }
    return;
}

}  // namespace Wifi
}  // namespace OHOS
#endif