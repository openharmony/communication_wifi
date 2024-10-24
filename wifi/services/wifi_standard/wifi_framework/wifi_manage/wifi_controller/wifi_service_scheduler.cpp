/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "wifi_service_scheduler.h"
#include "wifi_controller_define.h"
#include "wifi_manager.h"
#include "wifi_config_center.h"
#include "wifi_internal_msg.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_event_helper.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "wifi_country_code_manager.h"
#include "wifi_common_util.h"
#include "app_network_speed_limit_service.h"
#include "wifi_internal_event_dispatcher.h"
#else
#include "wifi_internal_event_dispatcher_lite.h"
#endif
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiServiceScheduler");
WifiServiceScheduler &WifiServiceScheduler::GetInstance()
{
    static WifiServiceScheduler gWifiServiceScheduler;
    return gWifiServiceScheduler;
}

WifiServiceScheduler::WifiServiceScheduler()
{
    WIFI_LOGI("WifiServiceScheduler");
}

WifiServiceScheduler::~WifiServiceScheduler()
{
    WIFI_LOGI("~WifiServiceScheduler");
}

void WifiServiceScheduler::ClearStaIfaceNameMap(int instId)
{
    WIFI_LOGI("ClearStaIfaceNameMap");
    std::lock_guard<std::mutex> lock(mutex);
    auto iter = staIfaceNameMap.begin();
    while (iter != staIfaceNameMap.end()) {
        if (iter->first == instId) {
            staIfaceNameMap.erase(iter);
            break;
        }
        iter++;
    }
}

void WifiServiceScheduler::ClearSoftApIfaceNameMap(int instId)
{
    WIFI_LOGI("ClearSoftApIfaceNameMap");
    std::lock_guard<std::mutex> lock(mutex);
    auto iter = softApIfaceNameMap.begin();
    while (iter != softApIfaceNameMap.end()) {
        if (iter->first == instId) {
            softApIfaceNameMap.erase(iter);
            break;
        }
        iter++;
    }
}

ErrCode WifiServiceScheduler::AutoStartStaService(int instId, std::string &staIfName)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartStaService, current sta state:%{public}d", staState);
    std::lock_guard<std::mutex> lock(mutex);
    if (staState == WifiOprMidState::RUNNING) {
        return WIFI_OPT_SUCCESS;
    }
    if (PreStartWifi(instId, staIfName) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_OPENING, instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName());
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartStaService start wifi fail.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::OPEN_WIFI_FAILED),
            "HAL_FAIL", static_cast<int>(staState));
        WifiManager::GetInstance().GetWifiTogglerManager()->StopWifiToggledTimer();
        return WIFI_OPT_FAILED;
    }
    if (PostStartWifi(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, instId);
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_SUCCEED, instId);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaStart(instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStopStaService(int instId)
{
    WifiOprMidState staStateBefore = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStopStaService, current sta state:%{public}d", staStateBefore);
    std::lock_guard<std::mutex> lock(mutex);
    if (staStateBefore == WifiOprMidState::CLOSED) {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ret = WIFI_OPT_FAILED;
#ifdef FEATURE_P2P_SUPPORT
    ret = WifiManager::GetInstance().GetWifiP2pManager()->AutoStopP2pService();
    if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED) {
        WIFI_LOGE("AutoStopStaService,AutoStopP2pService failed!");
    }
#endif

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staStateBefore, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGE("AutoStopStaService,set wifi mid state closing failed!");
        return WIFI_OPT_FAILED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopStaService, Instance get sta service is null!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
#ifdef FEATURE_SELF_CURE_SUPPORT
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SELFCURE, instId);
#endif
        return WIFI_OPT_SUCCESS;
    }
    DispatchWifiCloseRes(OperateResState::CLOSE_WIFI_CLOSING, instId);
    ret = pService->DisableStaService();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable sta failed, ret %{public}d!", static_cast<int>(ret));
    }
    if (WifiStaHalInterface::GetInstance().StopWifi() != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("stop wifi failed.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, staStateBefore, instId)) {
            WIFI_LOGE("AutoStopStaService, set wifi mid state:%{public}d failed!", staStateBefore);
            return WIFI_OPT_FAILED;
        }
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::CLOSE_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(staState));
        return WIFI_OPT_FAILED;
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_STOPED, instId);
    DispatchWifiCloseRes(OperateResState::CLOSE_WIFI_SUCCEED, instId);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaClose(instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStartScanOnly(int instId, std::string &staIfName)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("AutoStartScanOnly, Wifi scan only state is %{public}d", static_cast<int>(curState));
    std::lock_guard<std::mutex> lock(mutex);
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGE("ScanOnly State  is not closed, return\n");
        return WIFI_OPT_SUCCESS;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId) ||
        WifiOprMidState::OPENING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
        return WIFI_OPT_SUCCESS;
    }
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::string ifaceName = "";
    if (staIfaceNameMap.count(instId) > 0) {
        ifaceName = staIfaceNameMap[instId];
    }
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateStaIface(
        std::bind(&WifiServiceScheduler::StaIfaceDestoryCallback, this, std::placeholders::_1, std::placeholders::_2),
        std::bind(&WifiServiceScheduler::OnRssiReportCallback, this, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("AutoStartScanOnly, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetStaIfaceName(ifaceName);
    staIfName = ifaceName;
    staIfaceNameMap.insert(std::make_pair(instId, ifaceName));
#endif
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING, instId);
    WifiManager::GetInstance().AutoStartEnhanceService();
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStartScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStopScanOnly(int instId, bool setIfaceDown)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("AutoStopScanOnly, current wifi scan only state is %{public}d", static_cast<int>(curState));
    std::lock_guard<std::mutex> lock(mutex);
    if (curState != WifiOprMidState::RUNNING) {
        return WIFI_OPT_SUCCESS;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId) ||
        WifiOprMidState::OPENING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
        return WIFI_OPT_SUCCESS;
    }

    if (!WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGE("set wifi scan only mid state opening failed!");
        return WIFI_OPT_FAILED;
    }

    if (setIfaceDown) {
#ifdef HDI_CHIP_INTERFACE_SUPPORT
        DelayedSingleton<HalDeviceManager>::GetInstance()->SetNetworkUpDown(
            WifiConfigCenter::GetInstance().GetStaIfaceName(), false);
#endif
    }
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStopScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStartSemiStaService(int instId, std::string &staIfName)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartSemiStaService, current sta state:%{public}d", staState);
    std::lock_guard<std::mutex> lock(mutex);
    if (staState == WifiOprMidState::SEMI_ACTIVE) {
        return WIFI_OPT_SUCCESS;
    }
    if (PreStartWifi(instId, staIfName) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_OPENING, instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName());
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartSemiStaService start wifi fail.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(staState));
        return WIFI_OPT_FAILED;
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, instId);
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_SUCCEED, instId);
    if (PostStartWifi(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaSemiActive(instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::PreStartWifi(int instId, std::string &staIfName)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::string ifaceName = "";
    if (staIfaceNameMap.count(instId) > 0) {
        ifaceName = staIfaceNameMap[instId];
        staIfName = ifaceName;
    }
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateStaIface(
        std::bind(&WifiServiceScheduler::StaIfaceDestoryCallback, this, std::placeholders::_1, std::placeholders::_2),
        std::bind(&WifiServiceScheduler::OnRssiReportCallback, this, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("PreStartWifi, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetStaIfaceName(ifaceName);
    staIfaceNameMap.insert(std::make_pair(instId, ifaceName));
#endif
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::OPENING, instId)) {
        WIFI_LOGE("PreStartWifi, set wifi mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::PostStartWifi(int instId)
{
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_STA) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }
        if (InitStaService(pService) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitStaService failed!");
            break;
        }
#ifdef FEATURE_SELF_CURE_SUPPORT
        if (StartSelfCureService(instId) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("StartSelfCureService failed!");
            break;
        }
#endif
        errCode = pService->EnableStaService();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Service enable sta failed ,ret %{public}d!", static_cast<int>(errCode));
            break;
        }
#ifndef OHOS_ARCH_LITE
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService == nullptr) {
            WIFI_LOGE("get pEnhance service failed!");
            break;
        }
        errCode = pService->SetEnhanceService(pEnhanceService);
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetEnhanceService failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
#endif
    } while (0);
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
#ifdef FEATURE_P2P_SUPPORT
    errCode = WifiManager::GetInstance().GetWifiP2pManager()->AutoStartP2pService();
    if (errCode != WIFI_OPT_SUCCESS && errCode != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
        WIFI_LOGE("AutoStartStaService, AutoStartP2pService failed!");
    }
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::InitStaService(IStaService *pService)
{
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr");
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = pService->RegisterStaServiceCallback(
        WifiManager::GetInstance().GetWifiStaManager()->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
    errCode = pService->RegisterStaServiceCallback(WifiManager::GetInstance().GetWifiScanManager()->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("WifiScanManager register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    errCode = pService->RegisterStaServiceCallback(WifiCountryCodeManager::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("wifiCountryCodeManager register sta service callback failed, ret=%{public}d!",
            static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }

    errCode = pService->RegisterStaServiceCallback(AppNetworkSpeedLimitService::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AppNetworkSpeedLimitService register sta service callback failed, ret=%{public}d!",
            static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
#endif
    return WIFI_OPT_SUCCESS;
}

#ifdef FEATURE_SELF_CURE_SUPPORT
ErrCode WifiServiceScheduler::StartSelfCureService(int instId)
{
    if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_SELFCURE) < 0) {
        WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_SELFCURE);
        return WIFI_OPT_FAILED;
    }
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId);
    if (pSelfCureService == nullptr) {
        WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_SELFCURE);
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = pSelfCureService->InitSelfCureService();
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Service enable self cure failed, ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("Get %{public}s service failed!", WIFI_SERVICE_STA);
        return WIFI_OPT_FAILED;
    }
    errCode = pService->RegisterStaServiceCallback(pSelfCureService->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SelfCure register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
#endif

#ifdef HDI_CHIP_INTERFACE_SUPPORT
void WifiServiceScheduler::StaIfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    WIFI_LOGI("IfaceDestoryCallback, ifaceName:%{public}s, ifaceType:%{public}d",
        destoryIfaceName.c_str(), createIfaceType);
    auto iter = staIfaceNameMap.begin();
    while (iter != staIfaceNameMap.end()) {
        if (destoryIfaceName == iter->second) {
            WifiConfigCenter::GetInstance().SetStaIfaceName("");
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->SendMessage(CMD_STA_REMOVED, createIfaceType, iter->first);
            staIfaceNameMap.erase(iter);
            return;
        }
        iter++;
    }
}

void WifiServiceScheduler::OnRssiReportCallback(int index, int antRssi)
{
    WIFI_LOGI("HwWiTas OnRssiReportCallback, index:%{public}d, antRssi:%{public}d", index, antRssi);

    std::string data = std::to_string(antRssi);
    WifiCommonEventHelper::PublishWiTasRssiValueChangedEvent(index, data);
}
#endif

void WifiServiceScheduler::DispatchWifiOpenRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiOpenRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::OPEN_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::ENABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENING));
        return;
    }
    if (state == OperateResState::OPEN_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::ENABLE);
        return;
    }
}

void WifiServiceScheduler::DispatchWifiSemiActiveRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiSemiActiveRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::ENABLE_SEMI_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSING));
        return;
    }
    if (state == OperateResState::ENABLE_SEMI_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVE, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::SEMI_ACTIVE, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::SEMI_ENABLE);
        return;
    }
}

void WifiServiceScheduler::DispatchWifiCloseRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiCloseRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::CLOSE_WIFI_CLOSING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_DEACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        if (!WifiConfigCenter::GetInstance().GetWifiSelfcureReset()) {
            WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        }
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSING));
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_INACTIVE, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::DISABLE);
        return;
    }
}

/*--------------------------------------------------softAp------------------------------------------------------------*/

#ifdef FEATURE_AP_SUPPORT
ErrCode WifiServiceScheduler::AutoStartApService(int instId, std::string &softApIfName)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(instId);
    WIFI_LOGE("AutoStartApService, current ap state:%{public}d", apState);
    std::lock_guard<std::mutex> lock(mutex);
    if (apState != WifiOprMidState::CLOSED) {
        if (apState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_FAILED;
        } else {
            return WIFI_OPT_SUCCESS;
        }
    }
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::string ifaceName = "";
    if (softApIfaceNameMap.count(instId) > 0) {
        ifaceName = softApIfaceNameMap[instId];
    }
    if (ifaceName.empty() && !DelayedSingleton<HalDeviceManager>::GetInstance()->CreateApIface(
        std::bind(&WifiServiceScheduler::SoftApIfaceDestoryCallback,
        this, std::placeholders::_1, std::placeholders::_2),
        ifaceName)) {
        WIFI_LOGE("AutoStartApService, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetApIfaceName(ifaceName);
    softApIfName = ifaceName;
    softApIfaceNameMap.insert(std::make_pair(instId, ifaceName));
#endif
    if (!WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::OPENING, 0)) {
        WIFI_LOGE("AutoStartApService, set ap mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = TryToStartApService(instId);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, instId);
        return errCode;
    }
    WifiManager::GetInstance().GetWifiHotspotManager()->StopUnloadApSaTimer();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStopApService(int instId)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(instId);
    WIFI_LOGE("AutoStopApService, current ap state:%{public}d", apState);
    std::lock_guard<std::mutex> lock(mutex);
    if (apState != WifiOprMidState::RUNNING) {
        if (apState == WifiOprMidState::OPENING) {
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }

    if (!WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGE("AutoStopApService,set ap mid state closing failed!");
        return WIFI_OPT_SUCCESS;
    }

    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopApService, Instance get hotspot service is null!");
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, instId);
        return WIFI_OPT_SUCCESS;
    }

    ErrCode ret = pService->DisableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable ap failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING, instId);
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::TryToStartApService(int instId)
{
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_AP) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_AP);
            break;
        }
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(instId);
        if (pService == nullptr) {
            WIFI_LOGE("Instance get hotspot service is null!");
            break;
        }
        errCode = pService->RegisterApServiceCallbacks(
            WifiManager::GetInstance().GetWifiHotspotManager()->GetApCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register ap service callback failed!");
            break;
        }
        errCode = pService->RegisterApServiceCallbacks(WifiCountryCodeManager::GetInstance().GetApCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("WifiCountryCodeManager Register ap service callback failed! ret %{public}d!",
                static_cast<int>(errCode));
            break;
        }
        errCode = pService->EnableHotspot();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable ap failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (false);
    return errCode;
}

#ifdef HDI_CHIP_INTERFACE_SUPPORT
void WifiServiceScheduler::SoftApIfaceDestoryCallback(std::string &destoryIfaceName, int createIfaceType)
{
    WIFI_LOGI("IfaceDestoryCallback, ifaceName:%{public}s, ifaceType:%{public}d",
        destoryIfaceName.c_str(), createIfaceType);
    auto iter = softApIfaceNameMap.begin();
    while (iter != softApIfaceNameMap.end()) {
        if (destoryIfaceName == iter->second) {
            WifiConfigCenter::GetInstance().SetApIfaceName("");
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->SendMessage(CMD_AP_REMOVED, createIfaceType, iter->first);
            softApIfaceNameMap.erase(iter);
            return;
        }
        iter++;
    }
}
#endif
#endif
}
}