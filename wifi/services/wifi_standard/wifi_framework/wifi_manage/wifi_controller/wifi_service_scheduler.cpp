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
#include "wifi_history_record_manager.h"
#else
#include "wifi_internal_event_dispatcher_lite.h"
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
#include "wifi_asset_manager.h"
#endif
#ifdef WIFI_SECURITY_DETECT_ENABLE
#include "wifi_security_detect.h"
#endif
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif
#include "wifi_global_func.h"
#include "wifi_sensor_scene.h"

namespace OHOS {
namespace Wifi {
constexpr const char* WIFI_SELFCURE_PROP_CONFIG = "const.wifi.selfcure";
constexpr const int32_t WIFI_SELFCURE_PROP_SIZE = 16;
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
        } else {
            iter++;
        }
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
        } else {
            iter++;
        }
    }
}

ErrCode WifiServiceScheduler::AutoStartStaService(int instId, std::string &staIfName, int type)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartStaService, current sta state:%{public}d", staState);
    std::lock_guard<std::mutex> lock(mutex);
    if (staState == WifiOprMidState::RUNNING) {
        WIFI_LOGI("AutoStartStaService, cur sta state is running.");
    }
    if (PreStartWifi(instId, staIfName) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_OPENING, instId);
    WIFI_LOGI("AutoStartStaService startwifi iface:%{public}s instId:%{public}d",
        WifiConfigCenter::GetInstance().GetStaIfaceName(instId).c_str(), instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName(instId),
        instId);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartStaService start wifi fail.");
        WifiManager::GetInstance().GetWifiTogglerManager()->StopWifiToggledTimer();
        DispatchWifiOpenRes(OperateResState::OPEN_WIFI_FAILED, instId);
        return WIFI_OPT_FAILED;
    } else {
        WIFI_LOGE("AutoStartStaService start wifi instId:%{public}d success.", instId);
    }
    if (PostStartWifi(instId) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartStaService PostStartWifi instId:%{public}d", instId);
        return WIFI_OPT_FAILED;
    }
    DispatchWifiOpenRes(OperateResState::OPEN_WIFI_SUCCEED, instId);
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, instId);
    if (type != RESET_STA_TYPE_SELFCURE) {
        auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
        ins->HandleStaStartSuccess(instId);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStartWifi2Service(int instId, std::string &staIfName)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartWifi2Service, current sta state:%{public}d", staState);
    std::lock_guard<std::mutex> lock(mutex);
    if (staState == WifiOprMidState::RUNNING) {
        WIFI_LOGI("AutoStartWifi2Service, cur sta2 state is running.");
    }
    if (PreStartWifi(instId, staIfName) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }
    DispatchWifi2OpenRes(OperateResState::OPEN_WIFI_OPENING, instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName(instId),
        instId);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartWifi2Service start wifi fail.");
        return WIFI_OPT_FAILED;
    }
    if (PostStartWifi2(instId) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartWifi2Service PostStartWifi instId %{public}d", instId);
        return WIFI_OPT_FAILED;
    }
    DispatchWifi2OpenRes(OperateResState::OPEN_WIFI_SUCCEED, instId);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleWifi2Start(instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStopStaService(int instId, int type)
{
    WifiOprMidState staStateBefore = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStopStaService, current sta state:%{public}d", staStateBefore);
    std::lock_guard<std::mutex> lock(mutex);
    if (staStateBefore == WifiOprMidState::CLOSED) {
        WIFI_LOGI("AutoStopStaService, cur sta state is closed.");
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
        HandleGetStaFailed(instId);
        return WIFI_OPT_SUCCESS;
    }
    DispatchWifiCloseRes(OperateResState::CLOSE_WIFI_CLOSING, instId);
    ret = pService->DisableStaService();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable sta failed, ret %{public}d!", static_cast<int>(ret));
    }
    if (WifiStaHalInterface::GetInstance().StopWifi(instId) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("stop wifi failed.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, staStateBefore, instId)) {
            WIFI_LOGE("AutoStopStaService, set wifi mid state:%{public}d failed!", staStateBefore);
            return WIFI_OPT_FAILED;
        }
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::CLOSE_WIFI_FAILED), "TIME_OUT",
            static_cast<int>(staState));
        WifiManager::GetInstance().GetWifiTogglerManager()->ForceStopWifi();
        return WIFI_OPT_FAILED;
    }
    DispatchWifiCloseRes(OperateResState::CLOSE_WIFI_SUCCEED, instId);
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_STOPED, instId);
    if (type != RESET_STA_TYPE_SELFCURE) {
        auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
        ins->HandleStaClose(instId);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStopWifi2Service(int instId)
{
    WifiOprMidState staStateBefore = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStopWifi2Service, current sta state:%{public}d, instId:%{public}d",
        staStateBefore, instId);
    std::lock_guard<std::mutex> lock(mutex);
    if (staStateBefore == WifiOprMidState::CLOSED) {
        WIFI_LOGI("AutoStopWifi2Service, cur sta2 state is closed.");
    }
    ErrCode ret = WIFI_OPT_FAILED;

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staStateBefore, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGE("AutoStopWifi2Service,set wifi mid state closing failed!");
        return WIFI_OPT_FAILED;
    }

    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopWifi2Service, Instance get sta service is null!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        return WIFI_OPT_SUCCESS;
    }
    DispatchWifi2CloseRes(OperateResState::CLOSE_WIFI_CLOSING, instId);
    ret = pService->DisableStaService();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStopWifi2Service service disable sta failed, ret %{public}d!", static_cast<int>(ret));
    }
    if (WifiStaHalInterface::GetInstance().StopWifi(instId) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("AutoStopWifi2Service stop wifi failed.");
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, staStateBefore, instId)) {
            WIFI_LOGE("AutoStopWifi2Service, set wifi mid state:%{public}d failed!", staStateBefore);
            return WIFI_OPT_FAILED;
        }
    }
    DispatchWifi2CloseRes(OperateResState::CLOSE_WIFI_SUCCEED, instId);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleWifi2Close(instId);
    WIFI_LOGE("AutoStopWifi2Service %{public}d success!", instId);
    return WIFI_OPT_SUCCESS;
}

void WifiServiceScheduler::HandleGetStaFailed(int instId)
{
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
}

ErrCode WifiServiceScheduler::AutoStartScanOnly(int instId, std::string &staIfName)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("AutoStartScanOnly, Wifi scan only state is %{public}d, instId = %{public}d",
        static_cast<int>(curState), instId);
    std::lock_guard<std::mutex> lock(mutex);
    if (curState != WifiOprMidState::CLOSED && instId == 0) {
        WIFI_LOGE("ScanOnly State  is not closed.");
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
    if (ifaceName.empty() && !HalDeviceManager::GetInstance().CreateStaIface(
        [this](std::string &destoryIfaceName, int createIfaceType) {
            this->StaIfaceDestoryCallback(destoryIfaceName, createIfaceType);
        },
        [this](int index, int antRssi) { this->OnRssiReportCallback(index, antRssi);},
        [this](int type, const std::vector<uint8_t>& recvMsg) {
            this->OnNetlinkReportCallback(type, recvMsg);
        },
        ifaceName, instId)) {
        WIFI_LOGE("AutoStartScanOnly, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("AutoStartScanOnly SetStaIfaceName:%{public}s, instId:%{public}d", ifaceName.c_str(), instId);
    WifiConfigCenter::GetInstance().SetStaIfaceName(ifaceName);
    staIfName = ifaceName;
    staIfaceNameMap.insert(std::make_pair(instId, ifaceName));
#endif
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING, instId);
    if (instId == INSTID_WLAN0) {
        WifiManager::GetInstance().AutoStartEnhanceService();
    }
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
        WIFI_LOGI("AutoStopScanOnly, cur scan only state is not running.");
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
        HalDeviceManager::GetInstance().SetNetworkUpDown(
            WifiConfigCenter::GetInstance().GetStaIfaceName(instId), false);
#endif
    }
    WifiManager::GetInstance().GetWifiScanManager()->CheckAndStopScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
#ifdef DYNAMIC_UNLOAD_SA
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE, instId);
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::AutoStartSemiStaService(int instId, std::string &staIfName)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("AutoStartSemiStaService, current sta state:%{public}d", staState);
    std::lock_guard<std::mutex> lock(mutex);
    if (staState == WifiOprMidState::SEMI_ACTIVE) {
        WIFI_LOGI("AutoStartSemiStaService, cur sta state is semi active.");
    }
    if (PreStartWifi(instId, staIfName) != WIFI_OPT_SUCCESS) {
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_FAILED),
            "HAL_CREATE_FAILED", static_cast<int>(WifiConfigCenter::GetInstance().GetWifiMidState(instId)));
        WifiManager::GetInstance().GetWifiTogglerManager()->StopSemiWifiToggledTimer();
        return WIFI_OPT_FAILED;
    }
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_OPENING, instId);
    int ret = WifiStaHalInterface::GetInstance().StartWifi(WifiConfigCenter::GetInstance().GetStaIfaceName(instId),
        instId);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AutoStartSemiStaService start wifi fail.");
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_FAILED),
            "HAL_START_FAILED", static_cast<int>(WifiConfigCenter::GetInstance().GetWifiMidState(instId)));
        WifiManager::GetInstance().GetWifiTogglerManager()->StopSemiWifiToggledTimer();
        return WIFI_OPT_FAILED;
    }
    if (PostStartWifi(instId) != WIFI_OPT_SUCCESS) {
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_FAILED),
            "POST_START_FAILED", static_cast<int>(WifiConfigCenter::GetInstance().GetWifiMidState(instId)));
        WifiManager::GetInstance().GetWifiTogglerManager()->StopSemiWifiToggledTimer();
        return WIFI_OPT_FAILED;
    }
    DispatchWifiSemiActiveRes(OperateResState::ENABLE_SEMI_WIFI_SUCCEED, instId);
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_MSG_OPENED, instId);
    auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    ins->HandleStaSemiActive(instId);
    return WIFI_OPT_SUCCESS;
}

void WifiServiceScheduler::BroadCastWifiStateChange(WifiState state, int instId)
{
#ifdef FEATURE_SELF_CURE_SUPPORT
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId);
    if ((pSelfCureService != nullptr) && (pSelfCureService->CheckSelfCureWifiResult(SCE_EVENT_WIFI_STATE_CHANGED))) {
        WIFI_LOGW("DispatchWifiCloseRes, ignore to send duo to wifi self curing");
        return;
    }
#endif // FEATURE_SELF_CURE_SUPPORT
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    cbMsg.msgData = static_cast<int>(state);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
}

ErrCode WifiServiceScheduler::PreStartWifi(int instId, std::string &staIfName)
{
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    std::string ifaceName = "";
    if (staIfaceNameMap.count(instId) > 0) {
        ifaceName = staIfaceNameMap[instId];
        staIfName = ifaceName;
    }
    if (ifaceName.empty() && !HalDeviceManager::GetInstance().CreateStaIface(
        [this](std::string &destoryIfaceName, int createIfaceType) {
            this->StaIfaceDestoryCallback(destoryIfaceName, createIfaceType);
        },
        [this](int index, int antRssi) { this->OnRssiReportCallback(index, antRssi);},
        [this](int type, const std::vector<uint8_t>& recvMsg) {
            this->OnNetlinkReportCallback(type, recvMsg);
        },
        ifaceName, instId)) {
        WIFI_LOGE("PreStartWifi, create iface failed!");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("PreStartWifi SetStaIfaceName:%{public}s, instId:%{public}d", ifaceName.c_str(), instId);
    WifiConfigCenter::GetInstance().SetStaIfaceName(ifaceName, instId);
    staIfaceNameMap.insert(std::make_pair(instId, ifaceName));
    staIfName = WifiConfigCenter::GetInstance().GetStaIfaceName(instId);
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
    if (StartWifiStaService(instId) == WIFI_OPT_FAILED) {
        WIFI_LOGE("StartWifiStaService failed!");
    }
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
#ifdef FEATURE_P2P_SUPPORT
    // auto start p2p service if p2p has been active before
    if (WifiManager::GetInstance().GetWifiP2pManager()->HasP2pActivatedBefore()) {
        ErrCode errCode = WifiManager::GetInstance().GetWifiP2pManager()->AutoStartP2pService();
        if (errCode != WIFI_OPT_SUCCESS && errCode != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
            WIFI_LOGE("AutoStartStaService, AutoStartP2pService failed!");
        }
    }
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::PostStartWifi2(int instId)
{
    StartWifiStaService(instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::StartWifiStaService(int instId)
{
    if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_STA, instId) < 0) {
        WIFI_LOGE("StartWifiStaService Load %{public}s service failed!", WIFI_SERVICE_STA);
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGD("StartWifiStaService GetStaServiceInst instId:%{public}d", instId);
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("StartWifiStaService Create %{public}s service failed!", WIFI_SERVICE_STA);
        return WIFI_OPT_FAILED;
    }

    if (StartDependentService(instId) != WIFI_OPT_SUCCESS) {
        return WIFI_OPT_FAILED;
    }

    WIFI_LOGD("StartWifiStaService InitStaService instId:%{public}d", instId);
    if (InitStaService(pService, instId) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartWifiStaService InitStaService failed!");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGD("StartWifiStaService EnableStaService instId:%{public}d", instId);
    ErrCode errCode = pService->EnableStaService();
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartWifiStaService Service enable sta failed ,ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("get pEnhance service failed!");
        return WIFI_OPT_FAILED;
    }
    errCode = pService->SetEnhanceService(pEnhanceService);
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SetEnhanceService failed, ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
#ifdef FEATURE_SELF_CURE_SUPPORT
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(instId);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("get selfcure service failed");
        return WIFI_OPT_FAILED;
    }
    pService->SetSelfCureService(pSelfCureService);
#endif // FEATURE_SELF_CURE_SUPPORT
#endif
    WIFI_LOGI("StartWifiStaService instId%{public}d successful", instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::StartDependentService(int instId)
{
    if (instId != INSTID_WLAN0) {
        return WIFI_OPT_SUCCESS;
    }

#ifdef FEATURE_WIFI_PRO_SUPPORT
    if (StartWifiProService(instId) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartWifiProService failed!");
        return WIFI_OPT_FAILED;
    }
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (StartSelfCureService(instId) == WIFI_OPT_FAILED) {
        WIFI_LOGE("StartSelfCureService failed!");
        return WIFI_OPT_FAILED;
    }
#endif

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::InitStaService(IStaService *pService, int instId)
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
    if (instId == INSTID_WLAN0) {
        errCode = pService->RegisterStaServiceCallback(
            WifiManager::GetInstance().GetWifiScanManager()->GetStaCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("WifiScanManager register sta service callback failed!");
            return WIFI_OPT_FAILED;
        }
#ifndef OHOS_ARCH_LITE
        errCode = InitStaServiceExtral(pService, instId);
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitStaServiceExtral Register callback failed!");
            return WIFI_OPT_FAILED;
        }
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
        errCode = pService->RegisterStaServiceCallback(WifiAssetManager::GetInstance().GetStaCallback());
        WIFI_LOGI("WifiAssetManager register");
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("WifiAssetManager register sta service callback failed, ret=%{public}d!",
                static_cast<int>(errCode));
            return WIFI_OPT_FAILED;
        }
#endif
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiServiceScheduler::InitStaServiceExtral(IStaService *pService, int instId)
{
#ifndef OHOS_ARCH_LITE
    ErrCode errCode = pService->RegisterStaServiceCallback(
        WifiManager::GetInstance().GetWifiStaManager()->GetStaCallback());
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
    errCode = pService->RegisterStaServiceCallback(WifiHistoryRecordManager::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("WifiHistoryRecordManager register callback failed, ret=%{public}d", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
#ifdef WIFI_SECURITY_DETECT_ENABLE
    errCode = pService->RegisterStaServiceCallback(WifiSecurityDetect::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("WifiSecurityDetect register callback failed, ret=%{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
#endif
    errCode = pService->RegisterStaServiceCallback(WifiSensorScene::GetInstance().GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGI("WifiSensorScene register sta service callback failed, ret=%{public}d!", static_cast<int>(errCode));
    }
#endif
    return WIFI_OPT_SUCCESS;
}

#ifdef FEATURE_WIFI_PRO_SUPPORT
ErrCode WifiServiceScheduler::StartWifiProService(int instId)
{
    if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE) {
        WIFI_LOGI("factory mode, not start wifipro service");
        return WIFI_OPT_SUCCESS;
    }
    if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_WIFIPRO) < 0) {
        WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_WIFIPRO);
        return WIFI_OPT_FAILED;
    }
 
    IWifiProService *pWifiProService = WifiServiceManager::GetInstance().GetWifiProServiceInst(instId);
    if (pWifiProService == nullptr) {
        WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_WIFIPRO);
        return WIFI_OPT_FAILED;
    }
    ErrCode errCode = pWifiProService->InitWifiProService();
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Service enable wifi pro failed, ret %{public}d!", static_cast<int>(errCode));
        return WIFI_OPT_FAILED;
    }
 
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("Get %{public}s service failed!", WIFI_SERVICE_STA);
        return WIFI_OPT_FAILED;
    }

    errCode = pService->RegisterStaServiceCallback(pWifiProService->GetStaCallback());
    if (errCode != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("WifiPro register sta service callback failed!");
        return WIFI_OPT_FAILED;
    }
 
    return WIFI_OPT_SUCCESS;
}
#endif

#ifdef FEATURE_SELF_CURE_SUPPORT
ErrCode WifiServiceScheduler::StartSelfCureService(int instId)
{
    if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE) {
        WIFI_LOGI("factory mode, not start selfcure service");
        return WIFI_OPT_NOT_SUPPORTED;
    }
    char preValue[WIFI_SELFCURE_PROP_SIZE] = {0};
    int errorCode = GetParamValue(WIFI_SELFCURE_PROP_CONFIG, "true", preValue, WIFI_SELFCURE_PROP_SIZE);
    if ((errorCode > 0) && (strcmp(preValue, "false") == 0)) {
        WIFI_LOGI("due to disable selfcure, not start selfcure service");
        return WIFI_OPT_NOT_SUPPORTED;
    }

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
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->SendMessage(CMD_STA_REMOVED, createIfaceType, iter->first);
            if (createIfaceType >= 0) {
                WifiConfigCenter::GetInstance().SetStaIfaceName("", iter->first);
                staIfaceNameMap.erase(iter);
            }
            return;
        } else {
            iter++;
        }
    }
}

void WifiServiceScheduler::OnRssiReportCallback(int index, int antRssi)
{
    WIFI_LOGI("HwWiTas OnRssiReportCallback, index:%{public}d, antRssi:%{public}d", index, antRssi);

    std::string data = std::to_string(antRssi);
    WifiCommonEventHelper::PublishWiTasRssiValueChangedEvent(index, data);
}

void WifiServiceScheduler::OnNetlinkReportCallback(int type, const std::vector<uint8_t>& recvMsg)
{
    WIFI_LOGI("OnNetlinkReportCallback, type:%{public}d", type);
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("get pEnhance service failed!");
        return;
    }
    pEnhanceService->ProcessWifiNetlinkReportEvent(type, recvMsg);

    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pStaService == nullptr) {
        WIFI_LOGE("Instance get Sta service is null!");
        return;
    }
    pStaService->ProcessVoWifiNetlinkReportEvent(type);
}
#endif

void WifiServiceScheduler::DispatchWifiOpenRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiOpenRes, state:%{public}d", static_cast<int>(state));
    if (state == OperateResState::OPEN_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATING, instId);
        BroadCastWifiStateChange(WifiState::ENABLING, instId);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENING));
        return;
    }
    if (state == OperateResState::OPEN_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
        BroadCastWifiStateChange(WifiState::ENABLED, instId);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
            static_cast<int>(WifiOperateState::STA_OPENED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::ENABLE);
#if defined(FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT) && defined(FEATURE_WIFI_PRO_SUPPORT)
        IWifiProService *pWifiProService = WifiServiceManager::GetInstance().GetWifiProServiceInst(instId);
        if (pWifiProService != nullptr) {
            pWifiProService->OnWifiStateOpen(static_cast<int>(state));
        }
#endif
        return;
    }
    if (state == OperateResState::OPEN_WIFI_FAILED) {
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
        WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::OPEN_WIFI_FAILED),
            "HAL_FAIL", static_cast<int>(staState));
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_INACTIVE, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        BroadCastWifiStateChange(WifiState::DISABLED, instId);
        return;
    }
}

void WifiServiceScheduler::DispatchWifi2OpenRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifi2OpenRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::OPEN_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::ENABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }
    if (state == OperateResState::OPEN_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }
    return;
}

void WifiServiceScheduler::DispatchWifiSemiActiveRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiSemiActiveRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_SEMI_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::ENABLE_SEMI_WIFI_OPENING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiDetailState::STATE_SEMI_ACTIVATING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_SEMI_OPEN),
            static_cast<int>(WifiOperateState::STA_SEMI_OPENING));
        return;
    }
    if (state == OperateResState::ENABLE_SEMI_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVE, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::SEMI_ACTIVE, instId);
        cbMsg.msgData = static_cast<int>(WifiDetailState::STATE_SEMI_ACTIVE);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_SEMI_OPEN),
            static_cast<int>(WifiOperateState::STA_SEMI_OPENED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::SEMI_ENABLE);
#if defined(FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT) && defined(FEATURE_WIFI_PRO_SUPPORT)
        IWifiProService *pWifiProService = WifiServiceManager::GetInstance().GetWifiProServiceInst(instId);
        if (pWifiProService != nullptr) {
            pWifiProService->OnWifiStateClose(static_cast<int>(state));
        }
#endif
        return;
    }
}

void WifiServiceScheduler::DispatchWifiCloseRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifiCloseRes, state:%{public}d", static_cast<int>(state));
    if (state == OperateResState::CLOSE_WIFI_CLOSING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_DEACTIVATING, instId);
        BroadCastWifiStateChange(WifiState::DISABLING, instId);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSING));
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_INACTIVE, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo();
        WifiConfigCenter::GetInstance().SetP2pEnhanceActionListenChannel(0);
        BroadCastWifiStateChange(WifiState::DISABLED, instId);
        WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CLOSE),
            static_cast<int>(WifiOperateState::STA_CLOSED));
        WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::DISABLE);
#if defined(FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT) && defined(FEATURE_WIFI_PRO_SUPPORT)
        IWifiProService *pWifiProService = WifiServiceManager::GetInstance().GetWifiProServiceInst(instId);
        if (pWifiProService != nullptr) {
            pWifiProService->OnWifiStateClose(static_cast<int>(state));
        }
#endif
        return;
    }
}

void WifiServiceScheduler::DispatchWifi2CloseRes(OperateResState state, int instId)
{
    WIFI_LOGI("DispatchWifi2CloseRes, state:%{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.id = instId;
    if (state == OperateResState::CLOSE_WIFI_CLOSING) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLING), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_DEACTIVATING, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::DISABLED), instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_INACTIVE, instId);
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        return;
    }
}

/*--------------------------------------------------softAp------------------------------------------------------------*/

#ifdef FEATURE_AP_SUPPORT
ErrCode WifiServiceScheduler::AutoStartApService(int instId, std::string &softApIfName, int hotspotMode)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(instId);
    WIFI_LOGE("AutoStartApService, current ap state:%{public}d, hotspotMode=%{public}d", apState, hotspotMode);
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
    if (ifaceName.empty() && !HalDeviceManager::GetInstance().CreateApIface(
        [this](std::string &destoryIfaceName, int createIfaceType) {
            this->SoftApIfaceDestoryCallback(destoryIfaceName, createIfaceType);
        },
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
    ErrCode errCode = TryToStartApService(instId, hotspotMode);
    if (errCode != WIFI_OPT_SUCCESS) {
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

ErrCode WifiServiceScheduler::TryToStartApService(int instId, int hotspotMode)
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
#ifndef OHOS_ARCH_LITE
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            WifiManager::GetInstance().AutoStartEnhanceService();
            pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        }
        pService->SetEnhanceService(pEnhanceService);
#endif
        pService->SetHotspotMode(HotspotMode(hotspotMode));
        errCode = pService->EnableHotspot();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable ap failed, ret %{public}d!", static_cast<int>(errCode));
            pService->SetHotspotMode(HotspotMode::NONE);
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
            WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
            auto &ins = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
            ins->SendMessage(CMD_AP_REMOVED, createIfaceType, iter->first);
            if (createIfaceType >= 0) {
                softApIfaceNameMap.erase(iter);
            }
            return;
        } else {
            iter++;
        }
    }
}
#endif
#endif
}
}