/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "wifi_manager.h"
#include <dirent.h>
#include "wifi_auth_center.h"
#include "wifi_chip_hal_interface.h"
#include "wifi_common_event_helper.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "wifi_sa_manager.h"
#include "common_timer_errors.h"
#include "wifi_datashare_utils.h"
#endif
#include "wifi_sta_hal_interface.h"
#include "wifi_service_manager.h"
#include "wifi_settings.h"
#include "define.h"
#include "wifi_config_center.h"
#include "wifi_common_def.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiManager");
int WifiManager::mCloseApIndex = 0;
#ifndef OHOS_ARCH_LITE
const uint32_t TIMEOUT_SCREEN_EVENT = 3000;
const uint32_t TIMEOUT_AIRPLANE_MODE_EVENT = 3000;
const uint32_t TIMEOUT_LOCATION_EVENT = 3000;
const uint32_t TIMEOUT_UNLOAD_WIFI_SA = 5 * 60 * 1000;
using TimeOutCallback = std::function<void()>;
#endif

WifiManager &WifiManager::GetInstance()
{
    static WifiManager gWifiManager;
    static std::mutex gInitMutex;
    if (gWifiManager.GetInitStatus() == INIT_UNKNOWN) {
        std::unique_lock<std::mutex> lock(gInitMutex);
        if (gWifiManager.GetInitStatus() == INIT_UNKNOWN) {
            if (gWifiManager.Init() != 0) {
                WIFI_LOGE("Failed to `WifiManager::Init` !");
            }
        }
    }

    return gWifiManager;
}

WifiManager::WifiManager() : mInitStatus(INIT_UNKNOWN), mSupportedFeatures(0)
{}

WifiManager::~WifiManager()
{
    Exit();
}

ErrCode WifiManager::AutoStartStaService(AutoStartOrStopServiceReason reason)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState();
    WIFI_LOGI("AutoStartStaService, current sta state:%{public}d, reason:%{public}d", staState, reason);
    if (staState != WifiOprMidState::CLOSED) {
        if (staState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }
    
    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::OPENING)) {
        WIFI_LOGI("AutoStartStaService, set wifi mid state opening failed!");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_STA) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_STA);
            break;
        }
        errCode = pService->RegisterStaServiceCallback(WifiManager::GetInstance().GetStaCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register sta service callback failed!");
            break;
        }
        errCode = pService->EnableWifi();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable sta failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
        return errCode;
    }

    StopUnloadStaSaTimer();
    if (reason == AutoStartOrStopServiceReason::STA_AP_EXCLUSION) {
        if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
            static_cast<int>(OperatorWifiType::USER_OPEN_WIFI_IN_AIRPLANEMODE)) {
            WIFI_LOGI("AutoStartStaService, user opened wifi in airplane mode!");
            return WIFI_OPT_SUCCESS;
        }

        int operatorWifiType = static_cast<int>(OperatorWifiType::USER_OPEN_WIFI_IN_NO_AIRPLANEMODE);
        if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
            operatorWifiType = static_cast<int>(OperatorWifiType::USER_OPEN_WIFI_IN_AIRPLANEMODE);
            WIFI_LOGI("AutoStartStaService, current airplane mode is opened, user open wifi!");
        }
        WifiConfigCenter::GetInstance().SetOperatorWifiType(operatorWifiType);
    }
#ifdef  FEATURE_P2P_SUPPORT
    errCode = AutoStartP2pService(reason);
    if (errCode != WIFI_OPT_SUCCESS && errCode != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
        WIFI_LOGE("AutoStartStaService, AutoStartP2pService failed!");
    }
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiManager::AutoStopStaService(AutoStartOrStopServiceReason reason)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState();
    WIFI_LOGI("AutoStopStaService, current sta state:%{public}d, reason:%{public}d", staState, reason);
    if (staState != WifiOprMidState::RUNNING) {
        if (staState == WifiOprMidState::OPENING) {
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }

    ErrCode ret = WIFI_OPT_FAILED;
#ifdef  FEATURE_P2P_SUPPORT
    ret = AutoStopP2pService(reason);
    if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED) {
        WIFI_LOGE("AutoStopStaService, AutoStopP2pService failed!");
    }
#endif

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSING)) {
        WIFI_LOGI("AutoStopStaService, set wifi mid state opening failed!");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopStaService, Instance get sta service is null!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }

    ret = pService->DisableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable sta failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING);
        return ret;
    }

    WifiConfigCenter::GetInstance().SetStaLastRunState(false);
    if (reason == AutoStartOrStopServiceReason::AIRPLANE_MODE) {
        WIFI_LOGI("DealOpenAirplaneModeEvent, auto stop wifi success!");
        WifiConfigCenter::GetInstance().SetOperatorWifiType(
            static_cast<int>(OperatorWifiType::CLOSE_WIFI_DUE_TO_AIRPLANEMODE_OPENED));
    } else if (reason == AutoStartOrStopServiceReason::STA_AP_EXCLUSION) {
        WifiConfigCenter::GetInstance().SetStaApExclusionType(
            static_cast<int>(StaApExclusionType::USER_OPEN_AP_AUTO_STOP_WIFI));
    }
    return WIFI_OPT_SUCCESS;
}

void WifiManager::AutoStartScanOnly(void)
{
    if (!WifiSettings::GetInstance().CheckScanOnlyAvailable() ||
        !WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) {
        WIFI_LOGI("No need to StartScanOnly, return");
        return;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState();
    WIFI_LOGI("Wifi scan only state is %{public}d", static_cast<int>(curState));
    
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("scanOnly state is not closed, return");
        return;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState()) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
        return;
    }

    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING);
    CheckAndStartScanService();
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("[AutoStartScanOnly] scan service is null.");
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return;
    }
    ErrCode ret = pService->StartWpa();
    if (ret != static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGE("Start Wpa failed");
    }
    ret = pService->OpenScanOnly();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return;
    }
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
}

void WifiManager::AutoStopScanOnly(void)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState();
    WIFI_LOGI("current wifi scan only state is %{public}d", static_cast<int>(curState));
    if (curState != WifiOprMidState::RUNNING) {
        return;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState()) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return;
    }

    if (!WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSING)) {
        WIFI_LOGI("set wifi scan only mid state opening failed!");
        return;
    }

    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return;
    }
    ErrCode ret = pService->CloseWpa();
    if (ret != static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGE("Stop Wpa failed");
    }
    ret = pService->CloseScanOnly();
    if (ret == WIFI_OPT_SUCCESS) {
        WIFI_LOGD("set wifi scan only mid state closed");
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
    }
}

void WifiManager::ForceStopWifi(void)
{
    WIFI_LOGI("Enter ForceStopWifi");
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr || (pService->DisableWifi() != WIFI_OPT_SUCCESS)) {
        WIFI_LOGE("service is null or disable wifi failed.");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
        WifiEventCallbackMsg cbMsg;
        cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
        cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
        return;
    }
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    WIFI_LOGI("In force stop wifi, state: %{public}d", static_cast<int>(curState));
    WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::CLOSED);
}

void WifiManager::CheckAndStartSta(AutoStartOrStopServiceReason reason)
{
    DIR *dir = nullptr;
    struct dirent *dent = nullptr;
    int currentWaitTime = 0;
    const int sleepTime = 1;
    const int maxWaitTimes = 30;

    while (currentWaitTime < maxWaitTimes) {
        dir = opendir("/sys/class/net");
        if (dir == nullptr) {
            WifiManager::GetInstance().AutoStartStaService(reason);
            return;
        }
        while ((dent = readdir(dir)) != nullptr) {
            if (dent->d_name[0] == '.') {
                continue;
            }
            if (strncmp(dent->d_name, "wlan", strlen("wlan")) == 0) {
                closedir(dir);
                WifiManager::GetInstance().AutoStartStaService(reason);
                return;
            }
        }
        closedir(dir);
        sleep(sleepTime);
        currentWaitTime++;
    }
    WifiManager::GetInstance().AutoStartStaService(reason);
}

void WifiManager::AutoStartServiceThread(AutoStartOrStopServiceReason reason)
{
    WIFI_LOGI("Auto start service...");
    CheckAndStartSta(reason);
}

#ifdef FEATURE_AP_SUPPORT
ErrCode WifiManager::AutoStartApService(AutoStartOrStopServiceReason reason)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState();
    WIFI_LOGI("AutoStartApService, current ap state:%{public}d, reason:%{public}d", apState, reason);
    if (apState != WifiOprMidState::CLOSED) {
        if (apState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }

    if (!WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::OPENING, 0)) {
        WIFI_LOGI("AutoStartApService, set ap mid state opening failed!");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }

    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_AP) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_AP);
            break;
        }
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("Instance get hotspot service is null!");
            break;
        }
        errCode = pService->RegisterApServiceCallbacks(WifiManager::GetInstance().GetApCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register ap service callback failed!");
            break;
        }
        errCode = pService->EnableHotspot();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable ap failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (false);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, 0);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, 0);
        return errCode;
    }

    StopUnloadApSaTimer();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiManager::AutoStopApService(AutoStartOrStopServiceReason reason)
{
    WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState();
    WIFI_LOGI("AutoStopApService, current ap state:%{public}d, reason:%{public}d", apState, reason);
    if (apState != WifiOprMidState::RUNNING) {
        if (apState == WifiOprMidState::OPENING) {
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }

    if (!WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, 0)) {
        WIFI_LOGI("AutoStopApService, set ap mid state closing failed!");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }

    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopApService, Instance get hotspot service is null!");
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, 0);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, 0);
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
        
    ErrCode ret = pService->DisableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable ap failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING, 0);
        return ret;
    }

    if (reason == AutoStartOrStopServiceReason::STA_AP_EXCLUSION) {
        WifiConfigCenter::GetInstance().SetStaApExclusionType(
            static_cast<int>(StaApExclusionType::USER_OPEN_WIFI_AUTO_STOP_AP));
    }
    return WIFI_OPT_SUCCESS;
}

#endif

#ifdef FEATURE_P2P_SUPPORT
WifiCfgMonitorEventCallback WifiManager::cfgMonitorCallback = {
    nullptr,
};

ErrCode WifiManager::AutoStartP2pService(AutoStartOrStopServiceReason reason)
{
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("AutoStartP2pService, current p2p state:%{public}d, reason:%{public}d", p2pState, reason);
    if (p2pState != WifiOprMidState::CLOSED) {
        if (p2pState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }

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
        ret = pService->RegisterP2pServiceCallbacks(WifiManager::GetInstance().GetP2pCallback());
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

    StopUnloadP2PSaTimer();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiManager::AutoStopP2pService(AutoStartOrStopServiceReason reason)
{
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("AutoStopP2pService, current p2p state:%{public}d, reason:%{public}d", p2pState, reason);
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
#endif

void WifiManager::AutoStartScanService(void)
{
    WIFI_LOGI("AutoStartScanService");
    if (!WifiConfigCenter::GetInstance().IsScanAlwaysActive()) {
        WIFI_LOGW("Scan always is not open, not open scan service.");
        return;
    }
    ScanControlInfo info;
    WifiConfigCenter::GetInstance().GetScanControlInfo(info);
    if (!IsAllowScanAnyTime(info)) {
        WIFI_LOGW("Scan control does not support scan always, not open scan service here.");
        return;
    }
    CheckAndStartScanService();
    return;
}

int WifiManager::Init()
{
    if (WifiConfigCenter::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiConfigCenter Init failed!");
        mInitStatus = CONFIG_CENTER_INIT_FAILED;
        return -1;
    }
    if (WifiAuthCenter::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiAuthCenter Init failed!");
        mInitStatus = AUTH_CENTER_INIT_FAILED;
        return -1;
    }
    if (WifiServiceManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiServiceManager Init failed!");
        mInitStatus = SERVICE_MANAGER_INIT_FAILED;
        return -1;
    }
    if (WifiInternalEventDispatcher::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiInternalEventDispatcher Init failed!");
        mInitStatus = EVENT_BROADCAST_INIT_FAILED;
        return -1;
    }
    mCloseServiceThread = std::thread(WifiManager::DealCloseServiceMsg, std::ref(*this));
    pthread_setname_np(mCloseServiceThread.native_handle(), "WifiCloseThread");
    
#ifndef OHOS_ARCH_LITE
    if (screenEventSubscriber_ == nullptr && screenTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(&WifiManager::RegisterScreenEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, screenTimerId, TIMEOUT_SCREEN_EVENT, false);
        WIFI_LOGI("RegisterScreenEvent success! screenTimerId:%{public}u", screenTimerId);
    }
    if (airplaneModeEventSubscriber_ == nullptr && airplaneModeTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(&WifiManager::RegisterAirplaneModeEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, airplaneModeTimerId, TIMEOUT_AIRPLANE_MODE_EVENT, false);
        WIFI_LOGI("RegisterAirplaneModeEvent success! airplaneModeTimerId:%{public}u", airplaneModeTimerId);
    }
    if (locationEventSubscriber_ == nullptr && locationTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(&WifiManager::RegisterLocationEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, locationTimerId, TIMEOUT_LOCATION_EVENT, false);
        WIFI_LOGI("RegisterLocationEvent success! locationTimerId:%{public}u", locationTimerId);
    }
#endif
    mInitStatus = INIT_OK;
    InitStaCallback();
    InitScanCallback();
#ifdef FEATURE_AP_SUPPORT
    InitApCallback();
#endif
#ifdef FEATURE_P2P_SUPPORT
    InitP2pCallback();
#endif
    if (WifiServiceManager::GetInstance().CheckPreLoadService() < 0) {
        WIFI_LOGE("WifiServiceManager check preload feature service failed!");
        WifiManager::GetInstance().Exit();
        return -1;
    }
    if (WifiConfigCenter::GetInstance().GetStaLastRunState()
        || (WifiConfigCenter::GetInstance().GetStaApExclusionType()
            == static_cast<int>(StaApExclusionType::USER_OPEN_AP_AUTO_STOP_WIFI)
            && WifiConfigCenter::GetInstance().GetApMidState() == WifiOprMidState::CLOSED)) { /* Automatic startup upon startup */
        if (WifiConfigCenter::GetInstance().GetStaApExclusionType()
            == static_cast<int>(StaApExclusionType::USER_OPEN_AP_AUTO_STOP_WIFI)) {
            WifiConfigCenter::GetInstance().SetStaApExclusionType(static_cast<int>(StaApExclusionType::INITIAL_TYPE));
        }
        WIFI_LOGI("AutoStartServiceThread");
        std::thread startStaSrvThread(WifiManager::AutoStartServiceThread,
            AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP);
        pthread_setname_np(startStaSrvThread.native_handle(), "AutoStartThread");
        startStaSrvThread.detach();
    } else {
        /**
         * The sta service automatically starts upon startup. After the sta
         * service is started, the scanning is directly started.
         */
        AutoStartEnhanceService();
#ifndef OHOS_ARCH_LITE
        WifiSaLoadManager::GetInstance().LoadWifiSa(WIFI_SCAN_ABILITY_ID);
#endif
        if ((WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
            WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) ||
            WifiConfigCenter::GetInstance().IsScanAlwaysActive()) {
            CheckAndStartScanService();
            IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
            if (pService != nullptr) {
                int res = pService->StartWpa();
                if (res != static_cast<int>(WIFI_IDL_OPT_OK)) {
                    WIFI_LOGE("Start Wpa failed");
                    if (WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
                        WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) {
                        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
                    }
                }
                if (WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
                    WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) {
                    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
                }
            }
        }
#ifndef OHOS_ARCH_LITE
        else {
            WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_SCAN_ABILITY_ID);
        }
#endif
    }

    InitPidfile();
    return 0;
}

void WifiManager::Exit()
{
    WIFI_LOGI("[WifiManager] Exit.");
    WifiServiceManager::GetInstance().UninstallAllService();
    /* NOTE:: DO NOT allow call hal interface function, delete at 2022.10.16 */
    /* Refer to WifiStaHalInterface::GetInstance().ExitAllIdlClient(); */
    WifiInternalEventDispatcher::GetInstance().Exit();
    if (mCloseServiceThread.joinable()) {
        PushServiceCloseMsg(WifiCloseServiceCode::SERVICE_THREAD_EXIT);
        mCloseServiceThread.join();
    }
#ifndef OHOS_ARCH_LITE
    if (screenEventSubscriber_ != nullptr) {
        UnRegisterScreenEvent();
    }

    if (airplaneModeEventSubscriber_ != nullptr) {
        UnRegisterAirplaneModeEvent();
    }

    if (locationEventSubscriber_ != nullptr) {
        UnRegisterLocationEvent();
    }
#endif
    return;
}

void WifiManager::PushServiceCloseMsg(WifiCloseServiceCode code)
{
    std::unique_lock<std::mutex> lock(mMutex);
    mEventQue.push_back(code);
    mCondition.notify_one();
    return;
}

void WifiManager::AddSupportedFeatures(WifiFeatures feature)
{
    mSupportedFeatures |= static_cast<long>(feature);
}

int WifiManager::GetSupportedFeatures(long &features) const
{
    long supportedFeatures = mSupportedFeatures;
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_INFRA);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_INFRA_5G);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_PASSPOINT);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_AP_STA);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_WPA3_SAE);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_WPA3_SUITE_B);
    supportedFeatures |= static_cast<long>(WifiFeatures::WIFI_FEATURE_OWE);
    /* NOTE: features = supportedFeatures & WifiChipHalInterface::GetInstance().GetChipCapabilities */
    /* It does NOT allow call HalInterface from wifi_manager */
    features = supportedFeatures;
    return 0;
}

InitStatus WifiManager::GetInitStatus()
{
    return mInitStatus;
}

#ifndef OHOS_ARCH_LITE
uint32_t WifiManager::unloadStaSaTimerId{0};
std::mutex WifiManager::unloadStaSaTimerMutex{};
void WifiManager::UnloadStaSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_DEVICE_ABILITY_ID);
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_SCAN_ABILITY_ID);
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_P2P_ABILITY_ID);
    if (static_cast<int>(ApState::AP_STATE_CLOSED) == WifiConfigCenter::GetInstance().GetHotspotState(0)) {
        WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_HOTSPOT_ABILITY_ID);
    }
    WifiManager::GetInstance().StopUnloadStaSaTimer();
}

void WifiManager::StopUnloadStaSaTimer(void)
{
    WIFI_LOGI("StopUnloadStaSaTimer! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
    std::unique_lock<std::mutex> lock(unloadStaSaTimerMutex);
    WifiTimer::GetInstance()->UnRegister(unloadStaSaTimerId);
    unloadStaSaTimerId = 0;
    return;
}

void WifiManager::StartUnloadStaSaTimer(void)
{
    WIFI_LOGI("StartUnloadStaSaTimer! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
    std::unique_lock<std::mutex> lock(unloadStaSaTimerMutex);
    if (unloadStaSaTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadStaSaTimerCallback);
        WifiTimer::GetInstance()->Register(timeoutCallback, unloadStaSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("StartUnloadStaSaTimer success! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
    }
    return;
}
#endif

void WifiManager::CloseStaService(void)
{
    WIFI_LOGI("close sta service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime();
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#ifdef FEATURE_P2P_SUPPORT
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("CloseStaService, current p2p state: %{public}d", p2pState);
    if (p2pState == WifiOprMidState::RUNNING) {
        WifiManager::GetInstance().AutoStopP2pService(
            AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
    }
#endif
#ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close sta SA!");
        return;
    }
    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState()) {
        WIFI_LOGI("scanonly not close sta SA!");
        return;
    }
    WifiManager::GetInstance().StartUnloadStaSaTimer();
#endif
    return;
}

#ifdef FEATURE_AP_SUPPORT

#ifndef OHOS_ARCH_LITE
uint32_t WifiManager::unloadHotspotSaTimerId{0};
std::mutex WifiManager::unloadHotspotSaTimerMutex{};
void WifiManager::UnloadHotspotSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_HOTSPOT_ABILITY_ID);
    WifiManager::GetInstance().StopUnloadApSaTimer();
}

void WifiManager::StopUnloadApSaTimer(void)
{
    WIFI_LOGI("StopUnloadApSaTimer! unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
    std::unique_lock<std::mutex> lock(unloadHotspotSaTimerMutex);
    WifiTimer::GetInstance()->UnRegister(unloadHotspotSaTimerId);
    unloadHotspotSaTimerId = 0;
    return;
}

void WifiManager::StartUnloadApSaTimer(void)
{
    WIFI_LOGI("StartUnloadApSaTimer! unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
    std::unique_lock<std::mutex> lock(unloadHotspotSaTimerMutex);
    if (unloadHotspotSaTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadHotspotSaTimerCallback);
        WifiTimer::GetInstance()->Register(timeoutCallback, unloadHotspotSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("RegisterUnloadHotspotSaTimer success! unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
    }
    return;
}
#endif

void WifiManager::CloseApService(int id)
{
    WIFI_LOGI("close %{public}d ap service", id);
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, id);
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, id);
    WifiSettings::GetInstance().SetHotspotState(static_cast<int>(ApState::AP_STATE_CLOSED), id);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(ApState::AP_STATE_CLOSED);
    cbMsg.id = id;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    #ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close ap SA!");
        return;
    }
    WifiManager::GetInstance().StartUnloadApSaTimer();
    #endif
    return;
}
#endif

void WifiManager::CloseScanService(void)
{
    WIFI_LOGI("close scan service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN);
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED);
    return;
}

#ifdef FEATURE_P2P_SUPPORT

#ifndef OHOS_ARCH_LITE
uint32_t WifiManager::unloadP2PSaTimerId{0};
std::mutex WifiManager::unloadP2PSaTimerMutex{};
void WifiManager::UnloadP2PSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_P2P_ABILITY_ID);
    WifiManager::GetInstance().StopUnloadP2PSaTimer();
}

void WifiManager::StopUnloadP2PSaTimer(void)
{
    WIFI_LOGI("StopUnloadP2PSaTimer! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
    std::unique_lock<std::mutex> lock(unloadP2PSaTimerMutex);
    WifiTimer::GetInstance()->UnRegister(unloadP2PSaTimerId);
    unloadP2PSaTimerId = 0;
    return;
}

void WifiManager::StartUnloadP2PSaTimer(void)
{
    WIFI_LOGI("StartUnloadP2PSaTimer! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
    std::unique_lock<std::mutex> lock(unloadP2PSaTimerMutex);
    if (unloadP2PSaTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadP2PSaTimerCallback);
        WifiTimer::GetInstance()->Register(timeoutCallback, unloadP2PSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("StartUnloadP2PSaTimer success! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
    }
    return;
}
#endif

void WifiManager::CloseP2pService(void)
{
    WIFI_LOGD("close p2p service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_P2P);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
    WifiSettings::GetInstance().SetP2pState(static_cast<int>(P2pState::P2P_STATE_CLOSED));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(P2pState::P2P_STATE_CLOSED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    #ifndef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WIFI_LOGI("airplaneMode not close p2p SA!");
        return;
    }
    WifiManager::GetInstance().StartUnloadP2PSaTimer();
    #endif
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState();
    WIFI_LOGI("CloseP2pService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::OPENING || staState == WifiOprMidState::RUNNING) {
        WifiManager::GetInstance().AutoStartP2pService(
            AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
    }
    return;
}
#endif

void WifiManager::DealCloseServiceMsg(WifiManager &manager)
{
    const int waitDealTime = 10 * 1000; /* 10 ms */
    while (true) {
        std::unique_lock<std::mutex> lock(manager.mMutex);
        while (manager.mEventQue.empty()) {
            manager.mCondition.wait(lock);
        }
        WifiCloseServiceCode msg = manager.mEventQue.front();
        manager.mEventQue.pop_front();
        lock.unlock();
        usleep(waitDealTime);
        switch (msg) {
            case WifiCloseServiceCode::STA_SERVICE_CLOSE:
                CloseStaService();
                break;
            case WifiCloseServiceCode::SCAN_SERVICE_CLOSE:
                CloseScanService();
                break;
#ifdef FEATURE_AP_SUPPORT
            case WifiCloseServiceCode::AP_SERVICE_CLOSE:
                CloseApService(mCloseApIndex);
                break;
#endif
#ifdef FEATURE_P2P_SUPPORT
            case WifiCloseServiceCode::P2P_SERVICE_CLOSE:
                CloseP2pService();
                break;
#endif
            case WifiCloseServiceCode::SERVICE_THREAD_EXIT:
                WIFI_LOGI("DealCloseServiceMsg thread exit!");
                return;
            default:
                WIFI_LOGW("Unknown message code, %{public}d", static_cast<int>(msg));
                break;
        }
    }
    WIFI_LOGD("WifiManager Thread exit");
    return;
}

void WifiManager::InitStaCallback(void)
{
    mStaCallback.OnStaOpenRes = DealStaOpenRes;
    mStaCallback.OnStaCloseRes = DealStaCloseRes;
    mStaCallback.OnStaConnChanged = DealStaConnChanged;
    mStaCallback.OnWpsChanged = DealWpsChanged;
    mStaCallback.OnStaStreamChanged = DealStreamChanged;
    mStaCallback.OnStaRssiLevelChanged = DealRssiChanged;
    return;
}

StaServiceCallback WifiManager::GetStaCallback()
{
    return mStaCallback;
}

void WifiManager::DealStaOpenRes(OperateResState state)
{
    WIFI_LOGI("Enter DealStaOpenRes: %{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    if (state == OperateResState::OPEN_WIFI_OPENING) {
        cbMsg.msgData = static_cast<int>(WifiState::ENABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        return;
    }
    if ((state == OperateResState::OPEN_WIFI_FAILED) || (state == OperateResState::OPEN_WIFI_DISABLED)) {
        WIFI_LOGE("DealStaOpenRes:wifi open failed!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        DealStaCloseRes(state);
        return;
    }

    WIFI_LOGI("DealStaOpenRes:wifi open successfully!");
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WifiConfigCenter::GetInstance().SetWifiStateWhenAirplaneMode(true);
        if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
            static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED)) {
            DealAirplaneExceptionWhenStaOpen();
            return;
        }
    }
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
    WifiConfigCenter::GetInstance().SetStaLastRunState(true);
    cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#ifdef FEATURE_P2P_SUPPORT
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("DealStaOpenRes, current p2p state:%{public}d", p2pState);
    if (p2pState == WifiOprMidState::CLOSED) {
        WifiManager::GetInstance().AutoStartP2pService(
            AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
    }
#endif
    AutoStartEnhanceService();
    CheckAndStartScanService();

    if (WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
        WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
    }
}

void WifiManager::DealStaCloseRes(OperateResState state)
{
    WIFI_LOGI("Enter DealStaCloseRes: %{public}d", static_cast<int>(state));
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    if (state == OperateResState::CLOSE_WIFI_CLOSING) {
        cbMsg.msgData = static_cast<int>(WifiState::DISABLING);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_FAILED) {
        WIFI_LOGI("DealStaCloseRes: broadcast wifi close failed event!");
        ForceStopWifi();
        cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WifiConfigCenter::GetInstance().SetWifiStateWhenAirplaneMode(false);
    }
#ifdef FEATURE_STA_AP_EXCLUSION
    if (WifiConfigCenter::GetInstance().GetStaApExclusionType()
        == static_cast<int>(StaApExclusionType::USER_OPEN_AP_AUTO_STOP_WIFI)) {
        WifiManager::GetInstance().AutoStartApService(AutoStartOrStopServiceReason::STA_AP_EXCLUSION);
    }
#endif
    if (WifiOprMidState::RUNNING != WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState()) {
        WIFI_LOGI("DealStaCloseRes: wifi scan only state is not running,to CheckAndStopScanService!");
        CheckAndStopScanService();
    }

    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_CLOSE) {
        if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
            static_cast<int>(OperatorWifiType::CLOSE_WIFI_DUE_TO_AIRPLANEMODE_OPENED)) {
            DealAirplaneExceptionWhenStaClose();
            return;
        }
    }
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_SERVICE_CLOSE);
    return;
}

void WifiManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info)
{
    WIFI_LOGI("Enter, DealStaConnChanged, state: %{public}d!\n", static_cast<int>(state));
    bool isReport = true;
    int reportStateNum = static_cast<int>(ConvertConnStateInternal(state, isReport));
    if (isReport) {
        WifiEventCallbackMsg cbMsg;
        cbMsg.msgCode = WIFI_CBK_MSG_CONNECTION_CHANGE;
        cbMsg.msgData = reportStateNum;
        cbMsg.linkInfo = info;
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }

    if (state == OperateResState::CONNECT_CONNECTING || state == OperateResState::CONNECT_AP_CONNECTED ||
        state == OperateResState::DISCONNECT_DISCONNECTING || state == OperateResState::DISCONNECT_DISCONNECTED ||
        state == OperateResState::CONNECT_OBTAINING_IP || state == OperateResState::CONNECT_ASSOCIATING ||
        state == OperateResState::CONNECT_ASSOCIATED) {
        if (WifiConfigCenter::GetInstance().GetScanMidState() == WifiOprMidState::RUNNING) {
            IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
            if (pService != nullptr) {
                pService->OnClientModeStatusChanged(static_cast<int>(state));
            }
        }
    }
#ifdef FEATURE_P2P_SUPPORT
    if (cfgMonitorCallback.onStaConnectionChange != nullptr) {
        cfgMonitorCallback.onStaConnectionChange(static_cast<int>(state));
    }
#endif
    return;
}

void WifiManager::DealWpsChanged(WpsStartState state, const int pinCode)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_WPS_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(state);
    cbMsg.pinCode = std::to_string(pinCode);
    int len = cbMsg.pinCode.length();
    if (len < 8) { /* Fill in 8 digits. */
        cbMsg.pinCode = std::string(8 - len, '0') + cbMsg.pinCode;
    }
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealStreamChanged(StreamDirection direction)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STREAM_DIRECTION;
    cbMsg.msgData = static_cast<int>(direction);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealRssiChanged(int rssi)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_RSSI_CHANGE;
    cbMsg.msgData = rssi;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::CheckAndStartScanService(void)
{
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState();
    WIFI_LOGI("CheckAndStartScanService scanState: %{public}d", static_cast<int>(scanState));
    if (scanState != WifiOprMidState::CLOSED) {
        /* If the scanning function is enabled when the STA is not enabled, you need to start the scheduled
             scanning function immediately when the STA is enabled. */
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
        if (pService != nullptr) {
            pService->OnClientModeStatusChanged(static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED));
        }
        return;
    }
    if (!WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::OPENING)) {
        WIFI_LOGW("Failed to set scan mid state opening! may be other activity has been operated");
        return;
    }
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_SCAN) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_SCAN);
            break;
        }
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_SCAN);
            break;
        }
        errCode = pService->RegisterScanCallbacks(WifiManager::GetInstance().GetScanCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register scan service callback failed!");
            break;
        }
        errCode = pService->Init();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("init scan service failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            break;
        }
        errCode = pService->SetEnhanceService(pEnhanceService);
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetEnhanceService failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN);
    }
    return;
}

void WifiManager::AutoStartEnhanceService(void)
{
    WIFI_LOGI("AutoStartEnhanceService start");
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_ENHANCE) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            break;
        }
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_ENHANCE);
            break;
        }
        errCode = pEnhanceService->Init();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("init Enhance service failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (0);
    return;
}

void WifiManager::CheckAndStopScanService(void)
{
    /**
     * Check unload SCAN service
     * When anytime scanning is enabled and the control policy allows, airplane
     * mode and power saving mode are disabled.   --- Do not disable the scan
     * service. Otherwise, disable the SCAN service.
     */
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState();
    WIFI_LOGI("[CheckAndStopScanService] scanState %{public}d!", static_cast<int>(scanState));
    if (scanState != WifiOprMidState::OPENING && scanState != WifiOprMidState::RUNNING) {
        return;
    }
    ScanControlInfo info;
    WifiConfigCenter::GetInstance().GetScanControlInfo(info);
    if (WifiConfigCenter::GetInstance().IsScanAlwaysActive() && IsAllowScanAnyTime(info) &&
        WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_CLOSE &&
        WifiConfigCenter::GetInstance().GetPowerSavingModeState() == MODE_STATE_CLOSE) {
        return;
    }
    /* After check condition over, begin unload SCAN service */
    if (WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSING)) {
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("[CheckAndStopScanService] scan service is null.");
            WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE);
            WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSED);
            return;
        }
        ErrCode ret = pService->UnInit();
        if (ret != WIFI_OPT_SUCCESS) { // scan service is not exist
            WIFI_LOGE("[CheckAndStopScanService] UnInit service failed!");
        }
        WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSED);
    }
}

void WifiManager::InitScanCallback(void)
{
    mScanCallback.OnScanStartEvent = DealScanOpenRes;
    mScanCallback.OnScanStopEvent = DealScanCloseRes;
    mScanCallback.OnScanFinishEvent = DealScanFinished;
    mScanCallback.OnScanInfoEvent = DealScanInfoNotify;
    mScanCallback.OnStoreScanInfoEvent = DealStoreScanInfoEvent;
    mScanCallback.OnOpenScanOnlyRes = DealOpenScanOnlyRes;
    mScanCallback.OnCloseScanOnlyRes = DealCloseScanOnlyRes;
}

IScanSerivceCallbacks WifiManager::GetScanCallback()
{
    return mScanCallback;
}

void WifiManager::DealScanOpenRes(void)
{
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
}

void WifiManager::DealScanCloseRes(void)
{
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE);
}

void WifiManager::DealScanFinished(int state)
{
    WIFI_LOGE("%{public}s, state: %{public}d!", __func__, state);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_SCAN_STATE_CHANGE;
    cbMsg.msgData = state;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishScanFinishedEvent(state,"OnScanFinished");
}

void WifiManager::DealScanInfoNotify(std::vector<InterScanInfo> &results)
{
    if (WifiConfigCenter::GetInstance().GetWifiMidState() == WifiOprMidState::RUNNING) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
        if (pService != nullptr) {
            pService->ConnectivityManager(results);
        }
    }
}

void WifiManager::DealStoreScanInfoEvent(std::vector<InterScanInfo> &results)
{
}

void WifiManager::InitPidfile()
{
    char pidFile[DIR_MAX_LENGTH] = {0, };
    int n = snprintf_s(pidFile, DIR_MAX_LENGTH, DIR_MAX_LENGTH - 1, "%s/%s.pid", CONFIG_ROOR_DIR, WIFI_MANAGGER_PID_NAME);
    if (n < 0) {
        LOGE("InitPidfile: construct pidFile name failed.");
        return;
    }
    unlink(pidFile);

    pid_t pid = getpid();
    char buf[PID_MAX_LENGTH] = {0};
    if (snprintf_s(buf, PID_MAX_LENGTH, PID_MAX_LENGTH - 1, "%d", pid) < 0) {
        LOGE("InitPidfile: pidFile:%{public}s failed, snprintf_s error:%{public}d!", pidFile, errno);
        return;
    }

    int fd;
    if ((fd = open(pidFile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
        LOGE("InitPidfile: open pidFile:%{public}s error:%{public}d!", pidFile, errno);
        return;
    }

    ssize_t bytes;
    if ((bytes = write(fd, buf, strlen(buf))) <= 0) {
        LOGE("InitPidfile failed, write pidFile:%{public}s error:%{public}d, bytes:%{public}zd!",
            pidFile, errno, bytes);
        close(fd);
        return;
    }
    LOGI("InitPidfile: buf:%{public}s write pidFile:%{public}s, bytes:%{public}zd!", buf, pidFile, bytes);
    close(fd);

    if (chdir(CONFIG_ROOR_DIR) != 0) {
        LOGE("InitPidfile failed, chdir pidDir:%{public}s error:%{public}d!", CONFIG_ROOR_DIR, errno);
        return;
    }

    umask(DEFAULT_UMASK_VALUE);
    chmod(pidFile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    return;
}
void WifiManager::DealOpenScanOnlyRes(OperateResState state)
{
    WIFI_LOGI("WifiManager::DealOpenScanOnlyRes");
    if (state == OperateResState::OPEN_SCAN_ONLY_SUCCEED) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
    }
    return;
}

void WifiManager::DealCloseScanOnlyRes(OperateResState state)
{
    WIFI_LOGI("DealCloseScanOnlyRes State:%{public}d", WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState());
    if (state == OperateResState::CLOSE_SCAN_ONLY_SUCCEED) {
        if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState()) {
            WIFI_LOGI("WifiManager::DealCloseScanOnlyRes wifi is on");
        } else {
            WIFI_LOGI("WifiManager::DealCloseScanOnlyRes wifi is off");
            CheckAndStopScanService();
            WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_SERVICE_CLOSE);
        }
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
    }
    return;
}

void WifiManager::DealAirplaneExceptionWhenStaOpen(void)
{
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
    WifiConfigCenter::GetInstance().SetStaLastRunState(true);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    ErrCode ret = WifiManager::GetInstance().AutoStopStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE);
    if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED) {
        WIFI_LOGE("DealAirplaneExceptionWhenStaOpen, AutoStopStaService failed!");
#ifdef FEATURE_P2P_SUPPORT
        WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
        WIFI_LOGI("DealAirplaneExceptionWhenStaOpen, current p2p state:%{public}d", p2pState);
        if (p2pState == WifiOprMidState::CLOSED) {
            WifiManager::GetInstance().AutoStartP2pService(
                AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
        }
#endif
        AutoStartEnhanceService();
        CheckAndStartScanService();
        if (WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
            WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) {
            WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
        }
    }
    return;
}

void WifiManager::DealAirplaneExceptionWhenStaClose(void)
{
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime();
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    ErrCode ret = WifiManager::GetInstance().AutoStartStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE);
    if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
        WIFI_LOGE("DealAirplaneExceptionWhenStaClose, AutoStartStaService failed!");
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
        WifiManager::GetInstance().StartUnloadStaSaTimer();
        return;
    }
    WifiConfigCenter::GetInstance().SetOperatorWifiType(
        static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED));
    return;
}

#ifdef FEATURE_AP_SUPPORT
void WifiManager::InitApCallback(void)
{
    mApCallback.OnApStateChangedEvent = DealApStateChanged;
    mApCallback.OnHotspotStaJoinEvent = DealApGetStaJoin;
    mApCallback.OnHotspotStaLeaveEvent = DealApGetStaLeave;
    return;
}

IApServiceCallbacks WifiManager::GetApCallback()
{
    return mApCallback;
}

void WifiManager::DealApStateChanged(ApState state, int id)
{
    WIFI_LOGE("%{public}s, state: %{public}d!", __func__, state);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(state);
    cbMsg.id = id;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    if (state == ApState::AP_STATE_IDLE) {
#ifdef FEATURE_STA_AP_EXCLUSION
    if (WifiConfigCenter::GetInstance().GetStaApExclusionType()
        == static_cast<int>(StaApExclusionType::USER_OPEN_WIFI_AUTO_STOP_AP) ||
        WifiConfigCenter::GetInstance().GetStaApExclusionType()
        == static_cast<int>(StaApExclusionType::USER_CLOSE_AP_AUTO_START_WIFI)) {
        WifiManager::GetInstance().AutoStartStaService(AutoStartOrStopServiceReason::STA_AP_EXCLUSION);
    }
#endif
        mCloseApIndex = id;
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, id);
        WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::AP_SERVICE_CLOSE);
    }
    if (state == ApState::AP_STATE_STARTED) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, id);
    }

    std::string msg = std::string("OnHotspotStateChanged") + std::string("id = ") + std::to_string(id);
    WifiCommonEventHelper::PublishHotspotStateChangedEvent((int)state, msg);
    return;
}

void WifiManager::DealApGetStaJoin(const StationInfo &info, int id)
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

void WifiManager::DealApGetStaLeave(const StationInfo &info, int id)
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
#endif

#ifdef FEATURE_P2P_SUPPORT
void WifiManager::InitP2pCallback(void)
{
    mP2pCallback.OnP2pStateChangedEvent = DealP2pStateChanged;
    mP2pCallback.OnP2pPeersChangedEvent = DealP2pPeersChanged;
    mP2pCallback.OnP2pServicesChangedEvent = DealP2pServiceChanged;
    mP2pCallback.OnP2pConnectionChangedEvent = DealP2pConnectionChanged;
    mP2pCallback.OnP2pThisDeviceChangedEvent = DealP2pThisDeviceChanged;
    mP2pCallback.OnP2pDiscoveryChangedEvent = DealP2pDiscoveryChanged;
    mP2pCallback.OnP2pGroupsChangedEvent = DealP2pGroupsChanged;
    mP2pCallback.OnP2pActionResultEvent = DealP2pActionResult;
    mP2pCallback.OnConfigChangedEvent = DealConfigChanged;
    return;
}

IP2pServiceCallbacks WifiManager::GetP2pCallback(void)
{
    return mP2pCallback;
}

void WifiManager::DealP2pStateChanged(P2pState state)
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
            WifiManager::GetInstance().AutoStopP2pService(
                AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
        }
    }
    if (state == P2pState::P2P_STATE_CLOSED) {
        bool ret = WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        if (ret) {
            WIFI_LOGE("P2p start failed, stop wifi!");
            ForceStopWifi();
            cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
            cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
            WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
        }
    }
    WifiCommonEventHelper::PublishP2pStateChangedEvent((int)state, "OnP2pStateChanged");
    return;
}

void WifiManager::DealP2pPeersChanged(const std::vector<WifiP2pDevice> &vPeers)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_PEER_CHANGE;
    cbMsg.device = vPeers;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pPeersStateChangedEvent(vPeers.size(), "OnP2pPeersChanged");
    return;
}

void WifiManager::DealP2pServiceChanged(const std::vector<WifiP2pServiceInfo> &vServices)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_SERVICE_CHANGE;
    cbMsg.serviceInfo = vServices;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealP2pConnectionChanged(const WifiP2pLinkedInfo &info)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CONNECT_CHANGE;
    cbMsg.p2pInfo = info;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pConnStateEvent((int)info.GetConnectState(), "OnP2pConnectStateChanged");
    return;
}

void WifiManager::DealP2pThisDeviceChanged(const WifiP2pDevice &info)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_THIS_DEVICE_CHANGE;
    cbMsg.p2pDevice = info;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pCurrentDeviceStateChangedEvent(
        (int)info.GetP2pDeviceStatus(), "OnP2pThisDeviceChanged");
    return;
}

void WifiManager::DealP2pDiscoveryChanged(bool bState)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_DISCOVERY_CHANGE;
    cbMsg.msgData = static_cast<int>(bState);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealP2pGroupsChanged()
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_PERSISTENT_GROUPS_CHANGE;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishP2pGroupStateChangedEvent(0, "OnP2pGroupStateChanged");
    return;
}

void WifiManager::DealP2pActionResult(P2pActionCallback action, ErrCode code)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_ACTION_RESULT;
    cbMsg.p2pAction = action;
    cbMsg.msgData = static_cast<int>(code);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealConfigChanged(CfgType type, char* data, int dataLen)
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

void WifiManager::RegisterCfgMonitorCallback(WifiCfgMonitorEventCallback callback)
{
    cfgMonitorCallback = callback;
}
#endif

#ifndef OHOS_ARCH_LITE
void WifiManager::RegisterScreenEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    screenEventSubscriber_ = std::make_shared<ScreenEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent SubscribeCommonEvent() OK");
        WifiTimer::GetInstance()->UnRegister(screenTimerId);
    }
}

void WifiManager::UnRegisterScreenEvent()
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent UnSubscribeCommonEvent() OK");
    }
    screenEventSubscriber_ = nullptr;
}

void ScreenEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("ScreenEventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("sta service is NOT start!");
        return;
    }

    int screenState = WifiSettings::GetInstance().GetScreenState();
    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pScanService == nullptr) {
        WIFI_LOGE("scan service is NOT start!");
        return;
    }
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF &&
        screenState == MODE_STATE_OPEN) {
        WifiSettings::GetInstance().SetScreenState(MODE_STATE_CLOSE);
        if (pScanService->OnScreenStateChanged(MODE_STATE_CLOSE) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("OnScreenStateChanged failed");
        }
        /* Send suspend to wpa */
        if (pService->SetSuspendMode(true) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetSuspendMode failed");
        }
        return;
    }

    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON &&
        screenState == MODE_STATE_CLOSE) {
        WifiSettings::GetInstance().SetScreenState(MODE_STATE_OPEN);
        if (pScanService->OnScreenStateChanged(MODE_STATE_OPEN) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("OnScreenStateChanged failed");
        }
        /* Send resume to wpa */
        if (pService->SetSuspendMode(false) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SetSuspendMode failed");
        }
        return;
    }
    WIFI_LOGW("ScreenEventSubscriber::OnReceiveEvent, screen state: %{public}d.", screenState);
}

void WifiManager::RegisterAirplaneModeEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPriority(1);
    airplaneModeEventSubscriber_ = std::make_shared<AirplaneModeEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(airplaneModeEventSubscriber_)) {
        WIFI_LOGE("AirplaneModeEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AirplaneModeEvent SubscribeCommonEvent() OK");
        WifiTimer::GetInstance()->UnRegister(airplaneModeTimerId);
    }
}

void WifiManager::UnRegisterAirplaneModeEvent()
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(airplaneModeEventSubscriber_)) {
        WIFI_LOGE("AirplaneModeEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AirplaneModeEvent UnSubscribeCommonEvent() OK");
    }
    airplaneModeEventSubscriber_ = nullptr;
}

void AirplaneModeEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    const auto &data = eventData.GetData();
    const auto &code = eventData.GetCode();
    WIFI_LOGI("AirplaneModeEventSubscriber::OnReceiveEvent: %{public}s,  %{public}s,  %{public}d", action.c_str(),
        data.c_str(), code);
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED) {
        if (code == 1) {
            /* open airplane mode */
            WifiManager::GetInstance().DealOpenAirplaneModeEvent();
        } else {
            /* close airplane mode */
            WifiManager::GetInstance().DealCloseAirplaneModeEvent();
        }
    }
}

void WifiManager::DealOpenAirplaneModeEvent()
{
    WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
    if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
        static_cast<int>(OperatorWifiType::USER_OPEN_WIFI_IN_AIRPLANEMODE)) {
            WIFI_LOGI("DealOpenAirplaneModeEvent, user opened sta in airplane mode, ignore openairplanemode event!");
            return;
    }

    AutoStopStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE);
    AutoStopScanOnly();
#ifdef FEATURE_AP_SUPPORT
    AutoStopApService(AutoStartOrStopServiceReason::AIRPLANE_MODE);
#endif
}

void WifiManager::DealCloseAirplaneModeEvent()
{
    WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_CLOSE);
    if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
        static_cast<int>(OperatorWifiType::CLOSE_WIFI_DUE_TO_AIRPLANEMODE_OPENED) &&
        !WifiConfigCenter::GetInstance().GetStaLastRunState()) {
            ErrCode ret = AutoStartStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE);
            if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
                WIFI_LOGE("DealCloseAirplaneModeEvent, AutoStartStaService failed!");
                return;
            }
            WIFI_LOGI("DealCloseAirplaneModeEvent, auto start wifi success!");
            WifiConfigCenter::GetInstance().SetOperatorWifiType(
                static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED));
            return;
    }

    if (!WifiConfigCenter::GetInstance().GetStaLastRunState()) {
        {
            std::unique_lock<std::mutex> lock(unloadStaSaTimerMutex);
            if (unloadStaSaTimerId == 0) {
                TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadStaSaTimerCallback);
                WifiTimer::GetInstance()->Register(timeoutCallback, unloadStaSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
                WIFI_LOGI("StartUnloadStaSaTimer success! unloadStaSaTimerId:%{public}u", unloadStaSaTimerId);
            }
        }
#ifdef FEATURE_P2P_SUPPORT
        {
            std::unique_lock<std::mutex> lock(unloadP2PSaTimerMutex);
            if (unloadP2PSaTimerId == 0) {
                TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadP2PSaTimerCallback);
                WifiTimer::GetInstance()->Register(timeoutCallback, unloadP2PSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
                WIFI_LOGI("StartUnloadP2PSaTimer success! unloadP2PSaTimerId:%{public}u", unloadP2PSaTimerId);
            }
        }
#endif
    }
    AutoStartScanOnly();
#ifdef FEATURE_AP_SUPPORT
    if (WifiConfigCenter::GetInstance().GetHotspotState() == static_cast<int>(ApState::AP_STATE_CLOSED)) {
        std::unique_lock<std::mutex> lock(unloadHotspotSaTimerMutex);
        if (unloadHotspotSaTimerId == 0) {
            TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadHotspotSaTimerCallback);
            WifiTimer::GetInstance()->Register(timeoutCallback, unloadHotspotSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
            WIFI_LOGI("RegisterUnloadHotspotSaTimer success!unloadHotspotSaTimerId:%{public}u", unloadHotspotSaTimerId);
        }
    }
#endif
    return;
}

void WifiManager::GetAirplaneModeByDatashare(int systemAbilityId)
{
    WIFI_LOGI("GetAirplaneModeByDatashare, systemAbilityId:%{public}d", systemAbilityId);
    auto datashareHelper = std::make_shared<WifiDataShareHelperUtils>(systemAbilityId);
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetAirplaneModeByDatashare, datashareHelper is nullprt!");
        return;
    }

    std::string airplaneMode;
    Uri uri(SETTINGS_DATASHARE_URL_AIRPLANE_MODE);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_AIRPLANE_MODE, airplaneMode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetAirplaneModeByDatashare, Query airplaneMode fail!");
        return;
    }

    WIFI_LOGI("GetAirplaneModeByDatashare, airplaneMode:%{public}s", airplaneMode.c_str());
    if (airplaneMode.compare("1") == 0) {
        WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
    }
    return;
}

bool WifiManager::GetLocationModeByDatashare(int systemAbilityId)
{
    WIFI_LOGI("GetLocationModeByDatashare, systemAbilityId:%{public}d", systemAbilityId);
    auto datashareHelper = std::make_shared<WifiDataShareHelperUtils>(systemAbilityId);
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetLocationModeByDatashare, datashareHelper is nullprt!");
        return false;
    }

    std::string locationMode;
    Uri uri(SETTINGS_DATASHARE_URI_LOCATION_MODE);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_LOCATION_MODE, locationMode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetLocationModeByDatashare, Query locationMode fail!");
        return false;
    }

    WIFI_LOGI("GetLocationModeByDatashare, locationMode:%{public}s", locationMode.c_str());
    return (locationMode.compare("1") == 0);
}

void WifiManager::RegisterLocationEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_LOCATION_MODE_STATE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    locationEventSubscriber_ = std::make_shared<LocationEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(locationEventSubscriber_)) {
        WIFI_LOGE("LocationEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("LocationEvent SubscribeCommonEvent() OK");
        WifiTimer::GetInstance()->UnRegister(locationTimerId);
    }
}

void WifiManager::UnRegisterLocationEvent()
{
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(locationEventSubscriber_)) {
        WIFI_LOGE("LocationEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("LocationEvent UnSubscribeCommonEvent() OK");
    }
    locationEventSubscriber_ = nullptr;
}

void LocationEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("LocationEventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());

    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_LOCATION_MODE_STATE_CHANGED) {
        WIFI_LOGI("LocationEventSubscriber::OnReceiveEvent COMMON_EVENT_LOCATION_MODE_STATE_CHANGED.");
    }
}

WifiTimer *WifiTimer::GetInstance()
{
    static WifiTimer instance;
    return &instance;
}

WifiTimer::WifiTimer() : timer_(std::make_unique<Utils::Timer>("WifiManagerTimer"))
{
    timer_->Setup();
}

WifiTimer::~WifiTimer()
{
    if (timer_) {
        timer_->Shutdown(true);
    }
}

ErrCode WifiTimer::Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return WIFI_OPT_FAILED;
    }

    uint32_t ret = timer_->Register(callback, interval, once);
    if (ret == Utils::TIMER_ERR_DEAL_FAILED) {
        WIFI_LOGE("Register timer failed");
        return WIFI_OPT_FAILED;
    }

    outTimerId = ret;
    return WIFI_OPT_SUCCESS;
}

void WifiTimer::UnRegister(uint32_t timerId)
{
    if (timerId == 0) {
        WIFI_LOGE("timerId is 0, no register timer");
        return;
    }

    if (timer_ == nullptr) {
        WIFI_LOGE("timer_ is nullptr");
        return;
    }

    timer_->Unregister(timerId);
    return;
}
#endif
}  // namespace Wifi
}  // namespace OHOS