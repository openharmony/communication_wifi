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
#include "wifi_location_mode_observer.h"
#include "wifi_country_code_manager.h"
#include "wifi_protect_manager.h"
#endif
#include "wifi_sta_hal_interface.h"
#include "wifi_service_manager.h"
#include "wifi_settings.h"
#include "define.h"
#include "wifi_config_center.h"
#include "wifi_common_def.h"
#include "wifi_hisysevent.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_controller_define.h"
#endif

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

static sptr<WifiLocationModeObserver> locationModeObserver_ = nullptr;
static sptr<WifiDeviceProvisionObserver> deviceProvisionObserver_ = nullptr;
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
            gWifiManager.InitSubscribeListener();
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiManager::AutoStartStaService(AutoStartOrStopServiceReason reason, int instId)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGD("AutoStartStaService, current sta state:%{public}d, reason:%{public}d", staState, reason);
    if (staState != WifiOprMidState::CLOSED) {
        if (staState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }
    
    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::OPENING, instId)) {
        WIFI_LOGD("AutoStartStaService, set wifi mid state opening failed!");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }
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
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
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

ErrCode WifiManager::AutoStopStaService(AutoStartOrStopServiceReason reason, int instId)
{
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
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

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGI("AutoStopStaService, set wifi mid state opening failed!");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("AutoStopStaService, Instance get sta service is null!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }

    ret = pService->DisableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("service disable sta failed, ret %{public}d!", static_cast<int>(ret));
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING, instId);
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

void WifiManager::AutoStartScanOnly(int instId)
{
    if (!WifiSettings::GetInstance().CheckScanOnlyAvailable() ||
        !WifiManager::GetInstance().GetLocationModeByDatashare()) {
        WIFI_LOGI("No need to StartScanOnly, return");
        return;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("Wifi scan only state is %{public}d", static_cast<int>(curState));
    
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("scanOnly state is not closed, return");
        return;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
        return;
    }

    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING, instId);
    CheckAndStartScanService(instId);
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
    if (pService == nullptr) {
        WIFI_LOGE("[AutoStartScanOnly] scan service is null.");
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
        return;
    }
    ErrCode ret = pService->StartWpa();
    if (ret != static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGE("Start Wpa failed");
    }
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
}

void WifiManager::AutoStopScanOnly(int instId)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId);
    WIFI_LOGI("current wifi scan only state is %{public}d", static_cast<int>(curState));
    if (curState != WifiOprMidState::RUNNING) {
        return;
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
        return;
    }

    if (!WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSING, instId)) {
        WIFI_LOGI("set wifi scan only mid state opening failed!");
        return;
    }

    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
        return;
    }
    ErrCode ret = pService->CloseWpa();
    if (ret != static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGE("Stop Wpa failed");
    }
    ret = pService->CloseScanOnly();
    WifiManager::GetInstance().CheckAndStopScanService(instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
}
#endif

void WifiManager::ForceStopWifi(int instId)
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
        return;
    }
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("In force stop wifi, state: %{public}d", static_cast<int>(curState));
    WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::CLOSED, instId);
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
#ifdef OHOS_ARCH_LITE
            WifiManager::GetInstance().AutoStartStaService(reason, 0);
#else
            WifiManager::GetInstance().WifiToggled(1, 0);
#endif
            return;
        }
        while ((dent = readdir(dir)) != nullptr) {
            if (dent->d_name[0] == '.') {
                continue;
            }
            if (strncmp(dent->d_name, "wlan", strlen("wlan")) == 0) {
                closedir(dir);
#ifdef OHOS_ARCH_LITE
                WifiManager::GetInstance().AutoStartStaService(reason, 0);
#else
                WifiManager::GetInstance().WifiToggled(1, 0);
#endif
                return;
            }
        }
        closedir(dir);
        sleep(sleepTime);
        currentWaitTime++;
    }
#ifdef OHOS_ARCH_LITE
    WifiManager::GetInstance().AutoStartStaService(reason, 0);
#else
    WifiManager::GetInstance().WifiToggled(1, 0);
#endif
}

void WifiManager::AutoStartServiceThread(AutoStartOrStopServiceReason reason)
{
    WIFI_LOGI("Auto start service...");
    CheckAndStartSta(reason);
}

#ifdef OHOS_ARCH_LITE
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
#endif

#ifndef OHOS_ARCH_LITE
ErrCode WifiManager::WifiToggled(int isOpen, int id)
{
    pWifiControllerMachine->SendMessage(CMD_WIFI_TOGGLED, isOpen, id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiManager::SoftapToggled(int isOpen, int id)
{
    pWifiControllerMachine->SendMessage(CMD_SOFTAP_TOGGLED, isOpen, id);
    return WIFI_OPT_SUCCESS;
}

bool WifiManager::HasAnyApRuning()
{
    WifiOprMidState apState0 = WifiConfigCenter::GetInstance().GetApMidState(0);
    WifiOprMidState apState1 = WifiConfigCenter::GetInstance().GetApMidState(1);
    if (apState0 == WifiOprMidState::RUNNING || apState0 == WifiOprMidState::OPENING ||
        apState1 == WifiOprMidState::RUNNING || apState1 == WifiOprMidState::OPENING) {
        return true;
    }
    return false;
}

ErrCode WifiManager::ScanOnlyToggled(int isOpen)
{
    int airplanState = WifiConfigCenter::GetInstance().GetAirplaneModeState();
    if (airplanState == MODE_STATE_OPEN) {
        WIFI_LOGE("Airplane mode do not start scanonly.");
        return WIFI_OPT_FAILED;
    }
#ifdef FEATURE_STA_AP_EXCLUSION
    if (WifiManager::GetInstance().HasAnyApRuning()) {
        WIFI_LOGE("Softap mode do not start scanonly.");
        return WIFI_OPT_FAILED;
    }
#endif
    pWifiControllerMachine->SendMessage(CMD_SCAN_ALWAYS_MODE_CHANGED, isOpen, 0);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiManager::AirplaneToggled(int isOpen)
{
    pWifiControllerMachine->SendMessage(CMD_AIRPLANE_TOGGLED, isOpen);
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

void WifiManager::AutoStartScanService(int instId)
{
    WIFI_LOGI("AutoStartScanService");
    if (!WifiConfigCenter::GetInstance().IsScanAlwaysActive()) {
        WIFI_LOGW("Scan always is not open, not open scan service.");
        return;
    }
    ScanControlInfo info;
    WifiConfigCenter::GetInstance().GetScanControlInfo(info, instId);
    if (!IsAllowScanAnyTime(info)) {
        WIFI_LOGW("Scan control does not support scan always, not open scan service here.");
        return;
    }
    WifiManager::GetInstance().CheckAndStartScanService(instId);
    return;
}

int WifiManager::Init()
{
#ifndef OHOS_ARCH_LITE
    if (WifiCountryCodeManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiCountryCodeManager Init failed!");
        mInitStatus = WIFI_COUNTRY_CODE_MANAGER_INIT_FAILED;
        return -1;
    }
#endif
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
#ifndef OHOS_ARCH_LITE
    pWifiControllerMachine = new (std::nothrow) WifiControllerMachine();
    if (pWifiControllerMachine == nullptr) {
        WIFI_LOGE("Alloc pWifiControllerMachine failed.\n");
        return -1;
    }
    if (pWifiControllerMachine->InitWifiControllerMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitWifiControllerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
#endif
    mCloseServiceThread = std::thread(WifiManager::DealCloseServiceMsg, std::ref(*this));
    pthread_setname_np(mCloseServiceThread.native_handle(), "WifiCloseThread");
    
#ifndef OHOS_ARCH_LITE
    RegisterDeviceProvisionEvent();
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
    if (locationModeObserver_ == nullptr && locationTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(&WifiManager::RegisterLocationEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, locationTimerId, TIMEOUT_LOCATION_EVENT, false);
        WIFI_LOGI("RegisterLocationEvent success! locationTimerId:%{public}u", locationTimerId);
    }
#endif
    mInitStatus = INIT_OK;
    InitStaCallback();
    InitScanCallback();
#ifndef OHOS_ARCH_LITE
    InitConcreteCallback();
#endif
#ifdef FEATURE_AP_SUPPORT
#ifndef OHOS_ARCH_LITE
    InitSoftapCallback();
#endif
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
#ifndef OHOS_ARCH_LITE
        WifiSettings::GetInstance().SetWifiToggledState(true);
#endif
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
        CheckAndStartScanService();
    }
    InitPidfile();
    return 0;
}

void WifiManager::InitSubscribeListener()
{
#ifndef OHOS_ARCH_LITE
    SubscribeSystemAbility(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID);
    SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID);
#endif
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

    if (locationModeObserver_ != nullptr) {
        UnRegisterLocationEvent();
    }
    if (deviceProvisionObserver_ != nullptr) {
        UnRegisterDeviceProvisionEvent();
    }
#endif
    return;
}

void WifiManager::PushServiceCloseMsg(WifiCloseServiceCode code, int instId)
{
    std::unique_lock<std::mutex> lock(mMutex);
    WifiCloseServiceMsg msg;
    msg.code = code;
    msg.instId = instId;
    mEventQue.push_back(msg);
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
WifiControllerMachine* WifiManager::GetControllerMachine()
{
    return pWifiControllerMachine;
}
#endif

#ifndef OHOS_ARCH_LITE
uint32_t WifiManager::unloadStaSaTimerId{0};
std::mutex WifiManager::unloadStaSaTimerMutex{};
void WifiManager::UnloadStaSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_DEVICE_ABILITY_ID);
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

void WifiManager::CloseStaService(int instId)
{
    WIFI_LOGI("close sta service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA, instId);
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED, instId);
#ifndef OHOS_ARCH_LITE
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->HandleStaClose(instId);
#endif
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime(instId);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
#ifdef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_CLOSE) {
        if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
            static_cast<int>(OperatorWifiType::CLOSE_WIFI_DUE_TO_AIRPLANEMODE_OPENED)) {
            DealAirplaneExceptionWhenStaClose();
            return;
        }
    }
#endif
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
#ifdef OHOS_ARCH_LITE
    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId)) {
        WIFI_LOGI("scanonly not close sta SA!");
        return;
    }
#endif
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
#ifndef OHOS_ARCH_LITE
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->SendMessage(CMD_AP_STOPPED, id);
#endif
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

void WifiManager::CloseScanService(int instId)
{
    WIFI_LOGI("close scan service");
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN, instId);
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED, instId);
    WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(instId);
    WIFI_LOGI("CloseScanService, current sta state:%{public}d", staState);
    if (staState == WifiOprMidState::OPENING || staState == WifiOprMidState::RUNNING) {
        WifiManager::GetInstance().CheckAndStartScanService(instId);
        return;
    }
    #ifndef OHOS_ARCH_LITE
    WifiManager::GetInstance().StartUnloadScanSaTimer();
    #endif
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
        WifiCloseServiceMsg msg = manager.mEventQue.front();
        manager.mEventQue.pop_front();
        lock.unlock();
        usleep(waitDealTime);
        switch (msg.code) {
            case WifiCloseServiceCode::STA_SERVICE_CLOSE:
                CloseStaService(msg.instId);
                break;
            case WifiCloseServiceCode::SCAN_SERVICE_CLOSE:
                CloseScanService(msg.instId);
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
                WIFI_LOGW("Unknown message code, %{public}d", static_cast<int>(msg.code));
                break;
        }
    }
    WIFI_LOGD("WifiManager Thread exit");
    return;
}

void WifiManager::InitStaCallback(void)
{
    mStaCallback.callbackModuleName = "WifiManager";
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

void WifiManager::DealStaOpenRes(OperateResState state, int instId)
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
        return;
    }
    if ((state == OperateResState::OPEN_WIFI_FAILED) || (state == OperateResState::OPEN_WIFI_DISABLED)) {
        WIFI_LOGE("DealStaOpenRes:wifi open failed!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        DealStaCloseRes(state, instId);
        return;
    }

    WIFI_LOGI("DealStaOpenRes:wifi open successfully!");
#ifdef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WifiConfigCenter::GetInstance().SetWifiStateWhenAirplaneMode(true);
        if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
            static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED)) {
            DealAirplaneExceptionWhenStaOpen(instId);
            return;
        }
    }
#endif
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
    WifiConfigCenter::GetInstance().SetStaLastRunState(true);
#ifndef OHOS_ARCH_LITE
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->HandleStaStart(instId);
#endif
    cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_OPEN),
        static_cast<int>(WifiOperateState::STA_OPENED));
#ifdef FEATURE_P2P_SUPPORT
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    WIFI_LOGI("DealStaOpenRes, current p2p state:%{public}d", p2pState);
    if (p2pState == WifiOprMidState::CLOSED) {
        WifiManager::GetInstance().AutoStartP2pService(
            AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
    }
#endif
    AutoStartEnhanceService();
    CheckAndStartScanService(instId);
#ifdef OHOS_ARCH_LITE
    if (WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
        WifiManager::GetInstance().GetLocationModeByDatashare()) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
    }
#endif
}

void WifiManager::DealStaCloseRes(OperateResState state, int instId)
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
        return;
    }
    if (state == OperateResState::CLOSE_WIFI_FAILED) {
        WIFI_LOGI("DealStaCloseRes: broadcast wifi close failed event!");
        WifiManager::GetInstance().ForceStopWifi(instId);
        cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
        WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    }
#ifdef OHOS_ARCH_LITE
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN) {
        WifiConfigCenter::GetInstance().SetWifiStateWhenAirplaneMode(false);
    }
#ifdef FEATURE_STA_AP_EXCLUSION
    if (WifiConfigCenter::GetInstance().GetStaApExclusionType()
        == static_cast<int>(StaApExclusionType::USER_OPEN_AP_AUTO_STOP_WIFI)) {
        WifiManager::GetInstance().AutoStartApService(AutoStartOrStopServiceReason::STA_AP_EXCLUSION);
    }
#endif
    if (WifiOprMidState::RUNNING != WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId)) {
        WIFI_LOGI("DealStaCloseRes: wifi scan only state is not running,to CheckAndStopScanService!");
        WifiManager::GetInstance().CheckAndStopScanService(instId);
    }
#endif
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::STA_SERVICE_CLOSE, instId);
    return;
}

void WifiManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    WIFI_LOGI("Enter, DealStaConnChanged, state: %{public}d!\n", static_cast<int>(state));
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
        state == OperateResState::CONNECT_ASSOCIATED) {
        if (WifiConfigCenter::GetInstance().GetScanMidState(instId) == WifiOprMidState::RUNNING) {
            IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
            if (pService != nullptr) {
                pService->OnClientModeStatusChanged(static_cast<int>(state));
            }
        }
    }
    switch (state) {
        case OperateResState::CONNECT_CONNECTING:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
                static_cast<int>(WifiOperateState::STA_CONNECTING));
            break;
        case OperateResState::CONNECT_AP_CONNECTED:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
                static_cast<int>(WifiOperateState::STA_CONNECTED));
            break;
        case OperateResState::DISCONNECT_DISCONNECTED:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_CONNECT),
                static_cast<int>(WifiOperateState::STA_DISCONNECTED));
            break;
        case OperateResState::CONNECT_ASSOCIATING:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
                static_cast<int>(WifiOperateState::STA_ASSOCIATING));
            break;
        case OperateResState::CONNECT_ASSOCIATED:
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_ASSOC),
                static_cast<int>(WifiOperateState::STA_ASSOCIATED));
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
        if (info.connState == ConnState::AUTHENTICATING)
        {
            WriteWifiOperateStateHiSysEvent(static_cast<int>(WifiOperateType::STA_AUTH),
                static_cast<int>(WifiOperateState::STA_AUTHING));
        }
        
#ifdef FEATURE_P2P_SUPPORT
    if (cfgMonitorCallback.onStaConnectionChange != nullptr) {
        cfgMonitorCallback.onStaConnectionChange(static_cast<int>(state));
    }
#endif
#ifndef OHOS_ARCH_LITE
    bool isConnected = (info.connState == CONNECTED) ? true : false;
    WifiProtectManager::GetInstance().UpdateWifiClientConnected(isConnected);
#endif
    return;
}

void WifiManager::DealWpsChanged(WpsStartState state, const int pinCode, int instId)
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

void WifiManager::DealStreamChanged(StreamDirection direction, int instId)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STREAM_DIRECTION;
    cbMsg.msgData = static_cast<int>(direction);
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealRssiChanged(int rssi, int instId)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_RSSI_CHANGE;
    cbMsg.msgData = rssi;
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

#ifndef OHOS_ARCH_LITE
uint32_t WifiManager::unloadScanSaTimerId{0};
std::mutex WifiManager::unloadScanSaTimerMutex{};
void WifiManager::UnloadScanSaTimerCallback()
{
    WifiSaLoadManager::GetInstance().UnloadWifiSa(WIFI_SCAN_ABILITY_ID);
    WifiManager::GetInstance().StopUnloadScanSaTimer();
}

void WifiManager::StopUnloadScanSaTimer(void)
{
    WIFI_LOGI("StopUnloadScanSaTimer! unloadScanSaTimerId:%{public}u", unloadScanSaTimerId);
    std::unique_lock<std::mutex> lock(unloadScanSaTimerMutex);
    WifiTimer::GetInstance()->UnRegister(unloadScanSaTimerId);
    unloadScanSaTimerId = 0;
    return;
}

void WifiManager::StartUnloadScanSaTimer(void)
{
    WIFI_LOGI("StartUnloadScanSaTimer! unloadScanSaTimerId:%{public}u", unloadScanSaTimerId);
    std::unique_lock<std::mutex> lock(unloadScanSaTimerMutex);
    if (unloadScanSaTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(WifiManager::UnloadScanSaTimerCallback);
        WifiTimer::GetInstance()->Register(timeoutCallback, unloadScanSaTimerId, TIMEOUT_UNLOAD_WIFI_SA);
        WIFI_LOGI("StartUnloadScanSaTimer success! unloadScanSaTimerId:%{public}u", unloadScanSaTimerId);
    }
    return;
}
#endif

void WifiManager::OnSystemAbilityChanged(int systemAbilityId, bool add)
{
#ifndef OHOS_ARCH_LITE
    switch (systemAbilityId) {
        case COMM_NET_CONN_MANAGER_SYS_ABILITY_ID: {
            if (!add) {
                break;
            }
            for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
                IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
                if (pService != nullptr) {
                    pService->OnSystemAbilityChanged(systemAbilityId, add);
                }
            }
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            if (add) {
                RegisterScreenEvent();
                RegisterAirplaneModeEvent();
                RegisterLocationEvent();
            } else {
                UnRegisterScreenEvent();
                UnRegisterAirplaneModeEvent();
                UnRegisterLocationEvent();
            }

            WIFI_LOGI("OnSystemAbilityChanged, id[%{public}d], mode=[%{public}d]!",
                systemAbilityId, add);
            for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
                IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
                if (pService != nullptr) {
                    pService->OnSystemAbilityChanged(systemAbilityId, add);
                }
            }
            break;
        }
        default:
            break;
    }
#endif
}

void WifiManager::CheckAndStartScanService(int instId)
{
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState(instId);
    WIFI_LOGI("CheckAndStartScanService scanState: %{public}d", static_cast<int>(scanState));
    if (scanState != WifiOprMidState::CLOSED) {
        /* If the scanning function is enabled when the STA is not enabled, you need to start the scheduled
             scanning function immediately when the STA is enabled. */
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
        if (pService != nullptr) {
            pService->OnClientModeStatusChanged(static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED));
        }
        return;
    }
    if (!WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::OPENING, instId)) {
        WIFI_LOGW("Failed to set scan mid state opening! may be other activity has been operated");
        return;
    }
    ErrCode errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_SCAN) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_SCAN);
            break;
        }
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
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
        WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, instId);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN, instId);
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

void WifiManager::CheckAndStopScanService(int instId)
{
    /**
     * Check unload SCAN service
     * When anytime scanning is enabled and the control policy allows, airplane
     * mode and power saving mode are disabled.   --- Do not disable the scan
     * service. Otherwise, disable the SCAN service.
     */
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState(instId);
    WIFI_LOGI("[CheckAndStopScanService] scanState %{public}d!", static_cast<int>(scanState));
    if (scanState != WifiOprMidState::OPENING && scanState != WifiOprMidState::RUNNING) {
        return;
    }
    ScanControlInfo info;
    WifiConfigCenter::GetInstance().GetScanControlInfo(info, instId);
    if (WifiConfigCenter::GetInstance().IsScanAlwaysActive() && IsAllowScanAnyTime(info) &&
        WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_CLOSE &&
        WifiConfigCenter::GetInstance().GetPowerSavingModeState() == MODE_STATE_CLOSE) {
        return;
    }
    /* After check condition over, begin unload SCAN service */
    if (WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSING, instId)) {
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(instId);
        if (pService == nullptr) {
            WIFI_LOGE("[CheckAndStopScanService] scan service is null.");
            WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE, instId);
            WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSED, instId);
            return;
        }
        ErrCode ret = pService->UnInit();
        if (ret != WIFI_OPT_SUCCESS) { // scan service is not exist
            WIFI_LOGE("[CheckAndStopScanService] UnInit service failed!");
        }
        WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSED, instId);
    }
}

void WifiManager::InitScanCallback(void)
{
    mScanCallback.OnScanStartEvent = DealScanOpenRes;
    mScanCallback.OnScanStopEvent = DealScanCloseRes;
    mScanCallback.OnScanFinishEvent = DealScanFinished;
    mScanCallback.OnScanInfoEvent = DealScanInfoNotify;
    mScanCallback.OnStoreScanInfoEvent = DealStoreScanInfoEvent;
}

IScanSerivceCallbacks WifiManager::GetScanCallback()
{
    return mScanCallback;
}

#ifndef OHOS_ARCH_LITE
ConcreteModeCallback WifiManager::GetConcreteCallback()
{
    return mConcreteModeCb;
}

SoftApModeCallback WifiManager::GetSoftApCallback()
{
    return mSoftApModeCb;
}

void WifiManager::InitConcreteCallback()
{
    mConcreteModeCb.onStartFailure = DealConcreateStartFailure;
    mConcreteModeCb.onStopped = DealConcreateStop;
}

void WifiManager::InitSoftapCallback()
{
    mSoftApModeCb.onStartFailure = DealSoftapStartFailure;
    mSoftApModeCb.onStopped = DealSoftapStop;
}

void WifiManager::DealConcreateStop(int id)
{
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->SendMessage(CMD_CONCRETE_STOPPED, id);
}

void WifiManager::DealConcreateStartFailure(int id)
{
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->SendMessage(CMD_STA_START_FAILURE, id);
}

void WifiManager::DealSoftapStop(int id)
{
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->SendMessage(CMD_AP_STOPPED, id);
}

void WifiManager::DealSoftapStartFailure(int id)
{
    WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
    ins->SendMessage(CMD_AP_START_FAILURE, id);
}
#endif

void WifiManager::DealScanOpenRes(int instId)
{
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
}

void WifiManager::DealScanCloseRes(int instId)
{
    WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::SCAN_SERVICE_CLOSE, instId);
}

void WifiManager::DealScanFinished(int state, int instId)
{
    WIFI_LOGE("%{public}s, state: %{public}d!", __func__, state);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_SCAN_STATE_CHANGE;
    cbMsg.msgData = state;
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    WifiCommonEventHelper::PublishScanFinishedEvent(state,"OnScanFinished");
}

void WifiManager::DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId)
{
    if (WifiConfigCenter::GetInstance().GetWifiMidState(instId) == WifiOprMidState::RUNNING) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(instId);
        if (pService != nullptr) {
            pService->ConnectivityManager(results);
        }
    }
}

void WifiManager::DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId)
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
void WifiManager::DealOpenScanOnlyRes(int instId)
{
    WIFI_LOGI("WifiManager::DealOpenScanOnlyRes");
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
    return;
}

void WifiManager::DealCloseScanOnlyRes(int instId)
{
    WIFI_LOGI("DealCloseScanOnlyRes State:%{public}d", WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId));
    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState(instId)) {
        WIFI_LOGI("WifiManager::DealCloseScanOnlyRes wifi is on");
    } else {
        WIFI_LOGI("WifiManager::DealCloseScanOnlyRes wifi is off");
        WifiManager::GetInstance().CheckAndStopScanService(instId);
    }
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED, instId);
    return;
}

#ifdef OHOS_ARCH_LITE
void WifiManager::DealAirplaneExceptionWhenStaOpen(int instId)
{
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, instId);
    WifiConfigCenter::GetInstance().SetStaLastRunState(true);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
    cbMsg.id = instId;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
    ErrCode ret = WifiManager::GetInstance().AutoStopStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE, instId);
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
        CheckAndStartScanService(instId);
        if (WifiSettings::GetInstance().CheckScanOnlyAvailable() &&
            WifiManager::GetInstance().GetLocationModeByDatashare()) {
            WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING, instId);
        }
    }
    return;
}

void WifiManager::DealAirplaneExceptionWhenStaClose(int instId)
{
    ErrCode ret = WifiManager::GetInstance().AutoStartStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE, instId);
    if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
        WIFI_LOGE("DealAirplaneExceptionWhenStaClose, AutoStartStaService failed!");
#ifdef FEATURE_P2P_SUPPORT
        WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
        WIFI_LOGI("CloseStaService, current p2p state: %{public}d", p2pState);
        if (p2pState == WifiOprMidState::RUNNING) {
            WifiManager::GetInstance().AutoStopP2pService(
                AutoStartOrStopServiceReason::TRYTO_OPERATE_P2P_WHEN_STA_STATE_CHANGE);
        }
#endif
        return;
    }
    WifiConfigCenter::GetInstance().SetOperatorWifiType(
        static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED));
    return;
}
#endif

#ifdef FEATURE_AP_SUPPORT
void WifiManager::InitApCallback(void)
{
    mApCallback.callbackModuleName = "WifiManager";
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
#ifdef OHOS_ARCH_LITE
#ifdef FEATURE_STA_AP_EXCLUSION
    if (WifiConfigCenter::GetInstance().GetStaApExclusionType()
        == static_cast<int>(StaApExclusionType::USER_OPEN_WIFI_AUTO_STOP_AP) ||
        WifiConfigCenter::GetInstance().GetStaApExclusionType()
        == static_cast<int>(StaApExclusionType::USER_CLOSE_AP_AUTO_START_WIFI)) {
        WifiManager::GetInstance().AutoStartStaService(AutoStartOrStopServiceReason::STA_AP_EXCLUSION);
    }
#endif
#endif
        mCloseApIndex = id;
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, id);
        WifiManager::GetInstance().PushServiceCloseMsg(WifiCloseServiceCode::AP_SERVICE_CLOSE);
    }
    if (state == ApState::AP_STATE_STARTED) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING, id);
#ifndef OHOS_ARCH_LITE
        WifiControllerMachine *ins =  WifiManager::GetInstance().GetControllerMachine();
        ins->SendMessage(CMD_AP_START, id);
#endif
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
#ifdef OHOS_ARCH_LITE
            WifiManager::GetInstance().ForceStopWifi();
#else
            WifiManager::GetInstance().WifiToggled(0, 0);
#endif
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
    std::unique_lock<std::mutex> lock(screenEventMutex);
    if (screenEventSubscriber_) {
        return;
    }
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
    std::unique_lock<std::mutex> lock(screenEventMutex);
    if (!screenEventSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent UnSubscribeCommonEvent() OK");
    }
}

void ScreenEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("ScreenEventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService == nullptr) {
            WIFI_LOGE("sta service is NOT start!");
            return;
        }

        int screenState = WifiSettings::GetInstance().GetScreenState();
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
        if (pScanService == nullptr) {
            WIFI_LOGE("scan service is NOT start!");
            return;
        }
    #ifndef OHOS_ARCH_LITE
        bool isScreenOn = (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) ? true : false;
        WifiProtectManager::GetInstance().HandleScreenStateChanged(isScreenOn);
    #endif
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
            pService->OnScreenStateChanged(MODE_STATE_CLOSE);
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
            pService->OnScreenStateChanged(MODE_STATE_OPEN);
            return;
        }
    }
}

ScreenEventSubscriber::ScreenEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("ScreenEventSubscriber enter");
}

ScreenEventSubscriber::~ScreenEventSubscriber()
{
    WIFI_LOGI("~ScreenEventSubscriber enter");
}

void WifiManager::RegisterAirplaneModeEvent()
{
    std::unique_lock<std::mutex> lock(airplaneModeEventMutex);
    if (airplaneModeEventSubscriber_) {
        return;
    }
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
    std::unique_lock<std::mutex> lock(airplaneModeEventMutex);
    if (!airplaneModeEventSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(airplaneModeEventSubscriber_)) {
        WIFI_LOGE("AirplaneModeEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AirplaneModeEvent UnSubscribeCommonEvent() OK");
    }
}

AirplaneModeEventSubscriber::AirplaneModeEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGE("AirplaneModeEventSubscriber enter");
}

AirplaneModeEventSubscriber::~AirplaneModeEventSubscriber()
{
    WIFI_LOGE("~AirplaneModeEventSubscriber enter");
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
#ifdef OHOS_ARCH_LITE
            WifiManager::GetInstance().DealOpenAirplaneModeEvent();
#else
            WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
            WifiManager::GetInstance().AirplaneToggled(1);
#endif
        } else {
            /* close airplane mode */
#ifdef OHOS_ARCH_LITE
            WifiManager::GetInstance().DealCloseAirplaneModeEvent();
#else
            WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_CLOSE);
            WifiManager::GetInstance().AirplaneToggled(0);
#endif
        }
    }
}

void WifiManager::DealOpenAirplaneModeEvent()
{
    WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
#ifdef OHOS_ARCH_LITE
#ifdef FEATURE_AP_SUPPORT
    AutoStopApService(AutoStartOrStopServiceReason::AIRPLANE_MODE);
#endif
#endif
    if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
        static_cast<int>(OperatorWifiType::USER_OPEN_WIFI_IN_AIRPLANEMODE)) {
            WIFI_LOGI("DealOpenAirplaneModeEvent, user opened sta in airplane mode, ignore openairplanemode event!");
            return;
    }
#ifdef OHOS_ARCH_LITE
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        AutoStopStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE, i);
    }
#endif
}

void WifiManager::DealCloseAirplaneModeEvent()
{
    WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_CLOSE);
    if (WifiConfigCenter::GetInstance().GetOperatorWifiType() ==
        static_cast<int>(OperatorWifiType::CLOSE_WIFI_DUE_TO_AIRPLANEMODE_OPENED) &&
        !WifiConfigCenter::GetInstance().GetStaLastRunState()) {
#ifdef OHOS_ARCH_LITE
            for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
                ErrCode ret = AutoStartStaService(AutoStartOrStopServiceReason::AIRPLANE_MODE, i);
                if (ret != WIFI_OPT_SUCCESS && ret != WIFI_OPT_OPEN_SUCC_WHEN_OPENED) {
                    WIFI_LOGE("DealCloseAirplaneModeEvent, AutoStartStaService failed!");
                    continue;
                }
                WIFI_LOGI("DealCloseAirplaneModeEvent, auto start wifi success!");
                WifiConfigCenter::GetInstance().SetOperatorWifiType(
                    static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED));
            }
#else
            WIFI_LOGI("DealCloseAirplaneModeEvent, auto start wifi success!");
            WifiConfigCenter::GetInstance().SetOperatorWifiType(
                static_cast<int>(OperatorWifiType::OPEN_WIFI_DUE_TO_AIRPLANEMODE_CLOSED));
#endif
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

void WifiManager::GetAirplaneModeByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
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

    WIFI_LOGD("GetAirplaneModeByDatashare, airplaneMode:%{public}s", airplaneMode.c_str());
    if (airplaneMode.compare("1") == 0) {
        WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
    }
    return;
}

void WifiManager::GetDeviceProvisionByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetDeviceProvisionByDatashare, datashareHelper is nullprt!");
        return;
    }

    std::string provision;
    Uri uri(SETTINGS_DATASHARE_URI_DEVICE_PROVISIONED);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_DEVICE_PROVISIONED, provision);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetDeviceProvisionByDatashare, Query provision fail!");
        return;
    }

    WIFI_LOGI("GetDeviceProvisionByDatashare, provision:%{public}s", provision.c_str());
    if (provision.compare("1") == 0) {
        WifiConfigCenter::GetInstance().SetDeviceProvisionState(MODE_STATE_CLOSE);
        return;
    }
    WifiConfigCenter::GetInstance().SetDeviceProvisionState(MODE_STATE_OPEN);
    return;
}

bool WifiManager::GetLocationModeByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
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

    WIFI_LOGD("GetLocationModeByDatashare, locationMode:%{public}s", locationMode.c_str());
    return (locationMode.compare("1") == 0);
}

void WifiManager::RegisterLocationEvent()
{
    std::unique_lock<std::mutex> lock(locationEventMutex);
    if (locationModeObserver_) {
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("LocationEvent datashareHelper is nullptr");
        return;
    }
    locationModeObserver_ = sptr<WifiLocationModeObserver>(new (std::nothrow)WifiLocationModeObserver());
    Uri uri(SETTINGS_DATASHARE_URI_LOCATION_MODE);
    datashareHelper->RegisterObserver(uri, locationModeObserver_);
}

void WifiManager::UnRegisterLocationEvent()
{
    std::unique_lock<std::mutex> lock(locationEventMutex);
    if (locationModeObserver_ == nullptr) {
        WIFI_LOGE("UnRegisterLocationEvent locationModeObserver_ is nullptr");
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("UnRegisterLocationEvent datashareHelper is nullptr");
        return;
    }
    Uri uri(SETTINGS_DATASHARE_URI_LOCATION_MODE);
    datashareHelper->UnRegisterObserver(uri, locationModeObserver_);
}

void WifiManager::RegisterDeviceProvisionEvent()
{
    if (deviceProvisionObserver_) {
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("RegisterDeviceProvisionEvent datashareHelper is nullptr");
        return;
    }
    WIFI_LOGI("RegisterDeviceProvisionEvent");
    deviceProvisionObserver_ = sptr<WifiDeviceProvisionObserver>(new (std::nothrow)WifiDeviceProvisionObserver());
    Uri uri(SETTINGS_DATASHARE_URI_DEVICE_PROVISIONED);
    datashareHelper->RegisterObserver(uri, deviceProvisionObserver_);
}

void WifiManager::UnRegisterDeviceProvisionEvent()
{
    if (deviceProvisionObserver_ == nullptr) {
        WIFI_LOGE("UnRegisterLocationEvent deviceProvisionObserver_ is nullptr");
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("UnRegisterLocationEvent datashareHelper is nullptr");
        return;
    }
    WIFI_LOGI("UnRegisterDeviceProvisionEvent");
    Uri uri(SETTINGS_DATASHARE_URI_DEVICE_PROVISIONED);
    datashareHelper->UnRegisterObserver(uri, deviceProvisionObserver_);
}

void WifiManager::DealLocationModeChangeEvent()
{
    if (WifiManager::GetInstance().GetLocationModeByDatashare()) {
        WIFI_LOGI("DealLocationModeChangeEvent open");
#ifdef OHOS_ARCH_LITE
        WifiManager::GetInstance().AutoStartScanOnly();
#else
        WifiManager::GetInstance().ScanOnlyToggled(1);
#endif
    } else {
        WIFI_LOGI("DealLocationModeChangeEvent close");
#ifdef OHOS_ARCH_LITE
        WifiManager::GetInstance().AutoStopScanOnly();
#else
        WifiManager::GetInstance().ScanOnlyToggled(0);
#endif
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
