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

#ifndef OHOS_ARCH_LITE
#include "wifi_app_state_aware.h"
#include "app_mgr_constants.h"
#include "iservice_registry.h"
#include "ability_manager_client.h"
#include "system_ability_definition.h"
#include "app_mgr_client.h"
#include "wifi_protect_manager.h"
#include "wifi_service_manager.h"
#include "sta_app_acceleration.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("WifiAppStateAware");
constexpr const char *WIFI_APP_STATE_AWARE_THREAD = "WIFI_APP_STATE_AWARE_THREAD";

WifiAppStateAware::WifiAppStateAware(int instId)
{
    foregroundAppBundleName_ = "";
    appChangeEventHandler = std::make_unique<WifiEventHandler>(WIFI_APP_STATE_AWARE_THREAD);
    if (appChangeEventHandler) {
        std::function<void()> RegisterAppStateObserverFunc =
                            std::bind(&WifiAppStateAware::RegisterAppStateObserver, this);
        appChangeEventHandler->PostSyncTask(RegisterAppStateObserverFunc);
    } else {
        WIFI_LOGE("Create event handler failed.");
    }
    WIFI_LOGI("Register app state observer successful.");
}

WifiAppStateAware::~WifiAppStateAware()
{
    if (appChangeEventHandler) {
        appChangeEventHandler.reset();
    }

    if (mAppStateObserver) {
        mAppStateObserver = nullptr;
    }
}

WifiAppStateAware &WifiAppStateAware::GetInstance()
{
    static WifiAppStateAware gWifiAppStateAware;
    return gWifiAppStateAware;
}

ErrCode WifiAppStateAware::InitAppStateAware()
{
    return WIFI_OPT_SUCCESS;
}

void WifiAppStateAware::RegisterAppStateObserver()
{
    WIFI_LOGD("%{public}s called", __func__);
    auto appMgrClient = std::make_unique<AppExecFwk::AppMgrClient>();
    mAppStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int regAppStatusObsRetry = 0;
    while (appMgrClient->ConnectAppMgrService() != AppExecFwk::AppMgrResultCode::RESULT_OK) {
        WIFI_LOGE("ConnectAppMgrService fail, try again! retryTimes=%{public}d", ++regAppStatusObsRetry);
    }
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    mAppObject = iface_cast<AppExecFwk::IAppMgr>(systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (mAppObject) {
        int ret = mAppObject->RegisterApplicationStateObserver(mAppStateObserver);
        if (ret == ERR_OK) {
            WIFI_LOGI("register application state observer success.");
            return;
        }
        WIFI_LOGE("register application state observer fail, ret = %{public}d", ret);
        return;
    }
    WIFI_LOGE("get SystemAbilityManager fail");
}

void WifiAppStateAware::OnForegroundAppChanged(const std::string &bundleName, int uid, int pid,
    const int state)
{
    if (state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND)) {
        foregroundAppBundleName_ = bundleName;
    } else if (state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND) &&
        foregroundAppBundleName_ == bundleName) {
        foregroundAppBundleName_ = "";
    } else {
        WIFI_LOGI("state = %{pubilc}d, not handle.", state);
    }
    WifiProtectManager::GetInstance().OnAppForegroudChanged(bundleName, state);
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(m_instId);
    if(pService != nullptr) {
        pService->HandleForegroundAppChangedAction(bundleName, uid, pid, state);
    }
}

std::string WifiAppStateAware::GetForegroundApp()
{
    return foregroundAppBundleName_;
}

bool WifiAppStateAware::IsForegroundApp(std::string &bundleName)
{
    return bundleName == foregroundAppBundleName_;
}

void AppStateObserver::OnAppStarted(const AppExecFwk::AppStateData &appStateData)
{
    WIFI_LOGD("%{public}s bundleName: %{public}s, uid: %{public}d, state: %{public}d, isFocused: %{public}d",
        __func__, appStateData.bundleName.c_str(), appStateData.uid,
        appStateData.state, appStateData.isFocused);
}

void AppStateObserver::OnAppStopped(const AppExecFwk::AppStateData &appStateData)
{
    WIFI_LOGI("%{public}s bundleName: %{public}s, uid: %{public}d, state: %{public}d, isFocused: %{public}d",
        __func__, appStateData.bundleName.c_str(), appStateData.uid,
        appStateData.state, appStateData.isFocused);
    
    if (appStateData.bundleName.empty()) {
        WIFI_LOGE("App bundle name is empty");
        return;
    }
    WifiProtectManager::GetInstance().OnAppDied(appStateData.bundleName);
    return;
}

void AppStateObserver::OnForegroundApplicationChanged(const AppExecFwk::AppStateData &appStateData)
{
    WIFI_LOGI("%{public}s bundleName: %{public}s, uid: %{public}d, state: %{public}d, isFocused: %{public}d",
        __func__, appStateData.bundleName.c_str(), appStateData.uid,
        appStateData.state, appStateData.isFocused);
    WifiAppStateAware::GetInstance().OnForegroundAppChanged(appStateData.bundleName, appStateData.uid, 
        appStateData.pid, appStateData.state);
}
} // namespace Wifi
} // namespace OHOS
#endif
