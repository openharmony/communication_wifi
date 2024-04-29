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

#include "wifi_app_state_aware.h"
#include "iservice_registry.h"
#include "ability_manager_client.h"
#include "system_ability_definition.h"
#include "app_mgr_client.h"
#include "wifi_protect_manager.h"
#include "wifi_service_manager.h"
#include "sta_app_acceleration.h"
#include "app_network_speed_limit_service.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("WifiAppStateAware");
constexpr const char *WIFI_APP_STATE_AWARE_THREAD = "WIFI_APP_STATE_AWARE_THREAD";
constexpr int32_t UID_CALLINGUID_TRANSFORM_DIVISOR = 200000;
WifiAppStateAware::WifiAppStateAware(int instId)
{
    GetForegroundApp();
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
    UnSubscribeAppState();
    if (appMgrProxy_) {
        appMgrProxy_ = nullptr;
    }
}

WifiAppStateAware &WifiAppStateAware::GetInstance()
{
    static WifiAppStateAware gWifiAppStateAware;
    return gWifiAppStateAware;
}

ErrCode WifiAppStateAware::InitAppStateAware(const WifiAppStateAwareCallbacks &wifiAppStateAwareCallbacks)
{
    mWifiAppStateAwareCallbacks = wifiAppStateAwareCallbacks;
    return WIFI_OPT_SUCCESS;
}
bool WifiAppStateAware::Connect()
{
    if (appMgrProxy_ != nullptr) {
        WIFI_LOGI("appManager already connect");
        return true;
    }

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        WIFI_LOGE("get SystemAbilityManager failed");
        return false;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        WIFI_LOGE("get App Manager Service failed");
        return false;
    }

    appMgrProxy_ = iface_cast<AppExecFwk::IAppMgr>(remoteObject);
    if (!appMgrProxy_ || !appMgrProxy_->AsObject()) {
        WIFI_LOGE("get appManager proxy failed!");
        return false;
    }
    return true;
}

void WifiAppStateAware::RegisterAppStateObserver()
{
    WIFI_LOGI("%{public}s called", __func__);
    std::lock_guard<std::mutex> lock(mutex_);
    if (mAppStateObserver) {
        WIFI_LOGI("mAppStateObserver already registered");
    }
    if (!Connect()) {
        return;
    }
    mAppStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int ret = appMgrProxy_->RegisterApplicationStateObserver(mAppStateObserver);
    if (ret != ERR_OK) {
        WIFI_LOGE("register application state observer fail, ret = %{public}d", ret);
        return;
    }
    WIFI_LOGI("register application state observer success.");
}

void WifiAppStateAware::UnSubscribeAppState()
{
    WIFI_LOGI("%{public}s called", __func__);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mAppStateObserver) {
        WIFI_LOGE("UnSubscribeAppState: mAppStateObserver is nullptr");
        return;
    }
    if (appMgrProxy_) {
        appMgrProxy_->UnregisterApplicationStateObserver(mAppStateObserver);
        appMgrProxy_ = nullptr;
        mAppStateObserver = nullptr;
    }
    WIFI_LOGI("UnSubscribeAppState end");
    return;
}

void WifiAppStateAware::OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData, const int mInstId)
{
    if (appStateData.state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND) &&
        appStateData.isFocused) {
        foregroundAppBundleName_ = appStateData.bundleName;
        foregroundAppUid_ = appStateData.uid;
    } else if (appStateData.state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND) &&
        foregroundAppBundleName_ == appStateData.bundleName) {
        foregroundAppBundleName_ = "";
        foregroundAppUid_ = -1;
    } else {
        WIFI_LOGI("state = %{pubilc}d, not handle.", appStateData.state);
    }
    WifiProtectManager::GetInstance().OnAppForegroudChanged(appStateData.bundleName, appStateData.state);
#ifndef OHOS_ARCH_LITE
    AppNetworkSpeedLimitService::GetInstance().HandleForegroundAppChangedAction(appStateData);
    mWifiAppStateAwareCallbacks.OnForegroundAppChanged(appStateData, mInstId);
#endif
}

void WifiAppStateAware::GetForegroundApp()
{
    if (!Connect()) {
        return ;
    }
    std::vector<AppExecFwk::AppStateData> fgAppList;
    appMgrProxy_->GetForegroundApplications(fgAppList);
    if (fgAppList.size() > 0) {
        WIFI_LOGI("fgApp: %{public}s, state = %{public}d", fgAppList[0].bundleName.c_str(), fgAppList[0].state);
        foregroundAppBundleName_ = fgAppList[0].bundleName;
        foregroundAppUid_ = fgAppList[0].uid;
        return;
    }
    return;
}

bool WifiAppStateAware::IsForegroundApp(int32_t uid)
{
    WIFI_LOGD("IsForegroundApp %{public}s %{public}d, try uid: %{public}d",
        foregroundAppBundleName_.c_str(), foregroundAppUid_, uid);
    return foregroundAppUid_ == uid;
}

bool WifiAppStateAware::IsForegroundApp(const std::string &bundleName)
{
    return bundleName == foregroundAppBundleName_;
}

std::string WifiAppStateAware::GetRunningProcessNameByPid(const int uid, const int pid)
{
    if (!Connect()) {
        return "";
    }
    int32_t userId = static_cast<int32_t>(uid / UID_CALLINGUID_TRANSFORM_DIVISOR);
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int ret = appMgrProxy_->GetProcessRunningInfosByUserId(infos, userId);
    if (ret != ERR_OK) {
        WIFI_LOGE("GetProcessRunningInfosByUserId fail, ret = [%{public}d]", ret);
        return "";
    }
    std::string processName = "";
    auto iter = infos.begin();
    while (iter != infos.end()) {
        if (iter->pid_ == pid) {
            processName = iter->processName_;
            break;
        }
        iter++;
    }
    return processName;
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
        __func__, appStateData.bundleName.c_str(), appStateData.uid, appStateData.state, appStateData.isFocused);
    WifiAppStateAware::GetInstance().OnForegroundAppChanged(appStateData);
}
} // namespace Wifi
} // namespace OHOS
