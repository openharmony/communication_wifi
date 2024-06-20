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
constexpr const int APP_INFO_USERID = 100;
constexpr int64_t WIFI_APP_STATE_SUBSCRIBE_TIME_DELAY = 3 * 1000;
#ifdef DTFUZZ_TEST
static WifiAppStateAware* gWifiAppStateAware = nullptr;
#endif
WifiAppStateAware::WifiAppStateAware(int instId)
{
    GetForegroundApp();
    appChangeEventHandler = std::make_unique<WifiEventHandler>(WIFI_APP_STATE_AWARE_THREAD);
    RegisterAppStateChangedCallback();
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
#ifndef DTFUZZ_TEST
    static WifiAppStateAware gWifiAppStateAware;
    return gWifiAppStateAware;
#else
    if (gWifiAppStateAware == nullptr) {
        gWifiAppStateAware = new (std::nothrow) WifiAppStateAware();
    }
    return *gWifiAppStateAware;
#endif
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

void WifiAppStateAware::RegisterAppStateChangedCallback(const int64_t delayTime)
{
    WIFI_LOGI("%{public}s enter", __func__);
    if (appChangeEventHandler) {
        std::function<void()> RegisterAppStateObserverFunc =
            std::bind(&WifiAppStateAware::RegisterAppStateObserver, this);
        appChangeEventHandler->PostAsyncTask(RegisterAppStateObserverFunc, delayTime);
    } else {
        WIFI_LOGE("%{public}s appChangeEventHandler is null", __func__);
    }
}

bool WifiAppStateAware::UpdateCurForegroundAppInfo(const AppExecFwk::AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND) &&
        !HasRecordInCurForegroundApps(appStateData)) {
        curForegroundApps_.push_back(appStateData);
        return true;
    }

    if (appStateData.state == static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND) &&
        HasRecordInCurForegroundApps(appStateData)) {
        curForegroundApps_.erase(std::remove_if(curForegroundApps_.begin(), curForegroundApps_.end(),
            [&](const AppExecFwk::AppStateData &recordApp) {
                return recordApp.uid == appStateData.uid;
            }), curForegroundApps_.end());
        return true;
    }
    return false;
}

bool WifiAppStateAware::HasRecordInCurForegroundApps(const AppExecFwk::AppStateData &appStateData)
{
    for (auto recordApp : curForegroundApps_) {
        if (recordApp.uid == appStateData.uid) {
            return true;
        }
    }
    return false;
}

void WifiAppStateAware::RegisterAppStateObserver()
{
    WIFI_LOGI("%{public}s called", __func__);
    std::lock_guard<std::mutex> lock(mutex_);
    if (mAppStateObserver) {
        WIFI_LOGI("mAppStateObserver already registered");
    }
    if (!Connect()) {
        WIFI_LOGI("%{public}s connect fail", __func__);
        RegisterAppStateChangedCallback(WIFI_APP_STATE_SUBSCRIBE_TIME_DELAY);
        return;
    }
    mAppStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int ret = appMgrProxy_->RegisterApplicationStateObserver(mAppStateObserver);
    if (ret != ERR_OK) {
        WIFI_LOGE("register application state observer fail, ret = %{public}d", ret);
        RegisterAppStateChangedCallback(WIFI_APP_STATE_SUBSCRIBE_TIME_DELAY);
        return;
    }
    GetForegroundApp();
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
    curForegroundApps_.clear();
    WIFI_LOGI("UnSubscribeAppState end");
    return;
}

void WifiAppStateAware::OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData, const int mInstId)
{
    if (!UpdateCurForegroundAppInfo(appStateData)) {
        return;
    }
    WifiProtectManager::GetInstance().OnAppForegroudChanged(appStateData.bundleName, appStateData.state);
#ifndef OHOS_ARCH_LITE
    AppNetworkSpeedLimitService::GetInstance().HandleForegroundAppChangedAction(appStateData);
    mWifiAppStateAwareCallbacks.OnForegroundAppChanged(appStateData, mInstId);
#endif
}

void WifiAppStateAware::GetForegroundApp()
{
    curForegroundApps_.clear();
    if (!Connect()) {
        WIFI_LOGE("%{public}s connect failed", __FUNCTION__);
        return ;
    }
    appMgrProxy_->GetForegroundApplications(curForegroundApps_);
}

ErrCode WifiAppStateAware::GetProcessRunningInfos(std::vector<AppExecFwk::RunningProcessInfo> &info)
{
    if (!Connect()) {
        WIFI_LOGE("%{public}s connect failed", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    if (appMgrProxy_->GetProcessRunningInfosByUserId(info, APP_INFO_USERID)
        != AppExecFwk::AppMgrResultCode::RESULT_OK) {
        WIFI_LOGE("%{public}s GetProcessRunningInfoByUserId failed", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiAppStateAware::IsForegroundApp(int32_t uid)
{
    for (auto foregroudApp : curForegroundApps_) {
        if (foregroudApp.uid == uid) {
            return true;
        }
    }
    return false;
}

bool WifiAppStateAware::IsForegroundApp(const std::string &bundleName)
{
    for (auto foregroudApp : curForegroundApps_) {
        if (foregroudApp.bundleName == bundleName) {
            return true;
        }
    }
    return false;
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
    WIFI_LOGD("%{public}s bundleName: %{public}s, uid: %{public}d, state: %{public}d, isFocused: %{public}d",
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
