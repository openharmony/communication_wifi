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
#include "app_network_speed_limit_service.h"
#include "wifi_logger.h"
#include "connection_observer_client.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("WifiAppStateAware");
constexpr const char *WIFI_APP_STATE_AWARE_THREAD = "WIFI_APP_STATE_AWARE_THREAD";
constexpr int32_t UID_CALLINGUID_TRANSFORM_DIVISOR = 200000;
constexpr int64_t WIFI_APP_STATE_SUBSCRIBE_TIME_DELAY = 3 * 1000;
const std::string APP_STATE_EVENT = "WIFI_APP_STATE_EVENT";
WifiAppStateAware::WifiAppStateAware(int instId)
{
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

sptr<AppExecFwk::IAppMgr> WifiAppStateAware::GetAppMgr()
{
    //获取AppMgr
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        WIFI_LOGE("get SystemAbilityManager failed");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        WIFI_LOGE("get App Manager Service failed");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(remoteObject);
}

void WifiAppStateAware::RegisterAppStateChangedCallback(const int64_t delayTime)
{
    WIFI_LOGI("%{public}s enter", __func__);
    if (appChangeEventHandler) {
        std::function<void()> RegisterAppStateObserverFunc = [this]() { this->RegisterAppStateObserver(); };
        appChangeEventHandler->PostAsyncTask(RegisterAppStateObserverFunc, APP_STATE_EVENT, delayTime);
    } else {
        WIFI_LOGE("%{public}s appChangeEventHandler is null", __func__);
    }
}

void WifiAppStateAware::RegisterAppStateObserver()
{
    WIFI_LOGI("%{public}s called", __func__);
    std::lock_guard<std::mutex> lock(mutex_);
    if (mAppStateObserver) {
        WIFI_LOGI("mAppStateObserver already registered");
    }
    auto appMgrProxy = GetAppMgr();
    if (appMgrProxy == nullptr) {
        WIFI_LOGI("%{public}s GetAppMgr fail", __func__);
        RegisterAppStateChangedCallback(WIFI_APP_STATE_SUBSCRIBE_TIME_DELAY);
        return;
    }
    mAppStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int ret = appMgrProxy->RegisterApplicationStateObserver(mAppStateObserver);
    if (ret != ERR_OK) {
        WIFI_LOGE("register application state observer fail, ret = %{public}d", ret);
        RegisterAppStateChangedCallback(WIFI_APP_STATE_SUBSCRIBE_TIME_DELAY);
        return;
    }
    WIFI_LOGI("register application state observer success.");
}

void WifiAppStateAware::UnSubscribeAppState()
{
    WIFI_LOGI("%{public}s called", __func__);
    auto appMgrProxy = GetAppMgr();
    if (appMgrProxy == nullptr) {
        WIFI_LOGI("%{public}s GetAppMgr fail", __func__);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mAppStateObserver) {
        WIFI_LOGE("UnSubscribeAppState: mAppStateObserver is nullptr");
        return;
    }
    appMgrProxy->UnregisterApplicationStateObserver(mAppStateObserver);
    mAppStateObserver = nullptr;
    WIFI_LOGI("UnSubscribeAppState end");
    return;
}

void WifiAppStateAware::OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData, const int mInstId)
{
    WifiProtectManager::GetInstance().OnAppForegroudChanged(appStateData.bundleName, appStateData.state);
#ifndef OHOS_ARCH_LITE
    AppNetworkSpeedLimitService::GetInstance().HandleForegroundAppChangedAction(appStateData);
    if (mWifiAppStateAwareCallbacks.OnForegroundAppChanged != nullptr) {
        mWifiAppStateAwareCallbacks.OnForegroundAppChanged(appStateData, mInstId);
    }
#endif
}

ErrCode WifiAppStateAware::GetProcessRunningInfos(std::vector<AppExecFwk::RunningProcessInfo> &info)
{
    auto appMgrProxy = GetAppMgr();
    if (appMgrProxy == nullptr) {
        WIFI_LOGE("%{public}s GetAppMgr failed", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    if (appMgrProxy->GetAllRunningProcesses(info)
        != AppExecFwk::AppMgrResultCode::RESULT_OK) {
        WIFI_LOGE("%{public}s GetProcessRunningInfoByUserId failed", __FUNCTION__);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiAppStateAware::IsForegroundApp(int32_t uid)
{
    auto appMgrProxy = GetAppMgr();
    if (appMgrProxy == nullptr) {
        WIFI_LOGE("%{public}s GetAppMgr failed", __FUNCTION__);
        return false;
    }
    std::vector<AppExecFwk::AppStateData> curForegroundApps;
    appMgrProxy->GetForegroundApplications(curForegroundApps);

    for (auto foregroudApp : curForegroundApps) {
        if (foregroudApp.uid == uid) {
            return true;
        }
    }
    return false;
}

bool WifiAppStateAware::IsForegroundApp(const std::string &bundleName)
{
    auto appMgrProxy = GetAppMgr();
    if (appMgrProxy == nullptr) {
        WIFI_LOGE("%{public}s GetAppMgr failed", __FUNCTION__);
        return false;
    }
    std::vector<AppExecFwk::AppStateData> curForegroundApps;
    appMgrProxy->GetForegroundApplications(curForegroundApps);
    for (auto foregroudApp : curForegroundApps) {
        if (foregroudApp.bundleName == bundleName) {
            return true;
        }
    }
    return false;
}

std::string WifiAppStateAware::GetRunningProcessNameByPid(const int uid, const int pid)
{
    auto appMgrProxy = GetAppMgr();
    if (appMgrProxy == nullptr) {
        WIFI_LOGE("%{public}s GetAppMgr failed", __FUNCTION__);
        return "";
    }
    int32_t userId = static_cast<int32_t>(uid / UID_CALLINGUID_TRANSFORM_DIVISOR);
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int ret = appMgrProxy->GetProcessRunningInfosByUserId(infos, userId);
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

bool WifiAppStateAware::CheckAssociatedAppInForeground(const int32_t uid)
{
    std::vector<AbilityRuntime::ConnectionData> connectionData;
    int32_t ret = AbilityRuntime::ConnectionObserverClient::GetInstance().GetConnectionData(connectionData);
    if (ret != 0) {
        WIFI_LOGE("get connection data failed: %{public}d", ret);
        return false;
    }
 
    for (auto it = connectionData.begin(); it != connectionData.end(); it++) {
        if (it->extensionUid != uid) {
            continue;
        }
        if (IsForegroundApp(it->callerUid) && IsAppInFilterList("ScanForegroundAllowLimitList", it->callerName)) {
            WIFI_LOGI("The Wifi caller is called by foreground app(callerUid: %{public}d, packageName: %{public}s)",
                it->callerUid,
                it->callerName.c_str());
            return true;
        }
    }
    return false;
}
 
bool WifiAppStateAware::IsAppInFilterList(const std::string &packageName, const std::string &callerName)
{
    std::vector<PackageInfo> specialList;
    if (WifiSettings::GetInstance().GetPackageInfoByName(packageName, specialList) != 0) {
        WIFI_LOGE("ProcessSwitchInfoRequest GetPackageInfoByName failed");
        return false;
    }
    for (auto iter = specialList.begin(); iter != specialList.end(); iter++) {
        if (iter->name == callerName) {
            return true;
        }
    }
    return false;
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
    WIFI_HILOG_COMM_INFO("%{public}s bundleName: %{public}s, uid: %{public}d, state: %{public}d, isFocused: %{public}d",
        __func__, appStateData.bundleName.c_str(), appStateData.uid, appStateData.state, appStateData.isFocused);
    WifiAppStateAware::GetInstance().OnForegroundAppChanged(appStateData);
}

void AppStateObserver::OnProcessCreated(const AppExecFwk::ProcessData &processData)
{
    WifiAppStateAware::GetInstance().HandleProcessCreatedEvent(processData);
}
} // namespace Wifi
} // namespace OHOS
