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

#ifndef OHOS_WIFI_APP_STATE_AWARE_H
#define OHOS_WIFI_APP_STATE_AWARE_H

#ifndef OHOS_ARCH_LITE
#include "appmgr/app_mgr_interface.h"
#include "appmgr/app_state_data.h"
#include "iremote_object.h"
#include "wifi_event_handler.h"
#include "wifi_errcode.h"
#include "appmgr/application_state_observer_stub.h"

namespace OHOS {
namespace Wifi {

struct WifiAppStateAwareCallbacks {
    std::function<void(const AppExecFwk::AppStateData &appStateData, const int mInstId)> OnForegroundAppChanged;
};
class AppStateObserver;

class WifiAppStateAware {
public:
    explicit WifiAppStateAware(int instId = 0);
    ~WifiAppStateAware();
    static WifiAppStateAware &GetInstance();
    ErrCode InitAppStateAware(const WifiAppStateAwareCallbacks &wifiAppStateAwareCallbacks);
    bool Connect();
    void RegisterAppStateObserver();
    void UnSubscribeAppState();
    void OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData, const int mInstId = 0);
    void GetForegroundApp();
    bool IsForegroundApp(int32_t uid);
    bool IsForegroundApp(const std::string &bundleName);
    std::string GetRunningProcessNameByPid(const int uid, const int pid);

private:
    std::mutex mutex_ {};
    std::string foregroundAppBundleName_;
    int32_t foregroundAppUid_;
    std::unique_ptr<WifiEventHandler> appChangeEventHandler = nullptr;
    sptr<AppExecFwk::IAppMgr> appMgrProxy_ {nullptr};
    sptr<AppStateObserver> mAppStateObserver {nullptr};
    WifiAppStateAwareCallbacks mWifiAppStateAwareCallbacks;
};

class AppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    /**
     * Will be called when the application start.
     *
     * @param appStateData Application state data.
     */
    void OnAppStarted(const AppExecFwk::AppStateData &appStateData) override;

    /**
     * Will be called when the application stop.
     *
     * @param appStateData Application state data.
     */
    void OnAppStopped(const AppExecFwk::AppStateData &appStateData) override;

    /**
     * Application foreground state changed callback.
     *
     * @param appStateData Application Process data.
     */
    void OnForegroundApplicationChanged(const AppExecFwk::AppStateData &appStateData) override;
};
} // namespace Wifi
} // namespace OHOS
#endif
#endif