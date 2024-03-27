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

#ifndef OHOS_WIFI_PROTECT_MANAGER_H
#define OHOS_WIFI_PROTECT_MANAGER_H

#include <vector>
#include "wifi_protect.h"
#ifndef OHOS_ARCH_LITE
#include "appmgr/application_state_observer_stub.h"
#include "appmgr/app_state_data.h"
#include "ipc_skeleton.h"
#include "event_handler.h"
#include "event_runner.h"
#include "appmgr/app_mgr_interface.h"
#include "wifi_event_handler.h"
#endif

namespace OHOS {
namespace Wifi {
#ifndef OHOS_ARCH_LITE
class AppStateObserver;
#endif
class WifiProtectManager {
public:
    ~WifiProtectManager();
    static WifiProtectManager &GetInstance();

    /**
     * @Description Validate that the protect mode is valid
     *
     * @param protectMode - The protect mode to verify
     * @return true - valid
     * @return false - invalid
     */
    static bool IsValidProtectMode(const WifiProtectMode &protectMode);

    /**
     * @Description Get the nearly protect type currently held by the WifiProtectManager
     *
     * @return WifiProtectMode - currently held protect
     */
    WifiProtectMode GetNearlyProtectMode();

    /**
     * @Description Create a Wifi Protect.
     *
     * @param protectMode - representation of the Wifi Protect type
     * @param protectName - represent the protect name
     * @return true - create the protect success
     * @return false - create protect failed
     */
    bool InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName);

    /**
     * @Description Allowing a calling app to acquire a Wifi Protect in the supplied mode
     *
     * @param protectMode - representation of the Wifi Protect type
     * @param name - represent the protect
     * @return true - acquired the protect success
     * @return false - acquired protect failed
     */
    bool GetWifiProtect(const WifiProtectMode &protectMode, const std::string name);

    /**
     * @Description Applications to release a WiFi Wake protect
     *
     * @param name - represent the protect
     * @return true - put protect success
     * @return false - put failed, the caller did not hold this protect
     */
    bool PutWifiProtect(const std::string &name);

    /**
     * @Description Applications whether or not hold WiFi protect
     *
     * @param name - represent the protect
     * @return true - app has held wifi protect
     * @return false - app has not held wifi protect
     */
    bool IsHeldWifiProtect(const std::string &name);
    /**
     * @Description Set hi-perf mode protect state
     *
     * @param isEnabled - True to force hi-perf mode, false to leave it up to acquired wifiProtects
     * @return true - success
     * @return false - failed
     */
    bool ChangeToPerfMode(bool isEnabled);

    /**
     * @Description Handler for screen state (on/off) changes
     *
     * @param screenOn - screen on/off state
     */
    void HandleScreenStateChanged(bool screenOn);

    /**
     * @Description Handler for Wifi Client mode state changes
     *
     * @param isConnected - wifi client connect state
     */
    void UpdateWifiClientConnected(bool isConnected);

    /**
     * @Description set low latency mode
     *
     * @param enabled - true: enable low latency, false: disable low latency
     * @return bool - operation result
     */
    bool SetLowLatencyMode(bool enabled);
    bool ChangeWifiPowerMode();
#ifndef OHOS_ARCH_LITE
    void RegisterAppStateObserver();
    void OnAppDied(const std::string bundlename);
    void OnAppForegroudChanged(const std::string &bundleName, int state);
#endif
private:
    WifiProtectManager();
    bool AddProtect(const WifiProtectMode &protectMode, const std::string &name);
    bool ReleaseProtect(const std::string &name);
    std::shared_ptr<WifiProtect> RemoveProtect(const std::string &name);
#ifndef OHOS_ARCH_LITE
    int GetFgLowlatyProtectCount();
    bool IsForegroundApplication(const std::string &BundleName);
#endif
private:
    std::vector<std::shared_ptr<WifiProtect>> mWifiProtects;
    WifiProtectMode mCurrentOpMode {WifiProtectMode::WIFI_PROTECT_NO_HELD};
    int mFullHighPerfProtectsAcquired {0};
    int mFullHighPerfProtectsReleased {0};
    int mFullLowLatencyProtectsAcquired {0};
    int mFullLowLatencyProtectsReleased {0};
    /* Not used: long mCurrentSessionStartTimeMs; */
    bool mWifiConnected {false};
    bool mScreenOn {false};
    bool mForceHiPerfMode {false};
    bool mForceLowLatencyMode {false};
    std::mutex mMutex;
#ifndef OHOS_ARCH_LITE
    sptr<AppExecFwk::IAppMgr> mAppObject {nullptr};
#endif
};
} // namespace Wifi
} // namespace OHOS

#endif
