/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFIMANAGER_H
#define OHOS_WIFIMANAGER_H

#include <string>
#include <vector>
#include <thread>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <functional>

#include <sys/stat.h>
#include <fcntl.h>
#include "define.h"
#include "wifi_internal_msg.h"
#include "sta_service_callback.h"
#include "iscan_service_callbacks.h"
#include "wifi_errcode.h"
#include "wifi_system_ability_listerner.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service_callbacks.h"
#endif
#ifdef FEATURE_P2P_SUPPORT
#include "ip2p_service_callbacks.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "common_event_manager.h"
#include "timer.h"
#endif

namespace OHOS {
namespace Wifi {
/* init state */
enum InitStatus {
    INIT_UNKNOWN = -1,
    INIT_OK = 0,
    CONFIG_CENTER_INIT_FAILED = 1,
    AUTH_CENTER_INIT_FAILED = 2,
    SERVICE_MANAGER_INIT_FAILED = 3,
    EVENT_BROADCAST_INIT_FAILED = 4,
    TASK_THREAD_INIT_FAILED = 5,
    WIFI_COUNTRY_CODE_MANAGER_INIT_FAILED = 6,
};

enum class WifiCloseServiceCode {
    STA_SERVICE_CLOSE,
    SCAN_SERVICE_CLOSE,
    AP_SERVICE_CLOSE,
    P2P_SERVICE_CLOSE,
    SERVICE_THREAD_EXIT,
};

struct WifiCloseServiceMsg
{
    WifiCloseServiceCode code;
    int instId;
};

struct WifiCfgMonitorEventCallback {
    std::function<void(int)> onStaConnectionChange = nullptr;
};

#ifndef OHOS_ARCH_LITE
class ScreenEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ScreenEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~ScreenEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};

class AirplaneModeEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit AirplaneModeEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~AirplaneModeEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class BatteryEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit BatteryEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    ~BatteryEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class WifiTimer {
public:
    using TimerCallback = std::function<void()>;
    static constexpr uint32_t DEFAULT_TIMEROUT = 10000;
    static WifiTimer *GetInstance(void);

    WifiTimer();
    ~WifiTimer();

    ErrCode Register(
        const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval = DEFAULT_TIMEROUT, bool once = true);
    void UnRegister(uint32_t timerId);

private:
    std::unique_ptr<Utils::Timer> timer_{nullptr};
};
#endif

class WifiManager : WifiSystemAbilityListener {
public:
    WifiManager();
    ~WifiManager();
    /**
     * @Description Initialize submodules and message processing threads.
     *              1. Initializing the Configuration Center
     *              2. Initialization permission management
     *              3. Initializing Service Management
     *              4. Initialization event broadcast
     *              5. Initializing a Message Queue
     *              6. Initialize the message processing thread
     *
     * @return int - Init result, when 0 means success, other means some fails happened.
     */
    int Init();

    /**
     * @Description When exiting, the system exits each submodule and then exits the message processing thread.
     *              1. Uninstall each feature service
     *              2. Exit the event broadcast module
     *              3. Wait for the message processing thread to exit
     *
     */
    void Exit();

    /**
     * @Description Get the sta callback object.
     *
     * @return StaServiceCallback - return mStaCallback
     */
    StaServiceCallback GetStaCallback(void);

    /**
     * @Description Get the scan callback object.
     *
     * @return IScanSerivceCallbacks - return mScanCallback
     */
    IScanSerivceCallbacks GetScanCallback(void);
    
    ErrCode AutoStartStaService(AutoStartOrStopServiceReason reason, int instId = 0);
    ErrCode AutoStopStaService(AutoStartOrStopServiceReason reason, int instId = 0);
    void StopUnloadStaSaTimer(void);
    void StartUnloadStaSaTimer(void);
    void StopUnloadScanSaTimer(void);
    void StartUnloadScanSaTimer(void);

    void OnSystemAbilityChanged(int systemAbilityId, bool add) override;
    
#ifdef FEATURE_AP_SUPPORT
    /**
     * @Description Get the ap callback object.
     *
     * @return IApServiceCallbacks - return mApCallback
     */
    IApServiceCallbacks GetApCallback(void);

    ErrCode AutoStartApService(AutoStartOrStopServiceReason reason);
    ErrCode AutoStopApService(AutoStartOrStopServiceReason reason);
    void StopUnloadApSaTimer(void);
    void StartUnloadApSaTimer(void);
#endif

#ifdef FEATURE_P2P_SUPPORT
    /**
     * @Description Get the p2p callback object.
     *
     * @return IP2pServiceCallbacks - return mP2pCallback
     */
    IP2pServiceCallbacks GetP2pCallback(void);

    ErrCode AutoStartP2pService(AutoStartOrStopServiceReason reason);
    ErrCode AutoStopP2pService(AutoStartOrStopServiceReason reason);
    void StopUnloadP2PSaTimer(void);
    void StartUnloadP2PSaTimer(void);
#endif

    /**
     * @Description Get supported features
     *
     * @param features - output supported features
     * @return int - operation result
     */
    int GetSupportedFeatures(long &features) const;

    /**
     * @Description Add supported feature
     *
     * @param feature
     */
    void AddSupportedFeatures(WifiFeatures feature);

    static WifiManager &GetInstance();

    void RegisterCfgMonitorCallback(WifiCfgMonitorEventCallback callback);
    void GetAirplaneModeByDatashare();
    void GetDeviceProvisionByDatashare();
    void DealOpenAirplaneModeEvent();
    void DealCloseAirplaneModeEvent();
    void DealLocationModeChangeEvent();
    bool GetLocationModeByDatashare();
#ifndef OHOS_ARCH_LITE
    bool GetLastStaStateByDatashare();
    void CheckAndStartStaByDataShare();
#endif
    static void CheckAndStartScanService(int instId = 0);

private:
    void PushServiceCloseMsg(WifiCloseServiceCode code, int instId = 0);
    void InitStaCallback(void);
    void InitScanCallback(void);
    void InitSubscribeListener();
#ifdef FEATURE_AP_SUPPORT
    void InitApCallback(void);
#endif
#ifdef FEATURE_P2P_SUPPORT
    void InitP2pCallback(void);
#endif
    InitStatus GetInitStatus();
    static void DealCloseServiceMsg(WifiManager &manager);
    static void CloseStaService(int instId = 0);
    static void UnloadStaSaTimerCallback();
    static void UnloadScanSaTimerCallback();
#ifdef FEATURE_AP_SUPPORT
    static void CloseApService(int id = 0);
    static void UnloadHotspotSaTimerCallback();
#endif
    static void CloseScanService(int instId = 0);
#ifdef FEATURE_P2P_SUPPORT
    static void CloseP2pService(void);
    static void UnloadP2PSaTimerCallback();
#endif
    static void DealStaOpenRes(OperateResState state, int instId = 0);
    static void DealStaCloseRes(OperateResState state, int instId = 0);
    static void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    static void DealWpsChanged(WpsStartState state, const int pinCode, int instId = 0);
    static void DealStreamChanged(StreamDirection direction, int instId = 0);
    static void DealRssiChanged(int rssi, int instId = 0);
    static void CheckAndStopScanService(int instId = 0);
    static void DealScanOpenRes(int instId = 0);
    static void DealScanCloseRes(int instId = 0);
    static void DealScanFinished(int state, int instId = 0);
    static void DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId = 0);
    static void DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId = 0);
    static void DealOpenScanOnlyRes(OperateResState state, int instId = 0);
    static void DealCloseScanOnlyRes(OperateResState state, int instId = 0);
    static void DealAirplaneExceptionWhenStaOpen(int instId = 0);
    static void DealAirplaneExceptionWhenStaClose(int instId = 0);
#ifdef FEATURE_AP_SUPPORT
    static void DealApStateChanged(ApState bState, int id = 0);
    static void DealApGetStaJoin(const StationInfo &info, int id = 0);
    static void DealApGetStaLeave(const StationInfo &info, int id = 0);
#endif
#ifdef FEATURE_P2P_SUPPORT
    static void DealP2pStateChanged(P2pState bState);
    static void DealP2pPeersChanged(const std::vector<WifiP2pDevice> &vPeers);
    static void DealP2pServiceChanged(const std::vector<WifiP2pServiceInfo> &vServices);
    static void DealP2pConnectionChanged(const WifiP2pLinkedInfo &info);
    static void DealP2pThisDeviceChanged(const WifiP2pDevice &info);
    static void DealP2pDiscoveryChanged(bool bState);
    static void DealP2pGroupsChanged(void);
    static void DealP2pActionResult(P2pActionCallback action, ErrCode code);
    static void DealConfigChanged(CfgType type, char* data, int dataLen);
#endif
    static void AutoStartScanOnly(int instId = 0);
    static void AutoStopScanOnly(int instId = 0);
    static void ForceStopWifi(int instId = 0);
    static void AutoStartScanService(int instId = 0);
    static void AutoStartEnhanceService(void);
    static void CheckAndStartSta(AutoStartOrStopServiceReason reason);
    static void AutoStartServiceThread(AutoStartOrStopServiceReason reason);

    void InitPidfile(void);
private:
    std::thread mCloseServiceThread;
    std::mutex mMutex;
    std::mutex screenEventMutex;
    std::mutex airplaneModeEventMutex;
    std::mutex locationEventMutex;
    std::mutex batteryEventMutex;
    std::condition_variable mCondition;
    std::deque<WifiCloseServiceMsg> mEventQue;
    StaServiceCallback mStaCallback;
    IScanSerivceCallbacks mScanCallback;
#ifndef OHOS_ARCH_LITE
    std::mutex settingsMigrateMutex;
    static uint32_t unloadStaSaTimerId;
    static std::mutex unloadStaSaTimerMutex;
    static uint32_t unloadScanSaTimerId;
    static std::mutex unloadScanSaTimerMutex;
#endif
#ifdef FEATURE_AP_SUPPORT
    IApServiceCallbacks mApCallback;
#ifndef OHOS_ARCH_LITE
    static uint32_t unloadHotspotSaTimerId;
    static std::mutex unloadHotspotSaTimerMutex;
#endif
#endif
#ifdef FEATURE_P2P_SUPPORT
    IP2pServiceCallbacks mP2pCallback;
    static WifiCfgMonitorEventCallback cfgMonitorCallback;
#ifndef OHOS_ARCH_LITE
    static uint32_t unloadP2PSaTimerId;
    static std::mutex unloadP2PSaTimerMutex;
#endif
#endif
#ifndef OHOS_ARCH_LITE
    void RegisterScreenEvent();
    void UnRegisterScreenEvent();
    std::shared_ptr<ScreenEventSubscriber> screenEventSubscriber_ = nullptr;
    uint32_t screenTimerId{0};
    void RegisterAirplaneModeEvent();
    void UnRegisterAirplaneModeEvent();
    std::shared_ptr<AirplaneModeEventSubscriber> airplaneModeEventSubscriber_ = nullptr;
    uint32_t airplaneModeTimerId{0};
    void RegisterLocationEvent();
    void UnRegisterLocationEvent();
    void RegisterDeviceProvisionEvent();
    void UnRegisterDeviceProvisionEvent();
    uint32_t locationTimerId{0};
    std::shared_ptr<BatteryEventSubscriber> batterySubscriber_ = nullptr;
    uint32_t batteryTimerId{0};
    void RegisterBatteryEvent();
    void UnRegisterBatteryEvent();
    void RegisterSettingsMigrateEvent();
    void UnRegisterSettingsMigrateEvent();
    uint32_t migrateTimerId{0};
#endif
    InitStatus mInitStatus;
    long mSupportedFeatures;
    static int mCloseApIndex;
};
} // namespace Wifi
} // namespace OHOS
#endif
