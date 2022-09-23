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

#include "define.h"
#include "wifi_internal_msg.h"
#include "sta_service_callback.h"
#include "iscan_service_callbacks.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service_callbacks.h"
#endif
#ifdef FEATURE_P2P_SUPPORT
#include "ip2p_service_callbacks.h"
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
};

enum class WifiCloseServiceCode {
    STA_SERVICE_CLOSE,
    SCAN_SERVICE_CLOSE,
    AP_SERVICE_CLOSE,
    P2P_SERVICE_CLOSE,
    SERVICE_THREAD_EXIT,
};

struct WifiCfgMonitorEventCallback {
    std::function<void(int)> onStaConnectionChange = nullptr;
};

class WifiManager {
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

#ifdef FEATURE_AP_SUPPORT
    /**
     * @Description Get the ap callback object.
     *
     * @return IApServiceCallbacks - return mApCallback
     */
    IApServiceCallbacks GetApCallback(void);
#endif

#ifdef FEATURE_P2P_SUPPORT
    /**
     * @Description Get the p2p callback object.
     *
     * @return IP2pServiceCallbacks - return mP2pCallback
     */
    IP2pServiceCallbacks GetP2pCallback(void);
#endif

    /**
     * @Description Get supported features
     *
     * @param features - output supported features
     * @return int - operation result
     */
    int GetSupportedFeatures(long &features);

    /**
     * @Description Add supported feature
     *
     * @param feature
     */
    void AddSupportedFeatures(WifiFeatures feature);

    static WifiManager &GetInstance();

    void RegisterCfgMonitorCallback(WifiCfgMonitorEventCallback callback);

private:
    void PushServiceCloseMsg(WifiCloseServiceCode code);
    void InitStaCallback(void);
    void InitScanCallback(void);
#ifdef FEATURE_AP_SUPPORT
    void InitApCallback(void);
#endif
#ifdef FEATURE_P2P_SUPPORT
    void InitP2pCallback(void);
#endif
    InitStatus GetInitStatus();
    static void DealCloseServiceMsg(WifiManager &manager);
    static void CloseStaService(void);
#ifdef FEATURE_AP_SUPPORT
    static void CloseApService(int id = 0);
#endif
    static void CloseScanService(void);
#ifdef FEATURE_P2P_SUPPORT
    static void CloseP2pService(void);
#endif
    static void DealStaOpenRes(OperateResState state);
    static void DealStaCloseRes(OperateResState state);
    static void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info);
    static void DealWpsChanged(WpsStartState state, const int pinCode);
    static void DealStreamChanged(StreamDirection direction);
    static void DealRssiChanged(int rssi);
    static void CheckAndStartScanService(void);
    static void CheckAndStopScanService(void);
    static void DealScanOpenRes(void);
    static void DealScanCloseRes(void);
    static void DealScanFinished(int state);
    static void DealScanInfoNotify(std::vector<InterScanInfo> &results);
    static void DealStoreScanInfoEvent(std::vector<InterScanInfo> &results);
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
    static void AutoStartStaService(void);
    static void ForceStopWifi(void);
#ifdef FEATURE_P2P_SUPPORT
    static void AutoStartP2pService(void);
#endif
    static void AutoStartScanService(void);
    static void CheckAndStartSta(void);
    static void AutoStartServiceThread(void);

private:
    std::thread mCloseServiceThread;
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::deque<WifiCloseServiceCode> mEventQue;
    StaServiceCallback mStaCallback;
    IScanSerivceCallbacks mScanCallback;
#ifdef FEATURE_AP_SUPPORT
    IApServiceCallbacks mApCallback;
#endif
#ifdef FEATURE_P2P_SUPPORT
    IP2pServiceCallbacks mP2pCallback;
    static WifiCfgMonitorEventCallback cfgMonitorCallback;
#endif
    InitStatus mInitStatus;
    long mSupportedFeatures;
    static int mCloseApIndex;
};
} // namespace Wifi
} // namespace OHOS
#endif