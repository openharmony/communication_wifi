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
#include <sys/stat.h>
#include <fcntl.h>
#include "define.h"
#include "wifi_internal_msg.h"
#include "wifi_errcode.h"
#include "wifi_sta_manager.h"
#include "wifi_scan_manager.h"
#include "wifi_toggler_manager.h"
#include "wifi_event_handler.h"
#ifdef FEATURE_AP_SUPPORT
#include "wifi_hotspot_manager.h"
#endif
#ifdef FEATURE_P2P_SUPPORT
#include "wifi_p2p_manager.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "wifi_event_subscriber_manager.h"
#include "wifi_app_state_aware.h"
#include "wifi_multi_vap_manager.h"
#endif
#include "rpt_interface.h"

#define ANY_ID (-1)

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
    STA_MSG_OPENED,
    STA_MSG_STOPED,
    STA_CLOSE_DHCP_SA,
    AP_CLOSE_DHCP_SA,
};

struct WifiCloseServiceMsg {
    WifiCloseServiceCode code;
    int instId;
};

constexpr uint32_t PROP_SUPPORT_SAPCOEXIST_LEN = 10;
const std::string SUPPORT_SAPCOEXIST_PROP = "const.wifi.support_sapcoexist";
const std::string SUPPORT_SAPCOEXIST = "true";
constexpr uint32_t SUPPORT_SAPCOEXIST_LEN = 7;

const int CAC_STOP_BY_DEFAULT_REASON = 0;
const int CAC_STOP_BY_SCAN_REQUEST = 1;
const int CAC_STOP_BY_RADAR_DETECT = 2;
const int CAC_STOP_BY_P2P_REQUEST = 3;
const int CAC_STOP_BY_HID2D_REQUEST = 4;
const int CAC_STOP_BY_AP_REQUEST = 5;
const int CAC_STOP_BY_HML_REQUEST = 6;
const int CAC_STOP_BY_STA_REQUEST = 7;
const int CAC_STOP_BY_BRIDGE_REQUEST = 8;
const int CAC_STOP_BY_WIFI2_REQUEST = 9;
const int CAC_STOP_BY_SCREEN_OFF = 10;
const int CAC_STOP_BY_SHARE_REQUEST = 11;
const int CAC_STOP_BY_SETTING_ON = 12;

class WifiManager {
public:
    static WifiManager &GetInstance();
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
    void PushServiceCloseMsg(WifiCloseServiceCode code, int instId = 0);
    void AutoStartEnhanceService(void);
    std::unique_ptr<WifiStaManager>& GetWifiStaManager();
    std::unique_ptr<WifiScanManager>& GetWifiScanManager();
    std::unique_ptr<WifiTogglerManager>& GetWifiTogglerManager();
    std::shared_ptr<RptInterface> GetRptInterface(int id = ANY_ID);
#ifdef FEATURE_AP_SUPPORT
    std::unique_ptr<WifiHotspotManager>& GetWifiHotspotManager();
#endif
#ifdef FEATURE_P2P_SUPPORT
    std::unique_ptr<WifiP2pManager>& GetWifiP2pManager();
#endif
#ifndef OHOS_ARCH_LITE
    std::unique_ptr<WifiEventSubscriberManager>& GetWifiEventSubscriberManager();
    std::unique_ptr<WifiMultiVapManager>& GetWifiMultiVapManager();
#endif
#ifdef FEATURE_HPF_SUPPORT
    void InstallPacketFilterProgram(int screenState, int instId);
#endif
    void OnNativeProcessStatusChange(int status);
    void StopGetCacResultAndLocalCac(int reason);

private:
    WifiManager();
    void DealCloseServiceMsg();
    void CheckAndStartSta();
    void AutoStartServiceThread();
    void InitPidfile(void);
    void CheckSapcoExist(void);
    void ProcessExtMsg(WifiCloseServiceCode code);
private:
    std::mutex initStatusMutex;
    InitStatus mInitStatus;
    long mSupportedFeatures;
    bool g_supportsapcoexistflag;
    std::unique_ptr<WifiEventHandler> mCloseServiceThread = nullptr;
    std::unique_ptr<WifiEventHandler> mStartServiceThread = nullptr;
    std::unique_ptr<WifiStaManager> wifiStaManager = nullptr;
    std::unique_ptr<WifiScanManager> wifiScanManager = nullptr;
    std::unique_ptr<WifiTogglerManager> wifiTogglerManager = nullptr;
#ifdef FEATURE_AP_SUPPORT
    std::unique_ptr<WifiHotspotManager> wifiHotspotManager = nullptr;
#endif
#ifdef FEATURE_P2P_SUPPORT
    std::unique_ptr<WifiP2pManager> wifiP2pManager = nullptr;
#endif
#ifndef OHOS_ARCH_LITE
    std::unique_ptr<WifiEventSubscriberManager> wifiEventSubscriberManager = nullptr;
    std::unique_ptr<WifiMultiVapManager> wifiMultiVapManager = nullptr;
#endif
};
} // namespace Wifi
} // namespace OHOS
#endif