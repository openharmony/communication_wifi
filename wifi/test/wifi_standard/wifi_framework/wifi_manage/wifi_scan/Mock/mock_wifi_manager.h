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
#ifndef OHOS_MOCK_WIFI_MANAGER_H
#define OHOS_MOCK_WIFI_MANAGER_H

#include <gmock/gmock.h>
#include "iscan_service_callbacks.h"
#include "wifi_sta_manager.h"
#include "wifi_scan_manager.h"
#include "wifi_toggler_manager.h"
#include "wifi_hotspot_manager.h"
#include "wifi_event_subscriber_manager.h"
#include "wifi_app_state_aware.h"
#include "wifi_multi_vap_manager.h"
#ifdef FEATURE_P2P_SUPPORT
#include "wifi_p2p_manager.h"
#endif
#include "rpt_interface.h"

#define ANY_ID (-1)

namespace OHOS {
namespace Wifi {

enum class WifiCloseServiceCode {
    STA_SERVICE_CLOSE,
    SCAN_SERVICE_CLOSE,
    AP_SERVICE_CLOSE,
    P2P_SERVICE_CLOSE,
    SERVICE_THREAD_EXIT,
    STA_MSG_OPENED,
    STA_MSG_STOPED,
};

class MockWifiManager {
public:
    virtual ~MockWifiManager() = default;
    virtual void DealScanOpenRes(int instId = 0) = 0;
    virtual void DealScanCloseRes(int instId = 0) = 0;
    virtual void DealScanFinished(int state, int instId = 0) = 0;
    virtual void DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId = 0) = 0;
    virtual void DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId = 0) = 0;
    virtual void PushServiceCloseMsg(WifiCloseServiceCode code, int instId = 0);
    virtual void AutoStartEnhanceService(void) = 0;
    virtual int GetSupportedFeatures(long &features) const = 0;
#ifdef FEATURE_HPF_SUPPORT
    virtual void InstallPacketFilterProgram(int event = 0, int instId = 0) = 0;
#endif
};

class WifiManager : public MockWifiManager {
public:
    WifiManager();
    ~WifiManager() = default;
    static WifiManager &GetInstance();
    IScanSerivceCallbacks GetScanCallback();

    MOCK_METHOD1(DealScanOpenRes, void(int));
    MOCK_METHOD1(DealScanCloseRes, void(int));
    MOCK_METHOD2(DealScanFinished, void(int state, int));
    MOCK_METHOD2(DealScanInfoNotify, void(std::vector<InterScanInfo> &results, int));
    MOCK_METHOD2(DealStoreScanInfoEvent, void(std::vector<InterScanInfo> &results, int));
    MOCK_METHOD2(PushServiceCloseMsg, void(WifiCloseServiceCode, int));
    MOCK_METHOD0(AutoStartEnhanceService, void());
    MOCK_CONST_METHOD1(GetSupportedFeatures, int(long&));
#ifdef FEATURE_HPF_SUPPORT
    MOCK_METHOD2(InstallPacketFilterProgram, void(int event, int instId));
#endif
    std::unique_ptr<WifiStaManager>& GetWifiStaManager();
    std::unique_ptr<WifiScanManager>& GetWifiScanManager();
    std::unique_ptr<WifiTogglerManager>& GetWifiTogglerManager();
    std::unique_ptr<WifiHotspotManager>& GetWifiHotspotManager();
    std::shared_ptr<RptInterface> GetRptInterface(int id = ANY_ID);
    std::unique_ptr<WifiEventSubscriberManager>& GetWifiEventSubscriberManager();
    std::unique_ptr<WifiMultiVapManager>& GetWifiMultiVapManager();
#ifdef FEATURE_P2P_SUPPORT
    std::unique_ptr<WifiP2pManager>& GetWifiP2pManager();
#endif
    int Init();
    void Exit();
private:
    IScanSerivceCallbacks mScanCallback;
    void InitScanCallback(void);
    std::unique_ptr<WifiEventHandler> mCloseServiceThread = nullptr;
    std::unique_ptr<WifiEventHandler> mStartServiceThread = nullptr;
    std::unique_ptr<WifiStaManager> wifiStaManager = nullptr;
    std::unique_ptr<WifiScanManager> wifiScanManager = nullptr;
    std::unique_ptr<WifiTogglerManager> wifiTogglerManager = nullptr;
    std::unique_ptr<WifiHotspotManager> wifiHotspotManager = nullptr;
    std::unique_ptr<WifiEventSubscriberManager> wifiEventSubscriberManager = nullptr;
    std::unique_ptr<WifiMultiVapManager> wifiMultiVapManager = nullptr;
#ifdef FEATURE_P2P_SUPPORT
    std::unique_ptr<WifiP2pManager> wifiP2pManager = nullptr;
#endif
};
}  // namespace Wifi
}  // namespace OHOS

#endif