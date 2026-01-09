/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_PERF_5G_HANDOVER_SERVICE_H
#define OHOS_WIFI_PERF_5G_HANDOVER_SERVICE_H
#include "wifi_msg.h"
#include <cstdint>
#include <memory>
#include <vector>
#include "connected_ap.h"
#include "relation_ap.h"
#include "inter_scan_info.h"
#include "wifi_pro_common.h"
#include "wifi_scan_controller.h"
#include "candidate_relation_ap_info.h"
#include "dual_band_repostitory.h"
#include "internal_message.h"
#include "wifi_hisysevent.h"

namespace OHOS {
namespace Wifi {
class Perf5gHandoverService {
public:
    Perf5gHandoverService();
    ~Perf5gHandoverService();
    void OnConnected(WifiLinkedInfo &wifiLinkedInfo);
    void NetworkStatusChanged(NetworkStatus networkStatus);
    std::string Switch5g();
    void ScanResultUpdated(std::vector<InterScanInfo> &scanInfos);
    void HandleSignalInfoChange(InternalMessagePtr msg);
    void QoeUpdate(InternalMessagePtr msg);
    void OnDisconnectedExternal();
    bool HasHiddenNetworkSsid() const;
    void LoadRelationApInfo();
 
public:
    std::shared_ptr<DualBandRepostitory> pDualBandRepostitory_ = nullptr;

private:
    std::mutex mPerf5gMutex;
    std::shared_ptr<ConnectedAp> connectedAp_ = nullptr;
    std::vector<RelationAp> relationAps_;
    std::vector<int32_t> monitorApIndexs_;
    std::shared_ptr<CandidateRelationApInfo> selectRelationAp_ = nullptr;
    std::shared_ptr<WifiScanController> pWifiScanController_ = nullptr;
    std::string bssidLastConnected_;
    std::list<LinkQuality> linkQualityLastConnected_;
    bool inMonitor_ = false;
    Pref5gStatisticsInfo perf5gChrInfo_;
    std::atomic<bool> isNewBssidConnected_ = true;
    const int apMaxNum_ = 20;
    bool lpScanFlag_ = false;
    void UpdateCurrentApInfo(InterScanInfo &wifiScanInfo);
    void UpdateRelationApInfo(std::vector<WifiDeviceConfig> &wifiDeviceConfigs, std::vector<InterScanInfo> &scanInfos);
    void GetCandidateRelationApInfo(std::vector<CandidateRelationApInfo> &candidateRelationApInfos,
        RelationAp &satisfySwitchRssiAp);
    void AddRelationAp(std::vector<WifiDeviceConfig> &wifiDeviceConfigs, std::vector<InterScanInfo> &wifiScanInfos);
    bool IsRelationFreq(int32_t frequency);
    void Monitor5gAp(std::vector<InterScanInfo> &wifiScanInfos);
    void ClearDeletedRelationAp(std::vector<WifiDeviceConfig> &wifiDeviceConfigs);
    void StartMonitor();
    void StopMonitor();
    void ActiveScan(int32_t rssi, int scanStyle = SCAN_DEFAULT_TYPE);
    void AddRelationApInfo(RelationAp &relationAp);
    void FoundMonitorAp(int32_t relationApIndex, std::vector<InterScanInfo> &wifiScanInfos);
    void UnloadScanController();
    void LoadHasInternetScanController();
    void LoadMonitorScanController();
    std::string HandleSwitchResult(WifiLinkedInfo &wifiLinkedInfo);
    void UpdateTriggerScanRssiThreshold();
    void RssiUpdate(int32_t rssi);
    void GetNoExistRelationInfo(std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
        std::vector<InterScanInfo> &wifiScanInfos, std::unordered_set<std::string> &noExistRelationBssidSet,
        std::vector<RelationAp> &sameSsidAps, std::unordered_set<std::string> &existRelationBssidSet);
    void PrintRelationAps();
    void InitConnectedAp(WifiLinkedInfo &wifiLinkedInfo, WifiDeviceConfig &wifiDeviceConfig);
    void HandleSwitchFailed(Perf5gSwitchResult switchResult);
    void OnDisconnected();
    void RemoveRelationApDuplicates(std::vector<RelationAp> &relationAps);
    bool IsValidAp(int32_t relationApIndex);
};
}
}
#endif

