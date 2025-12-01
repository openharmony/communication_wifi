/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "perf_5g_handover_service.h"
#include "dual_band_rdb_helper.h"
#include "wifi_settings.h"
#include "wifi_msg.h"
#include "network_status_history_manager.h"
#include "wifi_logger.h"
#include "dual_band_selector.h"
#include "ista_service.h"
#include "dual_band_utils.h"
#include "wifi_pro_common.h"
#include "wifi_service_manager.h"
#include "ienhance_service.h"
#include "dual_band_learning_alg_service.h"
#include "wifi_pro_utils.h"
#include "network_black_list_manager.h"
#include "wifi_common_util.h"
#include "wifi_global_func.h"
#include "wifi_config_center.h"
#include "wifi_chr_adapter.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("Perf5gHandoverService");
constexpr int32_t BLOCK5G_RELEASE_THRESHOLD = -60;
Perf5gHandoverService::Perf5gHandoverService()
{
    pDualBandRepostitory_ = std::make_shared<DualBandRepostitory>(
        std::dynamic_pointer_cast<IDualBandDataSource>(std::make_shared<DualBandRdbHelper>()));
}
Perf5gHandoverService::~Perf5gHandoverService()
{}
void Perf5gHandoverService::OnConnected(WifiLinkedInfo &wifiLinkedInfo)
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    std::string strategyName = HandleSwitchResult(wifiLinkedInfo);
    bool is5gAfterPerf = (strategyName != "");
    if (connectedAp_ != nullptr && connectedAp_->wifiLinkType == wifiLinkedInfo.wifiLinkType) {
        if (connectedAp_->apInfo.bssid == wifiLinkedInfo.bssid) {
            return;
        }
        WIFI_LOGI("OnConnected, connected ap is switched");
        OnDisconnected();
    }
    WifiDeviceConfig wifiDeviceConfig;
    WifiSettings::GetInstance().GetDeviceConfig(wifiLinkedInfo.networkId, wifiDeviceConfig);
    InitConnectedAp(wifiLinkedInfo, wifiDeviceConfig);
    connectedAp_->is5gAfterPerf = is5gAfterPerf;
    connectedAp_->perf5gStrategyName = strategyName;
    bool isItCustNetwork = false;
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService != nullptr) {
        isItCustNetwork = pEnhanceService->IsItCustNetwork(wifiDeviceConfig);
    }
    bool isEnterprise = DualBandUtils::IsEnterprise(wifiDeviceConfig);
    connectedAp_->canNotPerf = isEnterprise || wifiLinkedInfo.isDataRestricted || isItCustNetwork ||
        wifiDeviceConfig.keyMgmt == KEY_MGMT_NONE || connectedAp_->wifiLinkType == WifiLinkType::WIFI7_EMLSR;
    WIFI_LOGI("OnConnected, canNotPerf:isEnterprise(%{public}d),isItCustNetwork(%{public}d),isPortal(%{public}d),"
        "isDataRestricted(%{public}d),openNet(%{public}d), isEMLSR(%{public}d)", isEnterprise, isItCustNetwork,
        wifiDeviceConfig.isPortal, wifiLinkedInfo.isDataRestricted, wifiDeviceConfig.keyMgmt == KEY_MGMT_NONE,
        connectedAp_->wifiLinkType == WifiLinkType::WIFI7_EMLSR);
    if (connectedAp_->canNotPerf) {
        WIFI_LOGI("OnConnected, ap is not allow perf 5g");
        return;
    }
    if (isNewBssidConnected_.load()) {
        ApConnectionInfo apConnectionInfo(wifiLinkedInfo.bssid);
        apConnectionInfo.SetConnectedTime(std::chrono::steady_clock::now());
        connectedAp_->apInfo.apConnectionInfo = apConnectionInfo;
        pDualBandRepostitory_->LoadApHistoryInfo(connectedAp_->apInfo, connectedAp_->hasHistoryInfo);
        connectedAp_->canNotPerf = wifiDeviceConfig.isPortal && !connectedAp_->hasHistoryInfo;
        if (connectedAp_->canNotPerf) {
            WIFI_LOGI("OnConnected, ap is not history record,not allow pref");
            isNewBssidConnected_.store(false);
            return;
        }
        LoadRelationApInfo();
        perf5gChrInfo_.Reset();
        perf5gChrInfo_.connectTime = std::chrono::steady_clock::now();
        isNewBssidConnected_.store(false);
    }
    PrintRelationAps();
}

// Encapsulate the function into external and internal types.
void Perf5gHandoverService::OnDisconnectedExternal()
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    OnDisconnected();
}

void Perf5gHandoverService::InitConnectedAp(WifiLinkedInfo &wifiLinkedInfo, WifiDeviceConfig &wifiDeviceConfig)
{
    if (connectedAp_ == nullptr) {
        connectedAp_ = std::make_shared<ConnectedAp>();
    }
    ApInfo apInfo(wifiLinkedInfo.networkId, wifiLinkedInfo.ssid, wifiLinkedInfo.bssid,
        wifiDeviceConfig.keyMgmt, wifiLinkedInfo.frequency);
    connectedAp_->apInfo = apInfo;
    connectedAp_->isMloConnected = wifiLinkedInfo.isMloConnected;
    connectedAp_->wifiLinkType = wifiLinkedInfo.wifiLinkType;
}

void Perf5gHandoverService::OnDisconnected()
{
    isNewBssidConnected_.store(true);
    if (connectedAp_ == nullptr) {
        return;
    }
    UnloadScanController();
    if (connectedAp_->canNotPerf) {
        connectedAp_.reset();
        relationAps_.clear();
        return;
    }
    perf5gChrInfo_.bssid = MacAnonymize(connectedAp_->apInfo.bssid).data();
    perf5gChrInfo_.ssid = SsidAnonymize(connectedAp_->apInfo.ssid).data();
    perf5gChrInfo_.freq = connectedAp_->apInfo.frequency;
    if (selectRelationAp_ != nullptr) {
        perf5gChrInfo_.has5gPrefSwitch = true;
    }
    for (auto &relationAp : relationAps_) {
        if (!relationAp.relationInfo_.IsAdjacent()) {
            perf5gChrInfo_.notAdj5gNum++;
        }
    }
    EnhanceWrite5gPrefFailedHisysevent(perf5gChrInfo_);
    perf5gChrInfo_.Reset();
    bssidLastConnected_ = connectedAp_->apInfo.bssid;
    linkQualityLastConnected_ = connectedAp_->apInfo.apConnectionInfo.GetLinkQualitys();
    if (pDualBandRepostitory_ != nullptr) {
        pDualBandRepostitory_->SaveApInfo(connectedAp_->apInfo);
        pDualBandRepostitory_->SaveRelationApInfo(relationAps_);
    }
    StopMonitor();
    WIFI_LOGI("OnDisconnected, ssid(%{public}s),bssid(%{public}s),frequency(%{public}d)",
        SsidAnonymize(connectedAp_->apInfo.ssid).data(), MacAnonymize(connectedAp_->apInfo.bssid).data(),
        connectedAp_->apInfo.frequency);
    if (connectedAp_ != nullptr) {
        connectedAp_.reset();
    }
    relationAps_.clear();
}
void Perf5gHandoverService::NetworkStatusChanged(NetworkStatus networkStatus)
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    if (connectedAp_ == nullptr) {
        return;
    }
    connectedAp_->apInfo.networkStatus = networkStatus;
    if (connectedAp_->canNotPerf) {
        return;
    }
    if (networkStatus == NetworkStatus::HAS_INTERNET) {
        if (pWifiScanController_ == nullptr) {
            WIFI_LOGI("%{public}s, has internet, do load scan controller", __FUNCTION__);
            if (perf5gChrInfo_.noInternetTime != std::chrono::steady_clock::time_point::min()) {
                perf5gChrInfo_.durationNoInternet +=
                    duration_cast<seconds>(std::chrono::steady_clock::now() - perf5gChrInfo_.noInternetTime).count();
                perf5gChrInfo_.noInternetTime = std::chrono::steady_clock::time_point::min();
            }
            LoadHasInternetScanController();
        }
    } else {
        WIFI_LOGI("%{public}s, not has internet, do unload scan controller", __FUNCTION__);
        perf5gChrInfo_.noInternetTime = std::chrono::steady_clock::now();
        UnloadScanController();
    }
}
std::string Perf5gHandoverService::Switch5g()
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    if (selectRelationAp_ == nullptr || connectedAp_ == nullptr) {
        return "";
    }
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService != nullptr && pEnhanceService->GetLimitSwitchScenes() == LimitSwitchScenes::DUAL_BAND_ROAM) {
        WIFI_LOGE("Switch5g: fail, dual band roam is enable");
        selectRelationAp_.reset();
        return "";
    }
    WifiLinkedInfo linkedInfoWlan1;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfoWlan1, 1);
    if (linkedInfoWlan1.networkId != INVALID_NETWORK_ID && selectRelationAp_->apInfo.bssid == linkedInfoWlan1.bssid) {
        WIFI_LOGI("Switch5g : TarAp is wlan1.");
        selectRelationAp_.reset();
        return "";
    }
    IStaService *pStaService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pStaService == nullptr) {
        WIFI_LOGE("Switch5g: pStaService is invalid");
        selectRelationAp_.reset();
        return "";
    }
    int32_t ret;
    WIFI_LOGI("Switch5g StartConnectToBssid. bssid(%{public}s)", MacAnonymize(selectRelationAp_->apInfo.bssid).data());
    ret = pStaService->StartConnectToBssid(
        selectRelationAp_->apInfo.networkId, selectRelationAp_->apInfo.bssid, NETWORK_SELECTED_BY_WIFIPRO);
    if (ret == WIFI_OPT_SUCCESS) {
        return selectRelationAp_->apInfo.bssid;
    }
    WIFI_LOGW("Switch5g, StartConnectToBssid fail, ret = %{public}d", ret);
    selectRelationAp_.reset();
    return "";
}
void Perf5gHandoverService::ScanResultUpdated(std::vector<InterScanInfo> &scanInfos)
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    if (connectedAp_ == nullptr || connectedAp_->canNotPerf) {
        return;
    }
    InterScanInfo *currentApScanResult = nullptr;
    for (auto &wifiScanInfo : scanInfos) {
        if (wifiScanInfo.bssid == connectedAp_->apInfo.bssid) {
            currentApScanResult = &wifiScanInfo;
        }
        if (wifiScanInfo.rssi >= BLOCK5G_RELEASE_THRESHOLD &&
            NetworkBlockListManager::GetInstance().IsInPerf5gBlocklist(wifiScanInfo.bssid)) {
            WIFI_LOGI("Perf5gBlocklist, rssi:%{public}d remove", wifiScanInfo.rssi);
            NetworkBlockListManager::GetInstance().RemovePerf5gBlocklist(wifiScanInfo.bssid);
        }
    }
    if (currentApScanResult == nullptr) {
        WIFI_LOGI("ScanResultUpdated, not found scan result of current ap");
        return;
    }
    UpdateCurrentApInfo(*currentApScanResult);
    std::vector<WifiDeviceConfig> wifiDeviceConfigs;
    WifiSettings::GetInstance().GetDeviceConfig(wifiDeviceConfigs);
    if (wifiDeviceConfigs.empty()) {
        WIFI_LOGI("ScanResultUpdated, not found wifiDeviceConfigs");
        return;
    }
    UpdateRelationApInfo(wifiDeviceConfigs, scanInfos);
    if (IsValid5GHz(connectedAp_->apInfo.frequency)) {
        return;
    }
    Monitor5gAp(scanInfos);
}
void Perf5gHandoverService::HandleSignalInfoChange(InternalMessagePtr msg)
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    if (msg == nullptr) {
        WIFI_LOGI("HandleSignalInfoChange, msg is nullptr");
        return;
    }
    if (connectedAp_ == nullptr || connectedAp_->canNotPerf) {
        return;
    }
    WifiSignalPollInfo wifiSignalPollInfo;
    msg->GetMessageObj(wifiSignalPollInfo);
    if (wifiSignalPollInfo.signal == 0) {
        WIFI_LOGI("HandleSignalInfoChange, msg is nullptr");
        return;
    }
    RssiUpdate(wifiSignalPollInfo.signal);
    LinkQuality linkQuality;
    linkQuality.signal = wifiSignalPollInfo.signal;
    linkQuality.txrate = wifiSignalPollInfo.txrate;
    linkQuality.rxrate = wifiSignalPollInfo.rxrate;
    linkQuality.txBytes = wifiSignalPollInfo.txBytes;
    linkQuality.rxBytes = wifiSignalPollInfo.rxBytes;
    connectedAp_->apInfo.apConnectionInfo.HandleLinkQuality(linkQuality, connectedAp_->is5gAfterPerf,
        IsValid5GHz(connectedAp_->apInfo.frequency));
    if (linkQualityLastConnected_.empty() || bssidLastConnected_.empty() || !connectedAp_->is5gAfterPerf) {
        return;
    }
    if (connectedAp_->perf5gStrategyName != SelectStrategyName::LEARNING_ALG
        || !connectedAp_->apInfo.apConnectionInfo.IsFullLinkQuality()) {
        return;
    }
    for (auto &relationAp : relationAps_) {
        if (relationAp.apInfo_.bssid == bssidLastConnected_) {
            WIFI_LOGI("HandleSignalInfoChange, UpdateMeanPvalue before %{public}s",
                relationAp.relationInfo_.meanP_.data());
            DualBandLearningAlgService::UpdateMeanPValue(linkQualityLastConnected_,
                connectedAp_->apInfo.apConnectionInfo.GetLinkQualitys(),
                connectedAp_->apInfo.rssi, relationAp.relationInfo_.meanP_);
            WIFI_LOGI("HandleSignalInfoChange, UpdateMeanPvalue after %{public}s",
                relationAp.relationInfo_.meanP_.data());
            linkQualityLastConnected_.clear();
        }
    }
}
void Perf5gHandoverService::QoeUpdate(InternalMessagePtr msg)
{
    std::unique_lock<std::mutex> lock(mPerf5gMutex);
    if (msg == nullptr) {
        WIFI_LOGI("QoeUpdate, msg is nullptr");
        return;
    }
    if (connectedAp_ == nullptr || connectedAp_->canNotPerf) {
        return;
    }
    NetworkLagInfo networkLagInfo;
    msg->GetMessageObj(networkLagInfo);
    if (networkLagInfo.rssi == 0) {
        WIFI_LOGI("QoeUpdate, rssi is invalid");
        return;
    }
    connectedAp_->apInfo.apConnectionInfo.HandleRtt(networkLagInfo.rssi, networkLagInfo.tcpRtt, 1);
}
void Perf5gHandoverService::HandleSwitchFailed(Perf5gSwitchResult switchResult)
{
    switch (switchResult) {
        case Perf5gSwitchResult::TIMEOUT:
            WIFI_LOGE("HandleSwitchFailed, switch 5g timeout");
            break;
        case Perf5gSwitchResult::NO_PERF_5G_AP:
            WIFI_LOGE("HandleSwitchFailed, no perf 5g ap is connected");
            break;
        default:
            break;
    }
}
void Perf5gHandoverService::UpdateCurrentApInfo(InterScanInfo &wifiScanInfo)
{
    connectedAp_->apInfo.rssi = wifiScanInfo.rssi;
    connectedAp_->apInfo.channelWidth = wifiScanInfo.channelWidth;
    connectedAp_->apInfo.wifiCategory = wifiScanInfo.supportedWifiCategory;
    connectedAp_->apInfo.frequency = wifiScanInfo.frequency;
}
void Perf5gHandoverService::UpdateRelationApInfo(std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
    std::vector<InterScanInfo> &scanInfos)
{
    ClearDeletedRelationAp(wifiDeviceConfigs);
    AddRelationAp(wifiDeviceConfigs, scanInfos);
    for (auto &relationAp : relationAps_) {
        InterScanInfo *relationApScanInfo = nullptr;
        for (auto &wifiScanInfo : scanInfos) {
            if (wifiScanInfo.bssid == relationAp.apInfo_.bssid) {
                relationApScanInfo = &wifiScanInfo;
                break;
            }
        }
        if (relationApScanInfo == nullptr) {
            continue;
        }
        relationAp.UpdateInfo(*relationApScanInfo, connectedAp_->apInfo.rssi);
        for (auto &deviceConfig : wifiDeviceConfigs) {
            if (deviceConfig.ssid == relationAp.apInfo_.ssid && deviceConfig.keyMgmt == relationAp.apInfo_.keyMgmt) {
                relationAp.apInfo_.networkId = deviceConfig.networkId;
            }
        }
    }
}
void Perf5gHandoverService::GetCandidateRelationApInfo(std::vector<CandidateRelationApInfo> &candidateRelationApInfos,
    RelationAp &satisfySwitchRssiAp)
{
    CandidateRelationApInfo candidateRelationApInfo;
    candidateRelationApInfo.apInfo = satisfySwitchRssiAp.apInfo_;
    candidateRelationApInfo.meanP = satisfySwitchRssiAp.relationInfo_.meanP_;
    candidateRelationApInfos.push_back(candidateRelationApInfo);
}
void Perf5gHandoverService::AddRelationAp(std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
    std::vector<InterScanInfo> &wifiScanInfos)
{
    std::unordered_set<std::string> existRelationBssidSet;
    for (auto &relationAp : relationAps_) {
        existRelationBssidSet.insert(relationAp.apInfo_.bssid);
    }
    existRelationBssidSet.insert(connectedAp_->apInfo.bssid);
    std::unordered_set<std::string> noExistRelationBssidSet;
    std::vector<RelationAp> sameSsidAps;
    GetNoExistRelationInfo(wifiDeviceConfigs, wifiScanInfos, noExistRelationBssidSet, sameSsidAps,
        existRelationBssidSet);
    if (noExistRelationBssidSet.empty()) {
        WIFI_LOGD("AddRelationAp, not found new relation ap");
        return;
    }
    std::vector<RelationAp> relationApInfos;
    if (pDualBandRepostitory_ != nullptr) {
        relationApInfos = pDualBandRepostitory_->QueryRelationApInfos(noExistRelationBssidSet);
    }
    for (auto &relationApInfo : relationApInfos) {
        AddRelationApInfo(relationApInfo);
        if (sameSsidAps.empty()) {
            continue;
        }
        for (auto it = sameSsidAps.begin(); it != sameSsidAps.end(); it++) {
            RelationAp sameSsidAp = *it;
            if (relationApInfo.apInfo_.bssid == sameSsidAp.apInfo_.bssid) {
                sameSsidAps.erase(it);
                break;
            }
        }
    }
    for (auto &sameSsidAp : sameSsidAps) {
        AddRelationApInfo(sameSsidAp);
    }
}
bool Perf5gHandoverService::IsRelationFreq(int32_t frequency)
{
    if (IsValid5GHz(connectedAp_->apInfo.frequency)) {
        return IsValid24GHz(frequency);
    } else {
        return IsValid5GHz(frequency);
    }
}
void Perf5gHandoverService::Monitor5gAp(std::vector<InterScanInfo> &wifiScanInfos)
{
    perf5gChrInfo_.isIn5gPref = true;
    if (WifiProUtils::IsUserSelectNetwork()) {
        WIFI_LOGI("Monitor5gAp, IsUserSelectNetwork, can not monitor");
        perf5gChrInfo_.isUserConnected = true;
        return;
    }
    int32_t relationApSize = static_cast<int32_t>(relationAps_.size());
    perf5gChrInfo_.rela5gNum = relationApSize;
    perf5gChrInfo_.inBlackListNum = 0;
    perf5gChrInfo_.notInternetRela5gNum = 0;
    for (int32_t index = 0; index < relationApSize; index++) {
        FoundMonitorAp(index, wifiScanInfos);
    }
    if (relationApSize == perf5gChrInfo_.inBlackListNum + perf5gChrInfo_.notInternetRela5gNum) {
        perf5gChrInfo_.allRela5gInBlockListNum++;
    }
    if (monitorApIndexs_.empty()) {
        return;
    }
    StartMonitor();
    std::vector<CandidateRelationApInfo> candidateRelationApInfos;
    for (auto &monitorApIndex : monitorApIndexs_) {
        if (relationAps_[monitorApIndex].IsSatisfySwitchRssi()) {
            GetCandidateRelationApInfo(candidateRelationApInfos, relationAps_[monitorApIndex]);
        }
    }
    if (!candidateRelationApInfos.empty()) {
        selectRelationAp_ = DualBandSelector::Select(connectedAp_->apInfo, candidateRelationApInfos);
        if (selectRelationAp_ == nullptr) {
            perf5gChrInfo_.satisfySwitchRssiNoSelectedNum++;
        }
    }
    UpdateTriggerScanRssiThreshold();
    if (selectRelationAp_ != nullptr) {
        WIFI_LOGI("Monitor5gAp, is selected 5g");
        for (auto &relationAp : relationAps_) {
            if (relationAp.apInfo_.bssid == selectRelationAp_->apInfo.bssid) {
                relationAp.IsSelectedSwitch();
                break;
            }
        }
        StopMonitor();
        return;
    }
    if (pWifiScanController_ != nullptr && pWifiScanController_->IsActiveScansExhausted()) {
        WIFI_LOGI("Monitor5gAp, is active scans exhausted, stop monitor");
        StopMonitor();
    }
}
void Perf5gHandoverService::ClearDeletedRelationAp(std::vector<WifiDeviceConfig> &wifiDeviceConfigs)
{
    std::unordered_set<std::string> deletedBssids;
    int32_t relationApSize = static_cast<int32_t>(relationAps_.size());
    std::vector<RelationAp> relationApsAfterDel;
    for (int32_t index = 0; index < relationApSize; index++) {
        bool isDeletd = true;
        for (auto &wifiDeviceConfig : wifiDeviceConfigs) {
            if (wifiDeviceConfig.ssid == relationAps_[index].apInfo_.ssid &&
                wifiDeviceConfig.keyMgmt == relationAps_[index].apInfo_.keyMgmt) {
                isDeletd = false;
                break;
            }
        }
        if (!isDeletd) {
            relationApsAfterDel.push_back(relationAps_[index]);
            continue;
        }
        deletedBssids.insert(relationAps_[index].apInfo_.bssid);
        for (auto it = monitorApIndexs_.begin(); it != monitorApIndexs_.end();) {
            if (*it == index) {
                monitorApIndexs_.erase(it);
            } else {
                it++;
            }
        }
    }
    if (!deletedBssids.empty() && pDualBandRepostitory_ != nullptr) {
        pDualBandRepostitory_->DeleteAll(deletedBssids);
        relationAps_ = relationApsAfterDel;
    }
}
void Perf5gHandoverService::StartMonitor()
{
    if (!inMonitor_) {
        perf5gChrInfo_.enterMonitorNum++;
        WIFI_LOGI("StartMonitor, load scan controller");
        inMonitor_ = true;
        LoadMonitorScanController();
    }
}
void Perf5gHandoverService::StopMonitor()
{
    if (inMonitor_) {
        WIFI_LOGI("StopMonitor, unload scan controller");
        inMonitor_ = false;
        UnloadScanController();
        monitorApIndexs_.clear();
    }
}
void Perf5gHandoverService::ActiveScan(int32_t rssi, int scanStyle)
{
    WIFI_LOGI("Enter ActiveScan, rssi: %{public}d, scanStyle: %{public}d", rssi, scanStyle);
    if (pWifiScanController_ == nullptr) {
        return;
    }
    bool needScanInMonitor = false;
    std::unordered_set<int32_t> monitorFreqs;
    for (auto &monitorApIndex : monitorApIndexs_) {
        monitorFreqs.insert(relationAps_[monitorApIndex].apInfo_.frequency);
        if (!needScanInMonitor && relationAps_[monitorApIndex].CanTriggerScan(rssi)) {
            needScanInMonitor = true;
        }
    }
    if (pWifiScanController_->TryToScan(rssi, needScanInMonitor, connectedAp_->apInfo.frequency,
        monitorFreqs, scanStyle) && inMonitor_) {
        perf5gChrInfo_.monitorActiveScanNum++;
    }
}
void Perf5gHandoverService::AddRelationApInfo(RelationAp &relationAp)
{
    if (IsValid5GHz(connectedAp_->apInfo.frequency)) {
        RelationInfo relation(relationAp.apInfo_.bssid, connectedAp_->apInfo.bssid);
        relationAp.relationInfo_ = relation;
        relationAps_.push_back(relationAp);
        WIFI_LOGI("AddRelationApInfo, relation 2.4g ap(%{public}s) is added",
            MacAnonymize(relationAp.apInfo_.bssid).data());
    } else {
        RelationInfo relation(connectedAp_->apInfo.bssid, relationAp.apInfo_.bssid);
        relationAp.relationInfo_ = relation;
        relationAps_.push_back(relationAp);
        WIFI_LOGI("AddRelationApInfo, relation 5g ap(%{public}s) is added",
            MacAnonymize(relationAp.apInfo_.bssid).data());
    }
}
void Perf5gHandoverService::FoundMonitorAp(int32_t relationApIndex, std::vector<InterScanInfo> &wifiScanInfos)
{
    if (NetworkBlockListManager::GetInstance().IsInWifiBlocklist(relationAps_[relationApIndex].apInfo_.bssid) ||
        NetworkBlockListManager::GetInstance().IsInAbnormalWifiBlocklist(relationAps_[relationApIndex].apInfo_.bssid) ||
        NetworkBlockListManager::GetInstance().IsInPerf5gBlocklist(relationAps_[relationApIndex].apInfo_.bssid)) {
        WIFI_LOGI("FoundMonitorAp, relation ap(%{public}s) in block list, can not monitor",
            MacAnonymize(relationAps_[relationApIndex].apInfo_.bssid).data());
        perf5gChrInfo_.inBlackListNum++;
        return;
    }
    if (!IsValidAp(relationApIndex)) {
        return;
    }
    for (const auto &wifiScanInfo : wifiScanInfos) {
        std::string scanKeyMgmt = "";
        wifiScanInfo.GetDeviceMgmt(scanKeyMgmt);
        if (!(wifiScanInfo.bssid == relationAps_[relationApIndex].apInfo_.bssid &&
                WifiConfigCenter::GetInstance().IsSameKeyMgmt(
                    scanKeyMgmt, relationAps_[relationApIndex].apInfo_.keyMgmt))) {
            continue;
        }
        bool hasMonitor = false;
        for (auto &monitorApIndex : monitorApIndexs_) {
            if (wifiScanInfo.bssid != relationAps_[monitorApIndex].apInfo_.bssid) {
                continue;
            }
            hasMonitor = true;
        }
        if (!hasMonitor) {
            WIFI_LOGI(
                "FoundMonitorAp, bssid %{public}s", MacAnonymize(relationAps_[relationApIndex].apInfo_.bssid).data());
            relationAps_[relationApIndex].InitMonitorInfo();
            monitorApIndexs_.push_back(relationApIndex);
        }
    }
}

bool Perf5gHandoverService::IsValidAp(int32_t relationApIndex)
{
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(relationAps_[relationApIndex].apInfo_.networkId, config);
    if (!config.isAllowAutoConnect) {
        WIFI_LOGI("FoundMonitorAp, ssid:%{public}s not allow autoconnect",
            SsidAnonymize(relationAps_[relationApIndex].apInfo_.ssid).data());
        return false;
    }
    if (!config.isSecureWifi) {
        WIFI_LOGI("FoundMonitorAp, ssid:%{public}s insecure network",
            SsidAnonymize(relationAps_[relationApIndex].apInfo_.ssid).data());
        return false;
    }
    // Check if network is currently disabled (by DisableDeviceConfig)
    if (config.networkSelectionStatus.status != WifiDeviceConfigStatus::ENABLED) {
        WIFI_LOGI("FoundMonitorAp, ssid:%{public}s is disabled, cannot perform 5G handover",
            SsidAnonymize(relationAps_[relationApIndex].apInfo_.ssid).data());
        return false;
    }
    if (relationAps_[relationApIndex].apInfo_.networkStatus != NetworkStatus::HAS_INTERNET) {
        WIFI_LOGI("FoundMonitorAp, no internet(%{public}d), can not monitor",
            relationAps_[relationApIndex].apInfo_.networkStatus);
        perf5gChrInfo_.notInternetRela5gNum++;
        return false;
    }
    return true;
}

void Perf5gHandoverService::UnloadScanController()
{
    if (pWifiScanController_ != nullptr) {
        pWifiScanController_.reset();
    }
}
void Perf5gHandoverService::LoadHasInternetScanController()
{
    UnloadScanController();
    std::vector<std::shared_ptr<IDualBandScanStrategy>> dualBandScanStrategys;
    dualBandScanStrategys.push_back(
        std::dynamic_pointer_cast<IDualBandScanStrategy>(std::make_shared<StrongRssiScanStrategy>()));
    pWifiScanController_ = std::make_shared<WifiScanController>(dualBandScanStrategys);
}
void Perf5gHandoverService::LoadMonitorScanController()
{
    UnloadScanController();
    std::vector<std::shared_ptr<IDualBandScanStrategy>> dualBandScanStrategys;
    dualBandScanStrategys.push_back(
        std::dynamic_pointer_cast<IDualBandScanStrategy>(std::make_shared<StrongRssiScanStrategy>()));
    dualBandScanStrategys.push_back(
        std::dynamic_pointer_cast<IDualBandScanStrategy>(std::make_shared<PeriodicScanStrategy>()));
    pWifiScanController_ = std::make_shared<WifiScanController>(dualBandScanStrategys);
}
std::string Perf5gHandoverService::HandleSwitchResult(WifiLinkedInfo &wifiLinkedInfo)
{
    if (connectedAp_ != nullptr && connectedAp_->wifiLinkType == wifiLinkedInfo.wifiLinkType &&
        connectedAp_->apInfo.bssid == wifiLinkedInfo.bssid) {
        WIFI_LOGI("HandleSwitchResult, duplicate message");
        return "";
    }
    if (selectRelationAp_ == nullptr) {
        if (connectedAp_ != nullptr && connectedAp_->apInfo.bssid == wifiLinkedInfo.bssid) {
            WIFI_LOGI("HandleSwitchResult, ignore duplicate connect message");
            return "";
        }
        bssidLastConnected_ = "";
        linkQualityLastConnected_.clear();
        WIFI_LOGI("HandleSwitchResult, selectRelationAp_ is nullptr, clear ap info before switched");
        return "";
    }
    perf5gChrInfo_.has5gPrefSwitch = true;
    std::string selectStrategyName = "";
    if (wifiLinkedInfo.bssid == selectRelationAp_->apInfo.bssid) {
        WIFI_LOGI("HandleSwitchResult, perf 5g successful");
        selectStrategyName = selectRelationAp_->selectStrategyName;
    } else {
        WIFI_LOGW("HandleSwitchResult, perf 5g failed");
        HandleSwitchFailed(Perf5gSwitchResult::NO_PERF_5G_AP);
    }
    selectRelationAp_.reset();
    return selectStrategyName;
}
void Perf5gHandoverService::UpdateTriggerScanRssiThreshold()
{
    if (pWifiScanController_ == nullptr || connectedAp_ == nullptr) {
        WIFI_LOGE("UpdateTriggerScanRssiThreshold, pWifiScanController_ or connectedAp_ is nullptr");
        return;
    }
    if (pWifiScanController_->IsFastScan()) {
        return;
    }
    for (auto &monitorApIndex : monitorApIndexs_) {
        if (relationAps_[monitorApIndex].relationInfo_.IsOnSameRouter() ||
            !relationAps_[monitorApIndex].IsSatisfySwitchRssi()) {
            relationAps_[monitorApIndex].UpdateTriggerScanRssiThreshold(connectedAp_->apInfo.rssi);
        }
    }
}
void Perf5gHandoverService::RssiUpdate(int32_t rssi)
{
    if (connectedAp_->canNotPerf) {
        return;
    }
    int scanStyle = WifiConfigCenter::GetInstance().GetLpScanAbility() && !HasHiddenNetworkSsid() ?
        SCAN_TYPE_LOW_PRIORITY : SCAN_DEFAULT_TYPE;
    ActiveScan(rssi, scanStyle);
}
bool Perf5gHandoverService::HasHiddenNetworkSsid()
{
    for (auto &ap : relationAps_) {
        WifiDeviceConfig config;
        if (WifiSettings::GetInstance().GetDeviceConfig(ap.apInfo_.networkId, config) < 0) {
            continue;
        }
        if (config.hiddenSSID) {
            return true;
        }
    }
    return false;
}
void Perf5gHandoverService::GetNoExistRelationInfo(std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
    std::vector<InterScanInfo> &wifiScanInfos, std::unordered_set<std::string> &noExistRelationBssidSet,
    std::vector<RelationAp> &sameSsidAps, std::unordered_set<std::string> &existRelationBssidSet)
{
    for (auto &wifiScanInfo : wifiScanInfos) {
        if (!IsRelationFreq(wifiScanInfo.frequency) || existRelationBssidSet.count(wifiScanInfo.bssid) > 0) {
            continue;
        }
        std::string scanResultKmgmt;
        wifiScanInfo.GetDeviceMgmt(scanResultKmgmt);
        for (auto &wifiDeviceConfig : wifiDeviceConfigs) {
            if (wifiScanInfo.bssid == wifiDeviceConfig.bssid) {
                noExistRelationBssidSet.insert(wifiDeviceConfig.bssid);
                continue;
            }
            bool isSameSsidConnectedAp = (connectedAp_->apInfo.ssid == wifiDeviceConfig.ssid &&
                                          WifiConfigCenter::GetInstance().IsSameKeyMgmt(
                                              connectedAp_->apInfo.keyMgmt, wifiDeviceConfig.keyMgmt));
            if (isSameSsidConnectedAp) {
                noExistRelationBssidSet.insert(wifiScanInfo.bssid);
                RelationAp relationAp;
                relationAp.apInfo_.networkId = wifiDeviceConfig.networkId;
                relationAp.apInfo_.ssid = wifiDeviceConfig.ssid;
                relationAp.apInfo_.bssid = wifiScanInfo.bssid;
                relationAp.apInfo_.keyMgmt = wifiDeviceConfig.keyMgmt;
                relationAp.apInfo_.networkStatus = connectedAp_->apInfo.networkStatus;
                relationAp.apInfo_.frequency = wifiScanInfo.frequency;
                sameSsidAps.push_back(relationAp);
            }
        }
    }
}
void Perf5gHandoverService::LoadRelationApInfo()
{
    if (pDualBandRepostitory_ == nullptr || connectedAp_ == nullptr) {
        WIFI_LOGE("LoadRelationApInfo, pDualBandRepostitory_ or connectedAp_ is nullptr");
        return;
    }
    if (IsValid24GHz(connectedAp_->apInfo.frequency)) {
        pDualBandRepostitory_->LoadRelationApInfo(connectedAp_->apInfo.bssid, relationAps_,
            [](RelationInfo &relationInfo) {return relationInfo.relationBssid5g_;});
    } else {
        pDualBandRepostitory_->LoadRelationApInfo(connectedAp_->apInfo.bssid, relationAps_,
            [](RelationInfo &relationInfo) {return relationInfo.bssid24g_;});
    }
}

void Perf5gHandoverService::RemoveRelationApDuplicates(std::vector<RelationAp> &relationAps)
{
    int32_t num = static_cast<int32_t>(relationAps.size());
    std::sort(relationAps.begin(), relationAps.end());
    auto last = std::unique(relationAps.begin(), relationAps.end());
    relationAps.erase(last, relationAps.end());
    WIFI_LOGI("removeRelationApDuplicates, before:%{public}d after:%{public}d",
        num, static_cast<int32_t>(relationAps.size()));
}

void Perf5gHandoverService::PrintRelationAps()
{
    RemoveRelationApDuplicates(relationAps_);
    std::stringstream associateInfo;
    for (auto iter : relationAps_) {
        if (associateInfo.rdbuf() ->in_avail() != 0) {
            associateInfo << ",";
        }
        associateInfo << "\"" << SsidAnonymize(iter.apInfo_.ssid) << "_" <<
            iter.apInfo_.keyMgmt << "_" << MacAnonymize(iter.apInfo_.bssid)<<"\"";
    }
    WIFI_LOGI("OnConnected, ssid(%{public}s),bssid(%{public}s),frequency(%{public}d),relationAps [%{public}s]",
        SsidAnonymize(connectedAp_->apInfo.ssid).data(), MacAnonymize(connectedAp_->apInfo.bssid).data(),
        connectedAp_->apInfo.frequency, associateInfo.str().c_str());
}
}  // namespace Wifi
}  // namespace OHOS