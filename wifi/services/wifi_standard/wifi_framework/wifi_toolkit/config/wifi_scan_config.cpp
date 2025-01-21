/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "wifi_scan_config.h"
#include "wifi_config_center.h"
#include "wifi_common_util.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
WifiScanConfig::WifiScanConfig()
{
    InitScanControlForbidList();
    InitScanControlIntervalList();
}

WifiScanConfig::~WifiScanConfig()
{}

void WifiScanConfig::GetScanDeviceInfo(WifiScanDeviceInfo &scanDeviceInfo)
{
    WifiP2pLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetP2pInfo(linkedInfo);
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
#ifndef OHOS_ARCH_LITE
    mScanDeviceInfo.appId = GetCallingUid();
#endif
    mScanDeviceInfo.hid2dInfo.p2pConnectState = linkedInfo.GetConnectState();
    mScanDeviceInfo.hid2dInfo.p2pEnhanceState = WifiConfigCenter::GetInstance().GetP2pEnhanceState();
    mScanDeviceInfo.hid2dInfo.hid2dSceneLastSetTime = WifiConfigCenter::GetInstance().GetHid2dSceneLastSetTime();
    mScanDeviceInfo.idelState = WifiConfigCenter::GetInstance().GetPowerIdelState();
    mScanDeviceInfo.thermalLevel = WifiConfigCenter::GetInstance().GetThermalLevel();
    mScanDeviceInfo.screenState = WifiConfigCenter::GetInstance().GetScreenState();
    mScanDeviceInfo.noChargerState = WifiConfigCenter::GetInstance().GetNoChargerPlugModeState();
    mScanDeviceInfo.gnssFixState = WifiConfigCenter::GetInstance().GetGnssFixState();
    mScanDeviceInfo.freezeState = WifiConfigCenter::GetInstance().GetFreezeModeState();

    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SOFT_BUS_SERVICE_UID,
        mScanDeviceInfo.hid2dInfo.softBusScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(CAST_ENGINE_SERVICE_UID,
        mScanDeviceInfo.hid2dInfo.castScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MIRACAST_SERVICE_UID,
        mScanDeviceInfo.hid2dInfo.miraCastScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(SHARE_SERVICE_UID,
        mScanDeviceInfo.hid2dInfo.shareScene);
    WifiConfigCenter::GetInstance().GetHid2dUpperScene(MOUSE_CROSS_SERVICE_UID,
        mScanDeviceInfo.hid2dInfo.mouseCrossScene);
    scanDeviceInfo = mScanDeviceInfo;
}

void WifiScanConfig::SaveScanDeviceInfo(WifiScanDeviceInfo &scanDeviceInfo)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo = scanDeviceInfo;
}

void WifiScanConfig::SetAppRunningState(ScanMode appRunMode)
{
    if (static_cast<int>(appRunMode) < static_cast<int>(ScanMode::APP_FOREGROUND_SCAN) ||
        static_cast<int>(appRunMode) > static_cast<int>(ScanMode::SYS_BACKGROUND_SCAN)) {
        return;
    }
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.scanMode = appRunMode;
}

ScanMode WifiScanConfig::GetAppRunningState()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.scanMode;
}

void WifiScanConfig::SetScanType(ScanType scanType)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.scanType = scanType;
}

ScanType WifiScanConfig::GetScanType()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.scanType;
}

void WifiScanConfig::SetScanInitiatorUid(int initiatorUid)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.initiatorUid = initiatorUid;
}

int WifiScanConfig::GetScanInitiatorUid()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.initiatorUid;
}

WifiScanDeviceInfo WifiScanConfig::GetScanDeviceInfo()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo;
}

void WifiScanConfig::SetStaScene(const int &scene)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.staScene = scene;
}

void WifiScanConfig::SetStaSceneForbidCount(int count)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.staSceneForbidCount = count;
}

int WifiScanConfig::GetStaSceneForbidCount()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.staSceneForbidCount;
}

void WifiScanConfig::SetScanControlInfo(const ScanControlInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.scanControlInfo = info;
}

int WifiScanConfig::GetScanControlInfo(ScanControlInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    info = mScanDeviceInfo.scanControlInfo;
    return 0;
}

void WifiScanConfig::SetPackageInfo(std::map<std::string, std::vector<PackageInfo>> &filterMap)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.scan_thermal_trust_list = filterMap["scan_thermal_filter"];
    mScanDeviceInfo.scan_frequency_trust_list = filterMap["scan_frequency_filter"];
    mScanDeviceInfo.scan_screen_off_trust_list = filterMap["scan_screen_off_filter"];
    mScanDeviceInfo.scan_gps_block_list = filterMap["scan_gps_filter"];
    mScanDeviceInfo.scan_hid2d_list = filterMap["scan_hid2d_filter"];
}

void WifiScanConfig::SetMovingFreezeScaned(bool scanned)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.isAbsFreezeScaned = scanned;
}

bool WifiScanConfig::GetMovingFreezeScaned()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.isAbsFreezeScaned;
}

void WifiScanConfig::SetAbnormalApps(const std::vector<std::string> &abnormalAppList)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.abnormalAppList = abnormalAppList;
}

void WifiScanConfig::SetAppPackageName(const std::string &appPackageName)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.packageName = appPackageName;
}

std::string WifiScanConfig::GetAppPackageName()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.packageName;
}

void WifiScanConfig::SetStaCurrentTime(time_t time)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.staCurrentTime = time;
}

time_t WifiScanConfig::GetStaCurrentTime()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.staCurrentTime;
}

void WifiScanConfig::InitScanControlForbidList()
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    /* Disable external scanning during scanning. */
    ScanForbidMode forbidMode;
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_SCANNING;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);

    /* Disable external scanning when the screen is shut down. */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_SCREEN_OFF;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);

    /* Disable all scans in connection */
#ifdef SUPPORT_SCAN_CONTROL
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_ASSOCIATING;
    forbidMode.forbidTime = ASSOCIATING_SCAN_CONTROL_INTERVAL;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_ASSOCIATED;
    forbidMode.forbidTime = ASSOCIATED_SCAN_CONTROL_INTERVAL;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_OBTAINING_IP;
    forbidMode.forbidCount = OBTAINING_IP_SCAN_CONTROL_TIMES;
    forbidMode.forbidTime = OBTAINING_IP_SCAN_CONTROL_INTERVAL;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
#else
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
#endif
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTING;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);

    /* Deep sleep disables all scans. */
    forbidMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
    forbidMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    forbidMode.scanScene = SCAN_SCENE_DEEP_SLEEP;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);

    /* PNO scanning disabled */
    forbidMode.scanMode = ScanMode::PNO_SCAN;
    forbidMode.scanScene = SCAN_SCENE_CONNECTED;
    mScanDeviceInfo.scanControlInfo.scanForbidList.push_back(forbidMode);
    return;
}

void WifiScanConfig::InitScanControlIntervalList()
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    /* Foreground app: 4 times in 2 minutes for a single application */
    ScanIntervalMode scanIntervalMode;
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_ORIGIN;
    scanIntervalMode.scanMode = ScanMode::APP_FOREGROUND_SCAN;
    scanIntervalMode.isSingle = true;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = FOREGROUND_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = FOREGROUND_SCAN_CONTROL_TIMES;
    mScanDeviceInfo.scanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* Backend apps: once every 30 minutes */
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_ORIGIN;
    scanIntervalMode.scanMode = ScanMode::APP_BACKGROUND_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = BACKGROUND_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = BACKGROUND_SCAN_CONTROL_TIMES;
    mScanDeviceInfo.scanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* no charger plug */
    /* All app: If the scanning interval is less than 5s for five  */
    /* consecutive times, the scanning can be performed only after */
    /* the scanning interval is greater than 5s. */
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_CUSTOM;
    scanIntervalMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_CONTINUE;
    scanIntervalMode.interval = FREQUENCY_CONTINUE_INTERVAL;
    scanIntervalMode.count = FREQUENCY_CONTINUE_COUNT;
    mScanDeviceInfo.scanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* no charger plug */
    /* Single app: If all scanning interval in 10 times is less than */
    /* the threshold (20s), the app is added to the blocklist and  */
    /* cannot initiate scanning. */
    scanIntervalMode.scanScene = SCAN_SCENE_FREQUENCY_CUSTOM;
    scanIntervalMode.scanMode = ScanMode::ALL_EXTERN_SCAN;
    scanIntervalMode.isSingle = true;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_BLOCKLIST;
    scanIntervalMode.interval = FREQUENCY_BLOCKLIST_INTERVAL;
    scanIntervalMode.count = FREQUENCY_BLOCKLIST_COUNT;
    mScanDeviceInfo.scanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /* PNO scanning every 20 seconds */
    scanIntervalMode.scanScene = SCAN_SCENE_ALL;
    scanIntervalMode.scanMode = ScanMode::PNO_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_FIXED;
    scanIntervalMode.interval = PNO_SCAN_CONTROL_INTERVAL;
    scanIntervalMode.count = PNO_SCAN_CONTROL_TIMES;
    mScanDeviceInfo.scanControlInfo.scanIntervalList.push_back(scanIntervalMode);

    /*
     * The system scans for 20 seconds, multiplies 2 each time,
     * and performs scanning every 160 seconds.
     */
    scanIntervalMode.scanScene = SCAN_SCENE_ALL;
    scanIntervalMode.scanMode = ScanMode::SYSTEM_TIMER_SCAN;
    scanIntervalMode.isSingle = false;
    scanIntervalMode.intervalMode = IntervalMode::INTERVAL_EXP;
    scanIntervalMode.interval = SYSTEM_TIMER_SCAN_CONTROL_INTERVAL;
#ifdef SUPPORT_SCAN_CONTROL
    scanIntervalMode.count = 0;
#else
    scanIntervalMode.count = SYSTEM_TIMER_SCAN_CONTROL_TIMES;
#endif
    mScanDeviceInfo.scanControlInfo.scanIntervalList.push_back(scanIntervalMode);
}

int WifiScanConfig::SaveScanInfoList(const std::vector<WifiScanInfo> &results)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mWifiScanInfoList.clear();
    mWifiScanInfoList = results;
    return 0;
}

int WifiScanConfig::ClearScanInfoList()
{
    if (WifiConfigCenter::GetInstance().HasWifiActive()) {
        return 0;
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WifiConfigCenter::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO);
#endif
    std::unique_lock<std::mutex> lock(mScanMutex);
    mWifiScanInfoList.clear();
    return 0;
}

int WifiScanConfig::GetScanInfoList(std::vector<WifiScanInfo> &results)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    int64_t currentTime = GetElapsedMicrosecondsSinceBoot();
    for (auto iter = mWifiScanInfoList.begin(); iter != mWifiScanInfoList.end();) {
        if (iter->disappearCount >= WIFI_DISAPPEAR_TIMES) {
#ifdef SUPPORT_RANDOM_MAC_ADDR
            WifiConfigCenter::GetInstance().RemoveMacAddrPairInfo(
                WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO, iter->bssid, iter->bssidType);
#endif
            hilinkAbilityRecord.erase(iter->bssid);
            LOGI("ScanInfo remove ssid=%{public}s bssid=%{public}s.\n",
                SsidAnonymize(iter->ssid).c_str(), MacAnonymize(iter->bssid).c_str());
            iter = mWifiScanInfoList.erase(iter);
            mWifiCategoryRecord.erase(iter->bssid);
            continue;
        }
        if (iter->timestamp > currentTime - WIFI_GET_SCAN_INFO_VALID_TIMESTAMP) {
            results.push_back(*iter);
        }
        ++iter;
    }
    if (results.empty()) {
        results.assign(mWifiScanInfoList.begin(), mWifiScanInfoList.end());
    }
    LOGI("WifiSettings::GetScanInfoList size = %{public}zu", results.size());
    return 0;
}

void WifiScanConfig::GetScanInfoListInner(std::vector<WifiScanInfo> &results)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    results = mWifiScanInfoList;
}

void WifiScanConfig::RecordHilinkAbility(const std::string &bssid, bool isSupportHilink)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    if (bssid.empty()) {
        LOGE ("RecordHilinkAbility bssid is NULL!");
        return;
    }
    hilinkAbilityRecord.insert_or_assign(bssid, isSupportHilink);
}

bool WifiScanConfig::GetHilinkAbility(const std::string &bssid)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = hilinkAbilityRecord.find(bssid);
    if (iter != hilinkAbilityRecord.end()) {
        return iter->second;
    }
    return false;
}

void WifiScanConfig::RecordWifiCategory(const std::string bssid, WifiCategory category)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    if (bssid.empty()) {
        LOGE ("bassid is NULL!");
        return;
    }
    mWifiCategoryRecord.insert_or_assign(bssid, category);
}

WifiCategory WifiScanConfig::GetWifiCategoryRecord(const std::string bssid)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mWifiCategoryRecord.find(bssid);
    if (iter != mWifiCategoryRecord.end()) {
        return iter->second;
    }
    return WifiCategory::DEFAULT;
}

void WifiScanConfig::CleanWifiCategoryRecord()
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mWifiCategoryRecord.clear();
    std::vector<WifiScanInfo>().swap(mWifiScanInfoList);
}

void WifiScanConfig::RemoveWifiCategoryRecord(const std::string bssid)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mWifiCategoryRecord.erase(bssid);
}
}  // namespace Wifi
}  // namespace OHOS
