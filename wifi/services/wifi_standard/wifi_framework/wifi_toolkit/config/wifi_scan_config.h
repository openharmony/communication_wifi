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
#ifndef OHOS_WIFI_SCAN_CONFIG_H
#define OHOS_WIFI_SCAN_CONFIG_H

#include <mutex>
#include "wifi_scan_control_msg.h"

namespace OHOS {
namespace Wifi {
class WifiScanConfig {
public:
    WifiScanConfig();
    ~WifiScanConfig();

    void GetScanDeviceInfo(WifiScanDeviceInfo &scanDeviceInfo);

    void SaveScanDeviceInfo(WifiScanDeviceInfo &scanDeviceInfo);

    void SetAppRunningState(ScanMode appRunMode);

    ScanMode GetAppRunningState();

    void SetScanType(ScanType scanType);

    ScanType GetScanType();

    void SetScanInitiatorUid(int initiatorUid);

    int GetScanInitiatorUid();

    WifiScanDeviceInfo GetScanDeviceInfo();

    void SetStaScene(const int &scene);

    void SetStaSceneForbidCount(int count);

    int GetStaSceneForbidCount();

    void SetScanControlInfo(const ScanControlInfo &info, int instId = 0);

    int GetScanControlInfo(ScanControlInfo &info, int instId = 0);

    void SetPackageInfo(std::map<std::string, std::vector<PackageInfo>> &filterMap);

    void SetMovingFreezeScaned(bool scanned);

    bool GetMovingFreezeScaned();

    void SetAbnormalApps(const std::vector<std::string> &abnormalAppList);

    void SetAppPackageName(const std::string &appPackageName);

    std::string GetAppPackageName();

    void SetStaCurrentTime(time_t time);

    time_t GetStaCurrentTime();

    int SaveScanInfoList(const std::vector<WifiScanInfo> &results);

    int ClearScanInfoList();

    int GetScanInfoList(std::vector<WifiScanInfo> &results);

    void GetScanInfoListInner(std::vector<WifiScanInfo> &results);

    void RecordWifiCategory(const std::string bssid, WifiCategory category);

    WifiCategory GetWifiCategoryRecord(const std::string bssid);

    void CleanWifiCategoryRecord();

private:
    void InitScanControlForbidList();
    void InitScanControlIntervalList();

    std::mutex mScanDeviceInfoMutex;
    WifiScanDeviceInfo mScanDeviceInfo;
    std::mutex mScanMutex;
    std::map<std::string, WifiCategory> mWifiCategoryRecord;
    std::vector<WifiScanInfo> mWifiScanInfoList;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
