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

#ifndef OHOS_MOCK_WIFI_SCAN_CONFIG_H
#define OHOS_MOCK_WIFI_SCAN_CONFIG_H

#include <gmock/gmock.h>
#include "wifi_internal_msg.h"
#include "wifi_scan_control_msg.h"

namespace OHOS {
namespace Wifi {

class MockWifiScanConfig {
public:
    virtual ~MockWifiScanConfig() = default;
    virtual int GetScanControlInfo(ScanControlInfo &info, int instId = 0) = 0;
    virtual int SetScanControlInfo(const ScanControlInfo &info, int instId = 0) = 0;
    virtual int SaveScanInfoList(const std::vector<WifiScanInfo> &results) = 0;
    virtual int ClearScanInfoList() = 0;
    virtual int GetScanInfoList(std::vector<WifiScanInfo> &results) = 0;
    virtual void CleanWifiCategoryRecord() = 0;
    virtual void SetAppPackageName(const std::string &name) = 0;
    virtual std::string GetAppPackageName() = 0;
    virtual void SetPackageInfo(std::map<std::string, std::vector<PackageInfo>> &filterMap) = 0;
    virtual void SetAppRunningState(ScanMode appRunMode) = 0;
    virtual ScanMode GetAppRunningState() = 0;
    virtual void SetScanType(ScanType scanType) = 0;
    virtual ScanType GetScanType() = 0;
    virtual void SetScanInitiatorUid(int initiatorUid) = 0;
    virtual int GetScanInitiatorUid() = 0;
    virtual WifiScanDeviceInfo GetScanDeviceInfo() = 0;
    virtual void RecordWifiCategory(const std::string bssid, WifiCategory category) = 0;
    virtual WifiCategory GetWifiCategoryRecord(const std::string bssid) = 0;
    virtual void GetScanInfoListInner(std::vector<WifiScanInfo> &results) = 0;
    virtual void SetStaScene(const int &scene) = 0;
    virtual void SetStaSceneForbidCount(int count) = 0;
    virtual int GetStaSceneForbidCount() = 0;
    virtual void SetMovingFreezeScaned(bool scanned) = 0;
    virtual bool GetMovingFreezeScaned() = 0;
    virtual void SetAbnormalApps(const std::vector<std::string> &abnormalAppList) = 0;
    virtual void SetStaCurrentTime(time_t time) = 0;
    virtual time_t GetStaCurrentTime() = 0;
};

class WifiScanConfig : public MockWifiScanConfig {
public:
    MOCK_METHOD2(GetScanControlInfo, int(ScanControlInfo &info, int));
    MOCK_METHOD2(SetScanControlInfo, int(const ScanControlInfo &info, int));
    MOCK_METHOD1(SaveScanInfoList, int(const std::vector<WifiScanInfo> &results));
    MOCK_METHOD0(ClearScanInfoList, int());
    MOCK_METHOD1(GetScanInfoList, int(std::vector<WifiScanInfo> &results));
    MOCK_METHOD0(CleanWifiCategoryRecord, void());
    MOCK_METHOD1(SetAppPackageName, void(const std::string &name));
    MOCK_METHOD0(GetAppPackageName, std::string());
    MOCK_METHOD1(SetPackageInfo, void(std::map<std::string, std::vector<PackageInfo>> &filterMap));
    MOCK_METHOD1(SetAppRunningState, void(ScanMode appRunMode));
    MOCK_METHOD0(GetAppRunningState, ScanMode());
    MOCK_METHOD1(SetScanType, void(ScanType scanType));
    MOCK_METHOD0(GetScanType, ScanType());
    MOCK_METHOD1(SetScanInitiatorUid, void(int));
    MOCK_METHOD0(GetScanInitiatorUid, int());
    MOCK_METHOD0(GetScanDeviceInfo, WifiScanDeviceInfo());
    MOCK_METHOD2(RecordWifiCategory, void(const std::string bssid, WifiCategory category));
    MOCK_METHOD1(GetWifiCategoryRecord, WifiCategory(const std::string bssid));
    MOCK_METHOD1(GetScanInfoListInner, void(std::vector<WifiScanInfo> &results));
    MOCK_METHOD1(SetStaScene, void(const int &scene));
    MOCK_METHOD1(SetStaSceneForbidCount, void(int count));
    MOCK_METHOD0(GetStaSceneForbidCount, int());
    MOCK_METHOD1(SetMovingFreezeScaned, void(bool scanned));
    MOCK_METHOD0(GetMovingFreezeScaned, bool());
    MOCK_METHOD1(SetAbnormalApps, void(const std::vector<std::string> &abnormalAppList));
    MOCK_METHOD1(SetStaCurrentTime, void(time_t time));
    MOCK_METHOD0(GetStaCurrentTime, time_t());
};
}  // namespace OHOS
}  // namespace Wifi
#endif