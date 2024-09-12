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


WifiScanConfig &WifiScanConfig::GetInstance()
{
    static WifiScanConfig gWifiScanConfig;
    return gWifiScanConfig;
}

WifiScanConfig::WifiScanConfig()
{}

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
    mScanDeviceInfo.idelState = WifiConfigCenter::GetInstance().GetPowerIdelState();
    mScanDeviceInfo.thermalLevel = WifiConfigCenter::GetInstance().GetThermalLevel();
    mScanDeviceInfo.screenState = WifiConfigCenter::GetInstance().GetScreenState();
    mScanDeviceInfo.noChargerState = WifiConfigCenter::GetInstance().GetNoChargerPlugModeState();
    mScanDeviceInfo.gnssFixState = WifiConfigCenter::GetInstance().GetGnssFixState();
    mScanDeviceInfo.freezeState = WifiConfigCenter::GetInstance().GetFreezeModeState();

    WifiConfigCenter::GetInstance().GetHid2dUpperScene(
        mScanDeviceInfo.hid2dInfo.upperIfName, mScanDeviceInfo.hid2dInfo.upperScene);
    WifiConfigCenter::GetInstance().GetP2pBusinessType(mScanDeviceInfo.hid2dInfo.p2pBusinessType);
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

int& WifiScanConfig::GetStaSceneForbidCount()
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    return mScanDeviceInfo.staSceneForbidCount;
}

void WifiScanConfig::SetScanControlInfo(ScanControlInfo scanControlInfo)
{
    std::unique_lock<std::mutex> lock(mScanDeviceInfoMutex);
    mScanDeviceInfo.scanControlInfo = scanControlInfo;
}

void WifiScanConfig::SetPackageFilter(std::map<std::string, std::vector<std::string>> &filterMap)
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

}  // namespace Wifi
}  // namespace OHOS
