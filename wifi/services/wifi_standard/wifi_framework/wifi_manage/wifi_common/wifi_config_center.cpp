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

#include "wifi_config_center.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiConfigCenter");

namespace OHOS {
namespace Wifi {
WifiConfigCenter &WifiConfigCenter::GetInstance()
{
    static WifiConfigCenter gWifiConfigCenter;
    return gWifiConfigCenter;
}

WifiConfigCenter::WifiConfigCenter()
{
    mStaMidState.emplace(0, WifiOprMidState::CLOSED);
    mApMidState.emplace(0, WifiOprMidState::CLOSED);
    mP2pMidState = WifiOprMidState::CLOSED;
    mScanMidState.emplace(0, WifiOprMidState::CLOSED);
    mStaScanOnlyMidState.emplace(0, WifiOprMidState::CLOSED);
    mWifiCloseTime.emplace(0, std::chrono::steady_clock::now());
    mWifiOpenedWhenAirplane = false;
    mIsAncoConnected.emplace(0, false);
}

WifiConfigCenter::~WifiConfigCenter()
{}

int WifiConfigCenter::Init()
{
    if (WifiSettings::GetInstance().Init() < 0) {
        WIFI_LOGE("Init wifi settings failed!");
        return -1;
    }
    return 0;
}

WifiOprMidState WifiConfigCenter::GetWifiMidState(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mStaMidState.find(instId);
    if (iter != mStaMidState.end()) {
        return iter->second.load();
    } else {
        mStaMidState.emplace(instId, WifiOprMidState::CLOSED);
        return mStaMidState[instId].load();
    }
}

bool WifiConfigCenter::SetWifiMidState(WifiOprMidState expState, WifiOprMidState state, int instId)
{
    WIFI_LOGI("SetWifiMidState expState:%{public}d,state:%{public}d,instId:%{public}d",
        (int)expState, (int)state, instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mStaMidState.find(instId);
    if (iter != mStaMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mStaMidState.emplace(instId, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetWifiMidState(WifiOprMidState state, int instId)
{
    WIFI_LOGI("SetWifiMidState ,state:%{public}d,instId:%{public}d", (int)state, instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto ret = mStaMidState.emplace(instId, state);
    if (!ret.second) {
        mStaMidState[instId] = state;
    }
}

void WifiConfigCenter::SetWifiStaCloseTime(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    mWifiCloseTime[instId] = std::chrono::steady_clock::now();
}

double WifiConfigCenter::GetWifiStaInterval(int instId)
{
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mWifiCloseTime.find(instId);
    if (iter != mWifiCloseTime.end()) {
        std::chrono::steady_clock::time_point curr = std::chrono::steady_clock::now();
        double drMs = std::chrono::duration<double, std::milli>(curr - iter->second).count();
        return drMs;
    }

    return 0;
}

int WifiConfigCenter::GetWifiState(int instId)
{
    return WifiSettings::GetInstance().GetWifiState(instId);
}

bool WifiConfigCenter::IsScanAlwaysActive(int instId)
{
    return WifiSettings::GetInstance().GetScanAlwaysState(instId);
}

int WifiConfigCenter::GetScanInfoList(std::vector<WifiScanInfo> &results)
{
    return WifiSettings::GetInstance().GetScanInfoList(results);
}

int WifiConfigCenter::GetScanControlInfo(ScanControlInfo &info, int instId)
{
    return WifiSettings::GetInstance().GetScanControlInfo(info, instId);
}

int WifiConfigCenter::SetScanControlInfo(const ScanControlInfo &info, int instId)
{
    return WifiSettings::GetInstance().SetScanControlInfo(info, instId);
}

int WifiConfigCenter::AddDeviceConfig(const WifiDeviceConfig &config)
{
    return WifiSettings::GetInstance().AddDeviceConfig(config);
}

int WifiConfigCenter::RemoveDevice(int networkId)
{
    return WifiSettings::GetInstance().RemoveDevice(networkId);
}

int WifiConfigCenter::GetDeviceConfig(std::vector<WifiDeviceConfig> &results)
{
    return WifiSettings::GetInstance().GetDeviceConfig(results);
}

int WifiConfigCenter::GetCandidateConfigs(const int uid, std::vector<WifiDeviceConfig> &results)
{
    return WifiSettings::GetInstance().GetAllCandidateConfig(uid, results);
}

int WifiConfigCenter::SetDeviceState(int networkId, int state, bool bSetOther)
{
    return WifiSettings::GetInstance().SetDeviceState(networkId, state, bSetOther);
}

int WifiConfigCenter::GetIpInfo(IpInfo &info, int instId)
{
    return WifiSettings::GetInstance().GetIpInfo(info, instId);
}

int WifiConfigCenter::GetIpv6Info(IpV6Info &info, int instId)
{
    return WifiSettings::GetInstance().GetIpv6Info(info, instId);
}

int WifiConfigCenter::GetLinkedInfo(WifiLinkedInfo &info, int instId)
{
    return WifiSettings::GetInstance().GetLinkedInfo(info, instId);
}

int WifiConfigCenter::GetMacAddress(std::string &macAddress, int instId)
{
    return WifiSettings::GetInstance().GetMacAddress(macAddress, instId);
}

bool WifiConfigCenter::IsLoadStabak(int instId)
{
    return WifiSettings::GetInstance().IsLoadStabak(instId);
}

WifiOprMidState WifiConfigCenter::GetApMidState(int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApMidState.find(id);
    if (iter != mApMidState.end()) {
        return iter->second.load();
    } else {
        mApMidState.emplace(id, WifiOprMidState::CLOSED);
        return mApMidState[id].load();
    }
}

bool WifiConfigCenter::SetApMidState(WifiOprMidState expState, WifiOprMidState state, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApMidState.find(id);
    if (iter != mApMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mApMidState.emplace(id, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetApMidState(WifiOprMidState state, int id)
{
    std::unique_lock<std::mutex> lock(mApMutex);
    auto ret = mApMidState.emplace(id, state);
    if (!ret.second) {
        mApMidState[id] = state;
    }
}

int WifiConfigCenter::GetHotspotState(int id)
{
    return WifiSettings::GetInstance().GetHotspotState(id);
}

int WifiConfigCenter::SetHotspotConfig(const HotspotConfig &config, int id)
{
    return WifiSettings::GetInstance().SetHotspotConfig(config, id);
}

int WifiConfigCenter::GetHotspotConfig(HotspotConfig &config, int id)
{
    return WifiSettings::GetInstance().GetHotspotConfig(config, id);
}

int WifiConfigCenter::SetHotspotIdleTimeout(int time)
{
    return WifiSettings::GetInstance().SetHotspotIdleTimeout(time);
}

int WifiConfigCenter::GetHotspotIdleTimeout()
{
    return WifiSettings::GetInstance().GetHotspotIdleTimeout();
}

int WifiConfigCenter::GetStationList(std::vector<StationInfo> &results, int id)
{
    return WifiSettings::GetInstance().GetStationList(results, id);
}

int WifiConfigCenter::FindConnStation(const StationInfo &info, int id)
{
    return WifiSettings::GetInstance().FindConnStation(info, id);
}

int WifiConfigCenter::GetBlockLists(std::vector<StationInfo> &infos, int id)
{
    return WifiSettings::GetInstance().GetBlockList(infos, id);
}

int WifiConfigCenter::AddBlockList(const StationInfo &info, int id)
{
    return WifiSettings::GetInstance().ManageBlockList(info, MODE_ADD, id);
}

int WifiConfigCenter::DelBlockList(const StationInfo &info, int id)
{
    return WifiSettings::GetInstance().ManageBlockList(info, MODE_DEL, id);
}

int WifiConfigCenter::GetValidBands(std::vector<BandType> &bands)
{
    return WifiSettings::GetInstance().GetValidBands(bands);
}

int WifiConfigCenter::GetValidChannels(ChannelsTable &channelsInfo)
{
    return WifiSettings::GetInstance().GetValidChannels(channelsInfo);
}

WifiOprMidState WifiConfigCenter::GetScanMidState(int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mScanMidState.find(instId);
    if (iter != mScanMidState.end()) {
        return iter->second.load();
    } else {
        mScanMidState.emplace(instId, WifiOprMidState::CLOSED);
        return mScanMidState[instId].load();
    }
}

bool WifiConfigCenter::SetScanMidState(WifiOprMidState expState, WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mScanMidState.find(instId);
    if (iter != mScanMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mScanMidState.emplace(instId, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetScanMidState(WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto ret = mScanMidState.emplace(instId, state);
    if (!ret.second) {
        mScanMidState[instId] = state;
    }
}

int WifiConfigCenter::GetSignalLevel(const int &rssi, const int &band, int instId)
{
    return WifiSettings::GetInstance().GetSignalLevel(rssi, band, instId);
}

WifiOprMidState WifiConfigCenter::GetP2pMidState()
{
    return mP2pMidState.load();
}

bool WifiConfigCenter::SetP2pMidState(WifiOprMidState expState, WifiOprMidState state)
{
    return mP2pMidState.compare_exchange_strong(expState, state);
}

void WifiConfigCenter::SetP2pMidState(WifiOprMidState state)
{
    mP2pMidState = state;
}

int WifiConfigCenter::GetP2pState()
{
    return WifiSettings::GetInstance().GetP2pState();
}

int WifiConfigCenter::GetOperatorWifiType(int instId)
{
    return WifiSettings::GetInstance().GetOperatorWifiType(instId);
}

int WifiConfigCenter::SetOperatorWifiType(int type, int instId)
{
    return WifiSettings::GetInstance().SetOperatorWifiType(type, instId);
}

bool WifiConfigCenter::GetCanOpenStaWhenAirplaneMode(int instId)
{
    return WifiSettings::GetInstance().GetCanOpenStaWhenAirplaneMode(instId);
}

int WifiConfigCenter::SetWifiFlagOnAirplaneMode(bool ifOpen, int instId)
{
    return WifiSettings::GetInstance().SetWifiFlagOnAirplaneMode(ifOpen, instId);
}

bool WifiConfigCenter::GetWifiFlagOnAirplaneMode(int instId)
{
    return WifiSettings::GetInstance().GetWifiFlagOnAirplaneMode(instId);
}

bool WifiConfigCenter::GetWifiStateWhenAirplaneMode()
{
    return mWifiOpenedWhenAirplane.load();
}

void WifiConfigCenter::SetWifiStateWhenAirplaneMode(bool bState)
{
    mWifiOpenedWhenAirplane = bState;
}

bool WifiConfigCenter::GetStaLastRunState(int instId)
{
    return WifiSettings::GetInstance().GetStaLastRunState(instId);
}

int WifiConfigCenter::SetStaLastRunState(bool bRun, int instId)
{
    return WifiSettings::GetInstance().SetStaLastRunState(bRun, instId);
}

bool WifiConfigCenter::GetWifiConnectedMode(int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    return mIsAncoConnected[instId].load();
}

void WifiConfigCenter::SetWifiConnectedMode(bool isAncoConnected, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mIsAncoConnected[instId] = isAncoConnected;
}

void WifiConfigCenter::SetScreenState(const int &state)
{
    WifiSettings::GetInstance().SetScreenState(state);
}

int WifiConfigCenter::GetScreenState() const
{
    return WifiSettings::GetInstance().GetScreenState();
}

bool WifiConfigCenter::SetWifiStateOnAirplaneChanged(const int &state)
{
    return WifiSettings::GetInstance().SetWifiStateOnAirplaneChanged(state);
}

int WifiConfigCenter::GetAirplaneModeState() const
{
    return WifiSettings::GetInstance().GetAirplaneModeState();
}

void WifiConfigCenter::SetPowerSleepState(const int &state)
{
    WifiSettings::GetInstance().SetPowerSleepState(state);
}

int WifiConfigCenter::GetPowerSleepState() const
{
    return WifiSettings::GetInstance().GetPowerSleepState();
}

void WifiConfigCenter::SetAppRunningState(ScanMode appRunMode)
{
    WifiSettings::GetInstance().SetAppRunningState(appRunMode);
}

ScanMode WifiConfigCenter::GetAppRunningState() const
{
    return WifiSettings::GetInstance().GetAppRunningState();
}

void WifiConfigCenter::SetPowerSavingModeState(const int &state)
{
    WifiSettings::GetInstance().SetPowerSavingModeState(state);
}

int WifiConfigCenter::GetPowerSavingModeState() const
{
    return WifiSettings::GetInstance().GetPowerSavingModeState();
}

void WifiConfigCenter::SetAppPackageName(const std::string &appPackageName)
{
    WifiSettings::GetInstance().SetAppPackageName(appPackageName);
}

const std::string WifiConfigCenter::GetAppPackageName() const
{
    return WifiSettings::GetInstance().GetAppPackageName();
}

void WifiConfigCenter::SetFreezeModeState(int state)
{
    WifiSettings::GetInstance().SetFreezeModeState(state);
}

int WifiConfigCenter::GetFreezeModeState() const
{
    return WifiSettings::GetInstance().GetFreezeModeState();
}

void WifiConfigCenter::SetNoChargerPlugModeState(int state)
{
    WifiSettings::GetInstance().SetNoChargerPlugModeState(state);
}

int WifiConfigCenter::GetNoChargerPlugModeState() const
{
    return WifiSettings::GetInstance().GetNoChargerPlugModeState();
}

int WifiConfigCenter::SetP2pDeviceName(const std::string &deviceName)
{
    return WifiSettings::GetInstance().SetP2pDeviceName(deviceName);
}

int WifiConfigCenter::GetDisconnectedReason(DisconnectedReason &discReason, int instId)
{
    return WifiSettings::GetInstance().GetDisconnectedReason(discReason, instId);
}

WifiOprMidState WifiConfigCenter::GetWifiScanOnlyMidState(int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mStaScanOnlyMidState.find(instId);
    if (iter != mStaScanOnlyMidState.end()) {
        return iter->second.load();
    } else {
        mStaScanOnlyMidState.emplace(instId, WifiOprMidState::CLOSED);
        return mStaScanOnlyMidState[instId].load();
    }
}

bool WifiConfigCenter::SetWifiScanOnlyMidState(WifiOprMidState expState, WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto iter = mStaScanOnlyMidState.find(instId);
    if (iter != mStaScanOnlyMidState.end()) {
        return iter->second.compare_exchange_strong(expState, state);
    } else {
        mStaScanOnlyMidState.emplace(instId, state);
        return true;
    }
    return false;
}

void WifiConfigCenter::SetWifiScanOnlyMidState(WifiOprMidState state, int instId)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    auto ret = mStaScanOnlyMidState.emplace(instId, state);
    if (!ret.second) {
        mStaScanOnlyMidState[instId] = state;
    }
}

int WifiConfigCenter::GetStaApExclusionType()
{
    return WifiSettings::GetInstance().GetStaApExclusionType();
}

int WifiConfigCenter::SetStaApExclusionType(int type)
{
    return WifiSettings::GetInstance().SetStaApExclusionType(type);
}

int WifiConfigCenter::SetChangeDeviceConfig(ConfigChange value, const WifiDeviceConfig &config)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    mLastRemoveDeviceConfig = std::make_pair((int)value, config);
    return WIFI_OPT_SUCCESS;
}

bool WifiConfigCenter::GetChangeDeviceConfig(ConfigChange& value, WifiDeviceConfig &config)
{
    std::unique_lock<std::mutex> lock(mScanMutex);
    value = (ConfigChange)mLastRemoveDeviceConfig.first;
    config = mLastRemoveDeviceConfig.second;
    return true;
}
}  // namespace Wifi
}  // namespace OHOS
