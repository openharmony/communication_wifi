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
#include "wifi_log.h"
#undef LOG_TAG
#define LOG_TAG "OHWIFI_MANAGER_CONFIG_CENTER"

namespace OHOS {
namespace Wifi {
WifiConfigCenter &WifiConfigCenter::GetInstance()
{
    static WifiConfigCenter gWifiConfigCenter;
    return gWifiConfigCenter;
}

WifiConfigCenter::WifiConfigCenter()
{
    mStaMidState = WifiOprMidState::CLOSED;
    mApMidState = WifiOprMidState::CLOSED;
    mScanMidState = WifiOprMidState::CLOSED;
}

WifiConfigCenter::~WifiConfigCenter()
{}

int WifiConfigCenter::Init()
{
    if (WifiSettings::GetInstance().Init() < 0) {
        LOGE("Init wifi settings failed!");
        return -1;
    }
    return 0;
}

WifiOprMidState WifiConfigCenter::GetWifiMidState()
{
    return mStaMidState.load();
}

bool WifiConfigCenter::SetWifiMidState(WifiOprMidState expState, WifiOprMidState state)
{
    return mStaMidState.compare_exchange_strong(expState, state);
}

void WifiConfigCenter::SetWifiMidState(WifiOprMidState state)
{
    mStaMidState = state;
}

void WifiConfigCenter::SetWifiStaCloseTime()
{
    mWifiCloseTime = std::chrono::steady_clock::now();
}

double WifiConfigCenter::GetWifiStaInterval()
{
    std::chrono::steady_clock::time_point curr = std::chrono::steady_clock::now();
    double drMs = std::chrono::duration<double, std::milli>(curr - mWifiCloseTime).count();
    return drMs;
}

int WifiConfigCenter::GetWifiState()
{
    return WifiSettings::GetInstance().GetWifiState();
}

bool WifiConfigCenter::IsScanAlwaysActive()
{
    return WifiSettings::GetInstance().GetScanAlwaysState();
}

int WifiConfigCenter::GetScanInfoList(std::vector<WifiScanInfo> &results)
{
    return WifiSettings::GetInstance().GetScanInfoList(results);
}

int WifiConfigCenter::GetScanControlInfo(ScanControlInfo &info)
{
    return WifiSettings::GetInstance().GetScanControlInfo(info);
}

int WifiConfigCenter::SetScanControlInfo(const ScanControlInfo &info)
{
    return WifiSettings::GetInstance().SetScanControlInfo(info);
}

int WifiConfigCenter::AddDeviceConfig(const WifiDeviceConfig &config)
{
    return WifiSettings::GetInstance().AddDeviceConfig(config);
}

int WifiConfigCenter::RemoveDeviceConfig(int networkId)
{
    return WifiSettings::GetInstance().RemoveDeviceConfig(networkId);
}

int WifiConfigCenter::GetDeviceConfig(std::vector<WifiDeviceConfig> &results)
{
    return WifiSettings::GetInstance().GetDeviceConfig(results);
}

int WifiConfigCenter::SetDeviceState(int networkId, int state, bool bSetOther)
{
    return WifiSettings::GetInstance().SetDeviceState(networkId, state, bSetOther);
}

int WifiConfigCenter::GetDhcpInfo(DhcpInfo &info)
{
    return WifiSettings::GetInstance().GetDhcpInfo(info);
}

int WifiConfigCenter::GetLinkedInfo(WifiLinkedInfo &info)
{
    return WifiSettings::GetInstance().GetLinkedInfo(info);
}

int WifiConfigCenter::GetMacAddress(std::string &macAddress)
{
    return WifiSettings::GetInstance().GetMacAddress(macAddress);
}

int WifiConfigCenter::SetCountryCode(const std::string &countryCode)
{
    return WifiSettings::GetInstance().SetCountryCode(countryCode);
}

int WifiConfigCenter::GetCountryCode(std::string &countryCode)
{
    return WifiSettings::GetInstance().GetCountryCode(countryCode);
}

WifiOprMidState WifiConfigCenter::GetApMidState()
{
    return mApMidState.load();
}
bool WifiConfigCenter::SetApMidState(WifiOprMidState expState, WifiOprMidState state)
{
    return mApMidState.compare_exchange_strong(expState, state);
}

void WifiConfigCenter::SetApMidState(WifiOprMidState state)
{
    mApMidState = state;
}

int WifiConfigCenter::GetHotspotState()
{
    return WifiSettings::GetInstance().GetHotspotState();
}

int WifiConfigCenter::SetHotspotConfig(const HotspotConfig &config)
{
    return WifiSettings::GetInstance().SetHotspotConfig(config);
}

int WifiConfigCenter::GetHotspotConfig(HotspotConfig &config)
{
    return WifiSettings::GetInstance().GetHotspotConfig(config);
}

int WifiConfigCenter::GetStationList(std::vector<StationInfo> &results)
{
    return WifiSettings::GetInstance().GetStationList(results);
}

int WifiConfigCenter::FindConnStation(const StationInfo &info)
{
    return WifiSettings::GetInstance().FindConnStation(info);
}

int WifiConfigCenter::GetBlockLists(std::vector<StationInfo> &infos)
{
    return WifiSettings::GetInstance().GetBlockList(infos);
}

int WifiConfigCenter::AddBlockList(const StationInfo &info)
{
    return WifiSettings::GetInstance().ManageBlockList(info, MODE_ADD);
}

int WifiConfigCenter::DelBlockList(const StationInfo &info)
{
    return WifiSettings::GetInstance().ManageBlockList(info, MODE_DEL);
}

int WifiConfigCenter::GetValidBands(std::vector<BandType> &bands)
{
    return WifiSettings::GetInstance().GetValidBands(bands);
}

int WifiConfigCenter::GetValidChannels(ChannelsTable &channelsInfo)
{
    return WifiSettings::GetInstance().GetValidChannels(channelsInfo);
}

WifiOprMidState WifiConfigCenter::GetScanMidState()
{
    return mScanMidState.load();
}

bool WifiConfigCenter::SetScanMidState(WifiOprMidState expState, WifiOprMidState state)
{
    return mScanMidState.compare_exchange_strong(expState, state);
}

void WifiConfigCenter::SetScanMidState(WifiOprMidState state)
{
    mScanMidState = state;
}

int WifiConfigCenter::GetSignalLevel(const int &rssi, const int &band)
{
    return WifiSettings::GetInstance().GetSignalLevel(rssi, band);
}

bool WifiConfigCenter::GetCanUseStaWhenAirplaneMode()
{
    return WifiSettings::GetInstance().GetCanUseStaWhenAirplaneMode();
}

int WifiConfigCenter::SetCanUseStaWhenAirplaneMode(bool bCan)
{
    return WifiSettings::GetInstance().SetCanUseStaWhenAirplaneMode(bCan);
}

bool WifiConfigCenter::GetStaLastRunState()
{
    return WifiSettings::GetInstance().GetStaLastRunState();
}

int WifiConfigCenter::SetStaLastRunState(bool bRun)
{
    return WifiSettings::GetInstance().SetStaLastRunState(bRun);
}

void WifiConfigCenter::SetScreenState(const int &state)
{
    WifiSettings::GetInstance().SetScreenState(state);
}

int WifiConfigCenter::GetScreenState()
{
    return WifiSettings::GetInstance().GetScreenState();
}

void WifiConfigCenter::SetAirplaneModeState(const int &state)
{
    WifiSettings::GetInstance().SetAirplaneModeState(state);
}

int WifiConfigCenter::GetAirplaneModeState()
{
    return WifiSettings::GetInstance().GetAirplaneModeState();
}

void WifiConfigCenter::SetAppRunningState(const int &state)
{
    WifiSettings::GetInstance().SetAppRunningState(state);
}

int WifiConfigCenter::GetAppRunningState()
{
    return WifiSettings::GetInstance().GetAppRunningState();
}

void WifiConfigCenter::SetPowerSavingModeState(const int &state)
{
    WifiSettings::GetInstance().SetPowerSavingModeState(state);
}

int WifiConfigCenter::GetPowerSavingModeState()
{
    return WifiSettings::GetInstance().GetPowerSavingModeState();
}
} // namespace Wifi
} // namespace OHOS