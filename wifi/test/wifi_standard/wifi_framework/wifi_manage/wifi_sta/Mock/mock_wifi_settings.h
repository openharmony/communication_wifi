/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_WIFISETTINGS_H
#define OHOS_MOCK_WIFISETTINGS_H

#include "wifi_ap_msg.h"
#include "wifi_msg.h"
#include <gmock/gmock.h>
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {
class MockWifiSettings {
public:
    virtual ~MockWifiSettings() = default;
    virtual int AddDeviceConfig(const WifiDeviceConfig &config) = 0;
    virtual int RemoveDevice(int networkId) = 0;
    virtual void ClearDeviceConfig() = 0;
    virtual int GetDeviceConfig(std::vector<WifiDeviceConfig> &results) = 0;
    virtual int GetDeviceConfig(const int &networkId, WifiDeviceConfig &config) = 0;
    virtual int GetDeviceConfig(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config) = 0;
    virtual int GetDeviceConfig(const std::string &index, const int &indexType, WifiDeviceConfig &config) = 0;
    virtual int SetDeviceState(int networkId, int state, bool bSetOther = false) = 0;
    virtual int SyncDeviceConfig() = 0;
    virtual int ReloadDeviceConfig() = 0;
    virtual int SetCountryCode(const std::string &countryCode) = 0;
    virtual int GetCountryCode(std::string &countryCode) = 0;
    virtual int GetSignalLevel(const int &rssi, const int &band, int instId = 0) = 0;
    virtual int GetDhcpIpType(int instId = 0) = 0;
    virtual bool GetWhetherToAllowNetworkSwitchover(int instId = 0) = 0;
    virtual int GetSavedDeviceAppraisalPriority(int instId = 0) = 0;
    virtual int GetExternDeviceAppraisalPriority() = 0;
    virtual int GetScoretacticsScoreSlope(int instId = 0) = 0;
    virtual int GetScoretacticsInitScore(int instId = 0) = 0;
    virtual int GetScoretacticsSameBssidScore(int instId = 0) = 0;
    virtual int GetScoretacticsSameNetworkScore(int instId = 0) = 0;
    virtual int GetScoretacticsFrequency5GHzScore(int instId = 0) = 0;
    virtual int GetScoretacticsLastSelectionScore(int instId = 0) = 0;
    virtual int GetScoretacticsSecurityScore(int instId = 0) = 0;
    virtual int SetDeviceAfterConnect(int networkId) = 0;
    virtual int GetCandidateConfig(const int uid, const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config) = 0;
    virtual int GetCandidateConfig(const int uid, const int &networkId, WifiDeviceConfig &config) = 0;
    virtual int GetAllCandidateConfig(const int uid, std::vector<WifiDeviceConfig> &configs) = 0;
    virtual int SetDeviceConnFailedCount(const std::string &index, const int &indexType, int count) = 0;
    virtual int IncreaseDeviceConnFailedCount(const std::string &index, const int &indexType, int count) = 0;
    virtual int SetRealMacAddress(const std::string &macAddress, int instId = 0) = 0;
    virtual int GetRealMacAddress(std::string &macAddress, int instId = 0) = 0;
    virtual int GetScoretacticsNormalScore(int instId = 0) = 0;
    virtual int SetDeviceRandomizedMacSuccessEver(int networkId) = 0;
    virtual int GetPackageFilterMap(std::map<std::string, std::vector<std::string>> &filterMap) = 0;
    virtual int GetMinRssi2Dot4Ghz(int instId = 0) = 0;
    virtual int GetMinRssi5Ghz(int instId = 0) = 0;
    virtual const std::vector<TrustListPolicy> ReloadTrustListPolicies() = 0;
    virtual const MovingFreezePolicy ReloadMovingFreezePolicy() = 0;
    virtual bool EncryptionDeviceConfig(WifiDeviceConfig &config) const = 0;
    virtual bool GetRandomMac(WifiStoreRandomMac &randomMacInfo) = 0;
    virtual bool AddRandomMac(WifiStoreRandomMac &randomMacInfo) = 0;
    virtual int AddWpsDeviceConfig(const WifiDeviceConfig &config) = 0;
    virtual void SetDefaultFrequenciesByCountryBand(const BandType band, std::vector<int> &frequencies,
        int instId = 0) = 0;
    virtual int GetNextNetworkId() = 0;
    virtual int GetDeviceConfig(const std::string &ancoCallProcessName, const std::string &ssid,
            const std::string &keymgmt, WifiDeviceConfig &config) = 0;
    virtual int RemoveExcessDeviceConfigs(std::vector<WifiDeviceConfig> &configs) const = 0;
    virtual void EncryptionWifiDeviceConfigOnBoot()= 0;
    virtual int GetWifiP2pGroupInfo(std::vector<WifiP2pGroupInfo> &groups) = 0;
    virtual std::string FuzzyBssid(const std::string bssid) = 0;
    virtual int GetBlockList(std::vector<StationInfo> &results, int id = 0) = 0;
    virtual int ManageBlockList(const StationInfo &info, int mode, int id = 0) = 0;
    virtual int GetOperatorWifiType(int instId = 0) = 0;
    virtual int SetOperatorWifiType(int type, int instId = 0) = 0;
    virtual int GetLastAirplaneMode(int instId = 0) = 0;
    virtual bool GetCanOpenStaWhenAirplaneMode(int instId = 0) = 0;
    virtual int SetWifiFlagOnAirplaneMode(bool ifOpen, int instId = 0) = 0;
    virtual int GetStaLastRunState(int instId = 0) = 0;
    virtual int SetStaLastRunState(int bRun, int instId = 0) = 0;
    virtual void SetScanOnlySwitchState(const int &state, int instId = 0) = 0;
    virtual  bool IsModulePreLoad(const std::string &name) = 0;
    virtual bool GetConfigValueByName(const std::string &name, std::string &value) = 0;
    virtual int GetHotspotConfig(HotspotConfig &config, int id) = 0;
    virtual int GetVariableMap(std::map<std::string, std::string> &variableMap) = 0;
};

class WifiSettings : public MockWifiSettings {
public:
    WifiSettings() = default;
    ~WifiSettings() = default;
    static WifiSettings &GetInstance(void);

    MOCK_METHOD1(AddDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_METHOD1(RemoveDevice, int(int networkId));
    MOCK_METHOD0(ClearDeviceConfig, void());
    MOCK_METHOD1(GetDeviceConfig, int(std::vector<WifiDeviceConfig> &results));
    MOCK_METHOD2(GetDeviceConfig, int(const int &networkId, WifiDeviceConfig &config));
    MOCK_METHOD3(GetDeviceConfig, int(const std::string &ssid, const std::string &keymgmt, WifiDeviceConfig &config));
    MOCK_METHOD3(GetDeviceConfig, int(const std::string &index, const int &indexType, WifiDeviceConfig &config));
    MOCK_METHOD3(SetDeviceState, int(int networkId, int state, bool bSetOther));
    MOCK_METHOD0(SyncDeviceConfig, int());
    MOCK_METHOD0(ReloadDeviceConfig, int());
    MOCK_METHOD1(SetCountryCode, int(const std::string &countryCode));
    MOCK_METHOD1(GetCountryCode, int(std::string &countryCode));
    MOCK_METHOD3(GetSignalLevel, int(const int &rssi, const int &band, int));
    MOCK_METHOD1(GetDhcpIpType, int(int));
    MOCK_METHOD1(GetWhetherToAllowNetworkSwitchover, bool(int));
    MOCK_METHOD1(GetSavedDeviceAppraisalPriority, int(int));
    MOCK_METHOD0(GetExternDeviceAppraisalPriority, int());
    MOCK_METHOD1(GetScoretacticsScoreSlope, int(int));
    MOCK_METHOD1(GetScoretacticsInitScore, int(int));
    MOCK_METHOD1(GetScoretacticsSameBssidScore, int(int));
    MOCK_METHOD1(GetScoretacticsSameNetworkScore, int(int));
    MOCK_METHOD1(GetScoretacticsFrequency5GHzScore, int(int));
    MOCK_METHOD1(GetScoretacticsLastSelectionScore, int(int));
    MOCK_METHOD1(GetScoretacticsSecurityScore, int(int));
    MOCK_METHOD1(SetDeviceAfterConnect, int(int networkId));
    MOCK_METHOD4(GetCandidateConfig, int(const int uid, const std::string &ssid, const std::string &keymgmt,
        WifiDeviceConfig &config));
    MOCK_METHOD3(GetCandidateConfig, int(const int uid, const int &networkId, WifiDeviceConfig &config));
    MOCK_METHOD2(GetAllCandidateConfig, int(const int uid, std::vector<WifiDeviceConfig> &configs));
    MOCK_METHOD3(SetDeviceConnFailedCount, int(const std::string &index, const int &indexType, int count));
    MOCK_METHOD3(IncreaseDeviceConnFailedCount, int(const std::string &index, const int &indexType, int count));
    MOCK_METHOD2(SetRealMacAddress, int(const std::string &macAddress, int));
    MOCK_METHOD2(GetRealMacAddress, int(std::string &macAddress, int));
    MOCK_METHOD1(GetScoretacticsNormalScore, int(int));
    MOCK_METHOD1(SetDeviceRandomizedMacSuccessEver, int(int networkId));
    MOCK_METHOD1(GetPackageFilterMap,  int(std::map<std::string, std::vector<std::string>> &filterMap));
    MOCK_METHOD1(GetMinRssi2Dot4Ghz, int(int));
    MOCK_METHOD1(GetMinRssi5Ghz, int(int));
    MOCK_METHOD0(ReloadMovingFreezePolicy, const MovingFreezePolicy());
    MOCK_CONST_METHOD1(EncryptionDeviceConfig, bool(WifiDeviceConfig &config));
    MOCK_METHOD1(GetRandomMac, bool(WifiStoreRandomMac &randomMacInfo));
    MOCK_METHOD1(AddRandomMac, bool(WifiStoreRandomMac &randomMacInfo));
    MOCK_METHOD1(AddWpsDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_METHOD3(SetDefaultFrequenciesByCountryBand, void(const BandType band, std::vector<int> &frequencies, int));
    MOCK_METHOD0(GetNextNetworkId, int());
    MOCK_METHOD4(GetDeviceConfig, int(const std::string &ancoCallProcessName, const std::string &ssid,
            const std::string &keymgmt, WifiDeviceConfig &config));
    MOCK_CONST_METHOD1(RemoveExcessDeviceConfigs, int(std::vector<WifiDeviceConfig> &configs));
    MOCK_METHOD0(EncryptionWifiDeviceConfigOnBoot, void());
    MOCK_METHOD1(GetWifiP2pGroupInfo, int(std::vector<WifiP2pGroupInfo> &groups));
    MOCK_METHOD1(FuzzyBssid, std::string(const std::string bssid));
    MOCK_METHOD2(GetBlockList, int(std::vector<StationInfo> &results, int id));
    MOCK_METHOD3(ManageBlockList, int(const StationInfo &info, int mode, int id));
    MOCK_METHOD1(GetOperatorWifiType, int(int instId));
    MOCK_METHOD2(SetOperatorWifiType, int(int type, int instId));
    MOCK_METHOD1(GetLastAirplaneMode, int(int instId));
    MOCK_METHOD1(GetCanOpenStaWhenAirplaneMode, bool(int instId));
    MOCK_METHOD2(SetWifiFlagOnAirplaneMode, int(bool ifOpen, int instId));
    MOCK_METHOD1(GetStaLastRunState, int(int instId));
    MOCK_METHOD2(SetStaLastRunState, int(int bRun, int instId));
    MOCK_METHOD2(SetScanOnlySwitchState, void(const int &state, int instId));
    MOCK_METHOD0(ReloadTrustListPolicies, const std::vector<TrustListPolicy>());
    MOCK_METHOD1(IsModulePreLoad,  bool(const std::string &name));
    MOCK_METHOD2(GetConfigValueByName,  bool(const std::string &name, std::string &value));
    MOCK_METHOD2(GetHotspotConfig,  int(HotspotConfig &config, int id));
    MOCK_METHOD1(GetVariableMap,  int(std::map<std::string, std::string> &variableMap));
};
}  // namespace OHOS
}  // namespace Wifi
#endif