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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_settings.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiSettingsTest");
constexpr int NETWORK_ID = 15;
constexpr int TYPE = 3;
constexpr int SCORE = 0;
constexpr int STATE = 0;
constexpr int UID = 0;
constexpr int ZERO = 0;
constexpr int WIFI_OPT_RETURN = -1;
constexpr int MIN_RSSI_2DOT_4GHZ = -80;
constexpr int MIN_RSSI_5GZ = -77;
class WifiSettingsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiSettingsTest, ClearScanInfoListTest, TestSize.Level1)
{
    WIFI_LOGE("ClearScanInfoListTest enter!");
    int result = WifiSettings::GetInstance().ClearScanInfoList();
    WIFI_LOGE("ClearScanInfoListTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, SetWifiLinkedStandardAndMaxSpeedTest, TestSize.Level1)
{
    WIFI_LOGE("SetWifiLinkedStandardAndMaxSpeedTest enter!");
    WifiLinkedInfo linkInfo;
    int result = WifiSettings::GetInstance().SetWifiLinkedStandardAndMaxSpeed(linkInfo);
    WIFI_LOGE("SetWifiLinkedStandardAndMaxSpeedTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, ClearDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGE("ClearDeviceConfigTest enter!");
    WifiSettings::GetInstance().ClearDeviceConfig();
}

HWTEST_F(WifiSettingsTest, GetDeviceConfig2Test, TestSize.Level1)
{
    WIFI_LOGE("GetDeviceConfig2Test enter!");
    int networkId = ZERO;
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    WIFI_LOGE("GetDeviceConfig2Test result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetDeviceConfig3Test, TestSize.Level1)
{
    WIFI_LOGE("GetDeviceConfig3Test enter!");
    std::string ssid;
    std::string keymgmt;
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetDeviceConfig(ssid, keymgmt, config);
    WIFI_LOGE("GetDeviceConfig3Test result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetDeviceStateTest, TestSize.Level1)
{
    WIFI_LOGE("SetDeviceStateTest enter!");
    int result = WifiSettings::GetInstance().SetDeviceState(NETWORK_ID, WIFI_OPT_RETURN, true);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
    result = WifiSettings::GetInstance().SetDeviceState(NETWORK_ID, NETWORK_ID, true);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
    result = WifiSettings::GetInstance().SetDeviceState(NETWORK_ID, STATE, true);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
    result = WifiSettings::GetInstance().SetDeviceState(SCORE, STATE, true);
    WIFI_LOGE("SetDeviceStateTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetDeviceAfterConnectTest, TestSize.Level1)
{
    WIFI_LOGE("SetDeviceAfterConnectTest enter!");
    int result = WifiSettings::GetInstance().SetDeviceAfterConnect(NETWORK_ID);
    WIFI_LOGE("SetDeviceAfterConnectTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetCandidateConfigTest, TestSize.Level1)
{
    WIFI_LOGE("GetCandidateConfigTest enter!");
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetCandidateConfig(UID, NETWORK_ID, config);
    WIFI_LOGE("GetCandidateConfigTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetAllCandidateConfigTest, TestSize.Level1)
{
    WIFI_LOGE("GetAllCandidateConfigTest enter!");
    std::vector<WifiDeviceConfig> configs;
    int result = WifiSettings::GetInstance().GetAllCandidateConfig(UID, configs);
    WIFI_LOGE("GetAllCandidateConfigTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, IncreaseDeviceConnFailedCountTest, TestSize.Level1)
{
    WIFI_LOGE("IncreaseDeviceConnFailedCountTest enter!");
    std::string index;
    int indexType = ZERO;
    int count = ZERO;
    WifiSettings::GetInstance().SetDeviceConnFailedCount(index, TYPE, count);
    int result = WifiSettings::GetInstance().IncreaseDeviceConnFailedCount(index, indexType, count);
    WIFI_LOGE("IncreaseDeviceConnFailedCountTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetDeviceConnFailedCountTest, TestSize.Level1)
{
    WIFI_LOGE("SetDeviceConnFailedCountTest enter!");
    std::string index;
    int indexType = ZERO;
    int count = ZERO;
    WifiSettings::GetInstance().SetDeviceConnFailedCount(index, TYPE, count);
    int result = WifiSettings::GetInstance().SetDeviceConnFailedCount(index, indexType, count);
    WIFI_LOGE("SetDeviceConnFailedCountTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, AddRandomMacTest, TestSize.Level1)
{
    WIFI_LOGE("AddRandomMacTest enter!");
    WifiStoreRandomMac randomMacInfo;
    bool result = WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
    WIFI_LOGE("AddRandomMacTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, AddRandomMacTest2, TestSize.Level1)
{
    WIFI_LOGE("AddRandomMacTest2 enter!");
    WifiStoreRandomMac randomMacInfo;
    randomMacInfo.ssid = "wifitest1";
    randomMacInfo.keyMgmt = "keyMgmt";
    WifiSettings::GetInstance().mWifiStoreRandomMac.push_back(randomMacInfo);
    bool result = WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
    WIFI_LOGE("AddRandomMacTest result(%{public}d)", result);
    EXPECT_TRUE(result);
    randomMacInfo.ssid = "wifitest221";
    randomMacInfo.keyMgmt = "keyM3gmt";
    result = WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
    WIFI_LOGE("AddRandomMacTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, GetRandomMacTest, TestSize.Level1)
{
    WIFI_LOGE("GetRandomMacTest enter!");
    WifiStoreRandomMac randomMacInfo;
    bool result = WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
    WIFI_LOGE("GetRandomMacTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, RemoveRandomMacTest, TestSize.Level1)
{
    WIFI_LOGE("RemoveRandomMacTest enter!");
    std::string bssid;
    std::string randomMac;
    bool result = WifiSettings::GetInstance().RemoveRandomMac(bssid, randomMac);
    WIFI_LOGE("RemoveRandomMacTest result(%{public}d)", result);
}

HWTEST_F(WifiSettingsTest, SetHotspotIdleTimeoutTest, TestSize.Level1)
{
    WIFI_LOGE("SetHotspotIdleTimeoutTest enter!");
    int result = WifiSettings::GetInstance().SetHotspotIdleTimeout(STATE);
    WIFI_LOGE("SetHotspotIdleTimeoutTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetHotspotIdleTimeoutTest, TestSize.Level1)
{
    WIFI_LOGE("GetHotspotIdleTimeoutTest enter!");
    int result = WifiSettings::GetInstance().GetHotspotIdleTimeout();
    WIFI_LOGE("GetHotspotIdleTimeoutTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, FindConnStationTest, TestSize.Level1)
{
    WIFI_LOGE("FindConnStationTest enter!");
    StationInfo info;
    int id = ZERO;
    int result = WifiSettings::GetInstance().FindConnStation(info, id);
    WIFI_LOGE("FindConnStationTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetPowerModelTest, TestSize.Level1)
{
    WIFI_LOGE("SetPowerModelTest enter!");
    int id = ZERO;
    int result = WifiSettings::GetInstance().SetPowerModel(PowerModel::GENERAL, id);
    WIFI_LOGE("SetPowerModelTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetPowerModelTest, TestSize.Level1)
{
    WIFI_LOGE("GetPowerModelTest enter!");
    PowerModel model;
    int result = WifiSettings::GetInstance().GetPowerModel(model, ZERO);
    WIFI_LOGE("GetPowerModelTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, SetP2pConnectedStateTest, TestSize.Level1)
{
    WIFI_LOGE("SetP2pConnectedStateTest enter!");
    int result = WifiSettings::GetInstance().SetP2pConnectedState(STATE);
    WIFI_LOGE("SetP2pConnectedStateTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, UpdateLinkedChannelWidthTest, TestSize.Level1)
{
    WIFI_LOGE("UpdateLinkedChannelWidthTest enter!");
    std::string bssid;
    WifiSettings::GetInstance().UpdateLinkedChannelWidth(bssid, WifiChannelWidth::WIDTH_80MHZ);
}

HWTEST_F(WifiSettingsTest, GetUserLastSelectedNetworkTimeValTest, TestSize.Level1)
{
    WIFI_LOGE("GetUserLastSelectedNetworkTimeValTest enter!");
    WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal();
    WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal(NETWORK_ID);
}

HWTEST_F(WifiSettingsTest, SetOperatorWifiTypeTest, TestSize.Level1)
{
    WIFI_LOGE("SetOperatorWifiTypeTest enter!");
    int result = WifiSettings::GetInstance().SetOperatorWifiType(SCORE);
    WIFI_LOGE("SetOperatorWifiTypeTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetDefaultWifiInterfaceTest, TestSize.Level1)
{
    WIFI_LOGE("GetDefaultWifiInterfaceTest enter!");
    WifiSettings::GetInstance().GetDefaultWifiInterface();
    WifiSettings::GetInstance().GetDefaultWifiInterface(NETWORK_ID);
}

HWTEST_F(WifiSettingsTest, SetWhetherToAllowNetworkSwitchoverTest, TestSize.Level1)
{
    WIFI_LOGE("SetWhetherToAllowNetworkSwitchoverTest enter!");
    int result = WifiSettings::GetInstance().SetWhetherToAllowNetworkSwitchover(true);
    WIFI_LOGE("SetWhetherToAllowNetworkSwitchoverTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetWhetherToAllowNetworkSwitchoverTest, TestSize.Level1)
{
    WIFI_LOGE("GetWhetherToAllowNetworkSwitchoverTest enter!");
    WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover(NETWORK_ID);
    bool result = WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover();
    WIFI_LOGE("GetWhetherToAllowNetworkSwitchoverTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, SetScoretacticsInitScoreTest, TestSize.Level1)
{
    WIFI_LOGE("SetScoretacticsInitScoreTest enter!");
    int result = WifiSettings::GetInstance().SetScoretacticsInitScore(SCORE);
    WIFI_LOGE("SetScoretacticsInitScoreTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetScoretacticsInitScoreTest, TestSize.Level1)
{
    WIFI_LOGE("GetScoretacticsInitScoreTest enter!");
    WifiSettings::GetInstance().GetScoretacticsInitScore(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetScoretacticsInitScore();
    WIFI_LOGE("GetScoretacticsInitScoreTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, SetScoretacticsNormalScoreTest, TestSize.Level1)
{
    WIFI_LOGE("SetScoretacticsNormalScoreTest enter!");
    int result = WifiSettings::GetInstance().SetScoretacticsNormalScore(SCORE);
    WIFI_LOGE("SetScoretacticsNormalScoreTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetScoretacticsNormalScoreTest, TestSize.Level1)
{
    WIFI_LOGE("GetScoretacticsNormalScoreTest enter!");
    WifiSettings::GetInstance().GetScoretacticsNormalScore(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetScoretacticsNormalScore();
    WIFI_LOGE("GetScoretacticsNormalScoreTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, IsModulePreLoadTest, TestSize.Level1)
{
    WIFI_LOGE("IsModulePreLoadTest enter!");
    bool state = WifiSettings::GetInstance().IsModulePreLoad("wifitest");
    EXPECT_FALSE(state);
    WifiSettings::GetInstance().IsModulePreLoad("StaService");
    WifiSettings::GetInstance().IsModulePreLoad("ScanService");
    WifiSettings::GetInstance().IsModulePreLoad("ApService");
    WifiSettings::GetInstance().IsModulePreLoad("P2pService");
    WifiSettings::GetInstance().IsModulePreLoad("AwareService");
    WifiSettings::GetInstance().IsModulePreLoad("EnhanceService");
}

HWTEST_F(WifiSettingsTest, GetSupportHwPnoFlagTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportHwPnoFlagTest enter!");
    bool state = WifiSettings::GetInstance().GetSupportHwPnoFlag(NETWORK_ID);
    EXPECT_TRUE(state);
    bool result = WifiSettings::GetInstance().GetSupportHwPnoFlag();
    WIFI_LOGE("GetSupportHwPnoFlagTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, GetMinRssi2Dot4GhzTest, TestSize.Level1)
{
    WIFI_LOGE("GetMinRssi2Dot4GhzTest enter!");
    WifiSettings::GetInstance().GetMinRssi2Dot4Ghz(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetMinRssi2Dot4Ghz();
    WIFI_LOGE("GetMinRssi2Dot4GhzTest result(%{public}d)", result);
    EXPECT_EQ(result, MIN_RSSI_2DOT_4GHZ);
}

HWTEST_F(WifiSettingsTest, GetMinRssi5GhzTest, TestSize.Level1)
{
    WIFI_LOGE("GetMinRssi5GhzTest enter!");
    WifiSettings::GetInstance().GetMinRssi5Ghz(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetMinRssi5Ghz();
    WIFI_LOGE("GetMinRssi5GhzTest result(%{public}d)", result);
    EXPECT_EQ(result, MIN_RSSI_5GZ);
}

HWTEST_F(WifiSettingsTest, GetStrDnsBakTest, TestSize.Level1)
{
    WIFI_LOGE("GetStrDnsBakTest enter!");
    WifiSettings::GetInstance().GetStrDnsBak(NETWORK_ID);
    WifiSettings::GetInstance().GetStrDnsBak();
}
 
HWTEST_F(WifiSettingsTest, IsLoadStabakTest, TestSize.Level1)
{
    WIFI_LOGE("IsLoadStabakTest enter!");
    bool state = WifiSettings::GetInstance().IsLoadStabak(NETWORK_ID);
    EXPECT_TRUE(state);
    bool result = WifiSettings::GetInstance().IsLoadStabak();
    WIFI_LOGE("IsLoadStabakTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, SetRealMacAddressTest, TestSize.Level1)
{
    WIFI_LOGE("SetRealMacAddressTest enter!");
    std::string macAddress;
    int result = WifiSettings::GetInstance().SetRealMacAddress(macAddress);
    WIFI_LOGE("SetRealMacAddressTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetRealMacAddressTest, TestSize.Level1)
{
    WIFI_LOGE("GetRealMacAddressTest enter!");
    std::string macAddress;
    int state = WifiSettings::GetInstance().GetRealMacAddress(macAddress, NETWORK_ID);
    EXPECT_EQ(state, WIFI_OPT_SUCCESS);
    int result = WifiSettings::GetInstance().GetRealMacAddress(macAddress);
    WIFI_LOGE("GetRealMacAddressTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetConnectTimeoutBssidTest, TestSize.Level1)
{
    WIFI_LOGE("GetConnectTimeoutBssidTest enter!");
    WifiSettings::GetInstance().GetConnectTimeoutBssid();
}

HWTEST_F(WifiSettingsTest, SetConnectTimeoutBssidTest, TestSize.Level1)
{
    WIFI_LOGE("SetConnectTimeoutBssidTest enter!");
    std::string bssid;
    int result = WifiSettings::GetInstance().SetConnectTimeoutBssid(bssid);
    WIFI_LOGE("SetConnectTimeoutBssidTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, SetDefaultFrequenciesByCountryBandTest, TestSize.Level1)
{
    WIFI_LOGE("SetDefaultFrequenciesByCountryBandTest enter!");
    std::vector<int> frequencies;
    WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, frequencies);
}

HWTEST_F(WifiSettingsTest, SetThermalLevelTest, TestSize.Level1)
{
    WIFI_LOGE("SetThermalLevelTest enter!");
    WifiSettings::GetInstance().SetThermalLevel(ZERO);
}

HWTEST_F(WifiSettingsTest, GetThermalLevelTest, TestSize.Level1)
{
    WIFI_LOGE("GetThermalLevelTest enter!");
    int result = WifiSettings::GetInstance().GetThermalLevel();
    WIFI_LOGE("GetThermalLevelTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetThreadStatusFlagTest, TestSize.Level1)
{
    WIFI_LOGE("GetThreadStatusFlagTest enter!");
    bool result = WifiSettings::GetInstance().GetThreadStatusFlag();
    WIFI_LOGE("GetThreadStatusFlagTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, GetThreadStartTimeTest, TestSize.Level1)
{
    WIFI_LOGE("GetThreadStartTimeTest enter!");
    WifiSettings::GetInstance().GetThreadStartTime();
}

HWTEST_F(WifiSettingsTest, GetDisconnectedReasonTest, TestSize.Level1)
{
    WIFI_LOGE("GetDisconnectedReasonTest enter!");
    DisconnectedReason discReason;
    int result = WifiSettings::GetInstance().GetDisconnectedReason(discReason);
    WIFI_LOGE("GetDisconnectedReasonTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, SetScanOnlySwitchStateTest, TestSize.Level1)
{
    WIFI_LOGE("SetScanOnlySwitchStateTest enter!");
    WifiSettings::GetInstance().SetScanOnlySwitchState(STATE);
}

HWTEST_F(WifiSettingsTest, GetScanOnlySwitchStateTest, TestSize.Level1)
{
    WIFI_LOGE("GetScanOnlySwitchStateTest enter!");
    int result = WifiSettings::GetInstance().GetScanOnlySwitchState(NETWORK_ID);
    result = WifiSettings::GetInstance().GetScanOnlySwitchState();
    WIFI_LOGE("GetScanOnlySwitchStateTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, CheckScanOnlyAvailableTest, TestSize.Level1)
{
    WIFI_LOGE("CheckScanOnlyAvailableTest enter!");
    WifiSettings::GetInstance().CheckScanOnlyAvailable(NETWORK_ID);
    bool result = WifiSettings::GetInstance().CheckScanOnlyAvailable();
    WIFI_LOGE("CheckScanOnlyAvailableTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, GetStaApExclusionTypeTest, TestSize.Level1)
{
    WIFI_LOGE("GetStaApExclusionTypeTest enter!");
    int result = WifiSettings::GetInstance().GetStaApExclusionType();
    WIFI_LOGE("GetStaApExclusionTypeTest result(%{public}d)", result);
    EXPECT_TRUE(result == WIFI_OPT_SUCCESS || result == TYPE);
}

HWTEST_F(WifiSettingsTest, SetStaApExclusionTypeTest, TestSize.Level1)
{
    WIFI_LOGE("SetStaApExclusionTypeTest enter!");
    int result = WifiSettings::GetInstance().SetStaApExclusionType(SCORE);
    WIFI_LOGE("SetStaApExclusionTypeTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, StoreWifiMacAddrPairInfoTest, TestSize.Level1)
{
    WIFI_LOGE("StoreWifiMacAddrPairInfoTest enter!");
    std::string realMacAddr;
    bool result = WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
        realMacAddr, "");
    WIFI_LOGE("StoreWifiMacAddrPairInfoTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, RemoveMacAddrPairsTest, TestSize.Level1)
{
    WIFI_LOGE("RemoveMacAddrPairsTest enter!");
    WifiMacAddrInfo macAddrInfo;
    int result = WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
        macAddrInfo);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    result = WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO,
        macAddrInfo);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    result = WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO,
        macAddrInfo);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    result = WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO,
        macAddrInfo);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    result = WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::INVALID_MACADDR_INFO,
        macAddrInfo);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
    result = WifiSettings::GetInstance().RemoveMacAddrPairs(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO,
        macAddrInfo);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    WIFI_LOGE("RemoveMacAddrPairsTest result(%{public}d)", result);
}

HWTEST_F(WifiSettingsTest, GetMacAddrPairsTest, TestSize.Level1)
{
    WIFI_LOGE("GetMacAddrPairsTest enter!");
    WifiMacAddrInfo macAddrInfo;
    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO, macAddrInfo);
    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, macAddrInfo);
    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, macAddrInfo);
    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::INVALID_MACADDR_INFO, macAddrInfo);
    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, macAddrInfo);
    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, macAddrInfo);
}

HWTEST_F(WifiSettingsTest, PrintMacAddrPairsTest, TestSize.Level1)
{
    WIFI_LOGE("PrintMacAddrPairsTest enter!");
    WifiSettings::GetInstance().PrintMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO);
    WifiSettings::GetInstance().PrintMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO);
    WifiSettings::GetInstance().PrintMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO);
    WifiSettings::GetInstance().PrintMacAddrPairs(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO);
    WifiSettings::GetInstance().PrintMacAddrPairs(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO);
    WifiSettings::GetInstance().PrintMacAddrPairs(WifiMacAddrInfoType::INVALID_MACADDR_INFO);
}

HWTEST_F(WifiSettingsTest, ClearMacAddrPairsTest, TestSize.Level1)
{
    WIFI_LOGE("ClearMacAddrPairsTest enter!");
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO);
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO);
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO);
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::INVALID_MACADDR_INFO);
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO);
}

HWTEST_F(WifiSettingsTest, MergeWifiConfigTest, TestSize.Level1)
{
    WIFI_LOGI("MergeWifiConfigTest enter");
    WifiSettings::GetInstance().MergeWifiConfig();
}

HWTEST_F(WifiSettingsTest, MergeSoftapConfigTest, TestSize.Level1)
{
    WIFI_LOGI("MergeSoftapConfigTest enter");
    WifiSettings::GetInstance().MergeSoftapConfig();
}

HWTEST_F(WifiSettingsTest, MergeWifiCloneConfigTest, TestSize.Level1)
{
    WIFI_LOGI("MergeWifiCloneConfigTest enter");
    std::string cloneConfig = "wifitest";
    WifiSettings::GetInstance().MergeWifiCloneConfig(cloneConfig);
}

HWTEST_F(WifiSettingsTest, ConfigsDeduplicateAndSaveTest, TestSize.Level1)
{
    WIFI_LOGI("ConfigsDeduplicateAndSaveTest enter");
    WifiDeviceConfig config;
    config.ssid = "test";
    config.keyMgmt = "WPA-PSK";
    std::vector<WifiDeviceConfig> configs;
    configs.push_back(config);
    WifiSettings::GetInstance().ConfigsDeduplicateAndSave(configs);
}

HWTEST_F(WifiSettingsTest, RemoveMacAddrPairInfoTest, TestSize.Level1)
{
    WIFI_LOGI("RemoveMacAddrPairInfoTest enter");
    std::string randomMacAddr = "wifisettings";
    WifiSettings::GetInstance().RemoveMacAddrPairInfo(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO, randomMacAddr);
}

HWTEST_F(WifiSettingsTest, GetOperatorWifiTypeTest, TestSize.Level1)
{
    WIFI_LOGI("GetOperatorWifiTypeTest enter");
    WifiSettings::GetInstance().GetOperatorWifiType();
    WifiSettings::GetInstance().GetOperatorWifiType(NETWORK_ID);
}

HWTEST_F(WifiSettingsTest, GetCanOpenStaWhenAirplaneModeTest, TestSize.Level1)
{
    WIFI_LOGI("GetCanOpenStaWhenAirplaneModeTest enter");
    WifiSettings::GetInstance().GetCanOpenStaWhenAirplaneMode(NETWORK_ID);
}

HWTEST_F(WifiSettingsTest, GetIpv6InfoTest, TestSize.Level1)
{
    WIFI_LOGI("GetIpv6InfoTest enter");
    IpV6Info info;
    WifiSettings::GetInstance().GetIpv6Info(info);
    WifiSettings::GetInstance().GetIpv6Info(info, NETWORK_ID);
}

HWTEST_F(WifiSettingsTest, AddWpsDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("AddWpsDeviceConfigTest enter");
    WifiDeviceConfig config;
    WifiSettings::GetInstance().AddWpsDeviceConfig(config);
}

HWTEST_F(WifiSettingsTest, GetDeviceConfig5Test, TestSize.Level1)
{
    WIFI_LOGE("GetDeviceConfig5Test enter!");
    std::string ProcessName = "wifitest";
    int indexType = STATE;
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetDeviceConfig(ProcessName, indexType, config);
    WIFI_LOGE("GetDeviceConfig5Test result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GenerateRandomMacAddressTest, TestSize.Level1)
{
    WIFI_LOGI("GenerateRandomMacAddressTest enter");
    std::string randomMac;
    WifiSettings::GetInstance().GenerateRandomMacAddress(randomMac);
}

HWTEST_F(WifiSettingsTest, GetRandomTest, TestSize.Level1)
{
    WIFI_LOGI("GetRandomTest enter");
    WifiSettings::GetInstance().GetRandom();
}

HWTEST_F(WifiSettingsTest, GetRandomMacAddrTest, TestSize.Level1)
{
    WIFI_LOGI("GetRandomMacAddrTest enter");
    WifiMacAddrInfoType type = WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO;
    std::string randomMac;
    WifiSettings::GetInstance().GetRandomMacAddr(type, randomMac);
}

HWTEST_F(WifiSettingsTest, AddMacAddrPairsTest, TestSize.Level1)
{
    WIFI_LOGI("AddMacAddrPairsTest enter");
    WifiMacAddrInfoType type = WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO;
    WifiMacAddrInfo macAddrInfo;
    std::string randomMac;
    macAddrInfo.bssid = "";
    WifiMacAddrErrCode result = WifiSettings::GetInstance().AddMacAddrPairs(type, macAddrInfo, randomMac);
    EXPECT_EQ(result, WIFI_MACADDR_INVALID_PARAM);
}

HWTEST_F(WifiSettingsTest, AddMacAddrPairsTest2, TestSize.Level1)
{
    WIFI_LOGI("AddMacAddrPairsTest2 enter");
    WifiMacAddrInfo macAddrInfo;
    std::string randomMac;
    WifiMacAddrErrCode result = WifiSettings::GetInstance().AddMacAddrPairs(
        WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO, macAddrInfo, randomMac);
    EXPECT_EQ(result, WIFI_MACADDR_INVALID_PARAM);
    result = WifiSettings::GetInstance().AddMacAddrPairs(
        WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, macAddrInfo, randomMac);
    EXPECT_EQ(result, WIFI_MACADDR_INVALID_PARAM);
    result = WifiSettings::GetInstance().AddMacAddrPairs(
        WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, macAddrInfo, randomMac);
    EXPECT_EQ(result, WIFI_MACADDR_INVALID_PARAM);
    result = WifiSettings::GetInstance().AddMacAddrPairs(
        WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO, macAddrInfo, randomMac);
    EXPECT_EQ(result, WIFI_MACADDR_INVALID_PARAM);
    result = WifiSettings::GetInstance().AddMacAddrPairs(
        WifiMacAddrInfoType::INVALID_MACADDR_INFO, macAddrInfo, randomMac);
    EXPECT_EQ(result, WIFI_MACADDR_INVALID_PARAM);
}

HWTEST_F(WifiSettingsTest, ClearHotspotConfigTest, TestSize.Level1)
{
    WIFI_LOGI("ClearHotspotConfigTest enter");
    WifiSettings::GetInstance().ClearHotspotConfig();
}

HWTEST_F(WifiSettingsTest, ManageStationTest, TestSize.Level1)
{
    WIFI_LOGI("ManageStationTest enter");
    int count = 2;
    StationInfo info;
    int result = WifiSettings::GetInstance().ManageStation(info, SCORE, 0);
    EXPECT_EQ(result, 0);
    result = WifiSettings::GetInstance().ManageStation(info, 1, 0);
    EXPECT_EQ(result, 0);
    result = WifiSettings::GetInstance().ManageStation(info, count, 0);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiSettingsTest, SetDeviceStateTest1, TestSize.Level1)
{
    WIFI_LOGI("SetDeviceStateTest enter");
    WifiDeviceConfig config;
    WifiSettings::GetInstance().mWifiDeviceConfig.emplace(SCORE, config);
    int result = WifiSettings::GetInstance().SetDeviceState(SCORE, SCORE, true);
    EXPECT_EQ(result, 0);
    result = WifiSettings::GetInstance().SetDeviceState(SCORE, SCORE, false);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiSettingsTest, GetDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("GetDeviceConfigTest enter");
    std::string ancoCallProcessName = "wifitest";
    std::string ssid = "0123//45";
    std::string keymgmt = "WPA";
    WifiDeviceConfig config;
    WifiDeviceConfig configs;
    config.ssid = "0123//45";
    config.keyMgmt = "WPA";
    config.ancoCallProcessName = "wifitest";
    config.wifiEapConfig.clientCert = "//twifitest";
    WifiSettings::GetInstance().mWifiDeviceConfig.emplace(SCORE, config);
    WifiSettings::GetInstance().mWifiDeviceConfig.emplace(SCORE, configs);
    int result = WifiSettings::GetInstance().GetDeviceConfig(ancoCallProcessName, ssid, keymgmt, config);
    EXPECT_EQ(result, -1);
    result = WifiSettings::GetInstance().GetDeviceConfig(ssid, keymgmt, config);
    EXPECT_EQ(result, -1);
    WifiSettings::GetInstance().ClearDeviceConfig();
}

HWTEST_F(WifiSettingsTest, RemoveWifiP2pSupplicantGroupInfoTets, TestSize.Level1)
{
    WifiSettings::GetInstance().RemoveWifiP2pSupplicantGroupInfo();
}

HWTEST_F(WifiSettingsTest, EncryptionWifiDeviceConfigOnBootTest, TestSize.Level1)
{
    WIFI_LOGI("EncryptionWifiDeviceConfigOnBootTest enter");
    WifiSettings::GetInstance().EncryptionWifiDeviceConfigOnBoot();
}

HWTEST_F(WifiSettingsTest, EncryptionDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("EncryptionDeviceConfigTest enter");
    WifiDeviceConfig config;
    config.preSharedKey = "12345678";
    WifiSettings::GetInstance().EncryptionDeviceConfig(config);
}

HWTEST_F(WifiSettingsTest, DecryptionDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("DecryptionDeviceConfigTest enter");
    WifiDeviceConfig config;
    config.preSharedKey = "12345678";
    WifiSettings::GetInstance().DecryptionDeviceConfig(config);
}

HWTEST_F(WifiSettingsTest, IsWifiDeviceConfigDecipheredTest, TestSize.Level1)
{
    WIFI_LOGI("IsWifiDeviceConfigDecipheredTest enter");
    WifiDeviceConfig config;
    config.preSharedKey = "12345678";
    WifiSettings::GetInstance().IsWifiDeviceConfigDeciphered(config);
}

}  // namespace Wifi
}  // namespace OHO