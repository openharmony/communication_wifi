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

#include "wifi_config_center_test.h"
#include "wifi_global_func.h"
#include "wifi_internal_msg.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

constexpr int TEN = 10;

HWTEST_F(WifiConfigCenterTest, SetGetWifiMidState_SUCCESS, TestSize.Level1)
{
    WifiOprMidState state = OHOS::Wifi::WifiOprMidState::RUNNING;
    WifiConfigCenter::GetInstance().SetWifiMidState(state);
    EXPECT_EQ(state, WifiConfigCenter::GetInstance().GetWifiMidState());
}

HWTEST_F(WifiConfigCenterTest, SetWifiMidStateExp_SUCCESS, TestSize.Level1)
{
    WifiOprMidState cloState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState runState = OHOS::Wifi::WifiOprMidState::RUNNING;
    WifiConfigCenter::GetInstance().SetWifiMidState(cloState);
    EXPECT_EQ(true, WifiConfigCenter::GetInstance().SetWifiMidState(cloState, runState));
}

HWTEST_F(WifiConfigCenterTest, SetWifiMidStateExp_FAILED, TestSize.Level1)
{
    WifiOprMidState cloState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState runState = OHOS::Wifi::WifiOprMidState::RUNNING;
    WifiConfigCenter::GetInstance().SetWifiMidState(cloState);
    EXPECT_NE(true, WifiConfigCenter::GetInstance().SetWifiMidState(runState, cloState));
}

HWTEST_F(WifiConfigCenterTest, GetWifiStaIntervalTest, TestSize.Level1)
{
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime();
    sleep(1);
    double interval = WifiConfigCenter::GetInstance().GetWifiStaInterval();
    EXPECT_TRUE(interval >= 1000 && interval <= 2000);
}

HWTEST_F(WifiConfigCenterTest, GetWifiAllowSemiActiveTest01, TestSize.Level1)
{
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetWifiAllowSemiActive(), false);
}

HWTEST_F(WifiConfigCenterTest, GetWifiStateTest01, TestSize.Level1)
{
    int state = 0;
    int instId = 1;
    WifiConfigCenter::GetInstance().SetWifiState(state, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetWifiState(state), 1);
}

HWTEST_F(WifiConfigCenterTest, GetWifiDetailStateTest01, TestSize.Level1)
{
    int instId = 1;
    WifiDetailState state = WifiDetailState::STATE_UNKNOWN;
    WifiConfigCenter::GetInstance().SetWifiDetailState(state, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetWifiDetailState(instId), WifiDetailState::STATE_UNKNOWN);
}

HWTEST_F(WifiConfigCenterTest, GetIpInfoTest01, TestSize.Level1)
{
    int instId = 1;
    IpInfo info;
    WifiConfigCenter::GetInstance().SaveIpInfo(info, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetIpInfo(info, instId), 0);
}

HWTEST_F(WifiConfigCenterTest, GetIpv6InfoTest01, TestSize.Level1)
{
    int instId = 1;
    IpV6Info info;
    WifiConfigCenter::GetInstance().SaveIpV6Info(info, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetIpv6Info(info, instId), 0);
}

HWTEST_F(WifiConfigCenterTest, GetLinkedInfoTest01, TestSize.Level1)
{
    int instId = 1;
    WifiLinkedInfo info;
    WifiLinkedInfo info1;
    info.channelWidth = WifiChannelWidth::WIDTH_40MHZ;
    info.bssid = "TEST";
    WifiConfigCenter::GetInstance().SaveLinkedInfo(info, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetLinkedInfo(info1, instId), 0);
}

HWTEST_F(WifiConfigCenterTest, GetLastConnStaFreqTest01, TestSize.Level1)
{
    int lastConnStaFreq = 5200;
    WifiConfigCenter::GetInstance().SetLastConnStaFreq(lastConnStaFreq);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetLastConnStaFreq(), lastConnStaFreq);
}

HWTEST_F(WifiConfigCenterTest, GetMacAddressTest01, TestSize.Level1)
{
    std::string macAddress = "TEST";
    std::string macAddress1;
    int instId = 1;
    WifiConfigCenter::GetInstance().SetMacAddress(macAddress, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetMacAddress(macAddress1, instId), 0);
}

HWTEST_F(WifiConfigCenterTest, GetUserLastSelectedNetworkIdTest01, TestSize.Level1)
{
    int instId = 1;
    int networkId = 1;
    WifiConfigCenter::GetInstance().SetUserLastSelectedNetworkId(networkId, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetUserLastSelectedNetworkId(instId), 1);
}

HWTEST_F(WifiConfigCenterTest, GetUserLastSelectedNetworkTimeValTest01, TestSize.Level1)
{
    int instId = 1;
    int networkId = 1;
    WifiConfigCenter::GetInstance().SetUserLastSelectedNetworkId(networkId, instId);
    EXPECT_NE(WifiConfigCenter::GetInstance().GetUserLastSelectedNetworkTimeVal(instId), 0);
}

HWTEST_F(WifiConfigCenterTest, SetConnectTimeoutBssidTest01, TestSize.Level1)
{
    std::string bssid = "TEST";
    int instId = 1;
    EXPECT_EQ(WifiConfigCenter::GetInstance().SetConnectTimeoutBssid(bssid, instId), 0);
}

HWTEST_F(WifiConfigCenterTest, GetDisconnectedReasonTest01, TestSize.Level1)
{
    DisconnectedReason discReason = DisconnectedReason::DISC_REASON_DEFAULT;
    int instId = 1;
    WifiConfigCenter::GetInstance().SaveDisconnectedReason(discReason, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetDisconnectedReason(discReason, instId), 0);
}

HWTEST_F(WifiConfigCenterTest, InsertWifiCategoryBlackListCacheTest01, TestSize.Level1)
{
    int blacklistType = 1;
    std::string currentBssid = "TEST";
    WifiCategoryBlackListInfo wifiBlackListInfo;
    WifiConfigCenter::GetInstance().InsertWifiCategoryBlackListCache(blacklistType, currentBssid, wifiBlackListInfo);
    WifiConfigCenter::GetInstance().RemoveWifiCategoryBlackListCache(blacklistType, currentBssid);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, GetWifiCategoryBlackListCacheTest01, TestSize.Level1)
{
    int blacklistType = 0;
    std::map<std::string, WifiCategoryBlackListInfo> blackListCache;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetWifiCategoryBlackListCache(blacklistType, blackListCache), 0);
}

HWTEST_F(WifiConfigCenterTest, UpdateWifiConnectFailListCacheTest01, TestSize.Level1)
{
    int blacklistType = 0;
    std::string bssid = "TEST";
    WifiCategoryConnectFailInfo wifiConnectFailInfo;
    std::map<std::string, WifiCategoryBlackListInfo> blackListCache;
    WifiConfigCenter::GetInstance().UpdateWifiConnectFailListCache(blacklistType, bssid, wifiConnectFailInfo);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, RemoveWifiConnectFailListCacheTest01, TestSize.Level1)
{
    std::string bssid = "TEST";
    WifiConfigCenter::GetInstance().RemoveWifiConnectFailListCache(bssid);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, EnableNetworkTest01, TestSize.Level1)
{
    int networkId = 1;
    bool disableOthers = true;
    int instId = 1;
    EXPECT_EQ(WifiConfigCenter::GetInstance().EnableNetwork(networkId, disableOthers, instId), true);
}

HWTEST_F(WifiConfigCenterTest, GetScanMidStateTest01, TestSize.Level1)
{
    WifiOprMidState expState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState state = OHOS::Wifi::WifiOprMidState::CLOSED;
    int instId = 1;
    WifiConfigCenter::GetInstance().SetScanMidState(expState, state, instId);
    WifiConfigCenter::GetInstance().SetScanMidState(state, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetScanMidState(instId), OHOS::Wifi::WifiOprMidState::CLOSED);
}

HWTEST_F(WifiConfigCenterTest, GetWifiScanOnlyMidStateTest01, TestSize.Level1)
{
    WifiOprMidState expState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState state = OHOS::Wifi::WifiOprMidState::CLOSED;
    int instId = 1;
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(expState, state, instId);
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(state, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(instId), OHOS::Wifi::WifiOprMidState::CLOSED);
}

HWTEST_F(WifiConfigCenterTest, SetWifiLinkedStandardAndMaxSpeedTest01, TestSize.Level1)
{
    WifiLinkedInfo linkInfo;
    linkInfo.bssid = "TEST";
    EXPECT_EQ(WifiConfigCenter::GetInstance().SetWifiLinkedStandardAndMaxSpeed(linkInfo), 0);
}

HWTEST_F(WifiConfigCenterTest, GetConnectedBssidTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetConnectedBssid(instId), "");
}

HWTEST_F(WifiConfigCenterTest, GetApMidStateTest01, TestSize.Level1)
{
    WifiOprMidState expState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState state = OHOS::Wifi::WifiOprMidState::CLOSED;
    int id = 1;
    WifiConfigCenter::GetInstance().SetApMidState(expState, state, id);
    WifiConfigCenter::GetInstance().SetApMidState(state, id);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetApMidState(id), OHOS::Wifi::WifiOprMidState::CLOSED);
}

HWTEST_F(WifiConfigCenterTest, GetHotspotStateTest01, TestSize.Level1)
{
    int state = 1;
    int id = 1;
    WifiConfigCenter::GetInstance().SetHotspotState(state, id);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetHotspotState(id), 1);
}

HWTEST_F(WifiConfigCenterTest, GetPowerModelTest01, TestSize.Level1)
{
    PowerModel model = PowerModel::GENERAL;
    int id = 1;
    WifiConfigCenter::GetInstance().SetPowerModel(model, id);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetPowerModel(model, id), 0);
}

HWTEST_F(WifiConfigCenterTest, GetStationListTest01, TestSize.Level1)
{
    std::vector<StationInfo> results;
    int id = 1;
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetStationList(results, id), 0);
}

HWTEST_F(WifiConfigCenterTest, ManageStationTest01, TestSize.Level1)
{
    StationInfo info;
    info.bssid = "TEST";
    int mode = MODE_ADD;
    int id = 1;
    EXPECT_EQ(WifiConfigCenter::GetInstance().ManageStation(info, mode, id), 0);

    mode = MODE_DEL;
    EXPECT_EQ(WifiConfigCenter::GetInstance().ManageStation(info, mode, id), 0);
    mode = 3;
    EXPECT_EQ(WifiConfigCenter::GetInstance().ManageStation(info, mode, id), -1);
}

HWTEST_F(WifiConfigCenterTest, GetHid2dUpperSceneTest01, TestSize.Level1)
{
    int uid = 1;
    Hid2dUpperScene scene;
    WifiConfigCenter::GetInstance().SetHid2dUpperScene(uid, scene);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetHid2dUpperScene(uid, scene), 0);
}

HWTEST_F(WifiConfigCenterTest, GetHid2dSceneLastSetTimeTest01, TestSize.Level1)
{
    int64_t setTime = 0;
    WifiConfigCenter::GetInstance().SetHid2dSceneLastSetTime(setTime);
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetHid2dSceneLastSetTime(), 0);
}

HWTEST_F(WifiConfigCenterTest, ClearLocalHid2dInfoTest01, TestSize.Level1)
{
    int uid = 1;
    WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(uid);

    uid = 0;
    WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(uid);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, SetWifiStateOnAirplaneChangedTest01, TestSize.Level1)
{
    int state = MODE_STATE_OPEN;
    WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(state);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, GetWifiToggledEnableTest01, TestSize.Level1)
{
    int id = 1;
    WifiConfigCenter::GetInstance().GetWifiToggledEnable(id);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, SetWifiToggledStateTest01, TestSize.Level1)
{
    int state = 1;
    int id = 1;
    WifiConfigCenter::GetInstance().SetWifiToggledState(state, id);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, SetThreadStatusFlagTest01, TestSize.Level1)
{
    bool state = true;
    WifiConfigCenter::GetInstance().SetThreadStatusFlag(state);
    WifiConfigCenter::GetInstance().SetThreadStatusFlag(false);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, RemoveMacAddrPairsTest01, TestSize.Level1)
{
    WifiMacAddrInfoType type = WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO;
    WifiMacAddrInfo macAddrInfo;
    EXPECT_EQ(WifiConfigCenter::GetInstance().RemoveMacAddrPairs(type, macAddrInfo), 0);
    type = WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO;
    EXPECT_EQ(WifiConfigCenter::GetInstance().RemoveMacAddrPairs(type, macAddrInfo), 0);
    type = WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO;
    EXPECT_EQ(WifiConfigCenter::GetInstance().RemoveMacAddrPairs(type, macAddrInfo), 0);
    type = WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO;
    EXPECT_EQ(WifiConfigCenter::GetInstance().RemoveMacAddrPairs(type, macAddrInfo), 0);
    type = WifiMacAddrInfoType::INVALID_MACADDR_INFO;
    EXPECT_EQ(WifiConfigCenter::GetInstance().RemoveMacAddrPairs(type, macAddrInfo), -1);
}

HWTEST_F(WifiConfigCenterTest, GetMacAddrPairsTest01, TestSize.Level1)
{
    WifiMacAddrInfoType type = WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO;
    WifiMacAddrInfo macAddrInfo;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetMacAddrPairs(type, macAddrInfo), "test");
    type = WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetMacAddrPairs(type, macAddrInfo), "test");
    type = WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetMacAddrPairs(type, macAddrInfo), "test");
    type = WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetMacAddrPairs(type, macAddrInfo), "test");
    type = WifiMacAddrInfoType::INVALID_MACADDR_INFO;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetMacAddrPairs(type, macAddrInfo), "test");
}

HWTEST_F(WifiConfigCenterTest, ClearMacAddrPairsTest01, TestSize.Level1)
{
    WifiMacAddrInfoType type = WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO;
    WifiConfigCenter::GetInstance().ClearMacAddrPairs(type);
    type = WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO;
    WifiConfigCenter::GetInstance().ClearMacAddrPairs(type);
    type = WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO;
    WifiConfigCenter::GetInstance().ClearMacAddrPairs(type);
    type = WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO;
    WifiConfigCenter::GetInstance().ClearMacAddrPairs(type);
    type = WifiMacAddrInfoType::INVALID_MACADDR_INFO;
    WifiConfigCenter::GetInstance().ClearMacAddrPairs(type);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, HasWifiActiveTest01, TestSize.Level1)
{
    int state = 2;
    int instId = 1;
    WifiConfigCenter::GetInstance().SetWifiState(state, instId);
    EXPECT_EQ(WifiConfigCenter::GetInstance().HasWifiActive(), true);
}

HWTEST_F(WifiConfigCenterTest, UpdateLinkedInfoTest01, TestSize.Level1)
{
    int instId = 1;
    WifiConfigCenter::GetInstance().UpdateLinkedInfo(instId);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, SetPersistWifiStateTest01, TestSize.Level1)
{
    int state = 1;
    int instId = 1;
    WifiConfigCenter::GetInstance().SetPersistWifiState(state, instId);
    EXPECT_NE(WifiConfigCenter::GetInstance().mWifiIpV6Info.size(), TEN);
}

HWTEST_F(WifiConfigCenterTest, GetPersistWifiStateTest01, TestSize.Level1)
{
    int instId = 3;
    EXPECT_EQ(WifiConfigCenter::GetInstance().GetPersistWifiState(instId), -1);
    instId = 1;
    EXPECT_NE(WifiConfigCenter::GetInstance().GetPersistWifiState(instId), -1);
}

HWTEST_F(WifiConfigCenterTest, AddMacAddrPairsTest01, TestSize.Level1)
{
    WifiMacAddrInfoType type = WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO;
    WifiMacAddrInfo macAddrInfo;
    macAddrInfo.bssid = "TEST";
    std::string randomMacAddr = "TEST";
    EXPECT_EQ(WifiConfigCenter::GetInstance().AddMacAddrPairs(type, macAddrInfo, randomMacAddr), 0);
    type = WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO;
    EXPECT_EQ(WifiConfigCenter::GetInstance().AddMacAddrPairs(type, macAddrInfo, randomMacAddr), 0);
}
 
HWTEST_F(WifiConfigCenterTest, GetLocalOnlyHotspotConfigTest, TestSize.Level1)
{
    HotspotConfig config;
    config.ssid = "GetLocalOnlyHotspotConfigTest";
    WifiConfigCenter::GetInstance().SetLocalOnlyHotspotConfig(config);
    HotspotConfig outConfig;
    WifiConfigCenter::GetInstance().GetLocalOnlyHotspotConfig(outConfig);
    EXPECT_EQ(outConfig.ssid, "GetLocalOnlyHotspotConfigTest");
}
 
HWTEST_F(WifiConfigCenterTest, SetLocalOnlyHotspotConfigTest, TestSize.Level1)
{
    HotspotConfig config;
    config.ssid = "SetLocalOnlyHotspotConfigTest";
    WifiConfigCenter::GetInstance().SetLocalOnlyHotspotConfig(config);
    HotspotConfig outConfig;
    WifiConfigCenter::GetInstance().GetLocalOnlyHotspotConfig(outConfig);
    EXPECT_EQ(outConfig.ssid, "SetLocalOnlyHotspotConfigTest");
}

#ifndef OHOS_ARCH_LITE
HWTEST_F(WifiConfigCenterTest, SetScreenDispalyStateTest, TestSize.Level1)
{
    WifiConfigCenter::GetInstance().SetScreenDispalyState(1);
    EXPECT_EQ(WifiConfigCenter::GetInstance().IsScreenLandscape(), true);
}
#endif

HWTEST_F(WifiConfigCenterTest, IsAllowPcPopUpTest, TestSize.Level1)
{
    WifiConfigCenter::GetInstance().SetDeviceType(ProductDeviceType::PC);
    EXPECT_EQ(WifiConfigCenter::GetInstance().IsAllowPcPopUp(), false);
}

HWTEST_F(WifiConfigCenterTest, IsSameKeyMgmtTest, TestSize.Level1)
{
    WifiConfigCenter::GetInstance().IsSameKeyMgmt("WPA-PSK", "SAE");
    EXPECT_EQ(WifiConfigCenter::GetInstance().IsSameKeyMgmt("WPA-PSK+SAE", "WPA-PSK"), true);
}
}  // namespace Wifi
}  // namespace OHOS