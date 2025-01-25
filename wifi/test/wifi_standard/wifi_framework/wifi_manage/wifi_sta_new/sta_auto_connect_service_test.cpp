/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "sta_auto_connect_service.h"
#include "sta_state_machine.h"
#include "mock_wifi_sta_hal_interface.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "mock_device_appraisal.h"
#include <gtest/gtest.h>
#include <vector>

#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "sta_device_appraisal.h"
#include "wifi_native_struct.h"
#include "wifi_error_no.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

const std::string g_errLog = "wifitest";
constexpr int INVALIDRSSI = -90;
constexpr int NETWORK_ID = 15;
constexpr int RSSI = 8;

class StaAutoConnectServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pStaStateMachine = new (std::nothrow) StaStateMachine();
        pStaAutoConnectService = new (std::nothrow) StaAutoConnectService(pStaStateMachine);
    }
    virtual void TearDown()
    {
        if (pStaStateMachine != nullptr) {
            delete pStaStateMachine;
            pStaStateMachine = nullptr;
        }

        if (pStaAutoConnectService != nullptr) {
            delete pStaAutoConnectService;
            pStaAutoConnectService = nullptr;
        }
    }

public:
    StaAutoConnectService *pStaAutoConnectService;
    StaStateMachine *pStaStateMachine;
};

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceTest01, TestSize.Level1)
{
    WifiDeviceConfig electedDevice;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    EXPECT_EQ(pStaAutoConnectService->AutoSelectDevice(electedDevice,
        scanInfos, blockedBssids, info), WIFI_OPT_FAILED);
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckTest01, TestSize.Level1)
{
    WifiDeviceConfig electedDevice;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    WifiDeviceConfig network;
    network.keyMgmt = "WAPI-PSK";
    scanInfo.capabilities = "WAPI-PSK";
    scanInfo.rssi = 5;
    info.rssi = 8;

    EXPECT_EQ(pStaAutoConnectService->RoamingEncryptionModeCheck(electedDevice, scanInfo, info), false);
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckTest02, TestSize.Level1)
{
    WifiDeviceConfig electedDevice;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    WifiDeviceConfig network;
    network.keyMgmt = "EAP";
    scanInfo.capabilities = "EAP";
    scanInfo.rssi = 5;
    info.rssi = 8;
    int indexType = DEVICE_CONFIG_INDEX_SSID;
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(network), Return(0)));

    EXPECT_EQ(pStaAutoConnectService->RoamingEncryptionModeCheck(electedDevice, scanInfo, info), false);
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckTest03, TestSize.Level1)
{
    WifiDeviceConfig electedDevice;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    WifiDeviceConfig network;
    network.keyMgmt = "SAE";
    scanInfo.capabilities = "SAE";
    scanInfo.rssi = 5;
    info.rssi = 8;
    int indexType = DEVICE_CONFIG_INDEX_SSID;
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(network), Return(0)));

    EXPECT_EQ(pStaAutoConnectService->RoamingEncryptionModeCheck(electedDevice, scanInfo, info), false);
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckTest04, TestSize.Level1)
{
    WifiDeviceConfig electedDevice;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    WifiDeviceConfig network;
    network.keyMgmt = "WEP";
    network.wepTxKeyIndex = 0;
    scanInfo.capabilities = "WEP";
    scanInfo.rssi = 5;
    info.rssi = 8;
    int indexType = DEVICE_CONFIG_INDEX_SSID;
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(network), Return(0)));

    EXPECT_EQ(pStaAutoConnectService->RoamingEncryptionModeCheck(electedDevice, scanInfo, info), false);
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceTest01, TestSize.Level1)
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    InterScanInfo scanInfo;
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "HMWIFI_W2_EAP_G2_03";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = RSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
    scanInfos.push_back(scanInfo);

    info.detailedState = DetailedState::WORKING; // WORKING
    info.bssid = "2a:76:93:47:e2:8a";
    info.ssid = "HMWIFI_W2_EAP_G2_03";
    info.networkId = NETWORK_ID;
    info.connState = ConnState::CONNECTED;

    pStaAutoConnectService->selectDeviceLastTime = static_cast<int>(time(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_EQ(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info), false);
}

HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughTest01, TestSize.Level1)
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    info.networkId = NETWORK_ID;
    deviceConfig.networkId = 0;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_))
        .Times(AtLeast(1)).WillOnce(Return(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkTimeVal(_))
        .Times(AtLeast(1)).WillOnce(Return(time(0)));
    EXPECT_EQ(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info), true);
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosTest01, TestSize.Level1)
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    scanInfos.clear();

    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosTest02, TestSize.Level1)
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    
    InterScanInfo scanInfo;
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "HMWIFI_W2_EAP_G2_03";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = INVALIDRSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
    scanInfo.frequency = 3000;
    scanInfos.push_back(scanInfo);
    std::string bssid1 = "2a:76:93:47:e2:8a";
    blockedBssids.push_back(bssid1);

    info.connState = ConnState::CONNECTED;
    info.bssid = "2a:76:93:47:e2:8a";
    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosTest03, TestSize.Level1)
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    
    InterScanInfo scanInfo;
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "HMWIFI_W2_EAP_G2_03";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = INVALIDRSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
    scanInfo.frequency = 7000;
    scanInfos.push_back(scanInfo);
    std::string bssid1 = "2a:76:93:47:e2:8a";
    blockedBssids.push_back(bssid1);

    info.connState = ConnState::CONNECTED;
    info.bssid = "2a:76:93:47:e2:8a";
    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, RegisterAutoJoinConditionTest01, TestSize.Level1)
{
    std::string conditionName;
    pStaAutoConnectService->RegisterAutoJoinCondition(conditionName, []() {return false;});
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

} // WIFI
} // OHOS
