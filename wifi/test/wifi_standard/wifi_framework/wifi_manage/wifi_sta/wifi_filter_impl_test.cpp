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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_filter_impl.h"
#include "mock_wifi_settings.h"
#include "network_selection_utils.h"

using ::testing::_;
using ::testing::Return;
using ::testing::An;
using ::testing::ext::TestSize;
using ::testing::ReturnRoundRobin;
using ::testing::Invoke;

namespace OHOS {
namespace Wifi {


class WifiFilterImplTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiFilterImplTest, HiddenWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11:55";
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -77;
    scanInfo1.ssid = "";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    auto hiddenWifiFilter = std::make_shared<NetworkSelection::HiddenWifiFilter>();
    EXPECT_FALSE(hiddenWifiFilter->DoFilter(networkCandidate));
}

HWTEST_F(WifiFilterImplTest, HiddenWifiFilterReturnTrue, TestSize.Level1) {

    InterScanInfo scanInfo2;
    scanInfo2.bssid = "11:22:11:11:22:44";
    scanInfo2.frequency = 2407;
    scanInfo2.rssi = -77;
    scanInfo2.ssid = "sssx";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo2);
    networkCandidate1.wifiDeviceConfig.networkId = 5;
    auto hiddenWifiFilter = std::make_shared<NetworkSelection::HiddenWifiFilter>();
    EXPECT_TRUE(hiddenWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, RssiWifiFilter24gReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11:77";
    scanInfo1.ssid = "x";
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -82;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;

    auto signalStrengthWifiFilter = std::make_shared<NetworkSelection::SignalStrengthWifiFilter>();
    EXPECT_FALSE(signalStrengthWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, RssiWifiFilter24gReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo2;
    scanInfo2.bssid = "11:11:11:11:11:66";
    scanInfo2.ssid = "x";
    scanInfo2.rssi = -70;
    scanInfo2.frequency = 2407;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 2;

    auto signalStrengthWifiFilter = std::make_shared<NetworkSelection::SignalStrengthWifiFilter>();
    EXPECT_TRUE(signalStrengthWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, RssiWifiFilter5gReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11:44";
    scanInfo1.ssid = "x";
    scanInfo1.frequency = 5820;
    scanInfo1.rssi = -82;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 3;

    auto signalStrengthWifiFilter = std::make_shared<NetworkSelection::SignalStrengthWifiFilter>();
    EXPECT_FALSE(signalStrengthWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, RssiWifiFilter5gReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo2;
    scanInfo2.bssid = "11:11:11:11:11:22";
    scanInfo2.ssid = "x";
    scanInfo2.rssi = -70;
    scanInfo2.frequency = 5820;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 4;

    auto signalStrengthWifiFilter = std::make_shared<NetworkSelection::SignalStrengthWifiFilter>();
    EXPECT_TRUE(signalStrengthWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, SavedWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:33";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = -1;

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:77";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.uid = 1;
    networkCandidate2.wifiDeviceConfig.isShared = false;

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11:44";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;

    auto savedWifiFilter = std::make_shared<NetworkSelection::SavedWifiFilter>();
    EXPECT_FALSE(savedWifiFilter->DoFilter(networkCandidate1));
    EXPECT_FALSE(savedWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, SavedWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;

    auto savedWifiFilter = std::make_shared<NetworkSelection::SavedWifiFilter>();
    EXPECT_TRUE(savedWifiFilter->DoFilter(networkCandidate3));
}

HWTEST_F(WifiFilterImplTest, EphemeralWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.isEphemeral = true;

    auto ephemeralWifiFilter = std::make_shared<NetworkSelection::EphemeralWifiFilter>();
    EXPECT_FALSE(ephemeralWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, EphemeralWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo2;
    scanInfo2.ssid = "xx";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 2;
    networkCandidate2.wifiDeviceConfig.isEphemeral = false;

    auto ephemeralWifiFilter = std::make_shared<NetworkSelection::EphemeralWifiFilter>();
    EXPECT_TRUE(ephemeralWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, PassPointWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:22:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.isPasspoint = true;

    auto passPointWifiFilter = std::make_shared<NetworkSelection::PassPointWifiFilter>();
    EXPECT_FALSE(passPointWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, PassPointWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPasspoint = false;
    networkCandidate2.wifiDeviceConfig.networkId = 1;

    auto passPointWifiFilter = std::make_shared<NetworkSelection::PassPointWifiFilter>();
    EXPECT_TRUE(passPointWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, DisableWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::DISABLED;

    auto disableWifiFilter = std::make_shared<NetworkSelection::DisableWifiFilter>();
    EXPECT_FALSE(disableWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, DisableWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::ENABLED;

    auto disableWifiFilter = std::make_shared<NetworkSelection::DisableWifiFilter>();
    EXPECT_TRUE(disableWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, MatchedUserSelectBssidWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.userSelectBssid = "";
    networkCandidate.wifiDeviceConfig.networkId = 1;

    auto systemNetworkWifiFilter = std::make_shared<NetworkSelection::MatchedUserSelectBssidWifiFilter>();
    EXPECT_TRUE(systemNetworkWifiFilter->DoFilter(networkCandidate));
}

HWTEST_F(WifiFilterImplTest, MatchedUserSelectBssidWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.userSelectBssid = "11:22:11:11:11:22";

    auto systemNetworkWifiFilter = std::make_shared<NetworkSelection::MatchedUserSelectBssidWifiFilter>();
    EXPECT_FALSE(systemNetworkWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, HasInternetWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 7;

    auto hasInternetWifiFilter = std::make_shared<NetworkSelection::HasInternetWifiFilter>();
    EXPECT_TRUE(hasInternetWifiFilter->DoFilter(networkCandidate3));
}

HWTEST_F(WifiFilterImplTest, HasInternetWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 1;

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPortal = 1;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 7;

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.keyMgmt = KEY_MGMT_WEP;
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.networkStatusHistory = 15;

    auto hasInternetWifiFilter = std::make_shared<NetworkSelection::HasInternetWifiFilter>();
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate1));
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate2));
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate4));
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate5));
}

HWTEST_F(WifiFilterImplTest, RecoveryWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "99:11:11:11:99:22";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 0;
    

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "xx";
    scanInfo2.bssid = "99:11:11:11:99:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 5;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 3;
    networkCandidate2.wifiDeviceConfig.isPortal = 0;

    auto recoveryWifiFilter = std::make_shared<NetworkSelection::RecoveryWifiFilter>();
    EXPECT_TRUE(recoveryWifiFilter->DoFilter(networkCandidate));
    EXPECT_TRUE(recoveryWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, RecoveryWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "99:11:11:11:99:22";

    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 0;
    
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo1);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate2.wifiDeviceConfig.isPortal = 1;
    

    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo1);
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate3.wifiDeviceConfig.isPortal = 0;

    auto recoveryWifiFilter = std::make_shared<NetworkSelection::RecoveryWifiFilter>();
    EXPECT_FALSE(recoveryWifiFilter->DoFilter(networkCandidate1));
    EXPECT_FALSE(recoveryWifiFilter->DoFilter(networkCandidate2));
    EXPECT_FALSE(recoveryWifiFilter->DoFilter(networkCandidate3));
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter24gReturnTrue, TestSize.Level1) {
    //2.4g wifi
    InterScanInfo scanInfo2;
    scanInfo2.ssid = "xs";
    scanInfo2.bssid = "11:11:11:11:33:22";
    scanInfo2.rssi = -34;
    scanInfo2.band = 1;
    scanInfo2.frequency = 2640;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo2);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));

    auto poorPortalWifiFilter = std::make_shared<NetworkSelection::PoorPortalWifiFilter>();
    EXPECT_TRUE(poorPortalWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter24gReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.isPortal = 1;
    networkCandidate.wifiDeviceConfig.networkId = 1;
    networkCandidate.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 3;

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "xs";
    scanInfo3.bssid = "11:11:11:11:33:22";
    scanInfo3.rssi = -86;
    scanInfo3.band = 1;
    scanInfo3.frequency = 2640;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo3);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(1));

    auto poorPortalWifiFilter = std::make_shared<NetworkSelection::PoorPortalWifiFilter>();
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate));
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter5gReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo4;
    scanInfo4.ssid = "xs";
    scanInfo4.bssid = "11:11:11:11:33:22";
    scanInfo4.rssi = -50;
    scanInfo4.band = 2;
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo4);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));

    auto poorPortalWifiFilter = std::make_shared<NetworkSelection::PoorPortalWifiFilter>();
    EXPECT_TRUE(poorPortalWifiFilter->DoFilter(networkCandidate3));
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter5gReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo5;
    scanInfo5.ssid = "xs";
    scanInfo5.bssid = "11:11:11:11:33:22";
    scanInfo5.rssi = -85;
    scanInfo5.band = 2;
    scanInfo5.frequency = 5640;
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo5);
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(1));

    InterScanInfo scanInfo6;
    scanInfo6.ssid = "xs";
    scanInfo6.bssid = "11:11:11:11:33:22";
    scanInfo6.rssi = -79;
    scanInfo6.band = 2;
    scanInfo6.frequency = 5640;
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo6);
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.lastHasInternetTime = 1735366164;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(2));

    auto poorPortalWifiFilter = std::make_shared<NetworkSelection::PoorPortalWifiFilter>();
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate4));
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate5));
}

HWTEST_F(WifiFilterImplTest, PortalWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.isPortal = 1;
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;

    auto portalWifiFilter = std::make_shared<NetworkSelection::PortalWifiFilter>();
    EXPECT_TRUE(portalWifiFilter->DoFilter(networkCandidate3));
}

HWTEST_F(WifiFilterImplTest, PortalWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.isPortal = 1;
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 3;

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPortal = 0;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;

    auto portalWifiFilter = std::make_shared<NetworkSelection::PortalWifiFilter>();
    EXPECT_FALSE(portalWifiFilter->DoFilter(networkCandidate1));
    EXPECT_FALSE(portalWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, MaybePortalWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 0;

    auto maybePortalWifiFilter = std::make_shared<NetworkSelection::MaybePortalWifiFilter>();
    EXPECT_TRUE(maybePortalWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, MaybePortalWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    scanInfo1.capabilities = "OWE";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.keyMgmt = KEY_MGMT_WEP;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 1;

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate4.wifiDeviceConfig.networkStatusHistory = 7;

    auto maybePortalWifiFilter = std::make_shared<NetworkSelection::MaybePortalWifiFilter>();
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate1));
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate2));
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate3));
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate4));
}

HWTEST_F(WifiFilterImplTest, NoInternetWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate1.wifiDeviceConfig.networkId = 1;

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 5;
    networkCandidate2.wifiDeviceConfig.networkId = 1;

    auto noInternetWifiFilter = std::make_shared<NetworkSelection::NoInternetWifiFilter>();
    EXPECT_TRUE(noInternetWifiFilter->DoFilter(networkCandidate2));
}

HWTEST_F(WifiFilterImplTest, NoInternetWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate1.wifiDeviceConfig.networkId = 1;

    auto noInternetWifiFilter = std::make_shared<NetworkSelection::NoInternetWifiFilter>();
    EXPECT_FALSE(noInternetWifiFilter->DoFilter(networkCandidate1));
}

HWTEST_F(WifiFilterImplTest, WeakAlgorithmWifiFilterReturnTrue, TestSize.Level1) {
    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11:22";
    scanInfo4.securityType = WifiSecurity::PSK;
    scanInfo4.capabilities = "CCMPTKIP";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.networkId = 1;

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11:22";
    scanInfo5.securityType = WifiSecurity::EAP;
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.networkId = 1;

    auto weakAlgorithmWifiFilter = std::make_shared<NetworkSelection::WeakAlgorithmWifiFilter>();
    EXPECT_TRUE(weakAlgorithmWifiFilter->DoFilter(networkCandidate4));
    EXPECT_TRUE(weakAlgorithmWifiFilter->DoFilter(networkCandidate5));
}

HWTEST_F(WifiFilterImplTest, WeakAlgorithmWifiFilterReturnFalse, TestSize.Level1) {
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11:22";
    scanInfo1.securityType = WifiSecurity::WEP;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11:22";
    scanInfo2.securityType = WifiSecurity::OPEN;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;

    auto weakAlgorithmWifiFilter = std::make_shared<NetworkSelection::WeakAlgorithmWifiFilter>();
    EXPECT_FALSE(weakAlgorithmWifiFilter->DoFilter(networkCandidate1));
    EXPECT_FALSE(weakAlgorithmWifiFilter->DoFilter(networkCandidate2));
}

}
}