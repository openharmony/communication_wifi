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
#include <vector>
#include <gmock/gmock.h>
#include "inter_scan_info.h"
#include "wifi_filter_impl.h"
#include "wifi_scan_msg.h"
#include "mock_wifi_settings.h"
#include "network_selection.h"
#include "network_selection_manager.h"
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
    virtual void SetUp() {
        hiddenWifiFilter = std::make_shared<NetworkSelection::HiddenWifiFilter>();
        signalStrengthWifiFilter = std::make_shared<NetworkSelection::SignalStrengthWifiFilter>();
        savedWifiFilter = std::make_shared<NetworkSelection::SavedWifiFilter>();
        ephemeralWifiFilter = std::make_shared<NetworkSelection::EphemeralWifiFilter>();
        passPointWifiFilter = std::make_shared<NetworkSelection::PassPointWifiFilter>();
        disableWifiFilter = std::make_shared<NetworkSelection::DisableWifiFilter>();
        systemNetworkWifiFilter = std::make_shared<NetworkSelection::MatchedUserSelectBssidWifiFilter>();
        hasInternetWifiFilter = std::make_shared<NetworkSelection::HasInternetWifiFilter>();
        recoveryWifiFilter = std::make_shared<NetworkSelection::RecoveryWifiFilter>();
        poorPortalWifiFilter = std::make_shared<NetworkSelection::PoorPortalWifiFilter>();
        portalWifiFilter = std::make_shared<NetworkSelection::PortalWifiFilter>();
        maybePortalWifiFilter = std::make_shared<NetworkSelection::MaybePortalWifiFilter>();
        noInternetWifiFilter = std::make_shared<NetworkSelection::NoInternetWifiFilter>();
        weakAlgorithmWifiFilter = std::make_shared<NetworkSelection::WeakAlgorithmWifiFilter>();
    }
public:
    std::shared_ptr<NetworkSelection::HiddenWifiFilter> hiddenWifiFilter;
    std::shared_ptr<NetworkSelection::SignalStrengthWifiFilter> signalStrengthWifiFilter;
    std::shared_ptr<NetworkSelection::SavedWifiFilter> savedWifiFilter;
    std::shared_ptr<NetworkSelection::EphemeralWifiFilter> ephemeralWifiFilter;
    std::shared_ptr<NetworkSelection::PassPointWifiFilter> passPointWifiFilter;
    std::shared_ptr<NetworkSelection::DisableWifiFilter> disableWifiFilter;
    std::shared_ptr<NetworkSelection::MatchedUserSelectBssidWifiFilter> systemNetworkWifiFilter;
    std::shared_ptr<NetworkSelection::HasInternetWifiFilter> hasInternetWifiFilter;
    std::shared_ptr<NetworkSelection::RecoveryWifiFilter> recoveryWifiFilter;
    std::shared_ptr<NetworkSelection::PoorPortalWifiFilter> poorPortalWifiFilter;
    std::shared_ptr<NetworkSelection::PortalWifiFilter> portalWifiFilter;
    std::shared_ptr<NetworkSelection::MaybePortalWifiFilter> maybePortalWifiFilter;
    std::shared_ptr<NetworkSelection::NoInternetWifiFilter> noInternetWifiFilter;
    std::shared_ptr<NetworkSelection::WeakAlgorithmWifiFilter> weakAlgorithmWifiFilter;
    virtual void TearDown() {}
};

HWTEST_F(WifiFilterImplTest, HiddenWifiFilter, TestSize.Level1) {
    if (hiddenWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -77;
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(hiddenWifiFilter->DoFilter(networkCandidate));
    hiddenWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, HiddenWifiFilter1, TestSize.Level1) {
    if (hiddenWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo2;
    scanInfo2.bssid = "11:22:11:11:22";
    scanInfo2.frequency = 2407;
    scanInfo2.rssi = -77;
    scanInfo2.ssid = "sssx";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo2);
    networkCandidate1.wifiDeviceConfig.networkId = 5;
    EXPECT_TRUE(hiddenWifiFilter->DoFilter(networkCandidate1));
    hiddenWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, SignalStrengthWifiFilter, TestSize.Level1) {
    if (signalStrengthWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "x";
    //2.4g wifi
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -80;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(signalStrengthWifiFilter->DoFilter(networkCandidate1));

    scanInfo1.rssi = -70;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo1);
    networkCandidate2.wifiDeviceConfig.networkId = 2;
    EXPECT_TRUE(signalStrengthWifiFilter->DoFilter(networkCandidate2));

    //5g wifi
    scanInfo1.frequency = 5820;
    scanInfo1.rssi = -82;
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo1);
    networkCandidate3.wifiDeviceConfig.networkId = 3;
    EXPECT_FALSE(signalStrengthWifiFilter->DoFilter(networkCandidate3));

    scanInfo1.rssi = -70;
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo1);
    networkCandidate4.wifiDeviceConfig.networkId = 4;
    EXPECT_TRUE(signalStrengthWifiFilter->DoFilter(networkCandidate4));
    signalStrengthWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, SavedWifiFilter, TestSize.Level1) {
    if (savedWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = -1;
    EXPECT_FALSE(savedWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.uid = 1;
    networkCandidate2.wifiDeviceConfig.isShared = false;
    EXPECT_FALSE(savedWifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(savedWifiFilter->DoFilter(networkCandidate3));
    savedWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, EphemeralWifiFilter, TestSize.Level1) {
    if (ephemeralWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.isEphemeral = true;
    EXPECT_FALSE(ephemeralWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "xx";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 2;
    EXPECT_TRUE(ephemeralWifiFilter->DoFilter(networkCandidate2));
    ephemeralWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, PassPointWifiFilter, TestSize.Level1) {
    if (passPointWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.isPasspoint = true;
    EXPECT_FALSE(passPointWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(passPointWifiFilter->DoFilter(networkCandidate2));
    passPointWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, DisableWifiFilter, TestSize.Level1) {
    if (disableWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::DISABLED;
    EXPECT_FALSE(disableWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::ENABLED;
    EXPECT_TRUE(disableWifiFilter->DoFilter(networkCandidate2));
    disableWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, MatchedUserSelectBssidWifiFilter, TestSize.Level1) {
    if (systemNetworkWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(systemNetworkWifiFilter->DoFilter(networkCandidate));

    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.userSelectBssid = "11:22:11:11:11";
    EXPECT_FALSE(systemNetworkWifiFilter->DoFilter(networkCandidate1));
    systemNetworkWifiFilter.reset();

}

HWTEST_F(WifiFilterImplTest, HasInternetWifiFilter, TestSize.Level1) {
    if (hasInternetWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 1;
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPortal = 1;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 7;
    EXPECT_TRUE(hasInternetWifiFilter->DoFilter(networkCandidate3));

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.keyMgmt = KEY_MGMT_WEP;
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.networkStatusHistory = 15;
    EXPECT_FALSE(hasInternetWifiFilter->DoFilter(networkCandidate5));
    hasInternetWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, RecoveryWifiFilter, TestSize.Level1) {
    if (recoveryWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "99:11:11:11:99";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 0;
    EXPECT_TRUE(recoveryWifiFilter->DoFilter(networkCandidate));

    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(recoveryWifiFilter->DoFilter(networkCandidate1));

    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo1);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate2.wifiDeviceConfig.isPortal = 1;
    EXPECT_FALSE(recoveryWifiFilter->DoFilter(networkCandidate2));

    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo1);
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate3.wifiDeviceConfig.isPortal = 0;
    EXPECT_FALSE(recoveryWifiFilter->DoFilter(networkCandidate3));

    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo1);
    networkCandidate4.wifiDeviceConfig.networkStatusHistory = 5;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate4.wifiDeviceConfig.isPortal = 0;
    EXPECT_TRUE(recoveryWifiFilter->DoFilter(networkCandidate4));
    recoveryWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter, TestSize.Level1) {
    if (poorPortalWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.isPortal = 1;
    networkCandidate.wifiDeviceConfig.networkId = 1;
    networkCandidate.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 3;
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate));
    //2.4g wifi
    InterScanInfo scanInfo2;
    scanInfo2.ssid = "xs";
    scanInfo2.bssid = "11:11:11:11:33";
    scanInfo2.rssi = -50;
    scanInfo2.band = 1;
    scanInfo2.frequency = 2640;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo2);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_TRUE(poorPortalWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "xs";
    scanInfo3.bssid = "11:11:11:11:33";
    scanInfo3.rssi = -86;
    scanInfo3.band = 1;
    scanInfo3.frequency = 2640;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo3);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate2));
    poorPortalWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter1, TestSize.Level1) {
    if (poorPortalWifiFilter == nullptr) {
        return;
    }
    //5g wifi
    InterScanInfo scanInfo4;
    scanInfo4.ssid = "xs";
    scanInfo4.bssid = "11:11:11:11:33";
    scanInfo4.rssi = -50;
    scanInfo4.band = 2;
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo4);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_TRUE(poorPortalWifiFilter->DoFilter(networkCandidate3));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "xs";
    scanInfo5.bssid = "11:11:11:11:33";
    scanInfo5.rssi = -85;
    scanInfo5.band = 2;
    scanInfo5.frequency = 5640;
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo5);
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo6;
    scanInfo6.ssid = "xs";
    scanInfo6.bssid = "11:11:11:11:33";
    scanInfo6.rssi = -79;
    scanInfo6.band = 2;
    scanInfo6.frequency = 5640;
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo6);
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.lastHasInternetTime = 1735366164;
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(2));
    EXPECT_FALSE(poorPortalWifiFilter->DoFilter(networkCandidate5));
    poorPortalWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, PortalWifiFilter, TestSize.Level1) {
    if (portalWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.isPortal = 1;
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 3;
    EXPECT_FALSE(portalWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPortal = 0;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(portalWifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.isPortal = 1;
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_TRUE(portalWifiFilter->DoFilter(networkCandidate3));
    portalWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, MaybePortalWifiFilter, TestSize.Level1) {
    if (maybePortalWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.capabilities = "OWE";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.keyMgmt = KEY_MGMT_WEP;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 1;
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate3));

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate4.wifiDeviceConfig.networkStatusHistory = 7;
    EXPECT_FALSE(maybePortalWifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.networkStatusHistory = 0;
    EXPECT_TRUE(maybePortalWifiFilter->DoFilter(networkCandidate5));
    maybePortalWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, NoInternetWifiFilter, TestSize.Level1) {
    if (noInternetWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(noInternetWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 5;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(noInternetWifiFilter->DoFilter(networkCandidate2));
    noInternetWifiFilter.reset();
}

HWTEST_F(WifiFilterImplTest, WeakAlgorithmWifiFilter, TestSize.Level1) {
    if (weakAlgorithmWifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.securityType = WifiSecurity::WEP;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(weakAlgorithmWifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    scanInfo2.securityType = WifiSecurity::OPEN;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(weakAlgorithmWifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11";
    scanInfo4.securityType = WifiSecurity::PSK;
    scanInfo4.capabilities = "CCMPTKIP";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(weakAlgorithmWifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11";
    scanInfo5.securityType = WifiSecurity::EAP;
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(weakAlgorithmWifiFilter->DoFilter(networkCandidate5));
    weakAlgorithmWifiFilter.reset();
}

}
}