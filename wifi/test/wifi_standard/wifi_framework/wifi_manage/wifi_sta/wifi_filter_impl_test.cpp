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
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiFilterImplTest, HiddenWifiFilter, TestSize.Level1) {
    NetworkSelection::HiddenWifiFilter* wifiFilter = new NetworkSelection::HiddenWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -77;
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, HiddenWifiFilter1, TestSize.Level1) {
    NetworkSelection::HiddenWifiFilter* wifiFilter = new NetworkSelection::HiddenWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo2;
    scanInfo2.bssid = "11:22:11:11:22";
    scanInfo2.frequency = 2407;
    scanInfo2.rssi = -77;
    scanInfo2.ssid = "sssx";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo2);
    networkCandidate1.wifiDeviceConfig.networkId = 5;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate1));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, SignalStrengthWifiFilter, TestSize.Level1) {
    NetworkSelection::SignalStrengthWifiFilter* wifiFilter = new NetworkSelection::SignalStrengthWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "x";
    //2.4g wifi
    scanInfo1.frequency = 2503;
    scanInfo1.rssi = -85;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    scanInfo1.rssi = -70;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo1);
    networkCandidate2.wifiDeviceConfig.networkId = 2;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate2));

    //5g wifi
    scanInfo1.frequency = 5003;
    scanInfo1.rssi = -82;
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo1);
    networkCandidate3.wifiDeviceConfig.networkId = 3;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate3));

    scanInfo1.rssi = -70;
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo1);
    networkCandidate4.wifiDeviceConfig.networkId = 4;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate4));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, SavedWifiFilter, TestSize.Level1) {
    NetworkSelection::SavedWifiFilter* wifiFilter = new NetworkSelection::SavedWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = -1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.uid = 1;
    networkCandidate2.wifiDeviceConfig.isShared = false;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate3));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, EphemeralWifiFilter, TestSize.Level1) {
    NetworkSelection::EphemeralWifiFilter* wifiFilter = new NetworkSelection::EphemeralWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.isEphemeral = true;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.bssid = "xx";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 2;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate2));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, PassPointWifiFilter, TestSize.Level1) {
    NetworkSelection::PassPointWifiFilter* wifiFilter = new NetworkSelection::PassPointWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.isPasspoint = true;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate2));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, DisableWifiFilter, TestSize.Level1) {
    NetworkSelection::DisableWifiFilter* wifiFilter = new NetworkSelection::DisableWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::DISABLED;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.networkSelectionStatus.status = WifiDeviceConfigStatus::ENABLED;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate2));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, MatchedUserSelectBssidWifiFilter, TestSize.Level1) {
    NetworkSelection::MatchedUserSelectBssidWifiFilter* wifiFilter =
        new NetworkSelection::MatchedUserSelectBssidWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate));

    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.userSelectBssid = "11:22:11:11:11";
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, HasInternetWifiFilter, TestSize.Level1) {
    NetworkSelection::HasInternetWifiFilter* wifiFilter = new NetworkSelection::HasInternetWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPortal = 1;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 7;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate3));

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.keyMgmt = KEY_MGMT_WEP;
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.networkStatusHistory = 15;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate5));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, RecoveryWifiFilter, TestSize.Level1) {
    NetworkSelection::RecoveryWifiFilter* wifiFilter = new NetworkSelection::RecoveryWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "99:11:11:11:99";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.networkId = 1;
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 0;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate));

    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate1.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo1);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate2.wifiDeviceConfig.isPortal = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));

    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo1);
    networkCandidate3.wifiDeviceConfig.networkStatusHistory = 3;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate3.wifiDeviceConfig.isPortal = 0;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate3));

    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo1);
    networkCandidate4.wifiDeviceConfig.networkStatusHistory = 5;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate4.wifiDeviceConfig.isPortal = 0;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate4));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter, TestSize.Level1) {
    NetworkSelection::PoorPortalWifiFilter* wifiFilter = new NetworkSelection::PoorPortalWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    WIFI_LOGI("lgx PoorPortalWifiFilter   ");
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate(scanInfo1);
    networkCandidate.wifiDeviceConfig.isPortal = 1;
    networkCandidate.wifiDeviceConfig.networkId = 1;
    networkCandidate.wifiDeviceConfig.noInternetAccess = 1;
    networkCandidate.wifiDeviceConfig.networkStatusHistory = 3;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate));
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
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate1));

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
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, PoorPortalWifiFilter1, TestSize.Level1) {
    NetworkSelection::PoorPortalWifiFilter* wifiFilter = new NetworkSelection::PoorPortalWifiFilter();
    if (wifiFilter == nullptr) {
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
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate3));

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
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate4));

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
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate5));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, PortalWifiFilter, TestSize.Level1) {
    NetworkSelection::PortalWifiFilter* wifiFilter = new NetworkSelection::PortalWifiFilter();
    if (wifiFilter == nullptr) {
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
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.isPortal = 0;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.isPortal = 1;
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate3));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, MaybePortalWifiFilter, TestSize.Level1) {
    NetworkSelection::MaybePortalWifiFilter* wifiFilter = new NetworkSelection::MaybePortalWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.capabilities = "OWE";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.keyMgmt = KEY_MGMT_WEP;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    networkCandidate2.wifiDeviceConfig.noInternetAccess = 0;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo3;
    scanInfo3.ssid = "x";
    scanInfo3.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate3(scanInfo3);
    networkCandidate3.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate3.wifiDeviceConfig.networkId = 1;
    networkCandidate3.wifiDeviceConfig.noInternetAccess = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate3));

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    networkCandidate4.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate4.wifiDeviceConfig.networkStatusHistory = 7;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    networkCandidate5.wifiDeviceConfig.noInternetAccess = 0;
    networkCandidate5.wifiDeviceConfig.networkStatusHistory = 0;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate5));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, NoInternetWifiFilter, TestSize.Level1) {
    NetworkSelection::NoInternetWifiFilter* wifiFilter = new NetworkSelection::NoInternetWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkStatusHistory = 255;
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkStatusHistory = 5;
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate2));
    delete wifiFilter;
}

HWTEST_F(WifiFilterImplTest, WeakAlgorithmWifiFilter, TestSize.Level1) {
    NetworkSelection::WeakAlgorithmWifiFilter* wifiFilter = new NetworkSelection::WeakAlgorithmWifiFilter();
    if (wifiFilter == nullptr) {
        return;
    }
    InterScanInfo scanInfo1;
    scanInfo1.ssid = "x";
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.securityType = WifiSecurity::WEP;
    NetworkSelection::NetworkCandidate networkCandidate1(scanInfo1);
    networkCandidate1.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate1));

    InterScanInfo scanInfo2;
    scanInfo2.ssid = "x";
    scanInfo2.bssid = "11:11:11:11:11";
    scanInfo2.securityType = WifiSecurity::OPEN;
    NetworkSelection::NetworkCandidate networkCandidate2(scanInfo2);
    networkCandidate2.wifiDeviceConfig.networkId = 1;
    EXPECT_FALSE(wifiFilter->DoFilter(networkCandidate2));

    InterScanInfo scanInfo4;
    scanInfo4.ssid = "x";
    scanInfo4.bssid = "11:11:11:11:11";
    scanInfo4.securityType = WifiSecurity::PSK;
    scanInfo4.capabilities = "CCMPTKIP";
    NetworkSelection::NetworkCandidate networkCandidate4(scanInfo4);
    networkCandidate4.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate4));

    InterScanInfo scanInfo5;
    scanInfo5.ssid = "x";
    scanInfo5.bssid = "11:11:11:11:11";
    scanInfo5.securityType = WifiSecurity::EAP;
    NetworkSelection::NetworkCandidate networkCandidate5(scanInfo5);
    networkCandidate5.wifiDeviceConfig.networkId = 1;
    EXPECT_TRUE(wifiFilter->DoFilter(networkCandidate5));
    delete wifiFilter;
}

}
}