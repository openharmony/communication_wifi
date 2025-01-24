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
#include "wifi_scan_msg.h"
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


class NetworkSelectionUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(NetworkSelectionUtilsTest, GetNetworkCandidatesInfo, TestSize.Level1) {
    std::vector<NetworkSelection::NetworkCandidate*> networkCandidates;
    std::string filterName;
    std::string networkInfo;
    InterScanInfo scanInfo1;
    NetworkSelection::NetworkCandidate filternetworkCandidate(scanInfo1);
    filternetworkCandidate.wifiDeviceConfig.ssid = "xx";
    filternetworkCandidate.wifiDeviceConfig.bssid = "11:11:11:11:11";
    filternetworkCandidate.wifiDeviceConfig.networkId = 1;
    filternetworkCandidate.filtedReason["hasInternet"].insert(NetworkSelection::WEAK_ALGORITHM_WEP_SECURITY);
    networkCandidates.emplace_back(&filternetworkCandidate);
    EXPECT_NE(NetworkSelection::NetworkSelectionUtils::GetNetworkCandidatesInfo(networkCandidates,
        filterName),"");
    filterName = "hasInternet";
    EXPECT_NE(NetworkSelection::NetworkSelectionUtils::GetNetworkCandidatesInfo(networkCandidates,
        filterName),"");
}

HWTEST_F(NetworkSelectionUtilsTest, IsOpenAndMaybePortal1, TestSize.Level1) {
    InterScanInfo scanInfo1;
    NetworkSelection::NetworkCandidate filternetworkCandidate(scanInfo1);
    std::string filterName;
    filternetworkCandidate.wifiDeviceConfig.ssid = "xx";
    filternetworkCandidate.wifiDeviceConfig.bssid = "11:11:11:11:11";
    filternetworkCandidate.wifiDeviceConfig.networkId = 1;
    filternetworkCandidate.wifiDeviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
    filternetworkCandidate.filtedReason["hasInternet"].insert(NetworkSelection::WEAK_ALGORITHM_WEP_SECURITY);
    filterName = "";
    EXPECT_FALSE(NetworkSelection::NetworkSelectionUtils::IsOpenAndMaybePortal(filternetworkCandidate, filterName));
}

HWTEST_F(NetworkSelectionUtilsTest, IsOpenAndMaybePortal2, TestSize.Level1) {
    InterScanInfo scanInfo1;
    NetworkSelection::NetworkCandidate filternetworkCandidate(scanInfo1);
    std::string filterName;
    filternetworkCandidate.wifiDeviceConfig.ssid = "xx";
    filternetworkCandidate.wifiDeviceConfig.bssid = "11:11:11:11:11";
    filternetworkCandidate.wifiDeviceConfig.networkId = 1;
    filternetworkCandidate.wifiDeviceConfig.noInternetAccess = 1;
    filternetworkCandidate.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    filternetworkCandidate.filtedReason["hasInternet"].insert(NetworkSelection::WEAK_ALGORITHM_WEP_SECURITY);
    filterName = "hasInternet";
    EXPECT_FALSE(NetworkSelection::NetworkSelectionUtils::IsOpenAndMaybePortal(filternetworkCandidate, filterName));
}

HWTEST_F(NetworkSelectionUtilsTest, IsOpenAndMaybePortal3, TestSize.Level1) {
    InterScanInfo scanInfo1;
    NetworkSelection::NetworkCandidate filternetworkCandidate(scanInfo1);
    std::string filterName;
    filternetworkCandidate.wifiDeviceConfig.ssid = "xx";
    filternetworkCandidate.wifiDeviceConfig.bssid = "11:11:11:11:11";
    filternetworkCandidate.wifiDeviceConfig.networkId = 1;
    filternetworkCandidate.wifiDeviceConfig.noInternetAccess = 0;
    filternetworkCandidate.wifiDeviceConfig.networkStatusHistory = 3;
    filternetworkCandidate.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    filternetworkCandidate.filtedReason["hasInternet"].insert(NetworkSelection::WEAK_ALGORITHM_WEP_SECURITY);
    filterName = "hasInternet";
    EXPECT_FALSE(NetworkSelection::NetworkSelectionUtils::IsOpenAndMaybePortal(filternetworkCandidate, filterName));
}

HWTEST_F(NetworkSelectionUtilsTest, IsOpenAndMaybePortal4, TestSize.Level1) {
    InterScanInfo scanInfo1;
    NetworkSelection::NetworkCandidate filternetworkCandidate(scanInfo1);
    std::string filterName;
    filternetworkCandidate.wifiDeviceConfig.ssid = "xx";
    filternetworkCandidate.wifiDeviceConfig.bssid = "11:11:11:11:11";
    filternetworkCandidate.wifiDeviceConfig.networkId = 1;
    filternetworkCandidate.wifiDeviceConfig.noInternetAccess = 0;
    filternetworkCandidate.wifiDeviceConfig.networkStatusHistory = 0;
    filternetworkCandidate.wifiDeviceConfig.keyMgmt = KEY_MGMT_NONE;
    filternetworkCandidate.filtedReason["hasInternet"].insert(NetworkSelection::WEAK_ALGORITHM_WEP_SECURITY);
    filterName = "hasInternet";
    EXPECT_TRUE(NetworkSelection::NetworkSelectionUtils::IsOpenAndMaybePortal(filternetworkCandidate, filterName));
}

}
}