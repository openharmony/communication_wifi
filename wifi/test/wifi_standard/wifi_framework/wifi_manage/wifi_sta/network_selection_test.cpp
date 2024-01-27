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
#include "mock_wifi_settings.h"
#include "network_selection_manager.h"
#include "external_wifi_filter_builder_manager.h"

using ::testing::_;
using ::testing::Return;
using ::testing::An;
using ::testing::ext::TestSize;
using ::testing::ReturnRoundRobin;
using ::testing::Invoke;


namespace OHOS {
namespace Wifi {
class NetworkSelectionTest : public testing::Test {};

HWTEST_F(NetworkSelectionTest, TestHiddenNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -77;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    scanInfo1.ssid = "test1";
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestMinRssiFor24G, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 2407;
    scanInfo1.rssi = -78;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    scanInfo1.rssi = -77;
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestMinRssiFor5G, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5820;
    scanInfo1.rssi = -81;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    scanInfo1.rssi = -80;
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestUnSavedNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
    WillRepeatedly(Return(0));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestPasspointNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
    WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        wifiDeviceConfig.isPasspoint = true;
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        wifiDeviceConfig.isPasspoint = false;
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestEphemeralNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
    WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        wifiDeviceConfig.isEphemeral = true;
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        wifiDeviceConfig.isEphemeral = false;
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestEnableNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
    WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::DISABLED);
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::UNKNOWN);
        return 0;
    }));
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestMatchUserSelectBssidNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
    WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        wifiDeviceConfig.networkId = 0;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        wifiDeviceConfig.userSelectBssid = "22:22:22:22:22";
        return 0;
    }));
    NetworkSelectionManager selectionManager;
    EXPECT_FALSE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    scanInfo1.bssid = "22:22:22:22:22";
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
}

HWTEST_F(NetworkSelectionTest, TestBlackListNetworks, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    auto &scanInfo3 = scanInfos.emplace_back();
    scanInfo3.bssid = "33:33:33:33:33";
    scanInfo3.ssid = "test3";
    scanInfo3.frequency = 5028;
    scanInfo3.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
    WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
        } else if (ssid == "test3") {
            wifiDeviceConfig.networkId = 2;
        }
        wifiDeviceConfig.connFailedCount = 3;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 2);
}

HWTEST_F(NetworkSelectionTest, TestHasInternetNetworksByDifferentHistoryStatus, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.networkStatusHistory = 0b01;
        }
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestHasInternetNetworksWithDifferentSignalLevels, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(ReturnRoundRobin({3, 4}));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
        }
        wifiDeviceConfig.networkStatusHistory = 0b01;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestHasInternetNetworksWithDifferentSecurities, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    scanInfo2.capabilities = "SAE";
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
        }
        wifiDeviceConfig.networkStatusHistory = 0b01;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestHasInternetNetworksWithDifferentBands, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 2047;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
        }
        wifiDeviceConfig.networkStatusHistory = 0b01;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestHasInternetNetworksWithDifferentBandsAndDifferentSignalLevels, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 2047;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(ReturnRoundRobin({4, 3}));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
        }
        wifiDeviceConfig.networkStatusHistory = 0b01;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestHasInternetNetworksWithDiffrentRssi, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 2047;
    scanInfo1.rssi = -56;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 2047;
    scanInfo2.rssi = -55;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
        }
        wifiDeviceConfig.networkStatusHistory = 0b01;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestPortalNetworks, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -55;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 2047;
    scanInfo2.rssi = -55;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(ReturnRoundRobin({4, 3}));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
            wifiDeviceConfig.lastHasInternetTime = time(0) - 1;
        } else if (ssid == "test2") {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.lastHasInternetTime = time(0) + 1;
        }
        wifiDeviceConfig.isPortal = true;
        wifiDeviceConfig.networkStatusHistory = 0b01;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    EXPECT_TRUE(selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos));
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestBlackListNetworkAndNoInternetNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
            wifiDeviceConfig.connFailedCount = 3;
        } else {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.noInternetAccess = true;
        }
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos);
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestNoInternetNetworkAndPortalNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
            wifiDeviceConfig.noInternetAccess = true;
        } else {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.isPortal = true;
        }
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos);
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestPortalNetworkAndRecoveryNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
            wifiDeviceConfig.isPortal = true;
        } else {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.noInternetAccess = true;
            wifiDeviceConfig.networkStatusHistory = 0b0111;
        }
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos);
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestRecoveryNetworkAndHasInternetNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -80;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -80;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
            wifiDeviceConfig.noInternetAccess = true;
            wifiDeviceConfig.networkStatusHistory = 0b0111;
        } else {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.networkStatusHistory = 0b0101;
        }
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos);
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestRecentUserSelectNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -55;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -55;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(
        time(0) - 8 * 60 * 60 + 1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else {
            wifiDeviceConfig.networkId = 1;
        }
        wifiDeviceConfig.networkStatusHistory = 0b0101;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos);
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}

HWTEST_F(NetworkSelectionTest, TestHighSecurityNetwork, TestSize.Level1)
{
    NetworkSelectionResult selectionResult;
    std::vector<InterScanInfo> scanInfos;
    auto &scanInfo1 = scanInfos.emplace_back();
    scanInfo1.bssid = "11:11:11:11:11";
    scanInfo1.ssid = "test1";
    scanInfo1.frequency = 5028;
    scanInfo1.rssi = -55;
    auto &scanInfo2 = scanInfos.emplace_back();
    scanInfo2.bssid = "22:22:22:22:22";
    scanInfo2.ssid = "test2";
    scanInfo2.frequency = 5028;
    scanInfo2.rssi = -55;
    NetworkSelectionManager selectionManager;
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkId(_)).WillRepeatedly(Return(-1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    EXPECT_CALL(WifiSettings::GetInstance(),
        GetDeviceConfig(An<const std::string &>(), An<const std::string &>(), _)).
        WillRepeatedly(Invoke([](const std::string &ssid, const std::string &, WifiDeviceConfig &wifiDeviceConfig) {
        if (ssid == "test1") {
            wifiDeviceConfig.networkId = 0;
        } else {
            wifiDeviceConfig.networkId = 1;
            wifiDeviceConfig.keyMgmt = "WEP";
        }
        wifiDeviceConfig.networkStatusHistory = 0b0101;
        wifiDeviceConfig.status = static_cast<int>(WifiDeviceConfigStatus::ENABLED);
        return 0;
    }));
    selectionManager.SelectNetwork(selectionResult, NetworkSelectType::AUTO_CONNECT, scanInfos);
    EXPECT_EQ(selectionResult.wifiDeviceConfig.networkId, 1);
}
}
}
