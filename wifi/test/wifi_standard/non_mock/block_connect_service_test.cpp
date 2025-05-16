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

#include <gtest/gtest.h>
#include <memory>
#include "wifi_log.h"
#include "wifi_logger.h"
#include "block_connect_service.h"

namespace OHOS {
namespace Wifi {

using namespace testing;
using ::testing::ext::TestSize;

class BlockConnectServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        WifiDeviceConfig config;
        config.networkSelectionStatus.status = WifiDeviceConfigStatus::ENABLED;
        config.networkId = 1;
        config.bssid = "00:00:00:00:00:00";
        config.ssid = "test";
        WifiSettings::GetInstance().AddDeviceConfig(config);
    }
    virtual void TearDown() {}
};

HWTEST_F(BlockConnectServiceTest, shouldAutoConnect_ReturnsTrueWhenStatusIsEnabled, TestSize.Level1)
{
    // Test logic here
    WifiDeviceConfig config;
    config.networkSelectionStatus.status = WifiDeviceConfigStatus::ENABLED;
    bool result = BlockConnectService::GetInstance().ShouldAutoConnect(config);
    EXPECT_EQ(result, true);
}

HWTEST_F(BlockConnectServiceTest, shouldAutoConnect_ReturnsFalseWhenStatusIsDisabled, TestSize.Level1)
{
    // Test logic here
    WifiDeviceConfig config;
    config.networkSelectionStatus.status = WifiDeviceConfigStatus::DISABLED;
    bool result = BlockConnectService::GetInstance().ShouldAutoConnect(config);
    EXPECT_EQ(result, false);
}

HWTEST_F(BlockConnectServiceTest, updateAllNetworkSelectStatus_ReturnsTrueWhenSuccessful, TestSize.Level1)
{
    // Test logic here
    bool result = BlockConnectService::GetInstance().UpdateAllNetworkSelectStatus();
    EXPECT_EQ(result, true);
}

HWTEST_F(BlockConnectServiceTest, EnableNetworkSelectStatus_ReturnsTrueWhenSuccessful, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = 1;
    bool result = BlockConnectService::GetInstance().EnableNetworkSelectStatus(targetNetworkId);
    EXPECT_EQ(result, true);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
}

HWTEST_F(BlockConnectServiceTest, EnableNetworkSelectStatus_ReturnsFalseWhenInvalidId, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = -1;
    bool result = BlockConnectService::GetInstance().EnableNetworkSelectStatus(targetNetworkId);
    EXPECT_EQ(result, false);
}

HWTEST_F(BlockConnectServiceTest, CalculateDisablePolicy_ReturnsCorrectDisablePolicy, TestSize.Level1)
{
    // Test logic here
    DisablePolicy policy =
        BlockConnectService::GetInstance().CalculateDisablePolicy(DisabledReason::DISABLED_AUTHENTICATION_FAILURE);
    EXPECT_EQ(policy.disableTime, 5 * 60 * 1000 * 1000);
    EXPECT_EQ(policy.disableCount, 3);
    EXPECT_EQ(policy.disableStatus, WifiDeviceConfigStatus::DISABLED);
}

HWTEST_F(BlockConnectServiceTest, updateNetworkSelectStatus_ReturnsTrueWhenSuccessful, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = 1;
    DisabledReason reason = DisabledReason::DISABLED_AUTHENTICATION_FAILURE;
    bool result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason);
    EXPECT_EQ(result, true);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::DISABLED);
    EXPECT_EQ(config.networkSelectionStatus.networkSelectionDisableReason, reason);
}

HWTEST_F(BlockConnectServiceTest, updateNetworkSelectStatus_ReturnsFalseWhenInvalidReason, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = 1;
    bool result = BlockConnectService::GetInstance().EnableNetworkSelectStatus(targetNetworkId);
    EXPECT_EQ(result, true);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
 
    DisabledReason reason = DisabledReason::DISABLED_DISASSOC_REASON;
    int reasonNumder = static_cast<int>(DisconnectDetailReason::UNUSED);
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason, reasonNumder);
    EXPECT_EQ(result, false);
 
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
}

HWTEST_F(BlockConnectServiceTest, updateNetworkSelectStatus_ReturnsTrueWhenValidReason, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = 1;
    bool result = BlockConnectService::GetInstance().EnableNetworkSelectStatus(targetNetworkId);
    EXPECT_EQ(result, true);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
 
    config.networkSelectionStatus.networkSelectionDisableReason = DisabledReason::DISABLED_DISASSOC_REASON;
    config.networkSelectionStatus.networkDisableTimeStamp = 0;
    config.networkSelectionStatus.networkDisableCount = 0;
    WifiSettings::GetInstance().AddDeviceConfig(config);
 
    DisabledReason reason = DisabledReason::DISABLED_DISASSOC_REASON;
    int reasonNumder = static_cast<int>(DisconnectDetailReason::PREV_AUTH_NOT_VALID);
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason, reasonNumder);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
 
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason, reasonNumder);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
 
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason, reasonNumder);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
 
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason, reasonNumder);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
 
    result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason, reasonNumder);
    EXPECT_EQ(result, true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::DISABLED);
}

HWTEST_F(BlockConnectServiceTest, isFrequentDisconnect_ReturnsFalseWhenFrequentDisconnects, TestSize.Level1)
{
    // Test logic here
    std::string bssid = "00:00:00:00:00:00";
    int wpaDisconnectReason = 1;
    int locallyGenerated = 0;
    bool result = BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, wpaDisconnectReason, locallyGenerated);
    EXPECT_EQ(result, false);
    result = BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, wpaDisconnectReason, locallyGenerated);
    EXPECT_EQ(result, false);
    result = BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, wpaDisconnectReason, locallyGenerated);
    EXPECT_EQ(result, false);
    result = BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, wpaDisconnectReason, locallyGenerated);
    EXPECT_EQ(result, false);
    result = BlockConnectService::GetInstance().IsFrequentDisconnect(bssid, wpaDisconnectReason, locallyGenerated);
    EXPECT_EQ(result, true);
}

HWTEST_F(BlockConnectServiceTest, IsWrongPassword_ReturnsTrueWhenBlockedDueToWrongPassword, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = 1;
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    config.numAssociation = 0;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    bool result = BlockConnectService::GetInstance().IsWrongPassword(targetNetworkId);
    EXPECT_EQ(result, true);
    config.numAssociation = 1;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    result = BlockConnectService::GetInstance().IsWrongPassword(targetNetworkId);
    EXPECT_EQ(result, false);
}

HWTEST_F(BlockConnectServiceTest, OnReceiveSettingsEnterEvent_EnablesAllNetworksWhenEnteringSettings, TestSize.Level1)
{
    // Test logic here
    int targetNetworkId = 1;
    DisabledReason reason = DisabledReason::DISABLED_AUTHENTICATION_FAILURE;
    bool result = BlockConnectService::GetInstance().UpdateNetworkSelectStatus(targetNetworkId, reason);
    EXPECT_EQ(result, true);
    WifiDeviceConfig config;
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
    BlockConnectService::GetInstance().OnReceiveSettingsEnterEvent(true);
    WifiSettings::GetInstance().GetDeviceConfig(targetNetworkId, config);
    EXPECT_EQ(config.networkSelectionStatus.status, WifiDeviceConfigStatus::ENABLED);
}
} // namespace Wifi
} // namespace OHOS