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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include "wifi_log.h"
#include "wifi_logger.h"
#include "block_connect_service.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("BlockConnectServiceTest");
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
    BlockConnectService::GetInstance().CheckNeedChangePolicy();
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

}
}