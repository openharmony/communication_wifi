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
#include <gmock/gmock.h>
#include "wifi_cmd_client.h"
#include "wifi_log.h"
#include "wifi_logger.h"
using namespace OHOS::Wifi;
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
class WifiCmdClientTest : public Test {
public:
    void SetUp() override
    {
        wifiCmdClient_ = std::make_shared<WifiCmdClient>();
    }

    void TearDown() override
    {
        wifiCmdClient_.reset();
    }

protected:
    static const int maxPrivCmdSize = 4096;
    std::shared_ptr<WifiCmdClient> wifiCmdClient_;
};

HWTEST_F(WifiCmdClientTest, SendCmdToDriver_ReturnsNegativeOneWhenIfNameIsEmpty, TestSize.Level1)
{
    int result = wifiCmdClient_->SendCmdToDriver("", 0, "param");
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiCmdClientTest, SendCmdToDriver_ReturnsNegativeOneWhenParamIsEmpty, TestSize.Level1)
{
    int result = wifiCmdClient_->SendCmdToDriver("ifName", 0, "");
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiCmdClientTest, SendCmdToDriver_ReturnsNegativeOneWhenParamSizeExceedsMaxPrivCmdSize, TestSize.Level1)
{
    std::string param(maxPrivCmdSize, 'a');
    int result = wifiCmdClient_->SendCmdToDriver("ifName", 0, param);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiCmdClientTest, SendCmdToDriver_CallsSetRxListenWhenCommandIdIsCMD_SET_RX_LISTEN_POWER_SAVING_SWITCH,
    TestSize.Level1)
{
    std::string ifName = "ifName";
    std::string param = "param";
    int result1 = wifiCmdClient_->SetRxListen(ifName, param);
    int result = wifiCmdClient_->SendCmdToDriver(ifName, CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH, param);
    EXPECT_EQ(result, result1);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiCmdClientTest, SendCmdToDriver_CallsSet2gSoftapMssWhenCommandIdIsCMD_SET_SOFTAP_2G_MSS, TestSize.Level1)
{
    std::string ifName = "ifName";
    std::string param = "param";
    int result1 = wifiCmdClient_->Set2gSoftapMss(ifName, param);

    int result = wifiCmdClient_->SendCmdToDriver(ifName, CMD_SET_SOFTAP_2G_MSS, param);
    EXPECT_EQ(result, result1);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiCmdClientTest, SendCmdToDriver_ReturnsNegativeOneWhenCommandIdIsNotSupported, TestSize.Level1)
{
    std::string ifName = "ifName";
    std::string param = "param";

    int result = wifiCmdClient_->SendCmdToDriver(ifName, 100, param);
    EXPECT_EQ(result, -1);
}

