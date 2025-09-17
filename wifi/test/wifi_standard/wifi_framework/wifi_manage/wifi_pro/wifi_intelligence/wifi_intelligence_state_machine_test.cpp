/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include <wifi_intelligence_state_machine.h>
#include <internal_message.h>

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class WifiIntelligenceStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
       wifiIntelligenceStateMachine_ = std::make_unique<WifiIntelligenceStateMachine>();
        defaultState_ = std::make_unique<WifiIntelligenceStateMachine::DefaultState>(
            wifiIntelligenceStateMachine_.get()); 
    }
    virtual void TearDown() {}
public:
    std::unique_ptr<WifiIntelligenceStateMachine>wifiIntelligenceStateMachine_;
    std::unique_ptr<WifiIntelligenceStateMachine::DefaultState>defaultState_;
};

HWTEST_F(WifiIntelligenceStateMachineTest, InitWifiIntelligenceStatesTest, TestSize.Level1)
{
    EXPECT_EQ(wifiIntelligenceStateMachine_->InitWifiIntelligenceStates(), WIFI_OPT_SUCCESS);
}
 
HWTEST_F(WifiIntelligenceStateMachineTest, InitializeTest, TestSize.Level1)
{
    EXPECT_EQ(wifiIntelligenceStateMachine_->Initialize(), WIFI_OPT_SUCCESS);
}
 
HWTEST_F(WifiIntelligenceStateMachineTest, ExecuteStateMsgTest, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}
 
HWTEST_F(WifiIntelligenceStateMachineTest, HandleWifiDisabledTest00, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED));
    defaultState_->HandleWifiDisabled(msg);
    int state = static_cast<int>(OperateResState::CONNECT_AP_CONNECTED);
    EXPECT_EQ(msg->GetParam1(), state);
}
 
HWTEST_F(WifiIntelligenceStateMachineTest, HandleWifiDisabledTest01, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED));
    defaultState_->HandleWifiDisabled(msg);
    int state = static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED);
    EXPECT_EQ(msg->GetParam1(), state);
}
}
}