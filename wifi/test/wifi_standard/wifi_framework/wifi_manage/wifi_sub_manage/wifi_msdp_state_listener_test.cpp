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
#include <string>
#include <vector>
#include "wifi_msdp_state_listener.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"

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

class DeviceMovementCallbackTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}

    static void TearDownTestCase()
    {}

    virtual void SetUp()
    {
        deviceMovementCallback_ = std::make_unique<DeviceMovementCallback>();
    }

    virtual void TearDown()
    {
        deviceMovementCallback_.reset();
    }
    std::unique_ptr<DeviceMovementCallback> deviceMovementCallback_;
};

HWTEST_F(DeviceMovementCallbackTest, DealMultiStaStopTest01, TestSize.Level1)
{
    Msdp::MovementDataUtils::MovementData movementData;
    movementData.type = Msdp::MovementDataUtils::MovementType::TYPE_STILL;
    movementData.value = Msdp::MovementDataUtils::MovementValue::VALUE_ENTER;
    deviceMovementCallback_->OnMovementChanged(movementData);
    EXPECT_NE(deviceMovementCallback_->movementChangeEventHandler, nullptr);

    movementData.value = Msdp::MovementDataUtils::MovementValue::VALUE_INVALID;
    deviceMovementCallback_->OnMovementChanged(movementData);
}

} // namespace Wifi
} // namespace OHOS