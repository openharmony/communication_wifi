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
#include "wifi_toggler_manager.h"
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

class WifiTogglerManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}

    static void TearDownTestCase()
    {}

    virtual void SetUp()
    {
        wifiTogglerManager_ = std::make_unique<WifiTogglerManager>();
    }

    virtual void TearDown()
    {
        wifiTogglerManager_.reset();
    }
    std::unique_ptr<WifiTogglerManager> wifiTogglerManager_;
};

HWTEST_F(WifiTogglerManagerTest, SoftapToggledTest02, TestSize.Level1)
{
    int isOpen = 0;
    int id = 1;
    EXPECT_EQ(wifiTogglerManager_->SoftapToggled(isOpen, id), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiTogglerManagerTest, ScanOnlyToggledTest01, TestSize.Level1)
{
    int isOpen = 0;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAirplaneModeState()).WillRepeatedly(Return(MODE_STATE_OPEN));
    EXPECT_EQ(wifiTogglerManager_->ScanOnlyToggled(isOpen), WIFI_OPT_FAILED);

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAirplaneModeState()).WillRepeatedly(Return(MODE_STATE_CLOSE));
    EXPECT_EQ(wifiTogglerManager_->ScanOnlyToggled(isOpen), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiTogglerManagerTest, AirplaneToggledTest01, TestSize.Level1)
{
    int isOpen = 1;
    EXPECT_EQ(wifiTogglerManager_->AirplaneToggled(isOpen), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiTogglerManagerTest, GetControllerMachineTest01, TestSize.Level1)
{
    EXPECT_NE(wifiTogglerManager_->GetControllerMachine(), nullptr);
}

HWTEST_F(WifiTogglerManagerTest, DealConcreateStopTest01, TestSize.Level1)
{
    int id = 1;
    wifiTogglerManager_->DealConcreateStop(id);
    EXPECT_NE(wifiTogglerManager_->pWifiControllerMachine, nullptr);
}

HWTEST_F(WifiTogglerManagerTest, DealRptStopTest01, TestSize.Level1)
{
    int id = 1;
    wifiTogglerManager_->DealRptStop(id);
    EXPECT_NE(wifiTogglerManager_->pWifiControllerMachine, nullptr);
}

HWTEST_F(WifiTogglerManagerTest, DealRptStartFailureTest01, TestSize.Level1)
{
    int id = 1;
    wifiTogglerManager_->DealRptStartFailure(id);
    EXPECT_NE(wifiTogglerManager_->pWifiControllerMachine, nullptr);
}

HWTEST_F(WifiTogglerManagerTest, DealClientRemovedTest01, TestSize.Level1)
{
    int id = 1;
    wifiTogglerManager_->DealClientRemoved(id);
    EXPECT_NE(wifiTogglerManager_->pWifiControllerMachine, nullptr);
}

HWTEST_F(WifiTogglerManagerTest, DealMultiStaStartFailureTest01, TestSize.Level1)
{
    int id = 1;
    wifiTogglerManager_->DealMultiStaStartFailure(id);
    EXPECT_NE(wifiTogglerManager_->pWifiControllerMachine, nullptr);
}

HWTEST_F(WifiTogglerManagerTest, DealMultiStaStopTest01, TestSize.Level1)
{
    int id = 1;
    wifiTogglerManager_->DealMultiStaStop(id);
    EXPECT_NE(wifiTogglerManager_->pWifiControllerMachine, nullptr);
}
} // namespace Wifi
} // namespace OHOS