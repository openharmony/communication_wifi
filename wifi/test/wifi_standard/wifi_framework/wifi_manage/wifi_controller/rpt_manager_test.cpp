/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "rpt_manager.h"
#include "wifi_logger.h"
#include "mock_wifi_manager.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
#ifdef FEATURE_RPT_SUPPORT
class RptManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        WifiManager::GetInstance().Exit();
    }

    virtual void SetUp()
    {
        rptManager_ = std::make_unique<RptManager>(RptManager::Role::ROLE_RPT, 0);
        EXPECT_EQ(rptManager_->InitRptManager(), WIFI_OPT_SUCCESS);
    }

    virtual void TearDown()
    {
        rptManager_.reset();
    }

    std::unique_ptr<RptManager> rptManager_;
};

HWTEST_F(RptManagerTest, RoleAndRunningTest, TestSize.Level1)
{
    EXPECT_EQ(rptManager_->GetRole(), RptManager::Role::ROLE_RPT);
    EXPECT_NE(rptManager_->GetMachine(), nullptr);
    EXPECT_FALSE(rptManager_->IsRptRunning());
}

#ifdef FEATURE_WITH_GO_SIMULATION_AP
HWTEST_F(RptManagerTest, OnStaConnChanged_LinkedAndUnlinked, TestSize.Level1)
{
    rptManager_->OnStaConnChanged(true);
    rptManager_->OnStaConnChanged(false);
    EXPECT_NE(rptManager_->GetMachine(), nullptr);
}
#endif

HWTEST_F(RptManagerTest, StationJoinLeaveTest, TestSize.Level1)
{
    rptManager_->OnStationJoin("aa:bb:cc:dd:ee:ff");
    rptManager_->OnStationLeave("aa:bb:cc:dd:ee:ff");
    EXPECT_NE(rptManager_->GetMachine(), nullptr);
}
#endif
} // namespace Wifi
} // namespace OHOS
