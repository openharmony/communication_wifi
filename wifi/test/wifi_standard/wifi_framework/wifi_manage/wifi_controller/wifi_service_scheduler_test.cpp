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
#include "wifi_service_scheduler.h"
#include "wifi_config_center.h"


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
class WWifiServiceSchedulerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pWifiServiceScheduler = std::make_unique<WifiServiceScheduler>();
    }

    virtual void TearDown()
    {
        pWifiServiceScheduler.reset();
    }

    std::unique_ptr<WifiServiceScheduler> pWifiServiceScheduler;

    void AutoStartStaServiceTest()
    {
        std::string ifName;
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::RUNNING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartStaService(0, ifName), WIFI_OPT_SUCCESS);
    }

    void AutoStopStaServiceTest()
    {
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopStaService(0), WIFI_OPT_SUCCESS);
    }

    void AutoStartScanOnlyTest()
    {
        std::string ifName;
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::RUNNING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartScanOnly(0, ifName), WIFI_OPT_SUCCESS);
    }

    void AutoStopScanOnlyTest()
    {
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSED, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopScanOnly(0), WIFI_OPT_SUCCESS);
    }

    void AutoStartSemiStaServiceTest()
    {
        std::string ifName;
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::SEMI_ACTIVE, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartSemiStaService(0, ifName), WIFI_OPT_SUCCESS);
    }

    void AutoStartApServiceTest()
    {
        std::string ifName;
        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(0, ifName), WIFI_OPT_FAILED);

        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::RUNNING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(0, ifName), WIFI_OPT_SUCCESS);
    }
    
    void AutoStopApServiceTest()
    {
        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::OPENING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopApService(0), WIFI_OPT_CLOSE_FAIL_WHEN_OPENING);

        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSED, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopApService(0), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
    }
};

HWTEST_F(WWifiServiceSchedulerTest, AutoStartStaServiceTest, TestSize.Level1)
{
    AutoStartStaServiceTest();
}

HWTEST_F(WWifiServiceSchedulerTest, AutoStopStaServiceTest, TestSize.Level1)
{
    AutoStopStaServiceTest();
}

HWTEST_F(WWifiServiceSchedulerTest, AutoStartScanOnlyTest, TestSize.Level1)
{
    AutoStartScanOnlyTest();
}

HWTEST_F(WWifiServiceSchedulerTest, AutoStopScanOnlyTest, TestSize.Level1)
{
    AutoStopScanOnlyTest();
}

HWTEST_F(WWifiServiceSchedulerTest, AutoStartSemiStaServiceTest, TestSize.Level1)
{
    AutoStartSemiStaServiceTest();
}

HWTEST_F(WWifiServiceSchedulerTest, AutoStartApServiceTest, TestSize.Level1)
{
    AutoStartApServiceTest();
}

HWTEST_F(WWifiServiceSchedulerTest, AutoStopApServiceTest, TestSize.Level1)
{
    AutoStopApServiceTest();
}
}
}