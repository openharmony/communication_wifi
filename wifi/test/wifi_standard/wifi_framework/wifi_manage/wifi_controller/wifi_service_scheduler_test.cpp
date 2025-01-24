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
#include "mock_wifi_config_center.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_sta_hal_interface.h"
#include "wifi_history_record_manager.h"

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

static std::string g_errLog;
    void WifiServiceSchedulerCallback(const LogType type, const LogLevel level,
                                      const unsigned int domain, const char *tag,
                                      const char *msg)
    {
        g_errLog = msg;
    }
class WifiServiceSchedulerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WifiManager::GetInstance().Init();
    }

    static void TearDownTestCase()
    {
        WifiManager::GetInstance().Exit();
    }

    virtual void SetUp()
    {
        pWifiServiceScheduler = std::make_unique<WifiServiceScheduler>();
        LOG_SetCallback(WifiServiceSchedulerCallback);
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
        EXPECT_EQ(pWifiServiceScheduler->AutoStartStaService(0, ifName), WIFI_OPT_FAILED);
    }

    void AutoStopStaServiceTest()
    {
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopStaService(0), WIFI_OPT_FAILED);
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
        EXPECT_EQ(pWifiServiceScheduler->AutoStopScanOnly(0, true), WIFI_OPT_FAILED);
    }

    void AutoStartSemiStaServiceTest()
    {
        std::string ifName;
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::SEMI_ACTIVE, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartSemiStaService(0, ifName), WIFI_OPT_FAILED);
    }

    void AutoStartApServiceTest()
    {
        std::string ifName;
        WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(0, ifName), WIFI_OPT_FAILED);

        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::RUNNING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(0, ifName), WIFI_OPT_FAILED);
    }
    
    void AutoStopApServiceTest()
    {
        WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::OPENING, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopApService(0), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);

        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSED, 0);
        EXPECT_EQ(pWifiServiceScheduler->AutoStopApService(0), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
    }
};

HWTEST_F(WifiServiceSchedulerTest, AutoStartStaServiceTest, TestSize.Level1)
{
    AutoStartStaServiceTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopStaServiceTest, TestSize.Level1)
{
    AutoStopStaServiceTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartScanOnlyTest, TestSize.Level1)
{
    AutoStartScanOnlyTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopScanOnlyTest, TestSize.Level1)
{
    AutoStopScanOnlyTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartSemiStaServiceTest, TestSize.Level1)
{
    AutoStartSemiStaServiceTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartApServiceTest, TestSize.Level1)
{
    AutoStartApServiceTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopApServiceTest, TestSize.Level1)
{
    AutoStopApServiceTest();
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartStaServiceTest01, TestSize.Level1)
{
    #undef HDI_CHIP_INTERFACE_SUPPORT
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
    EXPECT_EQ(pWifiServiceScheduler->AutoStartStaService(instId, staIfName), WIFI_OPT_FAILED);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartStaServiceTest02, TestSize.Level1)
{
    #undef HDI_CHIP_INTERFACE_SUPPORT
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    EXPECT_EQ(pWifiServiceScheduler->AutoStartStaService(instId, staIfName), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartWifi2ServiceTest01, TestSize.Level1)
{
    #undef HDI_CHIP_INTERFACE_SUPPORT
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
    EXPECT_EQ(pWifiServiceScheduler->AutoStartWifi2Service(instId, staIfName), WIFI_OPT_FAILED);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartWifi2ServiceTest02, TestSize.Level1)
{
    #undef HDI_CHIP_INTERFACE_SUPPORT
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    EXPECT_EQ(pWifiServiceScheduler->AutoStartWifi2Service(instId, staIfName), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopStaServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
    EXPECT_EQ(pWifiServiceScheduler->AutoStopStaService(instId), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopStaServiceTest02, TestSize.Level1)
{
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    EXPECT_EQ(pWifiServiceScheduler->AutoStopStaService(instId), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopWifi2ServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
    EXPECT_EQ(pWifiServiceScheduler->AutoStopWifi2Service(instId), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopWifi2ServiceTest02, TestSize.Level1)
{
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    EXPECT_EQ(pWifiServiceScheduler->AutoStopWifi2Service(instId), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, HandleGetStaFailedTest01, TestSize.Level1)
{
    int instId = 1;
    pWifiServiceScheduler->HandleGetStaFailed(instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartScanOnlyTest01, TestSize.Level1)
{
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiScanOnlyMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_EQ(pWifiServiceScheduler->AutoStartScanOnly(instId, staIfName), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartScanOnlyTest02, TestSize.Level1)
{
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiScanOnlyMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_EQ(pWifiServiceScheduler->AutoStartScanOnly(instId, staIfName), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopScanOnlyTest01, TestSize.Level1)
{
    int instId = 1;
    bool setIfaceDown = true;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiScanOnlyMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_EQ(pWifiServiceScheduler->AutoStopScanOnly(instId, setIfaceDown), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopScanOnlyTest02, TestSize.Level1)
{
    int instId = 1;
    bool setIfaceDown = true;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiScanOnlyMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiScanOnlyMidState(_, _, _))
        .WillRepeatedly(Return(true));
    EXPECT_EQ(pWifiServiceScheduler->AutoStopScanOnly(instId, setIfaceDown), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartSemiStaServiceTest01, TestSize.Level1)
{
    #undef HDI_CHIP_INTERFACE_SUPPORT
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
    EXPECT_EQ(pWifiServiceScheduler->AutoStartSemiStaService(instId, staIfName), WIFI_OPT_FAILED);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartSemiStaServiceTest02, TestSize.Level1)
{
    #undef HDI_CHIP_INTERFACE_SUPPORT
    int instId = 1;
    std::string staIfName = "TEST";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiMidState(_, _, _))
        .WillRepeatedly(Return(true));
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    EXPECT_EQ(pWifiServiceScheduler->AutoStartSemiStaService(instId, staIfName), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, PostStartWifi2Test01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_EQ(pWifiServiceScheduler->PostStartWifi2(instId), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, StartDependentServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_EQ(pWifiServiceScheduler->StartDependentService(instId), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, StartWifiProServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_EQ(pWifiServiceScheduler->StartWifiProService(instId), WIFI_OPT_FAILED);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiOpenResTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::OPEN_WIFI_OPENING;
    int instId = 1;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset())
        .WillRepeatedly(Return(false));
    pWifiServiceScheduler->DispatchWifiOpenRes(state, instId);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiOpenResTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::OPEN_WIFI_SUCCEED;
    int instId = 1;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset())
        .WillRepeatedly(Return(false));
    pWifiServiceScheduler->DispatchWifiOpenRes(state, instId);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifi2OpenResTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::OPEN_WIFI_OPENING;
    int instId = 1;

    pWifiServiceScheduler->DispatchWifi2OpenRes(state, instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifi2OpenResTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::OPEN_WIFI_SUCCEED;
    int instId = 1;

    pWifiServiceScheduler->DispatchWifi2OpenRes(state, instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiSemiActiveResTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::ENABLE_SEMI_WIFI_OPENING;
    int instId = 1;

    pWifiServiceScheduler->DispatchWifiSemiActiveRes(state, instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiSemiActiveResTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::ENABLE_SEMI_WIFI_SUCCEED;
    int instId = 1;

    pWifiServiceScheduler->DispatchWifiSemiActiveRes(state, instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiCloseResTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CLOSE_WIFI_CLOSING;
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset())
        .WillRepeatedly(Return(false));
    pWifiServiceScheduler->DispatchWifiCloseRes(state, instId);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiCloseResTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::CLOSE_WIFI_SUCCEED;
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset())
        .WillRepeatedly(Return(true));
    pWifiServiceScheduler->DispatchWifiCloseRes(state, instId);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifiCloseResTest03, TestSize.Level1)
{
    OperateResState state = OperateResState::CLOSE_WIFI_SUCCEED;
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset())
        .WillRepeatedly(Return(false));
    pWifiServiceScheduler->DispatchWifiCloseRes(state, instId);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifi2CloseResTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CLOSE_WIFI_CLOSING;
    int instId = 1;

    pWifiServiceScheduler->DispatchWifi2CloseRes(state, instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, DispatchWifi2CloseResTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::CLOSE_WIFI_SUCCEED;
    int instId = 1;

    pWifiServiceScheduler->DispatchWifi2CloseRes(state, instId);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartApServiceTest01, TestSize.Level1)
{
    int instId = 1;
    std::string softApIfName = "TEST";
    
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSING));
    EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(instId, softApIfName), WIFI_OPT_FAILED);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartApServiceTest02, TestSize.Level1)
{
    int instId = 1;
    std::string softApIfName = "TEST";
    
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::OPENING));
    EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(instId, softApIfName), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStartApServiceTest03, TestSize.Level1)
{
    int instId = 1;
    std::string softApIfName = "TEST";
    
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetApMidState(_, _, _))
        .WillRepeatedly(Return(true));
    EXPECT_EQ(pWifiServiceScheduler->AutoStartApService(instId, softApIfName), WIFI_OPT_FAILED);
}

HWTEST_F(WifiServiceSchedulerTest, AutoStopApServiceTest01, TestSize.Level1)
{
    int instId = 1;
    
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetApMidState(_, _, _))
        .WillRepeatedly(Return(true));
    EXPECT_EQ(pWifiServiceScheduler->AutoStopApService(instId), WIFI_OPT_SUCCESS);
}
}
}