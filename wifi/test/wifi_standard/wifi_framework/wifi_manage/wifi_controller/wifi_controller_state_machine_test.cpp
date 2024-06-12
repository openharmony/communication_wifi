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
#include "wifi_controller_state_machine.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"

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
class WifiControllerMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pWifiControllerMachine = std::make_unique<WifiControllerMachine>();
        pWifiControllerMachine->InitWifiControllerMachine();
    }

    virtual void TearDown()
    {
        pWifiControllerMachine.reset();
    }

    std::unique_ptr<WifiControllerMachine> pWifiControllerMachine;

    void DefaultStateGoInStateSuccess()
    {
        pWifiControllerMachine->pDefaultState->GoInState();
    }

    void DefaultStateGoOutStateSuccess()
    {
        pWifiControllerMachine->pDefaultState->GoOutState();
    }

    void EnableStateGoInStateSuccess()
    {
        pWifiControllerMachine->pEnableState->GoInState();
    }

    void EnableStateGoOutStateSuccess()
    {
        pWifiControllerMachine->pEnableState->GoOutState();
    }

    void DisableStateGoInStateSuccess()
    {
        pWifiControllerMachine->pDisableState->GoInState();
    }

    void DisableStateGoOutStateSuccess()
    {
        pWifiControllerMachine->pDisableState->GoOutState();
    }

    void WifiToggledTest1()
    {
        InternalMessage msg;
        WifiSettings::GetInstance().SetWifiToggledState(false);
        WifiSettings::GetInstance().SetScanOnlySwitchState(0, 0);
        WifiSettings::GetInstance().SetWifiStopState(true);
        msg.SetMessageName(CMD_WIFI_TOGGLED);
        msg.SetParam1(1);
        msg.SetParam2(0);
        sleep(1);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(&msg));
        EXPECT_FALSE(pWifiControllerMachine->pDefaultState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(nullptr));
    }

    void WifiToggledTest2()
    {
        InternalMessage msg;
        WifiSettings::GetInstance().SetWifiToggledState(false);
        WifiSettings::GetInstance().SetScanOnlySwitchState(0, 0);
        WifiSettings::GetInstance().SetWifiStopState(true);
        msg.SetMessageName(CMD_WIFI_TOGGLED);
        msg.SetParam1(0);
        msg.SetParam2(0);
        sleep(1);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(&msg));
        msg.SetMessageName(CMD_AIRPLANE_TOGGLED);
        msg.SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(&msg));
    }

    void HandleStaStartFail()
    {
        InternalMessage msg;
        WifiSettings::GetInstance().SetWifiToggledState(false);
        WifiSettings::GetInstance().SetScanOnlySwitchState(0, 0);
        WifiSettings::GetInstance().SetWifiStopState(true);
        msg.SetMessageName(CMD_STA_START_FAILURE);
        msg.SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
        WifiSettings::GetInstance().SetWifiStateOnAirplaneChanged(1);
        msg.SetMessageName(CMD_CONCRETE_STOPPED);
        msg.SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
        msg.SetMessageName(CMD_STA_REMOVED);
        msg.SetParam1(0);
        msg.SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
        msg.SetMessageName(CMD_CONCRETECLIENT_REMOVED);
        msg.SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(&msg));
    }

    void RemoveConcreteManagerTest()
    {
        pWifiControllerMachine->RemoveConcreteManager(0);
    }

    void HandleStaCloseTest()
    {
        pWifiControllerMachine->HandleStaClose(0);
    }

    void HandleStaStartTest()
    {
        pWifiControllerMachine->HandleStaStart(0);
    }

    void HandleStaSemiActiveTest()
    {
        pWifiControllerMachine->HandleStaSemiActive(0);
    }

    void HandleConcreteStopTest()
    {
        pWifiControllerMachine->HandleConcreteStop(0);
    }

    void ClearStartFailCountTest()
    {
        pWifiControllerMachine->ClearWifiStartFailCount();
        pWifiControllerMachine->ClearApStartFailCount();
    }

    void RmoveSoftapManagerTest()
    {
        pWifiControllerMachine->RmoveSoftapManager(0);
    }

    void HandleSoftapStopTest()
    {
        pWifiControllerMachine->HandleSoftapStop(0);
    }

    void StopSoftapCloseTimerTest()
    {
        pWifiControllerMachine->StopSoftapCloseTimer();
    }
};

HWTEST_F(WifiControllerMachineTest, DefaultStateGoInStateSuccess, TestSize.Level1)
{
    DefaultStateGoInStateSuccess();
}

HWTEST_F(WifiControllerMachineTest, DefaultStateGoOutStateSuccess, TestSize.Level1)
{
    DefaultStateGoOutStateSuccess();
}

HWTEST_F(WifiControllerMachineTest, EnableStateGoInStateSuccess, TestSize.Level1)
{
    EnableStateGoInStateSuccess();
}

HWTEST_F(WifiControllerMachineTest, EnableStateGoOutStateSuccess, TestSize.Level1)
{
    EnableStateGoOutStateSuccess();
}

HWTEST_F(WifiControllerMachineTest, DisableStateGoInStateSuccess, TestSize.Level1)
{
    DisableStateGoInStateSuccess();
}

HWTEST_F(WifiControllerMachineTest, DisableStateGoOutStateSuccess, TestSize.Level1)
{
    DisableStateGoOutStateSuccess();
}

HWTEST_F(WifiControllerMachineTest, WifiToggledTest1, TestSize.Level1)
{
    WifiToggledTest1();
}

HWTEST_F(WifiControllerMachineTest, WifiToggledTest2, TestSize.Level1)
{
    WifiToggledTest2();
}

HWTEST_F(WifiControllerMachineTest, HandleStaStartFail, TestSize.Level1)
{
    HandleStaStartFail();
}

HWTEST_F(WifiControllerMachineTest, RemoveConcreteManagerTest, TestSize.Level1)
{
    RemoveConcreteManagerTest();
}

HWTEST_F(WifiControllerMachineTest, HandleStaCloseTest, TestSize.Level1)
{
    HandleStaCloseTest();
}

HWTEST_F(WifiControllerMachineTest, HandleStaStartTest, TestSize.Level1)
{
    HandleStaStartTest();
}

HWTEST_F(WifiControllerMachineTest, HandleStaSemiActiveTest, TestSize.Level1)
{
    HandleStaSemiActiveTest();
}

HWTEST_F(WifiControllerMachineTest, HandleConcreteStopTest, TestSize.Level1)
{
    HandleConcreteStopTest();
}

HWTEST_F(WifiControllerMachineTest, ClearStartFailCountTest, TestSize.Level1)
{
    ClearStartFailCountTest();
}

HWTEST_F(WifiControllerMachineTest, RmoveSoftapManagerTest, TestSize.Level1)
{
    RmoveSoftapManagerTest();
}

HWTEST_F(WifiControllerMachineTest, HandleSoftapStopTest, TestSize.Level1)
{
    HandleSoftapStopTest();
}

HWTEST_F(WifiControllerMachineTest, StopSoftapCloseTimerTest, TestSize.Level1)
{
    StopSoftapCloseTimerTest();
}
}
}