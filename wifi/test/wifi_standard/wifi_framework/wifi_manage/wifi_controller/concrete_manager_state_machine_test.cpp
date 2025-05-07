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
#include "concrete_manager_state_machine.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_country_code_manager.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_sta_hal_interface.h"

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

constexpr int SLEEP_TIME = 2;
constexpr int TEN = 10;
static std::string g_errLog;
void ConcreteManagerMachineCallback(const LogType type, const LogLevel level,
                                    const unsigned int domain, const char *tag,
                                    const char *msg)
{
    g_errLog = msg;
}

static std::unique_ptr<ConcreteMangerMachine> pConcreteManagerMachine;
class ConcreteManagerMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        sleep(TEN);
        pConcreteManagerMachine.reset();
        WifiManager::GetInstance().Exit();
    }
    virtual void SetUp()
    {
        WifiManager::GetInstance().Init();
        pConcreteManagerMachine = std::make_unique<ConcreteMangerMachine>();
        pWifiTogglerManager = std::make_unique<WifiTogglerManager>();
        pConcreteManagerMachine->InitConcreteMangerMachine();
        mCb.onStartFailure = DealConcreteStartFailure;
        mCb.onStopped = DealConcreteStop;
        mCb.onRemoved = DealClientRemoved;
        pConcreteManagerMachine->RegisterCallback(mCb);
        LOG_SetCallback(ConcreteManagerMachineCallback);
    }

    virtual void TearDown()
    {
        WifiAppStateAware::GetInstance().appChangeEventHandler->RemoveAsyncTask("WIFI_APP_STATE_EVENT");
    }

    static void DealConcreteStartFailure(int id = 0)
    {
        LOGI("concrete start fail");
    }

    static void DealConcreteStop(int id = 0)
    {
        LOGI("concrete stop");
    }

    static void DealClientRemoved(int id = 0)
    {
        LOGI("client remove");
    }

    std::unique_ptr<WifiTogglerManager> pWifiTogglerManager;
    ConcreteModeCallback mCb;

    void DefaultStateGoInStateSuccess()
    {
        pConcreteManagerMachine->pDefaultState->GoInState();
    }

    void DefaultStateGoOutStateSuccess()
    {
        pConcreteManagerMachine->pDefaultState->GoOutState();
    }

    void IdleStateGoInStateSuccess()
    {
        pConcreteManagerMachine->pIdleState->GoInState();
    }

    void IdleStateGoOutStateSuccess()
    {
        pConcreteManagerMachine->pIdleState->GoOutState();
    }

    void ConnectStateGoInStateSuccess()
    {
        pConcreteManagerMachine->pConnectState->GoInState();
    }

    void ConnectStateGoOutStateSuccess()
    {
        pConcreteManagerMachine->pConnectState->GoOutState();
    }

    void ScanOnlyStateGoInStateSuccess()
    {
        pConcreteManagerMachine->pScanonlyState->GoInState();
    }

    void ScanOnlyStateGoOutStateSuccess()
    {
        pConcreteManagerMachine->pScanonlyState->GoOutState();
    }

    void SemiActiveStateGoInStateSuccess()
    {
        pConcreteManagerMachine->pSemiActiveState->GoInState();
    }

    void SemiActiveStateGoOutStateSuccess()
    {
        pConcreteManagerMachine->pSemiActiveState->GoOutState();
    }

    void SetTargetRoleTest()
    {
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_UNKNOW);
        EXPECT_NE(pConcreteManagerMachine->mTargetRole, TEN);
    }

    void HandleSwitchToConnectOrMixModeTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::RUNNING, 0);
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_CONNECT_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
    }

    void HandleSwitchToScanOnlyModeTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::RUNNING, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
    }

    void HandleStartInIdleStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::RUNNING, 0);
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        msg->SetMessageName(CONCRETE_CMD_START);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY);
        msg->SetParam1(0);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_UNKNOW);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::RUNNING, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::SEMI_ACTIVE, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
    }

    void HandleSwitchToSemiActiveModeTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::SEMI_ACTIVE, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
    }

    void SwitchScanOnlyInConnectStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE);
        sleep(SLEEP_TIME);
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
    }

    void SwitchSemiFromEnableTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVE, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
    }

    void SwitchConnectInScanOnlyStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::RUNNING, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_CONNECT_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
    }

    void SwitchSemiActiveInScanOnlyStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::SEMI_ACTIVE, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
    }

    void SwitchConnectInSemiActiveStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_CONNECT_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        WifiManager::GetInstance().Exit();
    }

    void SwitchScanOnlyInSemiActiveStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        msg->SetMessageName(CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->mTargetRole =
            static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
    }

    void HandleStaStopTest1()
    {
        WifiCountryCodeManager::GetInstance().Init();
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::RUNNING, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA);
        msg->SetMessageName(CONCRETE_CMD_STA_STOP);
        sleep(SLEEP_TIME);
        EXPECT_TRUE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::SEMI_ACTIVE, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE);
        EXPECT_TRUE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE);
        EXPECT_TRUE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
    }

    void HandleStaStopTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSED, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY);
        msg->SetMessageName(CONCRETE_CMD_STA_STOP);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        WifiConfigCenter::GetInstance().SetWifiStopState(false);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_UNKNOW);
        EXPECT_TRUE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(nullptr));
    }

    void HandleStaStartTest1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA);
        msg->SetMessageName(CONCRETE_CMD_STA_START);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
    }

    void HandleStaStartTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, 0);
        msg->SetMessageName(CONCRETE_CMD_STA_START);
        sleep(1);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
    }

    void HandleStaStartTest3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        msg->SetMessageName(CONCRETE_CMD_STA_START);
        sleep(1);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_UNKNOW);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->SwitchEnableFromSemi();
        WifiManager::GetInstance().Exit();
    }

    void CheckAndContinueToStopWifiTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        msg->SetMessageName(CONCRETE_CMD_STOP);
        sleep(1);
        EXPECT_TRUE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        WifiConfigCenter::GetInstance().SetWifiStopState(false);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        WifiOprMidState staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSING, 0);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        staState = WifiConfigCenter::GetInstance().GetWifiMidState(0);
        WifiConfigCenter::GetInstance().SetWifiMidState(staState, WifiOprMidState::CLOSED, 0);
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        WifiManager::GetInstance().Exit();
    }

    void HandleStaSemiActiveTest1()
    {
        WifiCountryCodeManager::GetInstance().Init();
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::RUNNING, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_MIX_SEMI_ACTIVE);
        msg->SetMessageName(CONCRETE_CMD_STA_SEMI_ACTIVE);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA_SEMI_ACTIVE);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
    }

    void HandleStaSemiActiveTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::RUNNING, 0);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, 0);
        msg->SetMessageName(CONCRETE_CMD_STA_SEMI_ACTIVE);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_STA);
        sleep(1);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        WifiManager::GetInstance().Exit();
    }

    void HandleStaSemiActiveTest3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState(0);
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSED, 0);
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY);
        msg->SetMessageName(CONCRETE_CMD_STA_SEMI_ACTIVE);
        sleep(1);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
        pConcreteManagerMachine->SetTargetRole(ConcreteManagerRole::ROLE_UNKNOW);
        EXPECT_FALSE(pConcreteManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pConnectState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pScanonlyState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pConcreteManagerMachine->pSemiActiveState->ExecuteStateMsg(msg));
    }
};

HWTEST_F(ConcreteManagerMachineTest, DefaultStateGoInStateSuccess, TestSize.Level1)
{
    DefaultStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, DefaultStateGoOutStateSuccess, TestSize.Level1)
{
    DefaultStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, IdleStateGoInStateSuccess, TestSize.Level1)
{
    IdleStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, IdleStateGoOutStateSuccess, TestSize.Level1)
{
    IdleStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, ConnectStateGoInStateSuccess, TestSize.Level1)
{
    ConnectStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, ConnectStateGoOutStateSuccess, TestSize.Level1)
{
    ConnectStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, ScanOnlyStateGoInStateSuccess, TestSize.Level1)
{
    ScanOnlyStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, ScanOnlyStateGoOutStateSuccess, TestSize.Level1)
{
    ScanOnlyStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, SemiActiveStateGoInStateSuccess, TestSize.Level1)
{
    SemiActiveStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, SemiActiveStateGoOutStateSuccess, TestSize.Level1)
{
    SemiActiveStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteManagerMachineTest, SetTargetRoleTest, TestSize.Level1)
{
    SetTargetRoleTest();
}

HWTEST_F(ConcreteManagerMachineTest, HandleSwitchToConnectOrMixModeTest, TestSize.Level1)
{
    HandleSwitchToConnectOrMixModeTest();
}

HWTEST_F(ConcreteManagerMachineTest, HandleSwitchToScanOnlyModeTest, TestSize.Level1)
{
    HandleSwitchToScanOnlyModeTest();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStartInIdleStateTest, TestSize.Level1)
{
    HandleStartInIdleStateTest();
}

HWTEST_F(ConcreteManagerMachineTest, HandleSwitchToSemiActiveModeTest, TestSize.Level1)
{
    HandleSwitchToSemiActiveModeTest();
}

HWTEST_F(ConcreteManagerMachineTest, SwitchScanOnlyInConnectStateTest, TestSize.Level1)
{
    SwitchScanOnlyInConnectStateTest();
}

HWTEST_F(ConcreteManagerMachineTest, SwitchSemiFromEnableTest, TestSize.Level1)
{
    SwitchSemiFromEnableTest();
}

HWTEST_F(ConcreteManagerMachineTest, SwitchConnectInScanOnlyStateTest, TestSize.Level1)
{
    SwitchConnectInScanOnlyStateTest();
}

HWTEST_F(ConcreteManagerMachineTest, SwitchSemiActiveInScanOnlyStateTest, TestSize.Level1)
{
    SwitchSemiActiveInScanOnlyStateTest();
}

HWTEST_F(ConcreteManagerMachineTest, SwitchConnectInSemiActiveStateTest, TestSize.Level1)
{
    SwitchConnectInSemiActiveStateTest();
}

HWTEST_F(ConcreteManagerMachineTest, SwitchScanOnlyInSemiActiveStateTest, TestSize.Level1)
{
    SwitchScanOnlyInSemiActiveStateTest();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaStopTest1, TestSize.Level1)
{
    HandleStaStopTest1();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaStopTest2, TestSize.Level1)
{
    HandleStaStopTest2();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaStartTest1, TestSize.Level1)
{
    HandleStaStartTest1();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaStartTest2, TestSize.Level1)
{
    HandleStaStartTest2();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaStartTest3, TestSize.Level1)
{
    HandleStaStartTest3();
}

HWTEST_F(ConcreteManagerMachineTest, CheckAndContinueToStopWifiTest, TestSize.Level1)
{
    CheckAndContinueToStopWifiTest();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaSemiActiveTest1, TestSize.Level1)
{
    HandleStaSemiActiveTest1();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaSemiActiveTest2, TestSize.Level1)
{
    HandleStaSemiActiveTest2();
}

HWTEST_F(ConcreteManagerMachineTest, HandleStaSemiActiveTest3, TestSize.Level1)
{
    HandleStaSemiActiveTest3();
}
}
}
