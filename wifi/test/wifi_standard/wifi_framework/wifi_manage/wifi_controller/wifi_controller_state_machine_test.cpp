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
#include "mock_concrete_manager_state_machine.h"
#include "mock_softap_manager_state_machine.h"
#include "mock_wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_manager.h"
#include "wifi_settings.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

#define INVILAD_MSG 0x1111

namespace OHOS {
namespace Wifi {

constexpr int TEN = 10;

static std::string g_errLog;
    void WifiControllerMachineCallback(const LogType type,const LogLevel level,
                                       const unsigned int domain ,const char *tag,const char *msg)
    {
        g_errLog = msg;
    }

class WifiControllerMachineTest : public testing::Test {
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
        pWifiControllerMachine = std::make_unique<WifiControllerMachine>();
        pWifiControllerMachine->InitWifiControllerMachine();
        LOG_SetCallback(WifiControllerMachineCallback);
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
        int instId = 0;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiToggledState(false, instId);
        WifiSettings::GetInstance().SetScanOnlySwitchState(0, 0);
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        msg->SetMessageName(CMD_WIFI_TOGGLED);
        msg->SetParam1(1);
        msg->SetParam2(0);
        sleep(1);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pWifiControllerMachine->pDefaultState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(nullptr));
    }

    void WifiToggledTest2()
    {
        int instId = 0;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiToggledState(false, instId);
        WifiSettings::GetInstance().SetScanOnlySwitchState(0, 0);
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        msg->SetMessageName(CMD_WIFI_TOGGLED);
        msg->SetParam1(0);
        msg->SetParam2(0);
        sleep(1);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        msg->SetMessageName(CMD_AIRPLANE_TOGGLED);
        msg->SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pWifiControllerMachine->pDefaultState->ExecuteStateMsg(msg));
    }

    void HandleStaStartFail()
    {
        int instId = 0;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiConfigCenter::GetInstance().SetWifiToggledState(false, instId);
        WifiSettings::GetInstance().SetScanOnlySwitchState(0, 0);
        WifiConfigCenter::GetInstance().SetWifiStopState(true);
        msg->SetMessageName(CMD_STA_START_FAILURE);
        msg->SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(1);
        msg->SetMessageName(CMD_CONCRETE_STOPPED);
        msg->SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetMessageName(CMD_STA_REMOVED);
        msg->SetParam1(0);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetMessageName(CMD_CONCRETECLIENT_REMOVED);
        msg->SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
    }

    void RemoveConcreteManagerTest()
    {
        pWifiControllerMachine->concreteManagers.RemoveManager(0);
        EXPECT_NE(pWifiControllerMachine->mWifiStartFailCount, TEN);
    }

    void HandleStaCloseTest()
    {
        pWifiControllerMachine->HandleStaClose(0);
    }

    void HandleStaStartSuccessTest()
    {
        pWifiControllerMachine->HandleStaStartSuccess(0);
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
        EXPECT_EQ(pWifiControllerMachine->mWifiStartFailCount, 0);
    }

    void RmoveSoftapManagerTest()
    {
        pWifiControllerMachine->softApManagers.RemoveManager(0);
        EXPECT_NE(pWifiControllerMachine->mWifiStartFailCount, TEN);
    }

    void HandleSoftapStopTest()
    {
        pWifiControllerMachine->HandleSoftapStop(0);
    }

    void SoftapToggledTest1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SOFTAP_TOGGLED);
        msg->SetParam1(0);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, 0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        auto softapmode = std::make_shared<SoftApManager>(SoftApManager::Role::ROLE_SOFTAP, 0);
        softapmode->pSoftapManagerMachine = new MockSoftapManagerStateMachine();
        pWifiControllerMachine->softApManagers.AddManager(softapmode);
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::RUNNING, 0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetParam1(1);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        auto clientmode = std::make_shared<ConcreteClientModeManager>(ConcreteManagerRole::ROLE_CLIENT_STA, 0);
        clientmode->pConcreteMangerMachine = new MockConcreteMangerMachine();
        pWifiControllerMachine->concreteManagers.AddManager(clientmode);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
    }

    void SoftapToggledTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SOFTAP_TOGGLED);
        msg->SetParam1(1);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->HasAnyManager());
        pWifiControllerMachine->ShutdownWifi(true);
    }

    void HandleAirplaneOpenTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_AIRPLANE_TOGGLED);
        msg->SetParam1(1);
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_SEMI_ACTIVE, 0);
        EXPECT_TRUE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetMessageName(INVILAD_MSG);
        EXPECT_FALSE(pWifiControllerMachine->pDisableState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
    }

    void ApStartFailureTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_AP_STOPPED);
        msg->SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetMessageName(CMD_AP_START_FAILURE);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        auto softapmode = std::make_shared<SoftApManager>(SoftApManager::Role::ROLE_HAS_REMOVED, 0);
        softapmode->pSoftapManagerMachine = new MockSoftapManagerStateMachine();
        pWifiControllerMachine->softApManagers.AddManager(softapmode);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        auto softapmodeBack = std::make_shared<SoftApManager>(SoftApManager::Role::ROLE_HAS_REMOVED, 0);
        softapmodeBack->pSoftapManagerMachine = new MockSoftapManagerStateMachine();
        pWifiControllerMachine->softApManagers.AddManager(softapmodeBack);
        auto clientmode = std::make_shared<ConcreteClientModeManager>(ConcreteManagerRole::ROLE_CLIENT_STA, 0);
        clientmode->pConcreteMangerMachine = new MockConcreteMangerMachine();
        pWifiControllerMachine->concreteManagers.AddManager(clientmode);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
    }

    void ApStartTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_AP_START);
        msg->SetParam1(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetMessageName(CMD_AP_START_TIME);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        msg->SetMessageName(CMD_AP_STOP_TIME);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        WifiConfigCenter::GetInstance().SetSoftapToggledState(true);
        EXPECT_FALSE(pWifiControllerMachine->ShouldEnableSoftap());
    }

    void RetryTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_OPEN_WIFI_RETRY);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
    }

    void ApRemoveTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_AP_REMOVED);
        msg->SetParam1(0);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
    }

    void RptStoppedTest()
    {
        #ifdef FEATURE_RPT_SUPPORT
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_RPT_STOPPED);
        msg->SetParam1(0);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        #else
        EXPECT_FALSE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        #endif
    }

    void P2pStoppedTest()
    {
        #ifdef FEATURE_RPT_SUPPORT
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_P2P_STOPPED);
        msg->SetParam1(0);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        #else
        EXPECT_FALSE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        #endif
    }

    void RptStartFailureTest()
    {
        #ifdef FEATURE_RPT_SUPPORT
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_RPT_START_FAILURE);
        msg->SetParam1(0);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        #else
        EXPECT_FALSE(pWifiControllerMachine->pEnableState->ExecuteStateMsg(msg));
        #endif
    }

    void MakeConcreteManagerTest()
    {
        pWifiControllerMachine->MakeConcreteManager(ConcreteManagerRole::ROLE_CLIENT_STA, 0);
        EXPECT_TRUE(pWifiControllerMachine->concreteManagers.HasAnyManager());
        pWifiControllerMachine->concreteManagers.RemoveManager(0);
    }

    void MakeSoftapManagerTest()
    {
        pWifiControllerMachine->MakeSoftapManager(SoftApManager::Role::ROLE_SOFTAP, 0);
        EXPECT_TRUE(pWifiControllerMachine->softApManagers.HasAnyManager());
        pWifiControllerMachine->softApManagers.RemoveManager(0);
    }

    void MakeRptManagerTest()
    {
        #ifdef FEATURE_RPT_SUPPORT
        pWifiControllerMachine->MakeRptManager(RptManager::Role::ROLE_RPT, 0);
        EXPECT_TRUE(pWifiControllerMachine->rptManagers.HasAnyManager());
        pWifiControllerMachine->rptManagers.RemoveManager(0);
        #endif
    }

    void GetRptManagerTest()
    {
        const int anyId = -1;
        const int id0 = 0;
        pWifiControllerMachine->ShouldUseRpt(0);
        EXPECT_TRUE(pWifiControllerMachine->GetRptManager(anyId) == nullptr);
        EXPECT_TRUE(pWifiControllerMachine->GetRptManager(id0) == nullptr);
    }

    void CalculateHotspotModeTest()
    {
        using HotspotMode = WifiControllerMachine::HotspotMode;
        pWifiControllerMachine->hotspotMode = HotspotMode::NONE;
        pWifiControllerMachine->CalculateHotspotMode(0);

        pWifiControllerMachine->hotspotMode = HotspotMode::SOFTAP;
        EXPECT_TRUE(pWifiControllerMachine->CalculateHotspotMode(0) == HotspotMode::SOFTAP);

        pWifiControllerMachine->hotspotMode = HotspotMode::RPT;
        EXPECT_TRUE(pWifiControllerMachine->CalculateHotspotMode(0) == HotspotMode::RPT);
    }

    void SoftApIdExistTest()
    {
        auto softapmode = std::make_shared<SoftApManager>(SoftApManager::Role::ROLE_SOFTAP, 0);
        softapmode->pSoftapManagerMachine = new MockSoftapManagerStateMachine();
        pWifiControllerMachine->softApManagers.AddManager(softapmode);
        EXPECT_TRUE(pWifiControllerMachine->softApManagers.IdExist(0));
        EXPECT_FALSE(pWifiControllerMachine->softApManagers.IdExist(1));
        EXPECT_TRUE(pWifiControllerMachine->softApManagers.HasAnyManager());
        pWifiControllerMachine->softApManagers.StopManager(0);
        pWifiControllerMachine->softApManagers.StopManager(1);
        pWifiControllerMachine->softApManagers.StopAllManagers();
        pWifiControllerMachine->softApManagers.GetManager(0);
        pWifiControllerMachine->softApManagers.GetManager(1);
        pWifiControllerMachine->softApManagers.RemoveManager(1);
        pWifiControllerMachine->softApManagers.RemoveManager(0);
    }

    void ConcreteIdExistTest()
    {
        int instId = 0;
        auto clientmode = std::make_shared<ConcreteClientModeManager>(ConcreteManagerRole::ROLE_CLIENT_STA, 0);
        clientmode->pConcreteMangerMachine = new MockConcreteMangerMachine();
        pWifiControllerMachine->concreteManagers.AddManager(clientmode);
        EXPECT_TRUE(pWifiControllerMachine->concreteManagers.IdExist(0));
        EXPECT_FALSE(pWifiControllerMachine->concreteManagers.IdExist(1));
        EXPECT_TRUE(pWifiControllerMachine->concreteManagers.HasAnyManager());
        EXPECT_TRUE(pWifiControllerMachine->HasAnyManager());
        pWifiControllerMachine->concreteManagers.StopAllManagers();
        pWifiControllerMachine->concreteManagers.StopManager(0);
        pWifiControllerMachine->concreteManagers.StopManager(1);
        pWifiControllerMachine->HandleStaStartSuccess(0);
        pWifiControllerMachine->HandleStaSemiActive(0);
        pWifiControllerMachine->HandleStaClose(0);
        pWifiControllerMachine->SwitchRole(ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY);
        WifiConfigCenter::GetInstance().SetWifiToggledState(1, instId);
        EXPECT_FALSE(pWifiControllerMachine->ShouldEnableWifi(instId));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_WIFI_TOGGLED);
        msg->SetParam2(0);
        EXPECT_TRUE(pWifiControllerMachine->ShouldDisableWifi(msg));
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_SEMI_ENABLED, instId);
        WifiConfigCenter::GetInstance().SetWifiDetailState(WifiDetailState::STATE_ACTIVATED, 0);
        EXPECT_TRUE(pWifiControllerMachine->ShouldDisableWifi(msg));
        pWifiControllerMachine->concreteManagers.RemoveManager(1);
        pWifiControllerMachine->concreteManagers.RemoveManager(0);
        pWifiControllerMachine->ShutdownWifi();
    }

    void GetWifiRoleTest()
    {
        int instId = 0;
        pWifiControllerMachine->GetWifiRole();
    }
};

HWTEST_F(WifiControllerMachineTest, DefaultStateGoInStateSuccess, TestSize.Level1)
{
    DefaultStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, DefaultStateGoOutStateSuccess, TestSize.Level1)
{
    DefaultStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, EnableStateGoInStateSuccess, TestSize.Level1)
{
    EnableStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, EnableStateGoOutStateSuccess, TestSize.Level1)
{
    EnableStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, DisableStateGoInStateSuccess, TestSize.Level1)
{
    DisableStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, DisableStateGoOutStateSuccess, TestSize.Level1)
{
    DisableStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, HandleStaStartSuccessTest, TestSize.Level1)
{
    HandleStaStartSuccessTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, HandleStaSemiActiveTest, TestSize.Level1)
{
    HandleStaSemiActiveTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, HandleConcreteStopTest, TestSize.Level1)
{
    HandleConcreteStopTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, SoftapToggledTest1, TestSize.Level1)
{
    SoftapToggledTest1();
}

HWTEST_F(WifiControllerMachineTest, SoftapToggledTest2, TestSize.Level1)
{
    SoftapToggledTest2();
}

HWTEST_F(WifiControllerMachineTest, HandleAirplaneOpenTest, TestSize.Level1)
{
    HandleAirplaneOpenTest();
}

HWTEST_F(WifiControllerMachineTest, ApStartFailureTest, TestSize.Level1)
{
    ApStartFailureTest();
}

HWTEST_F(WifiControllerMachineTest, ApStartTest, TestSize.Level1)
{
    ApStartTest();
}

HWTEST_F(WifiControllerMachineTest, RetryTest, TestSize.Level1)
{
    RetryTest();
}

HWTEST_F(WifiControllerMachineTest, ApRemoveTest, TestSize.Level1)
{
    ApRemoveTest();
}

HWTEST_F(WifiControllerMachineTest, RptStoppedTest, TestSize.Level1)
{
    RptStoppedTest();
}

HWTEST_F(WifiControllerMachineTest, P2pStoppedTest, TestSize.Level1)
{
    P2pStoppedTest();
}

HWTEST_F(WifiControllerMachineTest, RptStartFailureTest, TestSize.Level1)
{
    RptStartFailureTest();
}

HWTEST_F(WifiControllerMachineTest, MakeConcreteManagerTest, TestSize.Level1)
{
    MakeConcreteManagerTest();
}

HWTEST_F(WifiControllerMachineTest, MakeSoftapManagerTest, TestSize.Level1)
{
    MakeSoftapManagerTest();
}

HWTEST_F(WifiControllerMachineTest, MakeRptManagerTest, TestSize.Level1)
{
    MakeRptManagerTest();
}

HWTEST_F(WifiControllerMachineTest, GetRptManagerTest, TestSize.Level1)
{
    GetRptManagerTest();
}

HWTEST_F(WifiControllerMachineTest, CalculateHotspotModeTest, TestSize.Level1)
{
    CalculateHotspotModeTest();
}

HWTEST_F(WifiControllerMachineTest, SoftApIdExistTest, TestSize.Level1)
{
    SoftApIdExistTest();
}

HWTEST_F(WifiControllerMachineTest, ConcreteIdExistTest, TestSize.Level1)
{
    ConcreteIdExistTest();
}

HWTEST_F(WifiControllerMachineTest, GetWifiRoleTest, TestSize.Level1)
{
    GetWifiRoleTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, HandleApStopTest, TestSize.Level1)
{
    int instId = 0;
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(CMD_AP_STOPPED);
    msg->SetParam1(0);
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_DISABLED, instId);
    pWifiControllerMachine->pEnableState->HandleApStop(msg);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiControllerMachineTest, MakeMultiStaManagerTest01, TestSize.Level1)
{
    MultiStaManager::Role role = MultiStaManager::Role::ROLE_UNKNOW;
    int instId = 1;
    pWifiControllerMachine->MakeMultiStaManager(role, instId);
    EXPECT_NE(pWifiControllerMachine->pEnableState, nullptr);
}

HWTEST_F(WifiControllerMachineTest, HandleWifi2CloseTest01, TestSize.Level1)
{
    int id = 1;
    pWifiControllerMachine->HandleWifi2Close(id);
    EXPECT_NE(pWifiControllerMachine->pEnableState, nullptr);
}

HWTEST_F(WifiControllerMachineTest, HandleWifiToggleChangeForWlan1Test01, TestSize.Level1)
{
    int id = 1;
    int isOpen = 0;
    EXPECT_EQ(pWifiControllerMachine->pEnableState->HandleWifiToggleChangeForWlan1(id, isOpen), true);
}

HWTEST_F(WifiControllerMachineTest, HandleWifiToggleChangeForWlan1Test02, TestSize.Level1)
{
    int id = 1;
    int isOpen = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetPersistWifiState(_))
        .WillRepeatedly(Return(WIFI_STATE_ENABLED));
    EXPECT_EQ(pWifiControllerMachine->pEnableState->HandleWifiToggleChangeForWlan1(id, isOpen), true);
}
}
}
