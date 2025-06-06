/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sta_interface.h"
#include <mutex>
#include <condition_variable>
#include <gtest/gtest.h>
#include <sys/time.h>
#include "mock_sta_service.h"
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
static std::string g_errLog;
void ScanStateMachineCallback(const LogType type, const LogLevel level,
                              const unsigned int domain, const char *tag,
                              const char *msg)
    {
        g_errLog = msg;
    }
bool operator == (const WifiDeviceConfig &lhs, const WifiDeviceConfig &rhs)
{
    return lhs.networkId == rhs.networkId;
}

class StaInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() override
    {
        pStaInterface.reset(new StaInterface(0));
        pStaInterface->pStaService = new MockWifiStaService();
        pMockStaService = (MockWifiStaService *)pStaInterface->pStaService;
    }
    virtual void TearDown() override
    {
        pStaInterface.reset();
    }

    void SleepMs(const int sleepMs)
    {
        std::unique_lock<std::mutex> lck(mMtxBlock);
        mCvTest.wait_for(lck, std::chrono::milliseconds(sleepMs));
    }

public:
    std::unique_ptr<StaInterface> pStaInterface;
    MockWifiStaService *pMockStaService = nullptr;
    std::mutex mMtxBlock;
    std::condition_variable mCvTest;

    void EnableWifiSuccess()
    {
        EXPECT_CALL(*pMockStaService, InitStaService(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_CALL(*pMockStaService, EnableStaService()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->EnableStaService() == WIFI_OPT_SUCCESS);
    }

    void EnableWifiFail1()
    {
        EXPECT_CALL(*pMockStaService, InitStaService(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_CALL(*pMockStaService, EnableStaService()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pStaInterface->EnableStaService();
    }

    void DisableWifiSuceess()
    {
        EXPECT_CALL(*pMockStaService, DisableStaService()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->DisableStaService() == WIFI_OPT_SUCCESS);
    }

    void DisableWifiFail()
    {
        EXPECT_CALL(*pMockStaService, DisableStaService()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->DisableStaService() == WIFI_OPT_FAILED);
    }

    void ConnectToNetworkIdSuceess()
    {
        int networkId = 0;
        EXPECT_CALL(*pMockStaService, ConnectToNetwork(networkId, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->ConnectToNetwork(0) == WIFI_OPT_SUCCESS);
    }

    void ConnectToNetworkIdFail1()
    {
        int networkId = 0;
        EXPECT_CALL(*pMockStaService, ConnectToNetwork(networkId, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->ConnectToNetwork(0) == WIFI_OPT_FAILED);
    }

    void ConnectToConfigSuceess()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, ConnectToDevice(config)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->ConnectToDevice(config) == WIFI_OPT_SUCCESS);
    }

    void ConnectToConfigFail1()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, ConnectToDevice(config)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->ConnectToDevice(config) == WIFI_OPT_FAILED);
    }

    void ReAssociateSuceess()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, ReAssociate()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->ReAssociate() == WIFI_OPT_SUCCESS);
    }

    void ReAssociateFail1()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, ReAssociate()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->ReAssociate() == WIFI_OPT_FAILED);
    }

    void DisconnectSuceess()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, Disconnect()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->Disconnect() == WIFI_OPT_SUCCESS);
    }

    void DisconnectFail1()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, Disconnect()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->Disconnect() == WIFI_OPT_FAILED);
    }

    void AddDeviceConfigSuceess()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->AddDeviceConfig(config) == WIFI_OPT_SUCCESS);
    }

    void AddDeviceConfigFail1()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->AddDeviceConfig(config) == WIFI_OPT_FAILED);
    }

    void UpdateDeviceConfigSuceess()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, UpdateDeviceConfig(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->UpdateDeviceConfig(config) == WIFI_OPT_SUCCESS);
    }

    void UpdateDeviceConfigFail1()
    {
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, UpdateDeviceConfig(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->UpdateDeviceConfig(config) == WIFI_OPT_FAILED);
    }

    void RemoveDeviceConfigSuceess()
    {
        EXPECT_CALL(*pMockStaService, RemoveDevice(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->RemoveDevice(0) == WIFI_OPT_SUCCESS);
    }

    void RemoveDeviceConfigFail1()
    {
        EXPECT_CALL(*pMockStaService, RemoveDevice(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->RemoveDevice(0) == WIFI_OPT_FAILED);
    }

    void EnableDeviceConfigSuceess()
    {
        EXPECT_CALL(*pMockStaService, EnableDeviceConfig(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->EnableDeviceConfig(0, true) == WIFI_OPT_SUCCESS);
    }

    void EnableDeviceConfigFail1()
    {
        EXPECT_CALL(*pMockStaService, EnableDeviceConfig(_, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->EnableDeviceConfig(0, true) == WIFI_OPT_FAILED);
    }

    void DisableDeviceConfigSuceess()
    {
        EXPECT_CALL(*pMockStaService, DisableDeviceConfig(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->DisableDeviceConfig(0) == WIFI_OPT_SUCCESS);
    }

    void DisableDeviceConfigFail1()
    {
        EXPECT_CALL(*pMockStaService, DisableDeviceConfig(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->DisableDeviceConfig(0) == WIFI_OPT_FAILED);
    }

    void StartWpsSuceess()
    {
        WpsConfig config;
        EXPECT_CALL(*pMockStaService, StartWps(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->StartWps(config) == WIFI_OPT_SUCCESS);
    }

    void StartWpsFail1()
    {
        WpsConfig config;
        EXPECT_CALL(*pMockStaService, StartWps(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->StartWps(config) == WIFI_OPT_FAILED);
    }

    void CancelWpsSuceess()
    {
        EXPECT_CALL(*pMockStaService, CancelWps()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->CancelWps() == WIFI_OPT_SUCCESS);
    }

    void CancelWpsFail1()
    {
        EXPECT_CALL(*pMockStaService, CancelWps()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->CancelWps() == WIFI_OPT_FAILED);
    }
    
    void AutoConnectServiceSuceess()
    {
        std::vector<InterScanInfo> scanInfos;
        EXPECT_CALL(*pMockStaService, AutoConnectService(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->ConnectivityManager(scanInfos) == WIFI_OPT_SUCCESS);
    }

    void AutoConnectServiceFail()
    {
        std::vector<InterScanInfo> scanInfos;
        EXPECT_CALL(*pMockStaService, AutoConnectService(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->ConnectivityManager(scanInfos) == WIFI_OPT_FAILED);
    }

    void ConnectToCandidateConfigFail()
    {
        int uid = 1;
        int networkId = 0;
        EXPECT_CALL(*pMockStaService, ConnectToCandidateConfig(_, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->ConnectToCandidateConfig(uid, networkId) == WIFI_OPT_FAILED);
    }

    void ConnectToCandidateConfigSuccess()
    {
        int uid = 1;
        int networkId = 0;
        EXPECT_CALL(*pMockStaService, ConnectToCandidateConfig(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->ConnectToCandidateConfig(uid, networkId) == WIFI_OPT_SUCCESS);
    }
    void RemoveCandidateConfigSuccess()
    {
        int uid = 1;
        int networkId = 0;
        EXPECT_CALL(*pMockStaService, RemoveCandidateConfig(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->RemoveCandidateConfig(uid, networkId) == WIFI_OPT_SUCCESS);
    }

    void RemoveCandidateConfigFail()
    {
        int uid = 1;
        int networkId = 0;
        EXPECT_CALL(*pMockStaService, RemoveCandidateConfig(_, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->RemoveCandidateConfig(uid, networkId) == WIFI_OPT_FAILED);
    }

    void RemoveAllCandidateConfigSuccess()
    {
        int uid = 1;
        EXPECT_CALL(*pMockStaService, RemoveAllCandidateConfig(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->RemoveAllCandidateConfig(uid) == WIFI_OPT_SUCCESS);
    }

    void RemoveAllCandidateConfigFail()
    {
        int uid = 1;
        EXPECT_CALL(*pMockStaService, RemoveAllCandidateConfig(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->RemoveAllCandidateConfig(uid) == WIFI_OPT_FAILED);
    }

    void AddCandidateConfigSuccess()
    {
        int uid = 1;
        int networkId = 0;
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, AddCandidateConfig(_, _, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->AddCandidateConfig(uid, config, networkId) == WIFI_OPT_SUCCESS);
    }

    void AddCandidateConfigSupported()
    {
        int uid = 1;
        int networkId = 0;
        WifiDeviceConfig config;
        config.keyMgmt = "WEP";
        EXPECT_CALL(*pMockStaService, AddCandidateConfig(_, config, _)).WillRepeatedly(Return(WIFI_OPT_NOT_SUPPORTED));
        EXPECT_TRUE(pStaInterface->AddCandidateConfig(uid, config, networkId) == WIFI_OPT_NOT_SUPPORTED);
    }

    void AddCandidateConfigFail()
    {
        int uid = 1;
        int networkId = 0;
        WifiDeviceConfig config;
        EXPECT_CALL(*pMockStaService, AddCandidateConfig(_, _, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->AddCandidateConfig(uid, config, networkId) == WIFI_OPT_FAILED);
    }

    void SetSuspendModeFail()
    {
        bool mode = false;
        EXPECT_CALL(*pMockStaService, SetSuspendMode(mode)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->SetSuspendMode(mode) == WIFI_OPT_FAILED);
    }

    void SetSuspendModeSuccess()
    {
        bool mode = true;
        EXPECT_CALL(*pMockStaService, SetSuspendMode(mode)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->SetSuspendMode(mode) == WIFI_OPT_SUCCESS);
    }

    void RemoveAllDeviceFail()
    {
        EXPECT_CALL(*pMockStaService, RemoveAllDevice()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->RemoveAllDevice() == WIFI_OPT_FAILED);
    }

    void RemoveAllDeviceSuccess()
    {
        EXPECT_CALL(*pMockStaService, RemoveAllDevice()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->RemoveAllDevice() == WIFI_OPT_SUCCESS);
    }

    void ReConnectSuceess()
    {
        EXPECT_CALL(*pMockStaService, ReConnect()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(pStaInterface->ReConnect() == WIFI_OPT_SUCCESS);
    }

    void ReConnectFail()
    {
        EXPECT_CALL(*pMockStaService, ReConnect()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        EXPECT_TRUE(pStaInterface->ReConnect() == WIFI_OPT_FAILED);
    }
    
    void EnableHiLinkHandshakeSuceess()
    {
        WifiDeviceConfig config;
        std::string bssid = "01:23:45:67:89:ab";
        pStaInterface->EnableHiLinkHandshake(true, config, bssid);
    }

    void DeliverStaIfaceDataSuceess()
    {
        std::string mac = "01:23:45:67:89:ab";
        pStaInterface->DeliverStaIfaceData(mac);
    }

    void StartConnectToBssid()
    {
        std::string bssid = "01:23:45:67:89:ab";
        WifiDeviceConfig deviceConfig;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        pStaInterface->StartConnectToBssid(0, bssid, NETWORK_SELECTED_BY_AUTO);
    }

    void StartConnectToUserSelectNetwork()
    {
        std::string bssid = "01:23:45:67:89:ab";
        WifiDeviceConfig deviceConfig;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        pStaInterface->StartConnectToUserSelectNetwork(0, bssid);
    }

    void OnFoldStateChangedTest1()
    {
        int foldStatus = MODE_STATE_EXPAND;
        int result = pStaInterface->OnFoldStateChanged(foldStatus);
        EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    }
    
    void OnFoldStateChangedTest2()
    {
        int foldStatus = MODE_STATE_FOLDED;
        int result = pStaInterface->OnFoldStateChanged(foldStatus);
        EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    }

    void OnFoldStateChangedTest3()
    {
        int foldStatus = MODE_STATE_HALF_FOLD;
        int result = pStaInterface->OnFoldStateChanged(foldStatus);
        EXPECT_EQ(result, WIFI_OPT_SUCCESS);
    }

    void OnFoldStateChangedTest4()
    {
        int foldStatus = 100;
        int result = pStaInterface->OnFoldStateChanged(foldStatus);
        EXPECT_EQ(result, WIFI_OPT_INVALID_PARAM);
    }

    void SetPowerMode()
    {
        pStaInterface->SetPowerMode(0);
    }

    void OnSystemAbilityChanged()
    {
        pStaInterface->OnSystemAbilityChanged(0, 0);
    }

    void StartPortalCertification()
    {
        pStaInterface->StartPortalCertification();
    }

    void GetDetectNetStateTest()
    {
        OperateResState state;
        pStaInterface->GetDetectNetState(state);
    }
};

extern "C" IStaService *Create(void);
extern "C" void Destroy(IStaService *pservice);

HWTEST_F(StaInterfaceTest, CreateSuccess, TestSize.Level1)
{
    Create();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, EnableWifiSuccess, TestSize.Level1)
{
    EnableWifiSuccess();
}

HWTEST_F(StaInterfaceTest, EnableWifiFail1, TestSize.Level1)
{
    EnableWifiFail1();
}

HWTEST_F(StaInterfaceTest, DisableWifiSuceess, TestSize.Level1)
{
    DisableWifiSuceess();
}

HWTEST_F(StaInterfaceTest, DisableWifiFail, TestSize.Level1)
{
    DisableWifiFail();
}

HWTEST_F(StaInterfaceTest, ConnectToNetworkIdSuceess, TestSize.Level1)
{
    ConnectToNetworkIdSuceess();
}

HWTEST_F(StaInterfaceTest, ConnectToNetworkIdFail1, TestSize.Level1)
{
    ConnectToNetworkIdFail1();
}

HWTEST_F(StaInterfaceTest, ConnectToConfigSuceess, TestSize.Level1)
{
    ConnectToConfigSuceess();
}

HWTEST_F(StaInterfaceTest, ConnectToConfigFail1, TestSize.Level1)
{
    ConnectToConfigFail1();
}

HWTEST_F(StaInterfaceTest, ReAssociateSuceess, TestSize.Level1)
{
    ReAssociateSuceess();
}

HWTEST_F(StaInterfaceTest, ReAssociateFail1, TestSize.Level1)
{
    ReAssociateFail1();
}

HWTEST_F(StaInterfaceTest, DisconnectSuceess, TestSize.Level1)
{
    DisconnectSuceess();
}

HWTEST_F(StaInterfaceTest, DisconnectFail1, TestSize.Level1)
{
    DisconnectFail1();
}

HWTEST_F(StaInterfaceTest, AddDeviceConfigSuceess, TestSize.Level1)
{
    AddDeviceConfigSuceess();
}

HWTEST_F(StaInterfaceTest, AddDeviceConfigFail1, TestSize.Level1)
{
    AddDeviceConfigFail1();
}

HWTEST_F(StaInterfaceTest, UpdateDeviceConfigSuceess, TestSize.Level1)
{
    UpdateDeviceConfigSuceess();
}

HWTEST_F(StaInterfaceTest, UpdateDeviceConfigFail1, TestSize.Level1)
{
    UpdateDeviceConfigFail1();
}

HWTEST_F(StaInterfaceTest, RemoveDeviceConfigSuceess, TestSize.Level1)
{
    RemoveDeviceConfigSuceess();
}

HWTEST_F(StaInterfaceTest, RemoveDeviceConfigFail1, TestSize.Level1)
{
    RemoveDeviceConfigFail1();
}

HWTEST_F(StaInterfaceTest, EnableDeviceConfigSuceess, TestSize.Level1)
{
    EnableDeviceConfigSuceess();
}

HWTEST_F(StaInterfaceTest, EnableDeviceConfigFail1, TestSize.Level1)
{
    EnableDeviceConfigFail1();
}

HWTEST_F(StaInterfaceTest, DisableDeviceConfigSuceess, TestSize.Level1)
{
    DisableDeviceConfigSuceess();
}

HWTEST_F(StaInterfaceTest, DisableDeviceConfigFail1, TestSize.Level1)
{
    DisableDeviceConfigFail1();
}

HWTEST_F(StaInterfaceTest, StartWpsSuceess, TestSize.Level1)
{
    StartWpsSuceess();
}

HWTEST_F(StaInterfaceTest, StartWpsFail1, TestSize.Level1)
{
    StartWpsFail1();
}

HWTEST_F(StaInterfaceTest, CancelWpsSuceess, TestSize.Level1)
{
    CancelWpsSuceess();
}

HWTEST_F(StaInterfaceTest, CancelWpsFail1, TestSize.Level1)
{
    CancelWpsFail1();
}

HWTEST_F(StaInterfaceTest, AutoConnectServiceSuceess, TestSize.Level1)
{
    AutoConnectServiceSuceess();
}

HWTEST_F(StaInterfaceTest, AutoConnectServiceFail, TestSize.Level1)
{
    AutoConnectServiceFail();
}

HWTEST_F(StaInterfaceTest, RegisterStaServiceCallbackSuceess, TestSize.Level1)
{
    StaServiceCallback callbacks;
    EXPECT_EQ(pStaInterface->RegisterStaServiceCallback(callbacks), WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, ConnectToCandidateConfigSuccess, TestSize.Level1)
{
    ConnectToCandidateConfigSuccess();
}

HWTEST_F(StaInterfaceTest, ConnectToCandidateConfigFail, TestSize.Level1)
{
    ConnectToCandidateConfigFail();
}

HWTEST_F(StaInterfaceTest, RemoveCandidateConfigSuccess, TestSize.Level1)
{
    RemoveCandidateConfigSuccess();
}

HWTEST_F(StaInterfaceTest, RemoveCandidateConfigFail, TestSize.Level1)
{
    RemoveCandidateConfigFail();
}

HWTEST_F(StaInterfaceTest, RemoveAllCandidateConfigSuccess, TestSize.Level1)
{
    RemoveAllCandidateConfigSuccess();
}

HWTEST_F(StaInterfaceTest, RemoveAllCandidateConfigFail, TestSize.Level1)
{
    RemoveAllCandidateConfigFail();
}

HWTEST_F(StaInterfaceTest, AddCandidateConfigSuccess, TestSize.Level1)
{
    AddCandidateConfigSuccess();
}

HWTEST_F(StaInterfaceTest, AddCandidateConfigFail, TestSize.Level1)
{
    AddCandidateConfigFail();
}

HWTEST_F(StaInterfaceTest, AddCandidateConfigSupported, TestSize.Level1)
{
    AddCandidateConfigSupported();
}

HWTEST_F(StaInterfaceTest, SetSuspendModeSuccess, TestSize.Level1)
{
    SetSuspendModeSuccess();
}

HWTEST_F(StaInterfaceTest, SetSuspendModeFail, TestSize.Level1)
{
    SetSuspendModeFail();
}

HWTEST_F(StaInterfaceTest, RemoveAllDeviceSuccess, TestSize.Level1)
{
    RemoveAllDeviceSuccess();
}

HWTEST_F(StaInterfaceTest, RemoveAllDeviceFail, TestSize.Level1)
{
    RemoveAllDeviceFail();
}

HWTEST_F(StaInterfaceTest, ReConnectSuceess, TestSize.Level1)
{
    ReConnectSuceess();
}

HWTEST_F(StaInterfaceTest, ReConnectFail, TestSize.Level1)
{
    ReConnectFail();
}

HWTEST_F(StaInterfaceTest, OnScreenStateChangedSuccess1, TestSize.Level1)
{
    int screenState = MODE_STATE_OPEN;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->OnScreenStateChanged(screenState));
}

HWTEST_F(StaInterfaceTest, OnScreenStateChangedSuccess2, TestSize.Level1)
{
    int screenState = MODE_STATE_CLOSE;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->OnScreenStateChanged(screenState));
}

HWTEST_F(StaInterfaceTest, OnScreenStateChangedFail, TestSize.Level1)
{
    int screenState = 0;
    EXPECT_EQ(WIFI_OPT_INVALID_PARAM, pStaInterface->OnScreenStateChanged(screenState));
}

HWTEST_F(StaInterfaceTest, DisableAutoJoin, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->DisableAutoJoin("testCondition"));
}

HWTEST_F(StaInterfaceTest, GetDetectNetStateTest, TestSize.Level1)
{
    GetDetectNetStateTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, EnableAutoJoin, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->EnableAutoJoin("testCondition"));
}

HWTEST_F(StaInterfaceTest, RegisterAutoJoinCondition, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, RegisterAutoJoinCondition(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->RegisterAutoJoinCondition("testCondition", []() {return true;}));
}

HWTEST_F(StaInterfaceTest, DeregisterAutoJoinCondition, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, DeregisterAutoJoinCondition(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->DeregisterAutoJoinCondition("testCondition"));
}

HWTEST_F(StaInterfaceTest, RegisterFilterBuilderSuccess, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, RegisterFilterBuilder(_, _, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    FilterBuilder filterBuilder = [](auto & compositeWifiFilter) {};
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->RegisterFilterBuilder(FilterTag::SAVED_NETWORK_TRACKER_FILTER_TAG,
                                                                     "testFilterBuilder",
                                                                     filterBuilder));
}

HWTEST_F(StaInterfaceTest, RegisterFilterBuilderFail, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, RegisterFilterBuilder(_, _, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
    FilterBuilder filterBuilder = [](auto &filterFunc) {};
    EXPECT_EQ(WIFI_OPT_FAILED, pStaInterface->RegisterFilterBuilder(FilterTag::SAVED_NETWORK_TRACKER_FILTER_TAG,
                                                                    "testFilterBuilder",
                                                                    filterBuilder));
}

HWTEST_F(StaInterfaceTest, DeregisterFilterBuilderSuccess, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, DeregisterFilterBuilder(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_EQ(WIFI_OPT_SUCCESS, pStaInterface->DeregisterFilterBuilder(FilterTag::SAVED_NETWORK_TRACKER_FILTER_TAG,
                                                                       "testFilterBuilder"));
}

HWTEST_F(StaInterfaceTest, DeregisterFilterBuilderFail, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, DeregisterFilterBuilder(_, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
    EXPECT_EQ(WIFI_OPT_FAILED, pStaInterface->DeregisterFilterBuilder(FilterTag::SAVED_NETWORK_TRACKER_FILTER_TAG,
                                                                      "testFilterBuilder"));
}

HWTEST_F(StaInterfaceTest, EnableHiLinkHandshakeSuccess, TestSize.Level1)
{
    EnableHiLinkHandshakeSuceess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, DeliverStaIfaceDataSuccess, TestSize.Level1)
{
    DeliverStaIfaceDataSuceess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, StartConnectToBssid, TestSize.Level1)
{
    StartConnectToBssid();
}

HWTEST_F(StaInterfaceTest, StartConnectToUserSelectNetwork, TestSize.Level1)
{
    StartConnectToUserSelectNetwork();
}

HWTEST_F(StaInterfaceTest, SetPowerMode, TestSize.Level1)
{
    SetPowerMode();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, OnSystemAbilityChanged, TestSize.Level1)
{
    OnSystemAbilityChanged();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, OnFoldStateChangedTest1, TestSize.Level1)
{
    OnFoldStateChangedTest1();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, OnFoldStateChangedTest2, TestSize.Level1)
{
    OnFoldStateChangedTest2();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, OnFoldStateChangedTest3, TestSize.Level1)
{
    OnFoldStateChangedTest3();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaInterfaceTest, OnFoldStateChangedTest4, TestSize.Level1)
{
    OnFoldStateChangedTest4();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
} // namespace Wifi
} // namespace OHOS
