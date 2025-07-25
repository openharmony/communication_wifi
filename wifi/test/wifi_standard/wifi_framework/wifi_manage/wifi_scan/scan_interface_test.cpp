/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "scan_interface.h"
#include <gtest/gtest.h>
#include "mock_wifi_manager.h"
#include "mock_scan_service.h"
#include "mock_wifi_config_center.h"

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
class ScanInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp() override
    {
        pScanInterface = std::make_unique<ScanInterface>();
        pScanInterface->pScanService = new MockScanService();
        pScanInterface->mScanSerivceCallbacks = WifiManager::GetInstance().GetScanCallback();
    }
    void TearDown() override
    {
        pScanInterface.reset();
    }

public:
    std::unique_ptr<ScanInterface> pScanInterface;
};

std::vector<TrustListPolicy> refVecTrustList;
MovingFreezePolicy defaultValue;

HWTEST_F(ScanInterfaceTest, UnInitTest, TestSize.Level1)
{
    EXPECT_EQ(pScanInterface->UnInit(), WIFI_OPT_SUCCESS);
}

HWTEST_F(ScanInterfaceTest, ScanSuccess, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->Scan(true));
}

HWTEST_F(ScanInterfaceTest, ScanWithParamSuccess, TestSize.Level1)
{
    WifiScanParams wifiScanParams;
    wifiScanParams.ssid = "hmwifi";
    wifiScanParams.bssid = "a3:b1:d7:f2:d2:c2";
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->ScanWithParam(wifiScanParams, false));
}

HWTEST_F(ScanInterfaceTest, OnScreenStateChangedSuccess1, TestSize.Level1)
{
    int screenState = MODE_STATE_OPEN;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnScreenStateChanged(screenState));
}

HWTEST_F(ScanInterfaceTest, OnScreenStateChangedSuccess2, TestSize.Level1)
{
    int screenState = MODE_STATE_CLOSE;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnScreenStateChanged(screenState));
}

HWTEST_F(ScanInterfaceTest, OnScreenStateChangedFail, TestSize.Level1)
{
    int screenState = 0;
    EXPECT_EQ(WIFI_OPT_INVALID_PARAM, pScanInterface->OnScreenStateChanged(screenState));
}

HWTEST_F(ScanInterfaceTest, OnStandbyStateChangedSuccess, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnStandbyStateChanged(false));
}

HWTEST_F(ScanInterfaceTest, OnStandbyStateChangedFail, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_INVALID_PARAM, pScanInterface->OnStandbyStateChanged(true));
}

HWTEST_F(ScanInterfaceTest, OnClientModeStatusChangedSuccess, TestSize.Level1)
{
    EXPECT_EQ(pScanInterface->OnClientModeStatusChanged(
        static_cast<int>(OperateResState::CONNECT_MISS_MATCH)), WIFI_OPT_SUCCESS);
}

HWTEST_F(ScanInterfaceTest, OnAppRunningModeChangedSuccess, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnAppRunningModeChanged(ScanMode::APP_FOREGROUND_SCAN));
}

HWTEST_F(ScanInterfaceTest, OnCustomControlStateChangedSuccess, TestSize.Level1)
{
    int customSceneStatus = MODE_STATE_OPEN;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnCustomControlStateChanged(0, customSceneStatus));
}

HWTEST_F(ScanInterfaceTest, OnCustomControlStateChangedFail, TestSize.Level1)
{
    int customSceneStatus = 0;
    EXPECT_EQ(WIFI_OPT_INVALID_PARAM, pScanInterface->OnCustomControlStateChanged(0, customSceneStatus));
}

HWTEST_F(ScanInterfaceTest, OnControlStrategyChangedSuccess, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnControlStrategyChanged());
}

HWTEST_F(ScanInterfaceTest, OnAutoConnectStateChangedSuccess, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnAutoConnectStateChanged(true));
}

HWTEST_F(ScanInterfaceTest, RegisterScanCallbacksTest, TestSize.Level1)
{
    IScanSerivceCallbacks callbacks;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->RegisterScanCallbacks(callbacks));
}

HWTEST_F(ScanInterfaceTest, ScanTest, TestSize.Level1)
{
    bool externFlag = false;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->Scan(externFlag));
}

HWTEST_F(ScanInterfaceTest, ScanWithParamTest, TestSize.Level1)
{
    WifiScanParams wifiScanParams;
    wifiScanParams.ssid = "HMWIFI_G2_03";
    wifiScanParams.bssid = "2a:76:93:47:e2:8a";
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->ScanWithParam(wifiScanParams, false));
}

HWTEST_F(ScanInterfaceTest, StartWifiPnoScanTest, TestSize.Level1)
{
    int isStartAction = 1;
    int periodMs = 60 * 1000;
    int suspendReason = 0;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->StartWifiPnoScan(isStartAction, periodMs, suspendReason));
}

HWTEST_F(ScanInterfaceTest, DisableScanTest, TestSize.Level1)
{
    bool disable = false;
    pScanInterface->pScanService->pScanStateMachine = new (std::nothrow) ScanStateMachine(0);
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->DisableScan(disable));
}

HWTEST_F(ScanInterfaceTest, OnAppRunningModeChangedTest, TestSize.Level1)
{
    ScanMode appRunMode = ScanMode::APP_FOREGROUND_SCAN;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnAppRunningModeChanged(appRunMode));
}

HWTEST_F(ScanInterfaceTest, OnMovingFreezeStateChangeTest, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnMovingFreezeStateChange());
}

HWTEST_F(ScanInterfaceTest, OnGetCustomSceneStateTest, TestSize.Level1)
{
    std::map<int, time_t> sceneMap;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->OnGetCustomSceneState(sceneMap));
}

HWTEST_F(ScanInterfaceTest, SetEnhanceServiceTest, TestSize.Level1)
{
    IEnhanceService *enhanceService =nullptr;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pScanInterface->SetEnhanceService(enhanceService));
}

HWTEST_F(ScanInterfaceTest, SetNetworkInterfaceUpDownTest, TestSize.Level1)
{
    EXPECT_EQ(pScanInterface->SetNetworkInterfaceUpDown(false), WIFI_OPT_FAILED);
}
}  // namespace Wifi
}  // namespace OHOS

