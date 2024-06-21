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
#include "scan_service.h"
#include <gtest/gtest.h>
#include "Mock/mock_wifi_manager.h"
#include "Mock/mock_wifi_settings.h"
#include "Mock/mock_scan_state_machine.h"
#include "Mock/mock_wifi_scan_interface.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

constexpr int TWO = 2;
constexpr int FOUR = 4;
constexpr int STATUS = 17;

namespace OHOS {
namespace Wifi {

class ScanServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pScanService = std::make_unique<ScanService>();
        pScanService->pScanStateMachine = new MockScanStateMachine();
        pScanService->RegisterScanCallbacks(WifiManager::GetInstance().GetScanCallback());
    }
    virtual void TearDown()
    {
        pScanService.reset();
    }

public:
    std::unique_ptr<ScanService> pScanService;
 
    void SystemScanByIntervalSuccess()
    {
        int expScanCount = 1;
        int interval = 1;
        const int constTest = 2;
        int count = constTest;
        EXPECT_EQ(pScanService->SystemScanByInterval(expScanCount, interval, count), true);
    }
    void SetEnhanceServiceTest()
    {
        IEnhanceService* enhanceService = nullptr;
        pScanService->SetEnhanceService(enhanceService);
    }

    void StopPnoScanTest()
    {
        pScanService->isPnoScanBegined = true;
        pScanService->StopPnoScan();
    }

    void GetScanControlInfoSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanControlInfo(_, _)).WillRepeatedly(Return(0));
        pScanService->GetScanControlInfo();
    }

    void GetScanControlInfoFail()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanControlInfo(_, _)).WillRepeatedly(Return(-1));
        pScanService->GetScanControlInfo();
    }

    void AllowExternScanSuccess()
    {
        pScanService->AllowExternScan();
    }

    void AllowExternScanFail1()
    {
        int staScene = 0;
        StoreScanConfig cfg;
        cfg.externFlag = true;
        pScanService->scanConfigMap.emplace(staScene, cfg);
        ScanMode scanMode = ScanMode::SYS_FOREGROUND_SCAN;
        ScanForbidMode forbidMode;
        forbidMode.scanScene = SCAN_SCENE_SCANNING;
        forbidMode.scanMode = scanMode;
        pScanService->scanControlInfo.scanForbidList.push_back(forbidMode);

        pScanService->AllowExternScan();
    }

    void AllowExternScanFail2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetAppRunningState())
            .WillRepeatedly(Return(ScanMode::SYS_FOREGROUND_SCAN));
        EXPECT_CALL(WifiSettings::GetInstance(), GetThermalLevel()).WillRepeatedly(Return(FOUR));
        EXPECT_EQ(pScanService->AllowExternScan(), WIFI_OPT_FAILED);
    }

    void AllowExternScanFail3()
    {
        ScanMode scanMode = ScanMode::SYS_FOREGROUND_SCAN;
        ScanForbidMode forbidMode;
        forbidMode.scanScene = SCAN_SCENE_CONNECTED;
        forbidMode.scanMode = scanMode;
        forbidMode.forbidTime = 0;
        forbidMode.forbidCount = 0;
        pScanService->scanControlInfo.scanForbidList.push_back(forbidMode);
        pScanService->staStatus = STATUS;
        EXPECT_CALL(WifiSettings::GetInstance(), GetAppRunningState())
            .WillRepeatedly(Return(ScanMode::SYS_FOREGROUND_SCAN));
        EXPECT_CALL(WifiSettings::GetInstance(), GetThermalLevel()).WillRepeatedly(Return(FOUR));
        EXPECT_EQ(pScanService->AllowExternScan(), WIFI_OPT_FAILED);
    }

    void AllowExternScanFail4()
    {
        pScanService->disableScanFlag = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SetThermalLevel(TWO)).Times(AtLeast(0));
        EXPECT_EQ(pScanService->AllowExternScan(), WIFI_OPT_FAILED);
    }

    void SetMovingFreezeScanedTest()
    {
        pScanService->SetMovingFreezeScaned(true);
    }
};

HWTEST_F(ScanServiceTest, SystemScanByIntervalSuccess, TestSize.Level1)
{
    SystemScanByIntervalSuccess();
}

HWTEST_F(ScanServiceTest, SetEnhanceServiceTest, TestSize.Level1)
{
    SetEnhanceServiceTest();
}

HWTEST_F(ScanServiceTest, GetScanControlInfoSuccess, TestSize.Level1)
{
    GetScanControlInfoSuccess();
}

HWTEST_F(ScanServiceTest, GetScanControlInfoFail, TestSize.Level1)
{
    GetScanControlInfoFail();
}

HWTEST_F(ScanServiceTest, StopPnoScanTest, TestSize.Level1)
{
    StopPnoScanTest();
}

HWTEST_F(ScanServiceTest, AllowExternScanSuccess, TestSize.Level1)
{
    AllowExternScanSuccess();
}

HWTEST_F(ScanServiceTest, AllowExternScanFail1, TestSize.Level1)
{
    AllowExternScanFail1();
}

HWTEST_F(ScanServiceTest, AllowExternScanFail2, TestSize.Level1)
{
    AllowExternScanFail2();
}

HWTEST_F(ScanServiceTest, AllowExternScanFail3, TestSize.Level1)
{
    AllowExternScanFail3();
}

HWTEST_F(ScanServiceTest, AllowExternScanFail4, TestSize.Level1)
{
    AllowExternScanFail4();
}


    void HilinkSaveConfigTest()
    {
        pStaStateMachine->HilinkSaveConfig();
    }
 
    void IsRoamingTest()
    {
        pStaStateMachine->IsRoaming();
    }
    void OnDhcpResultNotifyEventTest()
    {
        pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_RENEW_FAIL);
    }
 
    void DealGetDhcpIpTimeoutTest()
    {
        InternalMessage *msg = nullptr;
        pStaStateMachine->DealGetDhcpIpTimeout(msg);
        InternalMessage msg1;
        msg1.SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        pStaStateMachine->DealGetDhcpIpTimeout(&msg1);
    }
 
    void FillSuiteB192CfgTest()
    {
        WifiHalDeviceConfig  halDeviceConfig;
        halDeviceConfig.keyMgmt = "WPA-EAP-SUITE-B-192";
        pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    }
 
    void ReplaceEmptyDnsTest()
    {
        DhcpResult *result = nullptr;
        pStaStateMachine->ReplaceEmptyDns(result);
        DhcpResult resultO;
        std::string bssid1 = "11:22:33:44";
        std::string bssid2 = "11:22:33:44";
        strcpy_s(resultO.strOptDns1, MAX_STR_LENT, bssid1.c_str());
        strcpy_s(resultO.strOptDns2, MAX_STR_LENT, bssid2.c_str());
        pStaStateMachine->ReplaceEmptyDns(&resultO);
    }

    HWTEST_F(StaStateMachineTest, HilinkSaveConfigTest, TestSize.Level1)
{
    HilinkSaveConfigTest();
}
 
HWTEST_F(StaStateMachineTest, ReplaceEmptyDnsTest, TestSize.Level1)
{
    ReplaceEmptyDnsTest();
}
}  // namespace Wifi
}  // namespace OHOS