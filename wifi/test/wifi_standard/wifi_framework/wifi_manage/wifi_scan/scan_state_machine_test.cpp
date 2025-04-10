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
#include "mock_wifi_manager.h"
#include "mock_wifi_config_center.h"
#include "mock_scan_service.h"
#include "scan_state_machine.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>

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
constexpr int FREQ_2_DOT_4_GHZ_VALUE = 2410;
constexpr int FREQ_5_GHZ_VALUE = 5010;
constexpr int NETWORK_ID = 15;
constexpr int BAND = 2;
constexpr int TWO = 2;
static std::string g_errLog;
void ScanStateMachineCallback(const LogType type, const LogLevel level,
                              const unsigned int domain, const char *tag,
                              const char *msg)
    {
        g_errLog = msg;
    }

class ScanStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        LOG_SetCallback(ScanStateMachineCallback);
        pScanStateMachine = std::make_unique<ScanStateMachine>();
        pScanStateMachine->InitScanStateMachine();
        pScanStateMachine->EnrollScanStatusListener(
            std::bind(&ScanStateMachineTest::HandleScanStatusReport, this, std::placeholders::_1));
    }
    void TearDown() override
    {
        pScanStateMachine.reset();
    }

    std::unique_ptr<ScanStateMachine> pScanStateMachine;

public:
    void HandleScanStatusReport(ScanStatusReport &scanStatusReport)
    {}
    void InitGoInStateTest()
    {
        pScanStateMachine->initState->GoInState();
    }

    void InitGoOutStateTest()
    {
        pScanStateMachine->initState->GoOutState();
    }

    void InitExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_PREPARE);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_FINISH);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_STOP_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess6()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(HARDWARE_LOAD_EVENT);
        EXPECT_FALSE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess7()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(HARDWARE_UNLOAD_EVENT);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == false);
    }

    void InitExeMsgSuccess8()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_STOP_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess9()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SYSTEM_SCAN_TIMER);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgSuccess10()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_INNER_EVENT_INVALID);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == false);
    }

    void InitExeMsgSuccess11()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_UPDATE_COUNTRY_CODE);
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);

        msg->AddStringMessageBody("CN");
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(msg) == true);
    }

    void InitExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->initState->ExecuteStateMsg(nullptr) == true);
    }

    void HardwareReadyExeMsgSuccess1()
    {
        pScanStateMachine->hardwareReadyState->GoInState();
        pScanStateMachine->hardwareReadyState->GoOutState();
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_PREPARE);
        EXPECT_TRUE(pScanStateMachine->hardwareReadyState->ExecuteStateMsg(msg) == false);
    }

    void HardwareReadyExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->hardwareReadyState->ExecuteStateMsg(msg) == true);
    }

    void HardwareReadyExeMsgFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->hardwareReadyState->ExecuteStateMsg(msg) == true);
        EXPECT_TRUE(pScanStateMachine->hardwareReadyState->ExecuteStateMsg(nullptr) == true);
    }

    void CommonScanGoInStateTest()
    {
        pScanStateMachine->commonScanState->GoInState();
    }

    void CommonScanGoOutStateTest()
    {
        pScanStateMachine->commonScanState->GoOutState();
    }

    void CommonScanExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_STOP_COMMON_SCAN);
        InterScanConfig interScanConfig;
        pScanStateMachine->runningScans.emplace(0, interScanConfig);
        pScanStateMachine->waitingScans.emplace(0, interScanConfig);
        pScanStateMachine->RemoveCommonScanRequest(0);
        EXPECT_TRUE(pScanStateMachine->commonScanState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanExeMsgFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->commonScanState->ExecuteStateMsg(msg) == false);
        EXPECT_TRUE(pScanStateMachine->commonScanState->ExecuteStateMsg(nullptr) == true);
    }

    void CommonScanUnworkedExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        pScanStateMachine->commonScanUnworkedState->GoInState();
        pScanStateMachine->commonScanUnworkedState->GoOutState();
        EXPECT_TRUE(pScanStateMachine->commonScanUnworkedState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanUnworkedExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->commonScanUnworkedState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanUnworkedExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_PREPARE);
        EXPECT_TRUE(pScanStateMachine->commonScanUnworkedState->ExecuteStateMsg(msg) == false);
    }

    void CommonScanUnworkedExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->commonScanUnworkedState->ExecuteStateMsg(nullptr) == true);
    }

    void CommonScanningExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        pScanStateMachine->commonScanningState->GoInState();
        pScanStateMachine->commonScanningState->GoOutState();
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanningExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_RESULT_EVENT);
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanningExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_FAILED_EVENT);
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanningExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WAIT_SCAN_RESULT_TIMER);
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanningExeMsgSuccess5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanningExeMsgSuccess6()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_FINISH);
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(msg) == false);
    }

    void CommonScanningExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->commonScanningState->ExecuteStateMsg(nullptr) == true);
    }

    void PnoScanExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->pnoScanState->GoInState();
        pScanStateMachine->pnoScanState->GoOutState();
        EXPECT_TRUE(pScanStateMachine->pnoScanState->ExecuteStateMsg(msg) == false);
    }

    void PnoScanExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->pnoScanState->ExecuteStateMsg(nullptr) == false);
    }

    void PnoScanHardwareExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->pnoScanHardwareState->GoInState();
        pScanStateMachine->pnoScanHardwareState->GoOutState();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(msg) == true);
    }

    void PnoScanHardwareExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_STOP_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(msg) == true);
    }

    void PnoScanHardwareExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_RESTART_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(msg) == true);
    }

    void PnoScanHardwareExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(PNO_SCAN_RESULT_EVENT);
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(msg) == true);
    }

    void PnoScanHardwareExeMsgSuccess5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(msg) == true);
    }

    void PnoScanHardwareExeMsgSuccess6()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_FINISH);
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(msg) == false);
    }

    void PnoScanHardwareExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->pnoScanHardwareState->ExecuteStateMsg(nullptr) == true);
    }

    void CommonScanAfterPnoGoInStateTest()
    {
        pScanStateMachine->commonScanAfterPnoState->GoInState();
        pScanStateMachine->commonScanAfterPnoState->GoOutState();
    }

    void CommonScanAfterPnoExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_RESULT_EVENT);
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanAfterPnoExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_FAILED_EVENT);
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanAfterPnoExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanAfterPnoExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanAfterPnoExeMsgSuccess5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_RESTART_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(msg) == true);
    }

    void CommonScanAfterPnoExeMsgSuccess6()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_FINISH);
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(msg) == false);
    }

    void CommonScanAfterPnoExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->commonScanAfterPnoState->ExecuteStateMsg(nullptr) == true);
    }

    void PnoScanSoftwareGoInStateTest()
    {
        pScanStateMachine->pnoScanSoftwareState->GoInState();
        pScanStateMachine->pnoScanSoftwareState->GoOutState();
    }

    void PnoScanSoftwareExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_STOP_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoScanSoftwareState->ExecuteStateMsg(msg) == true);
    }

    void PnoScanSoftwareExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_FINISH);
        EXPECT_TRUE(pScanStateMachine->pnoScanSoftwareState->ExecuteStateMsg(msg) == false);
    }

    void PnoScanSoftwareExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->pnoScanSoftwareState->ExecuteStateMsg(nullptr) == true);
    }

    void PnoSwScanFreeGoInStateTest()
    {
        pScanStateMachine->pnoSwScanFreeState->GoInState();
    }

    void PnoSwScanFreeGoOutStateTest()
    {
        pScanStateMachine->pnoSwScanFreeState->GoOutState();
    }

    void PnoSwScanFreeExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoSwScanFreeState->ExecuteStateMsg(msg) == true);
    }

    void PnoSwScanFreeExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_RESTART_PNO_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoSwScanFreeState->ExecuteStateMsg(msg) == true);
    }

    void PnoSwScanFreeExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_COMMON_SCAN);
        EXPECT_TRUE(pScanStateMachine->pnoSwScanFreeState->ExecuteStateMsg(msg) == true);
    }

    void PnoSwScanFreeExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SOFTWARE_PNO_SCAN_TIMER);
        EXPECT_TRUE(pScanStateMachine->pnoSwScanFreeState->ExecuteStateMsg(msg) == true);
    }

    void PnoSwScanFreeExeMsgSuccess5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SCAN_FINISH);
        EXPECT_TRUE(pScanStateMachine->pnoSwScanFreeState->ExecuteStateMsg(msg) == false);
    }

    void PnoSwScanFreeExeMsgFail()
    {
        EXPECT_TRUE(pScanStateMachine->pnoSwScanFreeState->ExecuteStateMsg(nullptr) == true);
    }

    void PnoSwScanningExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_RESULT_EVENT);
        pScanStateMachine->pnoSwScanningState->GoInState();
        pScanStateMachine->pnoSwScanningState->GoOutState();
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), true);
    }

    void PnoSwScanningExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_FAILED_EVENT);
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), true);
    }

    void PnoSwScanningExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WAIT_SCAN_RESULT_TIMER);
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), true);
    }

    void PnoSwScanningExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_START_PNO_SCAN);
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), true);
    }

    void PnoSwScanningExeMsgSuccess5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_RESTART_PNO_SCAN);
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), true);
    }

    void PnoSwScanningExeMsgSuccess6()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SOFTWARE_PNO_SCAN_TIMER);
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), true);
    }

    void PnoSwScanningExeMsgSuccess7()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(SCAN_INNER_EVENT_INVALID);
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(msg), false);
    }

    void PnoSwScanningExeMsgFail()
    {
        EXPECT_EQ(pScanStateMachine->pnoSwScanningState->ExecuteStateMsg(nullptr), true);
    }

    void GetCommonScanRequestInfoTest1()
    {
        InternalMessagePtr interMessage = std::make_shared<InternalMessage>();
        MessageBody body;
        interMessage->AddIntMessageBody(10);
        int requestIndex = 0;
        InterScanConfig scanConfig;
        EXPECT_TRUE(pScanStateMachine->GetCommonScanRequestInfo(interMessage, requestIndex, scanConfig));
    }

    void GetCommonScanRequestInfoTest2()
    {
        int requestIndex = 0;
        InterScanConfig scanConfig;
        EXPECT_FALSE(pScanStateMachine->GetCommonScanRequestInfo(nullptr, requestIndex, scanConfig));
    }

    void GetCommonScanConfigSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(0);
        InterScanConfig scanConfig;
        EXPECT_TRUE(pScanStateMachine->GetCommonScanConfig(msg, scanConfig));
    }

    void GetCommonScanConfigFail1()
    {
        InterScanConfig scanConfig;
        EXPECT_FALSE(pScanStateMachine->GetCommonScanConfig(nullptr, scanConfig));
    }

    void GetCommonScanConfigFail2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->AddIntMessageBody(1);
        InterScanConfig scanConfig;
        EXPECT_TRUE(pScanStateMachine->GetCommonScanConfig(msg, scanConfig));
    }

    void GetCommonScanConfigFail3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->AddIntMessageBody(1);
        msg->AddStringMessageBody("hmwifi1");
        msg->AddIntMessageBody(3);
        msg->AddIntMessageBody(0);
        InterScanConfig scanConfig;
        EXPECT_EQ(pScanStateMachine->GetCommonScanConfig(msg, scanConfig), true);
    }

    void StartNewCommonScanTest1()
    {
        InterScanConfig interScanConfig;
        {
            std::unique_lock<std::shared_mutex> guard(ScanStateMachine::lock);
            pScanStateMachine->waitingScans.emplace(0, interScanConfig);
        }
        pScanStateMachine->StartNewCommonScan();
    }

    void StartNewCommonScanTest2()
    {
        pScanStateMachine->StartNewCommonScan();
    }

    void StartSingleCommonScanSuccess()
    {
        WifiHalScanParam scanParam;
        scanParam.scanFreqs.push_back(FREQ_5_GHZ_VALUE);
        scanParam.hiddenNetworkSsid.push_back("wifi_ssid");
        pScanStateMachine->ClearRunningScanSettings();
        pScanStateMachine->StartSingleCommonScan(scanParam);
    }

    void StartSingleCommonScanFail()
    {
        WifiHalScanParam scanParam;
        scanParam.scanFreqs.push_back(FREQ_5_GHZ_VALUE);
        scanParam.hiddenNetworkSsid.push_back("wifi_ssid");
        EXPECT_EQ(pScanStateMachine->StartSingleCommonScan(scanParam), false);
    }

    void CommonScanWhenRunningFail()
    {
        pScanStateMachine->CommonScanWhenRunning(nullptr);
    }

    void ActiveCoverNewScanSuccess()
    {
        pScanStateMachine->runningFullScanFlag = true;
        InterScanConfig interScanConfig;
        interScanConfig.scanStyle = SCAN_TYPE_HIGH_ACCURACY;
        pScanStateMachine->ActiveCoverNewScan(interScanConfig);
    }

    void ActiveCoverNewScanFail()
    {
        pScanStateMachine->runningFullScanFlag = true;
        InterScanConfig interScanConfig;
        interScanConfig.scanStyle = SCAN_TYPE_INVALID;
        pScanStateMachine->ActiveCoverNewScan(interScanConfig);
    }

    void CommonScanInfoProcessTest()
    {
        pScanStateMachine->CommonScanInfoProcess();
    }

    void ReportCommonScanFailedAndClearTest1()
    {
        pScanStateMachine->ReportCommonScanFailedAndClear(true);
    }

    void ReportCommonScanFailedAndClearTest2()
    {
        pScanStateMachine->ReportCommonScanFailedAndClear(false);
    }

    void GetRunningIndexListTest()
    {
        InterScanConfig interScanConfig;
        pScanStateMachine->runningScans.emplace(0, interScanConfig);
        std::vector<int> runningIndexList;
        pScanStateMachine->GetRunningIndexList(runningIndexList);
    }

    void GetWaitingIndexListTest()
    {
        InterScanConfig interScanConfig;
        pScanStateMachine->waitingScans.emplace(0, interScanConfig);
        std::vector<int> waitingIndexList;
        pScanStateMachine->GetRunningIndexList(waitingIndexList);
    }

    void VerifyScanStyleSuccess()
    {
        int scanStyle = SCAN_TYPE_HIGH_ACCURACY;
        EXPECT_EQ(true, pScanStateMachine->VerifyScanStyle(scanStyle));
    }

    void VerifyScanStyleFail()
    {
        int scanStyle = SCAN_TYPE_INVALID;
        EXPECT_EQ(false, pScanStateMachine->VerifyScanStyle(scanStyle));
    }

    void ActiveScanStyleTest1()
    {
        pScanStateMachine->runningScanSettings.scanStyle = SCAN_TYPE_LOW_SPAN;
        int scanStyle = SCAN_TYPE_LOW_POWER;
        EXPECT_EQ(pScanStateMachine->ActiveScanStyle(scanStyle), true);
    }

    void ActiveScanStyleTest2()
    {
        pScanStateMachine->runningScanSettings.scanStyle = SCAN_TYPE_HIGH_ACCURACY;
        int scanStyle = SCAN_TYPE_LOW_POWER;
        EXPECT_EQ(pScanStateMachine->ActiveScanStyle(scanStyle), true);
    }

    void ActiveScanStyleTest3()
    {
        pScanStateMachine->runningScanSettings.scanStyle = SCAN_TYPE_INVALID;
        int scanStyle = SCAN_TYPE_LOW_POWER;
        EXPECT_EQ(pScanStateMachine->ActiveScanStyle(scanStyle), false);
    }

    void MergeScanStyleTest1()
    {
        int currentScanStyle = SCAN_TYPE_LOW_SPAN;
        int newScanStyle = SCAN_TYPE_HIGH_ACCURACY;
        EXPECT_EQ(pScanStateMachine->MergeScanStyle(currentScanStyle, newScanStyle), SCAN_TYPE_HIGH_ACCURACY);
    }

    void MergeScanStyleTest2()
    {
        int currentScanStyle = SCAN_TYPE_HIGH_ACCURACY;
        int newScanStyle = SCAN_TYPE_HIGH_ACCURACY;
        EXPECT_EQ(pScanStateMachine->MergeScanStyle(currentScanStyle, newScanStyle), SCAN_TYPE_HIGH_ACCURACY);
    }

    void MergeScanStyleTest3()
    {
        int currentScanStyle = SCAN_TYPE_INVALID;
        int newScanStyle = SCAN_TYPE_HIGH_ACCURACY;
        EXPECT_EQ(pScanStateMachine->MergeScanStyle(currentScanStyle, newScanStyle), SCAN_TYPE_HIGH_ACCURACY);
    }

    void PnoScanRequestProcessTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->PnoScanRequestProcess(msg);
    }

    void PnoScanRequestProcessFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->supportHwPnoFlag = false;
        pScanStateMachine->PnoScanRequestProcess(nullptr);
        pScanStateMachine->PnoScanRequestProcess(msg);
    }

    void PnoScanHardwareProcessTest1()
    {
        pScanStateMachine->runningHwPnoFlag = false;
        pScanStateMachine->pnoConfigStoredFlag = true;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->ContinuePnoScanProcess();
        pScanStateMachine->PnoScanHardwareProcess(msg);
    }

    void PnoScanHardwareProcessTest2()
    {
        pScanStateMachine->runningHwPnoFlag = true;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->PnoScanHardwareProcess(msg);
        pScanStateMachine->PnoScanHardwareProcess(nullptr);
    }

    void StartPnoScanHardwareSuccess1()
    {
        pScanStateMachine->runningHwPnoFlag = false;
        pScanStateMachine->pnoConfigStoredFlag = true;
        EXPECT_EQ(false, pScanStateMachine->StartPnoScanHardware());
    }

    void StartPnoScanHardwareSuccess2()
    {
        pScanStateMachine->runningHwPnoFlag = true;
        pScanStateMachine->pnoConfigStoredFlag = true;
        EXPECT_EQ(true, pScanStateMachine->StartPnoScanHardware());
    }

    void StartPnoScanHardwareSuccess3()
    {
        pScanStateMachine->runningHwPnoFlag = false;
        pScanStateMachine->pnoConfigStoredFlag = false;
        EXPECT_EQ(true, pScanStateMachine->StartPnoScanHardware());
    }

    void StartPnoScanHardwareFail()
    {
        pScanStateMachine->runningHwPnoFlag = false;
        pScanStateMachine->pnoConfigStoredFlag = true;
        EXPECT_EQ(false, pScanStateMachine->StartPnoScanHardware());
    }

    void StopPnoScanHardwareTest1()
    {
        pScanStateMachine->supportHwPnoFlag = true;
        pScanStateMachine->runningHwPnoFlag = true;
        pScanStateMachine->StopPnoScanHardware();
    }

    void StopPnoScanHardwareTest2()
    {
        pScanStateMachine->supportHwPnoFlag = false;
        pScanStateMachine->runningHwPnoFlag = true;
        pScanStateMachine->StopPnoScanHardware();
    }

    void StopPnoScanHardwareTest3()
    {
        pScanStateMachine->supportHwPnoFlag = true;
        pScanStateMachine->runningHwPnoFlag = true;
        pScanStateMachine->StopPnoScanHardware();
    }

    void UpdatePnoScanRequestTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->UpdatePnoScanRequest(msg);
        pScanStateMachine->UpdatePnoScanRequest(nullptr);
        EXPECT_NE(pScanStateMachine->m_instId, TWO);
    }

    void GetPnoScanRequestInfoTest1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->ClearMessageBody();
        pScanStateMachine->GetPnoScanRequestInfo(msg);
    }

    void GetPnoScanRequestInfoTest2()
    {
        pScanStateMachine->GetPnoScanRequestInfo(nullptr);
    }

    void GetPnoScanConfigSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(1);
        msg->AddStringMessageBody("hmwifi1");
        msg->AddIntMessageBody(0);
        msg->AddStringMessageBody("hmwifi2");
        msg->AddIntMessageBody(1);
        msg->AddIntMessageBody(FREQ_2_DOT_4_GHZ_VALUE);
        PnoScanConfig pnoScanConfig;
        EXPECT_EQ(true, pScanStateMachine->GetPnoScanConfig(msg, pnoScanConfig));
    }

    void GetPnoScanConfigFail1()
    {
        PnoScanConfig pnoScanConfig;
        EXPECT_EQ(false, pScanStateMachine->GetPnoScanConfig(nullptr, pnoScanConfig));
    }

    void GetPnoScanConfigFail2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(0);
        msg->AddIntMessageBody(1);
        PnoScanConfig pnoScanConfig;
        EXPECT_EQ(false, pScanStateMachine->GetPnoScanConfig(msg, pnoScanConfig));
    }

    void HwPnoScanInfoProcessTest1()
    {
        pScanStateMachine->runningHwPnoFlag = true;
        pScanStateMachine->HwPnoScanInfoProcess();
    }

    void HwPnoScanInfoProcessTest2()
    {
        pScanStateMachine->runningHwPnoFlag = false;
        pScanStateMachine->HwPnoScanInfoProcess();
    }

    void HwPnoScanInfoProcessTest3()
    {
        pScanStateMachine->runningHwPnoFlag = true;
        pScanStateMachine->HwPnoScanInfoProcess();
    }

    void ReportPnoScanInfosTest()
    {
        std::vector<InterScanInfo> scanInfos = { InterScanInfo() };
        pScanStateMachine->ReportPnoScanInfos(scanInfos);
    }

    void NeedCommonScanAfterPnoTest()
    {
        std::vector<InterScanInfo> scanInfos = { InterScanInfo() };
        EXPECT_EQ(false, pScanStateMachine->NeedCommonScanAfterPno(scanInfos));
    }

    void CommonScanAfterPnoProcessTest1()
    {
        pScanStateMachine->CommonScanAfterPnoProcess();
    }

    void CommonScanAfterPnoProcessTest2()
    {
        pScanStateMachine->CommonScanAfterPnoProcess();
    }

    void CommonScanAfterPnoResultTest1()
    {
        pScanStateMachine->CommonScanAfterPnoResult();
    }

    void CommonScanAfterPnoResultTest2()
    {
        pScanStateMachine->CommonScanAfterPnoResult();
    }

    void GetScanInfosSuccess()
    {
        std::vector<InterScanInfo> scanInfos;
        pScanStateMachine->GetScanInfos(scanInfos);
    }

    void GetScanInfosFail()
    {
        std::vector<InterScanInfo> scanInfos;
        EXPECT_EQ(false, pScanStateMachine->GetScanInfos(scanInfos));
    }

    void GetSecurityTypeAndBandTest()
    {
        std::vector<InterScanInfo> scanInfos;
        InterScanInfo interScanInfo;
        interScanInfo.frequency = FREQ_2_DOT_4_GHZ_VALUE;
        interScanInfo.capabilities = "WAPI-PSK";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "PSK";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "WEP";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "EAP-SUITE-B-192";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "EAP";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "SAE";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "OWE";
        scanInfos.push_back(interScanInfo);
        interScanInfo.frequency = FREQ_5_GHZ_VALUE;
        interScanInfo.capabilities = "CERT";
        scanInfos.push_back(interScanInfo);
        pScanStateMachine->GetSecurityTypeAndBand(scanInfos);
    }

    void StartNewSoftwareScanTest()
    {
        pScanStateMachine->StartNewSoftwareScan();
    }

    void RepeatStartCommonScanTest1()
    {
        pScanStateMachine->pnoConfigStoredFlag = true;
        pScanStateMachine->RepeatStartCommonScan();
    }

    void RepeatStartCommonScanTest2()
    {
        pScanStateMachine->pnoConfigStoredFlag = false;
        EXPECT_EQ(false, pScanStateMachine->RepeatStartCommonScan());
    }

    void RepeatStartCommonScanTest3()
    {
        pScanStateMachine->pnoConfigStoredFlag = true;
        EXPECT_EQ(false, pScanStateMachine->RepeatStartCommonScan());
    }

    void StopPnoScanSoftwareTest()
    {
        pScanStateMachine->StopPnoScanSoftware();
    }

    void PnoScanSoftwareProcessTest1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->runningSwPnoFlag = false;
        pScanStateMachine->PnoScanSoftwareProcess(msg);
    }

    void PnoScanSoftwareProcessTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->runningSwPnoFlag = true;
        pScanStateMachine->PnoScanSoftwareProcess(msg);
    }

    void PnoScanSoftwareProcessTest3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pScanStateMachine->runningSwPnoFlag = true;
        pScanStateMachine->PnoScanSoftwareProcess(msg);
    }

    void SoftwareScanInfoProcessTest1()
    {
        pScanStateMachine->SoftwareScanInfoProcess();
    }

    void SoftwareScanInfoProcessTest2()
    {
        pScanStateMachine->SoftwareScanInfoProcess();
    }

    void InitCommonScanStateTest()
    {
        pScanStateMachine->InitCommonScanState();
    }

    void InitPnoScanState()
    {
        EXPECT_EQ(pScanStateMachine->InitPnoScanState(), true);
    }

    void RecordFilteredScanResultTest()
    {
        WifiDeviceConfig config;
        config.bssid = "01:23:45:67:89:AB";
        config.band = BAND;
        config.networkId = NETWORK_ID;
        config.ssid = "";
        config.keyMgmt = "WEP";
        ScanStateMachine::FilterScanResultRecord records;
        InterScanInfo interScanInfo;
        interScanInfo.securityType = WifiSecurity::WEP;
        records.RecordFilteredScanResult(interScanInfo);
    }

    void GetScanInfoMsgTest()
    {
        InterScanInfo interScanInfo;
        interScanInfo.securityType = WifiSecurity::WEP;
        ScanStateMachine::FilterScanResultRecord records;
        records.GetScanInfoMsg(interScanInfo);
    }

    void GetFilteredScanResultMsgTest()
    {
        ScanStateMachine::FilterScanResultRecord records;
        EXPECT_EQ(records.GetFilteredScanResultMsg(), "");
    }

    void FilterScanResultTest()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetConnectedBssid(_)).Times(AtLeast(1));
        std::vector<InterScanInfo> scanInfoList;
        pScanStateMachine->FilterScanResult(scanInfoList);
    }

    void SetWifiModeTest()
    {
        InterScanInfo scanInfo;
        scanInfo. isHeInfoExist =true;
        pScanStateMachine->SetWifiMode(scanInfo);
        InterScanInfo scanInfo1;
        scanInfo1. band =SCAN_5GHZ_BAND;
        scanInfo1.isVhtInfoExist =true;
        pScanStateMachine->SetWifiMode(scanInfo1);
        InterScanInfo scanInfo2;
        scanInfo2.isHtInfoExist =true;
        pScanStateMachine->SetWifiMode(scanInfo2);
        InterScanInfo scanInfo3;
        scanInfo3.isErpExist =true;
        pScanStateMachine->SetWifiMode(scanInfo3);
        InterScanInfo scanInfo4;
        scanInfo4. band =SCAN_24GHZ_BAND;
        scanInfo4.isVhtInfoExist =false;
        pScanStateMachine->SetWifiMode(scanInfo4);
        InterScanInfo scanInfo5;
        scanInfo4. band =SCAN_24GHZ_BAND;
        pScanStateMachine->SetWifiMode(scanInfo5);
        EXPECT_NE(scanInfo4.wifiMode, 0);
    }
};

HWTEST_F(ScanStateMachineTest, InitGoInStateTest, TestSize.Level1)
{
    InitGoInStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, InitGoOutStateTest, TestSize.Level1)
{
    InitGoOutStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess1, TestSize.Level1)
{
    InitExeMsgSuccess1();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess2, TestSize.Level1)
{
    InitExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess3, TestSize.Level1)
{
    InitExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess4, TestSize.Level1)
{
    InitExeMsgSuccess4();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess5, TestSize.Level1)
{
    InitExeMsgSuccess5();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess6, TestSize.Level1)
{
    InitExeMsgSuccess6();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess7, TestSize.Level1)
{
    InitExeMsgSuccess7();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess8, TestSize.Level1)
{
    InitExeMsgSuccess8();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess9, TestSize.Level1)
{
    InitExeMsgSuccess9();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess10, TestSize.Level1)
{
    InitExeMsgSuccess10();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgSuccess11, TestSize.Level1)
{
    InitExeMsgSuccess11();
}

HWTEST_F(ScanStateMachineTest, InitExeMsgFail, TestSize.Level1)
{
    InitExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, HardwareReadyExeMsgSuccess1, TestSize.Level1)
{
    HardwareReadyExeMsgSuccess1();
}

HWTEST_F(ScanStateMachineTest, HardwareReadyExeMsgSuccess2, TestSize.Level1)
{
    HardwareReadyExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, HardwareReadyExeMsgFail, TestSize.Level1)
{
    HardwareReadyExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, CommonScanGoInStateTest, TestSize.Level1)
{
    CommonScanGoInStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanGoOutStateTest, TestSize.Level1)
{
    CommonScanGoOutStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanExeMsgSuccess, TestSize.Level1)
{
    CommonScanExeMsgSuccess();
}

HWTEST_F(ScanStateMachineTest, CommonScanExeMsgFail, TestSize.Level1)
{
    CommonScanExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, CommonScanUnworkedExeMsgSuccess1, TestSize.Level1)
{
    CommonScanUnworkedExeMsgSuccess1();
}

HWTEST_F(ScanStateMachineTest, CommonScanUnworkedExeMsgSuccess2, TestSize.Level1)
{
    CommonScanUnworkedExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, CommonScanUnworkedExeMsgSuccess3, TestSize.Level1)
{
    CommonScanUnworkedExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, CommonScanUnworkedExeMsgFail, TestSize.Level1)
{
    CommonScanUnworkedExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, CommonScanningExeMsgSuccess1, TestSize.Level1)
{
    CommonScanningExeMsgSuccess1();
}

HWTEST_F(ScanStateMachineTest, CommonScanningExeMsgSuccess3, TestSize.Level1)
{
    CommonScanningExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, CommonScanningExeMsgSuccess4, TestSize.Level1)
{
    CommonScanningExeMsgSuccess4();
}

HWTEST_F(ScanStateMachineTest, CommonScanningExeMsgSuccess5, TestSize.Level1)
{
    CommonScanningExeMsgSuccess5();
}

HWTEST_F(ScanStateMachineTest, CommonScanningExeMsgSuccess6, TestSize.Level1)
{
    CommonScanningExeMsgSuccess6();
}

HWTEST_F(ScanStateMachineTest, CommonScanningExeMsgFail, TestSize.Level1)
{
    CommonScanningExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, PnoScanExeMsgSuccess, TestSize.Level1)
{
    PnoScanExeMsgSuccess();
}

HWTEST_F(ScanStateMachineTest, PnoScanExeMsgFail, TestSize.Level1)
{
    PnoScanExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareExeMsgSuccess2, TestSize.Level1)
{
    PnoScanHardwareExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareExeMsgSuccess3, TestSize.Level1)
{
    PnoScanHardwareExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareExeMsgSuccess5, TestSize.Level1)
{
    PnoScanHardwareExeMsgSuccess5();
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareExeMsgSuccess6, TestSize.Level1)
{
    PnoScanHardwareExeMsgSuccess6();
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareExeMsgFail, TestSize.Level1)
{
    PnoScanHardwareExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoGoInStateTest, TestSize.Level1)
{
    CommonScanAfterPnoGoInStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoExeMsgSuccess2, TestSize.Level1)
{
    CommonScanAfterPnoExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoExeMsgSuccess3, TestSize.Level1)
{
    CommonScanAfterPnoExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoExeMsgSuccess4, TestSize.Level1)
{
    CommonScanAfterPnoExeMsgSuccess4();
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoExeMsgSuccess5, TestSize.Level1)
{
    CommonScanAfterPnoExeMsgSuccess5();
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoExeMsgSuccess6, TestSize.Level1)
{
    CommonScanAfterPnoExeMsgSuccess6();
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoExeMsgFail, TestSize.Level1)
{
    CommonScanAfterPnoExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareGoInStateTest, TestSize.Level1)
{
    PnoScanSoftwareGoInStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareExeMsgSuccess1, TestSize.Level1)
{
    PnoScanSoftwareExeMsgSuccess1();
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareExeMsgSuccess2, TestSize.Level1)
{
    PnoScanSoftwareExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareExeMsgFail, TestSize.Level1)
{
    PnoScanSoftwareExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeGoInStateTest, TestSize.Level1)
{
    PnoSwScanFreeGoInStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeGoOutStateTest, TestSize.Level1)
{
    PnoSwScanFreeGoOutStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeExeMsgSuccess1, TestSize.Level1)
{
    PnoSwScanFreeExeMsgSuccess1();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeExeMsgSuccess2, TestSize.Level1)
{
    PnoSwScanFreeExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeExeMsgSuccess3, TestSize.Level1)
{
    PnoSwScanFreeExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeExeMsgSuccess4, TestSize.Level1)
{
    PnoSwScanFreeExeMsgSuccess4();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeExeMsgSuccess5, TestSize.Level1)
{
    PnoSwScanFreeExeMsgSuccess5();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanFreeExeMsgFail, TestSize.Level1)
{
    PnoSwScanFreeExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgSuccess2, TestSize.Level1)
{
    PnoSwScanningExeMsgSuccess2();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgSuccess3, TestSize.Level1)
{
    PnoSwScanningExeMsgSuccess3();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgSuccess4, TestSize.Level1)
{
    PnoSwScanningExeMsgSuccess4();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgSuccess5, TestSize.Level1)
{
    PnoSwScanningExeMsgSuccess5();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgSuccess6, TestSize.Level1)
{
    PnoSwScanningExeMsgSuccess6();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgSuccess7, TestSize.Level1)
{
    PnoSwScanningExeMsgSuccess7();
}

HWTEST_F(ScanStateMachineTest, PnoSwScanningExeMsgFail, TestSize.Level1)
{
    PnoSwScanningExeMsgFail();
}

HWTEST_F(ScanStateMachineTest, GetCommonScanRequestInfoTest1, TestSize.Level1)
{
    GetCommonScanRequestInfoTest1();
}

HWTEST_F(ScanStateMachineTest, GetCommonScanRequestInfoTest2, TestSize.Level1)
{
    GetCommonScanRequestInfoTest2();
}

HWTEST_F(ScanStateMachineTest, GetCommonScanConfigSuccess, TestSize.Level1)
{
    GetCommonScanConfigSuccess();
}

HWTEST_F(ScanStateMachineTest, GetCommonScanConfigFail1, TestSize.Level1)
{
    GetCommonScanConfigFail1();
}

HWTEST_F(ScanStateMachineTest, GetCommonScanConfigFail2, TestSize.Level1)
{
    GetCommonScanConfigFail2();
}

HWTEST_F(ScanStateMachineTest, GetCommonScanConfigFail3, TestSize.Level1)
{
    GetCommonScanConfigFail3();
}

HWTEST_F(ScanStateMachineTest, StartNewCommonScanTest1, TestSize.Level1)
{
    StartNewCommonScanTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StartNewCommonScanTest2, TestSize.Level1)
{
    StartNewCommonScanTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StartSingleCommonScanSuccess, TestSize.Level1)
{
    StartSingleCommonScanSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StartSingleCommonScanFail, TestSize.Level1)
{
    StartSingleCommonScanFail();
}

HWTEST_F(ScanStateMachineTest, CommonScanWhenRunningFail, TestSize.Level1)
{
    CommonScanWhenRunningFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, ActiveCoverNewScanSuccess, TestSize.Level1)
{
    ActiveCoverNewScanSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, ActiveCoverNewScanFail, TestSize.Level1)
{
    ActiveCoverNewScanFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, ReportCommonScanFailedAndClearTest1, TestSize.Level1)
{
    ReportCommonScanFailedAndClearTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, ReportCommonScanFailedAndClearTest2, TestSize.Level1)
{
    ReportCommonScanFailedAndClearTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetRunningIndexListTest, TestSize.Level1)
{
    GetRunningIndexListTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetWaitingIndexListTest, TestSize.Level1)
{
    GetWaitingIndexListTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, VerifyScanStyleSuccess, TestSize.Level1)
{
    VerifyScanStyleSuccess();
}

HWTEST_F(ScanStateMachineTest, VerifyScanStyleFail, TestSize.Level1)
{
    VerifyScanStyleFail();
}

HWTEST_F(ScanStateMachineTest, ActiveScanStyleTest1, TestSize.Level1)
{
    ActiveScanStyleTest1();
}

HWTEST_F(ScanStateMachineTest, ActiveScanStyleTest2, TestSize.Level1)
{
    ActiveScanStyleTest2();
}

HWTEST_F(ScanStateMachineTest, ActiveScanStyleTest3, TestSize.Level1)
{
    ActiveScanStyleTest3();
}

HWTEST_F(ScanStateMachineTest, MergeScanStyleTest1, TestSize.Level1)
{
    MergeScanStyleTest1();
}

HWTEST_F(ScanStateMachineTest, MergeScanStyleTest2, TestSize.Level1)
{
    MergeScanStyleTest2();
}

HWTEST_F(ScanStateMachineTest, MergeScanStyleTest3, TestSize.Level1)
{
    MergeScanStyleTest3();
}

HWTEST_F(ScanStateMachineTest, PnoScanRequestProcessTest, TestSize.Level1)
{
    PnoScanRequestProcessTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareProcessTest1, TestSize.Level1)
{
    PnoScanHardwareProcessTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoScanHardwareProcessTest2, TestSize.Level1)
{
    PnoScanHardwareProcessTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StartPnoScanHardwareSuccess1, TestSize.Level1)
{
    StartPnoScanHardwareSuccess1();
}

HWTEST_F(ScanStateMachineTest, StartPnoScanHardwareSuccess2, TestSize.Level1)
{
    StartPnoScanHardwareSuccess2();
}

HWTEST_F(ScanStateMachineTest, StartPnoScanHardwareSuccess3, TestSize.Level1)
{
    StartPnoScanHardwareSuccess3();
}

HWTEST_F(ScanStateMachineTest, StopPnoScanHardwareTest1, TestSize.Level1)
{
    StopPnoScanHardwareTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StopPnoScanHardwareTest2, TestSize.Level1)
{
    StopPnoScanHardwareTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StopPnoScanHardwareTest3, TestSize.Level1)
{
    StopPnoScanHardwareTest3();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, UpdatePnoScanRequestTest, TestSize.Level1)
{
    UpdatePnoScanRequestTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetPnoScanRequestInfoTest1, TestSize.Level1)
{
    GetPnoScanRequestInfoTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetPnoScanRequestInfoTest2, TestSize.Level1)
{
    GetPnoScanRequestInfoTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetPnoScanConfigSuccess, TestSize.Level1)
{
    GetPnoScanConfigSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetPnoScanConfigFail1, TestSize.Level1)
{
    GetPnoScanConfigFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetPnoScanConfigFail2, TestSize.Level1)
{
    GetPnoScanConfigFail2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, HwPnoScanInfoProcessTest1, TestSize.Level1)
{
    HwPnoScanInfoProcessTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, HwPnoScanInfoProcessTest2, TestSize.Level1)
{
    HwPnoScanInfoProcessTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, HwPnoScanInfoProcessTest3, TestSize.Level1)
{
    HwPnoScanInfoProcessTest3();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, ReportPnoScanInfosTest, TestSize.Level1)
{
    ReportPnoScanInfosTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, NeedCommonScanAfterPnoTest, TestSize.Level1)
{
    NeedCommonScanAfterPnoTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoProcessTest1, TestSize.Level1)
{
    CommonScanAfterPnoProcessTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoProcessTest2, TestSize.Level1)
{
    CommonScanAfterPnoProcessTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoResultTest1, TestSize.Level1)
{
    CommonScanAfterPnoResultTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, CommonScanAfterPnoResultTest2, TestSize.Level1)
{
    CommonScanAfterPnoResultTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetScanInfosSuccess, TestSize.Level1)
{
    GetScanInfosSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetScanInfosFail, TestSize.Level1)
{
    GetScanInfosFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetSecurityTypeAndBandTest, TestSize.Level1)
{
    GetSecurityTypeAndBandTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StartNewSoftwareScanTest, TestSize.Level1)
{
    StartNewSoftwareScanTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, RepeatStartCommonScanTest1, TestSize.Level1)
{
    RepeatStartCommonScanTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, RepeatStartCommonScanTest2, TestSize.Level1)
{
    RepeatStartCommonScanTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, RepeatStartCommonScanTest3, TestSize.Level1)
{
    RepeatStartCommonScanTest3();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StopPnoScanSoftwareTest, TestSize.Level1)
{
    StopPnoScanSoftwareTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareProcessTest1, TestSize.Level1)
{
    PnoScanSoftwareProcessTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareProcessTest2, TestSize.Level1)
{
    PnoScanSoftwareProcessTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, PnoScanSoftwareProcessTest3, TestSize.Level1)
{
    PnoScanSoftwareProcessTest3();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, SoftwareScanInfoProcessTest1, TestSize.Level1)
{
    SoftwareScanInfoProcessTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, SoftwareScanInfoProcessTest2, TestSize.Level1)
{
    SoftwareScanInfoProcessTest2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, InitCommonScanStateTest, TestSize.Level1)
{
    InitCommonScanStateTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, InitPnoScanState, TestSize.Level1)
{
    InitPnoScanState();
}

HWTEST_F(ScanStateMachineTest, PnoScanRequestProcessFail, TestSize.Level1)
{
    PnoScanRequestProcessFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, StartPnoScanHardwareFail, TestSize.Level1)
{
    StartPnoScanHardwareFail();
}

HWTEST_F(ScanStateMachineTest, RecordFilteredScanResultTest, TestSize.Level1)
{
    RecordFilteredScanResultTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, GetFilteredScanResultMsgTest, TestSize.Level1)
{
    GetFilteredScanResultMsgTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, FilterScanResultTest, TestSize.Level1)
{
    FilterScanResultTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanStateMachineTest, SetWifiModeTest, TestSize.Level1)
{
    SetWifiModeTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}
} // namespace Wifi
} // namespace OHOS
