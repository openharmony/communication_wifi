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
#include "scan_monitor.h"
#include "mock_scan_state_machine.h"
#include <gtest/gtest.h>

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
void ScanMonitorCallback(const LogType type,const LogLevel level,const unsigned int domain ,const char *tag,const char *msg)
{
    g_errLog = msg;
}
class ScanMonitorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        LOG_SetCallback(ScanMonitorCallback);
        pScanMonitor = std::make_unique<ScanMonitor>();
        pScanStateMachine = std::make_unique<MockScanStateMachine>();
        pScanMonitor->SetScanStateMachine(pScanStateMachine.get());
    }
    void TearDown() override
    {
        pScanMonitor.reset();
        pScanStateMachine.reset();
    }

public:
    std::unique_ptr<ScanMonitor> pScanMonitor;
    std::unique_ptr<MockScanStateMachine> pScanStateMachine;

    void InitScanMonitorSuccessTest()
    {
        EXPECT_EQ(pScanMonitor->InitScanMonitor(), true);
    }

    void InitScanMonitorFailTest()
    {
        pScanMonitor->ReceiveScanEventFromIdl(0);
        EXPECT_EQ(pScanMonitor->InitScanMonitor(), true);
    }

    void ProcessReceiveScanEventTest1()
    {
        pScanMonitor->ProcessReceiveScanEvent(HAL_SINGLE_SCAN_OVER_OK);
    }

    void ProcessReceiveScanEventTest2()
    {
        pScanMonitor->ProcessReceiveScanEvent(HAL_SINGLE_SCAN_FAILED);
    }

    void ProcessReceiveScanEventTest3()
    {
        pScanMonitor->ProcessReceiveScanEvent(HAL_PNO_SCAN_OVER_OK);
    }

    void ProcessReceiveScanEventTest4()
    {
        pScanMonitor->ProcessReceiveScanEvent(HAL_WPA_CB_CONNECTED);
    }

    void SendScanInfoEventTest()
    {
        pScanMonitor->SendScanInfoEvent();
    }

    void SendPnoScanInfoEventTest()
    {
        pScanMonitor->SendPnoScanInfoEvent();
    }

    void SendScanFailedEventTest()
    {
        pScanMonitor->SendScanFailedEvent();
    }
};

HWTEST_F(ScanMonitorTest, InitScanMonitorSuccessTest, TestSize.Level1)
{
    InitScanMonitorSuccessTest();
}

HWTEST_F(ScanMonitorTest, InitScanMonitorFailTest, TestSize.Level1)
{
    InitScanMonitorFailTest();
}

HWTEST_F(ScanMonitorTest, ProcessReceiveScanEventTest1, TestSize.Level1)
{
    ProcessReceiveScanEventTest1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanMonitorTest, ProcessReceiveScanEventTest2, TestSize.Level1)
{
    ProcessReceiveScanEventTest2();
}

HWTEST_F(ScanMonitorTest, ProcessReceiveScanEventTest3, TestSize.Level1)
{
    ProcessReceiveScanEventTest3();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanMonitorTest, ProcessReceiveScanEventTest4, TestSize.Level1)
{
    ProcessReceiveScanEventTest4();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanMonitorTest, SendScanInfoEventTest, TestSize.Level1)
{
    SendScanInfoEventTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanMonitorTest, SendPnoScanInfoEventTest, TestSize.Level1)
{
    SendPnoScanInfoEventTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(ScanMonitorTest, SendScanFailedEventTest, TestSize.Level1)
{
    SendScanFailedEventTest();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}
} // namespace Wifi
} // namespace OHOS
