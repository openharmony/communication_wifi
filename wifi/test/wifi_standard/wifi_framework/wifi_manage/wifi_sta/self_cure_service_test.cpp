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
#include "self_cure_service.h"
#include "wifi_logger.h"
#include "self_cure_common.h"
#include "wifi_internal_msg.h"

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
void SelfCureServiceCallback(const LogType type, const LogLevel level,
                             const unsigned int domain, const char *tag,
                             const char *msg)
{
    g_errLog = msg;
}
class SelfCureServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSelfCureService = std::make_unique<SelfCureService>();
        LOG_SetCallback(SelfCureServiceCallback);
    }

    virtual void TearDown()
    {
        pSelfCureService.reset();
    }

    std::unique_ptr<SelfCureService> pSelfCureService;

    void InitSelfCureServiceTest()
    {
        pSelfCureService->InitSelfCureService();
    }

    void HandleRssiLevelChangedTest()
    {
        int rssi = MIN_VAL_LEVEL_4;
        pSelfCureService->HandleRssiLevelChanged(rssi);
    }

    void HandleStaConnChangedTest()
    {
        OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }

    void HandleStaConnChangedTest2()
    {
        OperateResState state = OperateResState::DISCONNECT_DISCONNECTED;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }

    void HandleStaConnChangedTest3()
    {
        OperateResState state = OperateResState::CONNECT_NETWORK_DISABLED;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }

    void HandleStaConnChangedTest4()
    {
        OperateResState state = OperateResState::CONNECT_NETWORK_ENABLED;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }

    void HandleStaConnChangedTest5()
    {
        OperateResState state = OperateResState::CONNECT_CHECK_PORTAL;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }

    void HandleDhcpOfferReportTest()
    {
        IpInfo ipInfo;
        pSelfCureService->HandleDhcpOfferReport(ipInfo);
    }

    void NotifyP2pConnectStateChangedTest()
    {
        WifiP2pLinkedInfo info;
        pSelfCureService->NotifyP2pConnectStateChanged(info);
    }

    void StopSelfCureWifiTest()
    {
        int32_t status = 0;
        pSelfCureService->StopSelfCureWifi(status);
    }

    void CheckSelfCureWifiResultTest()
    {
        int event = 0;
        pSelfCureService->CheckSelfCureWifiResult(event);
    }
};

HWTEST_F(SelfCureServiceTest, InitSelfCureServiceTest, TestSize.Level1)
{
    InitSelfCureServiceTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleRssiLevelChangedTest, TestSize.Level1)
{
    HandleRssiLevelChangedTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest, TestSize.Level1)
{
    HandleStaConnChangedTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest2, TestSize.Level1)
{
    HandleStaConnChangedTest2();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest3, TestSize.Level1)
{
    HandleStaConnChangedTest3();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest4, TestSize.Level1)
{
    HandleStaConnChangedTest4();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest5, TestSize.Level1)
{
    HandleStaConnChangedTest5();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, HandleDhcpOfferReportTest, TestSize.Level1)
{
    HandleDhcpOfferReportTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, NotifyP2pConnectStateChangedTest, TestSize.Level1)
{
    NotifyP2pConnectStateChangedTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, NotifyInternetFailureDetectedTest, TestSize.Level1)
{
    int forceNoHttpCheck = 0;
    pSelfCureService->NotifyInternetFailureDetected(forceNoHttpCheck);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, NotifyIpv6FailureDetectedTest, TestSize.Level1)
{
    // Test IPv6 failure detection notification
    bool result = pSelfCureService->NotifyIpv6FailureDetected();
    EXPECT_EQ(result, false);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, SetTxRxGoodButNoInternetTest, TestSize.Level1)
{
    // Test setting tx/rx good but no internet to true
    pSelfCureService->SetTxRxGoodButNoInternet(true);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
    
    // Test setting tx/rx good but no internet to false
    pSelfCureService->SetTxRxGoodButNoInternet(false);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
    
    // Test HandleStaConnChanged with tx/rx good but no internet flag set
    pSelfCureService->SetTxRxGoodButNoInternet(true);
    OperateResState state = OperateResState::CONNECT_NETWORK_ENABLED;
    WifiLinkedInfo info;
    pSelfCureService->HandleStaConnChanged(state, info);
}

HWTEST_F(SelfCureServiceTest, IsSelfCureOnGoingTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureService->IsSelfCureOnGoing(), false);
}

HWTEST_F(SelfCureServiceTest, IsSelfCureL2ConnectingTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureService->IsSelfCureL2Connecting(), false);
}

HWTEST_F(SelfCureServiceTest, StopSelfCureWifiTest, TestSize.Level1)
{
    StopSelfCureWifiTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureServiceTest, CheckSelfCureWifiResultTest, TestSize.Level1)
{
    CheckSelfCureWifiResultTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

} // namespace Wifi
} // namespace OHOS