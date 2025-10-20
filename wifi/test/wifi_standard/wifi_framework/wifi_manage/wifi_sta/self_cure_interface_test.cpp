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
#include "self_cure_interface.h"
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

constexpr int TEN = 10;
static std::string g_errLog;
void SelfCureInterfaceCallback(const LogType type, const LogLevel level,
                               const unsigned int domain, const char *tag,
                               const char *msg)
{
        g_errLog = msg;
}

class SelfCureInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSelfCureInterface = std::make_unique<SelfCureInterface>();
        if (pSelfCureInterface != nullptr) {
            pSelfCureInterface->InitSelfCureService();
        }
        LOG_SetCallback(SelfCureInterfaceCallback);
    }

    virtual void TearDown()
    {
        pSelfCureInterface.reset();
    }

    std::unique_ptr<SelfCureInterface> pSelfCureInterface;

    void InitSelfCureServiceTest()
    {
        pSelfCureInterface->InitSelfCureService();
    }

    void InitCallbackTest()
    {
        pSelfCureInterface->InitCallback();
    }

    void GetStaCallbackTest()
    {
        StaServiceCallback callback;
        EXPECT_EQ(pSelfCureInterface->GetStaCallback().callbackModuleName,
            pSelfCureInterface->mStaCallback.callbackModuleName);
    }

    void DealStaConnChangedTest()
    {
        OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
        WifiLinkedInfo info;
        int instId = 0;
        pSelfCureInterface->DealStaConnChanged(state, info, instId);
        pSelfCureInterface->pSelfCureService = nullptr;
        pSelfCureInterface->DealStaConnChanged(state, info, instId);
    }

    void DealRssiLevelChangedTest()
    {
        int rssi = MIN_VAL_LEVEL_4;
        int instId = 0;
        pSelfCureInterface->DealRssiLevelChanged(rssi, instId);
        pSelfCureInterface->pSelfCureService = nullptr;
        pSelfCureInterface->DealRssiLevelChanged(rssi, instId);
    }

    void DealDhcpOfferReportTest()
    {
        IpInfo ipInfo;
        int instId = 0;
        pSelfCureInterface->DealDhcpOfferReport(ipInfo, instId);
        pSelfCureInterface->pSelfCureService = nullptr;
        pSelfCureInterface->DealDhcpOfferReport(ipInfo, instId);
    }
};

HWTEST_F(SelfCureInterfaceTest, InitSelfCureServiceTest, TestSize.Level1)
{
    InitSelfCureServiceTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureInterfaceTest, InitCallbackTest, TestSize.Level1)
{
    InitCallbackTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureInterfaceTest, GetStaCallbackTest, TestSize.Level1)
{
    GetStaCallbackTest();
}

HWTEST_F(SelfCureInterfaceTest, DealStaConnChangedTest, TestSize.Level1)
{
    DealStaConnChangedTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureInterfaceTest, DealRssiLevelChangedTest, TestSize.Level1)
{
    DealRssiLevelChangedTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureInterfaceTest, NotifyInternetFailureDetectedTest, TestSize.Level1)
{
    int forceNoHttpCheck = 0;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pSelfCureInterface->NotifyInternetFailureDetected(forceNoHttpCheck));
    pSelfCureInterface->pSelfCureService = nullptr;
    EXPECT_EQ(WIFI_OPT_FAILED, pSelfCureInterface->NotifyInternetFailureDetected(forceNoHttpCheck));
}

HWTEST_F(SelfCureInterfaceTest, NotifyP2pConnectStateChangedTest, TestSize.Level1)
{
    WifiP2pLinkedInfo info;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pSelfCureInterface->NotifyP2pConnectStateChanged(info));
    pSelfCureInterface->pSelfCureService = nullptr;
    EXPECT_EQ(WIFI_OPT_FAILED, pSelfCureInterface->NotifyP2pConnectStateChanged(info));
}

HWTEST_F(SelfCureInterfaceTest, IsSelfCureOnGoingTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureInterface->IsSelfCureOnGoing(), false);
}

HWTEST_F(SelfCureInterfaceTest, IsSelfCureL2ConnectingTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureInterface->IsSelfCureL2Connecting(), false);
}

HWTEST_F(SelfCureInterfaceTest, StopSelfCureWifiTest, TestSize.Level1)
{
    int32_t status = 0;
    EXPECT_EQ(WIFI_OPT_SUCCESS, pSelfCureInterface->StopSelfCureWifi(status));
    pSelfCureInterface->pSelfCureService = nullptr;
    EXPECT_EQ(WIFI_OPT_FAILED, pSelfCureInterface->StopSelfCureWifi(status));
}

HWTEST_F(SelfCureInterfaceTest, CheckSelfCureWifiResultTest, TestSize.Level1)
{
    int event = 0;
    EXPECT_EQ(pSelfCureInterface->CheckSelfCureWifiResult(event), false);
}

HWTEST_F(SelfCureInterfaceTest, DealDhcpOfferReportTest, TestSize.Level1)
{
    DealDhcpOfferReportTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureInterfaceTest, NotifyIpv6FailureDetectedTest, TestSize.Level1)
{
    // Test with null service
    pSelfCureInterface->pSelfCureService = nullptr;
    EXPECT_EQ(WIFI_OPT_FAILED, pSelfCureInterface->NotifyIpv6FailureDetected());
}

HWTEST_F(SelfCureInterfaceTest, NotifyTxRxGoodButNoInternetTest, TestSize.Level1)
{
    // Test with valid service
    pSelfCureInterface->NotifyTxRxGoodButNoInternet(true);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);

    pSelfCureInterface->NotifyTxRxGoodButNoInternet(false);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);

    // Test with null service
    pSelfCureInterface->pSelfCureService = nullptr;
    pSelfCureInterface->NotifyTxRxGoodButNoInternet(true);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

} // namespace Wifi
} // namespace OHOS