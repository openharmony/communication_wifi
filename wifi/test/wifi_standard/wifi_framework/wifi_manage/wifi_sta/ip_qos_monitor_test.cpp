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
#include "mock_wifi_config_center.h"
#include <vector>
#include "ip_qos_monitor.h"
#include "wifi_netlink.h"
#include "wifi_logger.h"

using namespace OHOS::Wifi;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
static std::string g_errLog;
    void IpQosMonitorCallback(const LogType type, const LogLevel level,
                              const unsigned int domain, const char *tag,
                              const char *msg)
    {
        g_errLog = msg;
    }

class IpQosMonitorTest : public testing::Test {
public:
    void SetUp() override
    {
        LOG_SetCallback(IpQosMonitorCallback);
    }

    void TearDown() override
    {}
    void OnTcpReportMsgCompleteTest(const std::vector<int64_t> &elems, const int32_t cmd, const int32_t mInstId)
    {
        LOGI("enter OnTcpReportMsgCompleteTest");
    }
};

HWTEST_F(IpQosMonitorTest, TestStartMonitor, TestSize.Level1)
{
    int32_t arg = 0;
    IpQosMonitor::GetInstance().StartMonitor(arg);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(IpQosMonitorTest, TestQueryPackets, TestSize.Level1)
{
    int32_t arg = 0;
    using namespace std::placeholders;
    WifiNetLinkCallbacks mWifiNetLinkCallbacks;
    mWifiNetLinkCallbacks.OnTcpReportMsgComplete =
        std::bind(&IpQosMonitorTest::OnTcpReportMsgCompleteTest, this, _1, _2, _3);
    WifiNetLink::GetInstance().InitWifiNetLink(mWifiNetLinkCallbacks);
    IpQosMonitor::GetInstance().QueryPackets(arg);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(IpQosMonitorTest, TestHandleTcpReportMsgComplete, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 1, 2, 0, 1};
    int32_t cmd = 0;
    IpQosMonitor::GetInstance().HandleTcpReportMsgComplete(elems, cmd);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(IpQosMonitorTest, TestParseTcpReportMsg, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 1, 2, 0, 1};
    int32_t cmd = 123;
    IpQosMonitor::GetInstance().ParseTcpReportMsg(elems, cmd);

    cmd = 15;
    IpQosMonitor::GetInstance().ParseTcpReportMsg(elems, cmd);

    elems = {};
    IpQosMonitor::GetInstance().ParseTcpReportMsg(elems, cmd);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(IpQosMonitorTest, TestHandleTcpPktsResp, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 1, 2, 0, 1};
    IpQosMonitor::GetInstance().HandleTcpPktsResp(elems);

    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.rssi = -30;
    wifiLinkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    IpQosMonitor::GetInstance().HandleTcpPktsResp(elems);
}

HWTEST_F(IpQosMonitorTest, TestHandleTcpPktsResp002, TestSize.Level1)
{
    IpQosMonitor::GetInstance().lastTxRxGood_ = false;
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 1, 2, 0, 1};
    IpQosMonitor::GetInstance().HandleTcpPktsResp(elems);
    EXPECT_TRUE(IpQosMonitor::GetInstance().lastTxRxGood_);
}

HWTEST_F(IpQosMonitorTest, TestAllowSelfCureNetwork, TestSize.Level1)
{
    int32_t currentRssi = 123;
    EXPECT_FALSE(IpQosMonitor::GetInstance().AllowSelfCureNetwork(currentRssi));
}

HWTEST_F(IpQosMonitorTest, TestParseNetworkInternetGood, TestSize.Level1)
{
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 1, 2, 0, 1};
    EXPECT_TRUE(IpQosMonitor::GetInstance().ParseNetworkInternetGood(elems));
}

HWTEST_F(IpQosMonitorTest, TestQueryIpv6Packets, TestSize.Level1)
{
    int32_t arg = 0;
    using namespace std::placeholders;
    WifiNetLinkCallbacks mWifiNetLinkCallbacks;
    mWifiNetLinkCallbacks.OnTcpReportMsgComplete =
        std::bind(&IpQosMonitorTest::OnTcpReportMsgCompleteTest, this, _1, _2, _3);
    WifiNetLink::GetInstance().InitWifiNetLink(mWifiNetLinkCallbacks);
    IpQosMonitor::GetInstance().QueryIpv6Packets(arg);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(IpQosMonitorTest, TestHandleIpv6TcpPktsResp, TestSize.Level1)
{
    // Test IPv6 network good case
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 10, 5, 0, 5}; // elems[9] = QOS_IPV6_MSG_FROM = 5
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    IpQosMonitor::GetInstance().HandleIpv6TcpPktsResp(elems);
    EXPECT_EQ(IpQosMonitor::GetInstance().GetIpv6FailedCounter(), 0);
}

HWTEST_F(IpQosMonitorTest, TestHandleIpv6TcpPktsRespFailure, TestSize.Level1)
{
    // Test IPv6 failure case - TX packets but no RX packets
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 15, 5, 0, 5}; // TX=15, RX=5, MSG_FROM=5
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    // First call to set initial counters
    IpQosMonitor::GetInstance().HandleIpv6TcpPktsResp(elems);

    // Second call with same RX but more TX packets (failure condition)
    elems[6] = 20; // Increase TX packets
    IpQosMonitor::GetInstance().HandleIpv6TcpPktsResp(elems);

    EXPECT_GT(IpQosMonitor::GetInstance().GetIpv6FailedCounter(), 0);
}

HWTEST_F(IpQosMonitorTest, TestHandleIpv6TcpPktsRespDisconnected, TestSize.Level1)
{
    // Test IPv6 failure when WiFi is disconnected
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 15, 5, 0, 5};
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    int32_t initialFailedCount = IpQosMonitor::GetInstance().GetIpv6FailedCounter();
    IpQosMonitor::GetInstance().HandleIpv6TcpPktsResp(elems);

    // Should not increment failure counter when disconnected
    EXPECT_EQ(IpQosMonitor::GetInstance().GetIpv6FailedCounter(), initialFailedCount);
}

HWTEST_F(IpQosMonitorTest, TestParseIpv6NetworkInternetGood, TestSize.Level1)
{
    // Test normal IPv6 response
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 10, 8, 0, 5}; // QOS_IPV6_MSG_FROM = 5
    EXPECT_TRUE(IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems));
}

HWTEST_F(IpQosMonitorTest, TestParseIpv6NetworkInternetGoodShortLength, TestSize.Level1)
{
    // Test with insufficient length
    std::vector<int64_t> elems = {1, 2, 3}; // Length <= MIN_PACKET_LEN
    EXPECT_TRUE(IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems));
}

HWTEST_F(IpQosMonitorTest, TestParseIpv6NetworkInternetGoodWrongMsgFrom, TestSize.Level1)
{
    // Test with wrong MSG_FROM (not IPv6 response)
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 10, 8, 0, 0}; // MSG_FROM = 0 (IPv4)
    EXPECT_TRUE(IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems));
}

HWTEST_F(IpQosMonitorTest, TestParseIpv6NetworkInternetGoodFailure, TestSize.Level1)
{
    // Test IPv6 failure detection - TX > 3 but RX = 0
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 15, 8, 0, 5}; // TX=15, RX=8, MSG_FROM=5

    // First call to initialize counters
    IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems);

    // Second call with no RX increase but TX increase >= 3
    elems[6] = 20; // TX increases to 20, delta = 5 >= 3
    // RX stays same, delta = 0
    EXPECT_FALSE(IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems));
}

HWTEST_F(IpQosMonitorTest, TestParseIpv6NetworkInternetGoodOverflow, TestSize.Level1)
{
    // Test counter overflow handling
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 100, 50, 0, 5};

    // Set initial large values
    IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems);

    // Simulate overflow with smaller values
    elems[6] = 10; // TX counter wrapped around
    elems[7] = 5;  // RX counter wrapped around

    // Should return true on overflow detection
    EXPECT_TRUE(IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems));
}

HWTEST_F(IpQosMonitorTest, TestGetCurrentIpv6Counters, TestSize.Level1)
{
    // Test IPv6 counter getters
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 25, 15, 0, 5};
    IpQosMonitor::GetInstance().ParseIpv6NetworkInternetGood(elems);

    EXPECT_EQ(IpQosMonitor::GetInstance().GetCurrentIpv6TcpTxCounter(), 25);
    EXPECT_EQ(IpQosMonitor::GetInstance().GetCurrentIpv6TcpRxCounter(), 15);
}

HWTEST_F(IpQosMonitorTest, TestGetIpv6FailedCounter, TestSize.Level1)
{
    // Test IPv6 failed counter getter
    int32_t initialCount = IpQosMonitor::GetInstance().GetIpv6FailedCounter();
    EXPECT_GE(initialCount, 0);
}

HWTEST_F(IpQosMonitorTest, TestParseTcpReportMsgWithIpv6Cmd, TestSize.Level1)
{
    // Test ParseTcpReportMsg with IPv6 command
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 10, 8, 0, 5};
    int32_t cmd = 24; // CMD_QUERY_IPV6_PKTS

    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    IpQosMonitor::GetInstance().ParseTcpReportMsg(elems, cmd);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(IpQosMonitorTest, TestStartMonitorResetsIpv6Counter, TestSize.Level1)
{
    // Test that StartMonitor resets IPv6 failed counter

    // First simulate some IPv6 failures to increment counter
    std::vector<int64_t> elems = {1, 2, 3, 1, 2, 3, 15, 8, 0, 5};
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    // Initialize and cause failure
    IpQosMonitor::GetInstance().HandleIpv6TcpPktsResp(elems);
    elems[6] = 20; // Increase TX to cause failure
    IpQosMonitor::GetInstance().HandleIpv6TcpPktsResp(elems);

    // Verify counter is incremented
    EXPECT_GT(IpQosMonitor::GetInstance().GetIpv6FailedCounter(), 0);

    // Call StartMonitor to reset
    IpQosMonitor::GetInstance().StartMonitor(0);

    // Verify counter is reset to 0
    EXPECT_EQ(IpQosMonitor::GetInstance().GetIpv6FailedCounter(), 0);
}