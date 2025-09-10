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
#include "wifi_netlink.h"

using namespace OHOS::Wifi;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

enum CmdWord {
    CMD_START_MONITOR = 10,
};

static std::string g_errLog = "wifitest";
class WifiNetLinkTest : public testing::Test {
protected:
    void SetUp() override
    {}

    void TearDown() override
    {}
};

HWTEST_F(WifiNetLinkTest, TestInitWifiNetLink, TestSize.Level1)
{
    WifiNetLinkCallbacks callbacks;
    WifiNetLink::GetInstance().InitWifiNetLink(callbacks);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiNetLinkTest, TestSendCmdKernel, TestSize.Level1)
{
    WifiNetLink wifiNetLink;
    int32_t sockFd = 123;
    int32_t cmd = 456;
    int32_t flag = 789;
    WifiNetLink::GetInstance().SendCmdKernel(sockFd, cmd, flag);
    EXPECT_EQ(WifiNetLink::GetInstance().SendCmdKernel(sockFd, cmd, flag), -1);
}

HWTEST_F(WifiNetLinkTest, TestStartMonitor, TestSize.Level1)
{
    int32_t sockFd = 123;
    WifiNetLink::GetInstance().StartMonitor(sockFd);
    EXPECT_EQ(WifiNetLink::GetInstance().StartMonitor(sockFd), -1);
}

HWTEST_F(WifiNetLinkTest, TestProcessQueryTcp, TestSize.Level1)
{
    int32_t sockFd = 123;
    WifiNetLink::GetInstance().ProcessQueryTcp(sockFd);
    EXPECT_EQ(WifiNetLink::GetInstance().ProcessQueryTcp(sockFd), -1);
}

HWTEST_F(WifiNetLinkTest, TestSendQoeCmd, TestSize.Level1)
{
    int32_t cmd = 123;
    int32_t arg = 456;
    WifiNetLink::GetInstance().SendQoeCmd(cmd, arg);
    EXPECT_EQ(WifiNetLink::GetInstance().SendQoeCmd(cmd, arg), -1);
}

HWTEST_F(WifiNetLinkTest, TestProcessReportMsg, TestSize.Level1)
{
    int32_t sockFd = 123;
    int32_t cmd = 456;
    WifiNetLink::GetInstance().ProcessReportMsg(sockFd, cmd);
    EXPECT_EQ(WifiNetLink::GetInstance().ProcessReportMsg(sockFd, cmd), -1);
}

HWTEST_F(WifiNetLinkTest, SendQoeCmdTest001, TestSize.Level1)
{
    int32_t cmd = CMD_START_MONITOR;
    int32_t arg = 456;
    WifiNetLink::GetInstance().SendQoeCmd(cmd, arg);
    EXPECT_NE(WifiNetLink::GetInstance().SendQoeCmd(cmd, arg), -1);
}

HWTEST_F(WifiNetLinkTest, TestProcessQueryIpv6Tcp, TestSize.Level1)
{
    int32_t sockFd = 123;
    WifiNetLink::GetInstance().ProcessQueryIpv6Tcp(sockFd);
    EXPECT_EQ(WifiNetLink::GetInstance().ProcessQueryIpv6Tcp(sockFd), -1);
}

HWTEST_F(WifiNetLinkTest, SendIpv6QoeCmdTest, TestSize.Level1)
{
    int32_t cmd = 24; // CMD_QUERY_IPV6_PKTS
    int32_t arg = 0;
    WifiNetLink::GetInstance().SendQoeCmd(cmd, arg);
    EXPECT_EQ(WifiNetLink::GetInstance().SendQoeCmd(cmd, arg), -1);
}