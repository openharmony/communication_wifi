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
#include "wifi_net_agent.h"
#include "wifi_log.h"
#include "wifi_logger.h"
#include "net_supplier_callback_base.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_config_center.h"

using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr const char *WIFI_NET_CONN_MGR_WORK_THREAD = "WIFI_NET_CONN_MGR_WORK_THREAD";
constexpr int TEN = 10;
class WifiNetAgentTest : public Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

HWTEST_F(WifiNetAgentTest, RegisterNetSupplier_ReturnsFalseWhenRegistrationFails, TestSize.Level1)
{
    int instId = 0;
    EXPECT_FALSE(WifiNetAgent::GetInstance().RegisterNetSupplier(instId));
}

HWTEST_F(WifiNetAgentTest, RegisterNetSupplierCallback_ReturnsFalseWhenRegistrationFails, TestSize.Level1)
{
    int instId = 0;
    EXPECT_FALSE(WifiNetAgent::GetInstance().RegisterNetSupplierCallback(instId));
}

HWTEST_F(WifiNetAgentTest, UnregisterNetSupplier_CallsUnregisterNetSupplier, TestSize.Level1)
{
    int instId = 0;
    WifiNetAgent::GetInstance().UnregisterNetSupplier(instId);
}

HWTEST_F(WifiNetAgentTest, UpdateNetSupplierInfo_CallsUpdateNetSupplierInfo, TestSize.Level1)
{
    sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo = new NetManagerStandard::NetSupplierInfo();
    int instId = 0;
    WifiNetAgent::GetInstance().UpdateNetSupplierInfo(netSupplierInfo, instId);
}

HWTEST_F(WifiNetAgentTest, UpdateNetLinkInfo_CallsUpdateNetLinkInfo, TestSize.Level1)
{
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    int instId = 0;
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    WifiDeviceConfig config;
    WifiNetAgent::GetInstance().UpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, config.wifiProxyconfig, instId);
}

HWTEST_F(WifiNetAgentTest, OnStaMachineUpdateNetLinkInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    WifiProxyConfig wifiProxyConfig;
    int instId = 0;
    wifiNetAgent.OnStaMachineUpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, wifiProxyConfig, instId);
}

HWTEST_F(WifiNetAgentTest, OnStaMachineUpdateNetSupplierInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo =
        sptr<NetManagerStandard::NetSupplierInfo>(new (std::nothrow) NetManagerStandard::NetSupplierInfo());
    int instId = 0;
    wifiNetAgent.OnStaMachineUpdateNetSupplierInfo(netSupplierInfo, instId);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, OnStaMachineWifiStartTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    int instId = 0;
    wifiNetAgent.OnStaMachineWifiStart(instId);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, OnStaMachineNetManagerRestartTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    int instId = 0;
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState == ConnState::CONNECTED;
    WifiSettings::GetInstance().SaveLinkedInfo(linkedInfo, 0);
    sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo =
        sptr<NetManagerStandard::NetSupplierInfo>(new (std::nothrow) NetManagerStandard::NetSupplierInfo());
    wifiNetAgent.OnStaMachineNetManagerRestart(netSupplierInfo, instId);
}

HWTEST_F(WifiNetAgentTest, CreateNetLinkInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    WifiProxyConfig wifiProxyConfig;
    int instId = 0;
    wifiProxyConfig.configureMethod = ConfigureProxyMethod::AUTOCONFIGUE;

    wifiNetAgent.CreateNetLinkInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info, wifiProxyConfig, instId);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, CreateNetLinkInfoTest002, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    WifiProxyConfig wifiProxyConfig;
    int instId = 0;
    wifiProxyConfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;

    wifiNetAgent.CreateNetLinkInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info, wifiProxyConfig, instId);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, CreateNetLinkInfoTest003, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    WifiProxyConfig wifiProxyConfig;
    int instId = 0;
    wifiProxyConfig.configureMethod = ConfigureProxyMethod::CLOSED;

    wifiNetAgent.CreateNetLinkInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info, wifiProxyConfig, instId);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, SetNetLinkIPInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    wifiIpV6Info.globalIpV6Address = "TEST";
    wifiIpV6Info.netmask = "TEST2";
    wifiIpV6Info.randGlobalIpV6Address = "TEST3";
    wifiIpV6Info.uniqueLocalAddress1 = "TEST4";
    wifiIpV6Info.uniqueLocalAddress2 = "TEST5";
    wifiNetAgent.SetNetLinkIPInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, SetNetLinkDnsInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    wifiIpV6Info.dnsAddr.push_back("TEST1");
    wifiIpV6Info.dnsAddr.push_back("TEST2");
    wifiNetAgent.SetNetLinkDnsInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, SetNetLinkRouteInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    wifiIpV6Info.gateway = "TEST";
    wifiNetAgent.SetNetLinkRouteInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, SetNetLinkHostRouteInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    wifiNetAgent.SetNetLinkHostRouteInfo(netLinkInfo, wifiIpInfo);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, SetNetLinkLocalRouteInfoTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    wifiIpV6Info.netmask = "TEST";
    wifiNetAgent.SetNetLinkLocalRouteInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, InitWifiNetAgentTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    WifiNetAgentCallbacks wifiNetAgentCallbacks;
    wifiNetAgent.InitWifiNetAgent(wifiNetAgentCallbacks);
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}

HWTEST_F(WifiNetAgentTest, RequestNetworkTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    int uid = 0;
    int networkId = 0;
    EXPECT_EQ(wifiNetAgent.RequestNetwork(uid, networkId), false);
}

HWTEST_F(WifiNetAgentTest, RequestNetworkTest002, TestSize.Level1)
{
    WifiNetAgent::NetConnCallback netConnCallback;
    std::string ident = "";
    std::set<NetManagerStandard::NetCap> netCaps;
    NetManagerStandard::NetRequest netrequest;
    EXPECT_EQ(netConnCallback.RequestNetwork(ident, netCaps, netrequest), -1);

    ident = "1";
    EXPECT_EQ(netConnCallback.RequestNetwork(ident, netCaps, netrequest), -1);

    ident = "2";
    netrequest.requestId++;
    EXPECT_EQ(netConnCallback.RequestNetwork(ident, netCaps, netrequest), -1);

    ident = "wifi";
    netrequest.requestId++;
    EXPECT_EQ(netConnCallback.RequestNetwork(ident, netCaps, netrequest), -1);

    ident = "test123";
    netrequest.requestId++;
    EXPECT_EQ(netConnCallback.RequestNetwork(ident, netCaps, netrequest), -1);
}

HWTEST_F(WifiNetAgentTest, ReleaseNetworkTest001, TestSize.Level1)
{
    WifiNetAgent::NetConnCallback netConnCallback;
    std::string ident = "";
    std::set<NetManagerStandard::NetCap> netCaps;
    EXPECT_EQ(netConnCallback.ReleaseNetwork(ident, netCaps), 0);
}

HWTEST_F(WifiNetAgentTest, LogNetCapsTest001, TestSize.Level1)
{
    WifiNetAgent::NetConnCallback netConnCallback;
    std::string ident = "";
    std::set<NetManagerStandard::NetCap> netCaps;
    netConnCallback.LogNetCaps(ident, netCaps);
    EXPECT_NE(netConnCallback.requestIds_.size(), TEN);
}

HWTEST_F(WifiNetAgentTest, GetSupplierId001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    wifiNetAgent.ResetSupplierId();
    uint32_t tmpSupplierId = wifiNetAgent.GetSupplierId();
    EXPECT_EQ(tmpSupplierId, 0);
}

HWTEST_F(WifiNetAgentTest, RestoreWifiConnectionTest001, TestSize.Level1)
{
    WifiNetAgent wifiNetAgent;
    wifiNetAgent.RestoreWifiConnection();
    EXPECT_NE(wifiNetAgent.supplierId, TEN);
}
}
}