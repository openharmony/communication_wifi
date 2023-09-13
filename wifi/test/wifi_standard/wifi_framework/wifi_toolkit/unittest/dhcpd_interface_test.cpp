/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "dhcpd_interface.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("DhcpdInterfaceTest");

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class DhcpdInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pDhcpdInterface = std::make_unique<DhcpdInterface>();
    }
    virtual void TearDown()
    {
        pDhcpdInterface.reset();
    }

    void StartDhcpServerTest()
    {
        bool isIpV4 = false;
        std::string ifaceName = "wlan0";
        Ipv4Address ipv4(Ipv4Address::INVALID_INET_ADDRESS);
        Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
        pDhcpdInterface->StartDhcpServer(ifaceName, ipv4, ipv6, "", isIpV4);
    }
public:
    std::unique_ptr<DhcpdInterface> pDhcpdInterface;
};

class DhcpNotifyMock : public IDhcpResultNotify {
public:
    explicit DhcpNotifyMock()
    {
        WIFI_LOGI("DhcpNotifyMock constructor...");
    }

    ~DhcpNotifyMock() override
    {
        WIFI_LOGI("DhcpNotifyMock destructor...");
    }

    void OnSuccess(int status, const std::string &ifname, DhcpResult &result) override
    {
        WIFI_LOGI("OnSuccess mock enter...");
    }

    void OnFailed(int status, const std::string &ifname, const std::string &reason) override
    {
        WIFI_LOGI("OnFailed mock enter...");
    }

    void OnSerExitNotify(const std::string& ifname) override
    {
        WIFI_LOGI("OnSerExitNotify mock enter...");
    }
};
/**
 * @tc.name: StartDhcpServer_001
 * @tc.desc: StartDhcpServer
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, StartDhcpServer_001, TestSize.Level1)
{
    WIFI_LOGI("StartDhcpServer_001 enter");
    StartDhcpServerTest();
}
/**
 * @tc.name: StartDhcpServer_002
 * @tc.desc: StartDhcpServer with name hava p2p
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, StartDhcpServer_002, TestSize.Level1)
{
    WIFI_LOGI("StartDhcpServer_002 enter");
    std::string ifaceName = "p2p";
    bool isIpV4 = false;
    Ipv4Address ipv4(Ipv4Address::INVALID_INET_ADDRESS);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    pDhcpdInterface->StartDhcpServer(ifaceName, ipv4, ipv6, "", isIpV4);
}
/**
 * @tc.name: StartDhcpServer_003
 * @tc.desc: StartDhcpServer with ipAddress fail
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, StartDhcpServer_003, TestSize.Level1)
{
    WIFI_LOGI("StartDhcpServer_003 enter");
    bool isIpV4 = true;
    std::string ifaceName = "wlan0";
    Ipv4Address ipv4(Ipv4Address::INVALID_INET_ADDRESS);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    std::string ipAddress = "10";
    pDhcpdInterface->StartDhcpServer(ifaceName, ipv4, ipv6, ipAddress, isIpV4);
}
/**
 * @tc.name: StartDhcpServer_004
 * @tc.desc: StartDhcpServer with ipAddress succeed
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, StartDhcpServer_004, TestSize.Level1)
{
    WIFI_LOGI("StartDhcpServer_004 enter");
    bool isIpV4 = true;
    std::string ifaceName = "wlan0";
    Ipv4Address ipv4(Ipv4Address::INVALID_INET_ADDRESS);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    std::string ipAddress = "192.168.62.0";
    pDhcpdInterface->StartDhcpServer(ifaceName, ipv4, ipv6, ipAddress, isIpV4);
}
/**
 * @tc.name: StartDhcpServer_005
 * @tc.desc: StartDhcpServer wifh ipAddress fail
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, StartDhcpServer_005, TestSize.Level1)
{
    WIFI_LOGI("StartDhcpServer_005 enter");
    bool isIpV4 = true;
    std::string ifaceName = "p2p";
    Ipv4Address ipv4(Ipv4Address::INVALID_INET_ADDRESS);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    pDhcpdInterface->StartDhcpServer(ifaceName, ipv4, ipv6, "", isIpV4);
}
/**
 * @tc.name: SetDhcpEventFunc_001
 * @tc.desc: SetDhcpEventFunc with  pResultNotify == nullptr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, SetDhcpEventFunc_001, TestSize.Level1)
{
    WIFI_LOGI("SetDhcpEventFunc_001 enter");
    std::string ifaceName = "wlan0";
    IDhcpResultNotify *pResultNotify = nullptr;
    EXPECT_FALSE(pDhcpdInterface->SetDhcpEventFunc(ifaceName, pResultNotify));
}
/**
 * @tc.name: SetDhcpEventFunc_002
 * @tc.desc: SetDhcpEventFunc with ifaceName is null
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, SetDhcpEventFunc_002, TestSize.Level1)
{
    WIFI_LOGI("SetDhcpEventFunc_002 enter");
    std::string ifaceName = "";
    std::unique_ptr<DhcpNotifyMock> pResultNotify =  std::make_unique<DhcpNotifyMock>();
    EXPECT_FALSE(pDhcpdInterface->SetDhcpEventFunc(ifaceName, pResultNotify.get()));
    pResultNotify.reset();
}
/**
 * @tc.name: SetDhcpEventFunc_003
 * @tc.desc: SetDhcpEventFunc with mDhcpService == nullptr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, SetDhcpEventFunc_003, TestSize.Level1)
{
    WIFI_LOGI("SetDhcpEventFunc_003 enter");
    std::string ifaceName = "wlan0";
    std::unique_ptr<DhcpNotifyMock> pResultNotify =  std::make_unique<DhcpNotifyMock>();
    EXPECT_FALSE(pDhcpdInterface->SetDhcpEventFunc(ifaceName, pResultNotify.get()));
    pResultNotify.reset();
}
/**
 * @tc.name: SetDhcpEventFunc_004
 * @tc.desc: SetDhcpEventFunc
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, SetDhcpEventFunc_004, TestSize.Level1)
{
    WIFI_LOGI("SetDhcpEventFunc_004 enter");
    std::string ifaceName = "wlan0";
    std::unique_ptr<DhcpNotifyMock> pResultNotify =  std::make_unique<DhcpNotifyMock>();
    StartDhcpServerTest();
    pDhcpdInterface->SetDhcpEventFunc(ifaceName, pResultNotify.get());
    pResultNotify.reset();
}
/**
 * @tc.name: GetConnectedStationInfo_001
 * @tc.desc: GetConnectedStationInfo with mDhcpService == nullptr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, GetConnectedStationInfo_001, TestSize.Level1)
{
    WIFI_LOGI("GetConnectedStationInfo_001 enter");
    std::string ifaceName = "wlan0";
    std::map<std::string, StationInfo> result;
    EXPECT_FALSE(pDhcpdInterface->GetConnectedStationInfo(ifaceName, result));
}
/**
 * @tc.name: GetConnectedStationInfo_002
 * @tc.desc: GetConnectedStationInfo with ifaceName == nullptr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, GetConnectedStationInfo_002, TestSize.Level1)
{
    WIFI_LOGI("GetConnectedStationInfo_002 enter");
    std::string ifaceName;
    std::map<std::string, StationInfo> result;
    StartDhcpServerTest();
    EXPECT_FALSE(pDhcpdInterface->GetConnectedStationInfo(ifaceName, result));
}
/**
 * @tc.name: GetConnectedStationInfo_003
 * @tc.desc: GetConnectedStationInfo
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, GetConnectedStationInfo_003, TestSize.Level1)
{
    WIFI_LOGI("GetConnectedStationInfo_003 enter");
    std::string ifaceName = "wlan0";
    std::map<std::string, StationInfo> result;
    StartDhcpServerTest();
    EXPECT_FALSE(pDhcpdInterface->GetConnectedStationInfo(ifaceName, result));
}
/**
 * @tc.name: StopDhcpServer_001
 * @tc.desc: StopDhcpServer
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpdInterfaceTest, StopDhcpServer_001, TestSize.Level1)
{
    WIFI_LOGI("StopDhcpServer_001 enter");
    std::string ifaceName;
    EXPECT_FALSE(pDhcpdInterface->StopDhcpServer(ifaceName));
    ifaceName = "wlan0";
    EXPECT_FALSE(pDhcpdInterface->StopDhcpServer(ifaceName));
    StartDhcpServerTest();
    EXPECT_TRUE(pDhcpdInterface->StopDhcpServer(ifaceName));
}
}  // namespace Wifi
}  // namespace OHOS
