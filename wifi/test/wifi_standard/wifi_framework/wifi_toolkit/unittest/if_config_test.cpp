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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "securec.h"
#include "if_config.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("IfconfigTest");

using namespace testing::ext;
namespace OHOS {
namespace Wifi {
class IfconfigTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};
/**
 * @tc.name: ExecCommand
 * @tc.desc: test with overSize
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, ExecCommand, TestSize.Level1)
{
    WIFI_LOGI("ExecCommand enter");
    std::vector<std::string> ipRouteCmd;
    ipRouteCmd.clear();
    for (int i = 0; i < 33; i++) {
        ipRouteCmd.push_back("addr");
    }
    EXPECT_FALSE(IfConfig::GetInstance().ExecCommand(ipRouteCmd));
}
/**
 * @tc.name: AddIpAddr_001
 * @tc.desc: test with error ifName
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, AddIpAddr_001, TestSize.Level1)
{
    WIFI_LOGI("AddIpAddr_001");
    std::string ifName = "";
    std::string ipAddr = "";
    std::string mask = "";
    int ipType = static_cast<int>(IpType::IPTYPE_IPV4);
    IfConfig::GetInstance().AddIpAddr(ifName, ipAddr, mask, ipType);
}
/**
 * @tc.name: AddIpAddr_002
 * @tc.desc: test with IpType IPTYPE_IPV6
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, AddIpAddr_002, TestSize.Level1)
{
    WIFI_LOGI("AddIpAddr_002");
    std::string ifName = "wlan0";
    std::string ipAddr = "";
    std::string mask = "";
    int ipType = static_cast<int>(IpType::IPTYPE_IPV6);
    IfConfig::GetInstance().AddIpAddr(ifName, ipAddr, mask, ipType);
}
/**
 * @tc.name: AddIpAddr_003
 * @tc.desc: test with IpType IPTYPE_IPV4
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, AddIpAddr_003, TestSize.Level1)
{
    WIFI_LOGI("AddIpAddr_003");
    std::string ifName = "wlan0";
    std::string ipAddr = "";
    std::string mask = "";
    int ipType = static_cast<int>(IpType::IPTYPE_IPV4);
    IfConfig::GetInstance().AddIpAddr(ifName, ipAddr, mask, ipType);
}
/**
 * @tc.name: SetProxy_001
 * @tc.desc: test with isAuto false
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, SetProxy_001, TestSize.Level1)
{
    WIFI_LOGI("SetProxy_001");
    bool isAuto = false;
    IfConfig::GetInstance().SetProxy(isAuto, "proxy", "8080", " ", "pac");
}
/**
 * @tc.name: SetProxy_002
 * @tc.desc: test with isAuto true but noProxys is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, SetProxy_002, TestSize.Level1)
{
    WIFI_LOGI("SetProxy_002");
    bool isAuto = true;
    IfConfig::GetInstance().SetProxy(isAuto, "proxy", "8080", "  ", "pac");
}
/**
 * @tc.name: SetProxy_003
 * @tc.desc: test with isAuto true but noProxys is empty
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, SetProxy_003, TestSize.Level1)
{
    WIFI_LOGI("SetProxy_003");
    bool isAuto = true;
    IfConfig::GetInstance().SetProxy(isAuto, "", "8080", "noProxys", "pac");
}
/**
 * @tc.name: FlushIpAddr_001
 * @tc.desc: test with ipType is IPTYPE_IPV6
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(IfconfigTest, FlushIpAddr_001, TestSize.Level1)
{
    WIFI_LOGI("FlushIpAddr_001");
    std::string ifName = "test";
    int ipType = static_cast<int>(IpType::IPTYPE_IPV6);
    IfConfig::GetInstance().FlushIpAddr(ifName, ipType);
}
}  // namespace Wifi
}  // namespace OHOS