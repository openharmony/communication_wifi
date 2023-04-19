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
#include "mac_address.h"
#include <gtest/gtest.h>
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("MacAddressTest");
using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {
class MacAddressTest : public testing::Test {
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
 * @tc.name: Create_001
 * @tc.desc: Create mac by sockaddr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(MacAddressTest, Create_001, TestSize.Level1)
{
    WIFI_LOGI("Create_001");
    sockaddr hwAddr;
    for (int i = 0; i < (FIVE + 1); i++) {
        hwAddr.sa_data[i] = 0;
    }
    EXPECT_TRUE(MacAddress::Create(hwAddr) == MacAddress::INVALID_MAC_ADDRESS);
}
/**
 * @tc.name: Create_002
 * @tc.desc: Create mac by string
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(MacAddressTest, Create_002, TestSize.Level1)
{
    WIFI_LOGI("Create_002");
    std::string mac = "aa:bb:cc:dd:ee:ff";
    MacAddress::Create(mac);
}
/**
 * @tc.name: IsValidMac_001
 * @tc.desc: error mac
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(MacAddressTest, IsValidMac_001, TestSize.Level1)
{
    WIFI_LOGI("IsValidMac_001");
    std::string mac = "AA:BB:CC:DD:";
    EXPECT_FALSE(MacAddress::IsValidMac(mac));
    mac = "AA:BB:CC:DD:EEFFF";
    EXPECT_FALSE(MacAddress::IsValidMac(mac));
    mac = "AA:BB:CC:DD:EE://";
    EXPECT_FALSE(MacAddress::IsValidMac(mac));
    mac = "AA:BB:CC:DD:EE:::";
    EXPECT_FALSE(MacAddress::IsValidMac(mac));
    mac = "AA:BB:CC:DD:EE:~~";
    EXPECT_FALSE(MacAddress::IsValidMac(mac));
}
/**
 * @tc.name: IsValidMac_002
 * @tc.desc: right mac
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(MacAddressTest, IsValidMac_002, TestSize.Level1)
{
    WIFI_LOGI("IsValidMac_002");
    std::string mac = "AA:BB:CC:DD:EE:FF";
    EXPECT_TRUE(MacAddress::IsValidMac(mac));
}
/**
 * @tc.name: GetMacAddr_001
 * @tc.desc: GetMacAddr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(MacAddressTest, GetMacAddr_001, TestSize.Level1)
{
    WIFI_LOGI("GetMacAddr_001");
    std::string ifName = "AA:BB:CC:DD:EE:FF";
    unsigned char macAddr[MAC_LEN] = {0};
    EXPECT_FALSE(MacAddress::GetMacAddr(ifName, macAddr));
}
}  // namespace Wifi
}  // namespace OHOS
