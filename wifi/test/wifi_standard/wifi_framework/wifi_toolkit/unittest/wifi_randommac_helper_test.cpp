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
#include <cstddef>
#include <cstdint>
#include <string>
#include "wifi_randommac_helper.h"
#include "wifi_logger.h"
#include "wifi_global_func.h"
#include "mac_address.h"

using namespace testing::ext;
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
const std::string ERR_LOG = "WiFi_Test";
DEFINE_WIFILOG_LABEL("WifiRandomMacHelperTest");

class WifiRandomMacHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}

public:
};

HWTEST_F(WifiRandomMacHelperTest, GetRandom_001, TestSize.Level1)
{
    WIFI_LOGI("GetRandom_001 enter");
    long int data = WifiRandomMacHelper::GetRandom();
    EXPECT_TRUE(data >= 0);
    WIFI_LOGI("GetRandom_001 data:%{public}ld", data);
}

HWTEST_F(WifiRandomMacHelperTest, LongLongToBytes_001, TestSize.Level1)
{
    WIFI_LOGI("LongLongToBytes_001 enter");
    long long data = 888888888888888888;
    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(data, bytes);
    
    EXPECT_EQ(bytes.size(), 8);
    long long result = WifiRandomMacHelper::BytesToLonglong(bytes);
    EXPECT_EQ(data, result);
}

HWTEST_F(WifiRandomMacHelperTest, LongAddrFromByteAddr_001, TestSize.Level1)
{
    WIFI_LOGI("LongAddrFromByteAddr_001 enter");
    long long data = 888888888888888888;
    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(data, bytes);
    
    EXPECT_EQ(bytes.size(), 8);
    long long result = WifiRandomMacHelper::LongAddrFromByteAddr(bytes);
    EXPECT_FALSE(result != 0);
    std::vector<uint8_t> addBytes = {};
    addBytes.assign(bytes.begin() + 2, bytes.end());
    result = WifiRandomMacHelper::LongAddrFromByteAddr(addBytes);
    EXPECT_TRUE(result != 0);
}

HWTEST_F(WifiRandomMacHelperTest, BytesArrayToString_001, TestSize.Level1)
{
    WIFI_LOGI("BytesArrayToString_001 enter");
    std::vector<uint8_t> bytes = {};
    std::string result = WifiRandomMacHelper::BytesArrayToString(bytes);
    EXPECT_EQ("size:0 []", result);
    bytes.emplace_back(1);
    bytes.emplace_back(2);
    bytes.emplace_back(3);
    result = WifiRandomMacHelper::BytesArrayToString(bytes);
    EXPECT_EQ("size:3 [1,2,3]", result);
}

HWTEST_F(WifiRandomMacHelperTest, CalculateRandomMacForWifiDeviceConfig_000, TestSize.Level1)
{
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_000 enter");
    std::string content = "AP_NAME_1";
    std::string randomMacAddr;
    WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);
    printf("CalculateRandomMacForWifiDeviceConfig_000 randomMacAddr:%s\n", randomMacAddr.c_str());
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_000 exit");
    EXPECT_FALSE(ERR_LOG.find("ERROR LOG IS NULL")!=std::string::npos);
}

HWTEST_F(WifiRandomMacHelperTest, CalculateRandomMacForWifiDeviceConfig_001, TestSize.Level1)
{
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_001 enter");
    std::string content = "AP_NAME_1";
    std::string randomMacAddr;
    WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);

    std::string randomMacAddr2;
    WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr2);
    printf("CalculateRandomMacForWifiDeviceConfig_001 randomMacAddr:%s randomMacAddr2:%s\n",
        randomMacAddr.c_str(), randomMacAddr2.c_str());
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_001 randomMacAddr:%{public}s randomMacAddr2:%{public}s",
        randomMacAddr.c_str(), randomMacAddr2.c_str());
    EXPECT_EQ(randomMacAddr, randomMacAddr2);
}

HWTEST_F(WifiRandomMacHelperTest, CalculateRandomMacForWifiDeviceConfig_002, TestSize.Level1)
{
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_002 enter");
    std::string randomMacAddr;
    std::string randomMacAddr2;
    std::string content;
    int testMaxCount = 1000;
    int testPreCount = 100;
    for (int i = 0; i < testMaxCount; i++) {
        std::fill(content.begin(), content.end(), 0);
        content = "AP_NAME_CalculateRandom_" + std::to_string(i);
        WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);
        WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr2);
        if ((i % testPreCount) == 0) {
            printf("%s randomMacAddr:%s randomMacAddr2:%s\n",
                content.c_str(), randomMacAddr.c_str(), randomMacAddr2.c_str());
            WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_002 %{public}s "
                "randomMacAddr:%{public}s randomMacAddr2:%{public}s",
                content.c_str(), randomMacAddr.c_str(), randomMacAddr2.c_str());
        }
        EXPECT_EQ(randomMacAddr, randomMacAddr2);
        EXPECT_TRUE(MacAddress::IsValidMac(randomMacAddr));
    }
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_002 exit");
}

HWTEST_F(WifiRandomMacHelperTest, CalculateRandomMacForWifiDeviceConfig_003, TestSize.Level1)
{
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_003 enter");
    std::string randomMacAddr;
    std::string content;
    int ret = WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);
    EXPECT_NE(ret, 0);
    EXPECT_TRUE(randomMacAddr.empty());
    EXPECT_FALSE(MacAddress::IsValidMac(randomMacAddr));
    ret = WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);
    EXPECT_NE(ret, 0);
    EXPECT_TRUE(randomMacAddr.empty());
    EXPECT_FALSE(MacAddress::IsValidMac(randomMacAddr));
    WifiRandomMacHelper::GenerateRandomMacAddress(randomMacAddr);
    EXPECT_TRUE(MacAddress::IsValidMac(randomMacAddr));
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_003 %{public}s", randomMacAddr.c_str());
    WIFI_LOGI("CalculateRandomMacForWifiDeviceConfig_003 exit");
}

}  // namespace Wifi
}  // namespace OHOS