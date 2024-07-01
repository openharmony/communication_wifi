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
    WIFI_LOGI("%{public}s enter", __func__);
    long int data = WifiRandomMacHelper::GetRandom();
    EXPECT_TRUE(data > 0);
    printf("%s data:%ld", __func__, data);
}

HWTEST_F(WifiRandomMacHelperTest, LongLongToBytes_001, TestSize.Level1)
{
    WIFI_LOGI("%{public}s enter", __func__);
    long long data = 888888888888888888;
    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(data, bytes);
    
    EXPECT_EQ(bytes.size(), 8);
    long long result = WifiRandomMacHelper::BytesToLonglong(bytes);
    EXPECT_EQ(data, result);
}

HWTEST_F(WifiRandomMacHelperTest, LongAddrFromByteAddr_001, TestSize.Level1)
{
    WIFI_LOGI("%{public}s enter", __func__);
    long long data = 888888888888888888;
    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(data, bytes);
    
    EXPECT_EQ(bytes.size(), 8);
    long long result = WifiRandomMacHelper::BytesToLonglong(bytes);
    EXPECT_EQ(data, result);
}

HWTEST_F(WifiRandomMacHelperTest, BytesArrayToString_001, TestSize.Level1)
{
    WIFI_LOGI("%{public}s enter", __func__);
    long long data = 888888888888888888;
    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(data, bytes);
    
    EXPECT_EQ(bytes.size(), 8);
    long long result = WifiRandomMacHelper::BytesToLonglong(bytes);
    EXPECT_EQ(data, result);
}


HWTEST_F(WifiRandomMacHelperTest, BytesArrayToString_002, TestSize.Level1)
{
    WIFI_LOGI("%{public}s enter", __func__);
    long long data = 888888888888888888;
    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(data, bytes);
    
    EXPECT_EQ(bytes.size(), 8);
    long long result = WifiRandomMacHelper::BytesToLonglong(bytes);
    EXPECT_EQ(data, result);
}

HWTEST_F(WifiRandomMacHelperTest, CalculateRandomMacForWifiDeviceConfig_001, TestSize.Level1)
{
    WIFI_LOGI("%{public}s enter", __func__);
    std::string content = "TP_LINK_1";
    std::string randomMacAddr;
    WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(content, randomMacAddr);
    EXPECT_TRUE(randomMacAddr.size() > 0);
}

}  // namespace Wifi
}  // namespace OHOS