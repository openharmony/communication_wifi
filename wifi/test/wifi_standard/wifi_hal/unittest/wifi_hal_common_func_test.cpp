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
#include "wifi_hal_common_func.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Eq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

constexpr int MAC_LEN = 17;
constexpr int LENTH = 6;
class WifiHalCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiHalCommonTest, ConvertMacToStrFail1, TestSize.Level1)
{
    unsigned char *mac = NULL;
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    EXPECT_EQ(ConvertMacToStr(mac, macSize, macStr, strLen), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToStrFail2, TestSize.Level1)
{
    char *macStr = NULL;
    int macSize = LENTH;
    unsigned char mac[LENTH] = "ABCDE";
    int strLen = MAC_LEN + 1;
    EXPECT_EQ(ConvertMacToStr(mac, macSize, macStr, strLen), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToStrFail3, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = 7;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    EXPECT_EQ(ConvertMacToStr(mac, macSize, macStr, strLen), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToStrFail4, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN;
    EXPECT_EQ(ConvertMacToStr(mac, macSize, macStr, strLen), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToStrSuccess, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    EXPECT_EQ(ConvertMacToStr(mac, macSize, macStr, strLen), 0);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail1, TestSize.Level1)
{
    unsigned char *mac = NULL;
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("00:00:00:00:00:00", mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail2, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    const char *macStr = NULL;
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray(macStr, mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail3, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = 7;
    EXPECT_EQ(ConvertMacToArray("AA:BB:CC:DD:EE:FF", mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail4, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA:BB:CC:DD:EE", mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail5, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA:!!:CC:DD:EE:FF", mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail6, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA,BB:CC:DD:EE:FF", mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArraySuccess, TestSize.Level1)
{
    unsigned char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA:BB:CC:DD:EE:FF", mac, macSize), 0);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidFail1, TestSize.Level1)
{
    char *macStr = NULL;
    EXPECT_EQ(CheckMacIsValid(macStr), -1);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidFail2, TestSize.Level1)
{
    EXPECT_EQ(CheckMacIsValid("00:00:00:00:00"), -1);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidFail3, TestSize.Level1)
{
    EXPECT_EQ(CheckMacIsValid("00:!!:00:00:00:00"), -1);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidFail4, TestSize.Level1)
{
    EXPECT_EQ(CheckMacIsValid("00,00:00:00:00:00"), -1);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidSuccess, TestSize.Level1)
{
    EXPECT_EQ(CheckMacIsValid("00:00:00:00:00:00"), 0);
}

HWTEST_F(WifiHalCommonTest, DataAnonymizeFail, TestSize.Level1)
{
    char output[MAC_LEN] = "AA,bb:CC:DD:EE:F";
    EXPECT_EQ(DataAnonymize(NULL, 5, output, 5), 1);
    EXPECT_EQ(DataAnonymize("ABCDEF", 5, NULL, 0), 1);
    EXPECT_EQ(DataAnonymize("ABCDEF", 6, output, 5), 1);
    EXPECT_EQ(DataAnonymize("AA", 2, output, 2), 0);
    EXPECT_EQ(DataAnonymize("AA,bb:CC", 8, output, 8), 0);
    EXPECT_EQ(DataAnonymize("AA,bb:CC:DD:EE:FF", 17, output, 17), 0);
}
} // namespace Wifi
} // namespace OHOS

