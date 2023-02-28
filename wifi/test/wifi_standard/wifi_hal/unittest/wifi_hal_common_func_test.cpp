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
#include "wifi_hal_common_func.cpp"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Eq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

constexpr int MAC_LEN = 15;
constexpr int LENTH = 6;
class WifiHalCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiHalCommonTest, StrSafeCopyFail, TestSize.Level1)
{
    char *dst = NULL;
    unsigned len = LENTH;
    StrSafeCopy(dst, len, "00:00:00:00:00");
}

HWTEST_F(WifiHalCommonTest, StrSafeCopyFail, TestSize.Level1)
{
    char *src = NULL;
    unsigned len = LENTH;
    StrSafeCopy("00:00:00:00:00", len, src);
}

HWTEST_F(WifiHalCommonTest, StrSafeCopyFail, TestSize.Level1)
{
    const unsigned char *mac = NULL;
    int macSize = LENTH;
    char macStr[MAC_LEN] = {0};
    int strLen = MAC_LEN;
    ConvertMacToStr(mac, macSize, macStr, strLen);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToStrFail, TestSize.Level1)
{
    unsigned char *mac = NULL;
    int macSize = LENTH;
    char macStr[MAC_LEN] = {0};
    int strLen = MAC_LEN;
    ConvertMacToStr(mac, macSize, "00:00:00:00:00", strLen);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToStrSuccess, TestSize.Level1)
{
    int macSize = LENTH;
    char macStr[MAC_LEN] = {0};
    int strLen = MAC_LEN;
    ConvertMacToStr("ABCDE", macSize, "00:00:00:00:00", strLen);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail, TestSize.Level1)
{
    unsigned char *mac = NULL;
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("00:00:00:00:00:00", mac, macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail1, TestSize.Level1)
{
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA:!!:CC:DD:EE:FF", "ABCDEF", macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArrayFail2, TestSize.Level1)
{
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA,BB:CC:DD:EE:FF", "ABCDEF", macSize), -1);
}

HWTEST_F(WifiHalCommonTest, ConvertMacToArraySuccess, TestSize.Level1)
{
    int macSize = LENTH;
    EXPECT_EQ(ConvertMacToArray("AA,bb:CC:DD:EE:FF", "ABCDEF", macSize), 0);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidFail, TestSize.Level1)
{
    char *macStr = NULL;
    EXPECT_EQ(CheckMacIsValid(macStr), -1);
}

HWTEST_F(WifiHalCommonTest, CheckMacIsValidFail, TestSize.Level1)
{
    EXPECT_EQ(CheckMacIsValid("AA:!!:CC:DD:EE:FF"), -1);
}

HWTEST_F(WifiHalCommonTest, GetIfaceStateFail, TestSize.Level1)
{
    GetIfaceState("AA:CC:DD:EE:FF");
}

HWTEST_F(WifiHalCommonTest, GetIfaceStateFail, TestSize.Level1)
{
    char *data = NULL;
    EXPECT_EQ(CharReplace(data, 0, 5, 'A'), 1);
}

HWTEST_F(WifiHalCommonTest, DataAnonymizeFail, TestSize.Level1)
{
    EXPECT_EQ(DataAnonymize(NULL, 5, "AA,bb:CC:DD:EE:FF", 5), 1);
    EXPECT_EQ(DataAnonymize("ABCDEF", 5, NULL, 0), 1);
    EXPECT_EQ(DataAnonymize("ABCDEF", 6, "AA,bb", 5), 1);
    EXPECT_EQ(DataAnonymize("AA", 2, "  ", 2), 0);
    EXPECT_EQ(DataAnonymize("AA,bb:CC", 8, "  ", 8), 0);
    EXPECT_EQ(DataAnonymize("AA,bb:CC:DD:EE:FF", 17, "  ", 17), 0);
}
} // namespace Wifi
} // namespace OHOS

