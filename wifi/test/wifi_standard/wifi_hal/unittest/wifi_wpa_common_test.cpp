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
#include "wifi_wpa_common.h"
#include "wifi_wpa_common_test.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Eq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiWpaCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        g_wpaInterface = &wpaInterface;
    }
    virtual void TearDown() {}
    WifiWpaInterface wpaInterface;
};

HWTEST_F(WifiWpaCommonTest, Hex2DecTest, TestSize.Level1)
{
    char str[] = "0z1259";
    char src[] = "0a1259";
    char srf[] = "0xaAfF29";
    char stc[] = "A1s62";
    TrimQuotationMark(nullptr, 'A');
    TrimQuotationMark(stc, 'A');
    EXPECT_EQ(Hex2Dec(nullptr), 0);
    EXPECT_EQ(Hex2Dec(str), 0);
    EXPECT_EQ(Hex2Dec(src), 0);
    EXPECT_TRUE(Hex2Dec(srf));
}

HWTEST_F(WifiWpaCommonTest, InitWpaCtrlTest, TestSize.Level1)
{
    WpaCtrl *pCtrl = nullptr;
    char str[] = "A1s62";
    EXPECT_TRUE(InitWpaCtrl(pCtrl, str) == -1);
}

HWTEST_F(WifiWpaCommonTest, ReleaseWpaCtrlTest, TestSize.Level1)
{
    WpaCtrl pCtrl;
    char str[] = "A1s62";
    InitWpaCtrl(&pCtrl, str);
    ReleaseWpaCtrl(&pCtrl);
    EXPECT_NE(str, "A1s62");
}

HWTEST_F(WifiWpaCommonTest, WpaCliCmdTest_01, TestSize.Level1)
{
    const size_t bufLen = 10;
    const char cmd[bufLen] = "string";
    char buf[bufLen] = "string";
    int result = WpaCliCmd(cmd, buf, bufLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiWpaCommonTest, WpaCliCmdTest_02, TestSize.Level1)
{
    const size_t bufLen = 10;
    int ten = 10;
    const char cmd[bufLen] = "ENABLE";
    char buf[bufLen] = "string";
    int result = WpaCliCmd(cmd, buf, bufLen);
    EXPECT_NE(result, ten);
}

HWTEST_F(WifiWpaCommonTest, GetStrKeyValTest_01, TestSize.Level1)
{
    const int len = 10;
    char src[len];
    const char split[len] = "string";
    WpaKeyValue out;
    GetStrKeyVal(src, split, &out);
    EXPECT_NE(split, "string");
}

HWTEST_F(WifiWpaCommonTest, GetStrKeyValTest_02, TestSize.Level1)
{
    const int len = 10;
    char src[len] = "string";
    const char split[len] = "in";
    WpaKeyValue out;
    GetStrKeyVal(src, split, &out);
    EXPECT_NE(src, "string");
}

HWTEST_F(WifiWpaCommonTest, Hex2DecTest_01, TestSize.Level1)
{
    const char *str = "0x123456";
    int result = Hex2Dec(str);
    EXPECT_NE(result, 0);
}

HWTEST_F(WifiWpaCommonTest, TrimQuotationMarkTest, TestSize.Level1)
{
    const int len = 10;
    char str[len] = "string";
    char c = 'A';
    TrimQuotationMark(str, c);
    EXPECT_NE(str, "string");
}

HWTEST_F(WifiWpaCommonTest, Hex2numTest_01, TestSize.Level1)
{
    char c = '1';
    const char hex = '1';
    int result = Hex2num(c);
    EXPECT_NE(result, -1);

    result = Hex2byte(&hex);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiWpaCommonTest, Hex2numTest_02, TestSize.Level1)
{
    char c = 'a';
    const char hex = 'a';
    int result = Hex2num(c);
    EXPECT_NE(result, -1);

    result = Hex2byte(&hex);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiWpaCommonTest, Hex2numTest_03, TestSize.Level1)
{
    char c = 'A';
    const char hex = 'A';
    int result = Hex2num(c);
    EXPECT_NE(result, -1);

    result = Hex2byte(&hex);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiWpaCommonTest, Hex2numTest_04, TestSize.Level1)
{
    char c = '*';
    const char hex = '*';
    int result = Hex2num(c);
    EXPECT_EQ(result, -1);

    result = Hex2byte(&hex);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiWpaCommonTest, DealSymbolTest_01, TestSize.Level1)
{
    const int len = 10;
    u8 buf[len];
    const char *pos = "!";
    size_t size = 1;
    DealSymbol(buf, &pos, &size);
    EXPECT_NE(pos, "x");
}

HWTEST_F(WifiWpaCommonTest, DealSymbolTest_02, TestSize.Level1)
{
    const int len = 10;
    u8 buf[len];
    const char *pos = "x";
    size_t size = 1;
    DealSymbol(buf, &pos, &size);
    EXPECT_NE(pos, "x");
}

HWTEST_F(WifiWpaCommonTest, DealSymbolTest_03, TestSize.Level1)
{
    const int len = 10;
    u8 buf[len];
    const char *pos = "e";
    size_t size = 1;
    DealSymbol(buf, &pos, &size);
    EXPECT_NE(size, 1);
}

} // namespace Wifi
} // namespace OHOS

