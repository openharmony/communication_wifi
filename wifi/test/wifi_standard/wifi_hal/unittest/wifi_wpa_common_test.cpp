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
    virtual void SetUp() {}
    virtual void TearDown() {}
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
} // namespace Wifi
} // namespace OHOS

