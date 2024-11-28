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

#include "wifi_common_util.h"
#include "wifi_code_convert.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing::ext;using ::testing::_;
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

class WifiCodeConvertTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiCodeConvertTest, IsUtf8, TestSize.Level1)
{
    std::string gbkString {"\xC4\xE3\xBA\xC3\xA3\xAC\xC3\xF7\xCC\xEC"};
    std::string utf8String = WifiCodeConvertUtil::GbkToUtf8(gbkString);
    EXPECT_EQ(false, WifiCodeConvertUtil::IsUtf8(gbkString));
    EXPECT_EQ(false, WifiCodeConvertUtil::IsUtf8(utf8String));
}

HWTEST_F(WifiCodeConvertTest, IsUtf8PureInt, TestSize.Level1)
{
    std::string pureInt {"12345678aaa"};
    EXPECT_EQ(true, WifiCodeConvertUtil::IsUtf8(pureInt));
}

HWTEST_F(WifiCodeConvertTest, GbkToUtf8, TestSize.Level1)
{
    std::string gbkString {"\xC4\xE3\xBA\xC3\xA3\xAC\xC3\xF7\xCC\xEC"};
    std::string utf8String = WifiCodeConvertUtil::GbkToUtf8(gbkString);
    EXPECT_NE(utf8String, "112233");
}

HWTEST_F(WifiCodeConvertTest, Utf8ToGbk, TestSize.Level1)
{
    std::string utf8String {"你好，明天"};
    std::string gbkString = WifiCodeConvertUtil::Utf8ToGbk(utf8String);
    EXPECT_NE(utf8String, "112233");
}
}
}