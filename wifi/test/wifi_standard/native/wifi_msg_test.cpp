/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "wifi_msg.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int INVALID_VALUE = -1;
constexpr int FOUR = 4;
constexpr int FIVE = 5;
constexpr int NINE = 9;
class WifiMsgTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiMsgTest, Phase2MethodToStrTest, TestSize.Level1)
{
    std::string eap = "TTLS";
    int method = INVALID_VALUE;
    EXPECT_TRUE(WifiEapConfig::Phase2MethodToStr(eap, method) == "auth=NONE");
    method = NINE;
    EXPECT_TRUE(WifiEapConfig::Phase2MethodToStr(eap, method) == "auth=NONE");
    method = FOUR;
    EXPECT_TRUE(WifiEapConfig::Phase2MethodToStr(eap, method) == "autheap=GTC");
    method = FIVE;
    EXPECT_TRUE(WifiEapConfig::Phase2MethodToStr(eap, method) == "auth=SIM");
}

HWTEST_F(WifiMsgTest, Phase2MethodFromStrTest, TestSize.Level1)
{
    std::string str = "NONE";
    EXPECT_TRUE(WifiEapConfig::Phase2MethodFromStr(str) == Phase2Method::NONE);
    str = "auth=PAP";
    EXPECT_TRUE(WifiEapConfig::Phase2MethodFromStr(str) == Phase2Method::PAP);
    str = "auth=NONE";
    EXPECT_TRUE(WifiEapConfig::Phase2MethodFromStr(str) == Phase2Method::NONE);
    str = "autheap=PAP";
    EXPECT_TRUE(WifiEapConfig::Phase2MethodFromStr(str) == Phase2Method::PAP);
}
} // namespace Wifi
} // namespace OHOS
