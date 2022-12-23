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
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "../../../frameworks/native/c_adapter/inc/wifi_c_utils.h"

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
class WifiCUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    void IpStrToArraySuccess()
    {
        unsigned int ipAddr[IPV4_ARRAY_LEN] = {0};
        std::string str = "192.168.1.23";
        EXPECT_TRUE(IpStrToArray(str, ipAddr) == WIFI_SUCCESS);
    }

    void IpStrToArrayFail()
    {
        unsigned int ipAddr[IPV4_ARRAY_LEN] = {0};
        std::string str = "192.168.1";
        EXPECT_TRUE(IpStrToArray(str, ipAddr) == ERROR_WIFI_INVALID_ARGS);
    }
    
    void IpArrayToStrSuccess()
    {
        unsigned int ipAddr[IPV4_ARRAY_LEN] = {192, 168, 1, 23};
        EXPECT_EQ(IpArrayToStr(ipAddr), "192.168.1.23");
    }
};

HWTEST_F(WifiCUtilsTest, IpStrToArraySuccess, TestSize.Level1)
{
    IpStrToArraySuccess();
}

HWTEST_F(WifiCUtilsTest, IpStrToArrayFail, TestSize.Level1)
{
    IpStrToArrayFail();
}

HWTEST_F(WifiCUtilsTest, IpArrayToStrSuccess, TestSize.Level1)
{
    IpArrayToStrSuccess();
}
} // namespace Wifi
} // namespace OHOS