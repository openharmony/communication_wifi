/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <ifaddrs.h>
#include <string>
#include "ipv4_address.h"
#include "ipv6_address.h"
#include "base_address.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("BaseAddressTest");
using namespace testing::ext;

namespace OHOS {
namespace Wifi {
class BaseAddressTest : public testing::Test {
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

class BaseAddressSubClass : public BaseAddress {
public:
    BaseAddressSubClass() : BaseAddress("192.168.1.8", 1, FamilyType::FAMILY_UNSPEC)
    {
        WIFI_LOGI("BaseAddressSubClass constructor");
    }

    bool IsValid() const override
    {
        WIFI_LOGI("virtual IsValid override");
        return true;
    }
};
/**
 * @tc.name: DumpTest
 * @tc.desc: test all case
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(BaseAddressTest, DumpTest, TestSize.Level1)
{
    WIFI_LOGI("DumpTest enter");
    Ipv4Address ip = Ipv4Address::Create("10.0.0.1", "255.255.255.0");
    ip.Dump();
    Ipv6Address ipv6 = Ipv6Address::Create("fe80::47b1:fa81:b33e:ea6b/64");
    ipv6.Dump();
    BaseAddressSubClass mBaseAddressSubClass;
    mBaseAddressSubClass.Dump();
}
}  // namespace Wifi
}  // namespace OHOS