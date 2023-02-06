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

HWTEST_F(BaseAddressTest, DumpTest, TestSize.Level1)
{
    Ipv4Address ip = Ipv4Address::Create("10.0.0.1", "255.255.255.0");
    ip.Dump();
    Ipv6Address ipv6 = Ipv6Address::Create("fe80::47b1:fa81:b33e:ea6b/64");
    ipv6.Dump();
}
}  // namespace Wifi
}  // namespace OHOS