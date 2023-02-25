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
#include "mac_address.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiCMacAddress : public testing::Test {
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

HWTEST_F(WifiCMacAddress, CreateTest1, TestSize.Level1)
{
    std::string mac = "CreateTest1234";
    MacAddress::Create(mac);
}
HWTEST_F(WifiCMacAddress, CreateTest2, TestSize.Level1)
{
    sockaddr hwAddr;
    for (int i = 0; i < 7; i++)
    {
        hwAddr.sa_data[i] = i;
    }
    MacAddress::Create(hwAddr);
}

}  // namespace Wifi
}  // namespace OHOS
