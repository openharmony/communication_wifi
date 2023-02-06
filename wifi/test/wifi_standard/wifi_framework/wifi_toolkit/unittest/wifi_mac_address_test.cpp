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
#include "../../../services/wifi_standard/wifi_framework/wifi_toolkit/net_helper/mac_address.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"

#define SIZE 15

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiCMacAddress : public testing::Test{
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    virtual void SetUp(){};
    virtual void TearDown(){};

    void CreateTest()
    {
        char mac[SIZE];
        if (strcpy_s(mac, sizeof(mac), "CreateTest1234") != EOK) {
            return;
        }
        MacAddress.Create(&mac);
    }
    void DumpTest()
    {
        MacAddress.Dump();
	}
    void IsValidTest()
    {
        MacAddress.IsValid();
    }
};

HWTEST_F(WifiCMacAddress, CreateTest, TestSize.Level1)
{
    CreateTest();
}
HWTEST_F(WifiCMacAddress, DumpTest, TestSize.Level1)
{
    DumpTest();
}
HWTEST_F(WifiCMacAddress, IsValidTest, TestSize.Level1)
{
    IsValidTest();
}
}  // namespace Wifi
}  // namespace OHOS
