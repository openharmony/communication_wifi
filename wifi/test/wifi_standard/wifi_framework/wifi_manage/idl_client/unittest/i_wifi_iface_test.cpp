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
#include "i_wifi_iface.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
constexpr int LENTH = 5;
class IWifiIfaceTest : public testing::Test {
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

HWTEST_F(IWifiIfaceTest, GetNameTest, TestSize.Level1)
{
    char ifname[LENTH] = "test";
    int32_t size = LENTH;
    GetName(ifname, size);
}

HWTEST_F(IWifiIfaceTest, GetTypeTest, TestSize.Level1)
{
    int32_t type = 1;
    GetType(&type);
}

}  // namespace Wifi
}  // namespace OHOS
