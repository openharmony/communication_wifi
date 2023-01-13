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
#include "client.h"
#include "i_wifi.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
class IWifiTest : public testing::Test {
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

HWTEST_F(IWifiTest, GetWifiChipTest, TestSize.Level1)
{
    uint8_t id = 1;
    IWifiChip chip;
    GetWifiChip(id, &chip);
}

HWTEST_F(IWifiTest, GetWifiChipIdsTest, TestSize.Level1)
{
    uint8_t ids = 1;
    int32_t size = 1;
    GetWifiChipIds(&ids, &size);
}

HWTEST_F(IWifiTest, StopTest, TestSize.Level1)
{
    Stop();
}

HWTEST_F(IWifiTest, NotifyClearTest, TestSize.Level1)
{
    NotifyClear();
}

HWTEST_F(IWifiTest, OnTransactTest, TestSize.Level1)
{
    Context context;
    char test[] = "12";
    context.szRead = test;
    OnTransact(&context);
}
}  // namespace Wifi
}  // namespace OHOS
