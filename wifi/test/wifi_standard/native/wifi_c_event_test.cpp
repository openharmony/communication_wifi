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
#include "../../../interfaces/kits/c/wifi_event.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "../../../interfaces/kits/c/wifi_device.h"
#include "../../../interfaces/kits/c/wifi_scan_info.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiEventTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    virtual void SetUp() {};
    virtual void TearDown() {};
};

HWTEST_F(WifiEventTest, SetIsEventRegistratedTest, TestSize.Level1)
{
    WifiEvent *event = nullptr;
    EXPECT_EQ(RegisterWifiEvent(event), ERROR_WIFI_UNKNOWN);
}

HWTEST_F(WifiEventTest, UnRegisterWifiEventTest, TestSize.Level1)
{
    WifiEvent *event = nullptr;
    EXPECT_EQ(UnRegisterWifiEvent(event), WIFI_SUCCESS);
}
}  // namespace Wifi
}  // namespace OHOS
