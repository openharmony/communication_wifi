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

#include "wifi_hal_wpa_common_test.h"
#include "securec.h"
#include "wifi_log.h"
#include "wifi_common_hal.h"
#include "mock_wpa_ctrl.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalWpaCommonTest"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
void WifiHalWpaCommonTest::SetUpTestCase()
{
}

void WifiHalWpaCommonTest::TearDownTestCase()
{
}

HWTEST_F(WifiHalWpaCommonTest, SendComCmdTest, TestSize.Level1)
{
    LOGE("enter SendComCmdTest");
    const char* cmd = nullptr;
    EXPECT_EQ(-1, SendComCmd(cmd));

    const char* cmd1 = "nullptr";
    EXPECT_EQ(-1, SendComCmd(cmd1));
}

HWTEST_F(WifiHalWpaCommonTest, HalCallbackNotifyTest, TestSize.Level1)
{
    LOGE("enter HalCallbackNotifyTest");
    const char* event = nullptr;
    EXPECT_EQ(-1, HalCallbackNotify(event));

    const char* event1 = "nullptr";
    EXPECT_EQ(0, HalCallbackNotify(event1));
}
}  // namespace Wifi
}  // namespace OHOS