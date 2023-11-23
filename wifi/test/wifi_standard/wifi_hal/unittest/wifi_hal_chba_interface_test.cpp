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

#include "wifi_hal_chba_interface_test.h"
#include "securec.h"
#include "wifi_log.h"
#include "wifi_hal_chba_interface.h"
#include "mock_wpa_ctrl.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalChbaInterfaceTest"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
void WifiHalChbaInterfaceTest::SetUpTestCase()
{
    MockInitGlobalCmd();
}

HWTEST_F(WifiHalChbaInterfaceTest, ChbaStartTest, TestSize.Level1)
{
    LOGE("enter ChbaStartTest");
    EXPECT_TRUE(ChbaStart() == WIFI_HAL_SUCCESS);
}

HWTEST_F(WifiHalChbaInterfaceTest, ChbaStopTest, TestSize.Level1)
{
    LOGE("enter ChbaStopTest");
    EXPECT_TRUE(ChbaStop() == WIFI_HAL_SUCCESS);
}
}  // namespace Wifi
}  // namespace OHOS