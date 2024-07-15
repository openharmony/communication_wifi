/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_config_center_test.h"
#include "wifi_global_func.h"
#include "wifi_internal_msg.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

HWTEST_F(WifiConfigCenterTest, SetGetWifiMidState_SUCCESS, TestSize.Level1)
{
    WifiOprMidState state = OHOS::Wifi::WifiOprMidState::RUNNING;
    WifiConfigCenter::GetInstance().SetWifiMidState(state);
    EXPECT_EQ(state, WifiConfigCenter::GetInstance().GetWifiMidState());
}

HWTEST_F(WifiConfigCenterTest, SetWifiMidStateExp_SUCCESS, TestSize.Level1)
{
    WifiOprMidState cloState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState runState = OHOS::Wifi::WifiOprMidState::RUNNING;
    WifiConfigCenter::GetInstance().SetWifiMidState(cloState);
    EXPECT_EQ(true, WifiConfigCenter::GetInstance().SetWifiMidState(cloState, runState));
}

HWTEST_F(WifiConfigCenterTest, SetWifiMidStateExp_FAILED, TestSize.Level1)
{
    WifiOprMidState cloState = OHOS::Wifi::WifiOprMidState::CLOSED;
    WifiOprMidState runState = OHOS::Wifi::WifiOprMidState::RUNNING;
    WifiConfigCenter::GetInstance().SetWifiMidState(cloState);
    EXPECT_NE(true, WifiConfigCenter::GetInstance().SetWifiMidState(runState, cloState));
}

HWTEST_F(WifiConfigCenterTest, GetWifiStaIntervalTest, TestSize.Level1)
{
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime();
    sleep(1);
    double interval = WifiConfigCenter::GetInstance().GetWifiStaInterval();
    EXPECT_TRUE(interval >= 1000 && interval <= 2000);
}

}  // namespace Wifi
}  // namespace OHOS