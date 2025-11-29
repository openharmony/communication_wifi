/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "wifi_local_security_detect_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Wifi {

HWTEST_F(WifiLocalSecurityDetectTest, DealStaConnChangedConnect, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiLocalSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_TRUE(wifiLocalSecurityDetect_ != nullptr);
}

HWTEST_F(WifiLocalSecurityDetectTest, DealStaConnChangedDisconnect, TestSize.Level1)
{
    OperateResState state = OperateResState::DISCONNECT_DISCONNECTED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiLocalSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_TRUE(wifiLocalSecurityDetect_ != nullptr);
}

}  // namespace Wifi
}  // namespace OHOS