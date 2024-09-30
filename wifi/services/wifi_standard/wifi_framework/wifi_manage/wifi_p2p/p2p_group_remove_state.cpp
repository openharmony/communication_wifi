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
#include "p2p_group_remove_state.h"
#include "p2p_state_machine.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_P2P_LABEL("P2pGroupRemoveState");

namespace OHOS {
namespace Wifi {
P2pGroupRemoveState::P2pGroupRemoveState()
    : State("P2pGroupRemoveState")
{}
void P2pGroupRemoveState::GoInState()
{
    WIFI_LOGI("             GoInState");
}

void P2pGroupRemoveState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
}

bool P2pGroupRemoveState::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("P2pGroupRemoveState");
    return EXECUTED;
}
} // namespace Wifi
} // namespace OHOS
