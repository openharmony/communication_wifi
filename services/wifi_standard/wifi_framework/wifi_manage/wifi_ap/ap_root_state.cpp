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
#include "ap_root_state.h"
#include <typeinfo>
#include "ap_macro.h"
#include "ap_state_machine.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_ApRootState"
namespace OHOS {
namespace Wifi {
ApRootState::ApRootState() : State("ApRootState")
{}

ApRootState::~ApRootState()
{}

void ApRootState::Enter()
{
    LOGI("%{public}s  Enter", GetName().c_str());
}

void ApRootState::Exit()
{
    LOGI("%{public}s  Exit", GetName().c_str());
}

bool ApRootState::ProcessMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("fatal error!");
        return false;
    }
    int msgName = msg->GetMessageName();

    LOGI("msg = [%{public}dpublic}d] is not handled.", msgName);
    return HANDLED;
}
}  // namespace Wifi
}  // namespace OHOS