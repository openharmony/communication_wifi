/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "concrete_clientmode_manager.h"
#include "wifi_errcode.h"

DEFINE_WIFILOG_LABEL("ConcreteClientModeManager");

namespace OHOS {
namespace Wifi {
ConcreteClientModeManager::ConcreteClientModeManager(ConcreteManagerRole role, int id) : mid(id), curRole(role)
{}

ConcreteClientModeManager::~ConcreteClientModeManager()
{
    WIFI_LOGE("exit");
    delete pConcreteMangerMachine;
}

ErrCode ConcreteClientModeManager::RegisterCallback(const ConcreteModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

void ConcreteClientModeManager::SetRole(ConcreteManagerRole role)
{
    pConcreteMangerMachine->SetTargetRole(role);
    curRole = role;
    if (role == ConcreteManagerRole::ROLE_CLIENT_MIX) {
        pConcreteMangerMachine->SendMessage(CONCRETE_CMD_SWITCH_TO_MIX_MODE);
    } else if (role == ConcreteManagerRole::ROLE_CLIENT_STA) {
        pConcreteMangerMachine->SendMessage(CONCRETE_CMD_SWITCH_TO_CONNECT_MODE);
    } else if (role == ConcreteManagerRole::ROLE_CLIENT_SCAN_ONLY) {
        pConcreteMangerMachine->SendMessage(CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE);
    } else {
        WIFI_LOGE("setrole is invalid");
    }
}

ErrCode ConcreteClientModeManager::InitConcreteManager()
{
    pConcreteMangerMachine = new (std::nothrow) ConcreteMangerMachine();
    if (pConcreteMangerMachine == nullptr) {
        WIFI_LOGE("Alloc pConcreteMangerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pConcreteMangerMachine->InitConcreteMangerMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitConcreteMangerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    pConcreteMangerMachine->RegisterCallback(mcb);
    pConcreteMangerMachine->SendMessage(CONCRETE_CMD_START, static_cast<int>(curRole), mid);
    return WIFI_OPT_SUCCESS;
}

ConcreteMangerMachine *ConcreteClientModeManager::GetConcreteMachine()
{
    return pConcreteMangerMachine;
}

} // namespace Wifi
} // namespace OHOS