/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software``
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "multi_sta_manager.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("MultiStaManager");

namespace OHOS {
namespace Wifi {
MultiStaManager::MultiStaManager(MultiStaManager::Role role, int id) : mid(id), curRole(role),
    pMultiStaStateMachine(nullptr)
{}

MultiStaManager::~MultiStaManager()
{
    WIFI_LOGE("Exit.");
    if (pMultiStaStateMachine != nullptr) {
        delete pMultiStaStateMachine;
        pMultiStaStateMachine = nullptr;
    }
}

ErrCode MultiStaManager::InitMultiStaManager()
{
    pMultiStaStateMachine = new (std::nothrow) MultiStaStateMachine();
    if (pMultiStaStateMachine == nullptr) {
        WIFI_LOGE("Alloc pMultiStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pMultiStaStateMachine->InitMultiStaStateMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitMultiStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    pMultiStaStateMachine->RegisterCallback(mcb);
    pMultiStaStateMachine->SendMessage(MULTI_STA_CMD_START, static_cast<int>(curRole), mid);
    return WIFI_OPT_SUCCESS;
}

ErrCode MultiStaManager::RegisterCallback(const MultiStaModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

MultiStaStateMachine *MultiStaManager::GetMachine()
{
    return pMultiStaStateMachine;
}

void MultiStaManager::SetRole(Role role)
{
    curRole = role;
}

MultiStaManager::Role MultiStaManager::GetRole()
{
    return curRole;
}

} // namespace Wifi
} // namespace OHOS