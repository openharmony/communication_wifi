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

#include "softap_manager.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("SoftApManager");

namespace OHOS {
namespace Wifi {
SoftApManager::SoftApManager(SoftApManager::Role role, int id) : mid(id), curRole(role), pSoftapManagerMachine(nullptr)
{}

SoftApManager::~SoftApManager()
{
    WIFI_LOGE("Exit.");
    if (pSoftapManagerMachine != nullptr) {
        delete pSoftapManagerMachine;
    }
}

ErrCode SoftApManager::InitSoftapManager()
{
    pSoftapManagerMachine = new (std::nothrow) SoftapManagerMachine();
    if (pSoftapManagerMachine == nullptr) {
        WIFI_LOGE("Alloc pSoftapManagerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pSoftapManagerMachine->InitSoftapManagerMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitSoftapManagerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    pSoftapManagerMachine->RegisterCallback(mcb);
    pSoftapManagerMachine->SendMessage(SOFTAP_CMD_START, static_cast<int>(curRole), mid);
    return WIFI_OPT_SUCCESS;
}

ErrCode SoftApManager::RegisterCallback(const SoftApModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

SoftapManagerMachine *SoftApManager::GetSoftapMachine()
{
    return pSoftapManagerMachine;
}

void SoftApManager::SetRole(Role role)
{
    curRole = role;
}

SoftApManager::Role SoftApManager::GetRole()
{
    return curRole;
}

} // namespace Wifi
} // namespace OHOS