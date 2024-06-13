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

#ifndef OHOS_SOFT_AP_MANAGER_H
#define OHOS_SOFT_AP_MANAGER_H

#include <functional>
#include "wifi_errcode.h"
#include <string>
#include "softap_manager_state_machine.h"

namespace OHOS {
namespace Wifi {
class SoftApManager {
public:
    enum class Role {
        ROLE_UNKNOW = -1,
        ROLE_SOFTAP = 0,
        ROLE_HAS_REMOVED = 1,
    };

    ErrCode RegisterCallback(const SoftApModeCallback &callbacks);
    explicit SoftApManager(SoftApManager::Role role, int id);
    ~SoftApManager();
    ErrCode InitSoftapManager();
    void SetRole(Role role);
    Role GetRole();
    SoftapManagerMachine *GetSoftapMachine();
    int mid;

private:
    SoftApManager::Role curRole;
    SoftApModeCallback mcb;
    SoftapManagerMachine *pSoftapManagerMachine;
};
} // namespace Wifi
} // namespace OHOS
#endif