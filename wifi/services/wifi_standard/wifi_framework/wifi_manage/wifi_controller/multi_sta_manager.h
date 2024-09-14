/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTI_STA_MANAGER_H
#define OHOS_MULTI_STA_MANAGER_H

#include <functional>
#include <string>
#include "wifi_errcode.h"
#include "multi_sta_state_machine.h"

namespace OHOS {
namespace Wifi {
class MultiStaManager {
public:
    enum class Role {
        ROLE_UNKNOW = -1,
        ROLE_STA_WIFI_2 = 0,
        ROLE_STA_2_REMOVED = 1,
    };

    explicit MultiStaManager(MultiStaManager::Role role, int id);
    ErrCode RegisterCallback(const MultiStaModeCallback &callbacks);
    ~MultiStaManager();
    ErrCode InitMultiStaManager();
    void SetRole(Role role);
    Role GetRole();
    MultiStaStateMachine *GetMultiStaMachine();
    int mid;

private:
    MultiStaManager::Role curRole;
    MultiStaModeCallback mcb;
    MultiStaStateMachine *pMultiStaStateMachine;
};
} // namespace Wifi
} // namespace OHOS
#endif