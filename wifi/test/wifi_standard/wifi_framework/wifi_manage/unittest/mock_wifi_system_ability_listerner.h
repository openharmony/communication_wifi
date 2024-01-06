/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MOCK_WIFI_SYSTEM_ABILITY_LISTENER_H
#define OHOS_MOCK_WIFI_SYSTEM_ABILITY_LISTENER_H

#include <gmock/gmock.h>
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
class WifiSystemAbilityListener {
public:
    WifiSystemAbilityListener();
    virtual ~WifiSystemAbilityListener();
    void SubscribeSystemAbility(int systemAbilityId);
    void UnSubscribeSystemAbility(int systemAbilityId);
    virtual void OnSystemAbilityChanged(int systemAbilityId, bool add);
};
} // namespace Wifi
} // namespace OHOS
#endif