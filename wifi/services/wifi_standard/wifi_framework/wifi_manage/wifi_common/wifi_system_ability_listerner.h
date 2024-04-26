/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_SYSTEM_ABILITY_LISTENER_H
#define OHOS_WIFI_SYSTEM_ABILITY_LISTENER_H

#ifndef OHOS_ARCH_LITE
#include <unordered_set>
#include "system_ability_status_change_stub.h"
#include <mutex>
#endif // OHOS_ARCH_LITE

namespace OHOS {
namespace Wifi {

class WifiSystemAbilityListener {
public:
    WifiSystemAbilityListener();
    virtual ~WifiSystemAbilityListener();
    void SubscribeSystemAbility(int systemAbilityId);
    void UnSubscribeSystemAbility(int systemAbilityId);
    virtual void OnSystemAbilityChanged(int systemAbilityId, bool add) = 0;

#ifndef OHOS_ARCH_LITE
private:
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        explicit SystemAbilityStatusChangeListener(WifiSystemAbilityListener *listener)
        {
            abilityListener = listener;
        }
        ~SystemAbilityStatusChangeListener()
        {
            abilityListener = nullptr;
        }
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

    private:
        WifiSystemAbilityListener* abilityListener;
    };
#endif // OHOS_ARCH_LITE

private:
#ifndef OHOS_ARCH_LITE
    sptr<ISystemAbilityStatusChange> statusChangeListener;
    std::unordered_set<int32_t> allListenerIds;
    std::mutex listenerMutex;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
