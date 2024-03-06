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

#include "wifi_logger.h"
#include "wifi_system_ability_listerner.h"
#ifndef OHOS_ARCH_LITE
#include "iservice_registry.h"
#include "system_ability_definition.h"
#endif // OHOS_ARCH_LITE

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiSystemAbilityListener");
WifiSystemAbilityListener::WifiSystemAbilityListener()
{
#ifndef OHOS_ARCH_LITE
    statusChangeListener = new (std::nothrow) SystemAbilityStatusChangeListener(this);
#endif // OHOS_ARCH_LITE
}

WifiSystemAbilityListener::~WifiSystemAbilityListener()
{
#ifndef OHOS_ARCH_LITE
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy != NULL && statusChangeListener != NULL) {
        for (auto id : allListenerIds) {
            int32_t ret = samgrProxy->UnSubscribeSystemAbility(id, statusChangeListener);
            WIFI_LOGI("UnSubscribeSystemAbility %{public}d result:%{public}d", id, ret);
        }
        allListenerIds.clear();
    }
#endif
}

void WifiSystemAbilityListener::SubscribeSystemAbility(int systemAbilityId)
{
#ifndef OHOS_ARCH_LITE
    std::unique_lock<std::mutex> lock(listenerMutex);
    std::unordered_set<int32_t>::iterator pos = allListenerIds.find(systemAbilityId);
    if (pos != allListenerIds.end()) {
        WIFI_LOGE("SubscribeSystemAbility %{public}d already onlistener.", systemAbilityId);
        return;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == NULL || statusChangeListener == NULL) {
        WIFI_LOGE("samgrProxy or statusChangeListener is NULL");
        return;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(systemAbilityId, statusChangeListener);
    WIFI_LOGI("SubscribeSystemAbility %{public}d result:%{public}d", systemAbilityId, ret);
    if (ret == 0) {
        allListenerIds.emplace(systemAbilityId);
    }
#endif
}

void WifiSystemAbilityListener::UnSubscribeSystemAbility(int systemAbilityId)
{
#ifndef OHOS_ARCH_LITE
    std::unique_lock<std::mutex> lock(listenerMutex);
    std::unordered_set<int32_t>::iterator pos = allListenerIds.find(systemAbilityId);
    if (pos == allListenerIds.end()) {
        WIFI_LOGE("SubscribeSystemAbility %{public}d not onlistener.", systemAbilityId);
        return;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy != NULL && statusChangeListener != NULL) {
        int32_t ret = samgrProxy->UnSubscribeSystemAbility(systemAbilityId, statusChangeListener);
        if (ret == 0) {
            allListenerIds.erase(pos);
        }
        WIFI_LOGI("UnSubscribeSystemAbility %{public}d result:%{public}d", systemAbilityId, ret);
    }
#endif
}

#ifndef OHOS_ARCH_LITE
void WifiSystemAbilityListener::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    if (!abilityListener) {
        WIFI_LOGE("OnAddSystemAbility() abilityListener is null.");
        return;
    }
    WIFI_LOGI("OnAddSystemAbility() systemAbilityId:%{public}d", systemAbilityId);
    abilityListener->OnSystemAbilityChanged(systemAbilityId, true);
}

void WifiSystemAbilityListener::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    if (!abilityListener) {
        WIFI_LOGE("OnRemoveSystemAbility() abilityListener is null.");
        return;
    }
    WIFI_LOGI("OnRemoveSystemAbility() systemAbilityId:%{public}d", systemAbilityId);
    abilityListener->OnSystemAbilityChanged(systemAbilityId, false);
}
#endif // OHOS_ARCH_LITE
} // namespace Wifi
} // namespace OHOS