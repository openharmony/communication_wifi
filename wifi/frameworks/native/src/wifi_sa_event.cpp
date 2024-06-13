/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "kits/c/wifi_device.h"
#include "wifi_scan.h"
#include "wifi_p2p.h"
#include "wifi_device.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_sa_event.h"

DEFINE_WIFILOG_LABEL("WifiAbilityStatusChange");

namespace OHOS {
namespace Wifi {
void WifiAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    WIFI_LOGI("WifiAbilityStatusChange OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    switch (systemAbilityId) {
        case WIFI_DEVICE_ABILITY_ID: {
            EventManager::GetInstance().RegisterDeviceEvent(WifiCDeviceEventCallback::deviceCallbackEvent);
            break;
        }
        case WIFI_SCAN_ABILITY_ID: {
            EventManager::GetInstance().RegisterScanEvent(WifiCScanEventCallback::scanCallbackEvent);
            break;
        }
        case WIFI_HOTSPOT_ABILITY_ID: {
            EventManager::GetInstance().RegisterHotspotEvent(WifiCHotspotEventCallback::hotspotCallbackEvent);
            break;
        }
        case WIFI_P2P_ABILITY_ID: {
            std::vector<std::string> event;
            for (auto &eventName : EventManager::GetInstance().GetP2PCallbackEvent()) {
                event.emplace_back(eventName);
            }
            EventManager::GetInstance().RegisterP2PEvent(event);
            break;
        }
        default:
            WIFI_LOGI("WifiAbilityStatusChange OnAddSystemAbility unhandled sysabilityId:%{public}d", systemAbilityId);
            return;
    }
}

void WifiAbilityStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    WIFI_LOGI("OnRemoveSystemAbility: systemAbilityId:%{public}d!", systemAbilityId);
    return;
}

void WifiAbilityStatusChange::Init(int32_t systemAbilityId)
{
    WIFI_LOGI("Init: samgrProxy systemAbilityId:%{public}d!", systemAbilityId);
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    int32_t ret = samgrProxy->SubscribeSystemAbility(systemAbilityId, this);
    WIFI_LOGI("SubscribeSystemAbility:systemAbilityId:%{public}d, ret:%{public}d!", systemAbilityId, ret);
    return;
}
}
}

