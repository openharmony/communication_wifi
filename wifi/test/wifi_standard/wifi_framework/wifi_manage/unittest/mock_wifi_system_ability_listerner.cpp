/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "mock_wifi_system_ability_listerner.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiSystemAbilityListener");

namespace OHOS {
namespace Wifi {
WifiSystemAbilityListener::WifiSystemAbilityListener()
{}

WifiSystemAbilityListener::~WifiSystemAbilityListener()
{}

void WifiSystemAbilityListener::SubscribeSystemAbility(int systemAbilityId)
{
    WIFI_LOGD("WifiSystemAbilityListener::SubscribeSystemAbility");
}

void WifiSystemAbilityListener::UnSubscribeSystemAbility(int systemAbilityId)
{
    WIFI_LOGD("WifiSystemAbilityListener::UnSubscribeSystemAbility");
}

void WifiSystemAbilityListener::OnSystemAbilityChanged(int systemAbilityId, bool add)
{
    WIFI_LOGD("WifiSystemAbilityListener::OnSystemAbilityChanged");
}
} // namespace Wifi
} // namespace OHOS