/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "wifi_device_death_recipient.h"
#include "wifi_logger.h"
#include "wifi_internal_event_dispatcher.h"
DEFINE_WIFILOG_LABEL("WifiDeviceDeathRecipient");
namespace OHOS {
namespace Wifi {
void WifiDeviceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remoteObject)
{
    WIFI_LOGW("OnRemoteDied!");
    WifiInternalEventDispatcher::GetInstance().RemoveStaCallback(remoteObject.promote());
}
}  // namespace Wifi
}  // namespace OHOS