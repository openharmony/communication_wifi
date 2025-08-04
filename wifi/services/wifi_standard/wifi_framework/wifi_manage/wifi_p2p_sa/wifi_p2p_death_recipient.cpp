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
#include "wifi_p2p_death_recipient.h"
#include "wifi_logger.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_service_manager.h"
DEFINE_WIFILOG_P2P_LABEL("WifiP2pDeathRecipient");

namespace OHOS {
namespace Wifi {
void WifiP2pDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGD("WifiP2pDeathRecipient::OnRemoteDied!");
    int uid = WifiInternalEventDispatcher::GetInstance().GetRemoteUid(remoteObject.promote());
    WifiInternalEventDispatcher::GetInstance().RemoveP2pCallback(remoteObject.promote());
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (uid != -1 && pService != nullptr) {
        pService->NotifyRemoteDie(uid);
    }
}
}  // namespace Wifi
}  // namespace OHOS