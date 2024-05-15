/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "ability_manager_ipc_interface_code.h"
#include "iservice_registry.h"
#include "message_parcel.h"
#include "system_ability_definition.h"
#include "wifi_notification_util.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNotificationUtil");

WifiNotificationUtil &WifiNotificationUtil::GetInstance()
{
    static WifiNotificationUtil instance;
    return instance;
}

WifiNotificationUtil::WifiNotificationUtil()
{}

WifiNotificationUtil::~WifiNotificationUtil()
{}

void WifiNotificationUtil::PublishWifiNotification(WifiNotificationId notificationId, std::string& ssid,
    WifiNotificationStatus status)
{
    WIFI_LOGI("Publishing wifi notification, id [%{public}d]", static_cast<int>(notificationId));
    AAFwk::Want want;
    want.SetElementName("com.ohos.locationdialog", "WifiServiceAbility");
    want.SetParam("operateType", static_cast<int>(WifiNotificationOpetationType::PUBLISH));
    want.SetParam("notificationId", static_cast<int>(notificationId));
    want.SetParam("status", status);
    want.SetParam("ssid", ssid);
    auto result = StartAbility(want);
    WIFI_LOGI("Publishing wifi notification End, result = %{public}d", result);
}

void WifiNotificationUtil::CancelWifiNotification(WifiNotificationId notificationId)
{
    WIFI_LOGI("Cancel notification, id [%{public}d]", static_cast<int>(notificationId));
    AAFwk::Want want;
    want.SetElementName("com.ohos.locationdialog", "WifiServiceAbility");
    want.SetParam("operateType", static_cast<int>(WifiNotificationOpetationType::CANCEL));
    want.SetParam("notificationId", static_cast<int>(notificationId));
    auto result = StartAbility(want);
    WIFI_LOGI("Cancel notification End, result = %{public}d", result);
}

int32_t WifiNotificationUtil::StartAbility(OHOS::AAFwk::Want& want)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        WIFI_LOGE("systemAbilityManager is nullptr");
        return -1;
    }
    sptr<IRemoteObject> remote = systemAbilityManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remote == nullptr) {
        WIFI_LOGE("remote is nullptr");
        return -1;
    }

    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
 
    if (!data.WriteInterfaceToken(ABILITY_MGR_DESCRIPTOR)) {
        return -1;
    }
    if (!data.WriteParcelable(&want)) {
        WIFI_LOGE("want write failed.");
        return -1;
    }
 
    if (!data.WriteInt32(DEFAULT_INVAL_VALUE)) {
        WIFI_LOGE("userId write failed.");
        return -1;
    }
 
    if (!data.WriteInt32(DEFAULT_INVAL_VALUE)) {
        WIFI_LOGE("requestCode write failed.");
        return -1;
    }
    uint32_t task =  static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::START_ABILITY);
    error = remote->SendRequest(task, data, reply, option);
    if (error != NO_ERROR) {
        WIFI_LOGE("Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}
}
}