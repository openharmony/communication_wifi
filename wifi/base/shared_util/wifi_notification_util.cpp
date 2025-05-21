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
#include "extension_manager_client.h"
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
    switch (notificationId) {
        case WIFI_PORTAL_NOTIFICATION_ID:
            isPortalNtfPublished = true;
            break;
        case WIFI_5G_CONN_NOTIFICATION_ID:
            is5gConnNtfPublished = true;
            break;
        default: {
            break;
        }
    }
    WIFI_LOGI("Publishing wifi notification End, result = %{public}d", result);
}

void WifiNotificationUtil::CancelWifiNotification(WifiNotificationId notificationId)
{
    WIFI_LOGI("Cancel notification, id [%{public}d]", static_cast<int>(notificationId));
    switch (notificationId) {
        case WIFI_PORTAL_NOTIFICATION_ID:
            if (!isPortalNtfPublished) {
                WIFI_LOGE("Portal notification is canceled");
                return;
            }
            isPortalNtfPublished = false;
            break;
        case WIFI_5G_CONN_NOTIFICATION_ID:
            if (!is5gConnNtfPublished) {
                WIFI_LOGE("5g Conn notification is canceled");
                return;
            }
            is5gConnNtfPublished = false;
            break;
        default: {
            break;
        }
    }
    AAFwk::Want want;
    want.SetElementName("com.ohos.locationdialog", "WifiServiceAbility");
    want.SetParam("operateType", static_cast<int>(WifiNotificationOpetationType::CANCEL));
    want.SetParam("notificationId", static_cast<int>(notificationId));
    auto result = StartAbility(want);
    WIFI_LOGI("Cancel notification End, result = %{public}d", result);
}

void WifiNotificationUtil::DisplaySettingWlanPage(
    std::string bundleName, std::string abilityName, std::string navEntryKey)
{
    AAFwk::Want want;
    AppExecFwk::ElementName element("", bundleName, abilityName);
    want.SetElement(element);
    want.SetUri(navEntryKey);
    auto result = StartAbility(want);
    WIFI_LOGI("Display setting wlan page end, result = %{public}d", result);
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

void WifiNotificationUtil::ShowDialog(WifiDialogType type, std::string comInfo)
{
    WIFI_LOGI("ShowDialog, type=%{public}d", static_cast<int32_t>(type));
    AAFwk::Want want;
    std::string bundleName = "com.ohos.sceneboard";
    std::string abilityName = "com.ohos.sceneboard.systemdialog";
    want.SetElementName(bundleName, abilityName);
    nlohmann::json param;
    param["ability.want.params.uiExtensionType"] = "sysDialog/common";
    param["wifiDialogType"] = static_cast<int32_t>(type);
    switch (type) {
        case AUTO_IDENTIFY_CONN:
        case SETTINGS_AUTO_IDENTIFY_CONN:
            param["wifi5gSsid"] = comInfo;
            break;
        case P2P_WSC_PBC_DIALOG:
            param["p2pDeviceName"] = comInfo;
            break;
        case CANDIDATE_CONNECT:
            param["targetSsid"] = comInfo;
            break;
        default: {
            break;
        }
    }
    std::string cmdData = param.dump();
    sptr<UIExtensionAbilityConnection> connection(
        new (std::nothrow) UIExtensionAbilityConnection(cmdData, "com.ohos.locationdialog", "WifiUIExtAbility"));
    if (connection == nullptr) {
        WIFI_LOGE("connect UIExtensionAbilityConnection fail");
        return;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto ret =
        AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection, nullptr, -1);
    WIFI_LOGI("connect service extension ability result = %{public}d", ret);
    IPCSkeleton::SetCallingIdentity(identity);
}

void WifiNotificationUtil::ShowSettingsDialog(WifiDialogType type, std::string settings)
{
    WIFI_LOGI("ShowSettingsDialog, type=%{public}d", static_cast<int32_t>(type));
    AAFwk::Want want;
    std::string bundleName = "com.ohos.sceneboard";
    std::string abilityName = "com.ohos.sceneboard.systemdialog";
    want.SetElementName(bundleName, abilityName);
    nlohmann::json param;
    param["ability.want.params.uiExtensionType"] = "sysDialog/common";
    std::string cmdData = param.dump();
    if (settings.empty()) {
        WIFI_LOGI("settings name is null");
        return;
    }
    sptr<UIExtensionAbilityConnection> connection(
        new (std::nothrow) UIExtensionAbilityConnection(cmdData, settings, "WifiNotAvailableDialog"));
    if (connection == nullptr) {
        WIFI_LOGE("connect UIExtensionAbilityConnection fail");
        return;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto ret =
        AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection, nullptr, -1);
    WIFI_LOGI("connect service extension ability result = %{public}d", ret);
    IPCSkeleton::SetCallingIdentity(identity);
}

void UIExtensionAbilityConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    WIFI_LOGI("on ability connected");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(SIGNAL_NUM);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(bundleName_));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(abilityName_));
    data.WriteString16(u"parameters");
    data.WriteString16(Str8ToStr16(commandStr_));

    int32_t errCode = remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    WIFI_LOGI("AbilityConnectionWrapperProxy::OnAbilityConnectDone result %{public}d", errCode);
}

void UIExtensionAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    WIFI_LOGI("on ability disconnected");
}
}  // namespace Wifi
}  // namespace OHOS