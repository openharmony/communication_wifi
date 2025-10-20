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

#ifndef WIFI_NOTIFICATION_UTIL_H
#define WIFI_NOTIFICATION_UTIL_H
#include "ability_connect_callback_stub.h"
#include "ipc_skeleton.h"
#include "want.h"
#include "want_params_wrapper.h"
#include <atomic>
#include <string>

namespace OHOS {
namespace Wifi {
constexpr int DEFAULT_INVAL_VALUE = -1;
constexpr int32_t SIGNAL_NUM = 3;
inline const std::u16string ABILITY_MGR_DESCRIPTOR = u"ohos.aafwk.AbilityManager";
inline const std::string WIFI_EVENT_TAP_NOTIFICATION = "ohos.event.notification.wifi.TAP_NOTIFICATION";
inline const std::string WIFI_EVENT_DIALOG_ACCEPT = "ohos.event.wifi.DIALOG_ACCEPT";
inline const std::string WIFI_EVENT_DIALOG_REJECT = "ohos.event.wifi.DIALOG_REJECT";
inline const std::string EVENT_SETTINGS_WLAN_KEEP_CONNECTED = "event.settings.wlan.keep_connected";
enum WifiNotificationId {
    WIFI_PORTAL_NOTIFICATION_ID = 101000,
    WIFI_5G_CONN_NOTIFICATION_ID = 101100
};

enum WifiNotificationStatus {
    WIFI_PORTAL_CONNECTED = 0,
    WIFI_PORTAL_TIMEOUT = 1,
    WIFI_PORTAL_FOUND = 2,
    WIFI_5G_CONN_FOUND = 3
};

enum WifiNotificationOpetationType {
    CANCEL = 0,
    PUBLISH = 1
};

enum WifiDialogType {
    CDD = 0,
    THREE_VAP = 1,
    CANDIDATE_CONNECT = 2,
    AUTO_IDENTIFY_CONN = 3,
    P2P_WSC_PBC_DIALOG = 4,
    SETTINGS_AUTO_IDENTIFY_CONN = 5
};

class WifiNotificationUtil {
public:
    static WifiNotificationUtil& GetInstance(void);

    void PublishWifiNotification(WifiNotificationId notificationId, std::string& ssid, WifiNotificationStatus status);

    void CancelWifiNotification(WifiNotificationId notificationId);

    void DisplaySettingWlanPage(std::string bundleName, std::string abilityName, std::string navEntryKey);
 
    int32_t StartAbility(OHOS::AAFwk::Want& want);

    void ShowDialog(WifiDialogType type, std::string comInfo = "");

    void ShowSettingsDialog(WifiDialogType type, std::string settings);

private:
    std::atomic<bool> isPortalNtfPublished {false};
    std::atomic<bool> is5gConnNtfPublished {false};

    WifiNotificationUtil();
    ~WifiNotificationUtil();
};

class UIExtensionAbilityConnection : public AAFwk::AbilityConnectionStub {
public:
    UIExtensionAbilityConnection(
        const std::string commandStr, const std::string bundleName, const std::string abilityName)
        : commandStr_(commandStr), bundleName_(bundleName), abilityName_(abilityName)
    {}

    virtual ~UIExtensionAbilityConnection() = default;

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

private:
    std::string commandStr_;
    std::string bundleName_;
    std::string abilityName_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif