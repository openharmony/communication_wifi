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
#include <string>

namespace OHOS {
namespace Wifi {
enum WifiNotificationId {
    WIFI_PORTAL_NOTIFICATION_ID = 101000
};

enum WifiNotificationStatus {
    WIFI_PORTAL_CONNECTED = 0,
    WIFI_PORTAL_TIMEOUT = 1,
    WIFI_PORTAL_FOUND = 2
};

const std::string WIFI_EVENT_TAP_NOTIFICATION = "ohos.event.notification.wifi.TAP_NOTIFICATION";

class WifiBannerNotification {
public:
    static WifiBannerNotification& GetInstance(void);

    void PublishWifiNotification(WifiNotificationId notificationId, std::string& ssid, WifiNotificationStatus status);

    void CancelWifiNotification(WifiNotificationId notificationId);

private:
    WifiBannerNotification();
    ~WifiBannerNotification();
};
}
}
#endif