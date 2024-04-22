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

#include "image_source.h"
#include "image_type.h"
#include "locale_config.h"
#include "locale_info.h"
#include "notification_normal_content.h"
#include "notification_helper.h"
#include "notification_content.h"
#include "notification_request.h"
#include "pixel_map.h"
#include "want_agent_helper.h"
#include "want_agent_info.h"
#include "wifi_common_util.h"
#include "wifi_notification_util.h"
#include "wifi_logger.h"

#include <vector>

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNotification");

static const std::string ICON_PATH_NOTIFICATION = "/etc/wifi/portal_notification.png";

class WifiNotificationSubscriber : public Notification::NotificationSubscriber {
    void OnConnected() {}
    void OnDisconnected() {}
    void OnUpdate(const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap) {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<Notification::NotificationDoNotDisturbDate> &date) {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<Notification::EnabledNotificationCallbackData> &callbackData) {}
    void OnDied() {}
    void OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap, int deleteReason) {}
    void OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &notification,
        const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap) {}
    void OnBadgeChanged(const std::shared_ptr<Notification::BadgeNumberCallbackData> &badgeData) {}
    void OnBadgeEnabledChanged(const sptr<Notification::EnabledNotificationCallbackData> &callbackData) {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
        const std::shared_ptr<Notification::NotificationSortingMap> &sortingMap, int32_t deleteReason) {}
};

static const auto NOTIFICATION_SUBSCRIBER = WifiNotificationSubscriber();

static void AddWantAgent(Notification::NotificationRequest& request)
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetAction(WIFI_EVENT_TAP_NOTIFICATION);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags,
        wants,
        nullptr
    );
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo);
    request.SetWantAgent(wantAgent);
}

static std::shared_ptr<Media::PixelMap> GetPixelMap(std::string path)
{
    std::shared_ptr<Media::PixelMap> pixelMapSpr;
    if (std::filesystem::exists(path)) {
        uint32_t errorCode = 0;
        Media::SourceOptions opts;
        opts.formatHint = "image/png";
        std::unique_ptr<Media::ImageSource> imageSource =
            Media::ImageSource::CreateImageSource(path, opts, errorCode);
        Media::DecodeOptions decodeOpts;
        std::unique_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
        pixelMapSpr = std::move(pixelMap);
    }
    return pixelMapSpr;
}

static void GenerateDisplayInfo(std::shared_ptr<Notification::NotificationNormalContent> normalContent,
    std::string& ssid, WifiNotificationStatus status)
{
    OHOS::Global::I18n::LocaleInfo locale(Global::I18n::LocaleConfig::GetSystemLocale());
    std::string curSysLanguage = locale.GetLanguage();
    switch (status) {
        case WifiNotificationStatus::WIFI_PORTAL_CONNECTED:
            if (curSysLanguage == "en") {
                normalContent->SetTitle("Connected to" + ssid);
                normalContent->SetText("Touch to login/authorize");
            } else {
                normalContent->SetTitle("已连接" + ssid);
                normalContent->SetText("点击进行登录/认证");
            }
            break;
        case WifiNotificationStatus::WIFI_PORTAL_TIMEOUT:
            if (curSysLanguage == "en") {
                normalContent->SetTitle("WLAN authentication expired");
                normalContent->SetText("Touch here to log in to" + ssid);
            } else {
                normalContent->SetTitle("该 WLAN 网络认证已过期");
                normalContent->SetText("点击进行登录/认证" + ssid);
            }
            break;
        case WifiNotificationStatus::WIFI_PORTAL_FOUND:
            if (curSysLanguage == "en") {
                normalContent->SetTitle("Authorize Wi-Fi network");
                normalContent->SetText("Touch here to log in to" + ssid);
            } else {
                normalContent->SetTitle("发现需认证的 WLAN 网络");
                normalContent->SetText("点击进行登录/认证" + ssid);
            }
            break;
        default:
            break;
    }
}

WifiBannerNotification::WifiBannerNotification()
{
    WIFI_LOGI("WifiBannerNotification constructor enter.");
    int result = Notification::NotificationHelper::SubscribeNotification(NOTIFICATION_SUBSCRIBER);
    if (result != 0) {
        WIFI_LOGE("fail to subscribe notification");
    }
}

WifiBannerNotification::~WifiBannerNotification()
{}

WifiBannerNotification &WifiBannerNotification::GetInstance()
{
    static WifiBannerNotification gWifiBannerNotification;
    return gWifiBannerNotification;
}

void WifiBannerNotification::PublishWifiNotification(WifiNotificationId notificationId, std::string& ssid,
    WifiNotificationStatus status)
{
    WIFI_LOGI("Publishing wifi notification, id [%{public}d]", static_cast<int>(notificationId));
    std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
    if (normalContent == nullptr) {
        WIFI_LOGE("get notification normal content nullptr");
        return;
    }
    GenerateDisplayInfo(normalContent, ssid, status);
    const std::shared_ptr<Notification::NotificationContent> content =
        std::make_shared<Notification::NotificationContent>(normalContent);
    if (content == nullptr) {
        WIFI_LOGE("get notification content nullptr");
        return;
    }

    Notification::NotificationRequest request;
    request.SetSlotType(OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request.SetNotificationId(static_cast<int>(notificationId));
    request.SetContent(content);
    request.SetCreatorUid(GetCallingUid());
    request.SetCreatorBundleName("wifi_service");
    request.SetTapDismissed(true);
    request.SetNotificationControlFlags(0);
    AddWantAgent(request);
    std::shared_ptr<Media::PixelMap> pixelMapTotalSpr = GetPixelMap(ICON_PATH_NOTIFICATION);
    request.SetLittleIcon(pixelMapTotalSpr);
    request.SetBadgeIconStyle(Notification::NotificationRequest::BadgeStyle::LITTLE);
    
    int ret = Notification::NotificationHelper::PublishNotification(request);
    WIFI_LOGI("wifi service publish notification result = %{public}d", ret);
}

void WifiBannerNotification::CancelWifiNotification(WifiNotificationId notificationId)
{
    WIFI_LOGI("Cancel notification, id [%{public}d]", static_cast<int>(notificationId));
    int ret = Notification::NotificationHelper::CancelAllNotifications();
    WIFI_LOGI("Cancel notification result = %{public}d", ret);
}
}
}