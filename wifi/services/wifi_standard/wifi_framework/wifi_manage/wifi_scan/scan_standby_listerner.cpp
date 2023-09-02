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
#ifndef OHOS_ARCH_LITE
#include "wifi_logger.h"
#include "scan_standby_listerner.h"

#define WIFI_STANDBY_NAP "napped"
#define WIFI_STANDBY_SLEEPING "sleeping"

DEFINE_WIFILOG_LABEL("StandByListerner");

namespace OHOS {
namespace Wifi {

bool StandByListerner::allowScan = true;

StandByListerner::StandByListerner()
{}

StandByListerner::~StandByListerner()
{}

bool StandByListerner::Init()
{
    std::unique_lock<std::mutex> lock(standyMutex);
    if (standbySubscriber) {
        return false;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    standbySubscriber = std::make_shared<StandBySubscriber>(subscriberInfo, OnStandbyStateChanged);
    if (!OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(standbySubscriber)) {
        WIFI_LOGE("fail to SubscribeCommonEvent");
        standbySubscriber = nullptr;
    }
    return true;
}

void StandByListerner::Unit()
{
    if (!OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(standbySubscriber)) {
        WIFI_LOGE("fail to UnSubscribeCommonEvent");
    }
}

bool StandByListerner::AllowScan()
{
    WIFI_LOGD("StandByListerner AllowScan:%{public}d.", allowScan);
    return allowScan;
}

void StandByListerner::OnStandbyStateChanged(bool napped, bool sleeping)
{
    WIFI_LOGI("OnStandbyStateChanged napped:%{public}d, sleeping:%{public}d", napped, sleeping);
    allowScan = !sleeping;
}

StandBySubscriber::StandBySubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo,
    std::function<void(bool, bool)> callBack) : CommonEventSubscriber(subscriberInfo)
{
    onStandbyChangedEvent = callBack;
    WIFI_LOGI("StandBySubscriber enter");
}

StandBySubscriber::~StandBySubscriber()
{
    WIFI_LOGI("~StandBySubscriber enter");
}

void StandBySubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event)
{
    const auto &action = event.GetWant().GetAction();
    const bool napped = event.GetWant().GetBoolParam(WIFI_STANDBY_NAP, 0);
    const bool sleeping = event.GetWant().GetBoolParam(WIFI_STANDBY_SLEEPING, 0);
    WIFI_LOGI("StandByListerner OnReceiveEvent action[%{public}s], napped[%{public}d], sleeping[%{public}d]",
        action.c_str(), napped, sleeping);
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED &&
        onStandbyChangedEvent != NULL) {
        onStandbyChangedEvent(napped, sleeping);
    }
}

}  // namespace Wifi
}  // namespace OHOS
#endif