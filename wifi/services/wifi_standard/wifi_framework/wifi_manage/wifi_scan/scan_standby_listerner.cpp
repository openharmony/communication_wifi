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
#include "define.h"
#include "wifi_logger.h"
#include "scan_standby_listerner.h"
#include "wifi_service_manager.h"
#include "wifi_settings.h"

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

void StandByListerner::Init()
{
    WIFI_LOGI("Enter StandByListerner::Init.\n");
    RegisterStandByEvent();
    return;
}

void StandByListerner::Unit()
{
    WIFI_LOGI("Enter StandByListerner::Unit.\n");
    UnRegisterStandByEvent();
    return;
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
    if (sleeping) {
        return;
    }

    int state = WifiSettings::GetInstance().GetScreenState();
    WIFI_LOGI("Screen state(1:OPEN, 2:CLOSE): %{public}d.", state);
    if (state != MODE_STATE_OPEN) {
        return;
    }
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
        if (pScanService == nullptr) {
            WIFI_LOGE("scan service is NOT start!");
            return;
        }
        if (pScanService->OnStandbyStateChanged(sleeping) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("OnStandbyStateChanged failed");
        }
    }
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

void StandByListerner::RegisterStandByEvent()
{
    std::unique_lock<std::mutex> lock(standByEventMutex);
    if (isStandBySubscribered) {
        WIFI_LOGI("isStandBySubscribered is true!");
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    standBySubscriber_ = std::make_shared<StandBySubscriber>(subscriberInfo, OnStandbyStateChanged);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(standBySubscriber_)) {
        WIFI_LOGE("StandByEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("StandByEvent SubscribeCommonEvent() OK");
        isStandBySubscribered = true;
    }
}

void StandByListerner::UnRegisterStandByEvent()
{
    WIFI_LOGI("UnRegisterStandByEvent enter");
    std::unique_lock<std::mutex> lock(standByEventMutex);
    if (!isStandBySubscribered) {
        WIFI_LOGI("isStandBySubscribered is false!");
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(standBySubscriber_)) {
        WIFI_LOGE("StandByEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("StandByEvent UnSubscribeCommonEvent() OK");
        isStandBySubscribered = false;
    }
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