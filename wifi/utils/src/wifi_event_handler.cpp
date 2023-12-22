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

#include "wifi_event_handler.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiEventHandler");

WifiEventHandler::WifiEventHandler(const std::string &threadName)
{
    eventRunner = AppExecFwk::EventRunner::Create(threadName);
    if (eventRunner) {
        eventHandler = std::make_shared<AppExecFwk::EventHandler>(eventRunner);
    } else {
        WIFI_LOGE("WifiEventHandler: Create event runner failed!");
    }
    WIFI_LOGI("WifiEventHandler: Create a new event handler, threadName:%{public}s", threadName.c_str());
}

WifiEventHandler::~WifiEventHandler()
{
    WIFI_LOGI("WifiEventHandler: ~WifiEventHandler");
    if (eventRunner) {
        eventRunner->Stop();
        eventRunner.reset();
    }

    if (eventHandler) {
        eventHandler.reset();
    }
}

bool WifiEventHandler::PostSyncTask(const Callback &callback)
{
    if (eventHandler == nullptr) {
        WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
        return false;
    }

    return eventHandler->PostSyncTask(callback, Priority::HIGH);
}

bool WifiEventHandler::PostAsyncTask(const Callback &callback, int64_t delayTime)
{
    if (eventHandler == nullptr) {
        WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
        return false;
    }

    return eventHandler->PostTask(callback, delayTime, Priority::HIGH);
}

bool WifiEventHandler::PostAsyncTask(const Callback &callback, const std::string &name, int64_t delayTime)
{
    if (eventHandler == nullptr) {
        WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
        return false;
    }

    return eventHandler->PostTask(callback, name, delayTime, Priority::HIGH);
}

void WifiEventHandler::RemoveAsyncTask(const std::string &name)
{
    if (eventHandler == nullptr) {
        WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
        return;
    }

    eventHandler->RemoveTask(name);
}
} // namespace Wifi
} // namespace OHOS