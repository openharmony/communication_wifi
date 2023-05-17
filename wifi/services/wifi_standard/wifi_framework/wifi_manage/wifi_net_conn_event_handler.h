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

#ifndef WIFI_NET_CONN_EVENT_HANDLER_H
#define WIFI_NET_CONN_EVENT_HANDLER_H

#include <memory>

#include "event_handler.h"
#include "event_runner.h"

namespace OHOS {
namespace Wifi {
class WifiNetConnEventHandler final : public AppExecFwk::EventHandler {
public:
    explicit WifiNetConnEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner);
    ~WifiNetConnEventHandler() override = default;
    bool PostAsyncTask(const Callback &callback, int64_t delayTime);
    bool PostAsyncTask(const Callback &callback, const std::string &name = std::string(), int64_t delayTime = 0);
    void RemoveAsyncTask(const std::string &name);
};
} // namespace Wifi
} // namespace OHOS
#endif // WIFI_NET_CONN_EVENT_HANDLER_H