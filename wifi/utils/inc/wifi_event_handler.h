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

#ifndef WIFI_EVENT_HANDLER_H
#define WIFI_EVENT_HANDLER_H

#include <string>
#include <memory>
#include <chrono>
#include <future>
#include <mutex>

namespace OHOS {
namespace Wifi {
class WifiEventHandler {
public:
    using Callback = std::function<void()>;

    explicit WifiEventHandler(const std::string &threadName, const Callback &timeOutFunc = nullptr);
    ~WifiEventHandler();

    /**
     * @submit sync task to Handler
     *
     * @param Callback - Input task
     * @return bool - true: submit success, false: submit failed
     */
    bool PostSyncTask(const Callback &callback);

    /**
     * @submit Async task to Handler
     *
     * @param Callback - Input task
     * @param delayTime - Wait delayTime ms excute task
     * @return bool - true: submit success, false: submit failed
     */
    bool PostAsyncTask(const Callback &callback, int64_t delayTime = 0);

    /**
     * @submit Async task to Handler
     *
     * @param Callback - Input task
     * @param name - Describer of task
     * @param delayTime - Wait delayTime ms excute task
     * @return bool - true: submit success, false: submit failed
     */
    bool PostAsyncTask(const Callback &callback, const std::string &name, int64_t delayTime = 0);

    /**
     * @Remove Async task
     *
     * @param name - Describer of task
     */
    void RemoveAsyncTask(const std::string &name);

    /**
    * @Check if Has Async Task
    *
    * @param name
    * @param hasTask
    * @return int - 0: supported, -1: unsupported
    */
    int HasAsyncTask(const std::string &name, bool &hasTask);

    /**
    * @submit sync timeout task to Handler
    *
    * @param callback - Input task
    * @param waitTime - Wait time(ms) excute task
    * @return bool - true: excute task success, false: excute task timeout
    */
    static bool PostSyncTimeOutTask(const Callback &callback, uint64_t waitTime = 5000);

private:
    class WifiEventHandlerImpl;
    std::unique_ptr<WifiEventHandlerImpl> ptr;
    std::mutex handlerMutex {};
};
} // namespace Wifi
} // namespace OHOS
#endif