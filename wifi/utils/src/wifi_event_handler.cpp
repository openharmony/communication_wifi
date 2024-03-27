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
#include <map>
#include "wifi_event_handler.h"
#include "wifi_logger.h"
#ifdef OHOS_ARCH_LITE
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#elif WIFI_FFRT_ENABLE
#include "ffrt_inner.h"
#else
#include "event_handler.h"
#include "event_runner.h"
#endif
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiEventHandler");
#ifdef OHOS_ARCH_LITE
class WifiEventHandler::WifiEventHandlerImpl {
public:
    WifiEventHandlerImpl(const std::string &threadName)
    {
        mRunFlag = true;
        mWorkerThread = std::thread(WifiEventHandlerImpl::Run, std::ref(*this));
        pthread_setname_np(mWorkerThread.native_handle(), threadName.c_str());
    }
    ~WifiEventHandlerImpl()
    {
        mRunFlag = false;
        mCondition.notify_one();
        if (mWorkerThread.joinable()) {
            mWorkerThread.join();
        }
    }
    bool PostSyncTask(Callback &callback)
    {
        WIFI_LOGE("WifiEventHandlerImpl PostSyncTask Unsupported in lite.");
        return false;
    }
    bool PostAsyncTask(Callback &callback, int64_t delayTime = 0)
    {
        if (delayTime > 0) {
            WIFI_LOGE("WifiEventHandlerImpl PostAsyncTask with delayTime Unsupported in lite.");
            return false;
        }
        WIFI_LOGD("PostAsyncTask Enter");
        {
            std::unique_lock<std::mutex> lock(mMutex);
            mEventQue.push_back(callback);
        }
        mCondition.notify_one();
        return true;
    }
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0)
    {
        WIFI_LOGE("WifiEventHandlerImpl PostAsyncTask with name Unsupported in lite.");
        return false;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        WIFI_LOGE("WifiEventHandlerImpl RemoveAsyncTask Unsupported in lite.");
    }
private:
    static  void Run(WifiEventHandlerImpl &instance)
    {
        while (instance.mRunFlag) {
            std::unique_lock<std::mutex> lock(instance.mMutex);
            while (instance.mEventQue.empty() && instance.mRunFlag) {
                instance.mCondition.wait(lock);
            }
            if (!instance.mRunFlag) {
                break;
            }
            Callback msg = instance.mEventQue.front();
            instance.mEventQue.pop_front();
            lock.unlock();
            msg();
        }
        return;
    }
    std::thread mWorkerThread;
    std::atomic<bool> mRunFlag;
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::deque<Callback> mEventQue;
};
#elif WIFI_FFRT_ENABLE
class WifiEventHandler::WifiEventHandlerImpl {
public:
    WifiEventHandlerImpl(const std::string &threadName)
    {
        if (eventQueue != nullptr) {
            WIFI_LOGI("WifiEventHandlerImpl already init.");
            return;
        }
        eventQueue = std::make_shared<ffrt::queue>(threadName.c_str());
        WIFI_LOGI("WifiEventHandlerImpl: Create a new eventQueue, threadName:%{public}s", threadName.c_str());
    }
    ~WifiEventHandlerImpl()
    {
        WIFI_LOGI("WifiEventHandler: ~WifiEventHandler");
        if (eventQueue) {
            eventQueue = nullptr;
        }
        for (auto iter = taskMap_.begin(); iter != taskMap_.end();) {
            iter->second = nullptr;
            iter = taskMap_.erase(iter);
        }
    }
    bool PostSyncTask(Callback &callback)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            WIFI_LOGE("PostSyncTask: eventQueue is nullptr!");
            return false;
        }
        WIFI_LOGD("PostSyncTask Enter");
        ffrt::task_handle handle = eventQueue->submit_h(callback);
        if (handle == nullptr) {
            return false;
        }
        eventQueue->wait(handle);
        return true;
    }
    bool PostAsyncTask(Callback &callback, int64_t delayTime = 0)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            WIFI_LOGE("PostAsyncTask: eventQueue is nullptr!");
            return false;
        }
        int64_t delayTimeUs = delayTime * 1000;
        WIFI_LOGD("PostAsyncTask Enter");
        ffrt::task_handle handle = eventQueue->submit_h(callback, ffrt::task_attr().delay(delayTimeUs));
        return handle != nullptr;
    }
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue == nullptr) {
            WIFI_LOGE("PostAsyncTask: eventQueue is nullptr!");
            return false;
        }
        int64_t delayTimeUs = delayTime * 1000;
        WIFI_LOGD("PostAsyncTask Enter %{public}s", name.c_str());
        ffrt::task_handle handle = eventQueue->submit_h(
            callback, ffrt::task_attr().name(name.c_str()).delay(delayTimeUs));
        if (handle == nullptr) {
            return false;
        }
        taskMap_[name] = std::move(handle);
        return true;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        WIFI_LOGD("RemoveAsyncTask Enter %{public}s", name.c_str());
        auto item = taskMap_.find(name);
        if (item == taskMap_.end()) {
            WIFI_LOGD("task not found");
            return;
        }
        if (item->second != nullptr && eventQueue != nullptr) {
            int32_t ret = eventQueue->cancel(item->second);
            if (ret != 0) {
                WIFI_LOGE("RemoveAsyncTask failed, error code : %{public}d", ret);
            }
        }
        taskMap_.erase(name);
    }
private:
    std::shared_ptr<ffrt::queue> eventQueue = nullptr;
    mutable ffrt::mutex eventQurueMutex;
    std::map<std::string, ffrt::task_handle> taskMap_;
};
#else
class WifiEventHandler::WifiEventHandlerImpl {
public:
    WifiEventHandlerImpl(const std::string &threadName)
    {
        eventRunner = AppExecFwk::EventRunner::Create(threadName);
        if (eventRunner) {
            eventHandler = std::make_shared<AppExecFwk::EventHandler>(eventRunner);
        } else {
            WIFI_LOGE("WifiEventHandler: Create event runner failed!");
        }
        WIFI_LOGI("WifiEventHandler: Create a new event handler, threadName:%{public}s", threadName.c_str());
    }
    ~WifiEventHandlerImpl()
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
    bool PostSyncTask(Callback &callback)
    {
        if (eventHandler == nullptr) {
            WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
            return false;
        }
        return eventHandler->PostSyncTask(callback, AppExecFwk::EventHandler::Priority::HIGH);
    }
    bool PostAsyncTask(Callback &callback, int64_t delayTime = 0)
    {
        if (eventHandler == nullptr) {
            WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
            return false;
        }
        return eventHandler->PostTask(callback, delayTime, AppExecFwk::EventHandler::Priority::HIGH);
    }
    bool PostAsyncTask(Callback &callback, const std::string &name, int64_t delayTime = 0)
    {
        if (eventHandler == nullptr) {
            WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
            return false;
        }
        return eventHandler->PostTask(callback, name, delayTime, AppExecFwk::EventHandler::Priority::HIGH);
    }
    void RemoveAsyncTask(const std::string &name)
    {
        if (eventHandler == nullptr) {
            WIFI_LOGE("PostSyncTask: eventHandler is nullptr!");
            return;
        }
        eventHandler->RemoveTask(name);
    }
private:
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
};
#endif

WifiEventHandler::WifiEventHandler(const std::string &threadName)
    :ptr(new WifiEventHandlerImpl(threadName))
{}

WifiEventHandler::~WifiEventHandler()
{
    ptr.reset();
}

bool WifiEventHandler::PostSyncTask(const Callback &callback)
{
    return ptr->PostSyncTask(const_cast<Callback &>(callback));
}

bool WifiEventHandler::PostAsyncTask(const Callback &callback, int64_t delayTime)
{
    return ptr->PostAsyncTask(const_cast<Callback &>(callback), delayTime);
}

bool WifiEventHandler::PostAsyncTask(const Callback &callback, const std::string &name, int64_t delayTime)
{
    return ptr->PostAsyncTask(const_cast<Callback &>(callback), name, delayTime);
}
void WifiEventHandler::RemoveAsyncTask(const std::string &name)
{
    ptr->RemoveAsyncTask(name);
}
} // namespace Wifi
} // namespace OHOS