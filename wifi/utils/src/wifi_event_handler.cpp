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
    WifiEventHandlerImpl(const std::string &threadName, const Callback &timeOutFunc = nullptr)
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
constexpr int WIFI_THREAD_TIMEOUT_LIMIT = 30 * 1000 * 1000; // 30s
class WifiEventHandler::WifiEventHandlerImpl {
public:
    WifiEventHandlerImpl(const std::string &threadName, const Callback &timeOutFunc = nullptr)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        if (eventQueue != nullptr) {
            WIFI_LOGI("WifiEventHandlerImpl already init.");
            return;
        }
        if (timeOutFunc == nullptr) {
            eventQueue = std::make_shared<ffrt::queue>(threadName.c_str());
            WIFI_LOGI("WifiEventHandlerImpl: Create a new eventQueue, threadName:%{public}s", threadName.c_str());
        } else {
            eventQueue = std::make_shared<ffrt::queue>(threadName.c_str(),
            ffrt::queue_attr().callback(timeOutFunc));
            WIFI_LOGI("WifiEventHandlerImpl: Create a new eventQueue with callback,"
                "threadName:%{public}s", threadName.c_str());
        }
    }

    ~WifiEventHandlerImpl()
    {
        WIFI_LOGI("WifiEventHandler: ~WifiEventHandler");
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        for (auto iter = taskMap_.begin(); iter != taskMap_.end();) {
            if (iter->second != nullptr && eventQueue != nullptr) {
                int32_t ret = eventQueue->cancel(iter->second);
                if (ret != 0) {
                    WIFI_LOGD("~WifiEventHandler cancel failed, error code : %{public}d", ret);
                }
                iter->second = nullptr;
            }
            iter = taskMap_.erase(iter);
        }
        if (eventQueue != nullptr) {
            eventQueue.reset();
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
        taskMap_[name]  = std::move(handle);
        return true;
    }
    void RemoveAsyncTask(const std::string &name)
    {
        std::lock_guard<ffrt::mutex> lock(eventQurueMutex);
        WIFI_LOGD("RemoveAsyncTask Enter %{public}s", name.c_str());
        auto iter = taskMap_.find(name);
        if (iter != taskMap_.end() && iter->second != nullptr && eventQueue != nullptr) {
            int32_t ret = eventQueue->cancel(iter->second);
            if (ret != 0) {
                WIFI_LOGD("RemoveAsyncTask failed, error code : %{public}d", ret);
            }
            taskMap_.erase(iter);
        }
    }
private:
    std::shared_ptr<ffrt::queue> eventQueue = nullptr;
    mutable ffrt::mutex eventQurueMutex;
    std::map<std::string, ffrt::task_handle> taskMap_;
};
#else
class WifiEventHandler::WifiEventHandlerImpl {
public:
    WifiEventHandlerImpl(const std::string &threadName, const Callback &timeOutFunc = nullptr)
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

WifiEventHandler::WifiEventHandler(const std::string &threadName, const Callback &timeOutFunc)
    :ptr(new WifiEventHandlerImpl(threadName, timeOutFunc))
{}

WifiEventHandler::~WifiEventHandler()
{
    ptr.reset();
}

bool WifiEventHandler::PostSyncTask(const Callback &callback)
{
    if (ptr == nullptr) {
        WIFI_LOGE("PostSyncTask: ptr is nullptr!");
        return false;
    }
    return ptr->PostSyncTask(const_cast<Callback &>(callback));
}

bool WifiEventHandler::PostAsyncTask(const Callback &callback, int64_t delayTime)
{
    if (ptr == nullptr) {
        WIFI_LOGE("PostAsyncTask: ptr is nullptr!");
        return false;
    }
    return ptr->PostAsyncTask(const_cast<Callback &>(callback), delayTime);
}

bool WifiEventHandler::PostAsyncTask(const Callback &callback, const std::string &name, int64_t delayTime)
{
    if (ptr == nullptr) {
        WIFI_LOGE("PostAsyncTask: ptr is nullptr!");
        return false;
    }
    return ptr->PostAsyncTask(const_cast<Callback &>(callback), name, delayTime);
}
void WifiEventHandler::RemoveAsyncTask(const std::string &name)
{
    if (ptr == nullptr) {
        WIFI_LOGE("RemoveAsyncTask: ptr is nullptr!");
        return;
    }
    ptr->RemoveAsyncTask(name);
}


bool WifiEventHandler::PostSyncTimeOutTask(const Callback &callback, uint64_t waitTime)
{
#ifdef WIFI_FFRT_ENABLE
    ffrt::future f = ffrt::async(callback);
    ffrt::future_status status = f.wait_for(std::chrono::milliseconds(waitTime));
    if (status == ffrt::future_status::timeout) {
        WIFI_LOGE("PostSyncTimeOutTask: Task timeout!");
        return false;
    }

    return true;
#else
    std::future f = std::async(callback);
    std::future_status status = f.wait_for(std::chrono::milliseconds(waitTime));
    if (status == std::future_status::timeout) {
        WIFI_LOGE("PostSyncTimeOutTask: Task timeout!");
        return false;
    }

    return true;
#endif
}


} // namespace Wifi
} // namespace OHOS