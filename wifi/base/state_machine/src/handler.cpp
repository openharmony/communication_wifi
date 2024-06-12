/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "handler.h"
#include <iostream>
#include <sys/time.h>
#include "wifi_log.h"
#include "wifi_settings.h"
#undef LOG_TAG
#define LOG_TAG "OHWIFI_HANDLER"

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
Handler::Handler() : pMyQueue(nullptr), handleThread(0), isRunning(true)
{}
#else
Handler::Handler() : pMyTaskQueue(nullptr)
{}
#endif
Handler::~Handler()
{
    LOGI("Handler::~Handler");
    StopHandlerThread();
    return;
}

bool Handler::InitialHandler(const std::string &name)
{
#ifdef OHOS_ARCH_LITE
    if (handleThread != 0) {
        return true;
    }
    if (pMyQueue == nullptr) {
        pMyQueue = std::make_unique<MessageQueue>();
        if (pMyQueue == nullptr) {
            LOGE("pMyQueue alloc failed.\n");
            return false;
        }
    }

    int ret = pthread_create(&handleThread, nullptr, RunHandleThreadFunc, this);
    if (ret != 0) {
        LOGE("pthread_create failed.\n");
        return false;
    }
    LOGI("pthread_create ret: %{public}d\n", ret);
    pthread_setname_np(handleThread, name.c_str());
#else
    if (pMyTaskQueue == nullptr) {
        pMyTaskQueue = std::make_unique<WifiEventHandler>(name);
        if (pMyTaskQueue == nullptr) {
            LOGE("pMyTaskQueue alloc failed.\n");
            return false;
        }
    }
#endif
    LOGI("InitialHandler success: %{public}s", mThreadName.c_str());
    mThreadName = name;
    return true;
}

void Handler::StopHandlerThread()
{
    LOGI("Enter StopHandlerThread %{public}s", mThreadName.c_str());
#ifdef OHOS_ARCH_LITE
    if (isRunning) {
        isRunning = false;
        if (pMyQueue != nullptr) {
            pMyQueue->StopQueueLoop();
        }
        if (handleThread != 0) {
            pthread_join(handleThread, nullptr);
        }
    }
#else
    if (pMyTaskQueue != nullptr) {
        pMyTaskQueue.reset();
    }
#endif
    LOGI("Leave StopHandlerThread %{public}s", mThreadName.c_str());
    return;
}

#ifdef OHOS_ARCH_LITE
void *Handler::RunHandleThreadFunc(void *pInstance)
{
    if (pInstance == nullptr) {
        LOGE("pInstance is null.\n");
        return nullptr;
    }

    LOGI("Run handler func.");
    Handler *pHandler = (Handler *)pInstance;
    pHandler->GetAndDistributeMessage();

    return nullptr;
}

void Handler::GetAndDistributeMessage()
{
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        return;
    }

    while (isRunning) {
        InternalMessage *msg = pMyQueue->GetNextMessage();
        if (msg == nullptr) {
            LOGE("GetNextMessage null.\n");
            continue;
        }
        LOGD("Handler get message: %{public}d\n", msg->GetMessageName());
        WifiSettings::GetInstance().SetThreadStatusFlag(true);
        DistributeMessage(msg);
        MessageManage::GetInstance().ReclaimMsg(msg);
        WifiSettings::GetInstance().SetThreadStatusFlag(false);
    }

    return;
}
#endif

void Handler::SendMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("%{public}s SendMessage: msg is null.", mThreadName.c_str());
        return;
    }
    LOGD("%{public}s SendMessage msg:%{public}d", mThreadName.c_str(), msg->GetMessageName());
#ifdef OHOS_ARCH_LITE
    MessageExecutedLater(msg, 0);
#else
    std::function<void()> func = std::bind([this, msg]() {
        LOGI("%{public}s ExecuteMessage msg:%{public}d", mThreadName.c_str(), msg->GetMessageName());
        ExecuteMessage(msg);
        MessageManage::GetInstance().ReclaimMsg(msg);
        });
    pMyTaskQueue->PostAsyncTask(func, std::to_string(msg->GetMessageName()), 0);
#endif
    return;
}

void Handler::MessageExecutedLater(InternalMessage *msg, int64_t delayTimeMs)
{
    if (msg == nullptr) {
        LOGE("%{public}s MessageExecutedLater: msg is null.", mThreadName.c_str());
        return;
    }

    int64_t delayTime = delayTimeMs;
    if (delayTime < 0) {
        delayTime = 0;
    }
#ifdef OHOS_ARCH_LITE
    /* Obtains the current time, accurate to milliseconds. */
    struct timespec curTime = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &curTime) != 0) {
        LOGE("clock_gettime failed.");
        MessageManage::GetInstance().ReclaimMsg(msg);
        return;
    }
    int64_t nowTime = static_cast<int64_t>(curTime.tv_sec) * USEC_1000 +
        curTime.tv_nsec / (USEC_1000 * USEC_1000);

    MessageExecutedAtTime(msg, nowTime + delayTime);
#else
    if (pMyTaskQueue == nullptr) {
        LOGE("%{public}s pMyTaskQueue is null.\n", mThreadName.c_str());
        MessageManage::GetInstance().ReclaimMsg(msg);
        return;
    }
    std::function<void()> func = std::bind([this, msg]() {
        LOGI("%{public}s ExecuteMessage msg:%{public}d", mThreadName.c_str(), msg->GetMessageName());
        ExecuteMessage(msg);
        MessageManage::GetInstance().ReclaimMsg(msg);
        });
    pMyTaskQueue->PostAsyncTask(func, std::to_string(msg->GetMessageName()), delayTime);
#endif
    return;
}

void Handler::MessageExecutedAtTime(InternalMessage *msg, int64_t execTime)
{
    if (msg == nullptr) {
        LOGE("%{public}s MessageExecutedAtTime: msg is null.", mThreadName.c_str());
        return;
    }

    LOGD("{%public}s MessageExecutedAtTime msg: %{public}d", mThreadName.c_str(), msg->GetMessageName());
#ifdef OHOS_ARCH_LITE
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        MessageManage::GetInstance().ReclaimMsg(msg);
        return;
    }

    if (pMyQueue->AddMessageToQueue(msg, execTime) != true) {
        LOGE("AddMessageToQueue failed.\n");
        return;
    }
#else
    /* Obtains the current time, accurate to milliseconds. */
    struct timespec curTime = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &curTime) != 0) {
        LOGE("clock_gettime failed.");
        MessageManage::GetInstance().ReclaimMsg(msg);
        return;
    }
    int64_t nowTime = static_cast<int64_t>(curTime.tv_sec) * USEC_1000 +
        curTime.tv_nsec / (USEC_1000 * USEC_1000);
    MessageExecutedLater(msg, execTime - nowTime);
#endif
    return;
}

void Handler::PlaceMessageTopOfQueue(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("%{public}s PlaceMessageTopOfQueue: msg is null.", mThreadName.c_str());
        return;
    }

    LOGD("%{public}s PlaceMessageTopOfQueue msg: %{public}d", mThreadName.c_str(), msg->GetMessageName());
#ifdef OHOS_ARCH_LITE
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        MessageManage::GetInstance().ReclaimMsg(msg);
        return;
    }

    if (!pMyQueue->AddMessageToQueue(msg, 0)) {
        LOGE("AddMessageToQueue failed.\n");
        return;
    }
#else
    MessageExecutedLater(msg, 0);
#endif
    return;
}

void Handler::DeleteMessageFromQueue(int messageName)
{
    LOGD("%{public}s DeleteMessageFromQueue msg is: %{public}d", mThreadName.c_str(), messageName);
#ifdef OHOS_ARCH_LITE
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        return;
    }

    if (!pMyQueue->DeleteMessageFromQueue(messageName)) {
        LOGE("DeleteMessageFromQueue failed.\n");
        return;
    }
#else
    if (pMyTaskQueue == nullptr) {
        LOGE("%{public}s pMyQueue is null.\n", mThreadName.c_str());
        return;
    }
    pMyTaskQueue->RemoveAsyncTask(std::to_string(messageName));
#endif
    return;
}
#ifdef OHOS_ARCH_LITE
void Handler::DistributeMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    ExecuteMessage(msg);
    return;
}
#endif
}  // namespace Wifi
}  // namespace OHOS