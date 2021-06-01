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

#undef LOG_TAG
#define LOG_TAG "OHWIFI_HANDLER"

namespace OHOS {
namespace Wifi {
Handler::Handler() : pMyQueue(nullptr), handleThread(0), isRunning(true)
{}

Handler::~Handler()
{
    LOGI("Handler::~Handler");
    StopHandlerThread();
    return;
}

bool Handler::InitialHandler()
{
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
    if (ret < 0) {
        LOGE("pthread_create failed.\n");
        return false;
    }

    return true;
}

void Handler::StopHandlerThread()
{
    LOGI("Handler::StopHandlerThread");
    if (isRunning) {
        isRunning = false;
        if (pMyQueue != nullptr) {
            pMyQueue->StopQueueLoop();
        }

        if (handleThread != 0) {
            pthread_join(handleThread, nullptr);
        }
    }

    return;
}

void *Handler::RunHandleThreadFunc(void *pInstance)
{
    if (pInstance == nullptr) {
        LOGE("pInstance is null.\n");
        return nullptr;
    }

    Handler *pHandler = (Handler *)pInstance;
    pHandler->GetAndHandleMessage();

    return nullptr;
}

void Handler::GetAndHandleMessage()
{
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        return;
    }

    while (isRunning) {
        InternalMessage *msg = pMyQueue->GetNextMessage();
        if (msg == nullptr) {
            LOGE("GetNextMessage failed.\n");
            continue;
        }

        DispatchMessage(msg);
        MessageManage::GetInstance().Recycle(msg);
    }

    return;
}

void Handler::SendMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("Handler::SendMessage: msg is null.");
        return;
    }

    LOGD("Handler::SendMessage msg:%{public}d", msg->GetMessageName());
    SendMessageDelayed(msg, 0);
    return;
}

void Handler::SendMessageDelayed(InternalMessage *msg, long delayMillis)
{
    if (msg == nullptr) {
        LOGE("Handler::SendMessageDelayed: msg is null.");
        return;
    }

    LOGD("Handler::SendMessageDelayed msg:%{public}d", msg->GetMessageName());
    long delayTime = delayMillis;
    if (delayTime < 0) {
        delayTime = 0;
    }

    /* Obtains the current time, accurate to milliseconds. */
    struct timeval curTime = {0, 0};
    if (gettimeofday(&curTime, nullptr) != 0) {
        LOGE("gettimeofday failed.\n");
        return;
    }
    long nowTime = curTime.tv_sec * USEC_1000 + curTime.tv_usec / USEC_1000;

    SendMessageAtTime(msg, nowTime + delayTime);
    return;
}

void Handler::SendMessageAtTime(InternalMessage *msg, long uptimeMillis)
{
    if (msg == nullptr) {
        LOGE("Handler::SendMessageAtTime: msg is null.");
        return;
    }

    LOGD("Handler::SendMessageAtTime msg: %{public}d", msg->GetMessageName());
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        return;
    }

    if (pMyQueue->AddMessageToQueue(msg, uptimeMillis) != true) {
        LOGE("AddMessageToQueue failed.\n");
        return;
    }

    return;
}

void Handler::SendMessageAtFrontOfQueue(InternalMessage *msg)
{
    if (msg == nullptr) {
        LOGE("Handler::SendMessageAtFrontOfQueue: msg is null.");
        return;
    }

    LOGD("Handler::SendMessageAtFrontOfQueue msg: %{public}d", msg->GetMessageName());
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        return;
    }

    if (!pMyQueue->AddMessageToQueue(msg, 0)) {
        LOGE("AddMessageToQueue failed.\n");
        return;
    }

    return;
}

void Handler::DeleteMessageFromQueue(int messageName)
{
    LOGD("Handler::DeleteMessageFromQueue msg is: %{public}d", messageName);
    if (pMyQueue == nullptr) {
        LOGE("pMyQueue is null.\n");
        return;
    }

    if (!pMyQueue->DeleteMessageFromQueue(messageName)) {
        LOGE("DeleteMessageFromQueue failed.\n");
        return;
    }

    return;
}

void Handler::DispatchMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    HandleMessage(msg);
    return;
}
}  // namespace Wifi
}  // namespace OHOS