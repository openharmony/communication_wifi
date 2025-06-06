/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "message_queue.h"
#include <cinttypes>
#include <sys/time.h>
#include <thread>
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_MESSAGE_QUEUE"

namespace OHOS {
namespace Wifi {
MessageQueue::MessageQueue() : pMessageQueue(nullptr), mIsBlocked(false), mNeedQuit(false)
{
    LOGI("MessageQueue");
}

MessageQueue::~MessageQueue()
{
    LOGI("~MessageQueue");
    /* Releasing Messages in a Queue */
    std::unique_lock<std::mutex> lock(mMtxQueue);
    InternalMessagePtr current = pMessageQueue;
    InternalMessagePtr next = nullptr;
    while (current != nullptr) {
        next = current->GetNextMsg();
        current = nullptr;
        current = next;
    }
    return;
}

bool MessageQueue::AddMessageToQueue(InternalMessagePtr message, int64_t handleTime)
{
    if (message == nullptr) {
        LOGE("message is null.");
        return false;
    }

    LOGD("AddMessageToQueue, msg: %{public}d, timestamp:%" PRId64 "\n",
        message->GetMessageName(), handleTime);

    if (mNeedQuit) {
        MessageManage::GetInstance().ReclaimMsg(message);
        LOGE("Already quit the message queue.");
        return false;
    }

    message->SetHandleTime(handleTime);
    bool mNeedWakeup = false;
    /*
     * If the queue is empty, the current message needs to be executed
     * immediately, or the execution time is earlier than the queue header, the
     * message is placed in the queue header and is woken up when the queue is
     * blocked.
     */
    {
        std::unique_lock<std::mutex> lck(mMtxQueue);
        InternalMessagePtr pTop = pMessageQueue;
        if (pTop == nullptr || handleTime == 0 || handleTime <= pTop->GetHandleTime()) {
            LOGD("Add the message in the head of queue.");
            message->SetNextMsg(pTop);
            pMessageQueue = message;
            mNeedWakeup = mIsBlocked;
        } else {
            LOGD("Insert the message in the middle of the queue.");
            InternalMessagePtr pPrev = nullptr;
            InternalMessagePtr pCurrent = pTop;
            /* Inserts messages in the middle of the queue based on the execution time. */
            while (pCurrent != nullptr) {
                pPrev = pCurrent;
                pCurrent = pCurrent->GetNextMsg();
                if (pCurrent == nullptr || handleTime < pCurrent->GetHandleTime()) {
                    message->SetNextMsg(pCurrent);
                    pPrev->SetNextMsg(message);
                    break;
                }
            }
        }
    }

    LOGD("Add message needWakeup: %{public}d", static_cast<int>(mNeedWakeup));
    if (mNeedWakeup) {
        mIsBlocked = false;
    }
    /* Wake up the process. */
    mCvQueue.notify_one();
    return true;
}

bool MessageQueue::DeleteMessageFromQueue(int messageName)
{
    std::unique_lock<std::mutex> lck(mMtxQueue);
    InternalMessagePtr pTop = pMessageQueue;
    if (pTop == nullptr) {
        return true;
    }

    InternalMessagePtr pCurrent = pTop;
    while (pCurrent != nullptr) {
        InternalMessagePtr pPrev = pCurrent;
        pCurrent = pCurrent->GetNextMsg();
        if ((pCurrent != nullptr) && (pCurrent->GetMessageName() == messageName)) {
            InternalMessagePtr pNextMsg = pCurrent->GetNextMsg();
            pPrev->SetNextMsg(pNextMsg);
            MessageManage::GetInstance().ReclaimMsg(pCurrent);
            pCurrent = pNextMsg;
        }
    }

    if (pTop->GetMessageName() == messageName) {
        pMessageQueue = pTop->GetNextMsg();
        MessageManage::GetInstance().ReclaimMsg(pTop);
    }
    return true;
}

InternalMessagePtr MessageQueue::GetNextMessage()
{
    LOGD("GetNextMessage");
    int nextBlockTime = 0;

    while (!mNeedQuit) {
        /* Obtains the current time, accurate to milliseconds. */
        struct timespec curTime = {0, 0};
        if (clock_gettime(CLOCK_BOOTTIME, &curTime) != 0) {
            LOGE("clock_gettime failed.");
            return nullptr;
        }

        int64_t nowTime = static_cast<int64_t>(curTime.tv_sec) * TIME_USEC_1000 +
            curTime.tv_nsec / (TIME_USEC_1000 * TIME_USEC_1000);
        {
            std::unique_lock<std::mutex> lck(mMtxQueue); // Data queue lock
            InternalMessagePtr curMsg = pMessageQueue;
            mIsBlocked = true;
            if (curMsg != nullptr) {
                LOGD("Message queue is not empty.");
                if (nowTime < curMsg->GetHandleTime()) {
                    /* The execution time of the first message is not reached.
                        The remaining time is blocked here. */
                    nextBlockTime = curMsg->GetHandleTime() - nowTime;
                } else {
                    /* Get the message of queue header. */
                    mIsBlocked = false;
                    pMessageQueue = curMsg->GetNextMsg();
                    curMsg->SetNextMsg(nullptr);
                    LOGD("Get queue message: %{public}d", curMsg->GetMessageName());
                    return curMsg;
                }
            } else {
                /* If there's no message, check it every 30 seconds. */
                nextBlockTime = WIFI_TIME_INTERVAL;
            }
        }

        if (mIsBlocked && (!mNeedQuit)) {
            std::mutex mtxBlock;
            std::unique_lock<std::mutex> lck(mtxBlock); // mCvQueue lock
            LOGD("mCvQueue wait_for: %{public}d", nextBlockTime);
            if (mCvQueue.wait_for(lck, std::chrono::milliseconds(nextBlockTime)) == std::cv_status::timeout) {
                LOGD("mCvQueue wake up, reason: cv_status::timeout: %{public}d", nextBlockTime);
            } else {
                LOGD("mCvQueue is wake up.");
            }
        }
        mIsBlocked = false;
    }
    LOGE("Already quit the message queue.");
    return nullptr;
}

void MessageQueue::StopQueueLoop()
{
    LOGI("Start stop queue loop.");
    mNeedQuit = true;
    if (mIsBlocked) {
        mIsBlocked = false;
    }
    mCvQueue.notify_one();
    LOGI("Queue loop has stopped.");
}
}  // namespace Wifi
}  // namespace OHOS
