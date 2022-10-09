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
#include <sys/time.h>
#include <thread>
#include "wifi_errcode.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_MESSAGE_QUEUE"

namespace OHOS {
namespace Wifi {
MessageQueue::MessageQueue() : pMessageQueue(nullptr), mIsBlocked(false), mNeedQuit(false), mWakeup(false)
{
    LOGI("MessageQueue::MessageQueue");
}

MessageQueue::~MessageQueue()
{
    LOGI("MessageQueue::~MessageQueue");
    /* Releasing Messages in a Queue */
    std::unique_lock<std::mutex> lock(mMtxQueue);
    InternalMessage *current = pMessageQueue;
    InternalMessage *next = nullptr;
    while (current != nullptr) {
        next = current->GetNextMsg();
        delete current;
        current = next;
    }
    return;
}

bool MessageQueue::WakeupOrKeepOriginalValue()
{
    return mIsBlocked ? mIsBlocked : mWakeup;
}

bool MessageQueue::AddMessageToQueue(InternalMessage *message, int64_t handleTime)
{
    if (message == nullptr) {
        LOGE("message is null.");
        return false;
    }
    LOGI("MessageQueue::AddMessageToQueue: %{public}d", message->GetMessageName());
    if (mNeedQuit) {
        MessageManage::GetInstance().ReclaimMsg(message);
        LOGE("Already quit the message queue.");
        return false;
    }

    message->SetHandleTime(handleTime);
    /*
     * If the queue is empty, the current message needs to be executed
     * immediately, or the execution time is earlier than the queue header, the
     * message is placed in the queue header and is woken up when the queue is
     * blocked.
     */
    {
        std::unique_lock<std::mutex> lck(mMtxQueue);
        InternalMessage *pTop = pMessageQueue;
        if (pTop == nullptr || handleTime == 0 || handleTime < pTop->GetHandleTime()) {
            message->SetNextMsg(pTop);
            pMessageQueue = message;
            mWakeup = WakeupOrKeepOriginalValue();
        } else {
            InternalMessage *pPrev = nullptr;
            InternalMessage *pCurrent = pTop;
            /* If the inserted message is executed earlier(In the head position), the thread needs to be awakened */
            if (handleTime <= pTop->GetHandleTime()) {
                mWakeup = WakeupOrKeepOriginalValue();
            }
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

    LOGI("Add message needWake: %{public}d", static_cast<int>(mWakeup.load()));
    /* Wake up the process. */
    if (mWakeup) {
        mCvQueue.notify_all();
        mIsBlocked = false;
    }
    return true;
}

bool MessageQueue::DeleteMessageFromQueue(int messageName)
{
    LOGI("MessageQueue::DeleteMessageFromQueue");
    std::unique_lock<std::mutex> lck(mMtxQueue);
    InternalMessage *pTop = pMessageQueue;
    if (pTop == nullptr) {
        return true;
    }

    InternalMessage *pCurrent = pTop;
    while (pCurrent != nullptr) {
        InternalMessage *pPrev = pCurrent;
        pCurrent = pCurrent->GetNextMsg();
        if ((pCurrent != nullptr) && (pCurrent->GetMessageName() == messageName)) {
            InternalMessage *pNextMsg = pCurrent->GetNextMsg();
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

InternalMessage *MessageQueue::GetNextMessage()
{
    LOGI("MessageQueue::GetNextMessage");
    int nextBlockTime = 0;

    while (!mNeedQuit) {
        /* Obtains the current time, accurate to milliseconds. */
        struct timeval curTime = {0, 0};
        if (gettimeofday(&curTime, nullptr) != 0) {
            LOGE("gettimeofday failed.");
            return nullptr;
        }

        int64_t nowTime = static_cast<int64_t>(curTime.tv_sec) * TIME_USEC_1000 + curTime.tv_usec / TIME_USEC_1000;
        {
            std::unique_lock<std::mutex> lck(mMtxQueue); // Data queue lock
            InternalMessage *curMsg = pMessageQueue;
            mIsBlocked = true;
            if (curMsg != nullptr) {
                if (nowTime < curMsg->GetHandleTime()) {
                    /* The execution time of the first message is not reached.
                        The remaining time is blocked here. */
                    nextBlockTime = curMsg->GetHandleTime() - nowTime;
                } else {
                    /* Get the message of queue header. */
                    mWakeup = false;
                    mIsBlocked = false;
                    pMessageQueue = curMsg->GetNextMsg();
                    curMsg->SetNextMsg(nullptr);
                    LOGI("Get queue message: %{public}d", curMsg->GetMessageName());
                    return curMsg;
                }
            } else {
                /* If there's no message, check it every 30 seconds. */
                nextBlockTime = TIME_INTERVAL;
            }
        }

        std::unique_lock<std::mutex> lck(mMtxBlock); // mCvQueue lock
        if (mIsBlocked && (!mNeedQuit) && (!mWakeup)) {
            LOGI("mCvQueue wait_for: %{public}d", nextBlockTime);
            if (mCvQueue.wait_for(lck, std::chrono::milliseconds(nextBlockTime)) == std::cv_status::timeout) {
                LOGI("mCvQueue wake up, reason: cv_status::timeout.");
            } else {
                LOGI("mCvQueue is wake up.");
            }
        }
        mWakeup = false;
        mIsBlocked = false;
    }
    LOGE("Already quit the message queue.");
    return nullptr;
}

void MessageQueue::StopQueueLoop()
{
    LOGI("Start stop queue loop.");
    mNeedQuit = true;
    while (mIsBlocked) {
        mNeedQuit = true;
        mCvQueue.notify_all();
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // sleep 1 ms
    }
    LOGI("Queue loop has stopped.");
}
}  // namespace Wifi
}  // namespace OHOS
