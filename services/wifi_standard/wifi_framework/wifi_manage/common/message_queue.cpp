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
#include "message_queue.h"
#include <sys/time.h>
#include "wifi_log.h"
#include "wifi_errcode.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_MESSAGE_QUEUE"

namespace OHOS {
namespace Wifi {
MessageQueue::MessageQueue() : pMessageQueue(nullptr), mIsBlocked(false), mNeedQuit(false)
{}

MessageQueue::~MessageQueue()
{
    LOGI("MessageQueue::~MessageQueue");
    /* Releasing Messages in a Queue */
    std::unique_lock<std::mutex> lock(mMtxQueue);
    InternalMessage *current = pMessageQueue;
    InternalMessage *next = nullptr;
    while (current != nullptr) {
        next = current->GetNext();
        delete current;
        current = next;
    }

    return;
}

bool MessageQueue::AddMessageToQueue(InternalMessage *message, long when)
{
    if (message == nullptr) {
        LOGE("message is null.\n");
        return false;
    }

    if (mNeedQuit) {
        MessageManage::GetInstance().Recycle(message);
        LOGE("Already quit the message queue.\n");
        return false;
    }

    message->SetWhen(when);
    bool needWake = false;
    /*
     * If the queue is empty, the current message needs to be executed
     * immediately, or the execution time is earlier than the queue header, the
     * message is placed in the queue header and is woken up when the queue is
     * blocked.
     */
    {
        std::unique_lock<std::mutex> lck(mMtxQueue);
        InternalMessage *pTop = pMessageQueue;
        if (pTop == nullptr || when == 0 || when < pTop->GetWhen()) {
            message->SetNext(pTop);
            pMessageQueue = message;
            needWake = mIsBlocked;
            /* Inserts messages in the middle of the queue based on the execution time. */
        } else {
            InternalMessage *pPrev = nullptr;
            InternalMessage *pCurrent = pTop;
            while (pCurrent != nullptr) {
                pPrev = pCurrent;
                pCurrent = pCurrent->GetNext();
                if (pCurrent == nullptr || when < pCurrent->GetWhen()) {
                    message->SetNext(pCurrent);
                    pPrev->SetNext(message);
                    break;
                }
            }
        }
    }

    /* Wake up the process. */
    if (needWake) {
        std::unique_lock<std::mutex> lck(mMtxBlock);
        mCvQueue.notify_all();
    }

    return true;
}

bool MessageQueue::DeleteMessageFromQueue(int messageName)
{
    std::unique_lock<std::mutex> lck(mMtxQueue);

    InternalMessage *pTop = pMessageQueue;
    if (pTop == nullptr) {
        return true;
    }

    InternalMessage *pCurrent = pTop;
    while (pCurrent != nullptr) {
        InternalMessage *pPrev = pCurrent;
        pCurrent = pCurrent->GetNext();
        if ((pCurrent != nullptr) && (pCurrent->GetMessageName() == messageName)) {
            InternalMessage *pNext = pCurrent->GetNext();
            pPrev->SetNext(pNext);
            MessageManage::GetInstance().Recycle(pCurrent);
            pCurrent = pNext;
        }
    }

    if (pTop->GetMessageName() == messageName) {
        pMessageQueue = pTop->GetNext();
        MessageManage::GetInstance().Recycle(pTop);
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
            LOGE("gettimeofday failed.\n");
            return nullptr;
        }
        long nowTime = curTime.tv_sec * TIME_USEC_1000 + curTime.tv_usec / TIME_USEC_1000;

        {
            std::unique_lock<std::mutex> lck(mMtxQueue);
            InternalMessage *curMsg = pMessageQueue;
            if (curMsg != nullptr) {
                if (nowTime < curMsg->GetWhen()) {
                    /* The execution time of the first message is not reached.
                       The remaining time is blocked here. */
                    nextBlockTime = curMsg->GetWhen() - nowTime;
                } else {
                    /* Return the first message. */
                    mIsBlocked = false;
                    pMessageQueue = curMsg->GetNext();
                    curMsg->SetNext(nullptr);
                    return curMsg;
                }
            } else {
                /* If there's no message, check it every 30 seconds. */
                nextBlockTime = TIME_INTERVAL;
            }
        }

        mIsBlocked = true;
        std::unique_lock<std::mutex> lck(mMtxBlock);
        if (mCvQueue.wait_for(lck, std::chrono::milliseconds(nextBlockTime)) == std::cv_status::timeout) {
            LOGD("mCvQueue timeout.\n");
        } else {
            LOGD("Wake up.\n");
        }
        mIsBlocked = false;
    }

    LOGE("Already quit the message queue.\n");
    return nullptr;
}

void MessageQueue::StopQueueLoop()
{
    mNeedQuit = true;
    if (mIsBlocked) {
        std::unique_lock<std::mutex> lck(mMtxBlock);
        mCvQueue.notify_all();
    }

    return;
}
}  // namespace Wifi
}  // namespace OHOS