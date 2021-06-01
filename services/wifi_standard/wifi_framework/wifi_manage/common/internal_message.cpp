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
#include "internal_message.h"
#include "securec.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_INTERNAL_MESSAGE"

namespace OHOS {
namespace Wifi {
void MessageBody::SaveIntData(int data)
{
    intArray_.push_back(data);
    return;
}

void MessageBody::SaveStringData(std::string data)
{
    stringArray_.push_back(data);
    return;
}

int MessageBody::GetIntData()
{
    if (intArray_.empty()) {
        LOGE("intArray is null.");
        return 0;
    }

    int tmp = intArray_.front();
    intArray_.pop_front();
    return tmp;
}

std::string MessageBody::GetStringData()
{
    std::string tmp;
    if (stringArray_.empty()) {
        LOGE("stringArray is null.");
        return tmp;
    }

    tmp = stringArray_.front();
    stringArray_.pop_front();
    return tmp;
}

void MessageBody::ClearAllData()
{
    intArray_.clear();
    stringArray_.clear();
    return;
}

void MessageBody::CopyMessageBody(const MessageBody &origBody)
{
    intArray_.assign(origBody.intArray_.begin(), origBody.intArray_.end());
    stringArray_.assign(origBody.stringArray_.begin(), origBody.stringArray_.end());

    return;
}

InternalMessage::InternalMessage()
    : mMsgName(0),
      mArg1(0),
      mArg2(0),
      pMessageObj(nullptr),
      mObjSize(0),
      pReplyTo(nullptr),
      mSendingUid(0),
      pNext(nullptr),
      mWhen(0)
{}

InternalMessage::~InternalMessage()
{
    if (pMessageObj != nullptr) {
        delete[] pMessageObj;
        pMessageObj = nullptr;
    }

    return;
}

int InternalMessage::GetMessageName() const
{
    return mMsgName;
}

int InternalMessage::GetArg1() const
{
    return mArg1;
}

int InternalMessage::GetArg2() const
{
    return mArg2;
}

const char *InternalMessage::GetMessageObj() const
{
    return pMessageObj;
}

int InternalMessage::GetObjSize() const
{
    return mObjSize;
}

int InternalMessage::GetIntFromMessage()
{
    return mMessageBody.GetIntData();
}

std::string InternalMessage::GetStringFromMessage()
{
    return mMessageBody.GetStringData();
}

const MessageBody &InternalMessage::GetMessageBody() const
{
    return mMessageBody;
}

void InternalMessage::CopyMessageBody(const MessageBody &origBody)
{
    mMessageBody.CopyMessageBody(origBody);
    return;
}

InternalMessage *InternalMessage::GetReplyTo() const
{
    return pReplyTo;
}

int InternalMessage::GetSendingUid() const
{
    return mSendingUid;
}

InternalMessage *InternalMessage::GetNext() const
{
    return pNext;
}

long InternalMessage::GetWhen() const
{
    return mWhen;
}

void InternalMessage::SetMessageName(int msgName)
{
    mMsgName = msgName;
    return;
}

void InternalMessage::SetArg1(int arg1)
{
    mArg1 = arg1;
    return;
}

void InternalMessage::SetArg2(int arg2)
{
    mArg2 = arg2;
    return;
}

void InternalMessage::ReleaseMessageObj()
{
    if (pMessageObj != nullptr) {
        delete[] pMessageObj;
        pMessageObj = nullptr;
        mObjSize = 0;
    }
    return;
}

void InternalMessage::AddIntMessageBody(int data)
{
    mMessageBody.SaveIntData(data);
    return;
}

void InternalMessage::AddStringMessageBody(std::string data)
{
    mMessageBody.SaveStringData(data);
    return;
}

void InternalMessage::ClearMessageBody()
{
    mMessageBody.ClearAllData();
    return;
}

void InternalMessage::SetReplyTo(InternalMessage *replyTo)
{
    pReplyTo = replyTo;
    return;
}

void InternalMessage::SetSendingUid(int sendingUid)
{
    mSendingUid = sendingUid;
    return;
}

void InternalMessage::SetNext(InternalMessage *next)
{
    pNext = next;
    return;
}

void InternalMessage::SetWhen(long when)
{
    mWhen = when;
    return;
}

std::unique_ptr<MessageManage> MessageManage::msgManage;

MessageManage &MessageManage::GetInstance()
{
    if (msgManage.get() == nullptr) {
        msgManage = std::make_unique<MessageManage>();
    }
    return *msgManage;
}

MessageManage::MessageManage() : MAX_POOL_SIZE(MAX_POOL_SIZE_INIT), pSPool(nullptr), pSPoolSize(0)
{}

MessageManage::~MessageManage()
{
    ReleasePool();
    return;
}

InternalMessage *MessageManage::Obtain()
{
    {
        std::unique_lock<std::mutex> lock(mPoolMutex);
        if (pSPool != nullptr) {
            InternalMessage *m = pSPool;
            pSPool = m->GetNext();
            m->SetNext(nullptr);
            pSPoolSize--;
            return m;
        }
    }

    auto pMessage = new InternalMessage();
    return pMessage;
}

InternalMessage *MessageManage::Obtain(const InternalMessage *orig)
{
    InternalMessage *m = Obtain();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(orig->GetMessageName());
    m->SetArg1(orig->GetArg1());
    m->SetArg2(orig->GetArg2());
    m->CopyMessageBody(orig->GetMessageBody());
    m->SetReplyTo(orig->GetReplyTo());
    m->SetSendingUid(orig->GetSendingUid());

    return m;
}

InternalMessage *MessageManage::Obtain(int messageName)
{
    InternalMessage *m = Obtain();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(messageName);
    return m;
}

InternalMessage *MessageManage::Obtain(int messageName, int arg1, int arg2)
{
    InternalMessage *m = Obtain();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(messageName);
    m->SetArg1(arg1);
    m->SetArg2(arg2);
    return m;
}

void MessageManage::Recycle(InternalMessage *m)
{
    if (m == nullptr) {
        return;
    }

    m->SetMessageName(0);
    m->SetArg1(0);
    m->SetArg2(0);
    m->ReleaseMessageObj();
    m->ClearMessageBody();
    m->SetReplyTo(nullptr);
    m->SetSendingUid(-1);

    {
        std::unique_lock<std::mutex> lock(mPoolMutex);
        if (pSPoolSize < MAX_POOL_SIZE) {
            m->SetNext(pSPool);
            pSPool = m;
            pSPoolSize++;
            return;
        }
    }

    delete m;
    return;
}

void MessageManage::ReleasePool()
{
    std::unique_lock<std::mutex> lock(mPoolMutex);
    InternalMessage *current = pSPool;
    InternalMessage *next = nullptr;
    while (current != nullptr) {
        next = current->GetNext();
        delete current;
        current = next;
    }

    return;
}
}  // namespace Wifi
}  // namespace OHOS