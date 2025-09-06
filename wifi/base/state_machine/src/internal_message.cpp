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
      mParam1(0),
      mParam2(0),
      pNextMsg(nullptr),
      mHandleTime(0)
{}

InternalMessage::~InternalMessage()
{
}

int InternalMessage::GetMessageName() const
{
    return mMsgName;
}

int InternalMessage::GetParam1() const
{
    return mParam1;
}

int InternalMessage::GetParam2() const
{
    return mParam2;
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

InternalMessagePtr InternalMessage::GetNextMsg() const
{
    return pNextMsg;
}

int64_t InternalMessage::GetHandleTime() const
{
    return mHandleTime;
}

void InternalMessage::SetMessageName(int msgName)
{
    mMsgName = msgName;
    return;
}

void InternalMessage::SetParam1(int param1)
{
    mParam1 = param1;
    return;
}

void InternalMessage::SetParam2(int param2)
{
    mParam2 = param2;
    return;
}

void InternalMessage::ReleaseMessageObj()
{
    mMessageObj.reset();
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

void InternalMessage::SetNextMsg(InternalMessagePtr nextMsg)
{
    pNextMsg = nextMsg;
    return;
}

void InternalMessage::SetHandleTime(int64_t time)
{
    mHandleTime = time;
    return;
}

void InternalMessage::PrintMsg(const std::string prefix)
{
    switch (msgLogLevel_) {
        case MsgLogLevel::LOG_D:
            LOGD("%{public}s ExecuteMessage msg:%{public}d", prefix.c_str(), mMsgName);
            break;
        case MsgLogLevel::LOG_I:
            LOGI("%{public}s ExecuteMessage msg:%{public}d", prefix.c_str(), mMsgName);
            break;
        case MsgLogLevel::LOG_W:
            LOGW("%{public}s ExecuteMessage msg:%{public}d", prefix.c_str(), mMsgName);
            break;
        case MsgLogLevel::LOG_E:
            LOGE("%{public}s ExecuteMessage msg:%{public}d", prefix.c_str(), mMsgName);
            break;
        default:
            break;
    }
}

std::unique_ptr<MessageManage> MessageManage::msgManage;

MessageManage &MessageManage::GetInstance()
{
    if (msgManage.get() == nullptr) {
        msgManage = std::make_unique<MessageManage>();
    }
    return *msgManage;
}

MessageManage::MessageManage()
{}

MessageManage::~MessageManage()
{}

InternalMessagePtr MessageManage::CreateMessage()
{
    auto pMessage = std::make_shared<InternalMessage>();
    return pMessage;
}

InternalMessagePtr MessageManage::CreateMessage(const InternalMessagePtr orig)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(orig->GetMessageName());
    m->SetParam1(orig->GetParam1());
    m->SetParam2(orig->GetParam2());
    m->SetMessageObj(orig->GetMessageObj());
    m->CopyMessageBody(orig->GetMessageBody());
    m->msgLogLevel_ = orig->msgLogLevel_;
    return m;
}

InternalMessagePtr MessageManage::CreateMessage(int messageName)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(messageName);
    return m;
}

InternalMessagePtr MessageManage::CreateMessage(int messageName, const std::any &messageObj)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(messageName);

    m->SetMessageObj(messageObj);
    return m;
}

InternalMessagePtr MessageManage::CreateMessage(int messageName, int param1, int param2)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(messageName);
    m->SetParam1(param1);
    m->SetParam2(param2);
    return m;
}

InternalMessagePtr MessageManage::CreateMessage(int messageName, int param1, int param2, const std::any &messageObj)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(messageName);
    m->SetParam1(param1);
    m->SetParam2(param2);
    m->SetMessageObj(messageObj);
    return m;
}

void MessageManage::ReclaimMsg(InternalMessagePtr m)
{
    if (m == nullptr) {
        return;
    }

    m->SetMessageName(0);
    m->SetParam1(0);
    m->SetParam2(0);
    m->ReleaseMessageObj();
    m->ClearMessageBody();
    m = nullptr;
    return;
}
}  // namespace Wifi
}  // namespace OHOS