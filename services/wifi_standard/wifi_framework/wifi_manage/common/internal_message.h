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

#ifndef OHOS_INTERNAL_MESSAGE_H
#define OHOS_INTERNAL_MESSAGE_H

#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <string>

namespace OHOS {
namespace Wifi {
const int MAX_POOL_SIZE_INIT = 50;
class MessageBody {
public:
    /**
     * @Description : Save an Integer Data.
     *
     * @param data - Integer Data.[in]
     */
    void SaveIntData(int data);

    /**
     * @Description : Save a String Data.
     *
     * @param data - String Data.[in]
     */
    void SaveStringData(std::string data);

    /**
     * @Description : Get an Integer Data.
     *
     * @return int
     */
    int GetIntData();

    /**
     * @Description : Get a String Data.
     *
     * @return std::string
     */
    std::string GetStringData();

    /**
     * @Description : Clear all Data.
     *
     */
    void ClearAllData();

    /**
     * @Description : Copy a message body.
     *
     * @param origBody - Source Message Body.[in]
     */
    void CopyMessageBody(const MessageBody &origBody);

    /* Integer data. */
    std::list<int> intArray_;
    /* String data. */
    std::list<std::string> stringArray_;
};

class InternalMessage {
public:
    /**
     * @Description : Construct a new Internal Message object.
     *
     */
    InternalMessage();

    /**
     * @Description Destroy the Internal Message object.
     *
     */
    ~InternalMessage();

    /**
     * @Description : Get message name.
     *
     * @return int
     */
    int GetMessageName() const;

    /**
     * @Description : Obtains the first parameter in the message body.
     *
     * @return int
     */
    int GetArg1() const;

    /**
     * @Description : Obtains the second parameter in the message body.
     *
     * @return int
     */
    int GetArg2() const;

    /**
     * @Description : Obtains the message object.
     *
     * @return char*
     */
    const char *GetMessageObj() const;

    /**
     * @Description : Obtains the object size.
     *
     * @return int
     */
    int GetObjSize() const;

    /**
     * @Description : Obtains Integer data from message.
     *
     * @return int
     */
    int GetIntFromMessage();

    /**
     * @Description : Obtains Sting data from message.
     *
     * @return std::string
     */
    std::string GetStringFromMessage();

    /**
     * @Description : Obtains message body.
     *
     * @return MessageBody&
     */
    const MessageBody &GetMessageBody() const;

    /**
     * @Description : Copy message body.
     *
     * @param origBody - Source Message Body.[in]
     */
    void CopyMessageBody(const MessageBody &origBody);

    /**
     * @Description : Get reply.
     *
     * @return InternalMessage*
     */
    InternalMessage *GetReplyTo() const;

    /**
     * @Description ： Get sending uid.
     *
     * @return int
     */
    int GetSendingUid() const;

    /**
     * @Description : Get next message.
     *
     * @return InternalMessage*
     */
    InternalMessage *GetNext() const;

    /**
     * @Description : Obtains time.
     *
     * @return long
     */
    long GetWhen() const;

    /**
     * @Description : Set message name.
     *
     * @param msgName - Message name.[in]
     */
    void SetMessageName(int msgName);

    /**
     * @Description : Set the first parameter in the message body.
     *
     * @param arg1 - The first parameter.[in]
     */
    void SetArg1(int arg1);

    /**
     * @Description : Set the second parameter in the message body.
     *
     * @param arg2 - The second parameter.[in]
     */
    void SetArg2(int arg2);

    /**
     * @Description : Release Message Object.
     *
     */
    void ReleaseMessageObj();

    /**
     * @Description : Add integer message body.
     *
     * @param data - Integer data.[in]
     */
    void AddIntMessageBody(int data);

    /**
     * @Description : Add string message body.
     *
     * @param data - String data.[in]
     */
    void AddStringMessageBody(std::string data);

    /**
     * @Description : Clear message body.
     *
     */
    void ClearMessageBody();

    /**
     * @Description : Set reply message pointer.
     *
     * @param replyTo - reply meassage pointer.[in]
     */
    void SetReplyTo(InternalMessage *replyTo);

    /**
     * @Description : Sets the UID to be sent.
     *
     * @param sendingUid - UID to be sent.[in]
     */
    void SetSendingUid(int sendingUid);

    /**
     * @Description : Sets next message.
     *
     * @param next - The next message.[in]
     */
    void SetNext(InternalMessage *next);

    /**
     * @Description : Set the time.
     *
     * @param when - Time.[in]
     */
    void SetWhen(long when);

    /* Message Name */
    int mMsgName;
    /* Parameter 1 */
    int mArg1;
    /* Parameter 2 */
    int mArg2;
    /* Message body, which can be empty and can be directly copied. */
    char *pMessageObj;
    /* Message bodies that cannot be directly copied */
    MessageBody mMessageBody;
    /* Message body length */
    int mObjSize;
    /* Replying to a Message */
    InternalMessage *pReplyTo;
    /* Sender UID */
    int mSendingUid;
    /* Next message in the resource pool or message queue */
    InternalMessage *pNext;
    /* Message execution time */
    long mWhen;
};
class MessageManage {
public:
    /**
     * @Description : Obtains a single instance.
     *
     * @return MessageManage&
     */
    static MessageManage &GetInstance();

    /**
     * @Description : Message obtaining function.
     *
     * @return InternalMessage*
     */
    InternalMessage *Obtain();

    /**
     * @Description : Obtain original messages.
     *
     * @param orig - Original messages.[in]
     * @return InternalMessage*
     */
    InternalMessage *Obtain(const InternalMessage *orig);

    /**
     * @Description : Obtains the message name.
     *
     * @param messageName - Message name.[in]
     * @return InternalMessage*
     */
    InternalMessage *Obtain(int messageName);

    /**
     * @Description : Obtaining Message Information.
     *
     * @param messageName - Message name.[in]
     * @param arg1 - arg1.[in]
     * @param arg2 - arg2.[in]
     * @return InternalMessage*
     */
    InternalMessage *Obtain(int messageName, int arg1, int arg2);

    /**
     * @Description :Recycle message.
     *
     * @param m - message.[in]
     */
    void Recycle(InternalMessage *m);

    /**
     * @Description : Release pool.
     *
     */

    void ReleasePool();

    /**
     * @Description : Construct a new Message Manage object.
     *
     */
    MessageManage();

    /**
     * @Description : Destroy the Message Manage object.
     *
     */
    ~MessageManage();

private:
    /* Maximum number of messages in the message resource pool */
    const int MAX_POOL_SIZE;
    /* Message resource pool */
    InternalMessage *pSPool;
    /* Number of messages in the message resource pool */
    int pSPoolSize;
    /* Mutex for operating the message resource pool */
    std::mutex mPoolMutex;
    static std::unique_ptr<MessageManage> msgManage;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
