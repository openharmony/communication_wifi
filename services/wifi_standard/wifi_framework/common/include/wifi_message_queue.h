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

#ifndef OHOS_WIFI_MESSAGE_QUEUE_H
#define OHOS_WIFI_MESSAGE_QUEUE_H

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>

namespace OHOS {
namespace Wifi {
template<typename MsgInfo>
class WifiMessageQueue {
public:
    /**
     * @Description Pushes message into the queue
     *
     * @param msg - input message struct
     */
    void Push(const MsgInfo &msg);

    /**
     * @Description Pop a message from the queue
     *
     * @param msg - output message struct
     * @return int - 0 Success
     */
    int Pop(MsgInfo &msg);

    /**
     * @Description Current message queue empty or not
     *
     * @return true - empty
     * @return false - not empty
     */
    bool Empty();

private:
    std::deque<MsgInfo> mQue;
    std::mutex mMutex;
    std::condition_variable mCondition;
};

template<typename MsgInfo>
void WifiMessageQueue<MsgInfo>::Push(const MsgInfo &msg)
{
    {
        std::unique_lock<std::mutex> lock(mMutex);
        mQue.push_back(msg);
    }
    mCondition.notify_one();
}

template<typename MsgInfo>
int WifiMessageQueue<MsgInfo>::Pop(MsgInfo &msg)
{
    while (true) {
        std::unique_lock<std::mutex> lock(mMutex);
        while (mQue.empty()) {
            mCondition.wait(lock);
        }
        msg = mQue.front();
        mQue.pop_front();
        break;
    }
    return 0;
}

template<typename MsgInfo>
bool WifiMessageQueue<MsgInfo>::Empty()
{
    std::unique_lock<std::mutex> lock(mMutex);
    return mQue.empty();
}
}  // namespace Wifi
}  // namespace OHOS
#endif