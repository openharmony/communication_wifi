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

#ifndef OHOS_BASE_SERVICE_H
#define OHOS_BASE_SERVICE_H

#include "wifi_internal_msg.h"
#include "wifi_message_queue.h"

namespace OHOS {
namespace Wifi {
class BaseService {
public:
    /**
     * @Description Destroy the Base Service object
     *
     */
    virtual ~BaseService()
    {}

    /**
     * @Description Enables and initializes the feature service and transfers the upstream
     *              message queue
     *
     * @param mqUp - WifiMessageQueue<WifiResponseMsgInfo>
     * @return int
     */
    virtual int Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp) = 0;

    /**
     * @Description send messages to feature service
     *
     * @param msg - WifiRequestMsgInfo object's pointer
     * @return int
     */
    virtual int PushMsg(WifiRequestMsgInfo *msg) = 0;

    /**
     * @Description Closes and unloads the feature service
     *
     * @return int
     */
    virtual int UnInit(void) = 0;
};

#define DECLARE_INIT_SERVICE(SERVICE)   \
    extern "C" SERVICE *Create()        \
    {                                   \
        return new SERVICE();           \
    }                                   \
    extern "C" void Destroy(SERVICE *p) \
    {                                   \
        delete p;                       \
    }
}  // namespace Wifi
}  // namespace OHOS
#endif