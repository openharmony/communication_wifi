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

#ifndef OHOS_WIFI_NET_CHECK_H
#define OHOS_WIFI_NET_CHECK_H

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <vector>
#include "http_request.h"
#include "sta_define.h"
#include "wifi_errcode.h"
#include "wifi_log.h"

#define DEFAULT_PORTAL_HTTPS_URL ""

namespace OHOS {
namespace Wifi {
class StaNetworkCheck {
    FRIEND_GTEST(StaNetworkCheck);
public:
    explicit StaNetworkCheck(NetStateHandler handle);
    virtual ~StaNetworkCheck();
    /**
     * @Description : Start NetCheck thread
     *
     * @Return success : WIFI_OPT_SUCCESS  failed : WIFI_OPT_FAILED
     */
    virtual ErrCode InitNetCheckThread();
    /**
     * @Description : wake up the DHCP processing thread.
     *
     * @param ipType - Type of IP to be obtained [in]
     */
    virtual void SignalNetCheckThread();
    /**
     * @Description : stop the NetCheck processing thread.
     *
     */
    virtual void StopNetCheckThread();

    /**
     * @Description : Exit the NetCheck thread.
     *
     */
    virtual void ExitNetCheckThread();

private:
    std::thread *pDealNetCheckThread;
    NetStateHandler netStateHandler;
    std::atomic<StaNetState> lastNetState;

    /**
     * @Description : Detect Internet ability
     *
     */
    bool HttpDetection();
    /**
     * @Description : NetCheck thread function
     *
     */
    void RunNetCheckThreadFunc();

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::condition_variable mCondition_timeout;
    std::atomic<bool> isStopNetCheck;
    std::atomic<bool> isExitNetCheckThread;
    std::atomic<bool> isExited;
};
}  // namespace Wifi
}  // namespace OHOS
#endif