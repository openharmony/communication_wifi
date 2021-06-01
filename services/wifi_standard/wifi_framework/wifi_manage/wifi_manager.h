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

#ifndef OHOS_WIFIMANAGER_H
#define OHOS_WIFIMANAGER_H

#include <pthread.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "wifi_internal_msg.h"
#include "wifi_message_queue.h"
#include "define.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
/* init state */
enum InitStatus {
    INIT_UNKNOWN = -1,
    INIT_OK = 0,
    CONFIG_CENTER_INIT_FAILED = 1,
    AUTH_CENTER_INIT_FAILED = 2,
    SERVICE_MANAGER_INIT_FAILED = 3,
    EVENT_BROADCAST_INIT_FAILED = 4,
    TASK_THREAD_INIT_FAILED = 5,
};

class WifiManager {
public:
    WifiManager();
    ~WifiManager();
    /**
     * @Description Initialize submodules and message processing threads
     *              1. Initializing the Configuration Center
     *              2. Initialization permission management
     *              3. Initializing Service Management
     *              4. Initialization event broadcast
     *              5. Initializing a Message Queue
     *              6. Initialize the message processing thread
     *
     * @return int - Init result, when 0 means success, other means some fails happened
     */
    int Init();

    /**
     * @Description Send a message to a feature service
     *              1. Search the service management module for the feature service based on the name
     *              2. Get the object and then invoke the PushMsg method of the object
     *
     * @param name - Feature Service Name
     * @param msg - Pushes message
     * @return int - 0 success; -1 feature service not exist
     */
    int PushMsg(const std::string &name, const WifiRequestMsgInfo &msg);

    /**
     * @Description When exiting, the system exits each submodule and then exits the message processing thread
     *              1. Uninstall each feature service
     *              2. Exit the event broadcast module
     *              3. Wait for the message processing thread to exit
     *
     */
    void Exit();

    /**
     * @Description Get message queue object
     *
     * @return WifiMessageQueue<WifiResponseMsgInfo>* - message queue reference
     */
    WifiMessageQueue<WifiResponseMsgInfo> *GetMessageQueue();

    /**
     * @Description Add a new device config
     *
     * @param config device config
     * @param networkId return device's network id
     * @return int - operate result, 0 success -1 failed
     */
    int AddDeviceConfig(const WifiDeviceConfig &config, int &networkId);

    /**
     * @Description Deal message from feature service, Obtain the message and process the message
     *              based on the message code
     *
     * @param p - WifiManager object
     * @return void* - nullptr, not care this return value
     */
    static void *DealServiceUpMsg(void *p);
    static WifiManager &GetInstance();

private:
    static void DealStaUpMsg(WifiManager *pInstance, const WifiResponseMsgInfo &msg);
    static void DealApUpMsg(const WifiResponseMsgInfo &msg);
    static void DealScanUpMsg(const WifiResponseMsgInfo &msg);
    static void UploadOpenWifiFailedEvent();
    static void UploadOpenWifiSuccessfulEvent();
    static void DealStaOpenRes(WifiManager *pInstance, const WifiResponseMsgInfo &msg);
    static void DealStaCloseRes(const WifiResponseMsgInfo &msg);
    static void DealStaConnChanged(const WifiResponseMsgInfo &msg);
    static void DealApOpenRes();
    static void DealApCloseRes();
    static void DealApConnChanged(const WifiResponseMsgInfo &msg);
    static void DealWpsChanged(const WifiResponseMsgInfo &msg);

    InitStatus GetInitStatus();
private:
    pthread_t mTid;
    std::atomic<bool> mRunFlag;
    std::unique_ptr<WifiMessageQueue<WifiResponseMsgInfo>> mMqUp;

    InitStatus mInitStatus_;
};
} // namespace Wifi
} // namespace OHOS
#endif