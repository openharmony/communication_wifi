/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_INTERNAL_EVENT_DISPATCHER_LITE_H
#define OHOS_WIFI_INTERNAL_EVENT_DISPATCHER_LITE_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <map>

#include "wifi_internal_msg.h"
#include "i_wifi_device_callback.h"
#include "i_wifi_scan_callback.h"

namespace OHOS {
namespace Wifi {
class WifiInternalEventDispatcher {
public:
    WifiInternalEventDispatcher();
    ~WifiInternalEventDispatcher();

    /**
     * @Description Init WifiInternalEventDispatcher object
     *
     * @return int - init result, when 0 means success, other means some fails happened
     */
    int Init();

    /**
     * @Description Send system motify message
     *
     * @return int - init result, when 0 means success, other means some fails happened
     */
    int SendSystemNotifyMsg(void);

    /**
     * @Description Add broadcast events to the internal event broadcast queue
     *
     * @param msg - callback msg
     * @return int - 0 success
     */
    int AddBroadCastMsg(const WifiEventCallbackMsg &msg);

    /**
     * @Description Exit event broadcast thread
     *
     */
    void Exit();

    /**
     * @Description Event broadcast thread processing function
     *              1. Obtain broadcast events from the internal event queue
     *                 mEventQue
     *              2. Send broadcast events to handles in the application
     *                 registration list one by one. The BpWifiCallbackService
     *                 method will eventually be called
     *
     * @param p WifiInternalEventDispatcher this Object
     * @return void* - nullptr, not care this now
     */
    static void Run(WifiInternalEventDispatcher &instance);

    static WifiInternalEventDispatcher &GetInstance();
    int SetSingleStaCallback(const std::shared_ptr<IWifiDeviceCallBack> &callback);
    std::shared_ptr<IWifiDeviceCallBack> GetSingleStaCallback() const;
    int SetSingleScanCallback(const std::shared_ptr<IWifiScanCallback> &callback);
    std::shared_ptr<IWifiScanCallback> GetSingleScanCallback() const;
private:
    static void DealStaCallbackMsg(WifiInternalEventDispatcher &pInstance, const WifiEventCallbackMsg &msg);
    static void DealScanCallbackMsg(WifiInternalEventDispatcher &pInstance, const WifiEventCallbackMsg &msg);
    static void PublishConnectionStateChangedEvent(int state, const WifiLinkedInfo &info);
    static void PublishWifiStateChangedEvent(int state);
    static void PublishRssiValueChangedEvent(int state);
private:
    std::thread mBroadcastThread;
    std::atomic<bool> mRunFlag;
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::deque<WifiEventCallbackMsg> mEventQue;
    std::shared_ptr<IWifiDeviceCallBack> mStaSingleCallback;
    std::shared_ptr<IWifiScanCallback> mScanSingleCallback;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
