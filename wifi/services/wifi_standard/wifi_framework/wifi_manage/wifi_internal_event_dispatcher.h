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

#ifndef OHOS_WIFI_INTERNAL_EVENT_DISPATCHER_H
#define OHOS_WIFI_INTERNAL_EVENT_DISPATCHER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <map>
#include <unordered_set>
#include <functional>

#include "wifi_internal_msg.h"
#ifndef OHOS_ARCH_LITE
#include "parcel.h"
#include "iremote_object.h"
#endif
#include "i_wifi_device_callback.h"
#include "i_wifi_scan_callback.h"
#include "i_wifi_hotspot_callback.h"
#include "i_wifi_p2p_callback.h"

namespace OHOS {
namespace Wifi {
using StaCallbackMapType = std::map<sptr<IRemoteObject>, sptr<IWifiDeviceCallBack>>;
using StaCallbackInfo = std::map<sptr<IRemoteObject>, WifiCallingInfo>;
using ScanCallbackMapType = std::map<sptr<IRemoteObject>, sptr<IWifiScanCallback>>;
using ScanCallbackInfo = std::map<sptr<IRemoteObject>, WifiCallingInfo>;
using HotspotCallbackMapType = std::map<sptr<IRemoteObject>, sptr<IWifiHotspotCallback>>;
using HotspotCallbackInfo = std::map<sptr<IRemoteObject>, std::unordered_set<int>>;
using P2pCallbackMapType = std::map<sptr<IRemoteObject>, sptr<IWifiP2pCallback>>;
using P2pCallbackInfo = std::map<sptr<IRemoteObject>, std::unordered_set<int>>;
using CallbackEventPermissionMap = std::multimap<int, std::pair<std::function<int()>, std::string>>;

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
    ErrCode AddStaCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiDeviceCallBack> &callback, int pid,
        const std::string &eventName);
    int SetSingleStaCallback(const sptr<IWifiDeviceCallBack> &callback, const std::string &eventName);
    sptr<IWifiDeviceCallBack> GetSingleStaCallback() const;
    int RemoveStaCallback(const sptr<IRemoteObject> &remote);
    bool HasStaRemote(const sptr<IRemoteObject> &remote);
    ErrCode AddScanCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiScanCallback> &callback, int pid,
        const std::string &eventName);
    int SetSingleScanCallback(const sptr<IWifiScanCallback> &callback, const std::string &eventName);
    sptr<IWifiScanCallback> GetSingleScanCallback() const;
    int RemoveScanCallback(const sptr<IRemoteObject> &remote);
    bool HasScanRemote(const sptr<IRemoteObject> &remote);
    ErrCode AddHotspotCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiHotspotCallback> &callback,
        const std::string &eventName, int id = 0);
    int SetSingleHotspotCallback(const sptr<IWifiHotspotCallback> &callback, int id = 0);
    sptr<IWifiHotspotCallback> GetSingleHotspotCallback(int id) const;
    int RemoveHotspotCallback(const sptr<IRemoteObject> &remote, int id = 0);
    bool HasHotspotRemote(const sptr<IRemoteObject> &remote, int id = 0);
    ErrCode AddP2pCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiP2pCallback> &callback,
        const std::string &eventName);
    int SetSingleP2pCallback(const sptr<IWifiP2pCallback> &callback);
    sptr<IWifiP2pCallback> GetSingleP2pCallback() const;
    int RemoveP2pCallback(const sptr<IRemoteObject> &remote);
    bool HasP2pRemote(const sptr<IRemoteObject> &remote);

    void InvokeScanCallbacks(const WifiEventCallbackMsg &msg);
    void InvokeDeviceCallbacks(const WifiEventCallbackMsg &msg);
    void InvokeHotspotCallbacks(const WifiEventCallbackMsg &msg);
    void InvokeP2pCallbacks(const WifiEventCallbackMsg &msg);
    bool VerifyRegisterCallbackPermission(int callbackEventId);
private:
    static void DealStaCallbackMsg(WifiInternalEventDispatcher &pInstance, const WifiEventCallbackMsg &msg);
    static void DealScanCallbackMsg(WifiInternalEventDispatcher &pInstance, const WifiEventCallbackMsg &msg);
    static void DealHotspotCallbackMsg(WifiInternalEventDispatcher &pInstance, const WifiEventCallbackMsg &msg);
    static void DealP2pCallbackMsg(WifiInternalEventDispatcher &pInstance, const WifiEventCallbackMsg &msg);
    static void SendP2pCallbackMsg(sptr<IWifiP2pCallback> &callback, const WifiEventCallbackMsg &msg);
    static void PublishConnStateChangedEvent(int state, const WifiLinkedInfo &info);
    static void PublishWifiStateChangedEvent(int state);
    static void PublishRssiValueChangedEvent(int state);
    static void SendConfigChangeEvent(sptr<IWifiP2pCallback> &callback,  CfgInfo* cfgInfo);
private:
    std::thread mBroadcastThread;
    std::atomic<bool> mRunFlag;
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::deque<WifiEventCallbackMsg> mEventQue;
    std::mutex mStaCallbackMutex;
    StaCallbackMapType mStaCallbacks;
    StaCallbackInfo mStaCallBackInfo;
    sptr<IWifiDeviceCallBack> mStaSingleCallback;
    std::mutex mScanCallbackMutex;
    ScanCallbackMapType mScanCallbacks;
    ScanCallbackInfo mScanCallBackInfo;
    sptr<IWifiScanCallback> mScanSingleCallback;
    std::mutex mHotspotCallbackMutex;
    std::map<int, HotspotCallbackMapType> mHotspotCallbacks;
    std::map<int, HotspotCallbackInfo> mHotspotCallbackInfo;
    std::map<int, sptr<IWifiHotspotCallback>> mHotspotSingleCallback;
    std::mutex mP2pCallbackMutex;
    P2pCallbackMapType mP2pCallbacks;
    P2pCallbackInfo mP2pCallbackInfo;
    sptr<IWifiP2pCallback> mP2pSingleCallback;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
