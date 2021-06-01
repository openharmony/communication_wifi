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

#include "wifi_event_broadcast.h"
#include "wifi_logger.h"
#include "wifi_permission_helper.h"

DEFINE_WIFILOG_LABEL("WifiEventBroadcast");

namespace OHOS {
namespace Wifi {
WifiEventBroadcast &WifiEventBroadcast::GetInstance()
{
    static WifiEventBroadcast gWifiEventBroadcast;
    return gWifiEventBroadcast;
}

WifiEventBroadcast::WifiEventBroadcast():mTid(0)
{
    mSystemNotifyInit = false;
    mRunFlag = true;
}

WifiEventBroadcast::~WifiEventBroadcast()
{}

int WifiEventBroadcast::Init()
{
    /* first init system notify service client here ! */

    int ret = pthread_create(&mTid, nullptr, Run, this);
    if (ret != 0) {
        WIFI_LOGE("Init WifiEventBroadcast notify message callback thread failed!");
        return -1;
    }
    return 0;
}

int WifiEventBroadcast::SendSystemNotifyMsg() /* parameters */
{
    return 0;
}

int WifiEventBroadcast::AddStaCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiDeviceCallBack> &callback)
{
    WIFI_LOGD("WifiEventBroadcast::AddStaCallback!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    mStaCallbacks[remote] = callback;
    return 0;
}

int WifiEventBroadcast::RemoveStaCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mStaCallbackMutex);
        auto iter = mStaCallbacks.find(remote);
        if (iter != mStaCallbacks.end()) {
            mStaCallbacks.erase(iter);
            WIFI_LOGD("WifiEventBroadcast::RemoveStaCallback!");
        }
    }
    return 0;
}

int WifiEventBroadcast::SetSingleStaCallback(const sptr<IWifiDeviceCallBack> &callback)
{
    mStaSingleCallback = callback;
    return 0;
}

sptr<IWifiDeviceCallBack> WifiEventBroadcast::GetSingleStaCallback() const
{
    return mStaSingleCallback;
}

bool WifiEventBroadcast::HasStaRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    if (remote != nullptr) {
        if (mStaCallbacks.find(remote) != mStaCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiEventBroadcast::AddScanCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiScanCallback> &callback)
{
    WIFI_LOGD("WifiEventBroadcast::AddCallbackClient!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    mScanCallbacks[remote] = callback;
    return 0;
}
int WifiEventBroadcast::RemoveScanCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mScanCallbackMutex);
        auto iter = mScanCallbacks.find(remote);
        if (iter != mScanCallbacks.end()) {
            mScanCallbacks.erase(iter);
            WIFI_LOGD("WifiEventBroadcast::RemoveScanCallback!");
        }
    }
    return 0;
}

int WifiEventBroadcast::SetSingleScanCallback(const sptr<IWifiScanCallback> &callback)
{
    mScanSingleCallback = callback;
    return 0;
}

sptr<IWifiScanCallback> WifiEventBroadcast::GetSingleScanCallback() const
{
    return mScanSingleCallback;
}

bool WifiEventBroadcast::HasScanRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    if (remote != nullptr) {
        if (mScanCallbacks.find(remote) != mScanCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiEventBroadcast::AddHotspotCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiHotspotCallback> &callback)
{
    WIFI_LOGD("WifiEventBroadcast::AddHotspotCallback!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    mHotspotCallbacks[remote] = callback;
    return 0;
}
int WifiEventBroadcast::RemoveHotspotCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
        auto iter = mHotspotCallbacks.find(remote);
        if (iter != mHotspotCallbacks.end()) {
            mHotspotCallbacks.erase(iter);
            WIFI_LOGD("WifiEventBroadcast::RemoveHotspotCallback!");
        }
    }
    return 0;
}

int WifiEventBroadcast::SetSingleHotspotCallback(const sptr<IWifiHotspotCallback> &callback)
{
    mHotspotSingleCallback = callback;
    return 0;
}

sptr<IWifiHotspotCallback> WifiEventBroadcast::GetSingleHotspotCallback() const
{
    return mHotspotSingleCallback;
}

bool WifiEventBroadcast::HasHotspotRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    if (remote != nullptr) {
        if (mHotspotCallbacks.find(remote) != mHotspotCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiEventBroadcast::AddBroadCastMsg(const WifiEventCallbackMsg &msg)
{
    WIFI_LOGD("WifiEventBroadcast::AddBroadCastMsg, msgcode %{public}d", msg.msgCode);
    {
        std::unique_lock<std::mutex> lock(mMutex);
        mEventQue.push_back(msg);
    }
    mCondition.notify_one();
    return 0;
}

void WifiEventBroadcast::Exit()
{
    mRunFlag = false;
    mCondition.notify_one();
    pthread_join(mTid, nullptr);
}

void WifiEventBroadcast::DealStaCallbackMsg(WifiEventBroadcast *pInstance, const WifiEventCallbackMsg &msg)
{
    auto callback = pInstance->GetSingleStaCallback();
    if (callback != nullptr) {
        switch (msg.msgCode) {
            case WIFI_CBK_MSG_STATE_CHANGE:
                callback->OnWifiStateChanged(msg.msgData);
                break;
            case WIFI_CBK_MSG_CONNECTION_CHANGE:
                callback->OnWifiConnectionChanged(msg.msgData, msg.linkInfo);
                break;
            case WIFI_CBK_MSG_RSSI_CHANGE:
                callback->OnWifiRssiChanged(msg.msgData);
                break;
            case WIFI_CBK_MSG_STREAM_DIRECTION:
                callback->OnStreamChanged(msg.msgData);
                break;
            case WIFI_CBK_MSG_WPS_STATE_CHANGE:
                callback->OnWifiWpsStateChanged(msg.msgData, msg.pinCode);
                break;
            default:
                WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                break;
        }
    }
    pInstance->InvokeDeviceCallbacks(msg);
    return;
}

void WifiEventBroadcast::DealScanCallbackMsg(WifiEventBroadcast *pInstance, const WifiEventCallbackMsg &msg)
{
    auto callback = pInstance->GetSingleScanCallback();
    if (callback != nullptr) {
        switch (msg.msgCode) {
            case WIFI_CBK_MSG_SCAN_STATE_CHANGE:
                callback->OnWifiScanStateChanged(msg.msgData);
                break;
            default:
                WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                break;
        }
    }
    pInstance->InvokeScanCallbacks(msg);
    return;
}

void WifiEventBroadcast::InvokeScanCallbacks(const WifiEventCallbackMsg &msg)
{
    ScanCallbackMapType callbacks = mScanCallbacks;
    ScanCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        if (callback != nullptr) {
            switch (msg.msgCode) {
                case WIFI_CBK_MSG_SCAN_STATE_CHANGE:
                    callback->OnWifiScanStateChanged(msg.msgData);
                    break;
                default:
                    WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                    break;
            }
        }
    }
}

void WifiEventBroadcast::InvokeDeviceCallbacks(const WifiEventCallbackMsg &msg)
{
    StaCallbackMapType callbacks = mStaCallbacks;
    StaCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        if (callback != nullptr) {
            switch (msg.msgCode) {
                case WIFI_CBK_MSG_STATE_CHANGE:
                    callback->OnWifiStateChanged(msg.msgData);
                    break;
                case WIFI_CBK_MSG_CONNECTION_CHANGE:
                    callback->OnWifiConnectionChanged(msg.msgData, msg.linkInfo);
                    break;
                case WIFI_CBK_MSG_RSSI_CHANGE:
                    callback->OnWifiRssiChanged(msg.msgData);
                    break;
                case WIFI_CBK_MSG_STREAM_DIRECTION:
                    callback->OnStreamChanged(msg.msgData);
                    break;
                case WIFI_CBK_MSG_WPS_STATE_CHANGE:
                    callback->OnWifiWpsStateChanged(msg.msgData, msg.pinCode);
                    break;
                default:
                    WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                    break;
            }
        }
    }
}
void WifiEventBroadcast::InvokeHotspotCallbacks(const WifiEventCallbackMsg &msg)
{
    HotspotCallbackMapType callbacks = mHotspotCallbacks;
    HotspotCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        if (callback != nullptr) {
            switch (msg.msgCode) {
                case WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE:
                    callback->OnHotspotStateChanged(msg.msgData);
                    break;
                case WIFI_CBK_MSG_HOTSPOT_STATE_JOIN:
                    callback->OnHotspotStaJoin(msg.staInfo);
                    break;
                case WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE:
                    callback->OnHotspotStaLeave(msg.staInfo);
                    break;
                default:
                    WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                    break;
            }
        }
    }
}
void WifiEventBroadcast::DealHotspotCallbackMsg(WifiEventBroadcast *pInstance, const WifiEventCallbackMsg &msg)
{
    auto callback = pInstance->GetSingleHotspotCallback();
    if (callback != nullptr) {
        switch (msg.msgCode) {
            case WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE:
                callback->OnHotspotStateChanged(msg.msgData);
                break;
            case WIFI_CBK_MSG_HOTSPOT_STATE_JOIN:
                callback->OnHotspotStaJoin(msg.staInfo);
                break;
            case WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE:
                callback->OnHotspotStaLeave(msg.staInfo);
                break;
            default:
                WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                break;
        }
    }
    pInstance->InvokeHotspotCallbacks(msg);
    return;
}

void *WifiEventBroadcast::Run(void *p)
{
    WifiEventBroadcast *pInstance = (WifiEventBroadcast *)p;
    while (pInstance->mRunFlag) {
        std::unique_lock<std::mutex> lock(pInstance->mMutex);
        while (pInstance->mEventQue.empty() && pInstance->mRunFlag) {
            pInstance->mCondition.wait(lock);
        }
        if (!pInstance->mRunFlag) {
            break;
        }
        WifiEventCallbackMsg msg = pInstance->mEventQue.front();
        pInstance->mEventQue.pop_front();
        lock.unlock();
        WIFI_LOGD("WifiEventBroadcast::Run broad cast a msg %{public}d", msg.msgCode);
        if (msg.msgCode >= WIFI_CBK_MSG_STATE_CHANGE && msg.msgCode <= WIFI_CBK_MSG_WPS_STATE_CHANGE) {
            DealStaCallbackMsg(pInstance, msg);
        } else if (msg.msgCode == WIFI_CBK_MSG_SCAN_STATE_CHANGE) {
            DealScanCallbackMsg(pInstance, msg);
        } else if (msg.msgCode >= WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE &&
                   msg.msgCode <= WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE) {
            DealHotspotCallbackMsg(pInstance, msg);
        }
    }
    return nullptr;
}
}  // namespace Wifi
}  // namespace OHOS