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

#include "wifi_internal_event_dispatcher.h"
#include "wifi_logger.h"
#include "wifi_permission_helper.h"
#include "wifi_common_event_helper.h"

DEFINE_WIFILOG_LABEL("WifiInternalEventDispatcher");

namespace OHOS {
namespace Wifi {
WifiInternalEventDispatcher &WifiInternalEventDispatcher::GetInstance()
{
    static WifiInternalEventDispatcher gWifiInternalEventDispatcher;
    return gWifiInternalEventDispatcher;
}

WifiInternalEventDispatcher::WifiInternalEventDispatcher():mTid(0)
{
    mSystemNotifyInit = false;
    mRunFlag = true;
}

WifiInternalEventDispatcher::~WifiInternalEventDispatcher()
{}

int WifiInternalEventDispatcher::Init()
{
    /* first init system notify service client here ! */

    int ret = pthread_create(&mTid, nullptr, Run, this);
    if (ret != 0) {
        WIFI_LOGE("Init WifiInternalEventDispatcher notify message callback thread failed!");
        return -1;
    }
    return 0;
}

int WifiInternalEventDispatcher::SendSystemNotifyMsg() /* parameters */
{
    return 0;
}

int WifiInternalEventDispatcher::AddStaCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiDeviceCallBack> &callback)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddStaCallback!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    mStaCallbacks[remote] = callback;
    return 0;
}

int WifiInternalEventDispatcher::RemoveStaCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mStaCallbackMutex);
        auto iter = mStaCallbacks.find(remote);
        if (iter != mStaCallbacks.end()) {
            mStaCallbacks.erase(iter);
            WIFI_LOGD("WifiInternalEventDispatcher::RemoveStaCallback!");
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleStaCallback(const sptr<IWifiDeviceCallBack> &callback)
{
    mStaSingleCallback = callback;
    return 0;
}

sptr<IWifiDeviceCallBack> WifiInternalEventDispatcher::GetSingleStaCallback() const
{
    return mStaSingleCallback;
}

bool WifiInternalEventDispatcher::HasStaRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    if (remote != nullptr) {
        if (mStaCallbacks.find(remote) != mStaCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiInternalEventDispatcher::AddScanCallback(const sptr<IRemoteObject> &remote, const sptr<IWifiScanCallback> &callback)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddCallbackClient!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    mScanCallbacks[remote] = callback;
    return 0;
}
int WifiInternalEventDispatcher::RemoveScanCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mScanCallbackMutex);
        auto iter = mScanCallbacks.find(remote);
        if (iter != mScanCallbacks.end()) {
            mScanCallbacks.erase(iter);
            WIFI_LOGD("WifiInternalEventDispatcher::RemoveScanCallback!");
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleScanCallback(const sptr<IWifiScanCallback> &callback)
{
    mScanSingleCallback = callback;
    return 0;
}

sptr<IWifiScanCallback> WifiInternalEventDispatcher::GetSingleScanCallback() const
{
    return mScanSingleCallback;
}

bool WifiInternalEventDispatcher::HasScanRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    if (remote != nullptr) {
        if (mScanCallbacks.find(remote) != mScanCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiInternalEventDispatcher::AddHotspotCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiHotspotCallback> &callback)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddHotspotCallback!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    mHotspotCallbacks[remote] = callback;
    return 0;
}
int WifiInternalEventDispatcher::RemoveHotspotCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
        auto iter = mHotspotCallbacks.find(remote);
        if (iter != mHotspotCallbacks.end()) {
            mHotspotCallbacks.erase(iter);
            WIFI_LOGD("WifiInternalEventDispatcher::RemoveHotspotCallback!");
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleHotspotCallback(const sptr<IWifiHotspotCallback> &callback)
{
    mHotspotSingleCallback = callback;
    return 0;
}

sptr<IWifiHotspotCallback> WifiInternalEventDispatcher::GetSingleHotspotCallback() const
{
    return mHotspotSingleCallback;
}

bool WifiInternalEventDispatcher::HasHotspotRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    if (remote != nullptr) {
        if (mHotspotCallbacks.find(remote) != mHotspotCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiInternalEventDispatcher::AddBroadCastMsg(const WifiEventCallbackMsg &msg)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddBroadCastMsg, msgcode %{public}d", msg.msgCode);
    {
        std::unique_lock<std::mutex> lock(mMutex);
        mEventQue.push_back(msg);
    }
    mCondition.notify_one();
    return 0;
}

void WifiInternalEventDispatcher::Exit()
{
    mRunFlag = false;
    mCondition.notify_one();
    pthread_join(mTid, nullptr);
}

void WifiInternalEventDispatcher::DealStaCallbackMsg(WifiInternalEventDispatcher *pInstance, const WifiEventCallbackMsg &msg)
{
    switch (msg.msgCode) {
        case WIFI_CBK_MSG_STATE_CHANGE:
            WifiInternalEventDispatcher::PublishWifiStateChangedEvent(msg.msgData);
            break;
        case WIFI_CBK_MSG_CONNECTION_CHANGE:
            WifiInternalEventDispatcher::PublishConnectionStateChangedEvent(msg.msgData, msg.linkInfo);
            break;
        case WIFI_CBK_MSG_RSSI_CHANGE:
            break;
        case WIFI_CBK_MSG_STREAM_DIRECTION:
            break;
        case WIFI_CBK_MSG_WPS_STATE_CHANGE:
            break;
        default:
            break;
    }

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

void WifiInternalEventDispatcher::PublishConnectionStateChangedEvent(int state, const WifiLinkedInfo &info)
{
    std::string eventData = "Other";
    switch (state) {
        case int(OHOS::Wifi::ConnectionState::CONNECT_CONNECTING):
            eventData = "Connecting";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_OBTAINING_IP):
            eventData = "OBtaingIp";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_OBTAINING_IP_FAIL):
            eventData = "OBtaingIpFail";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_AP_CONNECTED):
            eventData = "ApConnecting";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_CHECK_PORTAL):
            eventData = "Connecting";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_NETWORK_ENABLED):
            eventData = "NetworkEnabled";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_NETWORK_DISABLED):
            eventData = "NetworkDisabled";
            break;
        case int(OHOS::Wifi::ConnectionState::DISCONNECT_DISCONNECTING):
            eventData = "DisconnectDisconnecting";
            break;
        case int(OHOS::Wifi::ConnectionState::DISCONNECT_DISCONNECTED):
            eventData = "Disconnected";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_PASSWORD_WRONG):
            eventData = "ConnectPasswordWrong";
            break;
        case int(OHOS::Wifi::ConnectionState::CONNECT_CONNECTING_TIMEOUT):
            eventData = "ConnectingTimeout";
            break;
        default: {
            eventData = "UnknownState";
            break;
        }
    }
    if (!WifiCommonEventHelper::PublishConnectionStateChangedEvent(state, eventData)) {
        WIFI_LOGE("failed to publish connection state changed event!");
        return;
    }
    WIFI_LOGD("publish connection state changed event.");
}

void WifiInternalEventDispatcher::PublishWifiStateChangedEvent(int state)
{
    if (!WifiCommonEventHelper::PublishPowerStateChangeEvent(state, "OnWifiPowerStateChanged")) {
        WIFI_LOGE("failed to publish wifi state changed event!");
        return;
    }
    WIFI_LOGD("publish wifi state changed event.");
}
void WifiInternalEventDispatcher::DealScanCallbackMsg(WifiInternalEventDispatcher *pInstance, const WifiEventCallbackMsg &msg)
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

void WifiInternalEventDispatcher::InvokeScanCallbacks(const WifiEventCallbackMsg &msg)
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

void WifiInternalEventDispatcher::InvokeDeviceCallbacks(const WifiEventCallbackMsg &msg)
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
void WifiInternalEventDispatcher::InvokeHotspotCallbacks(const WifiEventCallbackMsg &msg)
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
void WifiInternalEventDispatcher::DealHotspotCallbackMsg(WifiInternalEventDispatcher *pInstance, const WifiEventCallbackMsg &msg)
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

void *WifiInternalEventDispatcher::Run(void *p)
{
    WifiInternalEventDispatcher *pInstance = (WifiInternalEventDispatcher *)p;
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
        WIFI_LOGD("WifiInternalEventDispatcher::Run broad cast a msg %{public}d", msg.msgCode);
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