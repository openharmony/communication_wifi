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

#include "wifi_internal_event_dispatcher.h"
#include "wifi_logger.h"
#include "wifi_permission_helper.h"
#include "wifi_errcode.h"
#include "wifi_common_event_helper.h"
#include "wifi_common_util.h"
#ifdef FEATURE_APP_FROZEN
#include "suspend_manager_client.h"
#endif

DEFINE_WIFILOG_LABEL("WifiInternalEventDispatcher");

namespace OHOS {
namespace Wifi {
WifiInternalEventDispatcher &WifiInternalEventDispatcher::GetInstance()
{
    static WifiInternalEventDispatcher gWifiEventBroadcast;
    return gWifiEventBroadcast;
}

WifiInternalEventDispatcher::WifiInternalEventDispatcher() : mRunFlag(true)
{}

WifiInternalEventDispatcher::~WifiInternalEventDispatcher()
{}

int WifiInternalEventDispatcher::Init()
{
    /* first init system notify service client here ! */

    mBroadcastThread = std::thread(WifiInternalEventDispatcher::Run, std::ref(*this));
    return 0;
}

int WifiInternalEventDispatcher::SendSystemNotifyMsg() /* parameters */
{
    return 0;
}

int WifiInternalEventDispatcher::AddStaCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiDeviceCallBack> &callback, int pid)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddStaCallback, remote:%{private}p!", static_cast<void*>(remote));
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    WifiCallingInfo callbackInfo;
    callbackInfo.callingUid = GetCallingUid();
    callbackInfo.callingPid = pid;
    WIFI_LOGI("%{public}s, add uid: %{public}d, pid: %{public}d", __func__, callbackInfo.callingUid,
        callbackInfo.callingPid);
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    mStaCallbacks[remote] = callback;
    mStaCallBackInfo[remote] = callbackInfo;
    return 0;
}

int WifiInternalEventDispatcher::RemoveStaCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mStaCallbackMutex);
        auto iter = mStaCallbacks.find(remote);
        if (iter != mStaCallbacks.end()) {
            mStaCallbacks.erase(iter);
            mStaCallBackInfo.erase(mStaCallBackInfo.find(remote));
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

int WifiInternalEventDispatcher::AddScanCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiScanCallback> &callback, int pid)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddCallbackClient!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    WifiCallingInfo callbackInfo;
    callbackInfo.callingUid = GetCallingUid();
    callbackInfo.callingPid = pid;
    WIFI_LOGI("%{public}s, add uid: %{public}d, pid: %{public}d", __func__, callbackInfo.callingUid,
        callbackInfo.callingPid);
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    mScanCallbacks[remote] = callback;
    mScanCallBackInfo[remote] = callbackInfo;
    return 0;
}

int WifiInternalEventDispatcher::RemoveScanCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mScanCallbackMutex);
        auto iter = mScanCallbacks.find(remote);
        if (iter != mScanCallbacks.end()) {
            mScanCallbacks.erase(iter);
            mScanCallBackInfo.erase(mScanCallBackInfo.find(remote));
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
    const sptr<IRemoteObject> &remote, const sptr<IWifiHotspotCallback> &callback, int id)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddHotspotCallback, id:%{public}d", id);
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    auto iter = mHotspotCallbacks.find(id);
    if (iter != mHotspotCallbacks.end()) {
        (iter->second)[remote] = callback;
        return 0;
    }
    HotspotCallbackMapType hotspotCallback;
    hotspotCallback[remote] = callback;
    mHotspotCallbacks[id] = hotspotCallback;
    return 0;
}

int WifiInternalEventDispatcher::RemoveHotspotCallback(const sptr<IRemoteObject> &remote, int id)
{
    if (remote != nullptr) {
        auto iter = mHotspotCallbacks.find(id);
        if (iter != mHotspotCallbacks.end()) {
            std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
            auto item = iter->second.find(remote);
            if (item != iter->second.end()) {
                iter->second.erase(item);
                WIFI_LOGD("hotspot is is %{public}d WifiInternalEventDispatcher::RemoveHotspotCallback!", id);
            }
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleHotspotCallback(const sptr<IWifiHotspotCallback> &callback, int id)
{
    mHotspotSingleCallback[id] = callback;
    return 0;
}

sptr<IWifiHotspotCallback> WifiInternalEventDispatcher::GetSingleHotspotCallback(int id) const
{
    auto iter = mHotspotSingleCallback.find(id);
    if (iter != mHotspotSingleCallback.end()) {
        return iter->second;
    }
    return nullptr;
}

bool WifiInternalEventDispatcher::HasHotspotRemote(const sptr<IRemoteObject> &remote, int id)
{
    if (remote != nullptr) {
        auto iter = mHotspotCallbacks.find(id);
        if (iter != mHotspotCallbacks.end()) {
            std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
            if (iter->second.find(remote) != iter->second.end()) {
                return true;
            }
        }
    }
    return false;
}

int WifiInternalEventDispatcher::SetSingleP2pCallback(const sptr<IWifiP2pCallback> &callback)
{
    mP2pSingleCallback = callback;
    return 0;
}

sptr<IWifiP2pCallback> WifiInternalEventDispatcher::GetSingleP2pCallback() const
{
    return mP2pSingleCallback;
}

bool WifiInternalEventDispatcher::HasP2pRemote(const sptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
    if (remote != nullptr) {
        if (mP2pCallbacks.find(remote) != mP2pCallbacks.end()) {
            return true;
        }
    }
    return false;
}

int WifiInternalEventDispatcher::AddP2pCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiP2pCallback> &callback)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddP2pCallback!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return 1;
    }
    std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
    mP2pCallbacks[remote] = callback;
    return 0;
}

int WifiInternalEventDispatcher::RemoveP2pCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
        auto iter = mP2pCallbacks.find(remote);
        if (iter != mP2pCallbacks.end()) {
            mP2pCallbacks.erase(iter);
            WIFI_LOGD("WifiInternalEventDispatcher::RemoveP2pCallback!");
        }
    }
    return 0;
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
    if (!mRunFlag) {
        return;
    }
    mRunFlag = false;
    mCondition.notify_one();
    if (mBroadcastThread.joinable()) {
        mBroadcastThread.join();
    }
}

void WifiInternalEventDispatcher::DealStaCallbackMsg(
    WifiInternalEventDispatcher &instance, const WifiEventCallbackMsg &msg)
{
    WIFI_LOGI("WifiInternalEventDispatcher:: Deal Sta Event Callback Msg: %{public}d", msg.msgCode);

    switch (msg.msgCode) {
        case WIFI_CBK_MSG_STATE_CHANGE:
            WifiInternalEventDispatcher::PublishWifiStateChangedEvent(msg.msgData);
            break;
        case WIFI_CBK_MSG_CONNECTION_CHANGE:
            WifiInternalEventDispatcher::PublishConnStateChangedEvent(msg.msgData, msg.linkInfo);
            break;
        case WIFI_CBK_MSG_RSSI_CHANGE:
            WifiInternalEventDispatcher::PublishRssiValueChangedEvent(msg.msgData);
            break;
        case WIFI_CBK_MSG_STREAM_DIRECTION:
            break;
        case WIFI_CBK_MSG_WPS_STATE_CHANGE:
            break;
        default:
            break;
    }

    auto callback = instance.GetSingleStaCallback();
    if (callback != nullptr) {
        WIFI_LOGI("Single Callback Msg: %{public}d", msg.msgCode);
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
            case WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE:
                callback->OnDeviceConfigChanged(ConfigChange(msg.msgData));
                break;
            default:
                WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                break;
        }
    }
    instance.InvokeDeviceCallbacks(msg);
    return;
}

void WifiInternalEventDispatcher::DealScanCallbackMsg(
    WifiInternalEventDispatcher &instance, const WifiEventCallbackMsg &msg)
{
    WIFI_LOGI("WifiInternalEventDispatcher:: Deal Scan Event Callback Msg: %{public}d", msg.msgCode);

    switch (msg.msgCode) {
        case WIFI_CBK_MSG_SCAN_STATE_CHANGE:
            WifiCommonEventHelper::PublishScanStateChangedEvent(msg.msgData, "OnScanStateChanged");
            break;
        default:
            WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
            break;
    }

    auto callback = instance.GetSingleScanCallback();
    if (callback != nullptr) {
        switch (msg.msgCode) {
            case WIFI_CBK_MSG_SCAN_STATE_CHANGE:
                callback->OnWifiScanStateChanged(msg.msgData);
                break;
            default:
                break;
        }
    }
    instance.InvokeScanCallbacks(msg);
    return;
}

void WifiInternalEventDispatcher::InvokeScanCallbacks(const WifiEventCallbackMsg &msg)
{
    ScanCallbackMapType callbacks = mScanCallbacks;
    ScanCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        if (callback == nullptr) {
            continue;
        }
        WIFI_LOGI("InvokeScanCallbacks, msg.msgCode: %{public}d", msg.msgCode);
        bool isFrozen = false;
#ifdef FEATURE_APP_FROZEN
        auto remote = itr->first;
        int uid = mScanCallBackInfo[remote].callingUid;
        int pid = mScanCallBackInfo[remote].callingPid;
        isFrozen = SuspendManager::SuspendManagerClient::GetInstance().IsAppFrozen(pid, uid);
        WIFI_LOGI("Check calling APP is frozen, uid: %{public}d, pid: %{public}d, isFrozen: %{public}d",
            uid, pid, isFrozen);
#endif
        switch (msg.msgCode) {
            case WIFI_CBK_MSG_SCAN_STATE_CHANGE:
                if (isFrozen == false) {
                    callback->OnWifiScanStateChanged(msg.msgData);
                }
                break;
            default:
                WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                break;
        }
    }
}

void WifiInternalEventDispatcher::InvokeDeviceCallbacks(const WifiEventCallbackMsg &msg)
{
    StaCallbackMapType callbacks = mStaCallbacks;
    StaCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        if (callback == nullptr) {
            continue;
        }
        WIFI_LOGI("InvokeDeviceCallbacks, msg.msgCode: %{public}d", msg.msgCode);
        bool isFrozen = false;
#ifdef FEATURE_APP_FROZEN
        auto remote = itr->first;
        int uid = mStaCallBackInfo[remote].callingUid;
        int pid = mStaCallBackInfo[remote].callingPid;
        isFrozen = SuspendManager::SuspendManagerClient::GetInstance().IsAppFrozen(pid, uid);
        WIFI_LOGI("Check calling APP is frozen, uid: %{public}d, pid: %{public}d, isFrozen: %{public}d",
            uid, pid, isFrozen);
#endif
        switch (msg.msgCode) {
            case WIFI_CBK_MSG_STATE_CHANGE:
                callback->OnWifiStateChanged(msg.msgData);
                break;
            case WIFI_CBK_MSG_CONNECTION_CHANGE:
                callback->OnWifiConnectionChanged(msg.msgData, msg.linkInfo);
                break;
            case WIFI_CBK_MSG_RSSI_CHANGE:
                if (isFrozen == false) {
                    callback->OnWifiRssiChanged(msg.msgData);
                }
                break;
            case WIFI_CBK_MSG_STREAM_DIRECTION:
                if (isFrozen == false) {
                    callback->OnStreamChanged(msg.msgData);
                }
                break;
            case WIFI_CBK_MSG_WPS_STATE_CHANGE:
                callback->OnWifiWpsStateChanged(msg.msgData, msg.pinCode);
                break;
            case WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE:
                callback->OnDeviceConfigChanged(ConfigChange(msg.msgData));
                break;
            default:
                WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
                break;
        }
    }
}

void WifiInternalEventDispatcher::InvokeHotspotCallbacks(const WifiEventCallbackMsg &msg)
{
    auto iter = mHotspotCallbacks.find(msg.id);
    if (iter != mHotspotCallbacks.end()) {
        HotspotCallbackMapType callbacks = iter->second;
        HotspotCallbackMapType::iterator itr;
        for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
            auto callback = itr->second;
            if (callback == nullptr) {
                continue;
            }
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

void WifiInternalEventDispatcher::DealHotspotCallbackMsg(
    WifiInternalEventDispatcher &instance, const WifiEventCallbackMsg &msg)
{
    WIFI_LOGI("WifiInternalEventDispatcher:: Deal Hotspot Event Callback Msg: %{public}d", msg.msgCode);
    auto callback = instance.GetSingleHotspotCallback(msg.id);
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
    instance.InvokeHotspotCallbacks(msg);
    return;
}

void WifiInternalEventDispatcher::InvokeP2pCallbacks(const WifiEventCallbackMsg &msg)
{
    P2pCallbackMapType callbacks = mP2pCallbacks;
    P2pCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        if (callback != nullptr) {
            SendP2pCallbackMsg(callback, msg);
        }
    }
}

void WifiInternalEventDispatcher::SendConfigChangeEvent(sptr<IWifiP2pCallback> &callback,  CfgInfo* cfgInfo)
{
    if (cfgInfo == nullptr) {
        WIFI_LOGE("cfgInfo is nullptr");
        return;
    }
    callback->OnConfigChanged(cfgInfo->type, cfgInfo->data, cfgInfo->dataLen);
    if (cfgInfo->data != nullptr) {
        delete[] cfgInfo->data;
        cfgInfo->data = nullptr;
    }
    delete cfgInfo;
    cfgInfo = nullptr;
}

void WifiInternalEventDispatcher::SendP2pCallbackMsg(sptr<IWifiP2pCallback> &callback, const WifiEventCallbackMsg &msg)
{
    if (callback == nullptr) {
        return;
    }

    switch (msg.msgCode) {
        case WIFI_CBK_MSG_P2P_STATE_CHANGE:
            callback->OnP2pStateChanged(msg.msgData);
            break;
        case WIFI_CBK_MSG_PERSISTENT_GROUPS_CHANGE:
            callback->OnP2pPersistentGroupsChanged();
            break;
        case WIFI_CBK_MSG_THIS_DEVICE_CHANGE:
            callback->OnP2pThisDeviceChanged(msg.p2pDevice);
            break;
        case WIFI_CBK_MSG_PEER_CHANGE:
            callback->OnP2pPeersChanged(msg.device);
            break;
        case WIFI_CBK_MSG_SERVICE_CHANGE:
            callback->OnP2pServicesChanged(msg.serviceInfo);
            break;
        case WIFI_CBK_MSG_CONNECT_CHANGE:
            callback->OnP2pConnectionChanged(msg.p2pInfo);
            break;
        case WIFI_CBK_MSG_DISCOVERY_CHANGE:
            callback->OnP2pDiscoveryChanged(msg.msgData);
            break;
        case WIFI_CBK_MSG_P2P_ACTION_RESULT:
            callback->OnP2pActionResult(msg.p2pAction, static_cast<ErrCode>(msg.msgData));
            break;
        case WIFI_CBK_MSG_CFG_CHANGE:
            SendConfigChangeEvent(callback, msg.cfgInfo);
            break;
        default:
            WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
            break;
    }
    return;
}

void WifiInternalEventDispatcher::DealP2pCallbackMsg(
    WifiInternalEventDispatcher &instance, const WifiEventCallbackMsg &msg)
{
    WIFI_LOGI("WifiInternalEventDispatcher:: Deal P2P Event Callback Msg: %{public}d", msg.msgCode);

    auto callback = instance.GetSingleP2pCallback();
    if (callback != nullptr) {
        SendP2pCallbackMsg(callback, msg);
    }
    instance.InvokeP2pCallbacks(msg);
    return;
}

void WifiInternalEventDispatcher::PublishConnStateChangedEvent(int state, const WifiLinkedInfo &info)
{
    std::string eventData = "Other";
    switch (state) {
        case int(OHOS::Wifi::ConnState::CONNECTING):
            eventData = "Connecting";
            break;
        case int(OHOS::Wifi::ConnState::CONNECTED):
            eventData = "ApConnected";
            break;
        case int(OHOS::Wifi::ConnState::DISCONNECTING):
            eventData = "Disconnecting";
            break;
        case int(OHOS::Wifi::ConnState::DISCONNECTED):
            eventData = "Disconnected";
            break;
        default: {
            eventData = "UnknownState";
            break;
        }
    }
    if (!WifiCommonEventHelper::PublishConnStateChangedEvent(state, eventData)) {
        WIFI_LOGE("failed to publish connection state changed event!");
        return;
    }
    WIFI_LOGD("publish connection state changed event.");
}

void WifiInternalEventDispatcher::PublishRssiValueChangedEvent(int state)
{
    if (!WifiCommonEventHelper::PublishRssiValueChangedEvent(state, "OnRssiValueChanged")) {
        WIFI_LOGE("failed to publish rssi value changed event!");
        return;
    }
    WIFI_LOGD("publish rssi value changed event.");
}

void WifiInternalEventDispatcher::PublishWifiStateChangedEvent(int state)
{
    if (!WifiCommonEventHelper::PublishPowerStateChangeEvent(state, "OnWifiPowerStateChanged")) {
        WIFI_LOGE("failed to publish wifi state changed event!");
        return;
    }
    WIFI_LOGD("publish wifi state changed event.");
}

void WifiInternalEventDispatcher::Run(WifiInternalEventDispatcher &instance)
{
    while (instance.mRunFlag) {
        std::unique_lock<std::mutex> lock(instance.mMutex);
        while (instance.mEventQue.empty() && instance.mRunFlag) {
            instance.mCondition.wait(lock);
        }
        if (!instance.mRunFlag) {
            break;
        }
        WifiEventCallbackMsg msg = instance.mEventQue.front();
        instance.mEventQue.pop_front();
        lock.unlock();
        WIFI_LOGD("WifiInternalEventDispatcher::Run broad cast a msg %{public}d", msg.msgCode);
        if (msg.msgCode >= WIFI_CBK_MSG_STATE_CHANGE && msg.msgCode <= WIFI_CBK_MSG_MAX_INVALID_STA) {
            DealStaCallbackMsg(instance, msg);
        } else if (msg.msgCode == WIFI_CBK_MSG_SCAN_STATE_CHANGE) {
            DealScanCallbackMsg(instance, msg);
        } else if (msg.msgCode >= WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE &&
                   msg.msgCode <= WIFI_CBK_MSG_MAX_INVALID_HOTSPOT) {
            DealHotspotCallbackMsg(instance, msg);
        } else if (msg.msgCode >= WIFI_CBK_MSG_P2P_STATE_CHANGE && msg.msgCode <= WIFI_CBK_MSG_MAX_INVALID_P2P) {
            DealP2pCallbackMsg(instance, msg);
        } else {
            WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
        }
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS