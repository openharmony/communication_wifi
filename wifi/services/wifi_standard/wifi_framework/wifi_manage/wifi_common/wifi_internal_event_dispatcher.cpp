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
#include "wifi_errcode.h"
#include "wifi_common_event_helper.h"
#include "wifi_common_util.h"
#include "wifi_auth_center.h"
#include "wifi_permission_utils.h"
#ifdef SUPPORT_RANDOM_MAC_ADDR
#include "wifi_p2p_msg.h"
#include "wifi_common_msg.h"
#include "wifi_settings.h"
#endif

DEFINE_WIFILOG_LABEL("WifiInternalEventDispatcher");

namespace OHOS {
namespace Wifi {
std::set<std::int32_t> g_CallbackEventChkSysAppList = {
    WIFI_CBK_MSG_HOTSPOT_STATE_JOIN,
    WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE,
    WIFI_CBK_MSG_STREAM_DIRECTION };

CallbackEventPermissionMap g_CallbackEventPermissionMap = {
    { WIFI_CBK_MSG_STATE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_CONNECTION_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_SCAN_STATE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_RSSI_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_HOTSPOT_STATE_JOIN,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyManageWifiHotspotPermission),
        "ohos.permission.MANAGE_WIFI_HOTSPOT") },
    { WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyManageWifiHotspotPermission),
        "ohos.permission.MANAGE_WIFI_HOTSPOT") },
    { WIFI_CBK_MSG_P2P_STATE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_CONNECT_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_THIS_DEVICE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_THIS_DEVICE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiDirectDevicePermission),
            "ohos.permission.LOCATION") },
    { WIFI_CBK_MSG_THIS_DEVICE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoInternalPermission),
            "ohos.permission.GET_WIFI_INFO_INTERNAL") },
    { WIFI_CBK_MSG_PERSISTENT_GROUPS_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_PEER_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
#ifndef SUPPORT_RANDOM_MAC_ADDR
    { WIFI_CBK_MSG_PEER_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiDirectDevicePermission),
        "ohos.permission.LOCATION") },
#endif
    { WIFI_CBK_MSG_PEER_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoInternalPermission),
        "ohos.permission.GET_WIFI_INFO_INTERNAL") },
    { WIFI_CBK_MSG_DISCOVERY_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_STREAM_DIRECTION,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyWifiConnectionPermission),
        "ohos.permission.MANAGE_WIFI_CONNECTION") },
    { WIFI_CBK_MSG_WPS_STATE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoPermission),
        "ohos.permission.GET_WIFI_INFO") },
    { WIFI_CBK_MSG_WPS_STATE_CHANGE,
        std::make_pair(std::bind(WifiPermissionUtils::VerifyGetWifiInfoInternalPermission),
        "ohos.permission.GET_WIFI_INFO_INTERNAL") },
};

WifiInternalEventDispatcher &WifiInternalEventDispatcher::GetInstance()
{
    static WifiInternalEventDispatcher gWifiEventBroadcast;
    return gWifiEventBroadcast;
}

WifiInternalEventDispatcher::WifiInternalEventDispatcher()
{}

WifiInternalEventDispatcher::~WifiInternalEventDispatcher()
{}

int WifiInternalEventDispatcher::Init()
{
    /* first init system notify service client here ! */
    mBroadcastThread = std::make_unique<WifiEventHandler>("InnerDisThread");
    return 0;
}

int WifiInternalEventDispatcher::SendSystemNotifyMsg() /* parameters */
{
    return 0;
}

ErrCode WifiInternalEventDispatcher::AddStaCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiDeviceCallBack> &callback, int pid,
    const std::string &eventName, int tokenId, int instId)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddStaCallback, remote! instId: %{public}d", instId);
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return WIFI_OPT_INVALID_PARAM;
    }

    auto eventIter = g_staCallBackNameEventIdMap.find(eventName);
    if (eventIter == g_staCallBackNameEventIdMap.end()) {
        WIFI_LOGE("%{public}s, Not find callback event, eventName:%{public}s", __func__, eventName.c_str());
        return WIFI_OPT_NOT_SUPPORTED;
    }

    if (!VerifyRegisterCallbackPermission(eventIter->second)) {
        WIFI_LOGE("%{public}s, VerifyRegisterCallbackPermission denied!", __func__);
        return WIFI_OPT_PERMISSION_DENIED;
    }

    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    auto iter = mStaCallbacks.find(instId);
    if (iter != mStaCallbacks.end()) {
        (iter->second)[remote] = callback;
        auto itr = mStaCallBackInfo[instId].find(remote);
        if (itr != mStaCallBackInfo[instId].end()) {
            (itr->second).regCallBackEventId.emplace(eventIter->second);
            WIFI_LOGD("%{public}s, add callback event: %{public}d, instId: %{public}d", __func__, eventIter->second,
                instId);
            return WIFI_OPT_SUCCESS;
        } else {
            WifiCallingInfo callbackInfo;
            callbackInfo.callingUid = GetCallingUid();
            callbackInfo.callingPid = pid;
            callbackInfo.callingTokenId = tokenId;
            callbackInfo.regCallBackEventId.emplace(eventIter->second);
            mStaCallBackInfo[instId].insert({remote, callbackInfo});
            WIFI_LOGD("%{public}s, add uid: %{public}d, pid: %{public}d, callback event:%{public}d,"
                "tokenId: %{private}d, instId: %{public}d",  __func__, callbackInfo.callingUid, callbackInfo.callingPid,
                eventIter->second, callbackInfo.callingTokenId, instId);
            return WIFI_OPT_SUCCESS;
        }
    }

    StaCallbackMapType &staCallback = mStaCallbacks[instId];
    staCallback[remote] = callback;
    StaCallbackInfo &staCallbackInfo = mStaCallBackInfo[instId];
    WifiCallingInfo callbackInfo;
    callbackInfo.callingUid = GetCallingUid();
    callbackInfo.callingPid = pid;
    callbackInfo.callingTokenId = tokenId;
    callbackInfo.regCallBackEventId.emplace(eventIter->second);
    staCallbackInfo[remote] = callbackInfo;
    return WIFI_OPT_SUCCESS;
}

int WifiInternalEventDispatcher::RemoveStaCallback(const sptr<IRemoteObject> &remote, int instId)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mStaCallbackMutex);
        auto iter = mStaCallbacks.find(instId);
        if (iter != mStaCallbacks.end()) {
            auto itr = iter->second.find(remote);
            if (itr != iter->second.end()) {
                iter->second.erase(itr);
                mStaCallBackInfo[instId].erase(mStaCallBackInfo[instId].find(remote));
                WIFI_LOGD("WifiInternalEventDispatcher::RemoveStaCallback!");
            }
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleStaCallback(const sptr<IWifiDeviceCallBack> &callback,
    const std::string &eventName, int instId)
{
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    mStaSingleCallback[instId] = callback;
    return 0;
}

sptr<IWifiDeviceCallBack> WifiInternalEventDispatcher::GetSingleStaCallback(int instId) const
{
    auto iter = mStaSingleCallback.find(instId);
    if (iter != mStaSingleCallback.end()) {
        return iter->second;
    }
    return nullptr;
}

bool WifiInternalEventDispatcher::HasStaRemote(const sptr<IRemoteObject> &remote, int instId)
{
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    if (remote != nullptr) {
        auto iter = mStaCallbacks.find(instId);
        if (iter != mStaCallbacks.end()) {
            if (iter->second.find(remote) != iter->second.end()) {
                return true;
            }
        }
    }
    return false;
}

ErrCode WifiInternalEventDispatcher::AddScanCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiScanCallback> &callback, int pid,
    const std::string &eventName, int tokenId, int instId)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddScanCallback! instId: %{public}d", instId);
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return WIFI_OPT_INVALID_PARAM;
    }

    auto eventIter = g_staCallBackNameEventIdMap.find(eventName);
    if (eventIter == g_staCallBackNameEventIdMap.end()) {
        WIFI_LOGE("%{public}s, Not find callback event, eventName:%{public}s", __func__, eventName.c_str());
        return WIFI_OPT_NOT_SUPPORTED;
    }

    if (!VerifyRegisterCallbackPermission(eventIter->second)) {
        WIFI_LOGE("%{public}s, VerifyRegisterCallbackPermission denied!", __func__);
        return WIFI_OPT_PERMISSION_DENIED;
    }

    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    auto iter = mScanCallbacks.find(instId);
    if (iter != mScanCallbacks.end()) {
        (iter->second)[remote] = callback;
        auto itr = mScanCallBackInfo[instId].find(remote);
        if (itr != mScanCallBackInfo[instId].end()) {
            (itr->second).regCallBackEventId.emplace(eventIter->second);
            WIFI_LOGD("%{public}s, add callback event: %{public}d, instId: %{public}d", __func__, eventIter->second,
                instId);
            return WIFI_OPT_SUCCESS;
        } else {
            WifiCallingInfo callbackInfo;
            callbackInfo.callingUid = GetCallingUid();
            callbackInfo.callingPid = pid;
            callbackInfo.callingTokenId = tokenId;
            callbackInfo.regCallBackEventId.emplace(eventIter->second);
            mScanCallBackInfo[instId].insert({remote, callbackInfo});
            WIFI_LOGD("%{public}s, add uid: %{public}d, pid: %{public}d, callback event:%{public}d,"
                "tokenId: %{private}d, instId: %{public}d",  __func__, callbackInfo.callingUid, callbackInfo.callingPid,
                eventIter->second, callbackInfo.callingTokenId, instId);
            return WIFI_OPT_SUCCESS;
        }
    }

    ScanCallbackMapType &scanCallback = mScanCallbacks[instId];
    scanCallback[remote] = callback;
    ScanCallbackInfo &scanCallbackInfo = mScanCallBackInfo[instId];
    WifiCallingInfo callbackInfo;
    callbackInfo.callingUid = GetCallingUid();
    callbackInfo.callingPid = pid;
    callbackInfo.callingTokenId = tokenId;
    callbackInfo.regCallBackEventId.emplace(eventIter->second);
    scanCallbackInfo[remote] = callbackInfo;
    return WIFI_OPT_SUCCESS;
}

int WifiInternalEventDispatcher::RemoveScanCallback(const sptr<IRemoteObject> &remote, int instId)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mScanCallbackMutex);
        auto iter = mScanCallbacks.find(instId);
        if (iter != mScanCallbacks.end()) {
            auto itr = iter->second.find(remote);
            if (itr != iter->second.end()) {
                iter->second.erase(itr);
                mScanCallBackInfo[instId].erase(mScanCallBackInfo[instId].find(remote));
                WIFI_LOGD("WifiInternalEventDispatcher::RemoveScanCallback!");
            }
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleScanCallback(const sptr<IWifiScanCallback> &callback,
    const std::string &eventName, int instId)
{
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    mScanSingleCallback[instId] = callback;
    return 0;
}

sptr<IWifiScanCallback> WifiInternalEventDispatcher::GetSingleScanCallback(int instId) const
{
    auto iter = mScanSingleCallback.find(instId);
    if (iter != mScanSingleCallback.end()) {
        return iter->second;
    }
    return nullptr;
}

bool WifiInternalEventDispatcher::HasScanRemote(const sptr<IRemoteObject> &remote, int instId)
{
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    if (remote != nullptr) {
        auto iter = mScanCallbacks.find(instId);
        if (iter != mScanCallbacks.end()) {
            if (iter->second.find(remote) != iter->second.end()) {
                return true;
            }
        }
    }
    return false;
}

ErrCode WifiInternalEventDispatcher::AddHotspotCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiHotspotCallback> &callback, const std::string &eventName, int id)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddHotspotCallback, id:%{public}d", id);
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return WIFI_OPT_INVALID_PARAM;
    }

    auto eventIter = g_apCallBackNameEventIdMap.find(eventName);
    if (eventIter == g_apCallBackNameEventIdMap.end()) {
        WIFI_LOGE("%{public}s, Not find callback event, eventName:%{public}s", __func__, eventName.c_str());
        return WIFI_OPT_NOT_SUPPORTED;
    }

    if (!VerifyRegisterCallbackPermission(eventIter->second)) {
        WIFI_LOGE("%{public}s, VerifyRegisterCallbackPermission denied!", __func__);
        return WIFI_OPT_PERMISSION_DENIED;
    }

    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    auto iter = mHotspotCallbacks.find(id);
    if (iter != mHotspotCallbacks.end()) {
        (iter->second)[remote] = callback;
        auto itr = mHotspotCallbackInfo[id].find(remote);
        if (itr != mHotspotCallbackInfo[id].end()) {
            (itr->second).emplace(eventIter->second);
            WIFI_LOGI("%{public}s, add callback event:%{public}d, id:%{public}d", __func__, eventIter->second, id);
            return WIFI_OPT_SUCCESS;
        }
        mHotspotCallbackInfo[id].insert({remote, {eventIter->second}});
        WIFI_LOGI("%{public}s, add new callback event:%{public}d, id:%{public}d", __func__, eventIter->second, id);
        return WIFI_OPT_SUCCESS;
    }

    HotspotCallbackMapType &hotspotCallback = mHotspotCallbacks[id];
    hotspotCallback[remote] = callback;
    HotspotCallbackInfo &hotspotCallbackInfo = mHotspotCallbackInfo[id];
    hotspotCallbackInfo[remote] = {eventIter->second};
    WIFI_LOGI("%{public}s, add ap callback event:%{public}d, id:%{public}d", __func__, eventIter->second, id);
    return WIFI_OPT_SUCCESS;
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
                mHotspotCallbackInfo[id].erase(mHotspotCallbackInfo[id].find(remote));
                WIFI_LOGD("hotspot is is %{public}d WifiInternalEventDispatcher::RemoveHotspotCallback!", id);
            }
        }
    }
    return 0;
}

int WifiInternalEventDispatcher::SetSingleHotspotCallback(const sptr<IWifiHotspotCallback> &callback, int id)
{
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
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
    std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
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

ErrCode WifiInternalEventDispatcher::AddP2pCallback(
    const sptr<IRemoteObject> &remote, const sptr<IWifiP2pCallback> &callback, int pid,
    const std::string &eventName, int tokenId)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddP2pCallback!");
    if (remote == nullptr || callback == nullptr) {
        WIFI_LOGE("remote object is null!");
        return WIFI_OPT_INVALID_PARAM;
    }

    auto eventIter = g_p2pCallBackNameEventIdMap.find(eventName);
    if (eventIter == g_p2pCallBackNameEventIdMap.end()) {
        WIFI_LOGE("%{public}s, Not find callback event, eventName:%{public}s", __func__, eventName.c_str());
        return WIFI_OPT_NOT_SUPPORTED;
    }

    if (!VerifyRegisterCallbackPermission(eventIter->second)) {
        WIFI_LOGE("%{public}s, VerifyRegisterCallbackPermission denied!", __func__);
        return WIFI_OPT_PERMISSION_DENIED;
    }

    std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
    auto iter = mP2pCallbackInfo.find(remote);
    if (iter != mP2pCallbackInfo.end()) {
        (iter->second).regCallBackEventId.emplace(eventIter->second);
    } else {
        WifiCallingInfo &callbackInfo = mP2pCallbackInfo[remote];
        callbackInfo.callingUid = GetCallingUid();
        callbackInfo.callingPid = pid;
        callbackInfo.callingTokenId = tokenId;
        callbackInfo.regCallBackEventId.emplace(eventIter->second);
        WIFI_LOGI("%{public}s, add uid: %{public}d, pid: %{public}d, callback event: %{public}d, tokenId: %{private}d",
            __func__, callbackInfo.callingUid, callbackInfo.callingPid,
            eventIter->second, callbackInfo.callingTokenId);
    }
    mP2pCallbacks[remote] = callback;
    WIFI_LOGI("%{public}s, add p2p callback event:%{public}d", __func__, eventIter->second);
    return WIFI_OPT_SUCCESS;
}

int WifiInternalEventDispatcher::RemoveP2pCallback(const sptr<IRemoteObject> &remote)
{
    if (remote != nullptr) {
        std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
        auto iter = mP2pCallbacks.find(remote);
        if (iter != mP2pCallbacks.end()) {
            mP2pCallbacks.erase(iter);
            mP2pCallbackInfo.erase(mP2pCallbackInfo.find(remote));
            WIFI_LOGD("WifiInternalEventDispatcher::RemoveP2pCallback!");
        }
    }
    return 0;
}

void WifiInternalEventDispatcher::Run(WifiInternalEventDispatcher &instance, const WifiEventCallbackMsg &msg)
{
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
    return;
}

int WifiInternalEventDispatcher::AddBroadCastMsg(const WifiEventCallbackMsg &msg)
{
    WIFI_LOGD("WifiInternalEventDispatcher::AddBroadCastMsg, msgcode %{public}d", msg.msgCode);
    std::function<void()> func = std::bind([this, msg]() {
        Run(std::ref(*this), msg);
    });
    int delayTime = 0;
    bool result = mBroadcastThread->PostAsyncTask(func, delayTime);
    if (!result) {
        WIFI_LOGF("WifiInternalEventDispatcher::AddBroadCastMsg failed %{public}d", msg.msgCode);
        return -1;
    }
    return 0;
}

void WifiInternalEventDispatcher::Exit()
{
    if (mBroadcastThread) {
        mBroadcastThread.reset();
    }
}

void WifiInternalEventDispatcher::DealStaCallbackMsg(
    WifiInternalEventDispatcher &instance, const WifiEventCallbackMsg &msg)
{
    WIFI_LOGD("Deal Sta Event Callback Msg: %{public}d", msg.msgCode);

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

    auto callback = instance.GetSingleStaCallback(msg.id);
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
    WIFI_LOGD("WifiInternalEventDispatcher:: Deal Scan Event Callback Msg: %{public}d", msg.msgCode);

    switch (msg.msgCode) {
        case WIFI_CBK_MSG_SCAN_STATE_CHANGE:
            WifiCommonEventHelper::PublishScanStateChangedEvent(msg.msgData, "OnScanStateChanged");
            break;
        default:
            WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
            break;
    }

    auto callback = instance.GetSingleScanCallback(msg.id);
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
    std::unique_lock<std::mutex> lock(mScanCallbackMutex);
    auto iter = mScanCallbacks.find(msg.id);
    if (iter != mScanCallbacks.end()) {
        ScanCallbackMapType callbacks = iter->second;
        ScanCallbackMapType::iterator itr;
        for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
            auto callback = itr->second;
            if (callback == nullptr) {
                continue;
            }
            WIFI_LOGD("InvokeScanCallbacks, msg.msgCode: %{public}d, instId: %{public}d", msg.msgCode, msg.id);
            auto remote = itr->first;
            bool isFrozen = false;
#ifdef FEATURE_APP_FROZEN
            int uid = mScanCallBackInfo[msg.id][remote].callingUid;
            int pid = mScanCallBackInfo[msg.id][remote].callingPid;
            isFrozen = IsAppFrozen(pid);
            WIFI_LOGD("APP is hardwareProxied, uid: %{public}d, pid: %{public}d, hardwareProxied:
                %{public}d", uid, pid, isFrozen);
#endif
            if (mScanCallBackInfo[msg.id][remote].regCallBackEventId.count(msg.msgCode) == 0) {
                WIFI_LOGI("Not registered callback event! msg.msgCode: %{public}d,"
                    "instId: %{public}d", msg.msgCode, msg.id);
                continue;
            }

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
}

void WifiInternalEventDispatcher::InvokeDeviceCallbacks(
    const WifiEventCallbackMsg &msg) __attribute__((no_sanitize("cfi")))
{
    std::unique_lock<std::mutex> lock(mStaCallbackMutex);
    auto iter = mStaCallbacks.find(msg.id);
    if (iter != mStaCallbacks.end()) {
        StaCallbackMapType callbacks = iter->second;
        StaCallbackMapType::iterator itr;
        for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
            auto callback = itr->second;
            if (callback == nullptr) {
                continue;
            }
            WIFI_LOGD("InvokeDeviceCallbacks, msg.msgCode: %{public}d, instId: %{public}d", msg.msgCode, msg.id);
            auto remote = itr->first;
            bool isFrozen = false;
#ifdef FEATURE_APP_FROZEN
            int uid = mStaCallBackInfo[msg.id][remote].callingUid;
            int pid = mStaCallBackInfo[msg.id][remote].callingPid;
            isFrozen = IsAppFrozen(pid);
            WIFI_LOGD("Check calling APP is hardwareProxied, uid: %{public}d, pid: %{public}d, hardwareProxied:
                %{public}d", uid, pid, isFrozen);
#endif
            if (mStaCallBackInfo[msg.id][remote].regCallBackEventId.count(msg.msgCode) == 0) {
                WIFI_LOGD("InvokeDeviceCallbacks, Not registered callback event! msg.msgCode: %{public}d,"
                    "instId: %{public}d", msg.msgCode, msg.id);
                continue;
            }

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
}

void WifiInternalEventDispatcher::InvokeHotspotCallbacks(const WifiEventCallbackMsg &msg)
{
    std::unique_lock<std::mutex> lock(mHotspotCallbackMutex);
    auto iter = mHotspotCallbacks.find(msg.id);
    if (iter != mHotspotCallbacks.end()) {
        HotspotCallbackMapType callbacks = iter->second;
        HotspotCallbackMapType::iterator itr;
        for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
            auto callback = itr->second;
            if (callback == nullptr) {
                continue;
            }
            auto remote = itr->first;
            if (mHotspotCallbackInfo[msg.id][remote].count(msg.msgCode) == 0) {
                WIFI_LOGI("InvokeHotspotCallbacks, Not registered callback event! msg.msgCode:%{public}d", msg.msgCode);
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
    WIFI_LOGI("Deal Hotspot Event Callback Msg: %{public}d", msg.msgCode);
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
    std::unique_lock<std::mutex> lock(mP2pCallbackMutex);
    P2pCallbackMapType callbacks = mP2pCallbacks;
    P2pCallbackMapType::iterator itr;
    for (itr = callbacks.begin(); itr != callbacks.end(); itr++) {
        auto callback = itr->second;
        auto remote = itr->first;
        if (mP2pCallbackInfo[remote].regCallBackEventId.count(msg.msgCode) == 0) {
            WIFI_LOGI("InvokeP2pCallbacks, Not registered callback event! msg.msgCode:%{public}d", msg.msgCode);
            continue;
        }
        int pid = mP2pCallbackInfo[remote].callingPid;
        int uid = mP2pCallbackInfo[remote].callingUid;
        int tokenId = mP2pCallbackInfo[remote].callingTokenId;
        if (callback != nullptr) {
            SendP2pCallbackMsg(callback, msg, pid, uid, tokenId);
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

#ifdef SUPPORT_RANDOM_MAC_ADDR
void WifiInternalEventDispatcher::updateP2pDeviceMacAddress(std::vector<WifiP2pDevice> &device)
{
    for (auto iter = device.begin(); iter != device.end(); ++iter) {
        WifiMacAddrInfo macAddrInfo;
        macAddrInfo.bssid = iter->GetDeviceAddress();
        macAddrInfo.bssidType = iter->GetDeviceAddressType();
        std::string randomMacAddr =
            WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, macAddrInfo);
        if (randomMacAddr.empty()) {
            WIFI_LOGW("%{public}s: no record found, bssid:%{private}s, bssidType:%{public}d",
                __func__, macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
        } else {
            WIFI_LOGD("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMac:%{private}s",
                __func__, iter->GetDeviceAddress().c_str(), iter->GetDeviceAddressType(), randomMacAddr.c_str());
            if (iter->GetDeviceAddressType() == REAL_DEVICE_ADDRESS) {
                iter->SetDeviceAddress(randomMacAddr);
                iter->SetDeviceAddressType(RANDOM_DEVICE_ADDRESS);
                WIFI_LOGD("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                    __func__, iter->GetDeviceAddress().c_str(), iter->GetDeviceAddressType());
            }
        }
    }
}
#endif

void WifiInternalEventDispatcher::SendP2pCallbackMsg(sptr<IWifiP2pCallback> &callback, const WifiEventCallbackMsg &msg,
    int pid, int uid, int tokenId)
{
    if (callback == nullptr) {
        WIFI_LOGE("%{public}s: callback is null", __func__);
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
            {
                WIFI_LOGD("%{public}s pid: %{public}d, uid: %{public}d, tokenId: %{private}d",
                    __func__, pid, uid, tokenId);
            #ifdef SUPPORT_RANDOM_MAC_ADDR
                if ((pid != 0) && (uid != 0)) {
                    std::vector<WifiP2pDevice> deviceVec = msg.device;
                    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermissionEx(pid, uid, tokenId) == PERMISSION_DENIED) {
                        WIFI_LOGD("%{public}s: GET_WIFI_PEERS_MAC PERMISSION_DENIED, pid: %{public}d, uid: %{public}d",
                            __func__, pid, uid);
                        updateP2pDeviceMacAddress(deviceVec);
                    }
                    callback->OnP2pPeersChanged(deviceVec);
                }
            #else
                callback->OnP2pPeersChanged(msg.device);
            #endif
                break;
            }
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
        case WIFI_CBK_MSG_P2P_GC_JOIN_GROUP:
            callback->OnP2pGcJoinGroup(msg.gcInfo);
            break;
        case WIFI_CBK_MSG_P2P_GC_LEAVE_GROUP:
            callback->OnP2pGcLeaveGroup(msg.gcInfo);
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
    WIFI_LOGI("Deal P2P Event Callback Msg: %{public}d", msg.msgCode);

    auto callback = instance.GetSingleP2pCallback();
    if (callback != nullptr) {
        SendP2pCallbackMsg(callback, msg, 0, 0, 0);
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
        WIFI_LOGE("failed to publish connection state changed event,%{public}s!", eventData.c_str());
        return;
    }
    WIFI_LOGI("publish connection state changed event,%{public}s.", eventData.c_str());
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

bool WifiInternalEventDispatcher::VerifyRegisterCallbackPermission(int callbackEventId)
{
    if (g_CallbackEventChkSysAppList.find(callbackEventId) != g_CallbackEventChkSysAppList.end()) {
        if (!WifiAuthCenter::IsSystemAppByToken()) {
            WIFI_LOGE("VerifyRegisterCallbackPermission:NOT System APP, PERMISSION_DENIED!");
            return false;
        }
    }

    std::pair<CallbackEventPermissionMap::iterator, CallbackEventPermissionMap::iterator>
        pr = g_CallbackEventPermissionMap.equal_range(callbackEventId);
    bool hasPermission = true;
    for (auto itr = pr.first; itr != pr.second; ++itr) {
        auto verifyPermissionFunc = itr->second.first;
        int result = verifyPermissionFunc();
        auto permissionName = itr->second.second;
        if (permissionName.compare("ohos.permission.GET_WIFI_INFO_INTERNAL") == 0) {
            if (result == PERMISSION_GRANTED) {
                return true;
            }
            WIFI_LOGE("%{public}s, No permission register callback! event:%{public}d", __func__, itr->first);
        } else {
            if (result != PERMISSION_GRANTED) {
                hasPermission = false;
                WIFI_LOGE("%{public}s, No permission register callback! event:%{public}d", __func__, itr->first);
            }
        }
    }
    return hasPermission;
}

void WifiInternalEventDispatcher::SetAppFrozen(std::set<int> pidList, bool isFrozen)
{
    std::unique_lock<std::mutex> lock(mPidFrozenMutex);
    WIFI_LOGI("%{public}s, list size:%{public}zu, isFrozen:%{public}d", __func__, pidList.size(), isFrozen);
    for (auto itr : pidList) {
        if (isFrozen) {
            frozenPidList.insert(itr);
        } else {
            frozenPidList.erase(itr);
        }
    }
    WIFI_LOGI("%{public}s finish, size:%{public}zu", __func__, frozenPidList.size());
}

void WifiInternalEventDispatcher::ResetAllFrozenApp()
{
    std::unique_lock<std::mutex> lock(mPidFrozenMutex);
    WIFI_LOGI("WifiInternalEventDispatcher::Reset All Frozen App");
    frozenPidList.clear();
}

bool WifiInternalEventDispatcher::IsAppFrozen(int pid)
{
    auto it = frozenPidList.find(pid);
    if (it != frozenPidList.end()) {
        return true;
    }
    return false;
}
}  // namespace Wifi
}  // namespace OHOS