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

#include "wifi_internal_event_dispatcher_lite.h"
#include "wifi_logger.h"
#include "wifi_permission_helper.h"
#include "wifi_errcode.h"
#include "wifi_common_event_helper.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"

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
    pthread_setname_np(mBroadcastThread.native_handle(), "InnerDisThread");
    return 0;
}

int WifiInternalEventDispatcher::SendSystemNotifyMsg() /* parameters */
{
    return 0;
}

int WifiInternalEventDispatcher::SetSingleStaCallback(const std::shared_ptr<IWifiDeviceCallBack> &callback,
    const std::string &eventName, int instId)
{
    auto iter = g_staCallBackNameEventIdMap.find(eventName);
    if (iter == g_staCallBackNameEventIdMap.end()) {
        WIFI_LOGE("SetSingleStaCallback: Not find event! eventName:%{public}s", eventName.c_str());
        return 1;
    }
    mStaSingleCallbackEvent.emplace(iter->second);
    mStaSingleCallback = callback;
    return 0;
}

std::shared_ptr<IWifiDeviceCallBack> WifiInternalEventDispatcher::GetSingleStaCallback() const
{
    return mStaSingleCallback;
}

std::unordered_set<int>& WifiInternalEventDispatcher::GetStaSingleCallbackEvent()
{
    return mStaSingleCallbackEvent;
}

int WifiInternalEventDispatcher::SetSingleScanCallback(const std::shared_ptr<IWifiScanCallback> &callback,
    const std::string &eventName, int instId)
{
    auto iter = g_staCallBackNameEventIdMap.find(eventName);
    if (iter == g_staCallBackNameEventIdMap.end()) {
        WIFI_LOGE("SetSingleScanCallback: Not find event! eventName:%{public}s", eventName.c_str());
        return 1;
    }
    mScanSingleCallbackEvent.emplace(iter->second);
    mScanSingleCallback = callback;
    return 0;
}

std::shared_ptr<IWifiScanCallback> WifiInternalEventDispatcher::GetSingleScanCallback() const
{
    return mScanSingleCallback;
}

std::unordered_set<int>& WifiInternalEventDispatcher::GetScanSingleCallbackEvent()
{
    return mScanSingleCallbackEvent;
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

    auto staSingleCallbackEvent = instance.GetStaSingleCallbackEvent();
    if (staSingleCallbackEvent.count(msg.msgData) == 0) {
        WIFI_LOGI("WifiInternalEventDispatcher:: Not registered callback event! msg.msgCode:%{public}d", msg.msgCode);
        return;
    }

    auto callback = instance.GetSingleStaCallback();
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

    auto scanSingleCallbackEvent = instance.GetScanSingleCallbackEvent();
    if (scanSingleCallbackEvent.count(msg.msgData) == 0) {
        WIFI_LOGI("WifiInternalEventDispatcher:: Not registered callback event! msg.msgCode:%{public}d", msg.msgCode);
        return;
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
    WifiLinkedInfo likedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(likedInfo);
    int signalLevel = WifiSettings::GetInstance().GetSignalLevel(state, likedInfo.band);
    if (!WifiCommonEventHelper::PublishRssiValueChangedEvent("wifiSignalLevel", signalLevel,
        state, "OnRssiValueChanged")) {
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
        if (msg.msgCode >= WIFI_CBK_MSG_STATE_CHANGE && msg.msgCode <= WIFI_CBK_MSG_WPS_STATE_CHANGE) {
            DealStaCallbackMsg(instance, msg);
        } else if (msg.msgCode == WIFI_CBK_MSG_SCAN_STATE_CHANGE) {
            DealScanCallbackMsg(instance, msg);
        } else if (msg.msgCode == WIFI_CBK_MSG_SEMI_STATE_CHANGE) {
            WifiCommonEventHelper::PublishWifiSemiStateChangedEvent(msg.msgData, "OnWifiSemiStateChanged");
        } else {
            WIFI_LOGI("UnKnown msgcode %{public}d", msg.msgCode);
        }
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS