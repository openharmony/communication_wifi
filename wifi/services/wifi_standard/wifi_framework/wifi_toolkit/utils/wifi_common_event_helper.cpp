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

#include "wifi_common_event_helper.h"
#ifndef OHOS_ARCH_LITE
#include "common_event_manager.h"
#include "common_event.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
#endif
#include "wifi_logger.h"

#ifndef OHOS_ARCH_LITE
using namespace OHOS::EventFwk;
#endif
DEFINE_WIFILOG_LABEL("WifiCommonEventHelper");
namespace OHOS {
namespace Wifi {
bool WifiCommonEventHelper::PublishEvent(const std::string &eventAction, const int &code, const std::string &data,
    const std::vector<std::string> &permissions)
{
    WIFI_LOGD("publish event[%{public}s], code:%{public}d", eventAction.c_str(), code);
#ifndef OHOS_ARCH_LITE
    Want want;
    want.SetAction(eventAction);
    CommonEventData commonData;
    commonData.SetWant(want);
    commonData.SetCode(code);
    commonData.SetData(data);
    if (permissions.size() > 0) {
        CommonEventPublishInfo publishInfo;
        publishInfo.SetSubscriberPermissions(permissions);
        if (!CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
            WIFI_LOGE("failed to publish event[%{public}s], code:%{public}d", eventAction.c_str(), code);
            return false;
        }
        return true;
    }
    if (!CommonEventManager::PublishCommonEvent(commonData)) {
        WIFI_LOGE("failed to publish event[%{public}s], code:%{public}d", eventAction.c_str(), code);
        return false;
    }
#endif
    return true;
}

bool WifiCommonEventHelper::PublishEvent(const std::string &eventAction, const int &code, const std::string &data)
{
    WIFI_LOGD("publish event[%{public}s], code:%{public}d", eventAction.c_str(), code);
#ifndef OHOS_ARCH_LITE
    Want want;
    want.SetAction(eventAction);
    CommonEventData commonData;
    commonData.SetWant(want);
    commonData.SetCode(code);
    commonData.SetData(data);
    if (!CommonEventManager::PublishCommonEvent(commonData)) {
        WIFI_LOGE("failed to publish event[%{public}s], code:%{public}d", eventAction.c_str(), code);
        return false;
    }
#endif
    return true;
}

template <typename T>
bool WifiCommonEventHelper::PublishEvent(const std::string &eventAction, const std::string &paramKey, T paramValue,
    const int &code, const std::string &data)
{
    WIFI_LOGD("publish event[%{public}s], paramKey:%{public}s,code:%{public}d",
        eventAction.c_str(), paramKey.c_str(), code);
#ifndef OHOS_ARCH_LITE
    Want want;
    want.SetAction(eventAction);
    want.SetParam(paramKey, paramValue);
    CommonEventData commonData;
    commonData.SetWant(want);
    commonData.SetCode(code);
    commonData.SetData(data);
    if (!CommonEventManager::PublishCommonEvent(commonData)) {
        WIFI_LOGE("failed to publish event:%{public}s, code:%{public}d", eventAction.c_str(), code);
        return false;
    }
#endif
    return true;
}

bool WifiCommonEventHelper::PublishWifi2PowerStateChangeEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI2_POWER_STATE, code, data);
}

bool WifiCommonEventHelper::PublishPowerStateChangeEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_POWER_STATE, code, data);
}

bool WifiCommonEventHelper::PublishScanFinishedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_SCAN_FINISHED, code, data);
}

bool WifiCommonEventHelper::PublishScanStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_SCAN_STATE, code, data);
}

bool WifiCommonEventHelper::PublishScanStartEvent(const int &code, const std::string &data)
{
    std::vector<std::string> permissions;
    permissions.push_back(COMMON_EVENT_GET_WIFI_INFO_PERMISSION);
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_SCAN_START, code, data, permissions);
}

bool WifiCommonEventHelper::PublishWifiSemiStateChangedEvent(const int &code, const std::string &data)
{
    WIFI_LOGI("PublishWifiSemiStateChangedEvent code:%{public}d", code);
    std::vector<std::string> permissions;
    permissions.push_back(COMMON_EVENT_GET_WIFI_INFO_PERMISSION);
    permissions.push_back(COMMON_EVENT_MANAGE_WIFI_CONNECTION_PERMISSION);
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_SEMI_STATE, code, data, permissions);
}

bool WifiCommonEventHelper::PublishRssiValueChangedEvent(const std::string &pramKey, int paramValue,
    const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_RSSI_VALUE, pramKey, paramValue, code, data);
}

bool WifiCommonEventHelper::PublishWiTasRssiValueChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WITAS_RSSI_VALUE, code, data);
}

bool WifiCommonEventHelper::PublishWifi2ConnStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI2_CONN_STATE, code, data);
}

bool WifiCommonEventHelper::PublishConnStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_CONN_STATE, code, data);
}

bool WifiCommonEventHelper::PublishHotspotStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_HOTSPOT_STATE, code, data);
}

bool WifiCommonEventHelper::PublishHotspotStateChangedEvent(const std::string &apModeKey, int apModeValue,
    const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_HOTSPOT_STATE, apModeKey, apModeValue, code, data);
}

bool WifiCommonEventHelper::PublishApStaJoinEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_AP_STA_JOIN, code, data);
}

bool WifiCommonEventHelper::PublishApStaLeaveEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_AP_STA_LEAVE, code, data);
}

bool WifiCommonEventHelper::PublishMPlinkEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_MPLINK_STATE, code, data);
}

bool WifiCommonEventHelper::PublishP2pStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_P2P_STATE_CHANGED, code, data);
}

bool WifiCommonEventHelper::PublishP2pConnStateEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_P2P_CONN_STATE, code, data);
}

bool WifiCommonEventHelper::PublishP2pPeersStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_P2P_PEERS_STATE_CHANGED, code, data);
}

bool WifiCommonEventHelper::PublishP2pDicoveryStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_P2P_PEERS_DISCOVERY_STATE_CHANGED, code, data);
}

bool WifiCommonEventHelper::PublishP2pCurrentDeviceStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_P2P_CURRENT_DEVICE_STATE_CHANGED, code, data);
}

bool WifiCommonEventHelper::PublishP2pGroupStateChangedEvent(const int &code, const std::string &data)
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_P2P_GROUP_STATE_CHANGED, code, data);
}

bool WifiCommonEventHelper::PublishNotAvailableDialog()
{
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_NOT_AVAILABLE_DIALOG, CANCEL_DIAG, "NotAvailableDialog");
}

bool WifiCommonEventHelper::PublishSelfcureStateChangedEvent(const int &pid, const int &code, bool isSelfCureOnGoing)
{
#ifndef OHOS_ARCH_LITE
    Want want;
    want.SetAction(COMMON_EVENT_WIFI_SELF_CURE_STATE_CHANGED);
    want.SetParam("pid", pid);
    want.SetParam("selfcureType", code);
    want.SetParam("isSelfCureOnGoing", isSelfCureOnGoing);
    CommonEventData commonData;
    commonData.SetWant(want);
    std::vector<std::string> permissions;
    permissions.push_back(COMMON_EVENT_GET_WIFI_INFO_PERMISSION);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions(permissions);
    if (!CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        WIFI_LOGE("failed to publish SelfcureStateChanged Event");
        return false;
    }
#endif
    return true;
}

bool WifiCommonEventHelper::PublishVoWifiSignalDetectInterruptEvent(const int &code, const std::string &data)
{
    std::vector<std::string> permissions;
    permissions.push_back(COMMON_EVENT_GET_WIFI_CONFIG_PERMISSION);
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_VOWIFI_SIGNAL_DETECT_INTERRUPT, code, data, permissions);
}

bool WifiCommonEventHelper::PublishInternetAccessChangedEvent(const int &code, const std::string &data)
{
    WIFI_LOGI("PublishInternetAccessChangedEvent code:%{public}d", code);
    std::vector<std::string> permissions;
    permissions.push_back(COMMON_EVENT_MANAGE_WIFI_CONNECTION_PERMISSION);
    return WifiCommonEventHelper::PublishEvent(COMMON_EVENT_WIFI_INTERNET_ACCESS_CHANGE, code, data, permissions);
}
}  // namespace Wifi
}  // namespace OHOS