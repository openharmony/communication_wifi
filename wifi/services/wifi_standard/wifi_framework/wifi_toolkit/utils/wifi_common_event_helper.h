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

#ifndef OHOS_WIFI_COMMON_EVENT_HELPER_H
#define OHOS_WIFI_COMMON_EVENT_HELPER_H

#include <string>

namespace OHOS {
namespace Wifi {
inline const std::string COMMON_EVENT_WIFI_POWER_STATE = "usual.event.wifi.POWER_STATE";
inline const std::string COMMON_EVENT_WIFI2_POWER_STATE = "usual.event.wifi.WIFI2_POWER_STATE";
inline const std::string COMMON_EVENT_WIFI_SCAN_FINISHED = "usual.event.wifi.SCAN_FINISHED";
inline const std::string COMMON_EVENT_WIFI_SCAN_STATE = "usual.event.wifi.SCAN_STATE";
inline const std::string COMMON_EVENT_WIFI_SEMI_STATE = "usual.event.wifi.SEMI_STATE";
inline const std::string COMMON_EVENT_WIFI_RSSI_VALUE = "usual.event.wifi.RSSI_VALUE";
inline const std::string COMMON_EVENT_WITAS_RSSI_VALUE = "usual.event.wifi.WITAS_RSSI_VALUE";
inline const std::string COMMON_EVENT_WIFI_CONN_STATE = "usual.event.wifi.CONN_STATE";
inline const std::string COMMON_EVENT_WIFI2_CONN_STATE = "usual.event.wifi.WIFI2_CONN_STATE";
inline const std::string COMMON_EVENT_WIFI_HOTSPOT_STATE = "usual.event.wifi.HOTSPOT_STATE";
inline const std::string COMMON_EVENT_WIFI_AP_STA_JOIN = "usual.event.wifi.WIFI_HS_STA_JOIN";
inline const std::string COMMON_EVENT_WIFI_AP_STA_LEAVE = "usual.event.wifi.WIFI_HS_STA_LEAVE";
inline const std::string COMMON_EVENT_WIFI_MPLINK_STATE = "usual.event.wifi.mplink.STATE_CHANGE";
inline const std::string COMMON_EVENT_WIFI_P2P_CONN_STATE = "usual.event.wifi.p2p.CONN_STATE_CHANGE";
inline const std::string COMMON_EVENT_WIFI_P2P_STATE_CHANGED = "usual.event.wifi.p2p.STATE_CHANGE";
inline const std::string COMMON_EVENT_WIFI_P2P_PEERS_STATE_CHANGED =
    "usual.event.wifi.p2p.DEVICES_CHANGE";
inline const std::string COMMON_EVENT_WIFI_P2P_PEERS_DISCOVERY_STATE_CHANGED =
    "usual.event.wifi.p2p.PEER_DISCOVERY_STATE_CHANGE";
inline const std::string COMMON_EVENT_WIFI_P2P_CURRENT_DEVICE_STATE_CHANGED =
    "usual.event.wifi.p2p.CURRENT_DEVICE_CHANGE";
inline const std::string COMMON_EVENT_WIFI_P2P_GROUP_STATE_CHANGED = "usual.event.wifi.p2p.GROUP_STATE_CHANGED";
inline const std::string COMMON_EVENT_WIFI_SELF_CURE_STATE_CHANGED = "usual.event.wifi.selfcure.STATE_CHANGED";
inline const std::string COMMON_EVENT_SET_WIFI_CONFIG_PERMISSION = "ohos.permission.SET_WIFI_CONFIG";
inline const std::string COMMON_EVENT_GET_WIFI_INFO_PERMISSION = "ohos.permission.GET_WIFI_INFO";
inline const std::string COMMON_EVENT_MANAGE_WIFI_CONNECTION_PERMISSION = "ohos.permission.MANAGE_WIFI_CONNECTION";
inline const std::string COMMON_EVENT_NOT_AVAILABLE_DIALOG = "event.settings.wlan.close_not_available_dialog";
inline const int CANCEL_DIAG = 0;

class WifiCommonEventHelper {
public:
    static bool PublishEvent(const std::string &eventAction, const int &code, const std::string &data,
        const std::vector<std::string> &permissions);

    static bool PublishEvent(const std::string &eventAction, const int &code, const std::string &data);

    template <typename T>
    static bool PublishEvent(const std::string &eventAction, const std::string &paramKey, T paramValue,
        const int &code, const std::string &data);
    static bool PublishPowerStateChangeEvent(const int &code, const std::string &data);
    static bool PublishWifi2PowerStateChangeEvent(const int &code, const std::string &data);
    static bool PublishScanFinishedEvent(const int &code, const std::string &data);
    static bool PublishScanStateChangedEvent(const int &code, const std::string &data);
    static bool PublishWifiSemiStateChangedEvent(const int &code, const std::string &data);
    static bool PublishRssiValueChangedEvent(const std::string &pramKey, int paramValue,
        const int &code, const std::string &data);
    static bool PublishWiTasRssiValueChangedEvent(const int &code, const std::string &data);
    static bool PublishConnStateChangedEvent(const int &code, const std::string &data);
    static bool PublishWifi2ConnStateChangedEvent(const int &code, const std::string &data);
    static bool PublishHotspotStateChangedEvent(const int &code, const std::string &data);
    static bool PublishApStaJoinEvent(const int &code, const std::string &data);
    static bool PublishApStaLeaveEvent(const int &code, const std::string &data);
    static bool PublishMPlinkEvent(const int &code, const std::string &data);
    static bool PublishP2pStateChangedEvent(const int &code, const std::string &data);
    static bool PublishP2pConnStateEvent(const int &code, const std::string &data);
    static bool PublishP2pPeersStateChangedEvent(const int &code, const std::string &data);
    static bool PublishP2pDicoveryStateChangedEvent(const int &code, const std::string &data);
    static bool PublishP2pCurrentDeviceStateChangedEvent(const int &code, const std::string &data);
    static bool PublishP2pGroupStateChangedEvent(const int &code, const std::string &data);
    static bool PublishSelfcureStateChangedEvent(const int &pid, const int &code, bool isSelfCureOnGoing);
    static bool PublishNotAvailableDialog();
};
}  // namespace Wifi
}  // namespace OHOS
#endif
