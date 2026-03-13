/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_ENHANCE_UTILS_H
#define OHOS_WIFI_ENHANCE_UTILS_H

namespace OHOS {
namespace Wifi {
namespace MultiLinkDefs {
    // Common constant parameters
    const int LINK_WLAN0 = 0;
    const int LINK_WLAN1 = 1;

    // Query constant parameters
    const int QUERY_DHCP_REQUIRED = 1;
    const int QUERY_IGNORE_DISCONN_REQUIRED = 2;
    const int QUERY_RECONNECT_ALLOWED = 3;
    const int QUERY_RANDOM_MAC_REQUIRED = 4;
    const int QUERY_SELECT_NETWORK_TYPE = 5;
    const int QUERY_FEATURE_ENABLED = 6;
    const int QUERY_GATEWAY_REQUIRED = 7;

    // QUERY_DHCP_REQUIRED
    const int DHCP_IGNORE = 1;
    const int DHCP_NEED = 0;

    // QUERY_IGNORE_DISCONN_REQUIRED
    const int NOTIFY_DISCONNECT = 0;
    const int IGNORE_DISCONNECT = 1;

    // QUERY_RECONNECT_ALLOWED
    const int NOT_ALLOW_IN_CONN_STATE = 0;
    const int ALLOW_IN_CONN_STATE = 1;

    // QUERY_RANDOM_MAC_REQUIRED
    const int RANDOM_MAC_USED = 0;
    const int RANDOM_MAC_NOT_USED = 1;

    // QUERY_SELECT_NETWORK_TYPE
    const int SELECT_NETWORK_NONE = 0;
    const int SELECT_NETWORK_MASTER = 1;
    const int SELECT_NETWORK_SLAVE = 2;

    // QUERY_FEATURE_ENABLED
    const int FEATURE_DISABLED = 0;
    const int FEATURE_ENABLED = 1;

    // QUERY_GATEWAY_REQUIRED
    const int GATEWAY_NEED = 0;
    const int GATEWAY_IGNORE = 1;

    // Notify constant parameters
    const int NOTIFY_CHAIN_DISCONNECTED = 101;
    const int NOTIFY_DELAY_DISCONNECTED = 102;
    const int NOTIFY_SWITCH_CHAIN = 103;
    const int NOTIFY_NETWORK_READY = 104;
    const int NOTIFY_STA_DISABLE = 105;
    const int NOTIFY_SELECT_NETWORK = 106;
    const int NOTIFY_QUIT_DUAL_WLAN = 107;

    // NOTIFY_SELECT_NETWORK
    const int SELECT_NETWORK_START = 1;
    const int SELECT_NETWORK_STOP = 0;

    // Event callback from enhance to wifi
    const int CBK_EVENT_REDHCP = 20;
}

} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_WIFI_ENHANCE_UTILS_H */
