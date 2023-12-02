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

#ifndef OHOS_STA_DEFINE_H
#define OHOS_STA_DEFINE_H

#include <functional>
#include <string>

namespace OHOS {
namespace Wifi {
#define FRIEND_GTEST(test_typename) friend class test_typename##Test

#define WIFI_SVR_CMD_STA_ENABLE_WIFI 0x2001
#define WIFI_SVR_CMD_STA_DISABLE_WIFI 0x2002
#define WIFI_SVR_CMD_STA_OPERATIONAL_MODE 0x2003
#define WIFI_SVR_CMD_STA_CONNECT_NETWORK 0x2004
#define WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK 0x2005
#define WIFI_SVR_CMD_STA_RECONNECT_NETWORK 0x2006
#define WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK 0x2007
#define WIFI_SVR_CMD_STA_DISCONNECT 0x2008
#define WIFI_SVR_CMD_STA_STARTWPS 0x2009
#define WIFI_SVR_CMD_STA_CANCELWPS 0x200A
#define WIFI_SVR_COM_STA_START_ROAM 0x200B

#define WIFI_SVR_CMD_STA_ERROR 0x3001
#define WIFI_SVR_CMD_STA_SUP_CONNECTION_EVENT 0x3002
#define WIFI_SVR_CMD_STA_SUP_DISCONNECTION_EVENT 0x3003
#define WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT 0x3004
#define WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT 0x3005
#define WIFI_SVR_CMD_STA_WPS_START_EVENT 0x3006
#define WIFI_SVR_CMD_STA_WPS_CANCEL_EVENT 0x3007
#define WIFI_SVR_CMD_STA_WPS_FAILED_EVENT 0x3008
#define WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT 0x3009
#define WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET 0x300A
#define WIFI_SVR_CMD_STA_WPS_WEP_PROHIBITED 0x300B
#define WIFI_SVR_CMD_STA_WPS_TKIP_ONLY_PROHIBITED 0x300C
#define WIFI_SVR_CMD_STA_WPS_AUTH_FAILURE 0x300D
#define WIFI_SVR_CMD_STA_WPS_OVERLAP_ERROR 0x300E
#define WIFI_SVR_CMD_STA_SUP_REQUEST_IDENTITY 0x300F
#define WIFI_SVR_CMD_STA_SUP_REQUEST_SIM_AUTH 0x3010
#define WIFI_SVR_CMD_STA_AUTHENTICATION_FAILURE_EVENT 0x3011
#define WIFI_SVR_CMD_STA_REASON_TKIP_ONLY_PROHIBITED 0x3012
#define WIFI_SVR_CMD_STA_REASON_WEP_PROHIBITED 0x3013
#define WIFI_SVR_CMD_STA_CONFIG_AUTH_FAILURE 0x3014
#define WIFI_SVR_CMD_STA_CONFIG_MULTIPLE_PBC_DETECTED 0x3015
#define WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT 0x3016
#define WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT 0x3017
#define WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT 0x3018
#define WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT 0x3019
#define WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT 0x301A
#define WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT 0x301B

#define WPA_BLOCK_LIST_CLEAR_EVENT 0x4001
#define WIFI_SVR_CMD_UPDATE_COUNTRY_CODE 0x4002
#define WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT 0x4003

#define BSSID_LEN 17
#define KEY_LEN 128
#define SSID_LEN 30
#define VALUE_LIMIT_MIN_RSSI (-100)
#define VALUE_LIMIT_MAX_RSSI (-55)

#define NETWORK_SELECTED_BY_AUTO 0
#define NETWORK_SELECTED_BY_USER 1
#define NETWORK_SELECTED_BY_RETRY 2

const int NETWORK_24G_BAND = 1;
const int NETWORK_5G_BAND = 2;
const int MAX_RETRY_COUNT = 3;
#define BAND_2_G 1
#define BAND_5_G 2

typedef enum EnumStaNetState {
    NETWORK_STATE_UNKNOWN,
    NETWORK_STATE_WORKING,
    NETWORK_CHECK_PORTAL,
    NETWORK_STATE_NOINTERNET,
    NETWORK_STATE_BUTT,
} StaNetState;

typedef enum EnumStaArpState {
    ARP_STATE_WORKING,
    ARP_STATE_UNREACHABLE,
} StaArpState;

typedef enum EnumStaDnsState {
    DNS_STATE_WORKING,
    DNS_STATE_UNREACHABLE,
} StaDnsState;

using NetStateHandler = std::function<void(StaNetState netState, std::string portalUrl)>;
using ArpStateHandler = std::function<void(StaArpState arpState)>;
using DnsStateHandler = std::function<void(StaDnsState dnsState)>;
}  // namespace Wifi
}  // namespace OHOS
#endif /* OHOS_STA_DEFINE_H */
