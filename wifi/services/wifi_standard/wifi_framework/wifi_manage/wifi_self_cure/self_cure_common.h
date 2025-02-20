/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SELF_CURE_DEFINE_H
#define OHOS_WIFI_SELF_CURE_DEFINE_H

namespace OHOS {
namespace Wifi {
#define FRIEND_GTEST(test_typename) friend class test_typename##Test


#define INTERNET_STATUS_DETECT_INTERVAL_MS (8 * 1000)
#define NO_INTERNET_DETECT_INTERVAL_MS (5 * 1000)

#define WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD 104
#define WIFI_CURE_DHCP_OFFER_PKT_RCV 106
#define CMD_INTERNET_STATUS_DETECT_INTERVAL 107
#define WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD 108
#define WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT 109
#define WIFI_CURE_CMD_NETWORK_ROAMING_DETECT 110
#define WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE 112
#define WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM 113
#define WIFI_CURE_CMD_SELF_CURE_WIFI_LINK 114
#define WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT 115
#define WIFI_CURE_CMD_IP_CONFIG_TIMEOUT 116
#define WIFI_CURE_CMD_IP_CONFIG_COMPLETED 117
#define WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR 118
#define WIFI_CURE_CMD_UPDATE_CONN_SELF_CURE_HISTORY 119
#define WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED 122
#define WIFI_CURE_CMD_DNS_FAILED_MONITOR 123
#define WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT 128
#define WIFI_CURE_CMD_INVALID_IP_CONFIRM 129
#define WIFI_CURE_CMD_INVALID_DHCP_OFFER_EVENT 130
#define WIFI_CURE_CMD_HTTP_REACHABLE_RCV 136
#define WIFI_CURE_CMD_ARP_FAILED_DETECTED 139
#define WIFI_CURE_CMD_WIFI6_SELFCURE 140
#define WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE 141
#define WIFI_CURE_CMD_MULTI_GATEWAY 142
#define WIFI_CURE_CMD_MULTI_GATEWAY_RESULT 143
#define WIFI_CURE_CMD_RAND_MAC_SELFCURE_COMPLETE 144
#define WIFI_CURE_CMD_P2P_ENHANCE_STATE_CHANGED 146
#define WIFI_CURE_CMD_WIFI7_DISCONNECT_COUNT 147
#define WIFI_CURE_CMD_WIFI7_MLD_BACKOFF 148
#define WIFI_CURE_CMD_WIFI7_NON_MLD_BACKOFF 149
#define WIFI_CURE_CMD_WIFI7_BACKOFF_RECOVER 150

#define EVENT_AX_BLA_LIST 131
#define EVENT_AX_CLOSE_HTC 132
#define EVENT_BE_BLA_LIST 221
#define WIFI_CURE_RESET_LEVEL_IDLE 200
#define WIFI_CURE_RESET_LEVEL_LOW_1_DNS 201
#define WIFI_CURE_RESET_LEVEL_WIFI6 202
#define WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP 203
#define WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC 204
#define WIFI_CURE_RESET_LEVEL_HIGH_RESET 205
#define WIFI_CURE_RESET_REJECTED_BY_STATIC_IP_ENABLED 206
#define WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP 207
#define WIFI_CURE_RESET_LEVEL_DEAUTH_BSSID 208
#define WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC 209
#define WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY 210

#define WIFI_CURE_RESET_LEVEL_HIGH_RESET_WIFI_ON 211

#define WIFI_CURE_INTERNET_FAILED_RAND_MAC 300
#define WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY 302
#define WIFI_CURE_INTERNET_FAILED_TYPE_DNS 303
#define WIFI_CURE_INTERNET_FAILED_TYPE_TCP 304
#define WIFI_CURE_INTERNET_FAILED_INVALID_IP 305
#define WIFI_CURE_CMD_PERIODIC_ARP_DETECTED 306
#define WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED 307
#define WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED 308
#define WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED 309
#define WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED 310

#define WIFI_CURE_RESET_OFF_TIMEOUT 311
#define WIFI_CURE_RESET_ON_TIMEOUT 312
#define WIFI_CURE_REASSOC_TIMEOUT 313
#define WIFI_CURE_CONNECT_TIMEOUT 314
#define WIFI_CURE_CMD_SELF_CURE_FAILED 315
#define WIFI_CURE_CMD_STOP_SELF_CURE 316

#define SELFCURE_FAIL_LENGTH 12
#define SELFCURE_HISTORY_LENGTH 18

#define SIGNAL_LEVEL_1 1
#define SIGNAL_LEVEL_2 2
#define SIGNAL_LEVEL_3 3
#define FAC_MAC_REASSOC 2
#define RAND_MAC_REASSOC 3
#define DEAUTH_BSSID_CNT 3
#define DEFAULT_SLOW_NUM_ARP_PINGS 3
#define MULTI_BSSID_NUM 2
#define ACTION_TYPE_HTC 0
#define ACTION_TYPE_WIFI6 1
#define ACTION_TYPE_MLD 0
#define ACTION_TYPE_WIFI7 1
#define ACTION_TYPE_RECOVER_FAIL 2
#define WIFI7_NO_SELFCURE 0
#define WIFI7_SELFCURE_DISCONNECTED 1

#define ARP_DETECTED_FAILED_COUNT 5
#define SELF_CURE_RAND_MAC_MAX_COUNT 20
#define SELF_CURE_RAND_MAC_CONNECT_FAIL_MAX_COUNT 3
#define SELF_CURE_WIFI7_CONNECT_FAIL_MAX_COUNT 2

#define SELF_CURE_WIFI_OFF_TIMEOUT 2000
#define SELF_CURE_WIFI_ON_TIMEOUT 5000
#define MAX_ARP_DNS_CHECK_TIME 300
#define SELF_CURE_DELAYED_MS 100
#define GATEWAY_CHANGED_DETECT_DELAYED_MS 300
#define DHCP_CONFIRM_DELAYED_MS 500
#define INTERNET_RECOVERY_TIME 300
#define WIFI6_HTC_ARP_DETECTED_MS 300
#define FAST_ARP_DETECTED_MS (10 * 1000)
#define DEFAULT_ARP_DETECTED_MS (60 * 1000)
#define SELF_CURE_MONITOR_DELAYED_MS (2 * 1000)
#define DHCP_RENEW_TIMEOUT_MS (6 * 1000)
#define DNS_UPDATE_CONFIRM_DELAYED_MS (1 * 1000)
#define IP_CONFIG_CONFIRM_DELAYED_MS (2 * 1000)
#define DELAYED_DAYS_LOW (24 * 60 * 60 * 1000)
#define DELAYED_DAYS_MID (3 * DELAYED_DAYS_LOW)
#define DELAYED_DAYS_HIGH (5 * DELAYED_DAYS_LOW)
#define RAND_MAC_FAIL_EXPIRATION_AGE_MILLIS (30 * 1000)
#define SET_STATIC_IP_TIMEOUT_MS (3 * 1000)
#define INTERNET_DETECT_INTERVAL_MS (6 * 1000)
#define WIFI_BLA_LIST_TIME_EXPIRED (2 * 24 * 60 * 60 * 1000)
#define HTTP_DETECT_TIMEOUT (13 * 1000)
#define HTTP_DETECT_USLEEP_TIME (50 * 1000)
#define WIFI_CONNECT_FAIL_LIST_TIME_EXPIRED (30 * 1000)

constexpr int32_t WIFI_CURE_OFF_TIMEOUT_MS = 12 * 1000;
constexpr int32_t WIFI_CURE_ON_TIMEOUT_MS = 8 * 1000;
constexpr int32_t WIFI_CURE_REASSOC_TIMEOUT_MS = 12 * 1000;
constexpr int32_t WIFI_CURE_CONNECT_TIMEOUT_MS = 8 * 1000;
constexpr int32_t WIFI_CURE_CONN_SUCCESS_MS = 500;

#define MIN_VAL_LEVEL_2_24G (-82)
#define MIN_VAL_LEVEL_2_5G (-79)
#define MIN_VAL_LEVEL_3 (-75)
#define MIN_VAL_LEVEL_3_5 (-70)
#define MIN_VAL_LEVEL_3_24G (-75)
#define MIN_VAL_LEVEL_3_5G (-72)
#define MIN_VAL_LEVEL_4 (-65)
} //namespace Wifi
} //namespace OHOS
#endif