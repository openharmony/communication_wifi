/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_PRO_COMMON_H
#define OHOS_WIFI_PRO_COMMON_H

namespace OHOS {
namespace Wifi {
#define FRIEND_GTEST(test_typename) friend class test_typename##Test
#define INVALID_RSSI (-127)

constexpr int32_t ROAM_SCENE = 1;
constexpr int64_t WIFI_SWITCH_RECORD_MAX_TIME = 1000 * 60 * 60 * 24 * 14; // 14天,单位:ms

enum WifiProCommond {
    EVENT_NOTIFY_WIFI_PRO_SWITCH_CHANGED = 0,
    EVENT_WIFI_CONNECT_STATE_CHANGED = 1,
    EVENT_DISCONNECT_DISCONNECTED = 2,
    EVENT_HANDLE_SCAN_RESULT = 3,
    EVENT_WIFI2WIFI_SELECT_NETWORK_RESULT = 4,
    EVENT_WIFI2WIFI_FAILED = 5,
    EVENT_WIFI_RSSI_CHANGED = 6,
    EVENT_CHECK_WIFI_INTERNET_RESULT = 7,
    EVENT_HTTP_REACHABLE_RESULT = 8,
    EVENT_REQUEST_SCAN_DELAY = 9,
    EVENT_REMOVE_BLOCK_LIST = 10,
    EVENT_REQUEST_NETWORK_DETECT = 11,
    EVENT_CMD_INTERNET_STATUS_DETECT_INTERVAL = 12,
    EVENT_QOE_APP_SLOW = 13,
    EVENT_SIGNAL_INFO_CHANGE = 14,
    EVENT_QOE_REPORT = 15,
};

enum SigLevel {
    SIG_LEVEL_0 = 0,
    SIG_LEVEL_1 = 1,
    SIG_LEVEL_2 = 2,
    SIG_LEVEL_3 = 3,
    SIG_LEVEL_4 = 4,
    SIG_LEVEL_MAX = 4,
};

inline const int32_t QUICK_SCAN_INTERVAL[SIG_LEVEL_MAX] = { 10000, 10000, 15000, 30000 };
inline const int32_t NORMAL_SCAN_INTERVAL[SIG_LEVEL_MAX] = { 15000, 15000, 30000, 60000 };
inline const int32_t QUICK_SCAN_MAX_COUNTER[SIG_LEVEL_MAX] = { 20, 20, 10, 10 };
inline const int32_t NORMAL_SCAN_MAX_COUNTER[SIG_LEVEL_MAX] = { 4, 4, 2, 2 };

enum WifiSwitchReason {
    // Default
    WIFI_SWITCH_REASON_DEFAULT = 0,
    // current ap triggers wifi switch because of no internet
    WIFI_SWITCH_REASON_NO_INTERNET = 1,
    // current ap triggers wifi switch because of rssi poor
    WIFI_SWITCH_REASON_POOR_RSSI = 2,
    // current ap triggers wifi switch because of internet block under poor rssi
    WIFI_SWITCH_REASON_STRONG_RSSI_INTERNET_SLOW = 3,
    // current ap triggers wifi switch because of internet block under strong rssi
    WIFI_SWITCH_REASON_POOR_RSSI_INTERNET_SLOW = 4,
    // current ap triggers wifi switch because of checking wifi in background
    WIFI_SWITCH_REASON_BACKGROUND_CHECK_AVAILABLE_WIFI = 5,
    // current ap triggers wifi switch because of appqoe slow
    WIFI_SWITCH_REASON_APP_QOE_SLOW = 6,
};

// current state in wifiPro
enum WifiProState {
    WIFI_DEFAULT = 0,
    WIFI_PRO_ENABLE,
    WIFI_PRO_DISABLE,
    WIFI_CONNECTED,
    WIFI_HASNET,
    WIFI_NONET,
    WIFI_PORTAL,
    WIFI_DISCONNECTED,
};
enum Perf5gSwitchResult {
    SUCCESS,
    TIMEOUT,
    NO_PERF_5G_AP,
};
struct LinkQuality {
    int signal;
    int txrate;
    int rxrate;
    unsigned int txBytes;
    unsigned int rxBytes;
    LinkQuality() : signal(0), txrate(0), rxrate(0), txBytes(0), rxBytes(0)
    {}
    ~LinkQuality()
    {}
};
}  // namespace Wifi
}  // namespace OHOS
#endif