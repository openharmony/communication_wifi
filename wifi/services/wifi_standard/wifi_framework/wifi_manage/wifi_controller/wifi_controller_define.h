/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_CONTROLLER_DEFINE_H
#define OHOS_WIFI_CONTROLLER_DEFINE_H
#include <functional>

namespace OHOS {
namespace Wifi {

#define SOFT_AP_TIME_OUT 10000
#define WIFI_OPEN_RETRY_MAX_COUNT 3
#define WIFI_OPEN_RETRY_TIMEOUT 1000
#define WIFI_OPEN_TIMEOUT 10000
#define CONCRETE_STOP_TIMEOUT 10000

#define CMD_WIFI_TOGGLED 0x1
#define CMD_SOFTAP_TOGGLED 0x2
#define CMD_SCAN_ALWAYS_MODE_CHANGED 0x3
#define CMD_STA_START_FAILURE 0x4
#define CMD_CONCRETE_STOPPED 0x5
#define CMD_AP_STOPPED 0x6
#define CMD_AP_START_FAILURE 0x7
#define CMD_AP_START 0x8
#define CMD_AIRPLANE_TOGGLED 0x9
#define CMD_WIFI_TOGGLED_TIMEOUT 0xA
#define CMD_SEMI_WIFI_TOGGLED_TIMEOUT 0xB
#define CMD_AP_START_TIME 0x10
#define CMD_AP_STOP_TIME 0x11
#define CMD_OPEN_WIFI_RETRY 0x12
#define CMD_STA_REMOVED 0x14
#define CMD_CONCRETECLIENT_REMOVED 0x15
#define CMD_AP_REMOVED 0x16
#define CMD_RPT_STOPPED 0x17
#define CMD_RPT_START_FAILURE 0x18
#define CMD_P2P_STOPPED 0x19

#define CONCRETE_CMD_START 0x101
#define CONCRETE_CMD_SWITCH_TO_CONNECT_MODE 0x102
#define CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE 0x103
#define CONCRETE_CMD_STA_STOP 0x104
#define CONCRETE_CMD_STA_START 0x105
#define CONCRETE_CMD_STOP 0x106
#define CONCRETE_CMD_STA_SEMI_ACTIVE 0x107
#define CONCRETE_CMD_SWITCH_TO_SEMI_ACTIVE_MODE 0x108
#define CONCRETE_CMD_STA_REMOVED 0x109
#define CONCRETE_CMD_RESET_STA 0x110
#define CONCRETE_CMD_SET_TARGET_ROLE 0x111
#define CONCRETE_CMD_STOP_MACHINE_RETRY 0X112
#define RESET_STA_TYPE_SELFCURE 1

#define SOFTAP_CMD_START 0x201
#define SOFTAP_CMD_STOP 0x202

#define MULTI_STA_CMD_START 0x301
#define MULTI_STA_CMD_STOP 0x302
#define MULTI_STA_CMD_STARTED 0x303
#define MULTI_STA_CMD_STOPPED 0x304
#define CMD_MULTI_STA_STOPPED 0x305

#define RPT_CMD_START 0x401
#define RPT_CMD_STOP 0x402
#define RPT_CMD_ON_P2P_CLOSE 0x403
#define RPT_CMD_ON_GROUP_CREATED 0x404
#define RPT_CMD_ON_GROUP_REMOVED 0x405
#define RPT_CMD_ON_CREATE_RPT_GROUP_FAILED 0x406
#define RPT_CMD_ON_REMOVE_RPT_GROUP_TIMEOUT 0x407
#define RPT_CMD_ON_REMOVE_CONFLICT_GROUP_TIMEOUT 0x408
#define RPT_CMD_ADD_BLOCK 0x409
#define RPT_CMD_DEL_BLOCK 0x40A
#define RPT_CMD_ON_STATION_JOIN 0x40B
#define RPT_CMD_ON_STATION_LEAVE 0x40C

#define STOP_WIFI_WAIT_TIME 100

struct ConcreteModeCallback {
    std::function<void(int)> onStopped;
    std::function<void(int)> onStartFailure;
    std::function<void(int)> onRemoved;
};

struct SoftApModeCallback {
    std::function<void(int)> onStopped;
    std::function<void(int)> onStartFailure;
};

struct MultiStaModeCallback {
    std::function<void(int)> onStopped;
    std::function<void(int)> onStartFailure;
};

struct RptModeCallback {
    std::function<void(int)> onStopped;
    std::function<void(int)> onStartFailure;
};

enum class ConcreteManagerRole {
    ROLE_UNKNOW = -1,
    ROLE_CLIENT_SCAN_ONLY = 0,
    ROLE_CLIENT_STA,
    ROLE_CLIENT_MIX_SEMI_ACTIVE,
    ROLE_CLIENT_STA_SEMI_ACTIVE,
};

enum class SoftApperateType {
    OPEN_SOFT_AP_FAILED = 0,
    CLOSE_SOFT_AP_FAILED = 1,
};

enum class SoftApChrEventType {
    SOFT_AP_OPEN_CNT = 0,
    SOFT_AP_OPEN_SUC_CNT,
    SOFT_AP_CONN_CNT,
    SOFT_AP_CONN_SUC_CNT,
};

}  // namespace Wifi
}  // namespace OHOS
#endif
