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

#define SFOT_AP_TIME_OUT 10000
#define WIFI_OPEN_RETRY_MAX_COUNT 3
#define AP_OPEN_RETRY_MAX_COUNT 3
#define WIFI_OPEN_RETRY_TIMEOUT 1000

#define CMD_WIFI_TOGGLED 0x1
#define CMD_SOFTAP_TOGGLED 0x2
#define CMD_SCAN_ALWAYS_MODE_CHANGED 0x3
#define CMD_STA_START_FAILURE 0x4
#define CMD_CONCRETE_STOPPED 0x5
#define CMD_AP_STOPPED 0x6
#define CMD_AP_START_FAILURE 0x7
#define CMD_AP_START 0x8
#define CMD_AIRPLANE_TOGGLED 0x9
#define CMD_AP_START_TIME 0x10
#define CMD_AP_STOP_TIME 0x11
#define CMD_OPEN_WIFI_RETRY 0x12
#define CMD_AP_SERVICE_START_FAILURE 0x13
#define CMD_STA_REMOVED 0x14
#define CMD_CONCRETECLIENT_REMOVED 0x15
#define CMD_AP_REMOVED 0x16

#define CONCRETE_CMD_START 0x101
#define CONCRETE_CMD_SWITCH_TO_CONNECT_MODE 0x102
#define CONCRETE_CMD_SWITCH_TO_SCAN_ONLY_MODE 0x103
#define CONCRETE_CMD_SWITCH_TO_MIX_MODE 0x104
#define CONCRETE_CMD_STA_STOP 0x105
#define CONCRETE_CMD_STA_START 0x106
#define CONCRETE_CMD_STOP 0x107

#define SOFTAP_CMD_START 0x201
#define SOFTAP_CMD_STOP 0x202

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

enum class ConcreteManagerRole {
    ROLE_UNKNOW = -1,
    ROLE_CLIENT_SCAN_ONLY = 0,
    ROLE_CLIENT_STA,
    ROLE_CLIENT_MIX,
};

enum class SoftApperateType {
    OPEN_SOFT_AP_FAILED = 0,
    CLOSE_SOFT_AP_FAILED = 1,
};

}  // namespace Wifi
}  // namespace OHOS
#endif
