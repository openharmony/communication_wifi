/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_ERRORCODE_TAIHE_H
#define OHOS_WIFI_ERRORCODE_TAIHE_H

#include <map>
#include <string>
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
static const std::int32_t SYSCAP_WIFI_CORE = 2400000;
static const std::int32_t SYSCAP_WIFI_STA = 2500000;
static const std::int32_t SYSCAP_WIFI_AP_CORE = 2600000;
static const std::int32_t SYSCAP_WIFI_AP_EXT = 2700000;
static const std::int32_t SYSCAP_WIFI_P2P = 2800000;
enum WifiTaiheErrCode {
    WIFI_ERRCODE_SUCCESS = 0, /* successfully */
    WIFI_ERRCODE_PERMISSION_DENIED = 201, /* permission denied */
    WIFI_ERRCODE_NON_SYSTEMAPP = 202, /* not system app */
    WIFI_ERRCODE_INVALID_PARAM = 401, /* invalid params */
    WIFI_ERRCODE_NOT_SUPPORTED = 801, /* not supported */
    WIFI_ERRCODE_OPERATION_FAILED = 1000, /* failed */
    WIFI_ERRCODE_WIFI_NOT_OPENED  = 1001, /* sta service not opened */
    WIFI_ERRCODE_OPEN_FAIL_WHEN_CLOSING = 1003, /* forbid when current airplane opened */
    WIFI_ERRCODE_CLOSE_FAIL_WHEN_OPENING = 1004, /* forbid when current powersaving opened */
};

class WifiIdlErrorCode {
public:
    WifiIdlErrorCode();
    ~WifiIdlErrorCode();
    static int32_t GetErrCode(const int32_t errCodeIn, const int32_t sysCap);
    static std::string GetErrMsg(const int32_t errCodeIn, int sysCap);
    static void TaiheSetBusinessError(const char* funcName,
        const int32_t errCodeIn, int sysCap);

private:
    static std::map<int32_t, int32_t> errCodeMap_;
    static std::map<int32_t, std::string> errMsgMap_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif