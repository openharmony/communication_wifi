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

#ifndef WIFI_NAPI_ERRCODE_H_
#define WIFI_NAPI_ERRCODE_H_

#include "wifi_napi_utils.h"
#include <string>
#include "wifi_napi_errcode.h"

namespace OHOS {
namespace Wifi {
static const std::string BUSINESS_ERROR_PROPERTY_CODE = "code";
static const std::string BUSINESS_ERROR_PROPERTY_MESSAGE = "message";
static const std::string BUSINESS_ERROR_PROPERTY_DATA = "data";

enum {
    WIFI_NAPI_SUCCESS = 0,                     /* successfully */
    WIFI_NAPI_ERRCODE_FAILED_UNKNOWN = 1,      /* failed */
    WIFI_NAPI_ERRCODE_FORBID_AIRPLANE = 4,     /* forbid when current airplane opened */
    WIFI_NAPI_ERRCODE_FORBID_POWSAVING = 5,    /* forbid when current powersaving opened */
    WIFI_NAPI_ERRCODE_WIFI_NOT_OPENED  = 11,   /* sta service not opened */
    WIFI_NAPI_ERRCODE_AP_NOT_OPENED = 13,      /* ap service not opened */
    WIFI_NAPI_ERRCODE_PERMISSION_DENIED = 201, /* permission denied */
    WIFI_NAPI_ERRCODE_INVALID_PARAM = 401,     /* invalid params */
    WIFI_NAPI_ERRCODE_NOT_SUPPORTED = 801,     /* not supported */
};

#ifdef ENABLE_NAPI_WIFI_MANAGER
#ifndef WIFI_NAPI_ASSERT
#define WIFI_NAPI_ASSERT(env, cond, errCode) \
do { \
    if (!(cond)) { \
        napi_value res = nullptr; \
        HandleSyncErrCode(env, errCode); \
        napi_get_undefined(env, &res); \
        return res; \
    } \
} while (0)
#endif

#ifndef WIFI_NAPI_RETURN
#define WIFI_NAPI_RETURN(env, cond, errCode) \
do { \
    napi_value res = nullptr; \
    if (!(cond)) { \
        HandleSyncErrCode(env, errCode); \
    } \
    napi_get_undefined(env, &res); \
    return res; \
} while (0)
#endif

#else /* #else WIFI_NAPI_ASSERT */

#ifndef WIFI_NAPI_ASSERT
#define WIFI_NAPI_ASSERT(env, cond, errCode) \
do { \
    if (!(cond)) { \
        napi_value res = nullptr; \
        napi_get_boolean(env, cond, &res); \
        return res; \
    } \
} while (0)
#endif

#ifndef WIFI_NAPI_RETURN
#define WIFI_NAPI_RETURN(env, cond, errCode) \
do { \
    napi_value res = nullptr; \
    napi_get_boolean(env, cond, &res); \
    return res; \
} while (0)
#endif
#endif /* #endif WIFI_NAPI_ASSERT */

/**
 * @brief Thow error code for async-callback function.
 *
 * @param env The env.
 * @param info The input data.
 */
void HandleCallbackErrCode(    const napi_env &env, const AsyncContext &info);

/**
 * @brief Thow error code for async-promise function.
 *
 * @param env The env.
 * @param info The input data.
 */
void HandlePromiseErrCode(    const napi_env &env, const AsyncContext &info);

/**
 * @brief Thow error code for async function.
 *
 * @param env The env.
 * @param errCode The error code.
 */
void HandleSyncErrCode(const napi_env &env, int32_t errCode);
}  // namespace Wifi
}  // namespace OHOS
#endif

