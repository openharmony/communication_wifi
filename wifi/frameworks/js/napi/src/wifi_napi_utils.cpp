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

#include "wifi_napi_utils.h"
#include "securec.h"
#include "wifi_logger.h"
#include "context.h"
#include "wifi_napi_errcode.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNAPIUtils");

TraceFuncCall::TraceFuncCall(std::string funcName): m_funcName(funcName)
{
    if (m_isTrace) {
        m_startTime = std::chrono::steady_clock::now();
        WIFI_LOGI("Call wifi func: %{public}s (start)", m_funcName.c_str());
    }
}

TraceFuncCall::~TraceFuncCall()
{
    if (m_isTrace) {
        auto us = std::chrono::duration_cast<std::chrono::microseconds>
            (std::chrono::steady_clock::now() - m_startTime).count();
        constexpr int usForPerMs = 1000;
        WIFI_LOGI("Call wifi func: %{public}s (end), time cost:%{public}lldus, %{public}lldms",
            m_funcName.c_str(), us, us / usForPerMs);
    }
}

napi_value UndefinedNapiValue(const napi_env& env)
{
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

napi_value CreateInt32(const napi_env& env)
{
    int32_t value = 1;
    napi_value result = nullptr;
    napi_create_int32(env, value, &result);
    return result;
}

napi_value JsObjectToString(const napi_env& env, const napi_value& object,
    const char* fieldStr, const int bufLen, std::string& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_string, "Wrong argument type. String expected.");
        if (bufLen <= 0) {
            goto error;
        }
        char *buf = (char *)malloc(bufLen);
        if (buf == nullptr) {
            WIFI_LOGE("Js object to str malloc failed");
            goto error;
        }
        (void)memset_s(buf, bufLen, 0, bufLen);
        size_t result = 0;
        NAPI_CALL(env, napi_get_value_string_utf8(env, field, buf, bufLen, &result));
        fieldRef = buf;
        free(buf);
        buf = nullptr;
    } else {
        WIFI_LOGW("Js obj to str no property: %{public}s", fieldStr);
    }

error:
    return UndefinedNapiValue(env);
}

napi_value JsObjectToInt(const napi_env& env, const napi_value& object, const char* fieldStr, int& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. Number expected.");
        napi_get_value_int32(env, field, &fieldRef);
    } else {
        WIFI_LOGW("Js to int no property: %{public}s", fieldStr);
    }
    return UndefinedNapiValue(env);
}

napi_value JsObjectToUint(const napi_env& env, const napi_value& object, const char* fieldStr, uint32_t& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. Number expected.");
        napi_get_value_uint32(env, field, &fieldRef);
    } else {
        WIFI_LOGW("Js to int no property: %{public}s", fieldStr);
    }
    return UndefinedNapiValue(env);
}

napi_value JsObjectToBool(const napi_env& env, const napi_value& object, const char* fieldStr, bool& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_boolean, "Wrong argument type. Bool expected.");
        napi_get_value_bool(env, field, &fieldRef);
    } else {
        WIFI_LOGW("Js to bool no property: %{public}s", fieldStr);
    }
    return UndefinedNapiValue(env);
}

std::vector<uint8_t> JsObjectToU8Vector(const napi_env& env, const napi_value& object, const char* fieldStr)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, fieldStr, &hasProperty), {});
    if (!hasProperty) {
        WIFI_LOGW("JsObjectToU8Vector, Js to U8Vector no property: %{public}s", fieldStr);
        return {};
    }

    bool isTypedArray = false;
    if (napi_is_typedarray(env, object, &isTypedArray) != napi_ok || !isTypedArray) {
        WIFI_LOGW("JsObjectToU8Vector, property is not typedarray: %{public}s", fieldStr);
        return {};
    }

    size_t length = 0;
    size_t offset = 0;
    napi_typedarray_type type;
    napi_value buffer = nullptr;
    NAPI_CALL_BASE(env, napi_get_typedarray_info(env, object, &type, &length, nullptr, &buffer, &offset), {});
    if (type != napi_uint8_array || buffer == nullptr) {
        WIFI_LOGW("JsObjectToU8Vector, %{public}s, buffer is nullptr: %{public}d",
            fieldStr, (int)(buffer == nullptr));
        return {};
    }

    size_t total = 0;
    uint8_t *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_arraybuffer_info(env, buffer, reinterpret_cast<void **>(&data), &total), {});
    length = std::min<size_t>(length, total - offset);
    std::vector<uint8_t> result(length);
    int retCode = memcpy_s(result.data(), result.size(), &data[offset], length);
    if (retCode != 0) {
        WIFI_LOGW("JsObjectToU8Vector, memcpy_s return fail: %{public}d", retCode);
        return {};
    }
    return result;
}

napi_status SetValueUtf8String(const napi_env& env, const char* fieldStr, const char* str,
    napi_value& result, size_t strLen)
{
    napi_value value;
    size_t len = strLen;
    napi_status status = napi_create_string_utf8(env, str, len, &value);
    if (status != napi_ok) {
        WIFI_LOGE("Set value create utf8 string error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        WIFI_LOGE("Set utf8 string named property error! field: %{public}s", fieldStr);
    }
    return status;
}

napi_status SetValueUtf8String(const napi_env& env, const std::string &fieldStr, const std::string &valueStr,
    napi_value& result)
{
    WIFI_LOGD("SetValueUtf8String, fieldStr: %{public}s, valueStr: %{public}s",
        fieldStr.c_str(), valueStr.c_str());
    napi_value value;
    size_t len = valueStr.length();
    napi_status status = napi_create_string_utf8(env, valueStr.c_str(), len, &value);
    if (status != napi_ok) {
        WIFI_LOGE("Set value create utf8 string error! field: %{public}s", fieldStr.c_str());
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    if (status != napi_ok) {
        WIFI_LOGE("Set utf8 string named property error! field: %{public}s", fieldStr.c_str());
    }
    return status;
}

napi_status SetValueInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        WIFI_LOGE("Set value create int32 error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        WIFI_LOGE("Set int32 named property error! field: %{public}s", fieldStr);
    }
    return status;
}

napi_status SetValueUnsignedInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_uint32(env, intValue, &value);
    if (status != napi_ok) {
        WIFI_LOGE("Set value create unsigned int32 error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        WIFI_LOGE("Set unsigned int32 named property error! field: %{public}s", fieldStr);
    }
    return status;
}

napi_status SetValueInt64(const napi_env& env, const char* fieldStr, const int64_t intValue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_int64(env, intValue, &value);
    if (status != napi_ok) {
        WIFI_LOGE("Set value create int64 error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        WIFI_LOGE("Set int64 named property error! field: %{public}s", fieldStr);
    }
    return status;
}

napi_status SetValueBool(const napi_env& env, const char* fieldStr, const bool boolvalue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_get_boolean(env, boolvalue, &value);
    if (status != napi_ok) {
        WIFI_LOGE("Set value create boolean error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        WIFI_LOGE("Set boolean named property error! field: %{public}s", fieldStr);
    }
    return status;
}

static napi_value InitAsyncCallBackEnv(const napi_env& env, AsyncContext *asyncContext,
    const size_t argc, const napi_value *argv, const size_t nonCallbackArgNum)
{
    for (size_t i = nonCallbackArgNum; i != argc; ++i) {
        napi_valuetype valuetype;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected.");
        napi_create_reference(env, argv[i], 1, &asyncContext->callback[i - nonCallbackArgNum]);
    }
    return nullptr;
}

static napi_value InitAsyncPromiseEnv(const napi_env& env, AsyncContext *asyncContext, napi_value& promise)
{
    napi_deferred deferred;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncContext->deferred = deferred;
    return nullptr;
}

static napi_value DoCallBackAsyncWork(const napi_env& env, AsyncContext *asyncContext)
{
    napi_create_async_work(
        env,
        nullptr,
        asyncContext->resourceName,
        [](napi_env env, void* data) {
            if (data == nullptr) {
                WIFI_LOGE("Async data parameter is null");
                return;
            }
            AsyncContext *context = (AsyncContext *)data;
            context->executeFunc(context);
        },
        [](napi_env env, napi_status status, void* data) {
            if (data == nullptr) {
                WIFI_LOGE("Async data parameter is null");
                return;
            }
            AsyncContext *context = (AsyncContext *)data;
            context->completeFunc(data);
            HandleCallbackErrCode(env, *context);
            if (context->callback[0] != nullptr) {
                napi_delete_reference(env, context->callback[0]);
            }
            if (context->callback[1] != nullptr) {
                napi_delete_reference(env, context->callback[1]);
            }
            napi_delete_async_work(env, context->work);
            delete context;
        },
        (void *)asyncContext,
        &asyncContext->work);
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    return UndefinedNapiValue(env);
}

static napi_value DoPromiseAsyncWork(const napi_env& env, AsyncContext *asyncContext)
{
    napi_create_async_work(
        env,
        nullptr,
        asyncContext->resourceName,
        [](napi_env env, void *data) {
            if (data == nullptr) {
                WIFI_LOGE("Async data parameter is null");
                return;
            }
            AsyncContext *context = (AsyncContext *)data;
            context->executeFunc(context);
        },
        [](napi_env env, napi_status status, void *data) {
            if (data == nullptr) {
                WIFI_LOGE("Async data parameter is null");
                return;
            }
            AsyncContext *context = (AsyncContext *)data;
            context->completeFunc(data);
            HandlePromiseErrCode(env, *context);
            napi_delete_async_work(env, context->work);
            delete context;
        },
        (void *)asyncContext,
        &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
    return UndefinedNapiValue(env);
}

napi_value DoAsyncWork(const napi_env& env, AsyncContext *asyncContext,
    const size_t argc, const napi_value *argv, const size_t nonCallbackArgNum)
{
    if (argc > nonCallbackArgNum) {
        InitAsyncCallBackEnv(env, asyncContext, argc, argv, nonCallbackArgNum);
        return DoCallBackAsyncWork(env, asyncContext);
    } else {
        napi_value promise;
        InitAsyncPromiseEnv(env, asyncContext, promise);
        DoPromiseAsyncWork(env, asyncContext);
        return promise;
    }
}

void SetNamedPropertyByInteger(napi_env env, napi_value dstObj, int32_t objName, const char *propName)
{
    napi_value prop = nullptr;
    if (napi_create_int32(env, objName, &prop) == napi_ok) {
        napi_set_named_property(env, dstObj, propName, prop);
    }
}
}  // namespace Wifi
}  // namespace OHOS
