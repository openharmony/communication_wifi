/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "wifi_ext_napi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_napi_errcode.h"
#ifdef FEATURE_AP_EXTENSION
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiExtNAPIHotspot");

std::unique_ptr<WifiHotspot> GetHotspotInstance()
{
    return WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
}

napi_value EnableHotspot(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    std::unique_ptr<WifiHotspot> hotspot = GetHotspotInstance();
    WIFI_NAPI_ASSERT(env, hotspot != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_EXT);
    ErrCode ret = hotspot->EnableHotspot(ServiceType::WIFI_EXT);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Enable hotspot error: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_EXT);
}

napi_value DisableHotspot(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    std::unique_ptr<WifiHotspot> hotspot = GetHotspotInstance();
    WIFI_NAPI_ASSERT(env, hotspot != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_EXT);
    ErrCode ret = hotspot->DisableHotspot(ServiceType::WIFI_EXT);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Disable hotspot error: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_EXT);
}

static ErrCode NativePowerModelListToJsObj(const napi_env& env,
    const std::set<PowerModel>& setPowerModelList, napi_value& arrayResult)
{
    uint32_t idx = 0;
    for (auto& each : setPowerModelList) {
        napi_value result;
        napi_create_int32(env, static_cast<int>(each), &result);
        napi_status status = napi_set_element(env, arrayResult, idx++, result);
        if (status != napi_ok) {
            WIFI_LOGE("Wifi napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

napi_value GetSupportedPowerModel(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));

    PowerModelListAsyncContext *asyncContext = new (std::nothrow) PowerModelListAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_EXT);
    napi_create_string_latin1(env, "getSupportedPowerModel", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        PowerModelListAsyncContext *context = static_cast<PowerModelListAsyncContext *>(data);
        std::unique_ptr<WifiHotspot> hotspot = GetHotspotInstance();
        if (hotspot == nullptr) {
            WIFI_LOGE("hotspot instance is null.");
            return;
        }
        TRACE_FUNC_CALL_NAME("hotspot->GetSupportedPowerModel");
        context->errorCode = hotspot->GetSupportedPowerModel(context->setPowerModelList);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        PowerModelListAsyncContext *context = static_cast<PowerModelListAsyncContext *>(data);
        napi_create_array_with_length(context->env, context->setPowerModelList.size(), &context->result);
        NativePowerModelListToJsObj(context->env, context->setPowerModelList, context->result);
        WIFI_LOGI("Push power model list to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_AP_EXT;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value GetPowerModel(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));

    PowerModelAsyncContext *asyncContext = new (std::nothrow) PowerModelAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_EXT);
    napi_create_string_latin1(env, "getPowerModel", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        PowerModelAsyncContext *context = static_cast<PowerModelAsyncContext *>(data);
        std::unique_ptr<WifiHotspot> hotspot = GetHotspotInstance();
        if (hotspot == nullptr) {
            WIFI_LOGE("hotspot instance is null.");
            return;
        }
        TRACE_FUNC_CALL_NAME("hotspot->GetPowerModel");
        context->errorCode = hotspot->GetPowerModel(context->powerModel);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        PowerModelAsyncContext *context = static_cast<PowerModelAsyncContext *>(data);
        napi_create_int32(context->env, static_cast<int>(context->powerModel), &context->result);
        WIFI_LOGI("Push power model result to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_AP_EXT;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value SetPowerModel(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_AP_EXT);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_AP_EXT);

    int model = -1;
    napi_get_value_int32(env, argv[0], &model);
    std::unique_ptr<WifiHotspot> hotspot = GetHotspotInstance();
    WIFI_NAPI_ASSERT(env, hotspot != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_EXT);
    ErrCode ret = hotspot->SetPowerModel(static_cast<PowerModel>(model));
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Set power model error: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_EXT);
}
}  // namespace Wifi
}  // namespace OHOS
#endif