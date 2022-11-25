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

#ifndef WIFI_EXT_NAPI_HOTSPOT_H_
#define WIFI_EXT_NAPI_HOTSPOT_H_

#include <set>
#include "wifi_napi_utils.h"
#include "wifi_hotspot.h"

namespace OHOS {
namespace Wifi {
#ifdef FEATURE_AP_EXTENSION
napi_value EnableHotspot(napi_env env, napi_callback_info info);
napi_value DisableHotspot(napi_env env, napi_callback_info info);
napi_value GetSupportedPowerModel(napi_env env, napi_callback_info info);
napi_value GetPowerModel(napi_env env, napi_callback_info info);
napi_value SetPowerModel(napi_env env, napi_callback_info info);
#endif
class PowerModelAsyncContext : public AsyncContext {
public:
    PowerModel powerModel;

    PowerModelAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred), powerModel(PowerModel::GENERAL) {}

    PowerModelAsyncContext() = delete;
    ~PowerModelAsyncContext() override {}
};

class PowerModelListAsyncContext : public AsyncContext {
public:
    std::set<PowerModel> setPowerModelList;

    PowerModelListAsyncContext(napi_env env, napi_async_work work = nullptr, napi_deferred deferred = nullptr)
        : AsyncContext(env, work, deferred) {}

    PowerModelListAsyncContext() = delete;
    ~PowerModelListAsyncContext() override {}
};
}  // namespace Wifi
}  // namespace OHOS

#endif
