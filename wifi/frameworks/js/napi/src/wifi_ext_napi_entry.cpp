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

namespace OHOS {
namespace Wifi {

static napi_value PowerModelInit(napi_env env)
{
    napi_value PowerModel = nullptr;
    napi_create_object(env, &PowerModel);
    SetNamedPropertyByInteger(env, PowerModel, static_cast<int>(PowerModelJs::SLEEPING), "SLEEPING");
    SetNamedPropertyByInteger(env, PowerModel, static_cast<int>(PowerModelJs::GENERAL), "GENERAL");
    SetNamedPropertyByInteger(env, PowerModel, static_cast<int>(PowerModelJs::THROUGH_WALL), "THROUGH_WALL");
    return PowerModel;
}
static napi_value PropertyValueInit(napi_env env, napi_value exports)
{
    napi_value PowerModeloBJ = PowerModelInit(env);
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("PowerModel", PowerModeloBJ)
    };
    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);
    return exports;
}

/*
 * Module initialization function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    PropertyValueInit(env, exports);
    napi_property_descriptor desc[] = {
#ifdef FEATURE_AP_EXTENSION
        DECLARE_NAPI_FUNCTION("enableHotspot", EnableHotspot),
        DECLARE_NAPI_FUNCTION("disableHotspot", DisableHotspot),
        DECLARE_NAPI_FUNCTION("getSupportedPowerModel", GetSupportedPowerModel),
        DECLARE_NAPI_FUNCTION("getPowerModel", GetPowerModel),
        DECLARE_NAPI_FUNCTION("setPowerModel", SetPowerModel),
#endif
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc));
    return exports;
}

static napi_module wifiExtJsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = NULL,
    .nm_register_func = Init,
#ifdef ENABLE_NAPI_WIFI_MANAGER
    .nm_modname = "wifiManagerExt",
#else
    .nm_modname = "wifiext",
#endif
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&wifiExtJsModule);
}
}  // namespace Wifi
}  // namespace OHOS
