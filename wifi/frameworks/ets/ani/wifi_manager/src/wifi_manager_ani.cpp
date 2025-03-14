/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ani.h>
#include <array>
#include <iostream>
#include "wifi_manager_ani.h"
#include "wifi_logger.h"
#include "wifi_device.h"

using namespace OHOS::Wifi;

std::shared_ptr<WifiDevice> g_wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);

ani_boolean IsWifiActive([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    bool activeStatus = false;
    ErrCode ret = g_wifiDevicePtr->IsWifiActive(activeStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        std::cerr << "IsWifiActive failed." << std::endl;
    }
    return static_cast<ani_boolean>(activeStatus);
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return ANI_OUT_OF_REF;
    }

    static const char *NameSpaceName = "L@ohos/wifiManager/wifiManager;";
    ani_namespace wifimanager {};
    if (ANI_OK != env->FindNamespace(NameSpaceName, &wifimanager)) {
        std::cerr << "Not found '" << NameSpaceName << "'" << std::endl;
        return ANI_INVALID_ARGS;
    }

    std::array functions = {
        ani_native_function {"isWifiActive", ":Z", reinterpret_cast<ani_boolean *>(IsWifiActive)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(wifimanager, functions.data(), functions.size())) {
        std::cerr << "Namespace_BindNativeFunctions not OK" << std::endl;
        return ANI_INVALID_ARGS;
    }
    std::cout << "Start bind native methods to '" << NameSpaceName << "'" << std::endl;

    *result = ANI_VERSION_1;
    return ANI_OK;
}