#include <ani.h>
#include <array>
#include <iostream>
#include "wifi_device.h"

std::shared_ptr<OHOS::Wifi::WifiDevice> wifiDevicePtr = OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);

static ani_boolean isWifiActive([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    bool activeStatus = false;
    wifiDevicePtr->IsWifiActive(activeStatus);
    return static_cast<ani_boolean>(activeStatus);
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return (ani_status)9;
    }

    static const char *NameSpaceName = "Lwifi_manager/wifiManager;";
    ani_namespace wifimanager {};
    if (ANI_OK != env->FindNamespace(NameSpaceName, &wifimanager)) {
        std::cerr << "Not found '" << NameSpaceName << "'" << std::endl;
        return (ani_status)2;
    }

    std::array functions = {
        ani_native_function {"isWifiActive", ":Z", reinterpret_cast<ani_boolean *>(isWifiActive)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(wifimanager, functions.data(), functions.size())) {
        std::cerr << "Namespace_BindNativeFunctions not OK" << std::endl;
        return (ani_status)2;
    }
    std::cout << "Start bind native methods to '" << NameSpaceName << "'" << std::endl;

    *result = ANI_VERSION_1;
    return ANI_OK;
}