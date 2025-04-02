/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_config_update.h"
#include <dlfcn.h>
#include "wifi_logger.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiConfigUpdate");
void* WifiConfigUpdate::handle_ = nullptr;

LibraryUtils::LibraryUtils(const std::string& libName, void*& handle, bool isDlclose)
    : libName_(libName), isDlclose_(isDlclose), handle_(handle)
{
    WIFI_LOGI("LibraryUtils begin, libName: %{public}s", libName_.c_str());
    if (handle_) {
        WIFI_LOGI("Already loaded, libName: %{public}s", libName_.c_str());
        return;
    }

    handle_ = dlopen(libName_.c_str(), RTLD_LAZY);
    if (!handle_) {
        WIFI_LOGI("dlopen %{public}s error: %{public}s", libName_.c_str(), dlerror());
    } else {
        WIFI_LOGI("dlopen success, libName: %{public}s", libName_.c_str());
    }

    WIFI_LOGI("LibraryUtils end, libName: %{public}s", libName_.c_str());
}

LibraryUtils::~LibraryUtils()
{
    WIFI_LOGI("~LibraryUtils");
    if (!handle_ || !isDlclose_) {
        return;
    }
    int ret = dlclose(handle_);
    handle_ = nullptr;
    WIFI_LOGI("dlclose result: %{public}d", ret);
}

void* LibraryUtils::GetFunc(const std::string& funcName)
{
    WIFI_LOGI("Get func start, libName: %{public}s, funcName: %{public}s", libName_.c_str(), funcName.c_str());

    if (!handle_) {
        WIFI_LOGI("Get func failed, handle is null, libName: %{public}s", libName_.c_str());
        return nullptr;
    }

    void* func = dlsym(handle_, funcName.c_str());
    char* error = dlerror();
    if (error != nullptr) {
        WIFI_LOGI("Get func failed, libName: %{public}s funcName: %{public}s, error: %{public}s",
            libName_.c_str(), funcName.c_str(), error);
        return nullptr;
    }

    WIFI_LOGI("Get func end, libName: %{public}s, funcName: %{public}s", libName_.c_str(), funcName.c_str());
    return func;
}

void WifiConfigUpdate::SaveWifiConfig(const char* ssid, const char* keyMgmt, const char* preSharedKey)
{
    WIFI_LOGI("saveWifiConfig begin");
    using SaveWifiConfigFunc = void(*)(const char*, const char*, const char*);
    SaveWifiConfigFunc saveWifiConfig = (SaveWifiConfigFunc)libUtils.GetFunc("SaveWifiConfiguration");
    if (!saveWifiConfig) {
        WIFI_LOGI("SaveWifiConfigFunc is null");
        return;
    }

    WIFI_LOGD("call func");
    saveWifiConfig(ssid, keyMgmt, preSharedKey);
    return;
}
} // namespace Wifi
} // namespace OHOS
