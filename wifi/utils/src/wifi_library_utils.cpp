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

#include "wifi_library_utils.h"
#include <dlfcn.h>
#include "wifi_logger.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiLibraryUtils");
WifiLibraryUtils::WifiLibraryUtils(const std::string &libName, void*& libHandle, bool isDlClose)
    : libHandle_(libHandle), libName_(libName), isDlClose_(isDlClose)
{
    if (libName.empty()) {
        return;
    }
    if (libHandle_ != nullptr) {
        WIFI_LOGD("Library %s has been loaded", libName.c_str());
        return;
    }
    libHandle_ = dlopen(libName.c_str(), RTLD_LAZY);
    if (libHandle_ == nullptr) {
        WIFI_LOGE("Failed to load library %s, error: %s", libName.c_str(), dlerror());
    } else {
        WIFI_LOGI("Library %s loaded successfully", libName.c_str());
    }
}

WifiLibraryUtils::~WifiLibraryUtils()
{
    if (isDlClose_ && libHandle_ != nullptr) {
        if (dlclose(libHandle_) != 0) {
            WIFI_LOGE("Failed to close library %s, error: %s", libName_.c_str(), dlerror());
        } else {
            WIFI_LOGI("Library %s closed successfully", libName_.c_str());
        }
        libHandle_ = nullptr;
    }
}

void* WifiLibraryUtils::GetFunction(const std::string &funcName)
{
    if (libHandle_ == nullptr) {
        WIFI_LOGE("Library %s is not loaded", libName_.c_str());
        return nullptr;
    }
    void *func = dlsym(libHandle_, funcName.c_str());
    if (func == nullptr) {
        WIFI_LOGE("Failed to get function %s from library %s, error: %s",
            funcName.c_str(), libName_.c_str(), dlerror());
    }
    return func;
}
} // namespace Wifi
} // namespace OHOS