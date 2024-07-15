/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "wifi_base_hal_interface.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiBaseHalInterface"

namespace OHOS {
namespace Wifi {
WifiBaseHalInterface::WifiBaseHalInterface()
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    mHdiWpaClient = nullptr;
#else
    mIdlClient = nullptr;
#endif
}

WifiBaseHalInterface::~WifiBaseHalInterface()
{
#ifdef HDI_WPA_INTERFACE_SUPPORT
    if (mHdiWpaClient != nullptr) {
        delete mHdiWpaClient;
        mHdiWpaClient = nullptr;
    }
#else
    if (mIdlClient != nullptr) {
        delete mIdlClient;
        mIdlClient = nullptr;
    }
#endif
}

#ifdef HDI_WPA_INTERFACE_SUPPORT
bool WifiBaseHalInterface::InitHdiWpaClient(void)
{
    if (mHdiWpaClient == nullptr) {
        mHdiWpaClient = new (std::nothrow) WifiHdiWpaClient;
    }
    if (mHdiWpaClient == nullptr) {
        LOGE("Failed to create hdi wpa client");
        return false;
    }
    return true;
}
#else
bool WifiBaseHalInterface::InitIdlClient(void)
{
    if (mIdlClient == nullptr) {
        mIdlClient = new (std::nothrow) WifiIdlClient;
    }
    if (mIdlClient == nullptr) {
        LOGE("Failed to create idl client");
        return false;
    }
    if (mIdlClient->InitClient() != 0) {
        LOGE("Failed to init idl client");
        return false;
    }
    return true;
}

void WifiBaseHalInterface::ExitAllIdlClient(void)
{
    LOGI("Exit all idl client!");
    if (mIdlClient != nullptr) {
        mIdlClient->ExitAllClient();
    }
    return;
}
#endif
}  // namespace Wifi
}  // namespace OHOS