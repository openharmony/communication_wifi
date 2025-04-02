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
#include "wifi_device.h"
#include "wifi_device_impl.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("WifiDevice");

namespace OHOS {
namespace Wifi {

std::mutex g_instanceMutex;
NO_SANITIZE("cfi") std::shared_ptr<WifiDevice> WifiDevice::GetInstance(int systemAbilityId, int instId)
{
#ifndef OHOS_ARCH_LITE
    if (instId >= STA_INSTANCE_MAX_NUM || instId < 0) {
        WIFI_LOGE("the max obj id is %{public}d, current id is %{public}d", STA_INSTANCE_MAX_NUM, instId);
        return nullptr;
    }
#else
    if (instId != 0) {
        WIFI_LOGE("the current id is %{public}d", instId);
        return nullptr;
    }
#endif

    static std::vector<std::shared_ptr<WifiDeviceImpl>> devices = {nullptr, nullptr};
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    if (!devices[instId]) {
        devices[instId] = std::make_shared<WifiDeviceImpl>();
    }
    if (devices[instId] && devices[instId]->Init(systemAbilityId, instId)) {
        return devices[instId];
    } else {
        WIFI_LOGE("new wifi device failed.");
        return nullptr;
    }
}

WifiDevice::~WifiDevice()
{}
}  // namespace Wifi
}  // namespace OHOS
