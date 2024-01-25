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
NO_SANITIZE("cfi") std::shared_ptr<WifiDevice> WifiDevice::GetInstance(int systemAbilityId, int instId)
{
#ifndef OHOS_ARCH_LITE
    if (instId >= STA_INSTANCE_MAX_NUM) {
        WIFI_LOGE("the max obj id is %{public}d, current id is %{public}d", STA_INSTANCE_MAX_NUM, instId);
        return nullptr;
    }
#endif

    std::shared_ptr<WifiDeviceImpl> device = std::make_shared<WifiDeviceImpl>();
    if (device && device->Init(systemAbilityId, instId)) {
        return device;
    }

    WIFI_LOGE("new wifi device failed!");
    return nullptr;
}

WifiDevice::~WifiDevice()
{}
}  // namespace Wifi
}  // namespace OHOS