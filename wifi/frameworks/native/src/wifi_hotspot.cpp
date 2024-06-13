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

#include "wifi_hotspot.h"
#include "wifi_hotspot_impl.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspot");

namespace OHOS {
namespace Wifi {
NO_SANITIZE("cfi") std::shared_ptr<WifiHotspot> WifiHotspot::GetInstance(int systemAbilityId, int id)
{
    if (id >= AP_INSTANCE_MAX_NUM) {
        WIFI_LOGE("the max obj id is %{public}d, current id is %{public}d", AP_INSTANCE_MAX_NUM, id);
        return nullptr;
    }

    std::shared_ptr<WifiHotspotImpl> hotspot = std::make_shared<WifiHotspotImpl>();
    if (hotspot && hotspot->Init(systemAbilityId, id)) {
        WIFI_LOGD("ap obj id:%{public}d succeeded, sa id:%{public}d", id, systemAbilityId);
        return hotspot;
    }

    WIFI_LOGE("new wifi hotspot id:%{public}d failed, sa id:%{public}d", id, systemAbilityId);
    return nullptr;
}

WifiHotspot::~WifiHotspot()
{}
}  // namespace Wifi
}  // namespace OHOS