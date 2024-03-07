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

#include "wifi_hid2d.h"
#include "wifi_p2p_impl.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("Hid2d");

namespace OHOS {
namespace Wifi {
NO_SANITIZE("cfi") std::shared_ptr<Hid2d> Hid2d::GetInstance(int systemAbilityId)
{
    std::shared_ptr<WifiP2pImpl> impl = std::make_shared<WifiP2pImpl>();
    if (impl && impl->Init(systemAbilityId)) {
        return impl;
    }

    WIFI_LOGE("new wifi hid2d failed");
    return nullptr;
}

Hid2d::~Hid2d()
{}
}  // namespace Wifi
}  // namespace OHOS