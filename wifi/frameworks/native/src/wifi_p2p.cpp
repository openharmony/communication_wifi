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
#include "wifi_p2p.h"
#include "wifi_p2p_impl.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"
DEFINE_WIFILOG_P2P_LABEL("WifiP2p");

namespace OHOS {
namespace Wifi {

std::mutex g_p2pMutex;
NO_SANITIZE("cfi") std::shared_ptr<WifiP2p> WifiP2p::GetInstance(int systemAbilityId)
{
    static std::shared_ptr<WifiP2pImpl> impl = nullptr;
    std::lock_guard<std::mutex> lock(g_p2pMutex);
    if (!impl) {
        impl = std::make_shared<WifiP2pImpl>();
    }
    if (impl && impl->Init(systemAbilityId)) {
        WIFI_LOGD("init p2p successfully!");
        return impl;
    } else {
        WIFI_LOGE("new wifi p2p failed");
        return nullptr;
    }
}

WifiP2p::~WifiP2p()
{}
}  // namespace Wifi
}  // namespace OHOS