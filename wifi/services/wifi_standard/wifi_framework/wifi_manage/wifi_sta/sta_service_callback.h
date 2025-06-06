/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_STASERVICE_CALLBACK_H
#define OHOS_STASERVICE_CALLBACK_H

#include <functional>
#include <string>
#include "wifi_internal_msg.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
struct StaServiceCallback {
    std::string callbackModuleName;
    std::function<void(OperateResState, int)> OnStaOpenRes { nullptr };
    std::function<void(OperateResState, int)> OnStaCloseRes { nullptr };
    std::function<void(OperateResState, const WifiLinkedInfo &, int)> OnStaConnChanged { nullptr };
    std::function<void(WpsStartState, const int, int)> OnWpsChanged { nullptr };
    std::function<void(StreamDirection, int)> OnStaStreamChanged { nullptr };
    std::function<void(int, int)> OnStaRssiLevelChanged { nullptr };
    std::function<void(OperateResState, int)> OnStaSemiActiveRes { nullptr };
    std::function<void(IpInfo, int)> OnDhcpOfferReport { nullptr };
    std::function<void(int, int)> OnAutoSelectNetworkRes { nullptr };
    std::function<void(const WifiSignalPollInfo &)> OnWifiHalSignalInfoChange { nullptr };
    std::function<void(int, int)> OnInternetAccessChange { nullptr };
    std::function<void(const std::string, const int, const int)> OnSignalPollReport { nullptr };
};
}  // namespace Wifi
}  // namespace OHOS
#endif