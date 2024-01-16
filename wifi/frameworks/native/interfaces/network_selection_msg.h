/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_NETWORK_SELECTION_MSG_H_
#define OHOS_WIFI_NETWORK_SELECTION_MSG_H_

#include "wifi_msg.h"
#include "inter_scan_info.h"
#include <functional>

namespace OHOS {
namespace Wifi {
struct NetworkCandidate {
    const InterScanInfo &interScanInfo;
    WifiDeviceConfig wifiDeviceConfig;
    std::vector<std::string> filteredMsg;
    std::vector<std::string> nominateMsg;
    explicit NetworkCandidate(const InterScanInfo &interScanInfo) : interScanInfo(interScanInfo), wifiDeviceConfig() {}
};

enum class FilterTag {
    SAVED_NETWORK_SELECTOR_FILTER_TAG,
    HAS_INTERNET_NETWORK_SELECTOR_FILTER_TAG,
    RECOVERY_NETWORK_SELECTOR_FILTER_TAG,
    PORTAL_NETWORK_SELECTOR_FILTER_TAG
};

using FilterFunc = std::function<bool(NetworkCandidate &)>;
using FilterBuilder = std::function<void(FilterFunc &)>;
}
}
#endif
