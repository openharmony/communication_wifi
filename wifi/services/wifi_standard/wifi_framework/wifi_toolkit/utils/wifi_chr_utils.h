/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_CHR_UTILS_H
#define OHOS_WIFI_CHR_UTILS_H

#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
class WifiChrUtils {

public:
    static void AddSignalPollInfoArray(WifiSignalPollInfo signalInfo);
    static void GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length);
    static void ClearSignalPollInfoArray();
};
}  // namespace Wifi
}  // namespace OHOS
#endif