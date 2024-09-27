/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_PRO_UTILS_H
#define OHOS_WIFI_PRO_UTILS_H

#include "wifi_log.h"
#include "wifi_pro_common.h"

namespace OHOS {
namespace Wifi {
class WifiProUtils {
    FRIEND_GTEST(WifiProUtils);
public:
    WifiProUtils() = default;
    ~WifiProUtils() = default;
    static int32_t GetSignalLevel(int32_t instId);
    static bool IsWifiConnected(int32_t instId);
    static int32_t GetScanInterval(bool hasWifiSwitchRecord, int32_t rssiLevel);
    static int32_t GetMaxCounter(bool hasWifiSwitchRecord, int32_t rssiLevel);
    static int64_t GetCurrentTimeMs();
    static bool IsUserSelectNetwork();
    static bool IsSupplicantConnecting(SupplicantState supplicantState);
    static bool IsDefaultNet();
    static bool IsAppInWhiteLists();
};

}  // namespace Wifi
}  // namespace OHOS
#endif