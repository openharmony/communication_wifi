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
#include <set>

namespace OHOS {
namespace Wifi {
class WifiChrUtils {

public:
    static WifiChrUtils &GetInstance();
    ~WifiChrUtils() = default;
    void AddSignalPollInfoArray(WifiSignalPollInfo signalInfo);
    void GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length);
    void ClearSignalPollInfoArray();
    void BeaconLostReport(const std::string &bssid, const int32_t signalLevel, const int32_t instId);

private:
    WifiChrUtils();
 
private:
    const int SIGNALARR_LENGTH = 6;
    std::vector<WifiSignalPollInfo> signalPollInfoArray;
    std::mutex signalInfoMutex;
    int64_t startTime_ = 0;
    std::mutex bssidMutex_;
    std::mutex setMutex_;
    std::set<std::string> uploadedBssidSet_;
    std::vector<std::string> bssidArray_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif