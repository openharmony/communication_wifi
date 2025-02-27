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

#include "wifi_chr_utils.h"
#include "wifi_log.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
static const int SIGNALARR_LENGTH = 6;
static std::vector<WifiSignalPollInfo> signalPollInfoArray;
std::mutex signalInfoMutex;

void WifiChrUtils::AddSignalPollInfoArray(WifiSignalPollInfo signalInfo)
{
    std::unique_lock<std::mutex> lock(signalInfoMutex);
    if (signalPollInfoArray.size() >= SIGNALARR_LENGTH) {
        signalPollInfoArray.pop_back();
        signalPollInfoArray.insert(signalPollInfoArray.begin(), signalInfo);
    } else {
        signalPollInfoArray.push_back(signalInfo);
    }
}

void WifiChrUtils::ClearSignalPollInfoArray()
{
    std::unique_lock<std::mutex> lock(signalInfoMutex);
    signalPollInfoArray.clear();
}

void WifiChrUtils::GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length)
{
    LOGI("Eneter GetSignalPollInfoArray.");
    if (length > wifiSignalPollInfos.size()) {
        length = wifiSignalPollInfos.size();
    }
    std::unique_lock<std::mutex> lock(signalInfoMutex);
    for (int index = 0; index < length; index++) {
        wifiSignalPollInfos.push_back(signalPollInfoArray[index]);
    }
}
}  // namespace Wifi
}  // namespace OHOS