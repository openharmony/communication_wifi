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
#include "wifi_internal_msg.h"
#include "wifi_hisysevent.h"

namespace OHOS {
namespace Wifi {
WifiChrUtils &WifiChrUtils::GetInstance()
{
    static WifiChrUtils gWifiChrUtils;
    return gWifiChrUtils;
}
 
WifiChrUtils::WifiChrUtils()
{}

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
    std::unique_lock<std::mutex> lock(signalInfoMutex);
    int arrayLength = static_cast<int>(signalPollInfoArray.size());
    if (length > arrayLength) {
        length = arrayLength;
    }
    for (int index = 0; index < length; index++) {
        wifiSignalPollInfos.push_back(signalPollInfoArray[index]);
    }
}

void WifiChrUtils::BeaconLostReport(const std::string &bssid, const int32_t signalLevel, const int32_t instId)
{
    if (signalLevel < 0) return;
    std::vector<WifiSignalPollInfo> wifiCheckInfoArray = signalPollInfoArray;
    std::sort(wifiCheckInfoArray.begin(), wifiCheckInfoArray.end(),
        [](const WifiSignalPollInfo& a, const WifiSignalPollInfo& b) {return a.timeStamp > b.timeStamp;});
 
    bool beaconLost = false;
    {
        std::lock_guard<std::mutex> arrayLock(bssidMutex_);
        if (bssidArray_.size() >= SIGNALARR_LENGTH) bssidArray_.pop_back();
        bssidArray_.insert(bssidArray_.begin(), bssid);
        beaconLost = isBeaconLost(bssidArray_, wifiCheckInfoArray);
    }
 
    if (beaconLost) {
        LOGW("Beacon Lost.");
        int32_t errorCode = (signalLevel <= SIGNAL_LEVEL_TWO) ?
            BeaconLostType::SIGNAL_LEVEL_LOW : BeaconLostType::SIGNAL_LEVEL_HIGH;
        WriteWifiBeaconLostHiSysEvent(errorCode);
    }
}
}  // namespace Wifi
}  // namespace OHOS