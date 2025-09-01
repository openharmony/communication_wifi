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
    signalPollInfoItem_ = signalInfo;
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

bool WifiChrUtils::IsBeaconLost(const std::string &bssid, const int32_t signalLevel, const int32_t screenState,
    const int32_t instId)
{
    if (signalLevel < 0) return false;
    WifiSignalPollInfo wifiCheckInfo;
    {
        std::unique_lock<std::mutex> lock(signalInfoMutex);
        wifiCheckInfo = signalPollInfoItem_;
    }
    bool beaconLost = OHOS::Wifi::IsBeaconLost(bssid, wifiCheckInfo, screenState);
    if (beaconLost) {
        LOGW("Beacon Lost, signalLevel: %{public}d", signalLevel);
        if (screenState == MODE_STATE_OPEN) {
            WriteWifiBeaconLostHiSysEvent((signalLevel <= SIGNAL_LEVEL_TWO) ?
                BeaconLostType::SIGNAL_LEVEL_LOW : BeaconLostType::SIGNAL_LEVEL_HIGH);
        } else {
            WriteWifiBeaconLostHiSysEvent((signalLevel <= SIGNAL_LEVEL_TWO) ?
                BeaconLostType::SIGNAL_LEVEL_LOW_OFF_SCREEN : BeaconLostType::SIGNAL_LEVEL_HIGH_OFF_SCREEN);
        }
    }
    bool beaconAbnormal = OHOS::Wifi::IsBeaconAbnormal(bssid, wifiCheckInfo);
    if (beaconAbnormal) {
        LOGW("Beacon Abnormal, signalLevel: %{public}d", signalLevel);
        const int64_t checkTime = wifiCheckInfo.timeStamp;
        if (checkTime - intTime > BEACON_ABNORMAL_TWO_HOUR) {
            intTime = checkTime;
            WriteWifiBeaconLostHiSysEvent(BeaconLostType::BEACON_ABNORMAL);
        }
    }
    return beaconLost;
}
}  // namespace Wifi
}  // namespace OHOS