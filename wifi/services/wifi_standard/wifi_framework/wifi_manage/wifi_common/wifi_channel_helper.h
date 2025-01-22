/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INCLUDE_WIFI_CHANNEL_HELPER_H
#define INCLUDE_WIFI_CHANNEL_HELPER_H

#include "wifi_errcode.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {
using ChannelsTable = std::map<BandType, std::vector<int32_t>>;
inline const std::map <BandType, std::vector<int32_t>> DEFAULT_VALID_CHANNEL = {{
    BandType::BAND_2GHZ, { 2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472 }}};
class WifiChannelHelper {
public:
    static WifiChannelHelper &GetInstance();

    int GetValidBands(std::vector<BandType> &bands);

    int SetValidChannels(const ChannelsTable &channelsInfo);

    int GetValidChannels(ChannelsTable &channelsInfo);

    void UpdateValidChannels(std::string ifaceName, int instId = 0);

    bool GetAvailableScanFreqs(ScanBandType band, std::vector<int32_t>& freqs);

    bool IsFreqDbac(int freqA, int freqB);

    bool IsChannelDbac(int channelA, int channelB);

    void TransformFrequencyIntoChannel(const std::vector<int> &freqVector, std::vector<int> &chanVector);

    int TransformFrequencyIntoChannel(int freq);

    int TransformChannelToFrequency(int channel);

    BandType TransformFreqToBand(int freq);

    BandType TransformChannelToBand(int channel);

    bool IsValidFreq(int freq);

    bool IsValid5GHz(int freq);

    bool IsValid24GHz(int freq);

    bool IsValid24GChannel(int channel);

    bool IsValid5GChannel(int channel);

private:
    WifiChannelHelper();
    void UpdateValidFreqs();
    ChannelsTable mValidChannels {DEFAULT_VALID_CHANNEL};
    std::mutex mMutex;
    std::map<ScanBandType, std::vector<int>> mValidFreqs;
};
    
}  // namespace Wifi
}  // namespace OHOS
#endif
