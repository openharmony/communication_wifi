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

#include "wifi_channel_helper.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_settings.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiChannelHelper");

constexpr int FREQ_2G_MIN = 2412;
constexpr int FREQ_2G_MAX = 2472;
constexpr int FREQ_5G_MIN = 5170;
constexpr int FREQ_5G_MAX = 5825;
constexpr int CHANNEL_14_FREQ = 2484;
constexpr int CHANNEL_14 = 14;
constexpr int CENTER_FREQ_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_2G_MAX = 14;  // 2484
constexpr int CHANNEL_5G_MIN = 34;
constexpr int CHANNEL_5G_MAX = 165;  // 5825
constexpr int FREQ_CHANNEL_1 = 2412;
constexpr int FREQ_CHANNEL_34 = 5170;
constexpr int FREQ_2G_MIN_RANGE = 2400;
constexpr int FREQ_2G_MAX_RANGE = 2500;
constexpr int FREQ_5G_MIN_RANGE = 4900;
constexpr int FREQ_5G_MAX_RANGE = 5900;

WifiChannelHelper::WifiChannelHelper()
{
    UpdateValidFreqs();
}

WifiChannelHelper &WifiChannelHelper::GetInstance()
{
    static WifiChannelHelper gWifiChannelHelper;
    return gWifiChannelHelper;
}

int WifiChannelHelper::GetValidBands(std::vector<BandType> &bands)
{
    std::unique_lock<std::mutex> lock(mMutex);
    auto it = mValidChannels.find(BandType::BAND_2GHZ);
    if (it != mValidChannels.end() && it->second.size() > 0) {
        bands.push_back(BandType::BAND_2GHZ);
    }
    it = mValidChannels.find(BandType::BAND_5GHZ);
    if (it != mValidChannels.end() && it->second.size() > 0) {
        bands.push_back(BandType::BAND_5GHZ);
    }
    return 0;
}

int WifiChannelHelper::SetValidChannels(const ChannelsTable &channelsInfo)
{
    std::unique_lock<std::mutex> lock(mMutex);
    mValidChannels = channelsInfo;
    return 0;
}

int WifiChannelHelper::GetValidChannels(ChannelsTable &channelsInfo)
{
    std::unique_lock<std::mutex> lock(mMutex);
    channelsInfo = mValidChannels;
    return 0;
}

void WifiChannelHelper::UpdateValidChannels(std::string ifaceName, int instId)
{
    WIFI_LOGI("enter UpdateValidChannels");
    ChannelsTable chanTbs;
    std::vector<int> freqs2G;
    std::vector<int> freqs5G;
    int band = static_cast<int>(BandType::BAND_2GHZ);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, freqs2G)) {
        WIFI_LOGE("get 2g frequencies failed.");
        WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, freqs2G, instId);
    }
#endif
    band = static_cast<int>(BandType::BAND_5GHZ);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, freqs5G)) {
        WIFI_LOGE("get 5g frequencies failed.");
    }
#endif
    std::vector<int32_t> supp2Gfreqs(freqs2G.begin(), freqs2G.end());
    std::vector<int32_t> supp5Gfreqs(freqs5G.begin(), freqs5G.end());
    for (auto iter = supp2Gfreqs.begin(); iter != supp2Gfreqs.end(); iter++) {
        int32_t channel = TransformFrequencyIntoChannel(*iter);
        if (channel == INVALID_FREQ_OR_CHANNEL) {
            continue;
        }
        chanTbs[BandType::BAND_2GHZ].push_back(channel);
    }
    for (auto iter = supp5Gfreqs.begin(); iter != supp5Gfreqs.end(); iter++) {
        int32_t channel = TransformFrequencyIntoChannel(*iter);
        if (channel == INVALID_FREQ_OR_CHANNEL) {
            continue;
        }
        chanTbs[BandType::BAND_5GHZ].push_back(channel);
    }
    if (SetValidChannels(chanTbs)) {
        WIFI_LOGE("%{public}s, fail to SetValidChannels", __func__);
    }
}

void WifiChannelHelper::UpdateValidFreqs()
{
    std::vector<int> freqs2G;
    std::vector<int> freqs5G;
    std::vector<int> freqsDfs;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName();
    int band = static_cast<int>(ScanBandType::SCAN_BAND_24_GHZ);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, freqs2G)) {
        WIFI_LOGE("get 2g frequencies failed.");
    }
#endif
    band = static_cast<int>(ScanBandType::SCAN_BAND_5_GHZ);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, freqs5G)) {
        WIFI_LOGE("get 5g frequencies failed.");
    }
#endif
    band = static_cast<int>(ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!HalDeviceManager::GetInstance().GetFrequenciesByBand(ifaceName, band, freqsDfs)) {
        WIFI_LOGE("get 5g frequencies failed.");
    }
#endif
    mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ] = freqs2G;
    mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ] = freqs5G;
    mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY] = freqsDfs;
}

bool WifiChannelHelper::GetAvailableScanFreqs(ScanBandType band, std::vector<int32_t>& freqs)
{
    switch (band) {
        case ScanBandType::SCAN_BAND_24_GHZ: {
            freqs.assign(mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ].end());
            return true;
        }
        case ScanBandType::SCAN_BAND_5_GHZ: {
            freqs.assign(mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].end());
            return true;
        }
        case ScanBandType::SCAN_BAND_BOTH: {
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ].end());
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].end());
            return true;
        }
        case ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY: {
            freqs.assign(mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY].end());
            return true;
        }
        case ScanBandType::SCAN_BAND_5_GHZ_WITH_DFS: {
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].end());
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY].end());
            return true;
        }
        case ScanBandType::SCAN_BAND_BOTH_WITH_DFS: {
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_24_GHZ].end());
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ].end());
            freqs.insert(freqs.end(), mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY].begin(),
                mValidFreqs[ScanBandType::SCAN_BAND_5_GHZ_DFS_ONLY].end());
            return true;
        }
        default:
            WIFI_LOGE("bandType(%{public}d) is error.\n", band);
            return false;
    }
}

bool WifiChannelHelper::IsFreqDbac(int freqA, int freqB)
{
    if (freqA == freqB) {
        return false;
    }
    if (IsValid5GHz(freqA) && IsValid5GHz(freqB)) {
        return true;
    }
    if (IsValid24GHz(freqA) && IsValid24GHz(freqB)) {
        return true;
    }
    return false;
}

bool WifiChannelHelper::IsChannelDbac(int channelA, int channelB)
{
    if (channelA == channelB) {
        return false;
    }
    if (IsValid5GChannel(channelA) && IsValid5GChannel(channelB)) {
        return true;
    }
    if (IsValid24GChannel(channelA) && IsValid24GChannel(channelB)) {
        return true;
    }
    return false;
}

void WifiChannelHelper::TransformFrequencyIntoChannel(const std::vector<int> &freqVector, std::vector<int> &chanVector)
{
    int channel;
    for (size_t i = 0; i < freqVector.size(); ++i) {
        channel = TransformFrequencyIntoChannel(freqVector[i]);
        if (channel == -1) {
            LOGW("Invalid Freq:%d", freqVector[i]);
            continue;
        }
        chanVector.push_back(channel);
    }
}

int WifiChannelHelper::TransformFrequencyIntoChannel(int freq)
{
    if (freq >= FREQ_2G_MIN && freq <= FREQ_2G_MAX) {
        return (freq - FREQ_2G_MIN) / CENTER_FREQ_DIFF + CHANNEL_2G_MIN;
    } else if (freq == CHANNEL_14_FREQ) {
        return CHANNEL_14;
    } else if (freq >= FREQ_5G_MIN && freq <= FREQ_5G_MAX) {
        return (freq - FREQ_5G_MIN) / CENTER_FREQ_DIFF + CHANNEL_5G_MIN;
    }
    return -1;
}

int WifiChannelHelper::TransformChannelToFrequency(int channel)
{
    WIFI_LOGI("ChannelToFrequency: %{public}d", channel);
    if (channel >= CHANNEL_2G_MIN && channel <= CHANNEL_2G_MAX) {
        return ((channel - CHANNEL_2G_MIN) * CENTER_FREQ_DIFF + FREQ_CHANNEL_1);
    }
    if (CHANNEL_5G_MIN <= channel && channel <= CHANNEL_5G_MAX) {
        return ((channel - CHANNEL_5G_MIN) * CENTER_FREQ_DIFF + FREQ_CHANNEL_34);
    }
    return INVALID_FREQ_OR_CHANNEL;
}

BandType WifiChannelHelper::TransformFreqToBand(int freq)
{
    if (freq <= CHANNEL_14_FREQ) {
        return BandType::BAND_2GHZ;
    } else if (freq <= FREQ_5G_MAX) {
        return BandType::BAND_5GHZ;
    }
    return BandType::BAND_NONE;  // not supported currently 6/60GHZ
}

BandType WifiChannelHelper::TransformChannelToBand(int channel)
{
    if (channel <= CHANNEL_2G_MAX) {
        return BandType::BAND_2GHZ;
    } else if (channel <= CHANNEL_5G_MAX) {
        return BandType::BAND_5GHZ;
    }
    return BandType::BAND_NONE;  // not supported currently 6/60GHZ
}

bool WifiChannelHelper::IsValidFreq(int freq)
{
    return IsValid24GHz(freq) && IsValid5GHz(freq);
}

bool WifiChannelHelper::IsValid24GHz(int freq)
{
    return freq > FREQ_2G_MIN_RANGE && freq < FREQ_2G_MAX_RANGE;
}

bool WifiChannelHelper::IsValid5GHz(int freq)
{
    return freq > FREQ_5G_MIN_RANGE && freq < FREQ_5G_MAX_RANGE;
}

bool WifiChannelHelper::IsValid24GChannel(int channel)
{
    return channel >= CHANNEL_2G_MIN && channel <= CHANNEL_2G_MAX;
}

bool WifiChannelHelper::IsValid5GChannel(int channel)
{
    return channel >= CHANNEL_5G_MIN && channel <= CHANNEL_5G_MAX;
}

} // namespace Wifi
} // namespace OHOS
