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
#include "wifi_logger.h"
#include "wifi_settings.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiChannelHelper");

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
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->GetFrequenciesByBand(ifaceName, band, freqs2G)) {
        WIFI_LOGE("get 2g frequencies failed.");
        WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, freqs2G, instId);
    }
#endif
    band = static_cast<int>(BandType::BAND_5GHZ);
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    if (!DelayedSingleton<HalDeviceManager>::GetInstance()->GetFrequenciesByBand(ifaceName, band, freqs5G)) {
        WIFI_LOGE("get 5g frequencies failed.");
    }
#endif
    std::vector<int32_t> supp2Gfreqs(freqs2G.begin(), freqs2G.end());
    std::vector<int32_t> supp5Gfreqs(freqs5G.begin(), freqs5G.end());
    for (auto iter = supp2Gfreqs.begin(); iter != supp2Gfreqs.end(); iter++) {
        int32_t channel = FrequencyToChannel(*iter);
        if (channel == INVALID_FREQ_OR_CHANNEL) {
            continue;
        }
        chanTbs[BandType::BAND_2GHZ].push_back(channel);
    }
    for (auto iter = supp5Gfreqs.begin(); iter != supp5Gfreqs.end(); iter++) {
        int32_t channel = FrequencyToChannel(*iter);
        if (channel == INVALID_FREQ_OR_CHANNEL) {
            continue;
        }
        chanTbs[BandType::BAND_5GHZ].push_back(channel);
    }
    if (SetValidChannels(chanTbs)) {
        WIFI_LOGE("%{public}s, fail to SetValidChannels", __func__);
    }
}

} // namespace Wifi
} // namespace OHOS
