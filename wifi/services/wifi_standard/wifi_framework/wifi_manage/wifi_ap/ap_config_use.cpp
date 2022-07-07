/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "ap_config_use.h"
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <random>
#include "log_helper.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApConfigUse");

namespace OHOS {
namespace Wifi {
ApConfigUse::ApConfigUse(int id) : m_id(id)
{}

ApConfigUse::~ApConfigUse()
{}

int ApConfigUse::TransformFrequencyIntoChannel(int freq) const
{
    if (freq >= FREP_2G_MIN && freq <= FREP_2G_MAX) {
        return (freq - FREP_2G_MIN) / CENTER_FREP_DIFF + CHANNEL_2G_MIN;
    } else if (freq == CHANNEL_14_FREP) {
        return CHANNEL_14;
    } else if (freq >= FREP_5G_MIN && freq <= FREP_5G_MAX) {
        return (freq - FREP_5G_MIN) / CENTER_FREP_DIFF + CHANNEL_5G_MIN;
    }
    return -1;
}

void ApConfigUse::TransformFrequencyIntoChannel(const std::vector<int> &freqVector, std::vector<int> &chanVector) const
{
    int channel;
    for (size_t i = 0; i < freqVector.size(); ++i) {
        channel = TransformFrequencyIntoChannel(freqVector[i]);
        if (channel == -1) {
            WIFI_LOGW("Invalid Freq:%{public}d.", freqVector[i]);
        } else {
            chanVector.push_back(channel);
        }
    }

    /* just printf to debug */
    std::string printList;
    for (size_t i = 0; i < chanVector.size(); ++i) {
        printList += std::to_string(chanVector[i]);
        printList += "  ";
    }
    WIFI_LOGD("TransformFrequencyIntoChannel:size:(%{public}zu) to (%{public}zu).list: %{public}s.",
        freqVector.size(),
        chanVector.size(),
        printList.c_str());
}

void ApConfigUse::LogConfig(HotspotConfig &apConfig) const
{
    WIFI_LOGI("current instance is %{public}d", m_id);
    WIFI_LOGI("HotspotConfig::SSID         = %{private}s", apConfig.GetSsid().c_str());
    WIFI_LOGI("HotspotConfig::preSharedKey = %{private}s", apConfig.GetPreSharedKey().c_str());
    WIFI_LOGI("HotspotConfig::securityType = %{public}d", static_cast<int>(apConfig.GetSecurityType()));
    WIFI_LOGI("HotspotConfig::band         = %{public}d", static_cast<int>(apConfig.GetBand()));
    WIFI_LOGI("HotspotConfig::channel      = %{public}d", apConfig.GetChannel());
    WIFI_LOGI("HotspotConfig::maxConn      = %{public}d", apConfig.GetMaxConn());
}

bool ApConfigUse::IsValid24GHz(int freq) const
{
    return (freq >= FREP_2G_MIN) && (freq <= CHANNEL_14_FREP);
}

bool ApConfigUse::IsValid5GHz(int freq) const
{
    return (freq >= FREP_5G_MIN) && (freq <= FREP_5G_MAX);
}

void ApConfigUse::ApplyDefaultConfig(HotspotConfig &apConfig, std::vector<int32_t> &vecChannels) const
{
    if (!vecChannels.empty()) {
        apConfig.SetChannel(vecChannels.front());
        return;
    }

    if (apConfig.GetBand() == BandType::BAND_2GHZ) {
        apConfig.SetChannel(AP_CHANNEL_DEFAULT);
        return;
    }
    if (apConfig.GetBand() == BandType::BAND_5GHZ) {
        apConfig.SetChannel(AP_CHANNEL_5G_DEFAULT);
        return;
    }
    apConfig.SetBand(BandType::BAND_2GHZ);
    apConfig.SetChannel(AP_CHANNEL_DEFAULT);
    return;
}

void ApConfigUse::CheckBandChannel(HotspotConfig &apConfig, const ChannelsTable &validChanTable) const
{
    bool cfgValid = false;
    std::vector<int32_t> vecChannels;
    auto it = validChanTable.find(apConfig.GetBand());
    if (it != validChanTable.end() && it->second.size() != 0) {
        vecChannels = it->second;
        for (auto vecIt = it->second.begin(); vecIt != it->second.end(); ++vecIt) {
            if (*vecIt == apConfig.GetChannel()) {
                cfgValid = true;
                break;
            }
        }
    }
    if (!cfgValid) {
        WIFI_LOGE("Error band or error channels in band: %{public}d, %{public}d",
            static_cast<int>(apConfig.GetBand()), apConfig.GetChannel());
        ApplyDefaultConfig(apConfig, vecChannels);
        WIFI_LOGI("Use default config: %{public}d, %{public}d",
            static_cast<int>(apConfig.GetBand()), apConfig.GetChannel());
    }
}
}  // namespace Wifi
}  // namespace OHOS