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
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_ApConfigUse"

namespace OHOS {
namespace Wifi {
ApConfigUse *ApConfigUse::g_instance = nullptr;
ApConfigUse::ApConfigUse()
{}

ApConfigUse::~ApConfigUse()
{}

ApConfigUse &ApConfigUse::GetInstance()
{
    if (g_instance == nullptr) {
        g_instance = new ApConfigUse();
    }
    return *g_instance;
}

void ApConfigUse::DeleteInstance()
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

int ApConfigUse::TransformFrequencyIntoChannel(const int freq) const
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

void ApConfigUse::TransformFrequencyIntoChannel(std::vector<int> &freqVector, std::vector<int> &chanVector) const
{
    int channel;
    for (size_t i = 0; i < freqVector.size(); ++i) {
        channel = TransformFrequencyIntoChannel(freqVector[i]);
        if (channel == -1) {
            LOGW("Invalid Freq:%{public}d", freqVector[i]);
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
    LOGD("TransformFrequencyIntoChannel:size:(%zu) to (%zu).list: %{public}s",
        freqVector.size(),
        chanVector.size(),
        printList.c_str());
}

bool ApConfigUse::SetConfig(HotspotConfig &apConfig) const
{
    LOGI("enter SetConfig");
    std::string countryCode;
    WifiSettings::GetInstance().GetCountryCode(countryCode);
    if (WifiApHalInterface::GetInstance().SetWifiCountryCode(countryCode) != WifiErrorNo::WIFI_IDL_OPT_OK) {
        LOGE("set countryCode:%{public}s failed.", countryCode.c_str());
        return false;
    }

    LOGI("HotspotConfig::SSID         = %s", apConfig.GetSsid().c_str());
    LOGI("HotspotConfig::preSharedKey = %s", apConfig.GetPreSharedKey().c_str());
    LOGI("HotspotConfig::securityType = %{public}d", static_cast<int>(apConfig.GetSecurityType()));
    LOGI("HotspotConfig::band         = %{public}d", static_cast<int>(apConfig.GetBand()));
    LOGI("HotspotConfig::channel      = %{public}d", apConfig.GetChannel());
    LOGI("HotspotConfig::maxConn      = %{public}d", apConfig.GetMaxConn());
    LOGI("HotspotConfig  CountryCode  = %{public}s", countryCode.c_str());

    if (WifiApHalInterface::GetInstance().SetSoftApConfig(apConfig) != WifiErrorNo::WIFI_IDL_OPT_OK) {
        LOGE("set hostapd hotspot config failed.");
        return false;
    }
    LOGI("SetConfig OK!");
    return true;
}

bool ApConfigUse::IsValid24GHz(const int &freq) const
{
    return (freq > FREP_2G_MIN) && (freq < FREP_2G_MAX);
}

bool ApConfigUse::IsValid5GHz(const int &freq) const
{
    return (freq > FREP_5G_MIN) && (freq < FREP_5G_MAX);
}

bool ApConfigUse::ObtainValidChannels() const
{
    std::vector<int> allowed5GFreq, allowed2GFreq;
    std::vector<int> allowed5GChan, allowed2GChan;
    if (WifiApHalInterface::GetInstance().GetFrequenciesByBand(static_cast<int>(BandType::BAND_2GHZ), allowed2GFreq)) {
        LOGE("failed to get 2.4G channel");
    }
    if (WifiApHalInterface::GetInstance().GetFrequenciesByBand(static_cast<int>(BandType::BAND_5GHZ), allowed5GFreq)) {
        LOGE("failed to get 5G channel");
    }

    TransformFrequencyIntoChannel(allowed5GFreq, allowed5GChan);
    TransformFrequencyIntoChannel(allowed2GFreq, allowed2GChan);

    ChannelsTable ChanTbs;
    ChanTbs[BandType::BAND_2GHZ] = allowed2GChan;
    ChanTbs[BandType::BAND_5GHZ] = allowed5GChan;

    if (WifiSettings::GetInstance().SetValidChannels(ChanTbs)) {
        LOGE("failed to SetValidChannels");
        return false;
    }
    return true;
}

void ApConfigUse::CheckBandChannel(HotspotConfig &apConfig) const
{
    ChannelsTable chanTable;
    WifiSettings::GetInstance().GetValidChannels(chanTable);
    bool cfgValid = false;
    auto it = chanTable.find(apConfig.GetBand());
    if (it != chanTable.end() && it->second.size() != 0) {
        for (auto vecIt = it->second.begin(); vecIt != it->second.end(); ++vecIt) {
            if (*vecIt == apConfig.GetChannel()) {
                cfgValid = true;
                break;
            }
        }
    }
    if (!cfgValid) {
        LOGW("Error band or error channels in band, use 2.4G band default channel.");
        apConfig.SetBand(BandType::BAND_2GHZ);
        apConfig.SetChannel(AP_CHANNEL_DEFAULT);
    }
}
}  // namespace Wifi
}  // namespace OHOS