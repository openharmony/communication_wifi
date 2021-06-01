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
#ifndef OHOS_AP_CONFIG_UTIL_H
#define OHOS_AP_CONFIG_UTIL_H

#include <vector>
#include "ap_define.h"
#include "ap_macro.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_msg.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
constexpr int AP_CHANNEL_DEFAULT = 6;
constexpr int FREP_2G_MIN = 2412;
constexpr int FREP_2G_MAX = 2472;
constexpr int FREP_5G_MIN = 5170;
constexpr int FREP_5G_MAX = 5825;
constexpr int CHANNEL_14_FREP = 2484;
constexpr int CHANNEL_14 = 14;
constexpr int CENTER_FREP_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_5G_MIN = 34;

class ApConfigUse {
public:
    /**
     * @Description  Obtains the single instance
     * @param None
     * @return The reference of singleton objects
     */
    static ApConfigUse &GetInstance();
    /**
     * @Description  Delete the single instance
     * @param None
     * @return None
     */
    static void DeleteInstance();
    /**
     * @Description  Convert the frequency in the container into a channel.
     * @param freqVector - frequency vector input
     * @param chanVector - Channel vector output
     * @return None
     */
    void TransformFrequencyIntoChannel(std::vector<int> &freqVector, std::vector<int> &chanVector) const;
    /**
     * @Description  Check whether the channel or frequency band of the configuration
                     item is available and configure the configuration item.
     * @param apConfig - configuration input
     * @return true: success    false: failed
     */
    bool SetConfig(HotspotConfig &apConfig) const;
    /**
     * @Description  Check is a valid 2.4G frequency.
     * @param freq - Frequency input
     * @return true: is valid    false: bad frequency
     */
    bool IsValid24GHz(const int &freq) const;
    /**
     * @Description  Check is a valid 5G frequency.
     * @param freq - Frequency input
     * @return true: is valid    false: bad frequency
     */
    bool IsValid5GHz(const int &freq) const;
    /**
     * @Description  Obtain and report available channel information.
     * @param None
     * @return true: success    false: failed
     */
    bool ObtainValidChannels() const;
    /**
     * @Description  Obtain and report available channel information.
     * @param None
     * @return true: success    false: failed
     */
    void CheckBandChannel(HotspotConfig &apConfig) const;

private:
    /**
     * @Description  construction method
     * @param None
     * @return None
     */
    ApConfigUse();
    /**
     * @Description  destructor method
     * @param None
     * @return None
     */
    ~ApConfigUse();
    /**
     * @Description  Convert frequency to channel number
     * @param freq - frequency to convert
     * @return success: channel num    failed: -1
     */
    int TransformFrequencyIntoChannel(const int freq) const;

private:
    DISALLOW_COPY_AND_ASSIGN(ApConfigUse)
    static ApConfigUse *g_instance;
};
}  // namespace Wifi
}  // namespace OHOS

#endif