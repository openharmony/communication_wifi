/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_CONFIG_COUNTRY_FREQS_H
#define OHOS_WIFI_CONFIG_COUNTRY_FREQS_H

#include <string>
#include <vector>
#include "wifi_ap_msg.h"

namespace OHOS {
namespace Wifi {
struct CountryDefaultBandFreqs {
    std::string countryCode;
    BandType band;
    std::vector<int> freqs;
};

const std::vector<CountryDefaultBandFreqs> g_countryDefaultFreqs = {
    /* CN 2.4G valid frequencies */
    { "CN", BandType::BAND_2GHZ, {2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472} },
    /* CN 5G valid frequencies, exclude radar frequencies */
    { "CN", BandType::BAND_5GHZ, {5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825} },
};
}  // namespace Wifi
}  // namespace OHOS

#endif // OHOS_WIFI_CONFIG_COUNTRY_FREQS_H