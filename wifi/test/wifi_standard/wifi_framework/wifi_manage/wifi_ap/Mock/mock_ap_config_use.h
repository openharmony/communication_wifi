/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_MOCK_AP_CONFIG_USE_H
#define OHOS_MOCK_AP_CONFIG_USE_H

#include <gmock/gmock.h>
#include <vector>

#include "ap_macro.h"
#include "wifi_msg.h"
#include "ap_config_use.h"
#include "wifi_ap_msg.h"

namespace OHOS {
namespace Wifi {
class MockApConfigUse : public ApConfigUse {
public:
    MOCK_CONST_METHOD1(UpdateApChannelConfig, void(HotspotConfig &apConfig));
    MOCK_CONST_METHOD1(JudgeConflictBand, void(HotspotConfig &apConfig));
    MOCK_CONST_METHOD0(GetBestChannelFor2G, int());
    MOCK_CONST_METHOD0(GetBestChannelFor5G, int());
    MOCK_CONST_METHOD1(GetChannelFromDrvOrXmlByBand, std::vector<int>(const BandType &bandType));
    MOCK_CONST_METHOD1(FilterIndoorChannel, void(std::vector<int> &channels));
    MOCK_CONST_METHOD1(Filter165Channel, void(std::vector<int> &channels));
    MOCK_CONST_METHOD1(JudgeDbacWithP2p, void(HotspotConfig &apConfig));
    MOCK_CONST_METHOD1(GetIndoorChannels, std::set<int>(const std::string &countryCode));
    MOCK_CONST_METHOD1(GetPreferredChannels, std::set<int>(const BandType &bandType));
};
} // namespace Wifi
} // namespace OHOS
#endif
