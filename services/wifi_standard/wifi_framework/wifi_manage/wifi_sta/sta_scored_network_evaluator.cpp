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

#include "sta_scored_network_evaluator.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_SCORED_NETWORK_EVALUATOR"

namespace OHOS {
namespace Wifi {
StaScoredNetworkEvaluator::StaScoredNetworkEvaluator()
{}
StaScoredNetworkEvaluator::~StaScoredNetworkEvaluator()
{
    LOGI("StaScoredNetworkEvaluator::~StaScoredNetworkEvaluator");
}

void StaScoredNetworkEvaluator::Update(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaScoredNetworkEvaluator::Update.\n");
    UpdateNetworkScoreCache(scanResults);
}

void StaScoredNetworkEvaluator::UpdateNetworkScoreCache(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter UpdateNetworkScoreCache.[%s]\n", scanResults[0].bssid.c_str());
}

ErrCode StaScoredNetworkEvaluator::NetworkEvaluators(
    WifiDeviceConfig &candidate, std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info)
{
    LOGI("Enter StaScoredNetworkEvaluator::NetworkEvaluators.[%s]\n", candidate.bssid.c_str());
    LOGI("Enter StaScoredNetworkEvaluator::NetworkEvaluators.[%s]\n", scanResults[0].bssid.c_str());
    LOGI("Enter StaScoredNetworkEvaluator::NetworkEvaluators.[%s]\n", info.bssid.c_str());

    return WIFI_OPT_FAILED;
}
}  // namespace Wifi
}  // namespace OHOS