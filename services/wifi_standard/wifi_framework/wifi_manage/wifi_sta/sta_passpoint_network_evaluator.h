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

#ifndef OHOS_WIFI_PASSPOINTNETWORKEVALUTOR_H
#define OHOS_WIFI_PASSPOINTNETWORKEVALUTOR_H

#include "wifi_log.h"
#include "wifi_errcode.h"
#include "sta_network_evaluator.h"

namespace OHOS {
namespace Wifi {
class StaPasspointNetworkEvaluator : public StaNetworkEvaluator {
    /* Passpoint network candidate information */
    class PasspointNetworkCandidate {
    public:
        PasspointNetworkCandidate();
        ~PasspointNetworkCandidate();
    };

public:
    StaPasspointNetworkEvaluator();
    ~StaPasspointNetworkEvaluator() override;
    /**
     * @Description  Update saved network selection status.
     *
     * @param scanResults - Scan details list constructed from the scan result
     */
    void Update(const std::vector<WifiScanInfo> &scanResults) override;
    /**
     * @Description  Evaluate the Passpoint network from the scanning result and
                    return the Wi-Fi configuration of the selected network.
     *
     * @param ScanResults - Scan details list constructed based on the scan result(in)
     * @param Info - Current network(in)
     * @param candidate - candidate network(out)
     * @Return: Configuration of the selected network; Null if no networks are available in this category
     */
    ErrCode NetworkEvaluators(
        WifiDeviceConfig &candidate, std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info) override;
};
}  // namespace Wifi
}  // namespace OHOS
#endif