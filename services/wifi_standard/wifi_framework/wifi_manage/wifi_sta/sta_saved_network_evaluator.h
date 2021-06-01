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

#ifndef OHOS_WIFI_SAVEDNETWORKEVALUATOR_H
#define OHOS_WIFI_SAVEDNETWORKEVALUATOR_H

#include "wifi_log.h"
#include "wifi_settings.h"
#include "sta_connectivity_helper.h"
#include "sta_network_evaluator.h"

namespace OHOS {
namespace Wifi {
class StaSavedNetworkEvaluator : public StaNetworkEvaluator {
public:
    explicit StaSavedNetworkEvaluator(const StaConnectivityHelper *connectivityHelper);
    ~StaSavedNetworkEvaluator() override;
    /**
     * @Description  Update saved network selection status.
     *
     * @param scanResults - Scan details list constructed from the scan result
     */
    void Update(const std::vector<WifiScanInfo> &scanResults) override;
    /**
     * @Description  Evaluate the Saved network from the scanning result and
                    return the Wi-Fi configuration of the selected network.
     *
     * @param ScanResults - Scan details list constructed based on the scan result(in)
     * @param Info - Current network(in)
     * @param candidate - candidate network(out)
     * @Return: Configuration of the selected network; Null if no networks are available in this category
     */
    ErrCode NetworkEvaluators(
        WifiDeviceConfig &candidate, std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info) override;

private:
    int ScoreSlope;
    int InitScore;
    int SameBssidScore;
    int SameNetworkScore;
    int Frequency5GHzScore;
    int LastSelectionScore;
    int SecurityScore;
    const int iSignalBars;
    const StaConnectivityHelper *pConnectivityHelper;
    /**
     * @Description  Scoring mechanism.
     *
     * @param scanInfo - Scan Information.(in)
     * @param network - Saved Network.(in)
     * @param info - Connection information.(in)
     * @param score - score points.(out)
     */
    void CalculateNetworkScore(int &score, WifiScanInfo &scanInfo, WifiDeviceConfig &network, WifiLinkedInfo &info);
    /**
     * @Description  Signal strength converted to grids.
     *
     * @param rssi - Signal strength(in)
     * @param signalBars - Max Bars(in)
     * @Return: signal Bars
     */

    bool SkipNetwork(WifiDeviceConfig &network);
    int CalculateSignalBars(int rssi, int signalBars);
    /**
     * @Description  Whether the network is a 5G network.
     *
     * @param frequency(in)
     * @Return success: true; failed: false
     */
    bool Is5GNetwork(int frequency);
};
}  // namespace Wifi
}  // namespace OHOS
#endif