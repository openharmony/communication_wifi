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

#ifndef OHOS_WIFI_NETWORKSELECTOR_H
#define OHOS_WIFI_NETWORKSELECTOR_H

#include <algorithm>
#include <vector>
#include "wifi_log.h"
#include "wifi_settings.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "log_helper.h"
#include "sta_passpoint_network_evaluator.h"
#include "sta_saved_network_evaluator.h"
#include "sta_scored_network_evaluator.h"
#include "sta_define.h"

namespace OHOS {
namespace Wifi {
/*
 * The WiFi Network Selector supports multiple network types.
 * Each type can have an evaluator to select the optimal Wi-Fi network for the
 * device. Specify the network priority when registering the Wi-Fi network
 * evaluator with the Wi-Fi network selector. The value must be between 0 and
 * (EVALUATOR_MIN_PRIORITY - 1), where 0 indicates the highest priority. The
 * Wi-Fi network selector iterates from the highest priority to the lowest
 * priority registration scorer until the network is selected.
 */
static const int EVALUATOR_MIN_PRIORITY = 6;
static const int MAX_MUM_EVALUATOR = 6;
static const int MINIMUM_NETWORK_SELECTION_INTERVAL_S = 30;
static const int MINIMUM_5_GHZ_BAND_FREQUENCY_IN_MEGAHERTZ = 5000;
static const int RSSI_DELIMITING_VALUE = -65;
static const int MINIMUM_RSSI24 = -77;
static const int MINIMUM_RSSI5 = -80;

static const int LAST_USER_SELECTION_SUFFICIENT_S = 60;
static const int LEVEL = 6;
class StaNetworkSelector {
public:
    StaNetworkSelector();
    ~StaNetworkSelector();

    /**
     * @Description  Select the best network from the range.
     *
     * @param scanResults - WifiScanInfo list of all APs in the range(in)
     * @param blocklistedBssids - Blocklisted BSSID List(in)
     * @param info - Current Connected Network(in)
     * @param candidate - Candidate Network(out)
     * @Return success : WIFI_OPT_SUCCESS  failed : WIFI_OPT_FAILED
     */
    ErrCode SelectNetwork(WifiDeviceConfig &candidate, const std::vector<WifiScanInfo> &scanResults,
        std::vector<std::string> &blocklistedBssids, WifiLinkedInfo &info);

    /**
     * @Description  Registering the Network Evaluator
     *
     * @param evaluator - Network evaluator to be registered(in)
     * @param priority - Value between 0 and (SCORER_MIN_PRIORITY – 1)(in)
     * @Return success : true  failed : false
     */
    bool RegisterNetworkEvaluator(StaNetworkEvaluator *evaluator, int priority);

private:
    int LastNetworkSelectionTimeStamp;
    StaNetworkEvaluator *pEvaluators[MAX_MUM_EVALUATOR];
    /**
     * @Description  Filtering network
     *
     * @param scanResults - WifiScanInfo list of all APs in the range(in)
     * @param blocklistedBssids - Blocklisted BSSID List(in)
     * @param info - Current Connected Network(in)
     * @param filteredscanResults - Filtered Scan Result(out)
     */
    void FilterscanResults(std::vector<WifiScanInfo> &filteredscanResults, const std::vector<WifiScanInfo> &scanResults,
        std::vector<std::string> &blocklistedBssids, WifiLinkedInfo &info);
    /**
     * @Description  Whether the network needs to be switched.
     *
     * @param scanResults - WifiScanInfo list of all APs in the range(in)
     * @param info - Current Connected Network(in)
     * @Return success : true  failed : false
     */
    bool IsNetworkSelectionRequired(const std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info);
    /**
     * @Description  Whether the network strength is sufficient.
     *
     * @param scanResults - WifiScanInfo list of all APs in the range(in)
     * @param info - Current Connected Network(in)
     * @Return success : true  failed : false
     */
    bool IsCurrentNetworkSuffice(const std::vector<WifiScanInfo> &scanResults, WifiLinkedInfo &info);
    /**
     * @Description  Whether 5G networks are available.
     *
     * @param scanResults - WifiScanInfo list of all APs in the range(in)
     * @Return success : true  failed : false
     */
    bool Is5GHzNetworkAvailable(const std::vector<WifiScanInfo> &scanResults);
    /**
     * @Description  Select Roaming Network.
     *
     * @param filterdscanResults -Filtered network(in)
     * @param scanResults - WifiScanInfo list of all APs in the range(in)
     * @param info - Current Connected Network(in)
     * @param candidate - Candidate Network(out)
     * @Return success : true  failed : false
     */
    bool RoamingSelection(
        WifiDeviceConfig &candidate, std::vector<WifiScanInfo> &filteredscanResults, WifiLinkedInfo &info);
    /**
     * @Description  Select Roaming Network.
     *
     * @param WifiScanInfo - A scan result(in)
     * @param info - Current Connected Network(in)
     * @param candidate - Candidate Network(out)
     * @Return success : true  failed : false
     */
    bool RoamingEncryptionModeCheck(WifiDeviceConfig &candidate, WifiScanInfo scanInfo, WifiLinkedInfo &info);
    /**
     * @Description  Updating the Configuration Center Network.
     *
     */
    void UpdateConfigNetworks();
    /**
     * @Description  Whether the network is a 2.4G network.
     *
     * @param frequency(in)
     * @Return success : true  failed : false
     */
    bool Is24GNetwork(int frequency);
    /**
     * @Description  Whether the network is a 5G network.
     *
     * @param frequency(in)
     * @Return success : true  failed : false
     */
    bool Is5GNetwork(int frequency);
};
}  // namespace Wifi
}  // namespace OHOS
#endif