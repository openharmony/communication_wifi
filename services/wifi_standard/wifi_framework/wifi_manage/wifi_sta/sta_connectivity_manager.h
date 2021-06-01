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

#ifndef OHOS_WIFI_CONNECTIVITY_MANAGER_H
#define OHOS_WIFI_CONNECTIVITY_MANAGER_H

#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>
#include "wifi_log.h"
#include "wifi_settings.h"
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "log_helper.h"
#include "sta_define.h"
#include "sta_connectivity_helper.h"
#include "sta_network_selector.h"
#include "sta_state_machine.h"

namespace OHOS {
namespace Wifi {
static const int BSSID_BLOCKLIST_THRESHOLD = 3;
static const int REASON_CODE_AP_UNABLE_TO_HANDLE_NEW_STA = 17;
static const int BSSID_BLOCKLIST_EXPIRE_TIME_S = 5 * 60;
class StaConnectivityManager {
public:
    explicit StaConnectivityManager(StaStateMachine *staStateMachine);
    ~StaConnectivityManager();
    /**
     * @Description  Initialize ConnectivityManager
     *
     */
    ErrCode InitConnectivityManager();
    /**
     * @Description  Processing scan results
     *
     * @param scanResults - The list of scanning results(in)
     */
    void OnScanResultsReadyHandler(const std::vector<WifiScanInfo> &scanResults);
    /**
     * @Description  Whether tracking should enable or disable scanned BSSIDs
     *
     * @param bssid - BSSID to be enabled/disabled(in)
     * @param enable - true: Enable the BSSID. false: disable the BSSID.(in)
     * @param reasonCode - Enable/Disable reason code.(in)
     * @Return success: true. failed： false.
     */
    bool TrackBlockBssid(std::string bssid, bool enable, int reasonCode);

private:
    StaStateMachine *pStaStateMachine;
    StaNetworkEvaluator *pSavedNetworkEvaluator;
    StaNetworkEvaluator *pScoredNetworkEvaluator;
    StaNetworkEvaluator *pPasspointNetworkEvaluator;
    StaNetworkSelector *pNetworkSelector;
    StaConnectivityHelper *pConnectivityHelper;
    class BssidBlocklistStatus {
    public:
        int counter; /* Number of times the BSSID is rejected. */
        bool isBlocklisted;
        int blocklistedTimeStamp;
        BssidBlocklistStatus()
        {
            counter = 0;
            isBlocklisted = false;
            blocklistedTimeStamp = 0;
        }
        ~BssidBlocklistStatus(){}
    };
    std::unordered_map<std::string, BssidBlocklistStatus> bssidBlocklist;
    /**
     * @Description  Refreshing the BSSID Blocklist
     *
     */
    void RefreshBssidBlocklist();
    /**
     * @Description  Compiles and returns the hash set of the blocklist BSSID.
     *
     * @param blocklistedBssids - Blocklisted BSSID List(out)
     */
    void CreatBlocklist(std::vector<std::string> &blocklistedBssids);
    /**
     * @Description  Update the BSSID blocklist when the BSSID is enabled or disabled.
     *
     * @param bssid - BSSID to be enabled/disabled(in)
     * @param enable - true: Enable the BSSID. false: disable the BSSID.(in)
     * @param reasonCode - Enable/Disable reason code.(in)
     * @Return: If the blocklist is updated, The value is true. Otherwise, the value is false.
     */
    bool UpdateBssidBlocklist(std::string bssid, bool enable, int reasonCode);
    /**
     * @Description  If the firmware roaming function is supported,
                     update the firmware roaming config.
     *
     */
    void UpdateFirmwareRoamingConfig();
    /**
     * @Description  Connect to a candidate network
     *
     * @param candidate - Candidate Network(in)
     */
    void ConnectToNetwork(WifiDeviceConfig &candidate);
};
}  // namespace Wifi
}  // namespace OHOS
#endif