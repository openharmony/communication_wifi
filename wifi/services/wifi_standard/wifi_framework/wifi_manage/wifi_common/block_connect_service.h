/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_BLOCK_CONNECT_SERVICE_H
#define OHOS_BLOCK_CONNECT_SERVICE_H
#include "wifi_logger.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_settings.h"
#include "wifi_common_util.h"
#include "wifi_msg.h"
namespace OHOS {
namespace Wifi {
struct LastConnectedApInfo {
    std::string bssid;
    int64_t lastDisconnectTimestamp;
    int alreadyConnectedCount;
};
struct DisablePolicy {
    int64_t disableTime;
    int64_t disableCount;
    WifiDeviceConfigStatus disableStatus;
    DisablePolicy(int64_t timeDuration, int count, WifiDeviceConfigStatus status)
    {
        disableTime = timeDuration;
        disableCount = count;
        disableStatus = status;
    }
};
class BlockConnectService {
public:
   static BlockConnectService &GetInstance();
    // Constructor
    BlockConnectService();

    // Destructor
    ~BlockConnectService();

    void Exit();

    // Method to check if auto connect is enabled for a given WifiDeviceConfig
    bool ShouldAutoConnect(const WifiDeviceConfig& config);
    
    // Update the selection status of all saved networks and check if disabled networks have expired
    bool UpdateAllNetworkSelectStatus();
    
    // Enable the selection status of a target network
    bool EnableNetworkSelectStatus(int targetNetworkId);

    // Clear the blocklist information of a target network with reason for wpa_supplicant disconnection
    bool UpdateNetworkSelectStatusForWpa(int targetNetworkId, DisabledReason disableReason, int wpaReason);
    
    // Clear the blocklist information of a target network
    bool UpdateNetworkSelectStatus(int targetNetworkId, DisabledReason disableReason, int64_t blockDuration = -1);

    // Check if the given BSSID has frequent disconnects with the last connected network
    // false - Not frequent disconnect true - Frequent disconnect
    bool IsFrequentDisconnect(std::string bssid, int wpaReason, int locallyGenerated);

    // Check if the given targetNetworkId is blocked due to wrong password
    bool IsWrongPassword(int targetNetworkId);

    // Enable all networks by entering settings
    void OnReceiveSettingsEnterEvent(bool isEnter);
#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    // set thie blocklist information for mdm restrictedlist
    bool UpdateNetworkSelectStatusForMdmRestrictedList();
    // Clear mdmRestrictedList from block connect
    bool ClearBlockConnectForMdmRestrictedList();
#endif
#ifndef OHOS_ARCH_LITE
    // handle wifi stopped msg
    void DealStaStopped(int instId);

    // handle wifi connected failed msg
    void NotifyWifiConnFailedInfo(int targetNetworkId, std::string bssid, DisabledReason disableReason);

    // release all blacklist bssid
    void ReleaseUnusableBssidSet();

    // check if the given bssid match the unusable bssid set
    bool IsBssidMatchUnusableSet(std::string bssid);

    // release all dhcp fail bssid
    void ReleaseDhcpFailBssidSet();
#endif
private:
    DisablePolicy CalculateDisablePolicy(DisabledReason disableReason);
    void EnableAllNetworksByEnteringSettings(std::vector<DisabledReason> enableReasons);
    void LogDisabledConfig(const WifiDeviceConfig& config);
#ifndef OHOS_ARCH_LITE
    void StartClearSetTimer();
    void StopClearSetTimer();
    void ClearSetTimerCallback();
    void CheckNeedChangePolicy(void);
#endif
    LastConnectedApInfo mLastConnectedApInfo;
    std::map<DisabledReason, DisablePolicy> blockConnectPolicies;
    std::vector<int> validReasons;
#ifndef OHOS_ARCH_LITE
    std::set<std::string> autoJoinUnusableBssidSet_;
    std::string curUnusableSsid_;
    std::string curUnusableKeyMgmt_;
    std::mutex bssidMutex_;
    std::mutex clearSetTimerMutex_;
    uint32_t clearSetTimerId_ {0};
    std::set<std::string> dhcpFailBssids_;
    std::mutex dhcpFailMutex_;
#endif
};
}
}
#endif