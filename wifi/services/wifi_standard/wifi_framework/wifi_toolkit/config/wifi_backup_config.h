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

#ifndef OHOS_WIFI_BACKUP_CONFIG_H
#define OHOS_WIFI_BACKUP_CONFIG_H
#include "wifi_msg.h"
#include "wifi_ap_msg.h"

namespace OHOS {
namespace Wifi {
/* Backup configuration information */
struct WifiBackupConfig {
    int instanceId;
    int uid;
    std::string bssid;
    std::string userSelectBssid;
    std::string ssid;
    int priority;
    bool hiddenSSID;
    std::string keyMgmt;
    uint32_t keyMgmtBitset;
    unsigned int networkStatusHistory;
    bool isPortal;
    time_t lastHasInternetTime;
    bool noInternetAccess;
    std::string preSharedKey;
    int wepTxKeyIndex;
    std::string wepKeys[WEPKEYS_SIZE];
    WifiIpConfig wifiIpConfig;
    WifiProxyConfig wifiProxyconfig;
    WifiPrivacyConfig wifiPrivacySetting;
    bool isAllowAutoConnect;
    time_t lastDisconnectTime;
    WifiBackupConfig()
    {
        instanceId = 0;
        uid = WIFI_INVALID_UID;
        priority = 0;
        hiddenSSID = false;
        keyMgmtBitset = 0u;
        networkStatusHistory = 0;
        isPortal = false;
        lastHasInternetTime = -1;
        noInternetAccess = false;
        wepTxKeyIndex = 0;
        wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        isAllowAutoConnect = true;
        lastDisconnectTime = -1;
    }
};

struct HotspotBackupConfig {
    bool hotspotConfig;
    bool passwdDefault;
    std::string preSharedKey;
    BandType band;
    std::string deviceName;
    std::string deviceBssid;
    std::string deviceIpAddr;
    HotspotBackupConfig() : band(BandType::UNKNOWN) {};
};

void ConvertBackupCfgToDeviceCfg(const WifiBackupConfig &backupCfg, WifiDeviceConfig &config);

void ConvertDeviceCfgToBackupCfg(const WifiDeviceConfig &config, WifiBackupConfig &backupCfg);

}  // namespace Wifi
}  // namespace OHOS
#endif  // OHOS_WIFI_BACKUP_CONFIG_H