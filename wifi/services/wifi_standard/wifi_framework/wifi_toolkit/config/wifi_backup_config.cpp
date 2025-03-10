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

#include "wifi_backup_config.h"

namespace OHOS {
namespace Wifi {
void ConvertBackupCfgToDeviceCfg(const WifiBackupConfig &backupCfg, WifiDeviceConfig &config)
{
    config.instanceId = backupCfg.instanceId;
    config.uid = backupCfg.uid;
    config.bssid = backupCfg.bssid;
    config.userSelectBssid = backupCfg.userSelectBssid;
    config.ssid = backupCfg.ssid;
    config.priority = backupCfg.priority;
    config.hiddenSSID = backupCfg.hiddenSSID;
    config.keyMgmt = backupCfg.keyMgmt;
    config.keyMgmtBitset = backupCfg.keyMgmtBitset;
    config.networkStatusHistory = backupCfg.networkStatusHistory;
    config.isPortal = backupCfg.isPortal;
    config.lastHasInternetTime = backupCfg.lastHasInternetTime;
    config.noInternetAccess = backupCfg.noInternetAccess;
    config.preSharedKey = backupCfg.preSharedKey;
    config.wepTxKeyIndex = backupCfg.wepTxKeyIndex;
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = backupCfg.wepKeys[i];
    }
    config.wifiIpConfig = backupCfg.wifiIpConfig;
    config.wifiProxyconfig = backupCfg.wifiProxyconfig;
    config.wifiPrivacySetting = backupCfg.wifiPrivacySetting;
}

void ConvertDeviceCfgToBackupCfg(const WifiDeviceConfig &config, WifiBackupConfig &backupCfg)
{
    backupCfg.instanceId = config.instanceId;
    backupCfg.uid = config.uid;
    backupCfg.bssid = config.bssid;
    backupCfg.userSelectBssid = config.userSelectBssid;
    backupCfg.ssid = config.ssid;
    backupCfg.priority = config.priority;
    backupCfg.hiddenSSID = config.hiddenSSID;
    backupCfg.keyMgmt = config.keyMgmt;
    backupCfg.keyMgmtBitset = config.keyMgmtBitset;
    backupCfg.networkStatusHistory = config.networkStatusHistory;
    backupCfg.isPortal = config.isPortal;
    backupCfg.lastHasInternetTime = config.lastHasInternetTime;
    backupCfg.noInternetAccess = config.noInternetAccess;
    backupCfg.preSharedKey = config.preSharedKey;
    backupCfg.wepTxKeyIndex = config.wepTxKeyIndex;
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        backupCfg.wepKeys[i] = config.wepKeys[i];
    }
    backupCfg.wifiIpConfig = config.wifiIpConfig;
    backupCfg.wifiProxyconfig = config.wifiProxyconfig;
    backupCfg.wifiPrivacySetting = config.wifiPrivacySetting;
}
}  // namespace Wifi
}  // namespace OHOS