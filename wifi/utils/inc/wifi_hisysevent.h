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

#ifndef OHOS_WIFI_HISYSEVENT_H
#define OHOS_WIFI_HISYSEVENT_H

#include <string>

#define AP_ERR_CODE 3
#define AP_STA_PSK_MISMATCH_CNT 1

#define ENCRYPTION_EVENT 0
#define DECRYPTION_EVENT 1
#define NONE_ENCRYTION_UTIL 2

#define SOFTAP_MOUDLE_EVENT 0
#define STA_MOUDLE_EVENT 1

namespace OHOS {
namespace Wifi {
enum class WifiOperType {
    ENABLE,
    DISABLE
};

enum class WifiConnectionType {
    CONNECT,
    DISCONNECT
};

const int HISYS_EVENT_DEFAULT_VALUE = -1;
const int HISYS_EVENT_PROTAL_STATE_NOT_PORTAL = 0;
const int HISYS_EVENT_PROTAL_STATE_PORTAL_UNVERIFIED = 0;
const int HISYS_EVENT_PROTAL_STATE_PORTAL_VERIFIED = 1;

const std::string HISYS_STA_POWER_STATE_CHANGE = "wifiStateChange";
const std::string HISYS_STA_CONN_STATE_CHANGE = "wifiConnectionChange";
const std::string HISYS_STA_SCAN_STATE_CHANGE = "wifiScanStateChange";
const std::string HISYS_STA_RSSI_STATE_CHANGE = "wifiRssiChange";
const std::string HISYS_HOTSPOT_STATE_CHANGE = "hotspotStateChange";
const std::string HISYS_HOTSPOT_STA_JOIN = "hotspotStaJoin";
const std::string HISYS_HOTSPOT_STA_LEAVE = "hotspotStaLeave";
const std::string HISYS_P2P_STATE_CHANGE = "p2pStateChange";
const std::string HISYS_P2P_CONN_STATE_CHANGE = "p2pConnectionChange";
const std::string HISYS_P2P_DEVICE_STATE_CHANGE = "p2pDeviceChange";
const std::string HISYS_P2P_PERSISTENT_GROUP_CHANGE = "p2pPersistentGroupChange";
const std::string HISYS_P2P_PEER_DEVICE_CHANGE = "p2pPeerDeviceChange";
const std::string HISYS_P2P_DISCOVERY_CHANGE = "p2pDiscoveryChange";

const std::string HISYS_SERVICE_TYPE_STA = "STA";
const std::string HISYS_SERVICE_TYPE_AP = "AP";
const std::string HISYS_SERVICE_TYPE_P2P = "P2P";

void WriteWifiStateHiSysEvent(const std::string& serviceType, WifiOperType operType);

void WriteWifiApStateHiSysEvent(int32_t state);

void WriteWifiP2pStateHiSysEvent(const std::string& inter, int32_t type, int32_t state);

void WriteWifiConnectionHiSysEvent(const WifiConnectionType& type, const std::string& pkgName);

void WriteWifiScanHiSysEvent(const int result, const std::string& pkgName);

void WriteWifiEventReceivedHiSysEvent(const std::string& eventType, int value);

void WriteWifiBandHiSysEvent(int band);

void WriteWifiSignalHiSysEvent(int direction, int txPackets, int rxPackets);

void WriteWifiOperateStateHiSysEvent(int operateType, int operateState);

void WriteWifiAbnormalDisconnectHiSysEvent(int errorCode);

void WriteWifiConnectionInfoHiSysEvent(int networkId);

void WriteWifiOpenAndCloseFailedHiSysEvent(int operateType, std::string failReason, int apState);

void WriteSoftApOpenAndCloseFailedEvent(int operateType, std::string failReason);

void WriteWifiAccessIntFailedHiSysEvent(int operateRes, int failCnt);

void WriteWifiPnoScanHiSysEvent(int isStartScan, int suspendReason);

void WriteBrowserFailedForPortalHiSysEvent(int respCode, std::string &server);

void WriteWifiConnectFailedEventHiSysEvent(int operateType);

void WriteP2pKpiCountHiSysEvent(int eventType);

void WriteP2pConnectFailedHiSysEvent(int errCode, int failRes);

void WriteP2pAbDisConnectHiSysEvent(int errCode, int failRes);

void WriteSoftApAbDisconnectHiSysEvent(int errorCode);

void WriteIsInternetHiSysEvent(int isInternet);

void WriteSoftApConnectFailHiSysEvent(int errorCnt);

void WriteWifiScanApiFailHiSysEvent(const std::string& pkgName, int failReason);

void WriteWifiEncryptionFailHiSysEvent(int event, const std::string &maskSsid,
    const std::string &keyMgmt, int encryptedModule);

void WritePortalStateHiSysEvent(int portalState);

void WriteArpInfoHiSysEvent(uint64_t arpRtt, int arpFailedCount);

void WriteLinkInfoHiSysEvent(int signalLevel, int rssi, int band, int linkSpeed);

void WirteConnectTypeHiSysEvent(std::string connectType);

}  // namespace Wifi
}  // namespace OHOS
#endif