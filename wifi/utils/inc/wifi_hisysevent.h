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
#include "wifi_msg.h"
#include <mutex>
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
    DISABLE,
    SEMI_ENABLE
};

enum class WifiConnectionType {
    CONNECT,
    DISCONNECT
};

enum class EventAccessInternetFailReason {
    ARP_OPERATE_RES = 0,
    HTTP_OPERATE_RES = 1,
    NOINTERNET = 2,
    IPV6_FAILED = 3,
};

inline const int HISYS_EVENT_DEFAULT_VALUE = -1;
inline const int HISYS_EVENT_PROTAL_STATE_NOT_PORTAL = 0;
inline const int HISYS_EVENT_PROTAL_STATE_PORTAL_VERIFIED = 1;
inline const int HISYS_EVENT_PROTAL_STATE_PORTAL_UNVERIFIED = 2;

inline const std::string HISYS_STA_POWER_STATE_CHANGE = "wifiStateChange";
inline const std::string HISYS_STA_CONN_STATE_CHANGE = "wifiConnectionChange";
inline const std::string HISYS_STA_SCAN_STATE_CHANGE = "wifiScanStateChange";
inline const std::string HISYS_STA_RSSI_STATE_CHANGE = "wifiRssiChange";
inline const std::string HISYS_HOTSPOT_STATE_CHANGE = "hotspotStateChange";
inline const std::string HISYS_HOTSPOT_STA_JOIN = "hotspotStaJoin";
inline const std::string HISYS_HOTSPOT_STA_LEAVE = "hotspotStaLeave";
inline const std::string HISYS_P2P_STATE_CHANGE = "p2pStateChange";
inline const std::string HISYS_P2P_CONN_STATE_CHANGE = "p2pConnectionChange";
inline const std::string HISYS_P2P_DEVICE_STATE_CHANGE = "p2pDeviceChange";
inline const std::string HISYS_P2P_PERSISTENT_GROUP_CHANGE = "p2pPersistentGroupChange";
inline const std::string HISYS_P2P_PEER_DEVICE_CHANGE = "p2pPeerDeviceChange";
inline const std::string HISYS_P2P_DISCOVERY_CHANGE = "p2pDiscoveryChange";

inline const std::string HISYS_SERVICE_TYPE_STA = "STA";
inline const std::string HISYS_SERVICE_TYPE_AP = "AP";
inline const std::string HISYS_SERVICE_TYPE_P2P = "P2P";

enum class WifiScanFailReason {
    DEFAULT = -1,
    PROXY_FAIL,
    PERMISSION_DENIED,
    SCAN_SERVICE_NOT_RUNNING,
    SERVICE_SCAN_FAIL,
    SERVICE_ADVANCE_SCAN_FAIL,
    HDI_SERVICE_DIED,
    HDI_SCAN_FAIL,
    HDI_PNO_SCAN_FAIL,
    HDI_GET_SCAN_INFOS_FAIL,
    SERVICE_REGISTERCALLBACK_FAIL,
    HOTSPOT_REGISTERCALLBACK_FAIL
};

enum class WifiRiskInfoReason {
    DEFAULT = -1,
    WIFI_COPY_NETWORK = 1,
    WIFI_FORGERY_PROTECTION = 2,
    WIFI_DNS_SPOOFING = 3
};

enum class WifiCloudRiskType {
    UNKNOWN = -1,
    SAFE = 0,
    UNSAFE = 1
};

struct Pref5gStatisticsInfo {
    std::string bssid;
    std::string ssid;
    int32_t freq = 0;
    int64_t durationNoInternet = 0;
    int32_t enterMonitorNum = 0;
    int32_t monitorActiveScanNum = 0;
    int32_t rela5gNum = 0;
    int32_t notAdj5gNum = 0;
    int32_t notInternetRela5gNum = 0;
    int32_t allRela5gInBlockListNum = 0;
    int32_t satisfySwitchRssiNoSelectedNum = 0;
    int32_t inBlackListNum = 0;
    bool isUserConnected = false;
    bool isIn5gPref = false;
    bool has5gPrefSwitch = false;
    std::chrono::steady_clock::time_point noInternetTime = std::chrono::steady_clock::time_point::min();
    std::chrono::steady_clock::time_point connectTime = std::chrono::steady_clock::time_point::min();

    void Reset()
    {
        bssid = "";
        ssid = "";
        freq = 0;
        durationNoInternet = 0;
        enterMonitorNum = 0;
        monitorActiveScanNum = 0;
        rela5gNum = 0;
        notAdj5gNum = 0;
        notInternetRela5gNum = 0;
        allRela5gInBlockListNum = 0;
        satisfySwitchRssiNoSelectedNum = 0;
        inBlackListNum = 0;
        isUserConnected = false;
        isIn5gPref = false;
        has5gPrefSwitch = false;
        noInternetTime = std::chrono::steady_clock::time_point::min();
        connectTime = std::chrono::steady_clock::time_point::min();
    }
};

struct IodStatisticInfo {
    int32_t in2OutCnt = 0;
    int32_t out2InCnt = 0;
    int32_t outdoorFilterCnt = 0;
    int32_t outdoorAutoSelectCnt = 0;
    int32_t outdoorConnLevel0 = 0;
    int32_t outdoorConnLevel1 = 0;
    int32_t outdoorConnLevel2 = 0;
    int32_t outdoorConnLevel3 = 0;
    int32_t outdoorConnLevel4 = 0;
    int32_t indoorConnLevel0 = 0;
    int32_t indoorConnLevel1 = 0;
    int32_t indoorConnLevel2 = 0;
    int32_t indoorConnLevel3 = 0;
    int32_t indoorConnLevel4 = 0;
    int32_t outdoorConnShortTime = 0;
    int32_t indoorConnShortTime = 0;
};

struct ScanStatisticInfo {
    uint32_t fcLpScanCnt = 0;
    uint32_t fcLpScanApCnt = 0;
    uint32_t nfcLpScanCnt = 0;
    uint32_t nfcLpScanChannelCnt = 0;
    uint32_t nfcLpScanApCnt = 0;
    uint32_t fcScanCnt = 0;
    uint32_t fcScanApCnt = 0;
    uint32_t nfcScanCnt = 0;
    uint32_t nfcScanChannelCnt = 0;
    uint32_t nfcScanApCnt = 0;
    uint32_t lpScanUnctrlCnt = 0;
    uint32_t lpScanApSwtCnt = 0;
    uint32_t scanApSwtCnt = 0;
    uint32_t lpScanAbortCnt = 0;
};

struct MdmRestrictedInfo {
    std::string ssid = "";
    std::string bssid = "";
    std::string restrictedType = "";
    int uid = 0;
    std::string bundleName = "";
};

struct WifiRiskInfo {
    int riskType = -1;
    int lastDisconnectTime = -1;
    int connectInterval = -1;
    std::string hostName = "";
    //Ap_Info
    std::string ssid = "";
    std::string bssid = "";
    int frequency = 0;
    int band = -1;
    int rssi = -1;
    int cloudRiskType = -1;
};

void WriteWifiStateTypeHiSysEvent(const std::string& serviceType, WifiOperType operType);

void WriteWifiStateHiSysEvent(const std::string& serviceType, WifiOperType operType);

void WriteWifiApStateHiSysEvent(int32_t state);

void WriteWifiBridgeStateHiSysEvent(int32_t state);

void WriteWifiP2pStateHiSysEvent(const std::string& inter, int32_t type, int32_t state);

void WriteWifiConnectionHiSysEvent(int type, const std::string& pkgName);

void WriteAuthFailHiSysEvent(const std::string &authFailReason, int subErrCode = 0);

void WriteAssocFailHiSysEvent(const std::string &assocFailReason, int subErrCode = 0);

void WriteDhcpFailHiSysEvent(const std::string &dhcpFailReason, int subErrCode = 0);

void WriteScanLimitHiSysEvent(const std::string &scanInitiator, int scanLimitType, bool isForeground = false);

void WriteAutoConnectFailEvent(const std::string &failReason, const std::string &subReason = "");

void WriteWifiScanHiSysEvent(const int result, const std::string& pkgName);

void WriteWifiEventReceivedHiSysEvent(const std::string& eventType, int value);

void WriteWifiBandHiSysEvent(int band);

void WriteWifiSignalHiSysEvent(int direction, int txPackets, int rxPackets);

void WriteWifiOperateStateHiSysEvent(int operateType, int operateState);

void WriteWifiAbnormalDisconnectHiSysEvent(int errorCode, int locallyGenerated);

void WriteWifiBeaconLostHiSysEvent(int errorCode);

void WriteWifiConnectionInfoHiSysEvent(int networkId);

void WriteWifiOpenAndCloseFailedHiSysEvent(int operateType, std::string failReason, int apState);

void WriteSoftApOpenAndCloseFailedEvent(int operateType, std::string failReason);

void WriteSoftApOperateHiSysEvent(int operateType);

void WriteWifiAccessIntFailedHiSysEvent(int operateRes, int failCnt, int selfCureResetState,
    std::string selfCureHistory);

void WriteWifiPnoScanHiSysEvent(int isStartScan, int suspendReason);

void WriteBrowserFailedForPortalHiSysEvent(int respCode, std::string &server);

void WritePortalInfoHiSysEvent(bool isCN, bool isEverConnected);

void WriteP2pKpiCountHiSysEvent(int eventType);

void WriteP2pConnectFailedHiSysEvent(int errCode, int failRes);

void WriteP2pAbDisConnectHiSysEvent(int errCode, int failRes);

void WriteSoftApAbDisconnectHiSysEvent(int errorCode);

void WriteIsInternetHiSysEvent(int isInternet);

void WriteSoftApConnectFailHiSysEvent(int errorCnt);

void WriteSoftApClientAccessNetErrorHiSysEvent(int errorCode);

void WriteWifiScanApiFailHiSysEvent(const std::string& pkgName, const WifiScanFailReason failReason);

void WriteWifiEncryptionFailHiSysEvent(int event, const std::string &maskSsid,
    const std::string &keyMgmt, int encryptedModule);

void WritePortalStateHiSysEvent(int portalState);

void WriteArpInfoHiSysEvent(uint64_t arpRtt, int32_t arpFailedCount, int32_t gatewayCnt = 0);

void WriteLinkInfoHiSysEvent(int signalLevel, int rssi, int band, int linkSpeed);

void WriteConnectTypeHiSysEvent(int connectType, bool isFirstConnect = false);

void WriteWifiLinkTypeHiSysEvent(const std::string &ssid, int32_t wifiLinkType, const std::string &triggerReason);

void WriteEmlsrExitReasonHiSysEvent(const std::string &ssid, int32_t reason);

void WriteStaConnectIface(const std::string &ifName);

void WriteWifiWpaStateHiSysEvent(int state);

void WritePortalAuthExpiredHisysevent(int respCode, int detectNum, time_t connTime,
    time_t portalAuthTime, bool isNotificationClicked);

void WriteWifiSelfcureHisysevent(int type);

void Write3VapConflictHisysevent(int type);

void Write5gPrefFailedHisysevent(Pref5gStatisticsInfo &info);

void WriteAutoSelectHiSysEvent(int selectType, const std::string &selectedInfo,
    const std::string &filteredReason, const std::string &savedResult);

void WriteDhcpInfoHiSysEvent(const IpInfo &ipInfo, const IpV6Info &ipv6Info);

void WriteIodHiSysEvent(const IodStatisticInfo &iodStatisticInfo);

void WriteMdmHiSysEvent(const MdmRestrictedInfo &mdmRestrictedInfo);

void WriteWifiConfigStatusHiSysEvent(const std::string &packageName, WifiConfigReportType reportType);

void WritePositionAutoOpenWlanHiSysEvent(const std::string updateType);

void WriteWifiScanInfoHiSysEvent(const ScanStatisticInfo &scanStatisticInfo);
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
void WriteWifiRiskInfoHiSysEvent(const WifiRiskInfo &wifiRiskInfo);
#endif
}  // namespace Wifi
}  // namespace OHOS
#endif
