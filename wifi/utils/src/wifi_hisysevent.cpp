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

#include "wifi_hisysevent.h"
#include "wifi_common_util.h"
#include "hisysevent.h"
#include "sta_define.h"
#include "wifi_logger.h"
#include "json/json.h"
#include <map>

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiHiSysEvent");

const std::map<int, std::string> g_connectTypeTransMap {
    { NETWORK_SELECTED_BY_UNKNOWN, "UNKNOWN" },
    { NETWORK_SELECTED_BY_AUTO, "AUTO_CONNECT" },
    { NETWORK_SELECTED_BY_USER, "SELECT_CONNECT" },
    { NETWORK_SELECTED_BY_RETRY, "RETRY_CONNECT" },
    { NETWORK_SELECTED_BY_WIFIPRO, "WIFIPRO_CONNECT" },
    { NETWORK_SELECTED_BY_SELFCURE, "SELFCURE_CONNECT" },
    { NETWORK_SELECTED_BY_ROAM, "ROMA_CONNECT" },
    { NETWORK_SELECTED_BY_REASSOC, "REASSOC" },
};
constexpr int MAX_DNS_NUM = 10;

template<typename... Types>
static void WriteEvent(const std::string& eventType, Types... args)
{
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::COMMUNICATION, eventType,
        HiviewDFX::HiSysEvent::EventType::STATISTIC, args...);
    if (ret != 0) {
        WIFI_LOGE("Write event fail: %{public}s", eventType.c_str());
    }
}

template<typename... Type>
static void WriteEventBehavior(const std::string& eventType, Type... args)
{
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::COMMUNICATION, eventType,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, args...);
    if (ret != 0) {
        WIFI_LOGE("Write event fail: %{public}s", eventType.c_str());
    }
}

void WriteWifiStateHiSysEvent(const std::string& serviceType, WifiOperType operType)
{
    WriteEvent("WIFI_STATE", "TYPE", serviceType, "OPER_TYPE", static_cast<int>(operType));

    Json::Value root;
    Json::FastWriter writer;
    root["WIFI_STATE"] = static_cast<int>(operType);
    root["TYPE"] = serviceType;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WIFI_STATE", "EVENT_VALUE", writer.write(root));
}

void WriteWifiApStateHiSysEvent(int32_t state)
{
    WriteEventBehavior("WIFI_AP_STATE", "STATE", state);
}

void WriteWifiBridgeStateHiSysEvent(int32_t state)
{
    WriteEventBehavior("WIFI_BRIDGE_STATE", "STATE", state);
}

void WriteWifiP2pStateHiSysEvent(const std::string& inter, int32_t type, int32_t state)
{
    WriteEventBehavior("WIFI_P2P_STATE", "INTERFACE", inter, "P2PTYPE", type, "STATE", state);
}

void WriteWifiConnectionHiSysEvent(int type, const std::string& pkgName)
{
    WriteEvent("WIFI_CONNECTION", "TYPE", type, "PACKAGE_NAME", pkgName);
}

void WriteWifiScanHiSysEvent(const int result, const std::string& pkgName)
{
    WriteEvent("WIFI_SCAN", "EXECUTE_RESULT", result, "PACKAGE_NAME", pkgName);
}

void WriteWifiEventReceivedHiSysEvent(const std::string& eventType, int value)
{
    WriteEvent("WIFI_EVENT_RECEIVED", "EVENT_TYPE", eventType, "VALUE", value);
}

void WriteWifiBandHiSysEvent(int band)
{
    WriteEvent("WIFI_BAND", "BAND", band);
}

void WriteWifiSignalHiSysEvent(int direction, int txPackets, int rxPackets)
{
    WriteEvent("WIFI_SIGNAL", "DIRECTION", direction, "TXPACKETS", txPackets, "RXPACKETS", rxPackets);
}

void WriteWifiOperateStateHiSysEvent(int operateType, int operateState)
{
    Json::Value root;
    Json::FastWriter writer;
    root["OPERATE_TYPE"] = operateType;
    root["OPERATE_STATE"] = operateState;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_OPERATE_STATE", "EVENT_VALUE", writer.write(root));
}

void WriteWifiAbnormalDisconnectHiSysEvent(int errorCode, int locallyGenerated)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ERROR_CODE"] = errorCode;
    root["IS_ACTIVE_DISCONNECT"] = locallyGenerated;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ABNORMAL_DISCONNECT", "EVENT_VALUE", writer.write(root));
}

void WriteWifiBeaconLostHiSysEvent(int32_t errorCode)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ERROR_CODE"] = errorCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_BEACON_LOST", "EVENT_VALUE", writer.write(root));
}

void WriteWifiConnectionInfoHiSysEvent(int networkId)
{
    Json::Value root;
    Json::FastWriter writer;
    root["NETWORK_ID"] = networkId;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_CONNECTION_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteWifiOpenAndCloseFailedHiSysEvent(int operateType, std::string failReason, int apState)
{
    Json::Value root;
    Json::FastWriter writer;
    root["OPERATE_TYPE"] = operateType;
    root["FAIL_REASON"] = failReason;
    root["AP_STATE"] = apState;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_OPEN_AND_CLOSE_FAILED", "EVENT_VALUE", writer.write(root));
}

void WriteSoftApOpenAndCloseFailedEvent(int operateType, std::string failReason)
{
    WIFI_LOGE("WriteSoftApOpenAndCloseFailedEvent operateType=%{public}d", operateType);
    Json::Value root;
    Json::FastWriter writer;
    root["OPERATE_TYPE"] = operateType;
    root["FAIL_REASON"] = failReason;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_OPEN_AND_CLOSE_FAILED", "EVENT_VALUE", writer.write(root));
}

void WriteWifiAccessIntFailedHiSysEvent(int operateRes, int failCnt, int selfCureResetState,
    std::string selfCureHistory)
{
    Json::Value root;
    Json::FastWriter writer;
    root["OPERATE_TYPE"] = operateRes;
    root["FAIL_CNT"] = failCnt;
    root["RESET_STATE"] = selfCureResetState;
    root["SELF_CURE_HISTORY"] = selfCureHistory;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ACCESS_INTERNET_FAILED", "EVENT_VALUE", writer.write(root));
}

void WriteWifiPnoScanHiSysEvent(int isStartScan, int suspendReason)
{
    Json::Value root;
    Json::FastWriter writer;
    root["IS_START"] = isStartScan;
    root["SUSPEND_REASON"] = suspendReason;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_PNO_SCAN_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteBrowserFailedForPortalHiSysEvent(int respCode, std::string &server)
{
    Json::Value root;
    Json::FastWriter writer;
    root["RESP_CODE"] = respCode;
    root["SERVER"] = server;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "BROWSER_FAILED_FOR_PORTAL", "EVENT_VALUE", writer.write(root));
}

void WriteAuthFailHiSysEvent(const std::string &authFailReason, int subErrCode)
{
    Json::Value root;
    Json::FastWriter writer;
    root["FAIL_REASON"] = authFailReason;
    root["SUB_ERR_CODE"] = subErrCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_AUTH_FAIL_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteAssocFailHiSysEvent(const std::string &assocFailReason, int subErrCode)
{
    Json::Value root;
    Json::FastWriter writer;
    root["FAIL_REASON"] = assocFailReason;
    root["SUB_ERR_CODE"] = subErrCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ASSOC_FAIL_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteDhcpFailHiSysEvent(const std::string &dhcpFailReason, int subErrCode)
{
    Json::Value root;
    Json::FastWriter writer;
    root["FAIL_REASON"] = dhcpFailReason;
    root["SUB_ERR_CODE"] = subErrCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_DHCP_FAIL_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteScanLimitHiSysEvent(const std::string &scanInitiator, int scanLimitType, bool isForeground)
{
    if (scanInitiator.empty()) {
        return;
    }
    Json::Value root;
    Json::FastWriter writer;
    root["SCAN_INITIATOR"] = scanInitiator;
    root["IS_FOREGROUND"] = isForeground;
    root["SCAN_LIMIT_TYPE"] = scanLimitType;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_SCAN_LIMIT_STATISTICS", "EVENT_VALUE", writer.write(root));
}

void WriteAutoConnectFailEvent(const std::string &failReason, const std::string &subReason)
{
    Json::Value root;
    Json::FastWriter writer;
    root["FAIL_REASON"] = failReason;
    root["SUB_REASON"] = subReason;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_AUTO_RECONNECT_FAILED", "EVENT_VALUE", writer.write(root));
}

void WriteP2pKpiCountHiSysEvent(int eventType)
{
    Json::Value root;
    Json::FastWriter writer;
    root["EVENT_TYPE"] = eventType;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "P2P_CONNECT_STATICS", "EVENT_VALUE", writer.write(root));
}

void WriteP2pConnectFailedHiSysEvent(int errCode, int failRes)
{
    Json::Value root;
    Json::FastWriter writer;
    root["EVENT_TYPE"] = errCode;
    root["FAIL_RES"] = failRes;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "P2P_CONNECT_FAIL", "EVENT_VALUE", writer.write(root));
}

void WriteP2pAbDisConnectHiSysEvent(int errCode, int failRes)
{
    Json::Value root;
    Json::FastWriter writer;
    root["EVENT_TYPE"] = errCode;
    root["FAIL_RES"] = failRes;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "P2P_ABNORMAL_DISCONNECT", "EVENT_VALUE", writer.write(root));
}

void WriteSoftApAbDisconnectHiSysEvent(int errorCode)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ERROR_CODE"] = errorCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_ABNORMAL_DISCONNECT", "EVENT_VALUE", writer.write(root));
}

void WriteIsInternetHiSysEvent(int isInternet)
{
    Json::Value root;
    Json::FastWriter writer;
    root["IS_INTERNET"] = isInternet;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_KPI_INTERNET", "EVENT_VALUE", writer.write(root));
}

void WriteSoftApConnectFailHiSysEvent(int errorCnt)
{
    WIFI_LOGE("WriteSoftApConnectFailHiSysEvent errorCnt=%{public}d", errorCnt);
    Json::Value root;
    Json::FastWriter writer;
    root["ERROR_CODE"] = errorCnt;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_CONNECT_FAILED", "EVENT_VALUE", writer.write(root));
}

void WriteSoftApClientAccessNetErrorHiSysEvent(int errorCode)
{
    WIFI_LOGE("WriteSoftApClientAccessNetErrorHiSysEvent errorCode=%{public}d", errorCode);
    Json::Value root;
    Json::FastWriter writer;
    root["ERROR_CODE"] = errorCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_CLIENT_ACCESS_NET_ERROR", "EVENT_VALUE", writer.write(root));
}

void WriteWifiScanApiFailHiSysEvent(const std::string& pkgName, const WifiScanFailReason failReason)
{
#ifndef OHOS_ARCH_LITE
    Json::Value root;
    Json::FastWriter writer;
    root["PKG_NAME"] = pkgName;
    root["FAIL_REASON"] = static_cast<int>(failReason);
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFISCANCONTROL_TRIGGER_API_FAIL", "EVENT_VALUE", writer.write(root));
#endif
}

void WriteWifiEncryptionFailHiSysEvent(int event, const std::string& maskSsid, const std::string &keyMgmt, int encryptedModule)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ENCRY_OR_DECRY_EVENT"] = event;
    root["SSID"] = maskSsid;
    root["ENCRYKEYMANAGEMENT"] = keyMgmt;
    root["ENCRYEVENTMODULE"] = encryptedModule;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFIENCRY_OR_DECRY_FAIL", "EVENT_VALUE", writer.write(root));
}

void WritePortalStateHiSysEvent(int portalState)
{
    Json::Value root;
    Json::FastWriter writer;
    root["PORTAL_STATE"] = portalState;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_PORTAL_STATE", "EVENT_VALUE", writer.write(root));
}

void WriteArpInfoHiSysEvent(uint64_t arpRtt, int32_t arpFailedCount, int32_t gatewayCnt)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ARP_RTT"] = arpRtt;
    root["ARP_FAILED_COUNT"] = arpFailedCount;
    root["ARP_GWCOUNT"] = gatewayCnt;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_ARP_DETECTION_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteLinkInfoHiSysEvent(int signalLevel, int rssi, int band, int linkSpeed)
{
    Json::Value root;
    Json::FastWriter writer;
    root["LEVEL"] = signalLevel;
    root["BAND"] = band;
    root["RSSI"] = rssi;
    root["LINKSPEED"] = linkSpeed;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_LINK_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteConnectTypeHiSysEvent(int connectType, bool isFirstConnect)
{
    Json::Value root;
    Json::FastWriter writer;
    std::string connectTypeStr = "";
    if (g_connectTypeTransMap.find(connectType) != g_connectTypeTransMap.end()) {
        connectTypeStr = g_connectTypeTransMap.at(connectType);
    }
    if (isFirstConnect) {
        connectTypeStr = "FIRST_CONNECT";
    }
    root["CONNECT_TYPE"] = connectTypeStr;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_CONNECT_TYPE", "EVENT_VALUE", writer.write(root));
}

void WriteWifiLinkTypeHiSysEvent(const std::string &ssid, int32_t wifiLinkType, const std::string &triggerReason)
{
    Json::Value root;
    Json::FastWriter writer;
    root["SSID"] = ssid;
    root["WIFI_LINK_TYPE"] = wifiLinkType;
    root["TRIGGER_REASON"] = triggerReason;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WIFI_LINK_TYPE_UPDATE", "EVENT_VALUE", writer.write(root));
}

void WriteEmlsrExitReasonHiSysEvent(const std::string &ssid, int32_t reason)
{
    Json::Value root;
    Json::FastWriter writer;
    root["SSID"] = ssid;
    root["EMLSR_EXIT_REASON"] = reason;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WIFI_EMLSR_EXIT_REASON", "EVENT_VALUE", writer.write(root));
}

void WriteStaConnectIface(const std::string &ifName)
{
    Json::Value root;
    Json::FastWriter writer;
    root["IFACE_NAME"] = ifName;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_STA_CONNECT_IFNAME", "EVENT_VALUE", writer.write(root));
}

void WriteWifiWpaStateHiSysEvent(int state)
{
    Json::Value root;
    Json::FastWriter writer;
    root["WPA_STATE"] = state;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WPA_STATE", "EVENT_VALUE", writer.write(root));
}

void WritePortalAuthExpiredHisysevent(int respCode, int detectNum, time_t connTime,
    time_t portalAuthTime, bool isNotificationClicked)
{
    Json::Value root;
    Json::FastWriter writer;
    time_t now = time(nullptr);
    if (now < 0) {
        now = 0;
    }
    int64_t authDura = (now > 0 && portalAuthTime > 0 && now > portalAuthTime) ? now - portalAuthTime : 0;
    int64_t connDura = (now > 0 && connTime > 0 && now > connTime) ? now - connTime : 0;
    int64_t authCostDura =
        (portalAuthTime > 0 && connTime > 0 && portalAuthTime > connTime) ? portalAuthTime - connTime : 0;
    root["RESP_CODE"] = respCode;
    root["DURA"] = authDura;
    root["CONN_DURA"] = connDura;
    root["AUTH_COST_DURA"] = authCostDura;
    root["DET_NUM"] = detectNum;
    root["IS_NOTIFICA_CLICKED"] = isNotificationClicked ? 1 : 0;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "PORTAL_AUTH_EXPIRED", "EVENT_VALUE", writer.write(root));
}

void WriteWifiSelfcureHisysevent(int type)
{
    Json::Value root;
    Json::FastWriter writer;
    root["WIFI_SELFCURE_TYPE"] = type;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_SELFCURE", "EVENT_VALUE", writer.write(root));
}

void Write3VapConflictHisysevent(int type)
{
    Json::Value root;
    Json::FastWriter writer;
    root["WIFI_3VAP_CONFLICT_TYPE"] = type;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_3VAP_CONFLICT", "EVENT_VALUE", writer.write(root));
}

void Write5gPrefFailedHisysevent(Pref5gStatisticsInfo &info)
{
    int64_t conDuration = 0;
    if (info.isIn5gPref && !info.has5gPrefSwitch) {
        if (info.noInternetTime != std::chrono::steady_clock::time_point::min()) {
            info.durationNoInternet += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()
                - info.noInternetTime).count();
        }
        if (info.connectTime != std::chrono::steady_clock::time_point::min()) {
            conDuration = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()
                - info.connectTime).count();
        }
        Json::Value root;
        Json::FastWriter writer;
        root["BSSID"] = info.bssid;
        root["SSID"] = info.ssid;
        root["FREQ"] = info.freq;
        root["CON_DURATION"] = conDuration;
        root["DURATION_NO_INTERNET"] = info.durationNoInternet;
        root["ENTER_MONITOR_NUM"] = info.enterMonitorNum;
        root["MONITOR_ACTIVE_SCAN_NUM"] = info.monitorActiveScanNum;
        root["RELA_5G_NUM"] = info.rela5gNum;
        root["NOT_ADJ_5g_NUM"] = info.notAdj5gNum;
        root["NOT_INTERNET_RELA_5G_NUM"] = info.notInternetRela5gNum;
        root["ALL_RELA_5G_IN_BLOCK_LIST_NUM"] = info.allRela5gInBlockListNum;
        root["SATISFY_NO_SELECTED_NUM"] = info.satisfySwitchRssiNoSelectedNum;
        root["IS_USER_CONNECTED"] = (info.isUserConnected) ? 1 : 0;
        WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_5G_PREF_FAILED", "EVENT_VALUE", writer.write(root));
    }
}

void WriteAutoSelectHiSysEvent(int selectType, const std::string &selectedInfo,
    const std::string &filteredReason, const std::string &savedResult)
{
    Json::Value root;
    Json::FastWriter writer;
    root["AUTO_SELECT_TYPE"] = selectType;
    root["AUTO_SELECT_RESULT"] = selectedInfo;
    root["AUTO_SELECT_FILTER"] = filteredReason;
    root["SAVED_NETWORK_IN_SCAN"] = savedResult;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_AUTO_SELECT_STATISTIC", "EVENT_VALUE", writer.write(root));
}

void WriteDhcpInfoHiSysEvent(const IpInfo &ipInfo, const IpV6Info &ipv6Info)
{
    Json::Value root;
    Json::FastWriter writer;
    root["IPV4_IPADDRESS"] = Ipv4IntAnonymize(ipInfo.ipAddress);
    root["IPV4_GATEWAY"] = Ipv4IntAnonymize(ipInfo.gateway);
    root["IPV4_NETMASK"] = Ipv4IntAnonymize(ipInfo.netmask);
    root["IPV4_PRIMARYDNS"] = Ipv4IntAnonymize(ipInfo.primaryDns);
    root["IPV4_SECONDDNS"] = Ipv4IntAnonymize(ipInfo.secondDns);
    root["IPV4_SERVERIP"] = Ipv4IntAnonymize(ipInfo.serverIp);
    root["IPV4_LEASE"] = ipInfo.leaseDuration;
    root["IPV4_DNS_VEC_SIZE"] = static_cast<int32_t>(ipInfo.dnsAddr.size());
    for (size_t i = 0; i < ipInfo.dnsAddr.size(); i++) {
        if (i >= MAX_DNS_NUM) {
            WIFI_LOGE("ipInfo.dnsAddr size over limit");
            break;
        }
        std::string keyString = "IPV4_DNS" + std::to_string(i);
        root[keyString] = Ipv4IntAnonymize(ipInfo.dnsAddr[i]);
    }
    root["IPV6_LINKIPV6ADDR"] = Ipv6Anonymize(ipv6Info.linkIpV6Address);
    root["IPV6_GLOBALIPV6ADDR"] = Ipv6Anonymize(ipv6Info.globalIpV6Address);
    root["IPV6_RANDGLOBALIPV6ADDR"] = Ipv6Anonymize(ipv6Info.randGlobalIpV6Address);
    root["IPV6_GATEWAY"] = Ipv6Anonymize(ipv6Info.gateway);
    root["IPV6_NETMASK"] = Ipv6Anonymize(ipv6Info.netmask);
    root["IPV6_PRIMARYDNS"] = Ipv6Anonymize(ipv6Info.primaryDns);
    root["IPV6_SECONDDNS"] = Ipv6Anonymize(ipv6Info.secondDns);
    root["IPV6_UNIQUELOCALADDR1"] = Ipv6Anonymize(ipv6Info.uniqueLocalAddress1);
    root["IPV6_UNIQUELOCALADDR2"] = Ipv6Anonymize(ipv6Info.uniqueLocalAddress2);
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_DHCP_INFO", "EVENT_VALUE", writer.write(root));
}

void WriteIodHiSysEvent(const IodStatisticInfo &iodStatisticInfo)
{
    Json::Value root;
    Json::FastWriter writer;
    root["OUTDOORFILTERCNT"] = iodStatisticInfo.outdoorFilterCnt;
    root["OUTDOORSELECTWIFICNT"] = iodStatisticInfo.outdoorAutoSelectCnt;
    root["INTOOUTDOORCNT"] = iodStatisticInfo.in2OutCnt;
    root["OUTTOINDOORCNT"] = iodStatisticInfo.out2InCnt;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_IOD_STATISTIC", "EVENT_VALUE", writer.write(root));
}
}  // namespace Wifi
}  // namespace OHOS