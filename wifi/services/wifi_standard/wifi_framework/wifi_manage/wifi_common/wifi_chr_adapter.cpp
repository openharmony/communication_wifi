/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_service_manager.h"
#include "ienhance_service.h"
#include "cJSON.h"
#include "wifi_chr_adapter.h"
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
    { NETWORK_SELECTED_BY_MDM, "MDM" },
};
constexpr int MAX_DNS_NUM = 10;
 
bool EnhanceWriteEventIpc(const std::string eventname, const std::string jsonBody)
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("%{public}s: pEnhanceService is null", __FUNCTION__);
        return false;
    } else {
        pEnhanceService->ReportChrEventData(eventname, jsonBody);
        return true;
    }
}
 
void EnhanceWriteWifiStateHiSysEvent(const std::string& serviceType, WifiOperType operType)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "WIFI_STATE", static_cast<int>(operType));
    cJSON_AddStringToObject(root, "TYPE", serviceType.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_WIFI_STATE", std::string(jsonStr))) {
        WriteWifiStateHiSysEvent(serviceType, operType);
    } else {
        WriteWifiStateTypeHiSysEvent(serviceType, operType);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiAbnormalDisconnectHiSysEvent(int errorCode, int locallyGenerated)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ERROR_CODE", errorCode);
    cJSON_AddNumberToObject(root, "IS_ACTIVE_DISCONNECT", locallyGenerated);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_ABNORMAL_DISCONNECT", std::string(jsonStr))) {
        WriteWifiAbnormalDisconnectHiSysEvent(errorCode, locallyGenerated);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiConnectionInfoHiSysEvent(int networkId)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "NETWORK_ID", networkId);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_CONNECTION_INFO", std::string(jsonStr))) {
        WriteWifiConnectionInfoHiSysEvent(networkId);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiOpenAndCloseFailedHiSysEvent(int operateType, std::string failReason, int apState)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OPERATE_TYPE", operateType);
    cJSON_AddStringToObject(root, "FAIL_REASON", failReason.c_str());
    cJSON_AddNumberToObject(root, "AP_STATE", apState);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_OPEN_AND_CLOSE_FAILED", std::string(jsonStr))) {
        WriteWifiOpenAndCloseFailedHiSysEvent(operateType, failReason, apState);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiAccessIntFailedHiSysEvent(
    int operateRes, int failCnt, int selfCureResetState, std::string selfCureHistory)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OPERATE_TYPE", operateRes);
    cJSON_AddNumberToObject(root, "FAIL_CNT", failCnt);
    cJSON_AddNumberToObject(root, "RESET_STATE", selfCureResetState);
    cJSON_AddStringToObject(root, "SELF_CURE_HISTORY", selfCureHistory.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_ACCESS_INTERNET_FAILED", std::string(jsonStr))) {
        WriteWifiAccessIntFailedHiSysEvent(operateRes, failCnt, selfCureResetState, selfCureHistory);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteBrowserFailedForPortalHiSysEvent(int respCode, std::string &server)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "RESP_CODE", respCode);
    cJSON_AddStringToObject(root, "SERVER", server.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("BROWSER_FAILED_FOR_PORTAL", std::string(jsonStr))) {
        WriteBrowserFailedForPortalHiSysEvent(respCode, server);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteAssocFailHiSysEvent(const std::string &assocFailReason, int subErrCode)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "FAIL_REASON", assocFailReason.c_str());
    cJSON_AddNumberToObject(root, "SUB_ERR_CODE", subErrCode);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_ASSOC_FAIL_INFO", std::string(jsonStr))) {
        WriteAssocFailHiSysEvent(assocFailReason, subErrCode);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteDhcpFailHiSysEvent(const std::string &dhcpFailReason, int subErrCode)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "FAIL_REASON", dhcpFailReason.c_str());
    cJSON_AddNumberToObject(root, "SUB_ERR_CODE", subErrCode);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_DHCP_FAIL_INFO", std::string(jsonStr))) {
        WriteDhcpFailHiSysEvent(dhcpFailReason, subErrCode);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteAutoConnectFailEvent(const std::string &failReason, const std::string &subReason)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "FAIL_REASON", failReason.c_str());
    cJSON_AddStringToObject(root, "SUB_REASON", subReason.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_AUTO_RECONNECT_FAILED", std::string(jsonStr))) {
        WriteAutoConnectFailEvent(failReason, subReason);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteIsInternetHiSysEvent(int isInternet)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "IS_INTERNET", isInternet);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_KPI_INTERNET", std::string(jsonStr))) {
        WriteIsInternetHiSysEvent(isInternet);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWritePortalStateHiSysEvent(int portalState)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "PORTAL_STATE", portalState);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_PORTAL_STATE", std::string(jsonStr))) {
        WritePortalStateHiSysEvent(portalState);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteArpInfoHiSysEvent(uint64_t arpRtt, int32_t arpFailedCount, int32_t gatewayCnt)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ARP_RTT", static_cast<double>(arpRtt));
    cJSON_AddNumberToObject(root, "ARP_FAILED_COUNT", arpFailedCount);
    cJSON_AddNumberToObject(root, "ARP_GWCOUNT", gatewayCnt);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_ARP_DETECTION_INFO", std::string(jsonStr))) {
        WriteArpInfoHiSysEvent(arpRtt, arpFailedCount, gatewayCnt);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteLinkInfoHiSysEvent(int signalLevel, int rssi, int band, int linkSpeed)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "LEVEL", signalLevel);
    cJSON_AddNumberToObject(root, "BAND", band);
    cJSON_AddNumberToObject(root, "RSSI", rssi);
    cJSON_AddNumberToObject(root, "LINKSPEED", linkSpeed);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_LINK_INFO", std::string(jsonStr))) {
        WriteLinkInfoHiSysEvent(signalLevel, rssi, band, linkSpeed);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteConnectTypeHiSysEvent(int connectType, bool isFirstConnect)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    std::string connectTypeStr = "";
    if (g_connectTypeTransMap.find(connectType) != g_connectTypeTransMap.end()) {
        connectTypeStr = g_connectTypeTransMap.at(connectType);
    }
    if (isFirstConnect) {
        connectTypeStr = "FIRST_CONNECT";
    }
    cJSON_AddStringToObject(root, "CONNECT_TYPE", connectTypeStr.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("_CONNECT_TYPE", std::string(jsonStr))) {
        WriteConnectTypeHiSysEvent(connectType, isFirstConnect);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiLinkTypeHiSysEvent(const std::string &ssid, int32_t wifiLinkType, const std::string &triggerReason)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "SSID", ssid.c_str());
    cJSON_AddNumberToObject(root, "WIFI_LINK_TYPE", wifiLinkType);
    cJSON_AddStringToObject(root, "TRIGGER_REASON", triggerReason.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_WIFI_LINK_TYPE_UPDATE", std::string(jsonStr))) {
        WriteWifiLinkTypeHiSysEvent(ssid, wifiLinkType, triggerReason);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteEmlsrExitReasonHiSysEvent(const std::string &ssid, int32_t reason)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "SSID", ssid.c_str());
    cJSON_AddNumberToObject(root, "EMLSR_EXIT_REASON", reason);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_WIFI_EMLSR_EXIT_REASON", std::string(jsonStr))) {
        WriteEmlsrExitReasonHiSysEvent(ssid, reason);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteStaConnectIface(const std::string &ifName)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "IFACE_NAME", ifName.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_STA_CONNECT_IFNAME", std::string(jsonStr))) {
        WriteStaConnectIface(ifName);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiWpaStateHiSysEvent(int state)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "WPA_STATE", state);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("EVENT_WPA_STATE", std::string(jsonStr))) {
        WriteWifiWpaStateHiSysEvent(state);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
void EnhanceWritePortalAuthExpiredHisysevent(
    int respCode, int detectNum, time_t connTime, time_t portalAuthTime, bool isNotificationClicked)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    time_t now = time(nullptr);
    if (now < 0) {
        now = 0;
    }
    int64_t authDura = (now > 0 && portalAuthTime > 0 && now > portalAuthTime) ? (now - portalAuthTime) : 0;
    int64_t connDura = (now > 0 && connTime > 0 && now > connTime) ? (now - connTime) : 0;
    int64_t authCostDura =
        (portalAuthTime > 0 && connTime > 0 && portalAuthTime > connTime) ? (portalAuthTime - connTime) : 0;
    cJSON_AddNumberToObject(root, "RESP_CODE", respCode);
    cJSON_AddNumberToObject(root, "DURA", authDura);
    cJSON_AddNumberToObject(root, "CONN_DURA", connDura);
    cJSON_AddNumberToObject(root, "AUTH_COST_DURA", authCostDura);
    cJSON_AddNumberToObject(root, "DET_NUM", detectNum);
    cJSON_AddBoolToObject(root, "IS_NOTIFICA_CLICKED", isNotificationClicked);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("PORTAL_AUTH_EXPIRED", std::string(jsonStr))) {
        WritePortalAuthExpiredHisysevent(respCode, detectNum, connTime, portalAuthTime, isNotificationClicked);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteWifiSelfcureHisysevent(int type)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "WIFI_SELFCURE_TYPE", type);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_SELFCURE", std::string(jsonStr))) {
        WriteWifiSelfcureHisysevent(type);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWrite3VapConflictHisysevent(int type)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "WIFI_3VAP_CONFLICT_TYPE", type);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_3VAP_CONFLICT", std::string(jsonStr))) {
        Write3VapConflictHisysevent(type);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWrite5gPrefFailedHisysevent(Pref5gStatisticsInfo &info)
{
    int64_t conDuration = 0;
    if (info.isIn5gPref && !info.has5gPrefSwitch) {
        if (info.noInternetTime != std::chrono::steady_clock::time_point::min()) {
            info.durationNoInternet +=
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - info.noInternetTime)
                    .count();
        }
        if (info.connectTime != std::chrono::steady_clock::time_point::min()) {
            conDuration =
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - info.connectTime)
                    .count();
        }
        cJSON *root = cJSON_CreateObject();
        if (root == nullptr) {
            WIFI_LOGE("Failed to create cJSON object");
            return;
        }
        cJSON_AddStringToObject(root, "BSSID", info.bssid.c_str());
        cJSON_AddStringToObject(root, "SSID", info.ssid.c_str());
        cJSON_AddNumberToObject(root, "FREQ", info.freq);
        cJSON_AddNumberToObject(root, "CON_DURATION", conDuration);
        cJSON_AddNumberToObject(root, "DURATION_NO_INTERNET", info.durationNoInternet);
        cJSON_AddNumberToObject(root, "ENTER_MONITOR_NUM", info.enterMonitorNum);
        cJSON_AddNumberToObject(root, "MONITOR_ACTIVE_SCAN_NUM", info.monitorActiveScanNum);
        cJSON_AddNumberToObject(root, "RELA_5G_NUM", info.rela5gNum);
        cJSON_AddNumberToObject(root, "NOT_ADJ_5g_NUM", info.notAdj5gNum);
        cJSON_AddNumberToObject(root, "NOT_INTERNET_RELA_5G_NUM", info.notInternetRela5gNum);
        cJSON_AddNumberToObject(root, "ALL_RELA_5G_IN_BLOCK_LIST_NUM", info.allRela5gInBlockListNum);
        cJSON_AddNumberToObject(root, "SATISFY_NO_SELECTED_NUM", info.satisfySwitchRssiNoSelectedNum);
        cJSON_AddNumberToObject(root, "IS_USER_CONNECTED", info.isUserConnected ? 1 : 0);
 
        char *jsonStr = cJSON_PrintUnformatted(root);
        if (jsonStr == nullptr) {
            cJSON_Delete(root);
            return;
        }
        if (!EnhanceWriteEventIpc("WIFI_5G_PREF_FAILED", std::string(jsonStr))) {
            Write5gPrefFailedHisysevent(info);
        }
        free(jsonStr);
        cJSON_Delete(root);
    }
}
void EnhanceWriteAutoSelectHiSysEvent(
    int selectType, const std::string &selectedInfo, const std::string &filteredReason, const std::string &savedResult)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "AUTO_SELECT_TYPE", selectType);
    cJSON_AddStringToObject(root, "AUTO_SELECT_RESULT", selectedInfo.c_str());
    cJSON_AddStringToObject(root, "AUTO_SELECT_FILTER", filteredReason.c_str());
    cJSON_AddStringToObject(root, "SAVED_NETWORK_IN_SCAN", savedResult.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_AUTO_SELECT_STATISTIC", std::string(jsonStr))) {
        WriteAutoSelectHiSysEvent(selectType, selectedInfo, filteredReason, savedResult);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteDhcpInfoHiSysEvent(const IpInfo &ipInfo, const IpV6Info &ipv6Info)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "IPV4_IPADDRESS", Ipv4IntAnonymize(ipInfo.ipAddress).c_str());
    cJSON_AddStringToObject(root, "IPV4_GATEWAY", Ipv4IntAnonymize(ipInfo.gateway).c_str());
    cJSON_AddStringToObject(root, "IPV4_NETMASK", Ipv4IntAnonymize(ipInfo.netmask).c_str());
    cJSON_AddStringToObject(root, "IPV4_PRIMARYDNS", Ipv4IntAnonymize(ipInfo.primaryDns).c_str());
    cJSON_AddStringToObject(root, "IPV4_SECONDDNS", Ipv4IntAnonymize(ipInfo.secondDns).c_str());
    cJSON_AddStringToObject(root, "IPV4_SERVERIP", Ipv4IntAnonymize(ipInfo.serverIp).c_str());
    cJSON_AddNumberToObject(root, "IPV4_LEASE", ipInfo.leaseDuration);
    cJSON_AddNumberToObject(root, "IPV4_DNS_VEC_SIZE", static_cast<int32_t>(ipInfo.dnsAddr.size()));
    for (size_t i = 0; i < ipInfo.dnsAddr.size(); i++) {
        if (i >= MAX_DNS_NUM) {
            WIFI_LOGE("ipInfo.dnsAddr size over limit");
            break;
        }
        std::string keyString = "IPV4_DNS" + std::to_string(i);
        cJSON_AddStringToObject(root, keyString.c_str(), Ipv4IntAnonymize(ipInfo.dnsAddr[i]).c_str());
    }
    cJSON_AddStringToObject(root, "IPV6_LINKIPV6ADDR", Ipv6Anonymize(ipv6Info.linkIpV6Address).c_str());
    cJSON_AddStringToObject(root, "IPV6_GLOBALIPV6ADDR", Ipv6Anonymize(ipv6Info.globalIpV6Address).c_str());
    cJSON_AddStringToObject(root, "IPV6_RANDGLOBALIPV6ADDR", Ipv6Anonymize(ipv6Info.randGlobalIpV6Address).c_str());
    cJSON_AddStringToObject(root, "IPV6_GATEWAY", Ipv6Anonymize(ipv6Info.gateway).c_str());
    cJSON_AddStringToObject(root, "IPV6_NETMASK", Ipv6Anonymize(ipv6Info.netmask).c_str());
    cJSON_AddStringToObject(root, "IPV6_PRIMARYDNS", Ipv6Anonymize(ipv6Info.primaryDns).c_str());
    cJSON_AddStringToObject(root, "IPV6_SECONDDNS", Ipv6Anonymize(ipv6Info.secondDns).c_str());
    cJSON_AddStringToObject(root, "IPV6_UNIQUELOCALADDR1", Ipv6Anonymize(ipv6Info.uniqueLocalAddress1).c_str());
    cJSON_AddStringToObject(root, "IPV6_UNIQUELOCALADDR2", Ipv6Anonymize(ipv6Info.uniqueLocalAddress2).c_str());
    cJSON_AddNumberToObject(root, "IPV6_PREFERRED_LIFE_TIME", ipv6Info.preferredLifeTime);
    cJSON_AddNumberToObject(root, "IPV6_VALID_LIFE_TIME", ipv6Info.validLifeTime);
    cJSON_AddNumberToObject(root, "IPV6_ROUTE_LIFE_TIME", ipv6Info.routerLifeTime);
    std::string ipv6Address;
    for (const auto& pair : ipv6Info.IpAddrMap) {
        ipv6Address += Ipv6Anonymize(pair.first) + "|" + std::to_string(pair.second) + ";";
    }
    cJSON_AddStringToObject(root, "IPV6_IPADDRMAP", ipv6Address.c_str());
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_DHCP_INFO", std::string(jsonStr))) {
        WriteDhcpInfoHiSysEvent(ipInfo, ipv6Info);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
 
void EnhanceWriteIodHiSysEvent(const IodStatisticInfo &iodStatisticInfo)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OUTDOOR_FILTER_CNT", iodStatisticInfo.outdoorFilterCnt);
    cJSON_AddNumberToObject(root, "OUTDOOR_SELECT_WIFI_CNT", iodStatisticInfo.outdoorAutoSelectCnt);
    cJSON_AddNumberToObject(root, "IN_TO_OUTDOOR_CNT", iodStatisticInfo.in2OutCnt);
    cJSON_AddNumberToObject(root, "OUT_TO_INDOOR_CNT", iodStatisticInfo.out2InCnt);
    cJSON_AddNumberToObject(root, "OUTDOOR_CONN_LEVEL0", iodStatisticInfo.outdoorConnLevel0);
    cJSON_AddNumberToObject(root, "OUTDOOR_CONN_LEVEL1", iodStatisticInfo.outdoorConnLevel1);
    cJSON_AddNumberToObject(root, "OUTDOOR_CONN_LEVEL2", iodStatisticInfo.outdoorConnLevel2);
    cJSON_AddNumberToObject(root, "OUTDOOR_CONN_LEVEL3", iodStatisticInfo.outdoorConnLevel3);
    cJSON_AddNumberToObject(root, "OUTDOOR_CONN_LEVEL4", iodStatisticInfo.outdoorConnLevel4);
    cJSON_AddNumberToObject(root, "INDOOR_CONN_LEVEL0", iodStatisticInfo.indoorConnLevel0);
    cJSON_AddNumberToObject(root, "INDOOR_CONN_LEVEL1", iodStatisticInfo.indoorConnLevel1);
    cJSON_AddNumberToObject(root, "INDOOR_CONN_LEVEL2", iodStatisticInfo.indoorConnLevel2);
    cJSON_AddNumberToObject(root, "INDOOR_CONN_LEVEL3", iodStatisticInfo.indoorConnLevel3);
    cJSON_AddNumberToObject(root, "INDOOR_CONN_LEVEL4", iodStatisticInfo.indoorConnLevel4);
    cJSON_AddNumberToObject(root, "OUTDOOR_CONN_SHORT", iodStatisticInfo.outdoorConnShortTime);
    cJSON_AddNumberToObject(root, "INDOOR_CONN_SHORT", iodStatisticInfo.indoorConnShortTime);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    if (!EnhanceWriteEventIpc("WIFI_IOD_STATISTIC", std::string(jsonStr))) {
        WriteIodHiSysEvent(iodStatisticInfo);
    }
    free(jsonStr);
    cJSON_Delete(root);
}
}  // namespace Wifi
}  // namespace OHOS