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
#include "cJSON.h"
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
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
constexpr int MIN_RISKINFO_REPORT_INTERVAL = 2 * 60 * 60; // 上报间隔不短于2小时
static int lastWriteWifiRiskInfoHiSysEventTime = -1;
std::mutex riskInfoTimerMutex_;
#endif

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

void WriteWifiStateTypeHiSysEvent(const std::string& serviceType, WifiOperType operType)
{
    WriteEvent("WIFI_STATE", "TYPE", serviceType, "OPER_TYPE", static_cast<int>(operType));
}

void WriteWifiStateHiSysEvent(const std::string& serviceType, WifiOperType operType)
{
    WriteEvent("WIFI_STATE", "TYPE", serviceType, "OPER_TYPE", static_cast<int>(operType));

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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WIFI_STATE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
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
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OPERATE_TYPE", operateType);
    cJSON_AddNumberToObject(root, "OPERATE_STATE", operateState);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_OPERATE_STATE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiAbnormalDisconnectHiSysEvent(int errorCode, int locallyGenerated)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ABNORMAL_DISCONNECT", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiBeaconLostHiSysEvent(int32_t errorCode)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ERROR_CODE", errorCode);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_BEACON_LOST", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiConnectionInfoHiSysEvent(int networkId)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_CONNECTION_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiOpenAndCloseFailedHiSysEvent(int operateType, std::string failReason, int apState)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_OPEN_AND_CLOSE_FAILED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteSoftApOpenAndCloseFailedEvent(int operateType, std::string failReason)
{
    WIFI_LOGE("WriteSoftApOpenAndCloseFailedEvent operateType=%{public}d", operateType);
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OPERATE_TYPE", operateType);
    cJSON_AddStringToObject(root, "FAIL_REASON", failReason.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_OPEN_AND_CLOSE_FAILED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteSoftApOperateHiSysEvent(int operateType)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OPERATE_TYPE", operateType);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_OPERATE_STATE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiAccessIntFailedHiSysEvent(
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ACCESS_INTERNET_FAILED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiPnoScanHiSysEvent(int isStartScan, int suspendReason)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "IS_START", isStartScan);
    cJSON_AddNumberToObject(root, "SUSPEND_REASON", suspendReason);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_PNO_SCAN_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteBrowserFailedForPortalHiSysEvent(int respCode, std::string &server)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "BROWSER_FAILED_FOR_PORTAL", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WritePortalInfoHiSysEvent(bool isCN, bool isEverConnected)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "OVER_SEA", isCN);
    cJSON_AddNumberToObject(root, "IS_FIRST_DETECT", isEverConnected);
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_PORTAL_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteAuthFailHiSysEvent(const std::string &authFailReason, int subErrCode)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "FAIL_REASON", authFailReason.c_str());
    cJSON_AddNumberToObject(root, "SUB_ERR_CODE", subErrCode);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_AUTH_FAIL_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteAssocFailHiSysEvent(const std::string &assocFailReason, int subErrCode)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ASSOC_FAIL_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteDhcpFailHiSysEvent(const std::string &dhcpFailReason, int subErrCode)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_DHCP_FAIL_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteScanLimitHiSysEvent(const std::string &scanInitiator, int scanLimitType, bool isForeground)
{
    if (scanInitiator.empty()) {
        return;
    }
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "SCAN_INITIATOR", scanInitiator.c_str());
    cJSON_AddBoolToObject(root, "IS_FOREGROUND", isForeground);
    cJSON_AddNumberToObject(root, "SCAN_LIMIT_TYPE", scanLimitType);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_SCAN_LIMIT_STATISTICS", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteAutoConnectFailEvent(const std::string &failReason, const std::string &subReason)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_AUTO_RECONNECT_FAILED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteP2pKpiCountHiSysEvent(int eventType)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "EVENT_TYPE", eventType);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "P2P_CONNECT_STATICS", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteP2pConnectFailedHiSysEvent(int errCode, int failRes)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "EVENT_TYPE", errCode);
    cJSON_AddNumberToObject(root, "FAIL_RES", failRes);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "P2P_CONNECT_FAIL", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteP2pAbDisConnectHiSysEvent(int errCode, int failRes)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "EVENT_TYPE", errCode);
    cJSON_AddNumberToObject(root, "FAIL_RES", failRes);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "P2P_ABNORMAL_DISCONNECT", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteSoftApAbDisconnectHiSysEvent(int errorCode)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ERROR_CODE", errorCode);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_ABNORMAL_DISCONNECT", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteIsInternetHiSysEvent(int isInternet)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_KPI_INTERNET", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteSoftApConnectFailHiSysEvent(int errorCnt)
{
    WIFI_LOGE("WriteSoftApConnectFailHiSysEvent errorCnt=%{public}d", errorCnt);
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ERROR_CODE", errorCnt);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_CONNECT_FAILED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteSoftApClientAccessNetErrorHiSysEvent(int errorCode)
{
    WIFI_LOGE("WriteSoftApClientAccessNetErrorHiSysEvent errorCode=%{public}d", errorCode);
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ERROR_CODE", errorCode);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "SOFTAP_CLIENT_ACCESS_NET_ERROR", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiScanApiFailHiSysEvent(const std::string &pkgName, const WifiScanFailReason failReason)
{
#ifndef OHOS_ARCH_LITE
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "PKG_NAME", pkgName.c_str());
    cJSON_AddNumberToObject(root, "FAIL_REASON", static_cast<int>(failReason));
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFISCANCONTROL_TRIGGER_API_FAIL", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
#endif
}

void WriteWifiEncryptionFailHiSysEvent(
    int event, const std::string &maskSsid, const std::string &keyMgmt, int encryptedModule)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "ENCRY_OR_DECRY_EVENT", event);
    cJSON_AddStringToObject(root, "SSID", maskSsid.c_str());
    cJSON_AddStringToObject(root, "ENCRYKEYMANAGEMENT", keyMgmt.c_str());
    cJSON_AddNumberToObject(root, "ENCRYEVENTMODULE", encryptedModule);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFIENCRY_OR_DECRY_FAIL", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WritePortalStateHiSysEvent(int portalState)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_PORTAL_STATE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteArpInfoHiSysEvent(uint64_t arpRtt, int32_t arpFailedCount, int32_t gatewayCnt)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_ARP_DETECTION_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteLinkInfoHiSysEvent(int signalLevel, int rssi, int band, int linkSpeed)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_LINK_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteConnectTypeHiSysEvent(int connectType, bool isFirstConnect)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "_CONNECT_TYPE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiLinkTypeHiSysEvent(const std::string &ssid, int32_t wifiLinkType, const std::string &triggerReason)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WIFI_LINK_TYPE_UPDATE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteEmlsrExitReasonHiSysEvent(const std::string &ssid, int32_t reason)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WIFI_EMLSR_EXIT_REASON", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteStaConnectIface(const std::string &ifName)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_STA_CONNECT_IFNAME", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiWpaStateHiSysEvent(int state)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_WPA_STATE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WritePortalAuthExpiredHisysevent(
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "PORTAL_AUTH_EXPIRED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiSelfcureHisysevent(int type)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_SELFCURE", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void Write3VapConflictHisysevent(int type)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_3VAP_CONFLICT", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void Write5gPrefFailedHisysevent(Pref5gStatisticsInfo &info)
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
        WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_5G_PREF_FAILED", "EVENT_VALUE", std::string(jsonStr));
        cJSON_free(jsonStr);
        cJSON_Delete(root);
    }
}

void WriteAutoSelectHiSysEvent(
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_AUTO_SELECT_STATISTIC", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteDhcpInfoHiSysEvent(const IpInfo &ipInfo, const IpV6Info &ipv6Info)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_DHCP_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteIodHiSysEvent(const IodStatisticInfo &iodStatisticInfo)
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
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_IOD_STATISTIC", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteMdmHiSysEvent(const MdmRestrictedInfo &mdmRestrictedInfo)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    
    cJSON_AddStringToObject(root, "BUNDLE_NAME", mdmRestrictedInfo.bundleName.c_str());
    cJSON_AddNumberToObject(root, "UID", mdmRestrictedInfo.uid);
    cJSON_AddStringToObject(root, "SSID", SsidAnonymize(mdmRestrictedInfo.ssid).c_str());
    cJSON_AddStringToObject(root, "BSSID", MacAnonymize(mdmRestrictedInfo.bssid).c_str());
    cJSON_AddStringToObject(root, "RESTRICTED_TYPE", mdmRestrictedInfo.restrictedType.c_str());
    
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_MDM_RESTRICTED", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiConfigStatusHiSysEvent(const std::string &packageName, WifiConfigReportType reportType)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "PACKAGE_NAME", packageName.c_str());
    cJSON_AddNumberToObject(root, "OPER_TYPE", static_cast<int>(reportType));
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_CONFIG_OPER_STAT", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}
 
void WritePositionAutoOpenWlanHiSysEvent(const std::string updateType)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddStringToObject(root, "UPDATE_TYPE", updateType.c_str());
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "POSITION_AUTO_OPEN_WLAN", "EVENT_VALUE", std::string(jsonStr));
    free(jsonStr);
    cJSON_Delete(root);
}

void WriteWifiScanInfoHiSysEvent(const ScanStatisticInfo &scanStatisticInfo)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    cJSON_AddNumberToObject(root, "FC_LP_SCAN_CNT", scanStatisticInfo.fcLpScanCnt);
    cJSON_AddNumberToObject(root, "FC_LP_SCAN_AP_CNT", scanStatisticInfo.fcLpScanApCnt);
 
    cJSON_AddNumberToObject(root, "NFC_LP_SCAN_CNT", scanStatisticInfo.nfcLpScanCnt);
    cJSON_AddNumberToObject(root, "NFC_LP_SCAN_CHANNEL_CNT", scanStatisticInfo.nfcLpScanChannelCnt);
    cJSON_AddNumberToObject(root, "NFC_LP_SCAN_AP_CNT", scanStatisticInfo.nfcLpScanApCnt);
 
    cJSON_AddNumberToObject(root, "FC_SCAN_CNT", scanStatisticInfo.fcScanCnt);
    cJSON_AddNumberToObject(root, "FC_SCAN_AP_CNT", scanStatisticInfo.fcScanApCnt);
 
    cJSON_AddNumberToObject(root, "NFC_SCAN_CNT", scanStatisticInfo.nfcScanCnt);
    cJSON_AddNumberToObject(root, "NFC_SCAN_CHANNEL_CNT", scanStatisticInfo.nfcScanChannelCnt);
    cJSON_AddNumberToObject(root, "NFC_SCAN_AP_CNT", scanStatisticInfo.nfcScanApCnt);
 
    cJSON_AddNumberToObject(root, "LP_SCAN_UNCTRL_CNT", scanStatisticInfo.lpScanUnctrlCnt);
    cJSON_AddNumberToObject(root, "LP_SCAN_AP_SWT_CNT", scanStatisticInfo.lpScanApSwtCnt);
    cJSON_AddNumberToObject(root, "SCAN_AP_SWT_CNT", scanStatisticInfo.scanApSwtCnt);
    cJSON_AddNumberToObject(root, "LP_SCAN_ABORT_CNT", scanStatisticInfo.lpScanAbortCnt);
 
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_SCAN_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
}

#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
void WriteWifiRiskInfoHiSysEvent(const WifiRiskInfo &wifiRiskInfo)
{
    time_t now = time(nullptr);
    if (now < 0) {
        WIFI_LOGE("time return invalid!");
        return;
    }
    std::lock_guard<std::mutex> lock(riskInfoTimerMutex_);
    auto interval = now - lastWriteWifiRiskInfoHiSysEventTime;
    if (interval < MIN_RISKINFO_REPORT_INTERVAL) {
        return;
    }
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        WIFI_LOGE("Failed to create cJSON object");
        return;
    }
    
    cJSON_AddNumberToObject(root, "RISK_TYPE", wifiRiskInfo.riskType);
    cJSON_AddNumberToObject(root, "LAST_DISCONNECT_TIME", wifiRiskInfo.lastDisconnectTime);
    cJSON_AddNumberToObject(root, "CONNECT_INTERVAL", wifiRiskInfo.connectInterval);
    cJSON_AddStringToObject(root, "HOST_NAME", DomainAnonymize(wifiRiskInfo.hostName).c_str());
    cJSON_AddStringToObject(root, "SSID", SsidAnonymize(wifiRiskInfo.ssid).c_str());
    cJSON_AddStringToObject(root, "BSSID", MacAnonymize(wifiRiskInfo.bssid).c_str());
    cJSON_AddNumberToObject(root, "FREQUENCY", wifiRiskInfo.frequency);
    cJSON_AddNumberToObject(root, "BAND", wifiRiskInfo.band);
    cJSON_AddNumberToObject(root, "RSSI", wifiRiskInfo.rssi);
    cJSON_AddNumberToObject(root, "CLOUD_RISK_TYPE", wifiRiskInfo.cloudRiskType);
    
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return;
    }
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_RISK_INFO", "EVENT_VALUE", std::string(jsonStr));
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    lastWriteWifiRiskInfoHiSysEventTime = time(nullptr);
}
#endif
}  // namespace Wifi
}  // namespace OHOS