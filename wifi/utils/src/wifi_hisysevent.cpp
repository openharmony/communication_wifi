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
#include "hisysevent.h"
#include "wifi_logger.h"
#include "json/json.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiHiSysEvent");

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
}

void WriteWifiApStateHiSysEvent(int32_t state)
{
    WriteEventBehavior("WIFI_AP_STATE", "STATE", state);
}

void WriteWifiP2pStateHiSysEvent(const std::string& inter, int32_t type, int32_t state)
{
    WriteEventBehavior("WIFI_P2P_STATE", "INTERFACE", inter, "P2PTYPE", type, "STATE", state);
}

void WriteWifiConnectionHiSysEvent(const WifiConnectionType& type, const std::string& pkgName)
{
    WriteEvent("WIFI_CONNECTION", "TYPE", static_cast<int>(type), "PACKAGE_NAME", pkgName);
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

void WriteWifiAbnormalDisconnectHiSysEvent(int errorCode)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ERROR_CODE"] = errorCode;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_ABNORMAL_DISCONNECT", "EVENT_VALUE", writer.write(root));
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

void WriteWifiAccessIntFailedHiSysEvent(int operateRes, int failCnt)
{
    Json::Value root;
    Json::FastWriter writer;
    root["OPERATE_TYPE"] = operateRes;
    root["FAIL_CNT"] = failCnt;
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

void WriteWifiConnectFailedEventHiSysEvent(int operateType)
{
    Json::Value root;
    Json::FastWriter writer;
    root["OPERATE_TYPE"] = operateType;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_CONNECT_FAILED_EVENT", "EVENT_VALUE", writer.write(root));
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

void WriteWifiScanApiFailHiSysEvent(const std::string& pkgName, int failReason)
{
    Json::Value root;
    Json::FastWriter writer;
    root["PKG_NAME"] = pkgName;
    root["FAIL_REASON"] = failReason;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFISCANCONTROL_TRIGGER_API_FAIL", "EVENT_VALUE", writer.write(root));
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

void WriteArpInfoHiSysEvent(uint64_t arpRtt, int arpFailedCount)
{
    Json::Value root;
    Json::FastWriter writer;
    root["ARP_RTT"] = arpRtt;
    root["ARP_FAILED_COUNT"] = arpFailedCount;
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

void WirteConnectTypeHiSysEvent(std::string connectType)
{
    Json::Value root;
    Json::FastWriter writer;
    root["CONNECT_TYPE"] = connectType;
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "EVENT_CONNECT_TYPE", "EVENT_VALUE", writer.write(root));
}

}  // namespace Wifi
}  // namespace OHOS