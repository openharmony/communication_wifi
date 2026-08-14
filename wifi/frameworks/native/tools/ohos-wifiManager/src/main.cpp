/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <cstring>
#include <algorithm>
#include <cstdlib>
#include "cJSON.h"
#include "wifi_logger.h"
#include "wifi_device.h"
#include "wifi_scan.h"
#include "wifi_errcode.h"
#include "define.h"
#include "wifi_logger.h"
#include "securec.h"
#ifdef WIFI_EXCEPTION_RECORD_ENABLE
#include "wifi_exception_record_utils.h"
#endif
namespace {
DEFINE_WIFILOG_LABEL("WifiCli");

using WifiDevicePtr = std::shared_ptr<OHOS::Wifi::WifiDevice>;
using WifiScanPtr = std::shared_ptr<OHOS::Wifi::WifiScan>;

struct Command {
    const char* name;
    const char* description;
    std::function<int(int, char**)> handler;
};

static std::unordered_map<std::string, Command> g_commands;

std::shared_ptr<OHOS::Wifi::WifiDevice> GetWifiDevice()
{
    static WifiDevicePtr g_wifiDevice =
        OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    return g_wifiDevice;
}

std::shared_ptr<OHOS::Wifi::WifiScan> GetWifiScan()
{
    static WifiScanPtr g_wifiScan =
        OHOS::Wifi::WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
    return g_wifiScan;
}

void OutputSuccessJson(cJSON* data)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "result");
    cJSON_AddStringToObject(root, "status", "success");
    cJSON_AddItemToObject(root, "data", data);

    char* jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr != nullptr)
    {
        std::cout << jsonStr << std::endl;
        cJSON_free(jsonStr);
    }
    cJSON_Delete(root);
}

void OutputErrorJson(const std::string& code, const std::string& message, const std::string& suggestion = "")
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "result");
    cJSON_AddStringToObject(root, "status", "failed");
    cJSON_AddStringToObject(root, "errCode", code.c_str());
    cJSON_AddStringToObject(root, "errMsg", message.c_str());

    char* jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr != nullptr)
    {
        std::cout << jsonStr << std::endl;
        cJSON_free(jsonStr);
    }
    cJSON_Delete(root);
}

int CmdStaEnable(int argc, char** argv)
{
    WIFI_LOGI("sta-enable command started");

    auto wifiDevice = GetWifiDevice();
    if (wifiDevice == nullptr)
    {
        WIFI_LOGE("Failed to get WifiDevice instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiDevice instance",
                        "Please check if WiFi service is available");
        return 1;
    }

    OHOS::Wifi::ErrCode ret = wifiDevice->EnableWifi();
    WIFI_LOGI("EnableWifi returned %{public}d", ret);

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "WiFi STA mode enabled successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret)
    {
        case OHOS::Wifi::WIFI_OPT_FORBID_AIRPLANE:
            errorMsg = "WiFi cannot be enabled in airplane mode";
            break;
        case OHOS::Wifi::WIFI_OPT_OPEN_SUCC_WHEN_OPENED:
            errorMsg = "WiFi is already enabled";
            break;
        case OHOS::Wifi::WIFI_OPT_PERMISSION_DENIED:
            errorMsg = "Permission denied";
            break;
        default:
            errorMsg = "Failed to enable WiFi STA mode";
            break;
    }
    OutputErrorJson("WIFI_ERROR", errorMsg, "Check WiFi permissions and airplane mode");
    return 1;
}

int CmdStaDisable(int argc, char** argv)
{
    WIFI_LOGI("sta-disable command started");

    auto wifiDevice = GetWifiDevice();
    if (wifiDevice == nullptr)
    {
        WIFI_LOGE("Failed to get WifiDevice instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiDevice instance",
                        "Please check if WiFi service is available");
        return 1;
    }

    OHOS::Wifi::ErrCode ret = wifiDevice->DisableWifi();
    WIFI_LOGI("DisableWifi returned %{public}d", ret);

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "WiFi STA mode disabled successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret)
    {
        case OHOS::Wifi::WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED:
            errorMsg = "WiFi is already disabled";
            break;
        case OHOS::Wifi::WIFI_OPT_PERMISSION_DENIED:
            errorMsg = "Permission denied";
            break;
        default:
            errorMsg = "Failed to disable WiFi STA mode";
            break;
    }
    OutputErrorJson("WIFI_ERROR", errorMsg, "Check WiFi permissions");
    return 1;
}

int CmdScanStart(int argc, char** argv)
{
    WIFI_LOGI("scan-start command started");

    auto wifiScan = GetWifiScan();
    if (wifiScan == nullptr)
    {
        WIFI_LOGE("Failed to get WifiScan instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiScan instance",
                        "Please check if WiFi scan service is available");
        return 1;
    }

    OHOS::Wifi::ErrCode ret = wifiScan->Scan(false);
    WIFI_LOGI("Scan(false) returned %{public}d", ret);

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "WiFi scan started successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret)
    {
        case OHOS::Wifi::WIFI_OPT_SCAN_NOT_OPENED:
            errorMsg = "Scan service is not opened";
            break;
        case OHOS::Wifi::WIFI_OPT_PERMISSION_DENIED:
            errorMsg = "Permission denied";
            break;
        default:
            errorMsg = "Failed to start WiFi scan";
            break;
    }
    OutputErrorJson("WIFI_ERROR", errorMsg, "Check WiFi permissions and ensure STA is enabled");
    return 1;
}

static cJSON* BuildScanResultJson(const std::vector<OHOS::Wifi::WifiScanInfo>& scanInfoList)
{
    cJSON* data = cJSON_CreateObject();
    cJSON* networks = cJSON_CreateArray();

    for (const auto& info : scanInfoList) {
        cJSON* network = cJSON_CreateObject();

        cJSON_AddStringToObject(network, "ssid",
            info.ssid.empty() ? "<unknown>" : info.ssid.c_str());
        cJSON_AddStringToObject(network, "bssid",
            info.bssid.empty() ? "<unknown>" : info.bssid.c_str());
        cJSON_AddNumberToObject(network, "securityType", static_cast<int>(info.securityType));
        cJSON_AddNumberToObject(network, "rssi", info.rssi);
        cJSON_AddNumberToObject(network, "frequency", info.frequency);

        cJSON_AddItemToArray(networks, network);
    }

    cJSON_AddItemToObject(data, "networks", networks);
    cJSON_AddNumberToObject(data, "count", static_cast<int>(scanInfoList.size()));
    return data;
}

int CmdScanList(int argc, char** argv)
{
    WIFI_LOGI("scan-list command started");

    auto wifiScan = GetWifiScan();
    if (wifiScan == nullptr)
    {
        WIFI_LOGE("Failed to get WifiScan instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiScan instance",
                        "Please check if WiFi scan service is available");
        return 1;
    }

    std::vector<OHOS::Wifi::WifiScanInfo> scanInfoList;
    OHOS::Wifi::ErrCode ret = wifiScan->GetScanInfoList(scanInfoList, false);
    WIFI_LOGI("GetScanInfoList returned %{public}d, found %{public}zu networks",
              ret, scanInfoList.size());

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        OutputSuccessJson(BuildScanResultJson(scanInfoList));
        return 0;
    }

    std::string errorMsg;
    switch (ret)
    {
        case OHOS::Wifi::WIFI_OPT_SCAN_NOT_OPENED:
            errorMsg = "Scan service is not opened";
            break;
        case OHOS::Wifi::WIFI_OPT_PERMISSION_DENIED:
            errorMsg = "Permission denied";
            break;
        default:
            errorMsg = "Failed to get scan results";
            break;
    }
    OutputErrorJson("WIFI_ERROR", errorMsg, "Ensure WiFi scan has been performed first");
    return 1;
}

void SetKeyMgmtBySecurityType(OHOS::Wifi::WifiSecurity securityType, std::string &keyMgmt)
{
    switch (securityType)
    {
        case OHOS::Wifi::WifiSecurity::PSK:
        case OHOS::Wifi::WifiSecurity::PSK_SAE:
            keyMgmt = "WPA-PSK";
            break;
        case OHOS::Wifi::WifiSecurity::EAP:
            keyMgmt = "WPA-EAP";
            break;
        case OHOS::Wifi::WifiSecurity::SAE:
            keyMgmt = "SAE";
            break;
        case OHOS::Wifi::WifiSecurity::WEP:
            keyMgmt = "WEP";
            break;
        case OHOS::Wifi::WifiSecurity::EAP_SUITE_B:
            keyMgmt = "WPA-EAP-SUITE-B-192";
            break;
        case OHOS::Wifi::WifiSecurity::WAPI_CERT:
            keyMgmt = "WAPI-CERT";
            break;
        case OHOS::Wifi::WifiSecurity::WAPI_PSK:
            keyMgmt = "WAPI-PSK";
            break;
        case OHOS::Wifi::WifiSecurity::OPEN:
        case OHOS::Wifi::WifiSecurity::OWE:
        default:
            keyMgmt = "NONE";
            break;
    }
}

void ParseConnectArgs(int argc, char** argv, OHOS::Wifi::WifiDeviceConfig& tmpConfig)
{
    for (int i = 0; i < argc - 1; ++i) {
        std::string arg = argv[i];
        if (arg == "--ssid")
        {
            tmpConfig.ssid = argv[i + 1];
        }
        if (arg == "--preSharedKey")
        {
            tmpConfig.preSharedKey = argv[i + 1];
        }
    }
}

int ExecuteWifiConnect(std::shared_ptr<OHOS::Wifi::WifiDevice>& wifiDevice,
    OHOS::Wifi::WifiDeviceConfig& tmpConfig)
{
    OHOS::Wifi::ErrCode ret = wifiDevice->ConnectToDevice(tmpConfig);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "ssid", tmpConfig.ssid.c_str());
        cJSON_AddStringToObject(data, "message", "WiFi connection initiated successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    std::string suggestion;
    switch (ret)
    {
        case OHOS::Wifi::WIFI_OPT_STA_NOT_OPENED:
            errorMsg = "WiFi STA is not enabled";
            suggestion = "Enable WiFi first with 'ohos-wifiManager sta-enable'";
            break;
        default:
            errorMsg = "Failed to connect to network";
            suggestion = "Check SSID/password and ensure network is in range";
            break;
    }
    OutputErrorJson("WIFI_ERROR", errorMsg, suggestion);
    return 1;
}

int CmdStaConnect(int argc, char** argv)
{
    WIFI_LOGI("sta-connect command started");

    OHOS::Wifi::WifiDeviceConfig tmpConfig;
    ParseConnectArgs(argc, argv, tmpConfig);
    if (tmpConfig.ssid.empty())
    {
        OutputErrorJson("ERR_PARAM_INVALID",
            "Missing required parameter: --ssid",
            "Usage: ohos-wifiManager sta-connect --ssid <ssid> [--preSharedKey <preSharedKey>]");
        return 1;
    }
    auto wifiDevice = GetWifiDevice();
    auto wifiScan = GetWifiScan();
    if (wifiDevice == nullptr || wifiScan == nullptr)
    {
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiScan instance",
                        "Please check if WiFi scan service is available");
        return 1;
    }

    std::vector<OHOS::Wifi::WifiScanInfo> scanInfoList;
    OHOS::Wifi::ErrCode ret = wifiScan->GetScanInfoList(scanInfoList, false);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        OutputErrorJson("WIFI_ERROR", "Cannot get the scan list", "Please check if WiFi scan service is available");
        return 1;
    }
    bool isFound = false;
    for (const auto& scanInfo : scanInfoList) {
        if (scanInfo.ssid == tmpConfig.ssid)
        {
            SetKeyMgmtBySecurityType(scanInfo.securityType, tmpConfig.keyMgmt);
            isFound = true;
        }
    }
    if (!isFound)
    {
        OutputErrorJson("WIFI_ERROR", "Failed to find the network", "Check if the network is available");
        return 1;
    }

    return ExecuteWifiConnect(wifiDevice, tmpConfig);
}

std::string GetDetailedStateErr(OHOS::Wifi::DetailedState state)
{
    switch (state)
    {
        case OHOS::Wifi::DetailedState::VERIFYING_POOR_LINK:
            return "VerifyingPoorLink";
        case OHOS::Wifi::DetailedState::PASSWORD_ERROR:
            return "PasswordError";
        case OHOS::Wifi::DetailedState::CONNECTION_REJECT:
            return "ConnectionReject";
        case OHOS::Wifi::DetailedState::CONNECTION_FULL:
            return "ConnectionFull";
        case OHOS::Wifi::DetailedState::CONNECTION_TIMEOUT:
            return "ConnectionTimeout";
        case OHOS::Wifi::DetailedState::OBTAINING_IPADDR_FAIL:
            return "ObtainingIpaddrFail";
        case OHOS::Wifi::DetailedState::INVALID:
        default:
            return "Invalid";
    }
}
std::string GetDetailedStateStr(OHOS::Wifi::DetailedState state)
{
    switch (state)
    {
        case OHOS::Wifi::DetailedState::AUTHENTICATING:
            return "Authenticating";
        case OHOS::Wifi::DetailedState::BLOCKED:
            return "Blocked";
        case OHOS::Wifi::DetailedState::CAPTIVE_PORTAL_CHECK:
            return "CaptivePortalCheck";
        case OHOS::Wifi::DetailedState::CONNECTED:
            return "Connected";
        case OHOS::Wifi::DetailedState::CONNECTING:
            return "Connecting";
        case OHOS::Wifi::DetailedState::DISCONNECTED:
            return "Disconnected";
        case OHOS::Wifi::DetailedState::DISCONNECTING:
            return "Disconnecting";
        case OHOS::Wifi::DetailedState::FAILED:
            return "Failed";
        case OHOS::Wifi::DetailedState::IDLE:
            return "Idle";
        case OHOS::Wifi::DetailedState::OBTAINING_IPADDR:
            return "ObtainingIpaddr";
        case OHOS::Wifi::DetailedState::WORKING:
            return "Working";
        case OHOS::Wifi::DetailedState::NOTWORKING:
            return "NotWorking";
        case OHOS::Wifi::DetailedState::SCANNING:
            return "Scanning";
        case OHOS::Wifi::DetailedState::SUSPENDED:
            return "Suspended";
        default:
            return GetDetailedStateErr(state);
    }
}

int CmdStaGetLinkedInfo(int argc, char** argv)
{
    auto wifiDevice = GetWifiDevice();
    if (wifiDevice == nullptr)
    {
        OutputErrorJson("INTERNAL_ERROR", "Failed to get wifiDevice instance",
                        "Please check if WiFi service is available");
        return 1;
    }

    OHOS::Wifi::WifiLinkedInfo info;
    OHOS::Wifi::ErrCode ret = wifiDevice->GetLinkedInfo(info);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS)
    {
        OutputErrorJson("WIFI_ERROR", "Failed to get WiFi linked info", "Ensure WiFi is enabled and connected");
        return 1;
    }
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "ssid", info.ssid.empty() ? "" : info.ssid.c_str());
    cJSON_AddStringToObject(data, "bssid", info.bssid.empty() ? "" : info.bssid.c_str());
    cJSON_AddNumberToObject(data, "rssi", info.rssi);
    cJSON_AddNumberToObject(data, "frequency", info.frequency);
    cJSON_AddNumberToObject(data, "linkSpeed", info.linkSpeed);
    std::string detailedState = GetDetailedStateStr(info.detailedState);
    cJSON_AddStringToObject(data, "detailedState", detailedState.c_str());
    OutputSuccessJson(data);
    WIFI_LOGI("Get WiFi linked info successfully");
    return 0;
}

int CmdHelp(int argc, char** argv)
{
    WIFI_LOGI("help command called");
    cJSON* data = cJSON_CreateObject();
    cJSON* cmdArr = cJSON_CreateArray();

    for (const auto& pair : g_commands) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "cmd", pair.first.c_str());
        cJSON_AddStringToObject(item, "desc", pair.second.description);
        cJSON_AddItemToArray(cmdArr, item);
    }
    cJSON_AddItemToObject(data, "commands", cmdArr);
    OutputSuccessJson(data);
    return 0;
}

#ifdef WIFI_EXCEPTION_RECORD_ENABLE
constexpr int NO_REASON_FILTER = -1;
constexpr int NO_PER_AP_LIMIT = 0;

static std::string GetSuggestion(OHOS::Wifi::ExceptionReason reason, const std::string& ssid)
{
    using R = OHOS::Wifi::ExceptionReason;
    switch (reason) {
        case R::DHCP_CONNECTION_FAIL:
            return "Failed to start IP request for " + ssid + ". Try toggling WiFi.";
        case R::DHCP_GET_IP_TIMEOUT:
            return "IP request to " + ssid + " timed out. Try restarting the router.";
        case R::DHCP_IPV4_RESULT_FAIL:
            return "IP allocation failed for " + ssid + ". Possible IP conflict.";
        case R::DHCP_IP_EXPIRED:
            return "IP lease for " + ssid + " expired. Reconnect to obtain a new IP.";
        default:
            return "WiFi connection anomaly. Try again.";
    }
}

static void SerializeDetailForCli(cJSON* obj, const OHOS::Wifi::FaultDetail& detail)
{
    using namespace OHOS::Wifi;
    if (std::holds_alternative<DhcpFaultDetail>(detail))
    {
        auto& d = std::get<DhcpFaultDetail>(detail);
        cJSON_AddNumberToObject(obj, "dhcpStatus", d.dhcpStatus);
        cJSON_AddStringToObject(obj, "extra", d.extra.c_str());
    }
}

static cJSON* SerializeFaultForCli(const OHOS::Wifi::MergedFault& f, const std::string& ssid)
{
    using namespace OHOS::Wifi;
    WifiExceptionRecordUtils utils;
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "timestamp", static_cast<double>(f.timestamp));
    cJSON_AddStringToObject(item, "timeReadable", utils.FormatTime(f.timestamp).c_str());
    cJSON_AddNumberToObject(item, "reasonCode", static_cast<int>(f.reason));
    cJSON_AddStringToObject(item, "reason", utils.ReasonToString(f.reason).c_str());
    cJSON_AddStringToObject(item, "category", utils.CategoryToString(f.reason).c_str());
    SerializeDetailForCli(item, f.detail);
    cJSON_AddStringToObject(item, "suggestion", GetSuggestion(f.reason, ssid).c_str());
    return item;
}

static void FilterGroups(std::vector<OHOS::Wifi::ApGroup>& groups, const std::string& ssid,
                        const std::string& category, int reasonCode)
{
    using namespace OHOS::Wifi;
    WifiExceptionRecordUtils utils;
    if (!ssid.empty())
    {
        groups.erase(std::remove_if(groups.begin(), groups.end(),
            [&ssid](const ApGroup& g){ return g.ssid != ssid; }), groups.end());
    }
    for (auto& g : groups) {
        g.faults.erase(std::remove_if(g.faults.begin(), g.faults.end(),
            [&utils, &category, reasonCode](const MergedFault& f){
                if (!category.empty() && utils.CategoryToString(f.reason) != category) return true;
                if (reasonCode != NO_REASON_FILTER && static_cast<int>(f.reason) != reasonCode) return true;
                return false;
            }), g.faults.end());
    }
    groups.erase(std::remove_if(groups.begin(), groups.end(),
        [](const ApGroup& g){ return g.faults.empty();}), groups.end());
}

static void ApplyPerApLimit(std::vector<OHOS::Wifi::ApGroup>& groups, int perAp)
{
    using namespace OHOS::Wifi;
    if (perAp <= NO_PER_AP_LIMIT) return;
    for (auto& g : groups) {
        if (static_cast<int>(g.faults.size()) > perAp)
        {
            std::sort(g.faults.begin(), g.faults.end(),
                [](const MergedFault& a, const MergedFault& b){ return a.timestamp > b.timestamp; });
            g.faults.resize(perAp);
        }
    }
}

static int DoClearExceptions()
{
    using namespace OHOS::Wifi;
    WifiExceptionRecordUtils utils;
    int32_t ret = utils.ClearExceptions();
    if (ret != 0)
    {
        OutputErrorJson("CLEAR_ERROR", "Failed to clear exception records", "");
        return 1;
    }
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "message", "All exception records cleared");
    OutputSuccessJson(data);
    return 0;
}

static int DoListExceptions(const std::string& ssid, const std::string& category,
                            int reasonCode, int perAp)
{
    using namespace OHOS::Wifi;
    WifiExceptionRecordUtils utils;
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    FilterGroups(groups, ssid, category, reasonCode);
    ApplyPerApLimit(groups, perAp);

    cJSON* data = cJSON_CreateObject();
    cJSON* arr = cJSON_CreateArray();
    int count = 0;
    for (const auto& g : groups) {
        cJSON* grp = cJSON_CreateObject();
        cJSON_AddStringToObject(grp, "ssid", g.ssid.c_str());
        cJSON* faults = cJSON_CreateArray();
        for (const auto& f : g.faults) {
            cJSON_AddItemToArray(faults, SerializeFaultForCli(f, g.ssid));
            count++;
        }
        cJSON_AddItemToObject(grp, "faults", faults);
        cJSON_AddItemToArray(arr, grp);
    }
    cJSON_AddItemToObject(data, "exceptions", arr);
    cJSON_AddNumberToObject(data, "count", count);
    OutputSuccessJson(data);
    return 0;
}

int CmdWifiException(int argc, char** argv)
{
    bool doClear = false;
    std::string filterSsid;
    std::string filterCategory;
    int filterReason = NO_REASON_FILTER;
    int perAp = NO_PER_AP_LIMIT;
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--clear") doClear = true;
        else if (arg == "--ssid" && i + 1 < argc) filterSsid = argv[++i];
        else if (arg == "--category" && i + 1 < argc) filterCategory = argv[++i];
        else if (arg == "--reason" && i + 1 < argc) filterReason = atoi(argv[++i]);
        else if (arg == "--per-ap" && i + 1 < argc) perAp = atoi(argv[++i]);
    }
    if (doClear) return DoClearExceptions();
    return DoListExceptions(filterSsid, filterCategory, filterReason, perAp);
}
#endif

void InitCommands()
{
    g_commands["sta-enable"] = {"sta-enable", "Enable WiFi STA mode", CmdStaEnable};
    g_commands["sta-disable"] = {"sta-disable", "Disable WiFi STA mode", CmdStaDisable};
    g_commands["scan-start"] = {"scan-start", "Start WiFi scan", CmdScanStart};
    g_commands["scan-list"] = {"scan-list", "List scan results", CmdScanList};
    g_commands["sta-connect"] = {"sta-connect", "Start WiFi connect", CmdStaConnect};
    g_commands["sta-getLinkedInfo"] = {"sta-getLinkedInfo", "Return linked info", CmdStaGetLinkedInfo};
#ifdef WIFI_EXCEPTION_RECORD_ENABLE
    g_commands["wifi-exception"] = {"wifi-exception", "List/Clear WiFi exception records", CmdWifiException};
#endif
    g_commands["--help"] = {"--help", "Show help information", CmdHelp};
}

} // namespace

int main(int argc, char** argv)
{
    WIFI_LOGI("enter ohos-wifiManager");
    constexpr int MIN_ARG_COUNT = 2;
    if (argc < MIN_ARG_COUNT)
    {
        CmdHelp(argc, argv);
        return 1;
    }

    InitCommands();

    std::string cmdName = argv[1];
    auto it = g_commands.find(cmdName);
    if (it == g_commands.end())
    {
        WIFI_LOGE("Unknown command: %{public}s", cmdName.c_str());
        CmdHelp(argc, argv);
        return 1;
    }

    int cmdArgc = argc - MIN_ARG_COUNT;
    char** cmdArgv = argv + MIN_ARG_COUNT;

    WIFI_LOGI("Executing command: %{public}s", cmdName.c_str());
    int ret = it->second.handler(cmdArgc, cmdArgv);
    WIFI_LOGI("Command %{public}s finished with code %{public}d", cmdName.c_str(), ret);

    return ret;
}
