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
#include "cJSON.h"
#include "wifi_logger.h"
#include "wifi_device.h"
#include "wifi_scan.h"
#include "wifi_errcode.h"
#include "define.h"
#include "wifi_logger.h"
#include "securec.h"

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
    cJSON_AddTrueToObject(root, "success");
    cJSON_AddItemToObject(root, "data", data);

    char* jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr != nullptr) {
        std::cout << jsonStr << std::endl;
        cJSON_free(jsonStr);
    }
    cJSON_Delete(root);
}

void OutputErrorJson(const std::string& code, const std::string& message, const std::string& suggestion = "")
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddFalseToObject(root, "success");

    cJSON* errorObj = cJSON_CreateObject();
    cJSON_AddStringToObject(errorObj, "code", code.c_str());
    cJSON_AddStringToObject(errorObj, "message", message.c_str());
    if (!suggestion.empty()) {
        cJSON_AddStringToObject(errorObj, "suggestion", suggestion.c_str());
    }
    cJSON_AddItemToObject(root, "error", errorObj);

    char* jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr != nullptr) {
        std::cout << jsonStr << std::endl;
        cJSON_free(jsonStr);
    }
    cJSON_Delete(root);
}

int cmd_sta_enable(int argc, char** argv)
{
    WIFI_LOGI("sta-enable command started");

    auto wifiDevice = GetWifiDevice();
    if (wifiDevice == nullptr) {
        WIFI_LOGE("Failed to get WifiDevice instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiDevice instance",
                        "Please check if WiFi service is available");
        return 1;
    }

    OHOS::Wifi::ErrCode ret = wifiDevice->EnableWifi();
    WIFI_LOGI("EnableWifi returned %{public}d", ret);

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "WiFi STA mode enabled successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret) {
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

int cmd_sta_disable(int argc, char** argv)
{
    WIFI_LOGI("sta-disable command started");

    auto wifiDevice = GetWifiDevice();
    if (wifiDevice == nullptr) {
        WIFI_LOGE("Failed to get WifiDevice instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiDevice instance",
                        "Please check if WiFi service is available");
        return 1;
    }

    OHOS::Wifi::ErrCode ret = wifiDevice->DisableWifi();
    WIFI_LOGI("DisableWifi returned %{public}d", ret);

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "WiFi STA mode disabled successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret) {
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

int cmd_scan_start(int argc, char** argv)
{
    WIFI_LOGI("scan-start command started");

    auto wifiScan = GetWifiScan();
    if (wifiScan == nullptr) {
        WIFI_LOGE("Failed to get WifiScan instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiScan instance",
                        "Please check if WiFi scan service is available");
        return 1;
    }

    OHOS::Wifi::ErrCode ret = wifiScan->Scan(false);
    WIFI_LOGI("Scan(false) returned %{public}d", ret);

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        cJSON* data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "message", "WiFi scan started successfully");
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret) {
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

int cmd_scan_list(int argc, char** argv)
{
    WIFI_LOGI("scan-list command started");

    auto wifiScan = GetWifiScan();
    if (wifiScan == nullptr) {
        WIFI_LOGE("Failed to get WifiScan instance");
        OutputErrorJson("INTERNAL_ERROR", "Failed to get WifiScan instance",
                        "Please check if WiFi scan service is available");
        return 1;
    }

    std::vector<OHOS::Wifi::WifiScanInfo> scanInfoList;
    OHOS::Wifi::ErrCode ret = wifiScan->GetScanInfoList(scanInfoList, false);
    WIFI_LOGI("GetScanInfoList returned %{public}d, found %{public}zu networks",
              ret, scanInfoList.size());

    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
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
        OutputSuccessJson(data);
        return 0;
    }

    std::string errorMsg;
    switch (ret) {
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

int cmd_help(int argc, char** argv)
{
    WIFI_LOGI("help command called");
    std::cerr << "Available commands:\n";
    for (const auto& pair : g_commands) {
        std::cerr << "  " << pair.first << " - " << pair.second.description << "\n";
    }
    return 0;
}

void InitCommands()
{
    g_commands["sta-enable"] = {"sta-enable", "Enable WiFi STA mode", cmd_sta_enable};
    g_commands["sta-disable"] = {"sta-disable", "Disable WiFi STA mode", cmd_sta_disable};
    g_commands["scan-start"] = {"scan-start", "Start WiFi scan", cmd_scan_start};
    g_commands["scan-list"] = {"scan-list", "List scan results", cmd_scan_list};
    g_commands["--help"] = {"--help", "Show help information", cmd_help};
}

void PrintUsage(const char* progName)
{
    std::cerr << "Usage: " << progName << " <command>\n";
    std::cerr << "Available commands:\n";
    for (const auto& pair : g_commands) {
        std::cerr << "  " << pair.first << " - " << pair.second.description << "\n";
    }
    std::cerr << "\nFor help, run: " << progName << " <command>\n";
}

} // namespace

int main(int argc, char** argv)
{
    int argcSubcommandNum = 2;
    if (argc < argcSubcommandNum) {
        PrintUsage(argv[0]);
        return 1;
    }

    InitCommands();

    std::string cmdName = argv[1];
    auto it = g_commands.find(cmdName);
    if (it == g_commands.end()) {
        WIFI_LOGE("Unknown command: %{public}s", cmdName.c_str());
        PrintUsage(argv[0]);
        return 1;
    }

    int cmdArgc = argc - argcSubcommandNum;
    char** cmdArgv = argv + argcSubcommandNum;

    WIFI_LOGI("Executing command: %{public}s", cmdName.c_str());
    int ret = it->second.handler(cmdArgc, cmdArgv);
    WIFI_LOGI("Command %{public}s finished with code %{public}d", cmdName.c_str(), ret);

    return ret;
}
