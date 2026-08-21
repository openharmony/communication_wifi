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
#include "wifi_exception_cli.h"
#include "wifi_manager_cli.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <variant>
#include <vector>

#include "cJSON.h"

#ifdef WIFI_EXCEPTION_RECORD_ENABLE
#include "wifi_exception_record_utils.h"
#endif

namespace OHOS {
namespace WifiCli {

#ifdef WIFI_EXCEPTION_RECORD_ENABLE

constexpr int NO_REASON_FILTER = -1;
constexpr int NO_PER_AP_LIMIT = 0;
constexpr int DECIMAL_BASE = 10;
constexpr int INT_MIN_VALUE = -2147483647-1;
constexpr int INT_MAX_VALUE = 2147483647;

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
        case R::DHCP_IP_EXPIRED_FAIL:
            return "IP lease for " + ssid + " expired. Reconnect to obtain a new IP.";
        default:
            return "WiFi connection anomaly. Try again.";
    }
}

static void SerializeDetailForCli(cJSON* obj, const OHOS::Wifi::FaultDetail& detail)
{
    using namespace OHOS::Wifi;
    if (std::holds_alternative<DhcpFaultDetail>(detail)) {
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
    if (!ssid.empty()) {
        groups.erase(std::remove_if(groups.begin(), groups.end(),
            [&ssid](const ApGroup& g) { return g.ssid != ssid; }), groups.end());
    }
    for (auto& g : groups) {
        g.faults.erase(std::remove_if(g.faults.begin(), g.faults.end(),
            [&utils, &category, reasonCode](const MergedFault& f) {
                if (!category.empty() && utils.CategoryToString(f.reason) != category) return true;
                if (reasonCode != NO_REASON_FILTER && static_cast<int>(f.reason) != reasonCode) return true;
                return false;
            }), g.faults.end());
    }
    groups.erase(std::remove_if(groups.begin(), groups.end(),
        [](const ApGroup& g) { return g.faults.empty();}), groups.end());
}

static void ApplyPerApLimit(std::vector<OHOS::Wifi::ApGroup>& groups, int perAp)
{
    using namespace OHOS::Wifi;
    if (perAp <= NO_PER_AP_LIMIT) return;
    for (auto& g : groups) {
        if (static_cast<int>(g.faults.size()) > perAp) {
            std::sort(g.faults.begin(), g.faults.end(),
                [](const MergedFault& a, const MergedFault& b) { return a.timestamp > b.timestamp; });
            g.faults.resize(perAp);
        }
    }
}

static int DoClearExceptions()
{
    using namespace OHOS::Wifi;
    WifiExceptionRecordUtils utils;
    int32_t ret = utils.ClearExceptions();
    if (ret != 0) {
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

static bool ParseIntArg(const char* str, int& outValue, std::string& errMsg)
{
    if (str == nullptr || *str == '\0') {
        srrMsg = "Value is empty";
        return false;
    }
    char* endPtr = nullptr;
    errno = 0;
    long value = strtol(str, &endPtr, DECIMAL_BASE);
    if (endPtr == str || *str == '\0') {
        srrMsg = "Value is not a valid integer";
        return false;
    }
    if (errno == ERANGE || value < INT_MIN_VALUE || value > INT_MAX_VALUE) {
        errMsg = "Value out of range";
        return false;
    }
    outValue = static_cast<int>(value);
    return true;
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
        if (arg == "--clear") {
            doClear = true;
        } else if (arg == "--ssid" && i + 1 < argc) {
            filterSsid = argv[++i];
        } else if (arg == "--category" && i + 1 < argc) {
            filterCategory = argv[++i];
        } else if (arg == "--reason" && i + 1 < argc) {
            std::string err;
            if (!ParseIntArg(argv[++i], filterReason, err)) {
                OutputErrorJson("ERR_PARAM_INVALID", "Invalid --reason value", err);
                return 1;
            }
        } else if (arg == "--per-ap" && i + 1 < argc) {
            std::string err;
            if (!ParseIntArg(argv[++i], perAp, err)) {
                OutputErrorJson("ERR_PARAM_INVALID", "Invalid --per-ap value", err);
                return 1;
            }
        }
    }
    if (doClear) {
        return DoClearExceptions();
    }
    return DoListExceptions(filterSsid, filterCategory, filterReason, perAp);
}

#endif // WIFI_EXCEPTION_RECORD_ENABLE

} // namespace WifiCli
} // namespace OHOS
