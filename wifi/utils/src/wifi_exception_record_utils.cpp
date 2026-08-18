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
#include "wifi_exception_record_utils.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <ctime>
#include <cstring>
#include <climits>
#include <algorithm>
#include <fstream>
#include <sstream>
#include "wifi_logger.h"
#include "cJSON.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("WifiExceptionRecordUtils");

constexpr const char* WIFI_DIR_PATH = "/data/service/el1/public/wifi";
constexpr const char* FILE_PATH = "/data/service/el1/public/wifi/wifi_exception.json";
constexpr int LOCK_RETRIES = 3;
constexpr int MAX_FAULTS_PER_GROUP = 10;
constexpr int MAX_TOTAL_RECORDS = 50;
constexpr int REASON_CATEGORY_BASE = 100;
constexpr int DHCP_CATEGORY = 1;
constexpr mode_t FILE_PERMISSION_MODE = 0600;
constexpr mode_t DIR_PERMISSION_MODE = 0700;
constexpr int LOCK_RETRY_INTERVAL_US = 50000;

static int CategoryOf(ExceptionReason reason)
{
    return static_cast<int>(reason) / REASON_CATEGORY_BASE;
}

std::string WifiExceptionRecordUtils::ReasonToString(ExceptionReason reason)
{
    switch (reason) {
        case ExceptionReason::DHCP_CONNECTION_FAIL:    return "DHCP_CONNECTION_FAIL";
        case ExceptionReason::DHCP_GET_IP_TIMEOUT:     return "DHCP_GET_IP_TIMEOUT";
        case ExceptionReason::DHCP_IPV4_RESULT_FAIL:   return "DHCP_IPV4_RESULT_FAIL";
        case ExceptionReason::DHCP_IP_EXPIRED_FAIL:    return "DHCP_IP_EXPIRED_FAIL";
        default: return "UNKNOWN";
    }
}

std::string WifiExceptionRecordUtils::CategoryToString(ExceptionReason reason)
{
    switch (CategoryOf(reason)) {
        case DHCP_CATEGORY: return "DHCP";
        default: return "UNKNOWN";
    }
}

std::string WifiExceptionRecordUtils::FormatTime(int64_t timestamp)
{
    time_t timeValue = static_cast<time_t>(timestamp);
    struct tm result = {};
    localtime_r(&timeValue, &result);
    char buf[32] = {0};
    size_t len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &result);
    if (len == 0) {
        return std::string();
    }
    return std::string(buf, len);
}

static void SerializeDetail(cJSON* obj, const DhcpFaultDetail& detail)
{
    cJSON_AddNumberToObject(obj, "dhcpStatus", detail.dhcpStatus);
    cJSON_AddStringToObject(obj, "extra", detail.extra.c_str());
}

static cJSON* SerializeFault(const MergedFault& fault, WifiExceptionRecordUtils& utils)
{
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "timestamp", static_cast<double>(fault.timestamp));
    cJSON_AddStringToObject(item, "timeReadable", utils.FormatTime(fault.timestamp).c_str());
    cJSON_AddNumberToObject(item, "reasonCode", static_cast<int>(fault.reason));
    cJSON_AddStringToObject(item, "reason", utils.ReasonToString(fault.reason).c_str());
    cJSON_AddStringToObject(item, "category", utils.CategoryToString(fault.reason).c_str());
    std::visit([item](const auto& detail) {SerializeDetail(item, detail);}, fault.detail);
    return item;
}

static cJSON* BuildGroupsJson(const std::vector<ApGroup>& groups, WifiExceptionRecordUtils& utils)
{
    cJSON* arr = cJSON_CreateArray();
    for (const auto& group : groups) {
        cJSON* grp = cJSON_CreateObject();
        cJSON_AddStringToObject(grp, "ssid", group.ssid.c_str());
        cJSON* faults = cJSON_CreateArray();
        for (const auto& fault : group.faults) {
            cJSON_AddItemToArray(faults, SerializeFault(fault, utils));
        }
        cJSON_AddItemToObject(grp, "faults", faults);
        cJSON_AddItemToArray(arr, grp);
    }
    return arr;
}

static int WriteTmpAndRename(const std::string& jsonStr)
{
    std::string tmpPath = std::string(FILE_PATH) + ".tmp";
    int fd = open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, FILE_PERMISSION_MODE);
    if (fd < 0) {
        WIFI_LOGE("WriteTmpAndRename: open tmp failed");
        return -1;
    }
    ssize_t written = write(fd, jsonStr.c_str(), jsonStr.size());
    fsync(fd);
    close(fd);
    if (written < 0) {
        WIFI_LOGE("WriteTmpAndRename: write failed");
        return -1;
    }
    if (rename(tmpPath.c_str(), FILE_PATH) != 0) {
        WIFI_LOGE("WriteTmpAndRename: rename failed");
        return -1;
    }
    int dirFd = open(WIFI_DIR_PATH, O_RDONLY);
    if (dirFd >= 0) {
        fsync(dirFd);
        close(dirFd);
    }
    return 0;
}

static int32_t SaveToFile(const std::vector<ApGroup>& groups)
{
    WifiExceptionRecordUtils utils;
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "maxRecords", MAX_TOTAL_RECORDS);
    cJSON_AddItemToObject(root, "groups", BuildGroupsJson(groups, utils));
    char* jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (jsonStr == nullptr) {
        return -1;
    }
    int ret = WriteTmpAndRename(jsonStr);
    cJSON_free(jsonStr);
    return ret;
}

static FaultDetail ParseDetail(cJSON* faultNode, ExceptionReason reason)
{
    switch (CategoryOf(reason)) {
        case DHCP_CATEGORY: {
            cJSON* dhcpStatusNode = cJSON_GetObjectItem(faultNode, "dhcpStatus");
            cJSON* extraNode = cJSON_GetObjectItem(faultNode, "extra");
            return DhcpFaultDetail{
                dhcpStatusNode && cJSON_IsNumber(dhcpStatusNode) ? dhcpStatusNode->valueint : -1,
                extraNode && cJSON_IsString(extraNode) ? extraNode->valuestring : ""};
        }
        default:
            return DhcpFaultDetail{-1, "unknown reason"};
    }
}

static MergedFault ParseFault(cJSON* faultNode)
{
    MergedFault fault = {};
    cJSON* timestampNode = cJSON_GetObjectItem(faultNode, "timestamp");
    if (timestampNode && cJSON_IsNumber(timestampNode)) {
        fault.timestamp = static_cast<int64_t>(timestampNode->valuedouble);
    }
    cJSON* reasonCodeNode = cJSON_GetObjectItem(faultNode, "reasonCode");
    int reasonCode = reasonCodeNode && cJSON_IsNumber(reasonCodeNode) ? reasonCodeNode->valueint : 0;
    fault.reason = static_cast<ExceptionReason>(reasonCode);
    fault.detail = ParseDetail(faultNode, fault.reason);
    return fault;
}

static void ParseFaults(cJSON* faultsArr, std::vector<MergedFault>& faults)
{
    if (!faultsArr || !cJSON_IsArray(faultsArr)) {
        return;
    }
    int faultCount = cJSON_GetArraySize(faultsArr);
    for (int index = 0; index < faultCount; index++) {
        cJSON* faultNode = cJSON_GetArrayItem(faultsArr, index);
        if (faultNode) {
            faults.push_back(ParseFault(faultNode));
        }
    }
}

static void ParseGroups(cJSON* groupsArr, std::vector<ApGroup>& groups)
{
    if (!groupsArr || !cJSON_IsArray(groupsArr)) {
        return;
    }
    int groupCount = cJSON_GetArraySize(groupsArr);
    for (int index = 0; index < groupCount; index++) {
        cJSON* grpNode = cJSON_GetArrayItem(groupsArr, index);
        if (!grpNode) {
            continue;
        }
        cJSON* ssidNode = cJSON_GetObjectItem(grpNode, "ssid");
        if (!ssidNode || !cJSON_IsString(ssidNode)) {
            continue;
        }
        ApGroup group;
        group.ssid = ssidNode->valuestring;
        cJSON* faultsArr = cJSON_GetObjectItem(grpNode, "faults");
        ParseFaults(faultsArr, group.faults);
        groups.push_back(std::move(group));
    }
}

static int32_t LoadFromFile(std::vector<ApGroup>& groups)
{
    groups.clear();
    std::ifstream ifs(FILE_PATH);
    if (!ifs.is_open()) {
        return 0;
    }
    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string content = ss.str();
    if (content.empty()) {
        return 0;
    }
    cJSON* root = cJSON_Parse(content.c_str());
    if (!root) {
        WIFI_LOGE("LoadFromFile: parse failed, treating as empty");
        return 0;
    }
    cJSON* groupsArr = cJSON_GetObjectItem(root, "groups");
    ParseGroups(groupsArr, groups);
    cJSON_Delete(root);
    return 0;
}

static int AcquireLock(int fd, bool exclusive)
{
    int operation = exclusive ? (LOCK_EX | LOCK_NB) : LOCK_SH;
    int retries = LOCK_RETRIES;
    while (retries > 0) {
        int ret = flock(fd, operation);
        if (ret == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EWOULDBLOCK) {
            usleep(LOCK_RETRY_INTERVAL_US);
            retries--;
            continue;
        }
        return -1;
    }
    return -1;
}

static bool IsPathValid(const std::string& path)
{
    if (path.find("..") != std::string::npos) {
        return false;
    }
    std::string prefix = std::string(WIFI_DIR_PATH) + "/";
    if (path.find(prefix) != 0) {
        return false;
    }
    std::string dir = path.substr(0, path.find_last_of('/'));
    if (access(dir.c_str(), F_OK) != 0) {
        if (mkdir(dir.c_str(), DIR_PERMISSION_MODE) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

static ApGroup& FindOrAddGroup(std::vector<ApGroup>& groups, const std::string& ssid)
{
    for (auto& group : groups) {
        if (group.ssid == ssid) {
            return group;
        }
    }
    groups.push_back(ApGroup{ssid, {}});
    return groups.back();
}

static void MergeOrAddFault(std::vector<MergedFault>& faults, const WifiExceptionRecord& record)
{
    for (auto& fault : faults) {
        if (fault.reason == record.reason && fault.detail == record.detail) {
            fault.timestamp = record.timestamp;
            return;
        }
    }
    faults.push_back(MergedFault{record.timestamp, record.reason, record.detail});
}

static void TrimPerGroup(std::vector<ApGroup>& groups)
{
    for (auto& group : groups) {
        if (group.faults.size() > MAX_FAULTS_PER_GROUP) {
            std::sort(group.faults.begin(), group.faults.end(),
                [](const MergedFault& left, const MergedFault& right) {return left.timestamp > right.timestamp;});
            group.faults.resize(MAX_FAULTS_PER_GROUP);
        }
    }
}

static void TrimGlobal(std::vector<ApGroup>& groups)
{
    int total = 0;
    for (const auto& group : groups) total += static_cast<int>(group.faults.size());
    if (total <= MAX_TOTAL_RECORDS) {
        return;
    }
    struct Item {
        int groupIndex;
        int faultIndex;
        int64_t timestamp;
    };
    std::vector<Item> items;
    for (int groupIndex = 0; groupIndex < static_cast<int>(groups.size()); groupIndex++) {
        for (int faultIndex = 0; faultIndex < static_cast<int>(groups[groupIndex].faults.size()); faultIndex++) {
            items.push_back({groupIndex, faultIndex, groups[groupIndex].faults[faultIndex].timestamp});
        }
    }
    std::sort(items.begin(), items.end(), [](const Item& left, const Item& right) { return left.timestamp > right.timestamp;});
    std::vector<std::vector<MergedFault>> kept(groups.size());
    for (int index = 0; index < MAX_TOTAL_RECORDS && index < static_cast<int>(items.size()); index++) {
        kept[items[index].groupIndex].push_back(groups[items[index].groupIndex].faults[items[index].faultIndex]);
    }
    for (int groupIndex = 0; groupIndex < static_cast<int>(groups.size()); groupIndex++) {
        groups[groupIndex].faults = std::move(kept[groupIndex]);
    }
}

static void EnforceLimits(std::vector<ApGroup>& groups)
{
    TrimPerGroup(groups);
    TrimGlobal(groups);
}

int32_t WifiExceptionRecordUtils::AddException(const WifiExceptionRecord& record)
{
    if (!IsPathValid(FILE_PATH)) {
        WIFI_LOGE("AddException: path invalid");
        return -1;
    }
    int fd = open(FILE_PATH, O_RDWR | O_CREAT, FILE_PERMISSION_MODE);
    if (fd < 0) {
        WIFI_LOGE("AddException: open failed");
        return -1;
    }
    fchmod(fd, FILE_PERMISSION_MODE);
    if (AcquireLock(fd, true) < 0) {
        close(fd);
        WIFI_LOGE("AddException: lock failed,drop record");
        return -1;
    }
    std::vector<ApGroup> groups;
    LoadFromFile(groups);
    ApGroup& group = FindOrAddGroup(groups, record.ssid);
    MergeOrAddFault(group.faults, record);
    EnforceLimits(groups);
    SaveToFile(groups);
    flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

int32_t WifiExceptionRecordUtils::AddException(const std::string& ssid, ExceptionReason reason,
    int dhcpStatus, const std::string& extra)
{
    WifiExceptionRecord record;
    record.ssid = ssid;
    record.timestamp = static_cast<int64_t>(time(nullptr));
    record.reason = reason;
    record.detail = DhcpFaultDetail{dhcpStatus, extra};
    return AddException(record);
}

int32_t WifiExceptionRecordUtils::GetAllExceptions(std::vector<ApGroup>& groups)
{
    return LoadFromFile(groups);
}

int32_t WifiExceptionRecordUtils::ClearExceptions()
{
    if (!IsPathValid(FILE_PATH)) {
        return -1;
    }
    int fd = open(FILE_PATH, O_RDWR | O_CREAT, FILE_PERMISSION_MODE);
    if (fd < 0) {
        return -1;
    }
    fchmod(fd, FILE_PERMISSION_MODE);
    if (AcquireLock(fd, true) < 0) {
        close(fd);
        return -1;
    }
    std::vector<ApGroup> empty;
    SaveToFile(empty);
    flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

}
}
