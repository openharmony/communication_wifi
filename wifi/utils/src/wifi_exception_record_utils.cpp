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

constexpr const char* FILE_PATH = "/data/service/el1/public/wifi/wifi_exception.json";
constexpr int FILE_VERSION = 3;
constexpr int LOCK_RETRIES = 3;
constexpr int MAX_FAULTS_PER_GROUP = 10;
constexpr int MAX_TOTAL_RECORDS = 50;
constexpr int REASON_CATEGORY_BASE = 100;
constexpr mode_t FILE_PERMISSION_MODE = 0600;
constexpr mode_t DIR_PERMISSION_MODE = 0700;
constexpr int LOCK_RETRY_INTERVAL_US = 50000;

static int CategoryOf(ExceptionReason r)
{
    return static_cast<int>(r) / REASON_CATEGORY_BASE;
}

std::string WifiExceptionRecordUtils::ReasonToString(ExceptionReason r)
{
    switch (r) {
        case ExceptionReason::DHCP_CONNECTION_FAIL:    return "DHCP_CONNECTION_FAIL";
        case ExceptionReason::DHCP_GET_IP_TIMEOUT:     return "DHCP_GET_IP_TIMEOUT";
        case ExceptionReason::DHCP_IPV4_RESULT_FAIL:   return "DHCP_IPV4_RESULT_FAIL";
        case ExceptionReason::DHCP_IP_EXPIRED:         return "DHCP_IP_EXPIRED";
        default: return "UNKNOWN";
    }
}

std::string WifiExceptionRecordUtils::CategoryToString(ExceptionReason r)
{
    switch (CategoryOf(r)) {
        case 1: return "DHCP";
        default: return "UNKNOWN";
    }
}

std::string WifiExceptionRecordUtils::FormatTime(int64_t ts)
{
    time_t t = static_cast<time_t>(ts);
    struct tm result = {};
    localtime_r(&t, &result);
    char buf[32] = {0};
    size_t len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &result);
    if (len == 0) {
    return std::string(); 
}
    return std::string(buf, len);
}

static void SerializeDetail(cJSON* obj, const DhcpFaultDetail& d)
{
    cJSON_AddNumberToObject(obj, "dhcpStatus", d.dhcpStatus);
    cJSON_AddStringToObject(obj, "extra", d.extra.c_str());
}

static cJSON* SerializeFault(const MergedFault& f, WifiExceptionRecordUtils& utils)
{
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "timestamp", static_cast<double>(f.timestamp));
    cJSON_AddStringToObject(item, "timeReadable", utils.FormatTime(f.timestamp).c_str());
    cJSON_AddNumberToObject(item, "reasonCode", static_cast<int>(f.reason));
    cJSON_AddStringToObject(item, "reason", utils.ReasonToString(f.reason).c_str());
    cJSON_AddStringToObject(item, "category", utils.CategoryToString(f.reason).c_str());
    std::visit([item](const auto& d) {SerializeDetail(item, d);}, f.detail);
    return item;
}

static cJSON* BuildGroupsJson(const std::vector<ApGroup>& groups, WifiExceptionRecordUtils& utils)
{
    cJSON* arr = cJSON_CreateArray();
    for (const auto& g : groups) {
        cJSON* grp = cJSON_CreateObject();
        cJSON_AddStringToObject(grp, "ssid", g.ssid.c_str());
        cJSON* faults = cJSON_CreateArray();
        for (const auto& f : g.faults) {
            cJSON_AddItemToArray(faults, SerializeFault(f, utils));
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
    int dirFd = open("/data/service/el1/public/wifi", O_RDONLY);
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
    cJSON_AddNumberToObject(root, "version", FILE_VERSION);
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
        case 1: {
            cJSON* ds = cJSON_GetObjectItem(faultNode, "dhcpStatus");
            cJSON* ex = cJSON_GetObjectItem(faultNode, "extra");
            return DhcpFaultDetail{
                ds && cJSON_IsNumber(ds) ? ds->valueint : -1,
                ex && cJSON_IsString(ex) ? ex->valuestring : ""};
        }
        default:
            return DhcpFaultDetail{-1, "unknown reason"};
    }
}

static MergedFault ParseFault(cJSON* faultNode)
{
    MergedFault fault = {};
    cJSON* tsNode = cJSON_GetObjectItem(faultNode, "timestamp");
    if (tsNode && cJSON_IsNumber(tsNode)) {
        fault.timestamp = static_cast<int64_t>(tsNode->valuedouble);
    }
    cJSON* rcNode = cJSON_GetObjectItem(faultNode, "reasonCode");
    int reasonCode = rcNode && cJSON_IsNumber(rcNode) ? rcNode->valueint : 0;
    fault.reason = static_cast<ExceptionReason>(reasonCode);
    fault.detail = ParseDetail(faultNode, fault.reason);
    return fault;
}

static void ParseFaults(cJSON* faultsArr, std::vector<MergedFault>& faults)
{
    if (!faultsArr || !cJSON_IsArray(faultsArr)) {
        return;
    }
    int fsize = cJSON_GetArraySize(faultsArr);
    for (int j = 0; j < fsize; j++) {
        cJSON* faultNode = cJSON_GetArrayItem(faultsArr, j);
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
    int size = cJSON_GetArraySize(groupsArr);
    for (int i = 0; i < size; i++) {
        cJSON* grpNode = cJSON_GetArrayItem(groupsArr, i);
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
    cJSON* verNode = cJSON_GetObjectItem(root, "version");
    if (!verNode || !cJSON_IsNumber(verNode) || verNode->valueint != FILE_VERSION) {
        cJSON_Delete(root);
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
    const char* prefix = "/data/service/el1/public/wifi/";
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
    for (auto& g: groups) {
        if (g.ssid == ssid) {
            return g;
        }
    }
    groups.push_back(ApGroup{ssid, {}});
    return groups.back();
}

static void MergeOrAddFault(std::vector<MergedFault>& faults, const WifiExceptionRecord& record)
{
    for (auto& f : faults) {
        if (f.reason == record.reason && f.detail == record.detail) {
            f.timestamp = record.timestamp;
            return;
        }
    }
    faults.push_back(MergedFault{record.timestamp, record.reason, record.detail});
}

static void TrimPerGroup(std::vector<ApGroup>& groups)
{
    for (auto& g : groups) {
        if (g.faults.size() > MAX_FAULTS_PER_GROUP) {
            std::sort(g.faults.begin(), g.faults.end(),
                [](const MergedFault& a, const MergedFault& b) {return a.timestamp > b.timestamp;});
            g.faults.resize(MAX_FAULTS_PER_GROUP);
        }
    }
}
static void TrimGlobal(std::vector<ApGroup>& groups)
{
    int total = 0;
    for (const auto& g : groups) total += static_cast<int>(g.faults.size());
    if (total <= MAX_TOTAL_RECORDS) {
        return;
    }
    struct Item { int gIdx; int fIdx; int64_t ts; };
    std::vector<Item> items;
    for (int gi = 0; gi < static_cast<int>(groups.size()); gi++) {
        for (int fi = 0; fi < static_cast<int>(groups[gi].faults.size()); fi++) {
            items.push_back({gi, fi, groups[gi].faults[fi].timestamp});
        }
    }
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return a.ts > b.ts;});
    std::vector<std::vector<MergedFault>> kept(groups.size());
    for (int i = 0; i < MAX_TOTAL_RECORDS && i < static_cast<int>(items.size()); i++) {
        kept[items[i].gIdx].push_back(groups[items[i].gIdx].faults[items[i].fIdx]);
    }
    for (int gi = 0; gi < static_cast<int>(groups.size()); gi++) {
        groups[gi].faults = std::move(kept[gi]);
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