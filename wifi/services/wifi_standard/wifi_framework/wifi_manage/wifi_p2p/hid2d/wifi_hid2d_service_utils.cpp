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

#include "wifi_hid2d_service_utils.h"
#include <regex>
#include <shared_mutex>
#include "dhcp_define.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_P2P_LABEL("Hid2dIpPool");
std::list<std::string> IpPool::ipList;
std::map<std::string, std::string> IpPool::mapGcMacToAllocIp;
const std::string PATTERN_IP = "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
std::shared_mutex g_ipPoolMutex;
static std::mutex g_sharedLinkMutex;
std::map<int, int> SharedLinkManager::sharedLinkCountMap;
int SharedLinkManager::firstGroupUid = -1;
#define DEFAULT_UID 0

bool IpPool::InitIpPool(const std::string& serverIp)
{
    WIFI_LOGI("Init ip pool");

    std::unique_lock<std::shared_mutex> guard(g_ipPoolMutex);
    if (!ipList.empty()) {
        return true;
    }

    std::string hostIp = serverIp.empty() ? DHCP::IP_V4_DEFAULT : serverIp;
    if (!IsValidIp(hostIp)) {
        return false;
    }

    size_t lastDotPos = hostIp.find_last_of("\\.");
    if (lastDotPos == std::string::npos) {
        return false;
    }
 
    std::string serverIpHead = hostIp.substr(0, lastDotPos);
    std::string serverIpHead = hostIp.substr(0, hostIp.find_last_of("\\."));
    ipList.clear();
    mapGcMacToAllocIp.clear();
    for (int i = HID2D_IPPOOL_START; i <= HID2D_IPPOOL_END; ++i) {
        ipList.emplace_back(serverIpHead + "." + std::to_string(i));
    }
    return true;
}

std::string IpPool::GetIp(const std::string& gcMac)
{
    WIFI_LOGI("Get ip, gcMac: %{public}s", MacAnonymize(gcMac).c_str());

    std::unique_lock<std::shared_mutex> guard(g_ipPoolMutex);
    std::string ip = "";
    if (ipList.empty()) {
        WIFI_LOGE("Alloc ip failed!");
        return ip;
    }
    ip = ipList.front();
    ipList.pop_front();
    mapGcMacToAllocIp[gcMac] = ip;
    return ip;
}

void IpPool::ReleaseIp(const std::string& gcMac)
{
    WIFI_LOGI("Release ip, gcMac: %{public}s", MacAnonymize(gcMac).c_str());

    std::unique_lock<std::shared_mutex> guard(g_ipPoolMutex);
    auto iter = mapGcMacToAllocIp.find(gcMac);
    if (iter == mapGcMacToAllocIp.end()) {
        return;
    }

    if (std::find(ipList.begin(), ipList.end(), iter->second) != ipList.end()) {
        return;
    }
    if (IsValidIp(iter->second)) {
        ipList.emplace_back(iter->second);
        mapGcMacToAllocIp.erase(iter);
    }
}

void IpPool::ReleaseIpPool()
{
    WIFI_LOGI("Release ip pool");

    std::unique_lock<std::shared_mutex> guard(g_ipPoolMutex);
    mapGcMacToAllocIp.clear();
    ipList.clear();
}

bool IpPool::IsValidIp(const std::string& ip)
{
    if (ip.empty()) {
        return false;
    }
    return std::regex_match(ip, std::regex(PATTERN_IP));
}

void SharedLinkManager::SetGroupUid(int callingUid)
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    WIFI_LOGI("Set Group UID: %{public}d -> %{public}d", firstGroupUid, callingUid);
    if (firstGroupUid != -1) {
        return;
    }
    firstGroupUid = callingUid;
}

void SharedLinkManager::GetGroupUid(int &callingUid)
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    WIFI_LOGI("Get Group UID: %{public}d", firstGroupUid);
    callingUid = firstGroupUid;
}

void SharedLinkManager::IncreaseSharedLink()
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    WIFI_LOGI("IncreaseSharedLink, current GO UID: %{public}d", firstGroupUid);
    if (!sharedLinkCountMap.empty()) {
        WIFI_LOGE("IncreaseSharedLink, Current count is not zeros");
        sharedLinkCountMap.clear();
    }
    if (firstGroupUid == -1) {
        firstGroupUid = DEFAULT_UID;
    }
    sharedLinkCountMap[firstGroupUid]++;
    PrintMapInfo();
}

void SharedLinkManager::IncreaseSharedLink(int callingUid)
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    sharedLinkCountMap[callingUid]++;
    WIFI_LOGI("CallingUid %{public}d increase shared link to %{public}d", callingUid,
        sharedLinkCountMap[callingUid]);
    PrintMapInfo();
}

void SharedLinkManager::DecreaseSharedLink(int callingUid)
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    if (sharedLinkCountMap.find(callingUid) == sharedLinkCountMap.end()) {
        WIFI_LOGE("CallingUid %{public}d decrease error for not found!", callingUid);
        return;
    }
    if (sharedLinkCountMap[callingUid] == 0) {
        WIFI_LOGE("CallingUid %{public}d decrease error for sharedLinkCount == 0!", callingUid);
        return;
    }
    sharedLinkCountMap[callingUid]--;
    WIFI_LOGI("CallingUid %{public}d decrease shared link to %{public}d", callingUid,
        sharedLinkCountMap[callingUid]);
    PrintMapInfo();
}

void SharedLinkManager::ClearSharedLinkCount()
{
    WIFI_LOGI("ClearSharedLinkCount");
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    PrintMapInfo();
    firstGroupUid = -1;
    sharedLinkCountMap.clear();
}

int SharedLinkManager::GetSharedLinkCount()
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    int sharedLinkCount = 0;
    for (auto iter : sharedLinkCountMap) {
        sharedLinkCount += iter.second;
    }
    WIFI_LOGI("Get sharedLinkCount: %{public}d", sharedLinkCount);
    return sharedLinkCount;
}

void SharedLinkManager::ClearUidCount(int uid)
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    if (sharedLinkCountMap.find(uid) == sharedLinkCountMap.end()) {
        WIFI_LOGI("ClearUidCount %{public}d not found", uid);
        return;
    }
    WIFI_LOGI("ClearUidCount set %{public}d count to 0", uid);
    sharedLinkCountMap[uid] = 0;
}

void SharedLinkManager::PrintMapInfo(void)
{
    if (sharedLinkCountMap.empty()) {
        WIFI_LOGI("sharelink map is empty");
        return;
    }
    std::string mapInfo;
    for (auto iter : sharedLinkCountMap) {
        mapInfo += std::to_string(iter.first);
        mapInfo += " ";
    }
    WIFI_LOGI("sharelink map is %{public}s", mapInfo.c_str());
}

bool SharedLinkManager::CheckNeedRemoveGroup(int uid)
{
    std::unique_lock<std::mutex> lock(g_sharedLinkMutex);
    if (sharedLinkCountMap.find(uid) != sharedLinkCountMap.end()) {
        sharedLinkCountMap[uid] = 0;
    }
    PrintMapInfo();
    int sharedLinkCount = 0;
    for (auto iter : sharedLinkCountMap) {
        sharedLinkCount += iter.second;
    }
    if (sharedLinkCount == 0) {
        WIFI_LOGI("all create group server has died, need remove group");
        return true;
    }
    return false;
}
}  // namespace Wifi
}  // namespace OHOS