/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include <ctime>
#include <vector>
#include "wifi_timer.h"
#include "network_black_list_manager.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("NetworkBlockListManager");
namespace {
constexpr int32_t MAX_CONNECT_FAILED_TIMES = 2;
}

NetworkBlockListManager::NetworkBlockListManager()
{}

NetworkBlockListManager::~NetworkBlockListManager()
{}

NetworkBlockListManager &NetworkBlockListManager::GetInstance()
{
    static NetworkBlockListManager gNetworkBlockListManager;
    return gNetworkBlockListManager;
}

void NetworkBlockListManager::AddWifiBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("AddWifiBlocklist, bssid is invalid");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (wifiBlockSet_.find(bssid) != wifiBlockSet_.end()) {
        WIFI_LOGI("AddWifiBlocklist, bssid is in block");
        return;
    }
    WIFI_LOGI("AddWifiBlocklist, bssid:%{public}s", MacAnonymize(bssid).c_str());
    wifiBlockSet_.insert(bssid);
}

void NetworkBlockListManager::RemoveWifiBlocklist(const std::string &bssid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (wifiBlockSet_.empty()) {
        WIFI_LOGI("RemoveWifiBlocklist, wifiBlockSet is empty");
        return;
    }

    if (wifiBlockSet_.find(bssid) != wifiBlockSet_.end()) {
        WIFI_LOGI("RemoveWifiBlocklist, bssid:%{public}s", MacAnonymize(bssid).c_str());
        wifiBlockSet_.erase(bssid);
    }
}

bool NetworkBlockListManager::IsInWifiBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (wifiBlockSet_.empty()) {
        return false;
    }

    auto iter = wifiBlockSet_.find(bssid);
    return iter != wifiBlockSet_.end();
}

void NetworkBlockListManager::AddAbnormalWifiBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("AddAbnormalWifiBlocklist, bssid is invalid");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    WIFI_LOGI("AddAbnormalWifiBlocklist, bssid:%{public}s", MacAnonymize(bssid).c_str());
    abnormalWifiBlockSet_.insert(bssid);
}

void NetworkBlockListManager::CleanAbnormalWifiBlocklist()
{
    std::lock_guard<std::mutex> lock(mutex_);
    WIFI_LOGI("CleanAbnormalWifiBlocklist");
    abnormalWifiBlockSet_.clear();
}

bool NetworkBlockListManager::IsInAbnormalWifiBlocklist(const std::string &bssid)
{
    if (abnormalWifiBlockSet_.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return abnormalWifiBlockSet_.find(bssid) != abnormalWifiBlockSet_.end();
}

void NetworkBlockListManager::CleanTempWifiBlockList()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, uint32_t> tempMap;
    tempWifiBlockMap_.swap(tempMap);
}

bool NetworkBlockListManager::IsInTempWifiBlockList(const std::string &bssid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (tempWifiBlockMap_.empty()) {
        WIFI_LOGI("IsInTempWifiBlockList, bssid is invalid");
        return false;
    }

    return tempWifiBlockMap_.find(bssid) != tempWifiBlockMap_.end();
}

bool NetworkBlockListManager::IsFailedMultiTimes(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("IsFailedMultiTimes, bssid is invalid");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t counter = 1;
    auto iter = tempWifiBlockMap_.find(bssid);
    if (iter != tempWifiBlockMap_.end()) {
        counter++;
        iter->second = static_cast<uint32_t>(counter);
    } else {
        tempWifiBlockMap_[bssid] = static_cast<uint32_t>(counter);
    }

    return counter >= MAX_CONNECT_FAILED_TIMES;
}

bool NetworkBlockListManager::IsInPerf5gBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("IsInPerf5gBlocklist, bssid is invalid");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (perf5gBlockMap_.empty()) {
        return false;
    }

    auto iter = perf5gBlockMap_.find(bssid);
    if (iter != perf5gBlockMap_.end()) {
        return iter->second.second;
    }
    return false;
}

void NetworkBlockListManager::AddPerf5gBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("AddPerf5gBlocklist, bssid is invalid");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = perf5gBlockMap_.find(bssid);
    if (iter != perf5gBlockMap_.end()) {
        perf5gBlockMap_[bssid].first++;
        perf5gBlockMap_[bssid].second = true;
    } else {
        perf5gBlockMap_[bssid] = std::make_pair(1, true);
    }
    WIFI_LOGI("AddPerf5gBlocklist, bssid:%{public}s, num:%{public}d",
        MacAnonymize(bssid).c_str(),
        perf5gBlockMap_[bssid].first);
    return;
}

bool NetworkBlockListManager::IsOverTwiceInPerf5gBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("IsOverTwiceInPerf5gBlocklist, bssid is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (perf5gBlockMap_.empty()) {
        return false;
    }
    auto iter = perf5gBlockMap_.find(bssid);
    if (iter != perf5gBlockMap_.end()) {
        return iter->second.first > 1;
    }
    return false;
}

void NetworkBlockListManager::RemovePerf5gBlocklist(const std::string &bssid)
{
    if (bssid.empty()) {
        WIFI_LOGI("RemovePerf5gBlocklist, bssid is invalid");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (perf5gBlockMap_.empty()) {
        return;
    }
    auto iter = perf5gBlockMap_.find(bssid);
    if (iter != perf5gBlockMap_.end()) {
        iter->second.second = false;
        WIFI_LOGI("RemovePerf5gBlocklist, bssid:%{public}s", MacAnonymize(bssid).c_str());
    }
}

void NetworkBlockListManager::CleanPerf5gBlocklist()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<std::string, std::pair<uint32_t, bool>> tempPerf5gBlockMap_;
    perf5gBlockMap_.swap(tempPerf5gBlockMap_);
}
}  // namespace Wifi
}  // namespace OHOS