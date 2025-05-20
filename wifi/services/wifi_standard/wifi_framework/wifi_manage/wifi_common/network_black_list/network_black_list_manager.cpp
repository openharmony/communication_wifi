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

    WIFI_LOGI("AddWifiBlocklist, bssid:%{public}s", MacAnonymize(bssid).c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    wifiBlockSet_.insert(bssid);
}

void NetworkBlockListManager::RemoveWifiBlocklist(const std::string &bssid)
{
    WIFI_LOGI("Enter RemoveWifiBlocklist");
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
    std::map<std::string, int32_t> tempMap;
    tempWifiBlockMap_.swap(tempMap);
}

bool NetworkBlockListManager::IsInTempWifiBlockList(const std::string &bssid)
{
    if (tempWifiBlockMap_.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return tempWifiBlockMap_.find(bssid) != tempWifiBlockMap_.end();
}

bool NetworkBlockListManager::IsFailedMultiTimes(const std::string &bssid)
{
    if (bssid.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t counter = 1;
    auto iter = tempWifiBlockMap_.find(bssid);
    if (iter != tempWifiBlockMap_.end()) {
        counter++;
        iter->second = counter;
    } else {
        tempWifiBlockMap_[bssid] = counter;
    }

    return counter >= MAX_CONNECT_FAILED_TIMES;
}

} // namespace Wifi
} // namespace OHOS