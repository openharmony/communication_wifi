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

#ifndef OHOS_WIFI_NETWORK_BLACK_LIST_MANAGER_H
#define OHOS_WIFI_NETWORK_BLACK_LIST_MANAGER_H

#include <map>
#include <set>
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
class NetworkBlockListManager {
public:
    NetworkBlockListManager();
    ~NetworkBlockListManager();
    static NetworkBlockListManager &GetInstance();
    void AddWifiBlocklist(const std::string &bssid);
    bool IsInWifiBlocklist(const std::string &bssid);
    void AddAbnormalWifiBlocklist(const std::string &bssid);
    void CleanAbnormalWifiBlocklist();
    void CleanTempWifiBlockList();
    bool IsInAbnormalWifiBlocklist(const std::string &bssid);
    bool IsInTempWifiBlockList(const std::string &bssid);
    bool IsFailedMultiTimes(const std::string &bssid);
    void RemoveWifiBlocklist(const std::string &bssid);
    void AddPerf5gBlocklist(const std::string &bssid);
    bool IsInPerf5gBlocklist(const std::string &bssid);
    void RemovePerf5gBlocklist(const std::string &bssid);
    void CleanPerf5gBlocklist();
    bool IsOverTwiceInPerf5gBlocklist(const std::string &bssid);
private:
    std::mutex mutex_;
    std::set<std::string> wifiBlockSet_;
    std::set<std::string> abnormalWifiBlockSet_;
    std::map<std::string, int32_t> tempWifiBlockMap_;
    std::map<std::string, uint32_t> tempWifiBlockMap_;
    std::unordered_map<std::string, std::pair<uint32_t, bool>> perf5gBlockMap_;
};

} // namespace Wifi
} // namespace OHOS
#endif