/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_WIFI_NET_STATS_MANAGER_H
#define OHOS_WIFI_NET_STATS_MANAGER_H

#include "wifi_errcode.h"
#include <map>
#include <string>
#include <vector>
#include "singleton.h"
#include "net_stats_info.h"

namespace OHOS {
namespace Wifi {

using NetStats = std::vector<NetStatsInfo>;

class WifiNetStatsManager : public Singleton<WifiNetStatsManager> {
public:
    void StartNetStats();
    void StopNetStats();
private:
    void PerformPollAndLog();   
    ErrCode GetNetStatsDetail(NetStats netStats);
    NetStats GetIncrementalNetStats(NetStats curNetStats);
    NetStatsInfo GetTotalNetStatsInfo(NetStats netStats);
    void LogNetStatsTraffic(NetStats netStats);
    std::map<int32_t, NetStatsInfo> ConvertNetStatsToMap(NetStats netStats);
    bool ValidateNetStatsInfo(NetStatsInfo info);
    std::string GetTrafficLog(std::string bundleName, NetStatsInfo info, bool needEndStr = true);
    std::string GetBundleName(int32_t uid);
private:
    // NetStats m_lastStats;
    std::map<int32_t, NetStatsInfo> m_lastStatsMap;
    bool m_hasLastStats {false};
    uint64_t m_netStatsTimerId {0};
}
} // namespace Wifi
} // namespace OHOS

#endif