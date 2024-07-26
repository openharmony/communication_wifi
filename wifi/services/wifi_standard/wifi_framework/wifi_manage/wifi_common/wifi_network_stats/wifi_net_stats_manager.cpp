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

#include "wifi_net_stats_manager.h"
#include "wifi_common_util.h"
#include <algorithm>
#include "net_stats_client.h"
#include "wifi_system_timer.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNetStats");

const char* WLAN_0 = "wlan0";
const char* UNKNOWN_PACKAGE_NAME = "unknown_package";
const char* SEP_STR = "/";
const char* END_STR = ",";
const int32_t UID_ALL = -1;
const int32_t MAX_LOG_TRAFFIC = 10;
const int64_t NET_STATS_POLL_INTERVAL = 10 * 1000;
const int64_t NET_STATS_DELAY_TIME = 2 * 1000;

void WifiNetStatsManager::StartNetStats()
{
    WIFI_LOGI("%{public}s, enter", __FUNCTION__);
    if (m_netStatsTimerId != 0) {
        WIFI_LOGI("%{public}s, m_netStatsTimerId is not zero", __FUNCTION__);
        return;
    }
    std::shared_ptr<WifiSysTimer> netStatsTimer =
        std::make_shared<WifiSysTimer>(true, NET_STATS_POLL_INTERVAL, true, false);
    std::function<void()> callback = std::bind(&WifiNetStatsManager::PerformPollAndLog, this);
    netStatsTimer->SetCallbackInfo(callback);
    m_netStatsTimerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(netStatsTimer);
    int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
    MiscServices::TimeServiceClient::GetInstance()->StartTimer(m_netStatsTimerId, currentTime + NET_STATS_DELAY_TIME);
    WIFI_LOGI("%{public}s, succuss", __FUNCTION__);
}

void WifiNetStatsManager::StopNetStats()
{
    WIFI_LOGI("%{public}s, enter", __FUNCTION__);
    if (m_netStatsTimerId == 0) {
        WIFI_LOGE("%{public}s, m_netStatsTimerId is zero", __FUNCTION__);
    } else {
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(m_netStatsTimerId);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(m_netStatsTimerId);
        m_netStatsTimerId = 0;
    }
    m_lastStatsMap.clear();
    m_hasLastStats = false;
    WIFI_LOGI("%{public}s, succuss", __FUNCTION__);
}

void WifiNetStatsManager::PerformPollAndLog()
{
    WIFI_LOGD("%{public}s, enter", __FUNCTION__);
    NetStats curNetStats;
    if (GetWifiNetStatsDetail(curNetStats) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("%{public}s, get network stats failed", __FUNCTION__);
        return;
    }
    if (!m_hasLastStats) {
        WIFI_LOGE("%{public}s, get base network stats", __FUNCTION__);
        m_hasLastStats = true;
        m_lastStatsMap = ConvertNetStatsToMap(curNetStats);
        return;
    }
    NetStats incrementalNetStats = GetIncrementalNetStats(curNetStats);
    m_lastStatsMap = ConvertNetStatsToMap(curNetStats);
    LogNetStatsTraffic(incrementalNetStats);
}

ErrCode WifiNetStatsManager::GetWifiNetStatsDetail(NetStats &netStats)
{
    NetStats data;
    int32_t ret = DelayedSingleton<NetManagerStandard::NetStatsClient>::GetInstance()->GetAllStatsInfo(data);
    if (ret != ERR_OK) {
        WIFI_LOGE("%{public}s, get network stats failed, ret: %{public}d", __FUNCTION__, ret);
        return WIFI_OPT_FAILED;
    }
    std::copy_if(data.begin(), data.end(), std::back_insert_iterator(netStats), [](NetStatsInfo info) {
        return info.iface_ == WLAN_0 && !info.HasNoData();
    });
    return WIFI_OPT_SUCCESS;
}

NetStats WifiNetStatsManager::GetIncrementalNetStats(NetStats curNetStats)
{
    NetStats incrementNetStats;
    for (auto &curInfo : curNetStats) {
        NetStatsInfo deltaInfo;
        auto indexIter = m_lastStatsMap.find(curInfo.uid_);
        if (indexIter == m_lastStatsMap.end()) {
            deltaInfo = curInfo;
        } else {
            deltaInfo = curInfo - indexIter->second;
        }
        if (deltaInfo.HasNoData()) {
            continue;
        }
        incrementNetStats.push_back(deltaInfo);
    }
    return incrementNetStats;
}

NetStatsInfo WifiNetStatsManager::GetTotalNetStatsInfo(NetStats netStats)
{
    NetStatsInfo totalNetStatsInfo;
    for (const auto &info : netStats) {
        totalNetStatsInfo += info;
    }
    totalNetStatsInfo.uid_ = UID_ALL;
    return totalNetStatsInfo;
}

std::map<int32_t, NetStatsInfo> WifiNetStatsManager::ConvertNetStatsToMap(NetStats netStats)
{
    std::map<int32_t, NetStatsInfo> netStatsMap;
    for (const auto &item : netStats) {
        netStatsMap.emplace(item.uid_, item);
    }
    return netStatsMap;
}

std::string WifiNetStatsManager::GetTrafficLog(std::string bundleName, NetStatsInfo info, bool needEndStr)
{
    std::string trafficLog;
    trafficLog += bundleName;
    trafficLog += SEP_STR;
    trafficLog += std::to_string(info.rxBytes_);
    trafficLog += SEP_STR;
    trafficLog += std::to_string(info.txBytes_);
    trafficLog += SEP_STR;
    trafficLog += std::to_string(info.rxPackets_);
    trafficLog += SEP_STR;
    trafficLog += std::to_string(info.txPackets_);
    if (needEndStr) {
        trafficLog += END_STR;
    }
    return trafficLog;
}

std::string WifiNetStatsManager::GetBundleName(int32_t uid)
{
    if (uid == UID_ALL) {
        return "total";
    }
    std::string bundleName;
    if (OHOS::Wifi::GetBundleNameByUid(uid, bundleName) != WIFI_OPT_SUCCESS) {
        return "unknown:" + std::to_string(uid);
    }
    return bundleName;
}

void WifiNetStatsManager::LogNetStatsTraffic(NetStats netStats)
{
    std::sort(netStats.begin(), netStats.end(), [] (NetStatsInfo v1, NetStatsInfo v2) {
        return v1.GetStats() > v2.GetStats();
    });
    int maxCount = netStats.size() >= MAX_LOG_TRAFFIC ? MAX_LOG_TRAFFIC : static_cast<int>(netStats.size());
    NetStatsInfo totalNetStats = GetTotalNetStatsInfo(netStats);
    if (totalNetStats.HasNoData()) {
        return;
    }
    std::string allTrafficLog;
    allTrafficLog += GetTrafficLog(GetBundleName(totalNetStats.uid_), totalNetStats);
    for (int i = 0; i < maxCount; i++) {
        if (i != maxCount - 1) {
            allTrafficLog += GetTrafficLog(GetBundleName(netStats[i].uid_), netStats[i]);
        } else {
            allTrafficLog += GetTrafficLog(GetBundleName(netStats[i].uid_), netStats[i], false);
        }
    }
    WIFI_LOGI("%{public}s", allTrafficLog.c_str());
}
} // namespace Wifi
} // namespace OHOS