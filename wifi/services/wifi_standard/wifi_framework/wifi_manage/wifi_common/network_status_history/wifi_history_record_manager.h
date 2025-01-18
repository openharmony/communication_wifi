/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_HISTORY_RECORD_MANAGER_H
#define WIFI_HISTORY_RECORD_MANAGER_H

#include <string>
#include <cstdint>
#include "wifi_msg.h"
#include "sta_service_callback.h"
#include "wifi_event_handler.h"
#include "wifi_rdb_manager.h"

namespace OHOS {
namespace Wifi {
class WifiHistoryRecordManager {
public:
    /**
     * WifiHistoryRecordManager constructor
     */
    WifiHistoryRecordManager() = default;

    /**
     * @Description WifiHistoryRecordManager deconstruct
     */
    ~WifiHistoryRecordManager();

    /**
     * @Description get WifiHistoryRecordManager instance
     *
     * @return WifiHistoryRecordManager
     */
    static WifiHistoryRecordManager &GetInstance();

    /**
     * @Description disable WifiHistoryRecordManager construct
     *
     * @param WifiHistoryRecordManager - WifiHistoryRecordManager obj
     */
    WifiHistoryRecordManager(const WifiHistoryRecordManager&) = delete;

    /**
     * @Description disable WifiHistoryRecordManager equals sign opertaor
     */
    WifiHistoryRecordManager &operator=(const WifiHistoryRecordManager &) = delete;

    /**
     * @Description get sta change Callback
     *
     * @return callBack obj
     */
    StaServiceCallback GetStaCallback() const;

    /**
     * @Description init WifiHistoryRecordManager
     *
     * @return is success or not
     */
    int Init();

    /**
     * @Description is Home Ap
     *
     * @param bssid BSSID of queried hotspots
     * @return is home ap
     */
    bool IsHomeAp(const std::string &bssid);

    /**
     * @Description is Home router
     *
     * @return is home router
     */
    bool IsHomeRouter(const std::string &portalUrl);

    /**
     * @Description Delect All ApInfo
     */
    void DelectAllApInfo();

    /**
     * @Description Delect ApInfo
     *
     * @param ssid ap ssid
     * @param bssid ap bssid
     */
    void DelectApInfo(const std::string &ssid, const std::string &bssid);
private:
    class ConnectedApInfo {
    public:
        // archive attribute
        int networkId = 0;
        std::string ssid = "";
        std::string bssid = "";
        std::string keyMgmt = "";
        int64_t firstConnectedTime = 0;
        int64_t currentConnectedTime = 0;
        int64_t totalUseTime = 0;
        int64_t totalUseTimeAtNight = 0;
        int64_t totalUseTimeAtWeekend = 0;
        int64_t markedAsHomeApTime = 0;

        // temporary attribute
        int64_t currenttStaticTimePoint = 0;
        int currentRecordDayInWeek = 0;  // record the day of the week
        int currentRecordHour = 0;
        int currentRecordMinute = 0;
        int currentRecordSecond = 0;
    };
    int GetUpdateConnectTimeRecordInterval();
    void CreateTable();
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    void HandleWifiConnectedMsg(const WifiLinkedInfo &info, const WifiDeviceConfig &config);
    bool IsEnterprise(const WifiDeviceConfig &config);
    void NextUpdateApInfoTimer();
    void StopUpdateApInfoTimer();
    bool CheckIsHomeAp();
    void HomeApJudgeProcess();
    void UpdateConnectionTime(bool isNeedNext);
    bool IsAbnormalTimeRecords();
    void UpdateStaticTimePoint(const std::time_t &currentTime);
    void StaticDurationInNightAndWeekend(int day, int startTime, int endTime);
    void AddOrUpdateApInfoRecord();
    void RemoveApInfoRecord(const std::string &bssid);
    int QueryApInfoRecordByBssid(const std::string &bssid, ConnectedApInfo &dbApInfo);
    int QueryAllApInfoRecord(std::vector<ConnectedApInfo> &dbApInfoVector);
    NativeRdb::ValuesBucket CreateApInfoBucket(const ConnectedApInfo &apInfo);
    void ClearConnectedApInfo();
    bool IsFloatEqual(double a, double b);

    std::shared_ptr<WifiRdbManager> wifiDataBaseUtils_;
    StaServiceCallback staCallback_;
    ConnectedApInfo connectedApInfo_;
    std::recursive_mutex updateApInfoMutex_;
    std::mutex updateApInfoTimerMutex_;
    std::mutex dealStaConnChangedMutex_;
    std::unique_ptr<WifiEventHandler> periodicUpdateApInfoThread_ = nullptr;
    int updateConnectTimeRecordInterval_ = 0;
};
}
}
#endif