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

#include "wifi_history_record_manager.h"
#include <ctime>
#include <mutex>
#include <regex>
#include "wifi_logger.h"
#include "wifi_timer.h"
#include "wifi_settings.h"
#include "wifi_internal_msg.h"
#include "define.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiHistoryRecordManager");
const std::string WIFI_HISTORY_RECORD_MANAGER_CLASS_NAME = "WifiHistoryRecordManager";
const std::string PERIODIC_UPDATE_AP_INFO_THREAD = "PeriodicUpdateApInfoThread";
const std::string UPDATE_AP_INFO_TASK = "UpdateApInfoTask";
const std::string AP_CONNECTION_DURATION_INFO_TABLE_NAME = "ap_connection_duration_info";
const std::string NETWORK_ID = "networkId";
const std::string SSID = "ssid";
const std::string BSSID = "bssid";
const std::string KEY_MGMT = "keyMgmt";
const std::string FIRST_CONNECTED_TIME = "firstConnectedTime";
const std::string CURRENT_CONNECTED_TIME = "currentConnectedTime";
const std::string TOTAL_USE_TIME = "totalUseTime";
const std::string TOTAL_USE_TIME_AT_NIGHT = "totalUseTimeAtNight";
const std::string TOTAL_USE_TIME_AT_WEEKEND = "totalUseTimeAtWeekend";
const std::string MARKED_AS_HOME_AP_TIME = "markedAsHomeApTime";
inline constexpr const char* UPDATE_CONNECT_TIME_RECORD_INTERVAL = "const.wifi.update_connect_time_record_interval";
inline constexpr const char* UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT = "1800000";  // 30min
constexpr int64_t SECOND_OF_ONE_DAY = 60 * 60 * 24;
constexpr int64_t SECOND_OF_HALF_HOUR = 30 * 60;
constexpr int64_t SECOND_OF_ONE_HOUR = 60 * 60;
constexpr int64_t SECOND_OF_ONE_MINUTE = 60;
constexpr int64_t START_SECOND_OF_DAY = 0;
constexpr int64_t END_SECONDS_OF_DAY = (23 * SECOND_OF_ONE_HOUR + 59 * SECOND_OF_ONE_MINUTE + 59);
constexpr int64_t REST_TIME_END_PAST_SECONDS = 7 * SECOND_OF_ONE_HOUR;
constexpr int64_t REST_TIME_BEGIN_PAST_SECONDS = 20 * SECOND_OF_ONE_HOUR;
constexpr int64_t INVALID_TIME_POINT = 0;
constexpr float HOME_AP_MIN_TIME_RATE = 0.5;
constexpr int QUERY_FAILED = 0;
constexpr int QUERY_NO_RECORD = 1;
constexpr int QUERY_HAS_RECORD = 2;
constexpr int DAY_VALUE_SATURDAY_CALENDAR = 6;
constexpr int DAY_VALUE_SUNDAY_CALENDAR = 0;
constexpr int UPDATE_CONNECT_TIME_RECORD_INTERVAL_SIZE = 16;
constexpr int GET_DEVICE_CONFIG_SUCCESS = 0;
constexpr int TO_KEEP_TWO_DECIMAL = 100;

WifiHistoryRecordManager::~WifiHistoryRecordManager()
{
    StopUpdateApInfoTimer();
    ClearConnectedApInfo();
}

WifiHistoryRecordManager &WifiHistoryRecordManager::GetInstance()
{
    static WifiHistoryRecordManager gWifiHistoryRecordManager;
    return gWifiHistoryRecordManager;
}

int WifiHistoryRecordManager::Init()
{
    WIFI_LOGI("Init");
    periodicUpdateApInfoThread_ = std::make_unique<WifiEventHandler>(PERIODIC_UPDATE_AP_INFO_THREAD);
    wifiDataBaseUtils_ = WifiRdbManager::GetRdbManger(RdbType::WIFI_HISTORY_RECORD);
    staCallback_.callbackModuleName = WIFI_HISTORY_RECORD_MANAGER_CLASS_NAME;
    staCallback_.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
    updateConnectTimeRecordInterval_ = GetUpdateConnectTimeRecordInterval();
    if (periodicUpdateApInfoThread_ == nullptr || wifiDataBaseUtils_ == nullptr) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

int WifiHistoryRecordManager::GetUpdateConnectTimeRecordInterval()
{
    char preValue[UPDATE_CONNECT_TIME_RECORD_INTERVAL_SIZE] = {0};
    int errorCode = GetParamValue(UPDATE_CONNECT_TIME_RECORD_INTERVAL,
        UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT, preValue, UPDATE_CONNECT_TIME_RECORD_INTERVAL_SIZE);
    if (errorCode <= 0) {
        WIFI_LOGI("get UPDATE_CONNECT_TIME_RECORD_INTERVAL fail, take effect in 30 min");
        return ConvertStringToInt(UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT);
    }
    int intervalValue = ConvertStringToInt(preValue);
    WIFI_LOGI("get UPDATE_CONNECT_TIME_RECORD_INTERVAL is %{public}d", intervalValue);
    return intervalValue;
}

StaServiceCallback WifiHistoryRecordManager::GetStaCallback() const
{
    return staCallback_;
}

void WifiHistoryRecordManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    if (instId != INSTID_WLAN0) {
        return;
    }
    std::lock_guard<std::mutex> lock(dealStaConnChangedMutex_);
    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(info.networkId, config, instId);
    if (IsEnterprise(config)) {
        WIFI_LOGI("enterprise AP, not record, ssid=%{public}s, keyMgmt=%{public}s, state=%{public}d",
            SsidAnonymize(info.ssid).c_str(), config.keyMgmt.c_str(), static_cast<int>(state));
        return;
    }
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        WIFI_LOGI("deal disconnected, networkId=%{public}d, ssid=%{public}s, bssid=%{public}s",
            info.networkId, SsidAnonymize(info.ssid).c_str(), MacAnonymize(info.bssid).c_str());
        StopUpdateApInfoTimer();

        // If the saved network does not exist, maybe disconnect caused by deletion, do not update and save
        if (ret == GET_DEVICE_CONFIG_SUCCESS) {
            UpdateConnectionTime(false);
        }
        ClearConnectedApInfo();
    } else if (state == OperateResState::CONNECT_AP_CONNECTED) {
        HandleWifiConnectedMsg(info, config);
    }
}

void WifiHistoryRecordManager::HandleWifiConnectedMsg(const WifiLinkedInfo &info, const WifiDeviceConfig &config)
{
    if (info.bssid.empty() || info.bssid == connectedApInfo_.bssid) {
        return;
    }
    WIFI_LOGI("deal connected, ssid=%{public}s, bssid=%{public}s", SsidAnonymize(info.ssid).c_str(),
        MacAnonymize(info.bssid).c_str());
    if (info.networkId == connectedApInfo_.networkId) {
        WIFI_LOGI("roam, networkId=%{public}d, last bssid=%{public}s", info.networkId,
            MacAnonymize(connectedApInfo_.bssid).c_str());
        StopUpdateApInfoTimer();
        UpdateConnectionTime(false);
    }
    ClearConnectedApInfo();
    std::time_t currentTime = std::time(nullptr);
    connectedApInfo_.networkId = info.networkId;
    connectedApInfo_.ssid = info.ssid;
    connectedApInfo_.bssid = info.bssid;
    connectedApInfo_.currentConnectedTime = currentTime;
    ConnectedApInfo dbApInfo;
    int queryRet = QueryApInfoRecordByBssid(connectedApInfo_.bssid, dbApInfo);
    if (queryRet == QUERY_NO_RECORD) {  // First connect
        connectedApInfo_.keyMgmt = config.keyMgmt;
        connectedApInfo_.firstConnectedTime = currentTime;
    } else {
        connectedApInfo_.keyMgmt = dbApInfo.keyMgmt;
        connectedApInfo_.firstConnectedTime = dbApInfo.firstConnectedTime;
        connectedApInfo_.totalUseTime = dbApInfo.totalUseTime;
        connectedApInfo_.totalUseTimeAtNight = dbApInfo.totalUseTimeAtNight;
        connectedApInfo_.totalUseTimeAtWeekend = dbApInfo.totalUseTimeAtWeekend;
        connectedApInfo_.markedAsHomeApTime = dbApInfo.markedAsHomeApTime;
    }
    UpdateConnectionTime(true);
}

bool WifiHistoryRecordManager::IsEnterprise(const WifiDeviceConfig &config)
{
bool isEnterpriseSecurityType = (config.keyMgmt == KEY_MGMT_EAP) ||
    (config.keyMgmt == KEY_MGMT_SUITE_B_192) || (config.keyMgmt == KEY_MGMT_WAPI_CERT);
return isEnterpriseSecurityType && (config.wifiEapConfig.eap != EAP_METHOD_NONE);
}

void WifiHistoryRecordManager::NextUpdateApInfoTimer()
{
    std::lock_guard<std::mutex> lock(updateApInfoTimerMutex_);
    WIFI_LOGI("%{public}s", __func__);
    if (periodicUpdateApInfoThread_) {
        periodicUpdateApInfoThread_->RemoveAsyncTask(UPDATE_AP_INFO_TASK);
        periodicUpdateApInfoThread_->PostAsyncTask([this]() { this->UpdateConnectionTime(true);},
            UPDATE_AP_INFO_TASK, updateConnectTimeRecordInterval_);
        return;
    }
    WIFI_LOGE("%{public}s fail, periodicUpdateApInfoThread_ is null", __func__);
}

void WifiHistoryRecordManager::StopUpdateApInfoTimer()
{
    std::lock_guard<std::mutex> lock(updateApInfoTimerMutex_);
    WIFI_LOGI("%{public}s", __func__);
    if (periodicUpdateApInfoThread_) {
        periodicUpdateApInfoThread_->RemoveAsyncTask(UPDATE_AP_INFO_TASK);
    }
}

bool WifiHistoryRecordManager::IsFloatEqual(double a, double b)
{
    return (std::fabs(a - b) <= std::numeric_limits<double>::epsilon());
}

bool WifiHistoryRecordManager::CheckIsHomeAp()
{
    int64_t totalPassTime = connectedApInfo_.currenttStaticTimePoint - connectedApInfo_.firstConnectedTime;
    if (totalPassTime <= INVALID_TIME_POINT) {
        return false;
    }

    int64_t homeTime = connectedApInfo_.totalUseTimeAtNight + connectedApInfo_.totalUseTimeAtWeekend;
    int dayAvgRestTime = INVALID_TIME_POINT;
    int passDays = totalPassTime / SECOND_OF_ONE_DAY;
    if (passDays != INVALID_TIME_POINT) {
        dayAvgRestTime = homeTime / passDays;
    }

    double restTimeRate = 0.0;
    double homeTimeFloat = static_cast<double>(homeTime);
    double totalUseTimeFloat = static_cast<double>(connectedApInfo_.totalUseTime);
    if (!IsFloatEqual(totalUseTimeFloat, INVALID_TIME_POINT)) {
        restTimeRate = std::round((homeTimeFloat / totalUseTimeFloat) * TO_KEEP_TWO_DECIMAL) / TO_KEEP_TWO_DECIMAL;
    }

    // The conditions for determining homeAp must simultaneously meet:
    // 1.The total usage time needs to exceed 10 hours
    // 2.The duration of night and weekend use should account for more than 50% of the total usage time
    // 3.On average, it takes 30 minutes to use at night and 30 minutes on weekends
    bool ret = false;
    const int tenDay = 10;
    if ((connectedApInfo_.totalUseTime > SECOND_OF_ONE_HOUR * tenDay) && (restTimeRate > HOME_AP_MIN_TIME_RATE) &&
        (dayAvgRestTime >= SECOND_OF_HALF_HOUR)) {
        ret = true;
    }
    WIFI_LOGI("%{public}s, ret=%{public}d, totalUseTime=%{public}lld s, restTimeRate=%{public}.2f, "
        "dayAvgRestTime=%{public}d s, totalUseTimeAtNight=%{public}lld s, totalUseTimeAtWeekend=%{public}lld s, "
        "currenttStaticTimePoint=%{public}lld, firstConnectedTime=%{public}lld",
        __func__, ret, connectedApInfo_.totalUseTime, restTimeRate, dayAvgRestTime,
        connectedApInfo_.totalUseTimeAtNight, connectedApInfo_.totalUseTimeAtWeekend,
        connectedApInfo_.currenttStaticTimePoint, connectedApInfo_.firstConnectedTime);
    return ret;
}

void WifiHistoryRecordManager::HomeApJudgeProcess()
{
    if (CheckIsHomeAp()) {
        if (connectedApInfo_.markedAsHomeApTime == INVALID_TIME_POINT) {
            connectedApInfo_.markedAsHomeApTime = std::time(nullptr);
            WIFI_LOGI("%{public}s, set homeAp flag", __func__);
        }
    } else {
        if (connectedApInfo_.markedAsHomeApTime != INVALID_TIME_POINT) {
            WIFI_LOGI("%{public}s, remove homeAp flag", __func__);
        }
        connectedApInfo_.markedAsHomeApTime = INVALID_TIME_POINT;
    }
    AddOrUpdateApInfoRecord();
}

void WifiHistoryRecordManager::UpdateConnectionTime(bool isNeedNext)
{
    WIFI_LOGI("%{public}s, isNeedNext=%{public}d", __func__, isNeedNext);

    if (!IsAbnormalTimeRecords()) {
        // After caching the last statistics time, refresh the current round of statistics time point
        int lastRecordDayInWeek = connectedApInfo_.currentRecordDayInWeek;
        int64_t lastSecondsOfDay = connectedApInfo_.currentRecordHour * SECOND_OF_ONE_HOUR +
            connectedApInfo_.currentRecordMinute * SECOND_OF_ONE_MINUTE +
            connectedApInfo_.currentRecordSecond;

        std::time_t currentTime = std::time(nullptr);
        WIFI_LOGI("%{public}s start, last=%{public}lld, current=%{public}lld",
            __func__, connectedApInfo_.currenttStaticTimePoint, currentTime);
        UpdateStaticTimePoint(currentTime);
        int64_t currentSecondsOfDay = connectedApInfo_.currentRecordHour * SECOND_OF_ONE_HOUR +
            connectedApInfo_.currentRecordMinute * SECOND_OF_ONE_MINUTE +
            connectedApInfo_.currentRecordSecond;

        // Determine whether the statistical cycle spans 0 o'clock
        if (connectedApInfo_.currentRecordDayInWeek != lastRecordDayInWeek) {
            StaticDurationInNightAndWeekend(lastRecordDayInWeek, lastSecondsOfDay, END_SECONDS_OF_DAY);  // First day
            StaticDurationInNightAndWeekend(connectedApInfo_.currentRecordDayInWeek,
                START_SECOND_OF_DAY, currentSecondsOfDay);  // Second day
        } else {
            StaticDurationInNightAndWeekend(connectedApInfo_.currentRecordDayInWeek,
                lastSecondsOfDay, currentSecondsOfDay);
        }
        HomeApJudgeProcess();
    }
    if (isNeedNext) {
        NextUpdateApInfoTimer();
    }
}

bool WifiHistoryRecordManager::IsAbnormalTimeRecords()
{
    bool ret = false;
    std::time_t currentTime = std::time(nullptr);
    int64_t statisticalTimeInterval = currentTime - connectedApInfo_.currenttStaticTimePoint;
    if (connectedApInfo_.currenttStaticTimePoint == INVALID_TIME_POINT) {  // Maybe just connected
        WIFI_LOGI("%{public}s, currenttStaticTimePoint is zero, skip this round of statistics", __func__);
        UpdateStaticTimePoint(currentTime);
        ret = true;
    } else if (currentTime < connectedApInfo_.firstConnectedTime) {
        WIFI_LOGE("%{public}s, currentTime time is less than firstConnectedTime time, "
            "reset to zero and recalculate, currentTime=%{public}lld s, firstConnectedTime=%{public}lld s",
            __func__, currentTime, connectedApInfo_.firstConnectedTime);
        connectedApInfo_.firstConnectedTime = currentTime;
        connectedApInfo_.currentConnectedTime = currentTime;
        connectedApInfo_.totalUseTime = INVALID_TIME_POINT;
        connectedApInfo_.totalUseTimeAtNight = INVALID_TIME_POINT;
        connectedApInfo_.totalUseTimeAtWeekend = INVALID_TIME_POINT;
        connectedApInfo_.markedAsHomeApTime = INVALID_TIME_POINT;
        UpdateStaticTimePoint(currentTime);
        ret = true;
    } else if (statisticalTimeInterval >= SECOND_OF_ONE_DAY || statisticalTimeInterval < 0) {
        WIFI_LOGE("%{public}s, statisticalTimeInterval is greater than 1 day or less than 0, "
            "last=%{public}lld s, current=%{public}lld s",
            __func__, connectedApInfo_.currenttStaticTimePoint, currentTime);
        UpdateStaticTimePoint(currentTime);
        ret = true;
    }
    return ret;
}

void WifiHistoryRecordManager::UpdateStaticTimePoint(const std::time_t &currentTime)
{
    std::tm* localTime = std::localtime(&currentTime);
    connectedApInfo_.currenttStaticTimePoint = currentTime;
    connectedApInfo_.currentRecordDayInWeek = localTime->tm_wday;
    connectedApInfo_.currentRecordHour = localTime->tm_hour;
    connectedApInfo_.currentRecordMinute = localTime->tm_min;
    connectedApInfo_.currentRecordSecond = localTime->tm_sec;
}

void WifiHistoryRecordManager::StaticDurationInNightAndWeekend(int day, int startTime, int endTime)
{
    // A week starts on Sunday(0) and ends on Saturday(6)
    if (startTime >= endTime || startTime < 0 || endTime > END_SECONDS_OF_DAY ||
        (day > DAY_VALUE_SATURDAY_CALENDAR || day < DAY_VALUE_SUNDAY_CALENDAR)) {
        WIFI_LOGE("static duration invalid, day=%{public}d, startTime=%{public}d, endTime=%{public}d",
            day, startTime, endTime);
        return;
    }
    connectedApInfo_.totalUseTime += endTime - startTime;

    // Statistics weekend time, including nighttime time
    if (day == DAY_VALUE_SUNDAY_CALENDAR || day == DAY_VALUE_SATURDAY_CALENDAR) {
        connectedApInfo_.totalUseTimeAtWeekend += endTime - startTime;
        WIFI_LOGI("add %{public}d seconds to the weekend usage time", endTime - startTime);
        return;
    }

    if (startTime > REST_TIME_END_PAST_SECONDS && endTime < REST_TIME_BEGIN_PAST_SECONDS) {
        WIFI_LOGI("during weekdays and daytime(7:00~20:00), non home time is not counted");
        return;
    }

    // Statistics of nighttime, from 20:00 to 7:00
    int restTime = INVALID_TIME_POINT;
    if (startTime < REST_TIME_END_PAST_SECONDS) {  // StartTime < 7:00
        if (endTime < REST_TIME_END_PAST_SECONDS) {  // EndTime < 7:00
            restTime += endTime - startTime;
        } else if (endTime < REST_TIME_BEGIN_PAST_SECONDS) {  // EndTime < 20:00
            restTime += REST_TIME_END_PAST_SECONDS - startTime;
        } else {  // EndTime > 20:00
            restTime += REST_TIME_END_PAST_SECONDS - startTime;
            restTime += endTime - REST_TIME_BEGIN_PAST_SECONDS;
        }
    } else if (startTime < REST_TIME_BEGIN_PAST_SECONDS &&
        endTime >= REST_TIME_BEGIN_PAST_SECONDS) {  // 7:00 =< startTime < 20:00 && endTime >= 20:00
        restTime += endTime - REST_TIME_BEGIN_PAST_SECONDS;
    } else if (startTime >= REST_TIME_BEGIN_PAST_SECONDS) {  // StartTime >= 20:00 && endTime < 24:00
        restTime += endTime - startTime;
    }
    connectedApInfo_.totalUseTimeAtNight += restTime;
    WIFI_LOGI("add %{public}d seconds to the nighttime usage time", restTime);
}

void WifiHistoryRecordManager::AddOrUpdateApInfoRecord()
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (connectedApInfo_.ssid.empty() || wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("AddOrUpdateApInfoRecord fail, wifiDataBaseUtils_ is nullptr or not connected, ssid=%{public}s",
            SsidAnonymize(connectedApInfo_.ssid).c_str());
        return;
    }
    ConnectedApInfo dbApInfo;
    int queryRet = QueryApInfoRecordByBssid(connectedApInfo_.bssid, dbApInfo);
    if (queryRet == QUERY_NO_RECORD) {
        bool executeRet = wifiDataBaseUtils_->Insert(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
            CreateApInfoBucket(connectedApInfo_));
        WIFI_LOGI("insert ap info, ret=%{public}d", executeRet);
        return;
    } else if (queryRet == QUERY_HAS_RECORD) {
        NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
        predicates.EqualTo(SSID, connectedApInfo_.ssid);
        predicates.EqualTo(BSSID, connectedApInfo_.bssid);
        NativeRdb::ValuesBucket values = CreateApInfoBucket(connectedApInfo_);
        bool executeRet = wifiDataBaseUtils_->Update(values, predicates);
        WIFI_LOGI("update ap info, ret=%{public}d", executeRet);
        return;
    }
    WIFI_LOGE("%{public}s fail", __func__);
}

void WifiHistoryRecordManager::RemoveApInfoRecord(const std::string &bssid)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("RemoveApInfoRecord fail, wifiDataBaseUtils_ is nullptr");
        return;
    }
    NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
    predicates.EqualTo(BSSID, bssid);
    int deleteRowCount = 0;
    bool executeRet = wifiDataBaseUtils_->Delete(deleteRowCount, predicates);
    WIFI_LOGI("remove ap info, executeRet=%{public}d, deleteRowCount=%{public}d, bssid=%{public}s",
        executeRet, deleteRowCount, MacAnonymize(bssid).c_str());
}

int WifiHistoryRecordManager::QueryApInfoRecordByBssid(const std::string &bssid, ConnectedApInfo &dbApInfo)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
    predicates.EqualTo(BSSID, bssid);
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, query fail", __func__);
        return QUERY_FAILED;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, query empty", __func__);
        return QUERY_NO_RECORD;
    }
    int32_t columnCnt = 0;
    resultSet->GetInt(columnCnt++, dbApInfo.networkId);
    resultSet->GetString(columnCnt++, dbApInfo.ssid);
    resultSet->GetString(columnCnt++, dbApInfo.bssid);
    resultSet->GetString(columnCnt++, dbApInfo.keyMgmt);
    resultSet->GetLong(columnCnt++, dbApInfo.firstConnectedTime);
    resultSet->GetLong(columnCnt++, dbApInfo.currentConnectedTime);
    resultSet->GetLong(columnCnt++, dbApInfo.totalUseTime);
    resultSet->GetLong(columnCnt++, dbApInfo.totalUseTimeAtNight);
    resultSet->GetLong(columnCnt++, dbApInfo.totalUseTimeAtWeekend);
    resultSet->GetLong(columnCnt++, dbApInfo.markedAsHomeApTime);
    resultSet->Close();
    WIFI_LOGI("%{public}s success, ssid=%{public}s, bssid=%{public}s",
        __func__, SsidAnonymize(dbApInfo.ssid).c_str(), MacAnonymize(dbApInfo.bssid).c_str());
    return QUERY_HAS_RECORD;
}

int WifiHistoryRecordManager::QueryAllApInfoRecord(std::vector<ConnectedApInfo> &dbApInfoVector)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("QueryAllApInfoRecord fail, wifiDataBaseUtils_ is nullptr");
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, all query fail", __func__);
        return QUERY_FAILED;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, query empty", __func__);
        return QUERY_NO_RECORD;
    }
    do {
        int32_t columnCnt = 0;
        ConnectedApInfo dbApInfo;
        resultSet->GetInt(columnCnt++, dbApInfo.networkId);
        resultSet->GetString(columnCnt++, dbApInfo.ssid);
        resultSet->GetString(columnCnt++, dbApInfo.bssid);
        resultSet->GetString(columnCnt++, dbApInfo.keyMgmt);
        resultSet->GetLong(columnCnt++, dbApInfo.firstConnectedTime);
        resultSet->GetLong(columnCnt++, dbApInfo.currentConnectedTime);
        resultSet->GetLong(columnCnt++, dbApInfo.totalUseTime);
        resultSet->GetLong(columnCnt++, dbApInfo.totalUseTimeAtNight);
        resultSet->GetLong(columnCnt++, dbApInfo.totalUseTimeAtWeekend);
        resultSet->GetLong(columnCnt++, dbApInfo.markedAsHomeApTime);
        dbApInfoVector.push_back(dbApInfo);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    WIFI_LOGI("%{public}s success, count=%{public}u", __func__, dbApInfoVector.size());
    return QUERY_HAS_RECORD;
}

NativeRdb::ValuesBucket WifiHistoryRecordManager::CreateApInfoBucket(const ConnectedApInfo &apInfo)
{
    NativeRdb::ValuesBucket apInfoBucket;
    apInfoBucket.PutInt(NETWORK_ID, apInfo.networkId);
    apInfoBucket.PutString(SSID, apInfo.ssid);
    apInfoBucket.PutString(BSSID, apInfo.bssid);
    apInfoBucket.PutString(KEY_MGMT, apInfo.keyMgmt);
    apInfoBucket.PutLong(FIRST_CONNECTED_TIME, apInfo.firstConnectedTime);
    apInfoBucket.PutLong(CURRENT_CONNECTED_TIME, apInfo.currentConnectedTime);
    apInfoBucket.PutLong(TOTAL_USE_TIME, apInfo.totalUseTime);
    apInfoBucket.PutLong(TOTAL_USE_TIME_AT_NIGHT, apInfo.totalUseTimeAtNight);
    apInfoBucket.PutLong(TOTAL_USE_TIME_AT_WEEKEND, apInfo.totalUseTimeAtWeekend);
    apInfoBucket.PutLong(MARKED_AS_HOME_AP_TIME, apInfo.markedAsHomeApTime);
    return apInfoBucket;
}

bool WifiHistoryRecordManager::IsHomeAp(const std::string &bssid)
{
    if (connectedApInfo_.bssid.empty() || bssid.empty() || connectedApInfo_.bssid != bssid) {
        return false;
    }
    return connectedApInfo_.markedAsHomeApTime != INVALID_TIME_POINT;
}

bool WifiHistoryRecordManager::IsHomeRouter(const std::string &portalUrl)
{
    if (portalUrl.empty()) {
        WIFI_LOGE("%{public}s, portalUrl is null", __func__);
        return false;
    }
    std::map<std::string, std::vector<PackageInfo>> packageInfoMap;
    if (WifiSettings::GetInstance().GetPackageInfoMap(packageInfoMap) != 0 || packageInfoMap.empty()) {
        WIFI_LOGE("%{public}s, GetPackageInfoMap failed", __func__);
        return false;
    }
    std::vector<PackageInfo> homeRouterList = packageInfoMap["HOME_ROUTER_REDIRECTED_URL"];
    std::regex reg(portalUrl);
    for (const PackageInfo &info : homeRouterList) {
        if (std::regex_search(info.name, reg)) {
            WIFI_LOGI("home router");
            return true;
        }
    }
    WIFI_LOGI("not home router");
    return false;
}

void WifiHistoryRecordManager::ClearConnectedApInfo()
{
    connectedApInfo_.networkId = INVALID_NETWORK_ID;
    connectedApInfo_.ssid = "";
    connectedApInfo_.bssid = "";
    connectedApInfo_.keyMgmt = "";
    connectedApInfo_.firstConnectedTime = INVALID_TIME_POINT;
    connectedApInfo_.currentConnectedTime = INVALID_TIME_POINT;
    connectedApInfo_.totalUseTime = INVALID_TIME_POINT;
    connectedApInfo_.totalUseTimeAtNight = INVALID_TIME_POINT;
    connectedApInfo_.totalUseTimeAtWeekend = INVALID_TIME_POINT;
    connectedApInfo_.markedAsHomeApTime = INVALID_TIME_POINT;

    connectedApInfo_.currenttStaticTimePoint = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordDayInWeek = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordHour = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordMinute = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordSecond = INVALID_TIME_POINT;
}

void WifiHistoryRecordManager::DelectAllApInfo()
{
    std::vector<ConnectedApInfo> dbApInfoVector;
    int ret = QueryAllApInfoRecord(dbApInfoVector);
    if (ret != QUERY_HAS_RECORD) {
        WIFI_LOGE("%{public}s, no ap record", __func__);
        return;
    }
    WIFI_LOGE("%{public}s, size=%{public}u", __func__, dbApInfoVector.size());
    for (const ConnectedApInfo &item : dbApInfoVector) {
        RemoveApInfoRecord(item.bssid);
    }
}

void WifiHistoryRecordManager::DelectApInfo(const std::string &ssid, const std::string &bssid)
{
    WIFI_LOGI("%{public}s, ssid=%{public}s, bssid=%{public}s",
        __func__, SsidAnonymize(ssid).c_str(), MacAnonymize(bssid).c_str());
    RemoveApInfoRecord(bssid);
}
}
}