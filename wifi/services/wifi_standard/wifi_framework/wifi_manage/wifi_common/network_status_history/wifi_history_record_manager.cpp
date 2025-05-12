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
#include "wifi_logger.h"
#include "wifi_timer.h"
#include "wifi_settings.h"
#include "wifi_internal_msg.h"
#include "define.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiHistoryRecordManager");
const std::string WIFI_HISTORY_RECORD_MANAGER_CLASS_NAME = "WifiHistoryRecordManager";
const std::string PERIODIC_UPDATE_AP_INFO_THREAD = "PeriodicUpdateApInfoThread";
const std::string UPDATE_AP_INFO_TASK = "UpdateApInfoTask";
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
constexpr const char* UPDATE_CONNECT_TIME_RECORD_INTERVAL = "const.wifi.update_connect_time_record_interval";
constexpr const char* UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT = "1800000";  // 30min
constexpr int64_t SECOND_OF_ONE_DAY = 60 * 60 * 24;
constexpr int64_t SECOND_OF_HALF_HOUR = 30 * 60;
constexpr int64_t SECOND_OF_ONE_HOUR = 60 * 60;
constexpr int64_t SECOND_OF_TEN_HOUR = 60 * 60 * 10;
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
constexpr int INVALID_TIME_RECORD_INTERVAL = 0;
constexpr int ENTERPRISE_AP_NUM = 20;
constexpr int DELETE_AP_NUM = 5;
constexpr int MAX_NUM_OF_SAVED_AP = 500;

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
        std::string intervalDefaultStr(UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT);
        return CheckDataLegal(intervalDefaultStr);
    }
    std::string preValueStr(preValue);
    int intervalValue = CheckDataLegal(preValueStr);
    if (intervalValue == INVALID_TIME_RECORD_INTERVAL) {
        std::string intervalDefaultStr(UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT);
        return CheckDataLegal(intervalDefaultStr);
    }
    WIFI_LOGI("get UPDATE_CONNECT_TIME_RECORD_INTERVAL is %{public}d", intervalValue);
    return intervalValue;
}

StaServiceCallback WifiHistoryRecordManager::GetStaCallback() const
{
    return staCallback_;
}

void WifiHistoryRecordManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
if (instId != INSTID_WLAN0 || info.networkId == INVALID_NETWORK_ID || info.bssid.empty() ||
        (state != OperateResState::DISCONNECT_DISCONNECTED && state != OperateResState::CONNECT_AP_CONNECTED)) {
        return;
    }
    WIFI_LOGI("HandleConnectionChange, state=%{public}d(24:disconn, 17:conn), networkId=%{public}d, "
        "ssid=%{public}s, bssid=%{public}s", static_cast<int>(state), info.networkId,
        SsidAnonymize(info.ssid).c_str(), MacAnonymize(info.bssid).c_str());
    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(info.networkId, config, instId);
    if (CheckIsEnterpriseAp(config)) {
        RecordToEapApTable(config);
        WIFI_LOGI("enterprise AP, not record, ssid=%{public}s, keyMgmt=%{public}s, state=%{public}d",
            SsidAnonymize(info.ssid).c_str(), config.keyMgmt.c_str(), static_cast<int>(state));
        return;
    }
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        StopUpdateApInfoTimer();

        // 1.If the saved network does not exist, maybe disconnect caused by deletion, do not update and save.
        // 2.The system checks whether networkId_ is a valid value to ensure that the current state is connected
        // and the connection time can be updated.
        if (ret == GET_DEVICE_CONFIG_SUCCESS && connectedApInfo_.networkId_ != INVALID_NETWORK_ID) {
            UpdateConnectionTime(false);
        }
        ClearConnectedApInfo();
    } else if (state == OperateResState::CONNECT_AP_CONNECTED) {
        HandleWifiConnectedMsg(info, config);
    }
}

void WifiHistoryRecordManager::HandleWifiConnectedMsg(const WifiLinkedInfo &info, const WifiDeviceConfig &config)
{
    if (info.bssid == connectedApInfo_.bssid_) {
        WIFI_LOGI("already connected, bssid=%{public}s", MacAnonymize(connectedApInfo_.bssid_).c_str());
        return;
    }
    if (info.networkId == connectedApInfo_.networkId_) {
        WIFI_LOGI("roam, networkId=%{public}d, last bssid=%{public}s", info.networkId,
            MacAnonymize(connectedApInfo_.bssid_).c_str());
        StopUpdateApInfoTimer();
        UpdateConnectionTime(false);
    }
    ClearConnectedApInfo();
    int64_t currentTime = GetCurrentTimeSeconds();
    connectedApInfo_.networkId_ = info.networkId;
    connectedApInfo_.ssid_ = info.ssid;
    connectedApInfo_.bssid_ = info.bssid;
    connectedApInfo_.currentConnectedTime_ = currentTime;
    connectedApInfo_.keyMgmt_ = config.keyMgmt;
    std::vector<ConnectedApInfo> dbApInfoVector;
    int queryRet = QueryApInfoRecordByParam({{BSSID, config.bssid}}, dbApInfoVector);
    if (queryRet == QUERY_NO_RECORD) {  // First connect
        connectedApInfo_.firstConnectedTime_ = currentTime;
    } else if (queryRet == QUERY_HAS_RECORD) {
        ConnectedApInfo dbApInfo = dbApInfoVector.front();
        connectedApInfo_.keyMgmt_ = dbApInfo.keyMgmt_;
        connectedApInfo_.firstConnectedTime_ = dbApInfo.firstConnectedTime_;
        connectedApInfo_.totalUseTime_ = dbApInfo.totalUseTime_;
        connectedApInfo_.totalUseTimeAtNight_ = dbApInfo.totalUseTimeAtNight_;
        connectedApInfo_.totalUseTimeAtWeekend_ = dbApInfo.totalUseTimeAtWeekend_;
        connectedApInfo_.markedAsHomeApTime_ = dbApInfo.markedAsHomeApTime_;
    } else {
        WIFI_LOGE("ssid=%{public}s connected, but query failed, not counted", SsidAnonymize(info.ssid).c_str());
        ClearConnectedApInfo();
        return;
    }
    UpdateConnectionTime(true);
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
    int64_t totalPassTime = connectedApInfo_.currenttStaticTimePoint_ - connectedApInfo_.firstConnectedTime_;
    if (totalPassTime <= INVALID_TIME_POINT) {
        return false;
    }

    int64_t homeTime = connectedApInfo_.totalUseTimeAtNight_ + connectedApInfo_.totalUseTimeAtWeekend_;
    int dayAvgRestTime = INVALID_TIME_POINT;
    int passDays = totalPassTime / SECOND_OF_ONE_DAY;
    if (passDays != INVALID_TIME_POINT) {
        dayAvgRestTime = homeTime / passDays;
    }

    double restTimeRate = 0.0;
    double homeTimeFloat = static_cast<double>(homeTime);
    double totalUseTimeFloat = static_cast<double>(connectedApInfo_.totalUseTime_);
    if (!IsFloatEqual(totalUseTimeFloat, INVALID_TIME_POINT)) {
        restTimeRate = std::round((homeTimeFloat / totalUseTimeFloat) * TO_KEEP_TWO_DECIMAL) / TO_KEEP_TWO_DECIMAL;
    }

    // The conditions for determining homeAp must simultaneously meet:
    // 1.The total usage time needs to exceed 10 hours
    // 2.The duration of night and weekend use should account for more than 50% of the total usage time
    // 3.On average, it takes 30 minutes to use at night and 30 minutes on weekends
    bool ret = false;
    if ((connectedApInfo_.totalUseTime_ > SECOND_OF_TEN_HOUR) && (restTimeRate > HOME_AP_MIN_TIME_RATE) &&
        (dayAvgRestTime >= SECOND_OF_HALF_HOUR)) {
        ret = true;
    }
    WIFI_LOGI("%{public}s, ret=%{public}d, totalUseTime=%{public}" PRId64"s, restTimeRate=%{public}.2f, "
        "dayAvgRestTime=%{public}d s, totalUseTimeAtNight=%{public}" PRId64"s, "
        "totalUseTimeAtWeekend=%{public}" PRId64"s, currenttStaticTimePoint=%{public}" PRId64", "
        "firstConnectedTime=%{public}" PRId64,
        __func__, ret, connectedApInfo_.totalUseTime_, restTimeRate, dayAvgRestTime,
        connectedApInfo_.totalUseTimeAtNight_, connectedApInfo_.totalUseTimeAtWeekend_,
        connectedApInfo_.currenttStaticTimePoint_, connectedApInfo_.firstConnectedTime_);
    return ret;
}

void WifiHistoryRecordManager::HomeApJudgeProcess()
{
    if (CheckIsHomeAp()) {
        if (connectedApInfo_.markedAsHomeApTime_ == INVALID_TIME_POINT) {
            connectedApInfo_.markedAsHomeApTime_ = GetCurrentTimeSeconds();
            WIFI_LOGI("%{public}s, set homeAp flag", __func__);
        }
    } else {
        if (connectedApInfo_.markedAsHomeApTime_ != INVALID_TIME_POINT) {
            WIFI_LOGI("%{public}s, remove homeAp flag", __func__);
        }
        connectedApInfo_.markedAsHomeApTime_ = INVALID_TIME_POINT;
    }
    AddOrUpdateApInfoRecord();
}

void WifiHistoryRecordManager::UpdateConnectionTime(bool isNeedNext)
{
    WIFI_LOGI("%{public}s, isNeedNext=%{public}d", __func__, isNeedNext);

    if (!IsAbnormalTimeRecords()) {
        // After caching the last statistics time, refresh the current round of statistics time point
        int lastRecordDayInWeek = connectedApInfo_.currentRecordDayInWeek_;
        int64_t lastSecondsOfDay = connectedApInfo_.currentRecordHour_ * SECOND_OF_ONE_HOUR +
            connectedApInfo_.currentRecordMinute_ * SECOND_OF_ONE_MINUTE +
            connectedApInfo_.currentRecordSecond_;

        int64_t currentTime = GetCurrentTimeSeconds();
        WIFI_LOGI("%{public}s start, last=%{public}" PRId64", current=%{public}" PRId64,
            __func__, connectedApInfo_.currenttStaticTimePoint_, currentTime);
        UpdateStaticTimePoint(currentTime);
        int64_t currentSecondsOfDay = connectedApInfo_.currentRecordHour_ * SECOND_OF_ONE_HOUR +
            connectedApInfo_.currentRecordMinute_ * SECOND_OF_ONE_MINUTE +
            connectedApInfo_.currentRecordSecond_;

        // Determine whether the statistical cycle spans 0 o'clock
        if (connectedApInfo_.currentRecordDayInWeek_ != lastRecordDayInWeek) {
            StaticDurationInNightAndWeekend(lastRecordDayInWeek, lastSecondsOfDay, END_SECONDS_OF_DAY);  // First day
            StaticDurationInNightAndWeekend(connectedApInfo_.currentRecordDayInWeek_,
                START_SECOND_OF_DAY, currentSecondsOfDay);  // Second day
        } else {
            StaticDurationInNightAndWeekend(connectedApInfo_.currentRecordDayInWeek_,
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
    int64_t currentTime = GetCurrentTimeSeconds();
    int64_t statisticalTimeInterval = currentTime - connectedApInfo_.currenttStaticTimePoint_;
    if (connectedApInfo_.currenttStaticTimePoint_ == INVALID_TIME_POINT) {  // Maybe just connected
        WIFI_LOGI("%{public}s, currenttStaticTimePoint is zero, skip this round of statistics", __func__);
        UpdateStaticTimePoint(currentTime);
        ret = true;
    } else if (currentTime < connectedApInfo_.firstConnectedTime_) {
        WIFI_LOGE("%{public}s, currentTime time is less than firstConnectedTime time, "
            "reset to zero and recalculate, currentTime=%{public}" PRId64"s, firstConnectedTime=%{public}" PRId64"s",
            __func__, currentTime, connectedApInfo_.firstConnectedTime_);
        connectedApInfo_.firstConnectedTime_ = currentTime;
        connectedApInfo_.currentConnectedTime_ = currentTime;
        connectedApInfo_.totalUseTime_ = INVALID_TIME_POINT;
        connectedApInfo_.totalUseTimeAtNight_ = INVALID_TIME_POINT;
        connectedApInfo_.totalUseTimeAtWeekend_ = INVALID_TIME_POINT;
        connectedApInfo_.markedAsHomeApTime_ = INVALID_TIME_POINT;
        UpdateStaticTimePoint(currentTime);
        ret = true;
    } else if (statisticalTimeInterval >= SECOND_OF_ONE_DAY || statisticalTimeInterval < 0) {
        WIFI_LOGE("%{public}s, statisticalTimeInterval is greater than 1 day or less than 0, "
            "last=%{public}" PRId64"s, current=%{public}" PRId64"s",
            __func__, connectedApInfo_.currenttStaticTimePoint_, currentTime);
        UpdateStaticTimePoint(currentTime);
        ret = true;
    }
    return ret;
}

void WifiHistoryRecordManager::UpdateStaticTimePoint(const int64_t &currentTimeInt)
{
    std::time_t currentTime;
    if (currentTimeInt < INVALID_TIME_POINT ||
        currentTimeInt > static_cast<int64_t>(std::numeric_limits<std::time_t>::max())) {
        currentTime = GetCurrentTimeSeconds();
    } else {
        currentTime = static_cast<std::time_t>(currentTimeInt);
    }
    std::tm* localTime = std::localtime(&currentTime);
    if (localTime == nullptr) {
        WIFI_LOGE("%{public}s, localTime is nullptr", __func__);
        return;
    }
    connectedApInfo_.currenttStaticTimePoint_ = currentTime;
    connectedApInfo_.currentRecordDayInWeek_ = localTime->tm_wday;
    connectedApInfo_.currentRecordHour_ = localTime->tm_hour;
    connectedApInfo_.currentRecordMinute_ = localTime->tm_min;
    connectedApInfo_.currentRecordSecond_ = localTime->tm_sec;
}

void WifiHistoryRecordManager::StaticDurationInNightAndWeekend(int day, int64_t startTime, int64_t endTime)
{
    // A week starts on Sunday(0) and ends on Saturday(6)
    if (startTime >= endTime || startTime < 0 || endTime > END_SECONDS_OF_DAY ||
        (day > DAY_VALUE_SATURDAY_CALENDAR || day < DAY_VALUE_SUNDAY_CALENDAR)) {
        WIFI_LOGE("static duration invalid, day=%{public}d, startTime=%{public}" PRId64", endTime=%{public}" PRId64,
            day, startTime, endTime);
        return;
    }
    connectedApInfo_.totalUseTime_ += endTime - startTime;

    // Statistics weekend time, including nighttime time
    if (day == DAY_VALUE_SUNDAY_CALENDAR || day == DAY_VALUE_SATURDAY_CALENDAR) {
        connectedApInfo_.totalUseTimeAtWeekend_ += endTime - startTime;
        WIFI_LOGI("add %{public}" PRId64" seconds to the weekend usage time", endTime - startTime);
        return;
    }

    if (startTime > REST_TIME_END_PAST_SECONDS && endTime < REST_TIME_BEGIN_PAST_SECONDS) {
        WIFI_LOGI("during weekdays and daytime(7:00~20:00), non home time is not counted");
        return;
    }

    // Statistics of nighttime, from 20:00 to 7:00
    int64_t restTime = INVALID_TIME_POINT;
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
    connectedApInfo_.totalUseTimeAtNight_ += restTime;
    WIFI_LOGI("add %{public}" PRId64" seconds to the nighttime usage time", restTime);
}

void WifiHistoryRecordManager::AddOrUpdateApInfoRecord()
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (connectedApInfo_.ssid_.empty() || wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("AddOrUpdateApInfoRecord fail, wifiDataBaseUtils_ is nullptr or not connected, ssid=%{public}s",
            SsidAnonymize(connectedApInfo_.ssid_).c_str());
        return;
    }
    std::vector<ConnectedApInfo> dbConnectedApInfo;
    int queryRet = QueryApInfoRecordByParam({{BSSID, connectedApInfo_.bssid_}}, dbConnectedApInfo)
    if (queryRet == QUERY_NO_RECORD) {
        HandleOldHistoryRecord();
        bool executeRet = wifiDataBaseUtils_->Insert(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
            CreateApInfoBucket(connectedApInfo_));
        WIFI_LOGI("insert ap info, ret=%{public}d", executeRet);
        return;
    } else if (queryRet == QUERY_HAS_RECORD) {
        NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
        predicates.EqualTo(BSSID, connectedApInfo_.bssid_);
        NativeRdb::ValuesBucket values = CreateApInfoBucket(connectedApInfo_);
        bool executeRet = wifiDataBaseUtils_->Update(values, predicates);
        WIFI_LOGI("update ap info, ret=%{public}d", executeRet);
        return;
    }
    WIFI_LOGE("%{public}s fail", __func__);
}

nt WifiHistoryRecordManager::RemoveApInfoRecordByParam(const std::string tableName,
    const std::map<std::string, std::string> &deleteParms)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("RemoveApInfoRecord(%{public}s) fail, wifiDataBaseUtils_ is nullptr", tableName.c_str());
        return 0;
    }
    NativeRdb::AbsRdbPredicates predicates(tableName);
    if (!deleteParms.empty()) {

        auto it = deleteParms.begin();
        auto end = deleteParms.end();
        while (it != end) {
            auto nextIt = std::next(it);
            predicates.EqualTo(it->first, it->second);
            if (nextIt != end) {
                predicates.And();
            }
            ++it;
        }
    } 
    int deleteRowCount = 0;
    wifiDataBaseUtils_->Delete(deleteRowCount, predicates);
    return deleteRowCount;
}

int WifiHistoryRecordManager::QueryApInfoRecordByParam(const std::map<std::string, std::string> &queryParms,
    std::vector<ConnectedApInfo> &dbApInfoVector)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
    if (!queryParms.empty()) {
        auto it = queryParms.begin();
        auto end = queryParms.end();
        while (it != end) {
            auto nextIt = std::next(it);
            predicates.EqualTo(it->first, it->second);
            if (nextIt != end) {
                predicates.And();
            }
            ++it;
        }
    }
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
        WIFI_LOGE("%{public}s, all query fail", __func__);
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
        resultSet->GetInt(columnCnt++, dbApInfo.networkId_);
        resultSet->GetString(columnCnt++, dbApInfo.ssid_);
        resultSet->GetString(columnCnt++, dbApInfo.bssid_);
        resultSet->GetString(columnCnt++, dbApInfo.keyMgmt_);
        resultSet->GetLong(columnCnt++, dbApInfo.firstConnectedTime_);
        resultSet->GetLong(columnCnt++, dbApInfo.currentConnectedTime_);
        resultSet->GetLong(columnCnt++, dbApInfo.totalUseTime_);
        resultSet->GetLong(columnCnt++, dbApInfo.totalUseTimeAtNight_);
        resultSet->GetLong(columnCnt++, dbApInfo.totalUseTimeAtWeekend_);
        resultSet->GetLong(columnCnt++, dbApInfo.markedAsHomeApTime_);
        dbApInfoVector.emplace_back(dbApInfo);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    return QUERY_HAS_RECORD;
}

NativeRdb::ValuesBucket WifiHistoryRecordManager::CreateApInfoBucket(const ConnectedApInfo &apInfo)
{
    NativeRdb::ValuesBucket apInfoBucket;
    apInfoBucket.PutInt(NETWORK_ID, apInfo.networkId_);
    apInfoBucket.PutString(SSID, apInfo.ssid_);
    apInfoBucket.PutString(BSSID, apInfo.bssid_);
    apInfoBucket.PutString(KEY_MGMT, apInfo.keyMgmt_);
    apInfoBucket.PutLong(FIRST_CONNECTED_TIME, apInfo.firstConnectedTime_);
    apInfoBucket.PutLong(CURRENT_CONNECTED_TIME, apInfo.currentConnectedTime_);
    apInfoBucket.PutLong(TOTAL_USE_TIME, apInfo.totalUseTime_);
    apInfoBucket.PutLong(TOTAL_USE_TIME_AT_NIGHT, apInfo.totalUseTimeAtNight_);
    apInfoBucket.PutLong(TOTAL_USE_TIME_AT_WEEKEND, apInfo.totalUseTimeAtWeekend_);
    apInfoBucket.PutLong(MARKED_AS_HOME_AP_TIME, apInfo.markedAsHomeApTime_);
    return apInfoBucket;
}

bool WifiHistoryRecordManager::AddEnterpriseApRecord(const EnterpriseApInfo &enterpriseApInfo)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return false;
    }
 
    std::vector<EnterpriseApInfo> dbEnterpriseApInfo;
    int queryRet = QueryEnterpriseApRecordByParam(
        {{SSID, enterpriseApInfo.ssid_}, {KEY_MGMT, enterpriseApInfo.keyMgmt_}}, dbEnterpriseApInfo);
    if (queryRet == QUERY_NO_RECORD) {
        bool executeRet = wifiDataBaseUtils_->Insert(ENTERPRISE_AP_INFO_TABLE_NAME,
            CreateEnterpriseApInfoBucket(enterpriseApInfo));
        WIFI_LOGI("%{public}s, ret=%{public}d", __func__, executeRet);
        return executeRet;
    } else if (queryRet == QUERY_HAS_RECORD) {
        WIFI_LOGI("%{public}s, already exists", __func__);
        return true;
    }
    WIFI_LOGE("%{public}s fail", __func__);
    return false;
}
 
int WifiHistoryRecordManager::QueryEnterpriseApRecordByParam(const std::map<std::string, std::string> &queryParms,
    std::vector<EnterpriseApInfo> &dbEnterpriseApInfoVector)
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
        return QUERY_FAILED;
    }
    NativeRdb::AbsRdbPredicates predicates(ENTERPRISE_AP_INFO_TABLE_NAME);
    if (!queryParms.empty()) {
        auto it = queryParms.begin();
        auto end = queryParms.end();
        while (it != end) {
            auto nextIt = std::next(it);
            predicates.EqualTo(it->first, it->second);
            if (nextIt != end) {
                predicates.And();
            }
            ++it;
        }
    }
    std::vector<std::string> queryAllColumn;
    auto resultSet = wifiDataBaseUtils_->Query(predicates, queryAllColumn);
    if (resultSet == nullptr) {
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
        EnterpriseApInfo dbEnterpriseApInfo;
        resultSet->GetString(columnCnt++, dbEnterpriseApInfo.ssid_);
        resultSet->GetString(columnCnt++, dbEnterpriseApInfo.keyMgmt_);
        dbEnterpriseApInfoVector.emplace_back(dbEnterpriseApInfo);
    } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    resultSet->Close();
    return QUERY_HAS_RECORD;
}
 
NativeRdb::ValuesBucket WifiHistoryRecordManager::CreateEnterpriseApInfoBucket(
    const EnterpriseApInfo &enterpriseApInfo)
{
    NativeRdb::ValuesBucket enterpriseApInfoBucket;
    enterpriseApInfoBucket.PutString(SSID, enterpriseApInfo.ssid_);
    enterpriseApInfoBucket.PutString(KEY_MGMT, enterpriseApInfo.keyMgmt_);
    return enterpriseApInfoBucket;
}
 
bool WifiHistoryRecordManager::CheckIsEnterpriseAp(const WifiDeviceConfig &config)
{
    bool isEnterpriseSecurityType = (config.keyMgmt == KEY_MGMT_EAP) ||

        (config.keyMgmt == KEY_MGMT_SUITE_B_192) || (config.keyMgmt == KEY_MGMT_WAPI_CERT);
    if (isEnterpriseSecurityType && (config.wifiEapConfig.eap != EAP_METHOD_NONE)) {
        WIFI_LOGI("%{public}s, EAP ap", __func__);
        return true;
    }
 
    std::vector<EnterpriseApInfo> dbEnterpriseApInfo;
    int queryEnterpriseApRet = QueryEnterpriseApRecordByParam({{SSID, config.ssid}, {KEY_MGMT, config.keyMgmt}},
        dbEnterpriseApInfo);
    if (queryEnterpriseApRet == QUERY_HAS_RECORD || queryEnterpriseApRet == QUERY_FAILED) {
        WIFI_LOGE("%{public}s, query enterprise ap has_record/fail, ret=%{public}d", __func__, queryEnterpriseApRet);
        return true;
    }
 
    std::vector<ConnectedApInfo> dbApInfoVector;
    int queryApRet = QueryApInfoRecordByParam({{SSID, config.ssid}, {KEY_MGMT, config.keyMgmt}}, dbApInfoVector);
    if (queryApRet == QUERY_NO_RECORD) {
        return false;
    } else if (queryApRet == QUERY_FAILED) {
        WIFI_LOGE("%{public}s, query ap info fail", __func__);
        return true;
    } else if (queryApRet == QUERY_HAS_RECORD && dbApInfoVector.size() < ENTERPRISE_AP_NUM) {
        WIFI_LOGI("%{public}s, size=%{public}zu, quantity less than 20", __func__, dbApInfoVector.size());
        return false;
    }
 
    // If more than 20 hotspots with the same SSID and encryption mode exist,
    // the hotspots are considered as enterprise networks. The encryption mode is not limited to EAP.
    return true;
}
 
void WifiHistoryRecordManager::RecordToEapApTable(const WifiDeviceConfig &config)
{
    bool addRet = AddEnterpriseApRecord(EnterpriseApInfo(config.ssid, config.keyMgmt));

    if (!addRet) {
        return;
    }
    int count = RemoveApInfoRecordByParam(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
            {{SSID, config.ssid}, {KEY_MGMT, config.keyMgmt}});
    WIFI_LOGI("%{public}s, quantity more than 20, record ssid=%{public}s as EAP AP, delete count=%{public}d",
        __func__, SsidAnonymize(config.ssid).c_str(), count);
}

bool WifiHistoryRecordManager::IsHomeAp(const std::string &bssid)
{
    if (connectedApInfo_.bssid_.empty() || bssid.empty() || connectedApInfo_.bssid_ != bssid) {
        return false;
    }
    return connectedApInfo_.markedAsHomeApTime_ != INVALID_TIME_POINT;
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

    // Obtain the portal redirection address from the XML file
    std::vector<PackageInfo> homeRouterList = packageInfoMap["HOME_ROUTER_REDIRECTED_URL"];
    for (const PackageInfo &info : homeRouterList) {
        if (portalUrl.find(info.name) != std::string::npos) {
            WIFI_LOGI("home router");
            return true;
        }
    }
    WIFI_LOGI("not home router");
    return false;
}

void WifiHistoryRecordManager::ClearConnectedApInfo()
{
    connectedApInfo_.networkId_ = INVALID_NETWORK_ID;
    connectedApInfo_.ssid_ = "";
    connectedApInfo_.bssid_ = "";
    connectedApInfo_.keyMgmt_ = "";
    connectedApInfo_.firstConnectedTime_ = INVALID_TIME_POINT;
    connectedApInfo_.currentConnectedTime_ = INVALID_TIME_POINT;
    connectedApInfo_.totalUseTime_ = INVALID_TIME_POINT;
    connectedApInfo_.totalUseTimeAtNight_ = INVALID_TIME_POINT;
    connectedApInfo_.totalUseTimeAtWeekend_ = INVALID_TIME_POINT;
    connectedApInfo_.markedAsHomeApTime_ = INVALID_TIME_POINT;

    connectedApInfo_.currenttStaticTimePoint_ = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordDayInWeek_ = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordHour_ = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordMinute_ = INVALID_TIME_POINT;
    connectedApInfo_.currentRecordSecond_ = INVALID_TIME_POINT;
}

void WifiHistoryRecordManager::DeleteAllApInfo()
{
    std::lock_guard<std::recursive_mutex> lock(updateApInfoMutex_);
    if (wifiDataBaseUtils_ == nullptr) {
        WIFI_LOGE("%{public}s fail, wifiDataBaseUtils_ is nullptr", __func__);
 
        return;
    }
    std::string deleteAllApSql = "delete from ";
    deleteAllApSql.append(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
    bool deleteApRet = wifiDataBaseUtils_->ExecuteSql(deleteAllApSql);
 
    std::string deleteAllEapApSql = "delete from ";
    deleteAllEapApSql.append(ENTERPRISE_AP_INFO_TABLE_NAME);
    bool deleteEnterpriseApRet = wifiDataBaseUtils_->ExecuteSql(deleteAllEapApSql);
 
    WIFI_LOGI("%{public}s, deleteApRet=%{public}d, deleteEnterpriseApRet=%{public}d",
        __func__, deleteApRet, deleteEnterpriseApRet);
}

void WifiHistoryRecordManager::DeleteApInfo(const std::string &ssid, const std::string &keyMgmt)
{
    int count = RemoveApInfoRecordByParam(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
        {{SSID, ssid}, {KEY_MGMT, keyMgmt}});
    int eapCount = RemoveApInfoRecordByParam(ENTERPRISE_AP_INFO_TABLE_NAME,
        {{SSID, ssid}, {KEY_MGMT, keyMgmt}});
    WIFI_LOGI("%{public}s, ssid=%{public}s, keyMgmt=%{public}s, count=%{public}d, eapCount=%{public}d",
        __func__, SsidAnonymize(ssid).c_str(), keyMgmt.c_str(), count, eapCount);
}
 
void WifiHistoryRecordManager::HandleOldHistoryRecord()
{
    std::map<std::string, std::string> queryParms;
    std::vector<ConnectedApInfo> dbApInfoVector;
    int ret = QueryApInfoRecordByParam(queryParms, dbApInfoVector);
    if (ret != QUERY_HAS_RECORD || dbApInfoVector.empty() || dbApInfoVector.size() < MAX_NUM_OF_SAVED_AP) {
        return;
    }
    std::sort(dbApInfoVector.begin(), dbApInfoVector.end(), [](ConnectedApInfo ap1, ConnectedApInfo ap2) {
        return ap1.currentConnectedTime_ < ap2.currentConnectedTime_;  // asc
    });
    std::vector<ConnectedApInfo> deleteApInfoVector(dbApInfoVector.begin(), dbApInfoVector.begin() + DELETE_AP_NUM);
 
    std::string ssidList = "";
    std::for_each(deleteApInfoVector.begin(), deleteApInfoVector.end(), [&](const ConnectedApInfo &info) {
        ssidList += SsidAnonymize(info.ssid_) + "  ";
    });
 
    for (const ConnectedApInfo &apInfo : deleteApInfoVector) {
        RemoveApInfoRecordByParam(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
            {{SSID, apInfo.ssid_}, {KEY_MGMT, apInfo.keyMgmt_}});
    }
    WIFI_LOGI("delete old ap record, ssid=%{public}s", ssidList.c_str());
}
}
}
}