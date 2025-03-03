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
#include "wifi_common_util.h"

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
constexpr const char* UPDATE_CONNECT_TIME_RECORD_INTERVAL = "const.wifi.update_connect_time_record_interval";
constexpr const char* UPDATE_CONNECT_TIME_RECORD_INTERVAL_DEFAULT = "1800000";  // 30min
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
constexpr int INVALID_TIME_RECORD_INTERVAL = 0;
constexpr int TEN_DAY = 10;

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
    if (instId != INSTID_WLAN0) {
        return;
    }
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
    if (info.bssid.empty() || info.bssid == connectedApInfo_.bssid_) {
        return;
    }
    WIFI_LOGI("deal connected, ssid=%{public}s, bssid=%{public}s", SsidAnonymize(info.ssid).c_str(),
        MacAnonymize(info.bssid).c_str());
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
    ConnectedApInfo dbApInfo;
    int queryRet = QueryApInfoRecordByBssid(connectedApInfo_.bssid_, dbApInfo);
    if (queryRet == QUERY_NO_RECORD) {  // First connect
        connectedApInfo_.keyMgmt_ = config.keyMgmt;
        connectedApInfo_.firstConnectedTime_ = currentTime;
    } else {
        connectedApInfo_.keyMgmt_ = dbApInfo.keyMgmt_;
        connectedApInfo_.firstConnectedTime_ = dbApInfo.firstConnectedTime_;
        connectedApInfo_.totalUseTime_ = dbApInfo.totalUseTime_;
        connectedApInfo_.totalUseTimeAtNight_ = dbApInfo.totalUseTimeAtNight_;
        connectedApInfo_.totalUseTimeAtWeekend_ = dbApInfo.totalUseTimeAtWeekend_;
        connectedApInfo_.markedAsHomeApTime_ = dbApInfo.markedAsHomeApTime_;
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
    if ((connectedApInfo_.totalUseTime_ > SECOND_OF_ONE_HOUR * TEN_DAY) && (restTimeRate > HOME_AP_MIN_TIME_RATE) &&
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
    if (localTime == nullptr || currentTime <= INVALID_TIME_POINT) {
        WIFI_LOGE("%{public}s fail", __func__);
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
    ConnectedApInfo dbApInfo;
    int queryRet = QueryApInfoRecordByBssid(connectedApInfo_.bssid_, dbApInfo);
    if (queryRet == QUERY_NO_RECORD) {
        bool executeRet = wifiDataBaseUtils_->Insert(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
            CreateApInfoBucket(connectedApInfo_));
        WIFI_LOGI("insert ap info, ret=%{public}d", executeRet);
        return;
    } else if (queryRet == QUERY_HAS_RECORD) {
        NativeRdb::AbsRdbPredicates predicates(AP_CONNECTION_DURATION_INFO_TABLE_NAME);
        predicates.EqualTo(SSID, connectedApInfo_.ssid_);
        predicates.EqualTo(BSSID, connectedApInfo_.bssid_);
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
        WIFI_LOGE("%{public}s, query fail", __func__);
        return QUERY_FAILED;
    }
    int32_t resultSetNum = resultSet->GoToFirstRow();
    if (resultSetNum != NativeRdb::E_OK) {
        resultSet->Close();
        WIFI_LOGI("%{public}s, query empty", __func__);
        return QUERY_NO_RECORD;
    }
    int32_t columnCnt = 0;
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
    resultSet->Close();
    WIFI_LOGI("%{public}s success, ssid=%{public}s, bssid=%{public}s",
        __func__, SsidAnonymize(dbApInfo.ssid_).c_str(), MacAnonymize(dbApInfo.bssid_).c_str());
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
        dbApInfoVector.push_back(dbApInfo);
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
    std::vector<ConnectedApInfo> dbApInfoVector;
    int ret = QueryAllApInfoRecord(dbApInfoVector);
    if (ret != QUERY_HAS_RECORD) {
        WIFI_LOGE("%{public}s, no ap record", __func__);
        return;
    }
    WIFI_LOGE("%{public}s", __func__);
    for (const ConnectedApInfo &item : dbApInfoVector) {
        RemoveApInfoRecord(item.bssid_);
    }
}

void WifiHistoryRecordManager::DeleteApInfo(const std::string &ssid, const std::string &bssid)
{
    WIFI_LOGI("%{public}s, ssid=%{public}s, bssid=%{public}s",
        __func__, SsidAnonymize(ssid).c_str(), MacAnonymize(bssid).c_str());
    RemoveApInfoRecord(bssid);
}
}
}