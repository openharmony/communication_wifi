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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "wifi_history_record_manager.h"
#include "wifi_logger.h"
#include "rdb_helper.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_config_center.h"
#include "wifi_global_func.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiHistoryRecordManagerTest");
constexpr long INVALID_TIME_POINT = 0;
constexpr int QUERY_FAILED = 0;
constexpr int QUERY_NO_RECORD = 1;
constexpr int QUERY_HAS_RECORD = 2;
constexpr int AP_NUM = 40;
const std::string WIFI_HISTORY_RECORD_MANAGER_CLASS_NAME = "WifiHistoryRecordManager";
const std::string NETWORK_ID = "networkId";
const std::string SSID = "ssid";
const std::string BSSID = "bssid";
const std::string KEY_MGMT = "keyMgmt";
static std::string g_errLog;
void WifiHistoryRecordManagerCallback(const LogType type, const LogLevel level,
                                      const unsigned int domain, const char *tag,
                                      const char *msg)
{
    g_errLog = msg;
}

class WifiHistoryRecordManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        LOG_SetCallback(WifiHistoryRecordManagerCallback);
        wifiDataBaseUtils_ = WifiRdbManager::GetRdbManger(RdbType::WIFI_HISTORY_RECORD);
    }
    virtual void TearDown()
    {
        WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
        WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    }
    std::time_t GetCurrentTimeStampSeconds()
    {
        auto now = std::chrono::system_clock::now();
        auto nowMs = std::chrono::time_point_cast<std::chrono::seconds>(now);
        return nowMs.time_since_epoch().count();
    }
    using ConnectedApInfo = WifiHistoryRecordManager::ConnectedApInfo;
    std::shared_ptr<WifiRdbManager> wifiDataBaseUtils_ = nullptr;
};

HWTEST_F(WifiHistoryRecordManagerTest, InitTest, TestSize.Level1)
{
    WIFI_LOGI("InitTest enter");
    WifiHistoryRecordManager::GetInstance().Init();
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_ != nullptr);
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().wifiDataBaseUtils_ != nullptr);
}

HWTEST_F(WifiHistoryRecordManagerTest, GetUpdateConnectTimeRecordIntervalTest, TestSize.Level1)
{
    WIFI_LOGI("GetUpdateConnectTimeRecordIntervalTest enter");
    int interval = WifiHistoryRecordManager::GetInstance().GetUpdateConnectTimeRecordInterval();
    EXPECT_TRUE(interval != 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, GetStaCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("GetStaCallbackTest enter");
    StaServiceCallback callback = WifiHistoryRecordManager::GetInstance().GetStaCallback();
    EXPECT_TRUE(
        callback.callbackModuleName == WIFI_HISTORY_RECORD_MANAGER_CLASS_NAME);
}

HWTEST_F(WifiHistoryRecordManagerTest, DealStaConnChanged1Test, TestSize.Level1)
{
    WIFI_LOGI("DealStaConnChanged1Test enter");

    // test instId != 0
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    OperateResState state = OperateResState::DISCONNECT_DISCONNECTED;
    WifiLinkedInfo info;
    int instId = 1;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state, info, instId);

    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    // test disconnected
    OperateResState state2 = OperateResState::DISCONNECT_DISCONNECTED;
    WifiLinkedInfo info2;
    info2.networkId = 11;
    info2.ssid = "testSsid1";
    info2.bssid = "11:22:33:44:55:66";
    int instId2 = 0;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = "c3:aa:33:ff:55:66";
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state2, info2, instId2);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_.empty());
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_.empty());
}

HWTEST_F(WifiHistoryRecordManagerTest, DealStaConnChanged2Test1, TestSize.Level1)
{
    WIFI_LOGI("DealStaConnChanged2Test enter");

    // test bssid is same
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    std::string sameBssid = "3a:22:9f:44:ff:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = sameBssid;

    OperateResState state3 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info3;
    info3.networkId = 29;
    info3.ssid = "testSsid2";
    info3.bssid = sameBssid;
    int instId3 = 0;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state3, info3, instId3);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiHistoryRecordManagerTest, DealStaConnChanged2Test2, TestSize.Level1)
{
    // test roam
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    int roamNetworkId = 592;
    OperateResState state4 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info4;
    info4.networkId = roamNetworkId;
    info4.ssid = "testSsid3";
    info4.bssid = "11:22:33:44:55:bb";
    int instId4 = 0;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = roamNetworkId;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state4, info4, instId4);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}
HWTEST_F(WifiHistoryRecordManagerTest, DealStaConnChanged2Test3, TestSize.Level1)
{
    // test no record
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    OperateResState state5 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info5;
    info5.networkId = 44;
    info5.ssid = "testSsid4";
    info5.bssid = "f1:22:99:44:55:cc";
    int instId5 = 0;
    WifiDeviceConfig config5;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state5, info5, instId5);
    long firstConnectedTime5 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(firstConnectedTime5 != 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, DealStaConnChanged3Test, TestSize.Level1)
{
    WIFI_LOGI("DealStaConnChanged3Test enter");

    // test record, Save connection data to the database in advance.
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int recordNetworkId = 210;
    std::string recordSsid = "DealStaConnChangedTestRecordSsid";
    std::string recordBssid = "33:22:6c:44:55:cc";
    std::string recordKeyMgmt = "SAE";
    long recordFirstConnectedTime = 1736225372;
    long recordTotalUseTime = 12564;
    long recordTotalUseTimeAtNight = 152;
    long recordTotalUseTimeAtWeekend = 101;
    long recordMarkedAsHomeApTime = 1736225374;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = recordNetworkId;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = recordSsid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = recordBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = recordKeyMgmt;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_ = recordFirstConnectedTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime_ = recordTotalUseTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_ = recordTotalUseTimeAtNight;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_ = recordTotalUseTimeAtWeekend;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = recordMarkedAsHomeApTime;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    OperateResState state6 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info6;
    info6.networkId = recordNetworkId;
    info6.ssid = recordSsid;
    info6.bssid = recordBssid;
    int instId6 = 0;
    WifiDeviceConfig config6;
    config6.networkId = recordNetworkId;
    config6.ssid = recordSsid;
    config6.bssid = recordBssid;
    config6.keyMgmt = recordKeyMgmt;
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(config6), Return(0)));
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state6, info6, instId6);
    std::string testSsid = WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_;
    std::string testBssid = WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_;
    std::string testKeyMgmt = WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_;
    long testFirstConnectedTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_;
    long testTotalUseTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime_;
    long testTotalUseTimeAtNight = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long testTotalUseTimeAtWeekend = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    long testMarkedAsHomeApTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    EXPECT_TRUE(recordSsid == testSsid);
    EXPECT_TRUE(recordBssid == testBssid);
    EXPECT_TRUE(recordFirstConnectedTime == testFirstConnectedTime);
    EXPECT_TRUE(recordTotalUseTimeAtNight == testTotalUseTimeAtNight);
    EXPECT_TRUE(recordTotalUseTimeAtWeekend == testTotalUseTimeAtWeekend);
}

HWTEST_F(WifiHistoryRecordManagerTest, NextUpdateApInfoTimerTest, TestSize.Level1)
{
    WIFI_LOGI("NextUpdateApInfoTimerTest enter");
    WifiHistoryRecordManager::GetInstance().Init();
    WifiHistoryRecordManager::GetInstance().NextUpdateApInfoTimer();
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_ != nullptr);
}

HWTEST_F(WifiHistoryRecordManagerTest, StopUpdateApInfoTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StopUpdateApInfoTimerTest enter");
    WifiHistoryRecordManager::GetInstance().Init();
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_ != nullptr);
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
}

HWTEST_F(WifiHistoryRecordManagerTest, CheckIsHomeApTest, TestSize.Level1)
{
    WIFI_LOGI("CheckIsHomeApTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_ = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentConnectedTime_ = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime_ = 39000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_ = 36000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_ = 0;

    bool ret = WifiHistoryRecordManager::GetInstance().CheckIsHomeAp();
    EXPECT_TRUE(ret);
}

HWTEST_F(WifiHistoryRecordManagerTest, HomeApJudgeProcessTest, TestSize.Level1)
{
    WIFI_LOGI("HomeApJudgeProcessTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_ = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentConnectedTime_ = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime_ = 39000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_ = 36000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_ = 0;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    // already homeAp
    long recordMarkedAsHomeApTime1 = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = recordMarkedAsHomeApTime1;
    WifiHistoryRecordManager::GetInstance().HomeApJudgeProcess();
    long testMarkedAsHomeApTime1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_;
    EXPECT_TRUE(recordMarkedAsHomeApTime1 == testMarkedAsHomeApTime1);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    // set homeAp flag
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = INVALID_TIME_POINT;
    WifiHistoryRecordManager::GetInstance().HomeApJudgeProcess();
    long testMarkedAsHomeApTime2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_;
    EXPECT_TRUE(testMarkedAsHomeApTime2 != INVALID_TIME_POINT);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    // not homeAp
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_ = 0;
    WifiHistoryRecordManager::GetInstance().HomeApJudgeProcess();
    long testMarkedAsHomeApTime3 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_;
    EXPECT_TRUE(testMarkedAsHomeApTime3 == INVALID_TIME_POINT);
}

HWTEST_F(WifiHistoryRecordManagerTest, UpdateConnectionTimeTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateConnectionTimeTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    // The statistical time does not meet the requirements
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = 1736232414;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek_ = 2;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour_ = 14;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute_ = 45;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond_ = 54;
    WifiHistoryRecordManager::GetInstance().UpdateConnectionTime(true);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    long testTotalUseTimeAtNight1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    EXPECT_TRUE(testTotalUseTimeAtNight1 == 0);

    // Count time across 0 o'clock
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::time_t currentTime = GetCurrentTimeStampSeconds() - 84600;  // - 23:30
    std::tm* localTime = std::localtime(&currentTime);
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = currentTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek_ = localTime->tm_wday;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour_ = localTime->tm_hour;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute_ = localTime->tm_min;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond_ = localTime->tm_sec;
    WifiHistoryRecordManager::GetInstance().UpdateConnectionTime(false);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    long testTotalUseTimeAtNight2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;

    // The statistical time does not cross 0 o'clock
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::time_t currentTime3 = GetCurrentTimeStampSeconds() - 3600;  // Reduce by one hour
    std::tm* localTime3 = std::localtime(&currentTime3);
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = currentTime3;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek_ = localTime3->tm_wday;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour_ = localTime3->tm_hour;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute_ = localTime3->tm_min;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond_ = localTime3->tm_sec;
    WifiHistoryRecordManager::GetInstance().UpdateConnectionTime(true);
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();

    long testTotalUseTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime_;
    EXPECT_TRUE(testTotalUseTime != 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, IsAbnormalTimeRecordsTest, TestSize.Level1)
{
    WIFI_LOGI("IsAbnormalTimeRecordsTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = INVALID_TIME_POINT;
    bool ret1 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(ret1);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_ = 32503689365;  // 3000-01-01
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = GetCurrentTimeStampSeconds();
    bool ret2 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(ret2);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_ = 315559083;  // 1980-01-01
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_ = 315559083;  // 1980-01-01
    bool ret3 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(ret3);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_
        = GetCurrentTimeStampSeconds() - 5000;  // 5000:test time
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_
        = GetCurrentTimeStampSeconds() - 2000;  // 2000:test time
    bool ret4 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_FALSE(ret4);
}

HWTEST_F(WifiHistoryRecordManagerTest, UpdateStaticTimePointTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateStaticTimePointTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    // test valid time
    int64_t validTime = 315559083;  // 1980-01-01
    WifiHistoryRecordManager::GetInstance().UpdateStaticTimePoint(validTime);
    int64_t current1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_;
    int64_t dayIntWeek1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek_;
    int64_t hour1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour_;
    int64_t minute1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute_;
    int64_t second1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond_ ;

    std::tm* localTime = std::localtime(&validTime);
    int dayIntWeek2 = localTime->tm_wday;
    int hour2 = localTime->tm_hour;
    int minute2 = localTime->tm_min;
    int second2 = localTime->tm_sec;

    EXPECT_TRUE(current1 == validTime);
    EXPECT_TRUE(dayIntWeek1 == dayIntWeek2);
    EXPECT_TRUE(hour1 == hour2);
    EXPECT_TRUE(minute1 == minute2);
    EXPECT_TRUE(second1 == second2);

    // test invalid time
    int64_t invalidTime = -10;
    WifiHistoryRecordManager::GetInstance().UpdateStaticTimePoint(invalidTime);
    int64_t current2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint_;
    EXPECT_TRUE(current2 > 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, StaticDurationInNightAndWeekend1Test, TestSize.Level1)
{
    WIFI_LOGI("StaticDurationInNightAndWeekend1Test enter");

    // weekend
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day = 6;
    int64_t startTime = 192;
    int64_t endTime = 235;
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day, startTime, endTime);
    long nightTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    EXPECT_TRUE(nightTime == 0);
    EXPECT_TRUE(weekendTime != 0);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day1 = 0;
    int64_t startTime1 = 531;
    int64_t endTime1 = 5547;
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day1, startTime1, endTime1);
    long nightTime1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    EXPECT_TRUE(nightTime1 == 0);
    EXPECT_TRUE(weekendTime1 != 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, StaticDurationInNightAndWeekend2Test, TestSize.Level1)
{
    WIFI_LOGI("StaticDurationInNightAndWeekend2Test enter");

    // workday
    // startTime < 7:00, endTime < 7:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day2 = 1;  // Monday
    int64_t startTime2 = 18000;  // 5:00
    int64_t endTime2 = 21600;  // 6:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day2, startTime2, endTime2);
    long nightTime2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(nightTime2 != 0);
    EXPECT_TRUE(weekendTime2 == 0);

    // startTime < 7:00, 7:00 <= endTime < 20:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day3 = 2;  // Tuesday
    int64_t startTime3 = 18000;  // 5:00
    int64_t endTime3 = 36000;  // 10:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day3, startTime3, endTime3);
    long nightTime3 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime3 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(nightTime3 != 0);
    EXPECT_TRUE(weekendTime3 == 0);

    // startTime < 7:00, 24:00 > endTime > 20:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day4 = 3;  // Wednesday
    int64_t startTime4 = 18000;  // 5:00
    int64_t endTime4 = 79200;  // 22:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day4, startTime4, endTime4);
    long nightTime4 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime4 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(nightTime4 != 0);
    EXPECT_TRUE(weekendTime4 == 0);

    // 7:00 =< startTime < 20:00, endTime >= 20:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day5 = 4;  // Thursday
    int64_t startTime5 = 36000;  // 10:00
    int64_t endTime5 = 79200;  // 22:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day5, startTime5, endTime5);
    long nightTime5 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime5 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(nightTime5 != 0);
    EXPECT_TRUE(weekendTime5 == 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, StaticDurationInNightAndWeekend3Test, TestSize.Level1)
{
    WIFI_LOGI("StaticDurationInNightAndWeekend3Test enter");

    // startTime >= 20:00, 24:00 > endTime
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day6 = 5;  // Friday
    int64_t startTime6 = 75600;  // 21:00
    int64_t endTime6 = 79200;  // 22:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day6, startTime6, endTime6);
    long nightTime6 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime6 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(nightTime6 != 0);
    EXPECT_TRUE(weekendTime6 == 0);

    // startTime > 7:00, 20:00 > endTime
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day7 = 1;  // Monday
    int64_t startTime7 = 36000;  // 10:00
    int64_t endTime7 = 50400;  // 14:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day7, startTime7, endTime7);
    long nightTime7 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_;
    long weekendTime7 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_;
    WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_->RemoveAsyncTask("UpdateApInfoTask");
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(nightTime7 == 0);
    EXPECT_TRUE(weekendTime7 == 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, AddOrUpdateApInfoRecordTest, TestSize.Level1)
{
    WIFI_LOGI("AddOrUpdateApInfoRecordTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testSsid = "AddOrUpdateApInfoRecordTest";
    std::string testKeyMgmt = "SAE";
    std::string testBssid = "11:22:ff:3a:11:43";

    // insert
    long markedAsHomeApTime = 1736225374;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 8;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = testSsid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = testKeyMgmt;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime_ = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentConnectedTime_ = 1736225373;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime_ = 100;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight_ = 100;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend_ = 100;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = markedAsHomeApTime;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();

    std::vector<ConnectedApInfo> dbApInfoVector1;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector1);
    if (dbApInfoVector1.size() >= 1) {
        ConnectedApInfo dbApInfo1 = dbApInfoVector1.front();
        EXPECT_TRUE(ret == QUERY_HAS_RECORD);
        EXPECT_TRUE(dbApInfo1.bssid_ == testBssid);
        EXPECT_TRUE(dbApInfo1.markedAsHomeApTime_ == markedAsHomeApTime);
    }

    // update
    long markedAsHomeApTime2 = 1736225899;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = markedAsHomeApTime2;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();

    std::vector<ConnectedApInfo> dbApInfoVector2;
    int ret2 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector2);
    if (dbApInfoVector2.size() >= 1) {
        ConnectedApInfo dbApInfo2 = dbApInfoVector2.front();
        EXPECT_TRUE(ret2 == QUERY_HAS_RECORD);
        EXPECT_TRUE(dbApInfo2.bssid_ == testBssid);
        EXPECT_TRUE(dbApInfo2.markedAsHomeApTime_ == markedAsHomeApTime2);
    }
}

HWTEST_F(WifiHistoryRecordManagerTest, AddEnterpriseApRecordTest, TestSize.Level1)
{
    WIFI_LOGI("RemoveApInfoRecordTest enter");
    WIFI_LOGI("AddEnterpriseApRecordTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testSsid = "AddEnterpriseApRecordTest";
    std::string testKeyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().
        RemoveApInfoRecordByParam(ENTERPRISE_AP_INFO_TABLE_NAME, {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}});

    // test insert
    WifiHistoryRecordManager::EnterpriseApInfo enterpriseApInfo(testSsid, testKeyMgmt);
    bool ret = WifiHistoryRecordManager::GetInstance().AddEnterpriseApRecord(enterpriseApInfo);
    EXPECT_TRUE(ret);

    // test update
    ret = WifiHistoryRecordManager::GetInstance().AddEnterpriseApRecord(enterpriseApInfo);
    EXPECT_TRUE(ret);
}

HWTEST_F(WifiHistoryRecordManagerTest, RemoveApInfoRecordByParamTest, TestSize.Level1)
{
    WIFI_LOGI("RemoveApInfoRecordByParamTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    std::string testSsid = "RemoveApInfoRecordByParamTest";
    std::string testBssid = "dd:aa:55:55:0c:ff";
    std::string testKeyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 66;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = testSsid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = testKeyMgmt;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    std::vector<ConnectedApInfo> dbApInfoVector;
    int ret1 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector);
    EXPECT_TRUE(ret1 == QUERY_HAS_RECORD);

    WifiHistoryRecordManager::GetInstance().RemoveApInfoRecordByParam(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}});

    std::vector<ConnectedApInfo> dbApInfoVector2;
    int ret2 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector2);
    EXPECT_TRUE(ret2 != QUERY_HAS_RECORD);
}

HWTEST_F(WifiHistoryRecordManagerTest, QueryEnterpriseApRecordByParamTest, TestSize.Level1)
{
    WIFI_LOGI("QueryEnterpriseApRecordByParamTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testSsid = "QueryEnterpriseApRecordByParamTest";
    std::string testKeyMgmt = "SAE";

    WifiHistoryRecordManager::EnterpriseApInfo enterpriseApInfo(testSsid, testKeyMgmt);
    bool ret = WifiHistoryRecordManager::GetInstance().AddEnterpriseApRecord(enterpriseApInfo);
    EXPECT_TRUE(ret);

    WifiHistoryRecordManager::GetInstance().
        RemoveApInfoRecordByParam(ENTERPRISE_AP_INFO_TABLE_NAME, {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}});

    std::vector<WifiHistoryRecordManager::EnterpriseApInfo> dbEnterpriseApInfo;
    int queryEnterpriseApRet = WifiHistoryRecordManager::GetInstance().QueryEnterpriseApRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbEnterpriseApInfo);
    EXPECT_TRUE(queryEnterpriseApRet == QUERY_NO_RECORD);
    EXPECT_TRUE(dbEnterpriseApInfo.size() == 0);
}

HWTEST_F(WifiHistoryRecordManagerTest, QueryApInfoRecordByParamTest, TestSize.Level1)
{
    WIFI_LOGI("QueryApInfoRecordByParamTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    std::string testSsid = "QueryApInfoRecordByParamTest";
    std::string testBssid = "44:aa:12:55:0c:ff";
    std::string testKeyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 90;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = testSsid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = testKeyMgmt;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    std::vector<ConnectedApInfo> dbApInfoVector;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);

    std::string testSsid2 = "QueryApInfoRecordByParamTest2";
    std::string testKeyMgmt2 = "SAE";
    std::vector<ConnectedApInfo> dbApInfoVector2;
    int ret2 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid2}, {KEY_MGMT, testKeyMgmt2}}, dbApInfoVector2);
    EXPECT_TRUE(ret2 != QUERY_HAS_RECORD);
}

HWTEST_F(WifiHistoryRecordManagerTest, CreateApInfoBucketTest, TestSize.Level1)
{
    WIFI_LOGI("CreateApInfoBucketTest enter");
    ConnectedApInfo apInfo;
    apInfo.networkId_ = 12;  // 12: test networkId
    NativeRdb::ValuesBucket ret = WifiHistoryRecordManager::GetInstance().CreateApInfoBucket(apInfo);
    NativeRdb::ValueObject valueObject;
    int networkId = INVALID_NETWORK_ID;
    if (ret.GetObject("networkId", valueObject)) {
        valueObject.GetInt(networkId);
        EXPECT_TRUE(apInfo.networkId_ = networkId);
    }
}

HWTEST_F(WifiHistoryRecordManagerTest, CreateEnterpriseApInfoBucketTest, TestSize.Level1)
{
    WIFI_LOGI("CreateEnterpriseApInfoBucketTest enter");
    WifiHistoryRecordManager::EnterpriseApInfo apInfo;
    apInfo.ssid_ = "CreateEnterpriseApInfoBucketTest";
    NativeRdb::ValuesBucket ret = WifiHistoryRecordManager::GetInstance().CreateEnterpriseApInfoBucket(apInfo);
    NativeRdb::ValueObject valueObject;
    std::string ssid = "";
    if (ret.GetObject("ssid", valueObject)) {
        valueObject.GetString(ssid);
        EXPECT_TRUE(apInfo.ssid_ == ssid);
    }
}

HWTEST_F(WifiHistoryRecordManagerTest, CheckIsEnterpriseApTest, TestSize.Level1)
{
    WIFI_LOGI("CheckIsEnterpriseApTest enter");

    // test enterpriseAp has record
    std::string testSsid1 = "CheckIsEnterpriseApTest1";
    std::string testKeyMgmt1 = "SAE";
    WifiHistoryRecordManager::EnterpriseApInfo enterpriseApInfo(testSsid1, testKeyMgmt1);
    bool ret1 = WifiHistoryRecordManager::GetInstance().AddEnterpriseApRecord(enterpriseApInfo);
    WifiDeviceConfig config1;
    config1.ssid = testSsid1;
    config1.keyMgmt = testKeyMgmt1;
    bool ret11 = WifiHistoryRecordManager::GetInstance().CheckAndRecordEnterpriseAp(config1);
    EXPECT_TRUE(ret11);

    // test EAP AP
    std::string testSsid2 = "CheckIsEnterpriseApTest2";
    std::string testKeyMgmt2 = "WPA-EAP";
    WifiDeviceConfig config2;
    config2.ssid = testSsid2;
    config2.keyMgmt = testKeyMgmt2;
    bool ret2 = WifiHistoryRecordManager::GetInstance().CheckAndRecordEnterpriseAp(config2);
    EXPECT_TRUE(ret2);

    // test no apInfo record
    std::string testSsid3 = "CheckIsEnterpriseApTest3";
    std::string testKeyMgmt3 = "SAE";
    WifiDeviceConfig config3;
    config3.ssid = testSsid3;
    config3.keyMgmt = testKeyMgmt3;
    bool ret3 = WifiHistoryRecordManager::GetInstance().CheckAndRecordEnterpriseAp(config3);
    EXPECT_FALSE(ret3);

    // test has apInfo record, but the number is less than 20
    std::string testSsid4 = "CheckIsEnterpriseApTest4";
    std::string testBssid4 = "11:22:33:44:55:6f";
    std::string testKeyMgmt4 = "SAE";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 8;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = testSsid4;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid4;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = testKeyMgmt4;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    WifiDeviceConfig config4;
    config4.ssid = testSsid4;
    config4.keyMgmt = testKeyMgmt4;
    bool ret4 = WifiHistoryRecordManager::GetInstance().CheckAndRecordEnterpriseAp(config4);
    EXPECT_FALSE(ret4);
    
    // test has apInfo record and more than 20
    std::string testSsid5 = "CheckIsEnterpriseApTest5";
    std::string testKeyMgmt5 = "SAE";
    for (int i = 10; i <= AP_NUM; i++) {
        WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = i;
        WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = testSsid5;
        WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = "1a:44:5c:3d:21:" + std::to_string(i);
        WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = testKeyMgmt5;
        WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    }
    WifiDeviceConfig config5;
    config5.ssid = testSsid5;
    config5.keyMgmt = testKeyMgmt5;
    bool ret5 = WifiHistoryRecordManager::GetInstance().CheckAndRecordEnterpriseAp(config5);
    EXPECT_TRUE(ret5);
}

HWTEST_F(WifiHistoryRecordManagerTest, IsHomeApTest, TestSize.Level1)
{
    WIFI_LOGI("IsHomeApTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid1 = "11:3a:ff:22:ac:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = GetCurrentTimeStampSeconds();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid1;
    bool ret1 = WifiHistoryRecordManager::GetInstance().IsHomeAp(testBssid1);
    EXPECT_TRUE(ret1);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid2 = "11:3a:ff:22:ac:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = GetCurrentTimeStampSeconds();
    bool ret2 = WifiHistoryRecordManager::GetInstance().IsHomeAp(testBssid2);
    EXPECT_FALSE(ret2);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid3 = "11:3a:ff:22:ac:66";
    std::string testBssid4 = "31:5b:ff:55:ac:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid4;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = GetCurrentTimeStampSeconds();
    bool ret3 = WifiHistoryRecordManager::GetInstance().IsHomeAp(testBssid3);
    EXPECT_FALSE(ret3);

    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime_ = GetCurrentTimeStampSeconds();
    bool ret4 = WifiHistoryRecordManager::GetInstance().IsHomeAp("");
    EXPECT_FALSE(ret4);
}

HWTEST_F(WifiHistoryRecordManagerTest, IsHomeRouterTest, TestSize.Level1)
{
    WIFI_LOGI("IsHomeRouterTest enter");
    std::string portalUrl = "";
    bool ret = WifiHistoryRecordManager::GetInstance().IsHomeRouter(portalUrl);
    EXPECT_FALSE(ret);

    portalUrl = "test";
    ret = WifiHistoryRecordManager::GetInstance().IsHomeRouter(portalUrl);
    EXPECT_FALSE(ret);

    portalUrl = "test3546fsds<](!,={+";
    ret = WifiHistoryRecordManager::GetInstance().IsHomeRouter(portalUrl);
    EXPECT_FALSE(ret);
}

HWTEST_F(WifiHistoryRecordManagerTest, ClearConnectedApInfoTest, TestSize.Level1)
{
    WIFI_LOGI("ClearConnectedApInfoTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiHistoryRecordManagerTest, DeleteAllApInfoTest, TestSize.Level1)
{
    WIFI_LOGI("DeleteAllApInfoTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    std::string testBssid1 = "66:3b:12:6a:0c:ff";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 90;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = "DeleteAllApInfoTest1";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid1;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = "SAE";
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();

    std::vector<ConnectedApInfo> dbApInfoVector;
    std::map<std::string, std::string> queryParms;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(queryParms, dbApInfoVector);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);

    std::string testBssid2 = "3b:99:12:6a:2a:ff";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 906;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = "DeleteAllApInfoTest2";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid2;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = "SAE";
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    std::vector<ConnectedApInfo> dbApInfoVector2;
    std::map<std::string, std::string> queryParms2;
    ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(queryParms2, dbApInfoVector2);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);

    WifiHistoryRecordManager::GetInstance().DeleteAllApInfo();

    std::vector<ConnectedApInfo> dbApInfoVector3;
    std::map<std::string, std::string> queryParms3;
    ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(queryParms3, dbApInfoVector3);
    EXPECT_TRUE(ret == QUERY_NO_RECORD);
}

HWTEST_F(WifiHistoryRecordManagerTest, DeleteApInfoTest, TestSize.Level1)
{
    WIFI_LOGI("DeleteApInfoTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();

    std::string testSsid = "DeleteApInfoTest";
    std::string testBssid = "23:bb:9c:55:aa:cc";
    std::string testKeyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId_ = 33;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid_ = testSsid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid_ = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt_ = testKeyMgmt;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();

    std::vector<ConnectedApInfo> dbApInfoVector1;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector1);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);

    WifiHistoryRecordManager::GetInstance().DeleteApInfo(testSsid, testKeyMgmt);

    std::vector<ConnectedApInfo> dbApInfoVector2;
    ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(
        {{SSID, testSsid}, {KEY_MGMT, testKeyMgmt}}, dbApInfoVector2);
    EXPECT_TRUE(ret != QUERY_HAS_RECORD);
}

HWTEST_F(WifiHistoryRecordManagerTest, HandleOldHistoryRecordTest, TestSize.Level1)
{
    WIFI_LOGI("HandleOldHistoryRecordTest enter");
    WifiHistoryRecordManager::GetInstance().DeleteAllApInfo();

    // Preset 505 hotspot information
    EXPECT_FALSE(wifiDataBaseUtils_, nullptr);
    int64_t firstConnectedTimeTest = 1736225372;
    int64_t currentConnectedTimeTest = 1736225374;
    int ap_num = 505;
    for (int i = 1; i <= ap_num; i++) {
        ConnectedApInfo info;
        info.networkId_ = i;
        info.ssid_ = "HandleOldHistoryRecordTest_";
        info.ssid_.append(std::to_string(i));
        info.keyMgmt_ = "SAE";
        info.bssid_ = "13:1b:9c:55:aa:cc";
        info.firstConnectedTime_ = firstConnectedTimeTest;
        info.currentConnectedTime_ = currentConnectedTimeTest + i;
        info.totalUseTime_ = 1730;  // 1730: total use time
        info.totalUseTimeAtNight_ = 100;  // 100: total use time at night
        info.totalUseTimeAtWeekend_ = 32;  // 32: total use time at weekend
        info.markedAsHomeApTime_ = 0;    // 0: not home ap
        bool executeRet = wifiDataBaseUtils_->Insert(AP_CONNECTION_DURATION_INFO_TABLE_NAME,
            WifiHistoryRecordManager::GetInstance().CreateApInfoBucket(info));
    }

    // Deleting historical hotspot information
    WifiHistoryRecordManager::GetInstance().HandleOldHistoryRecord();

    std::map<std::string, std::string> queryParms;
    std::vector<ConnectedApInfo> dbApInfoVector;
    WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByParam(queryParms, dbApInfoVector);
    EXPECT_TRUE(dbApInfoVector.size() <= 500);
    for (ConnectedApInfo itemInfo : dbApInfoVector) {
        if (itemInfo.currentConnectedTime_ <= currentConnectedTimeTest + 5) {
            EXPECT_TRUE(false);  // Top 5 Hotspots for the Longest Time, need delete
        }
    }

    WifiHistoryRecordManager::GetInstance().DeleteAllApInfo();
}
}
}