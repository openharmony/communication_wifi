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
#include <wifi_history_record_manager.h>
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
 
class WifiHistoryRecordManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
 
    static constexpr long INVALID_TIME_POINT = 0;
    static constexpr int QUERY_FAILED = 0;
    static constexpr int QUERY_NO_RECORD = 1;
    static constexpr int QUERY_HAS_RECORD = 2;
    const std::string WIFI_HISTORY_RECORD_MANAGER_CLASS_NAME = "WifiHistoryRecordManager";
    using ConnectedApInfo = WifiHistoryRecordManager::ConnectedApInfo;
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
 
HWTEST_F(WifiHistoryRecordManagerTest, DealStaConnChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealStaConnChangedTest enter");
 
    // test instId != 0
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    OperateResState state = OperateResState::DISCONNECT_DISCONNECTED;
    WifiLinkedInfo info;
    int instId = 1;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state, info, instId);
 
    // test disconnected
    OperateResState state2 = OperateResState::DISCONNECT_DISCONNECTED;
    WifiLinkedInfo info2;
    info2.networkId = 11;
    info2.ssid = "testSsid1";
    info2.bssid = "11:22:33:44:55:66";
    int instId2 = 0;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = "c3:aa:33:ff:55:66";
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state2, info2, instId2);
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid.empty());
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid.empty());
 
    // test bssid is same
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    std::string sameBssid = "3a:22:9f:44:ff:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = sameBssid;
 
    OperateResState state3 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info3;
    info3.networkId = 29;
    info3.ssid = "testSsid2";
    info3.bssid = sameBssid;
    int instId3 = 0;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state3, info3, instId3);
 
    // test roam
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    int roamNetworkId = 592;
    OperateResState state4 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info4;
    info4.networkId = roamNetworkId;
    info4.ssid = "testSsid3";
    info4.bssid = "11:22:33:44:55:bb";
    int instId4 = 0;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = roamNetworkId;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state4, info4, instId4);
 
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
    long firstConnectedTime5 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime;
    EXPECT_TRUE(firstConnectedTime5 != 0);
 
    // test record
    // Save connection data to the database in advance.
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
 
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = recordNetworkId;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid = recordSsid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = recordBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt = recordKeyMgmt;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime = recordFirstConnectedTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime = recordTotalUseTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight = recordTotalUseTimeAtNight;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend = recordTotalUseTimeAtWeekend;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = recordMarkedAsHomeApTime;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    OperateResState state6 = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info6;
    info6.networkId = recordNetworkId;
    info6.ssid = recordSsid;
    info6.bssid = recordBssid;
    int instId6 = 0;
    WifiDeviceConfig config6;
    WifiHistoryRecordManager::GetInstance().DealStaConnChanged(state6, info6, instId6);
    std::string testSsid = WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid;
    std::string testBssid = WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid;
    std::string testKeyMgmt = WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt;
    long testFirstConnectedTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime;
    long testTotalUseTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime;
    long testTotalUseTimeAtNight = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long testTotalUseTimeAtWeekend = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    long testMarkedAsHomeApTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime;
 
    EXPECT_TRUE(recordSsid == testSsid);
    EXPECT_TRUE(recordBssid == testBssid);
    EXPECT_TRUE(recordKeyMgmt == testKeyMgmt);
    EXPECT_TRUE(recordFirstConnectedTime == testFirstConnectedTime);
    EXPECT_TRUE(recordTotalUseTime == recordTotalUseTime);
    EXPECT_TRUE(recordTotalUseTimeAtNight == testTotalUseTimeAtNight);
    EXPECT_TRUE(recordTotalUseTimeAtWeekend == testTotalUseTimeAtWeekend);
    EXPECT_TRUE(recordMarkedAsHomeApTime == testMarkedAsHomeApTime);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, NextUpdateApInfoTimerTest, TestSize.Level1)
{
    WIFI_LOGI("NextUpdateApInfoTimerTest enter");
    WifiHistoryRecordManager::GetInstance().Init();
    WifiHistoryRecordManager::GetInstance().NextUpdateApInfoTimer();
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_ != nullptr);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, StopUpdateApInfoTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StopUpdateApInfoTimerTest enter");
    WifiHistoryRecordManager::GetInstance().Init();
    WifiHistoryRecordManager::GetInstance().StopUpdateApInfoTimer();
    EXPECT_TRUE(WifiHistoryRecordManager::GetInstance().periodicUpdateApInfoThread_ != nullptr);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, CheckIsHomeApTest, TestSize.Level1)
{
    WIFI_LOGI("CheckIsHomeApTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentConnectedTime = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime = 39000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight = 36000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend = 0;
 
    bool ret = WifiHistoryRecordManager::GetInstance().CheckIsHomeAp();
    EXPECT_TRUE(ret);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, HomeApJudgeProcessTest, TestSize.Level1)
{
    WIFI_LOGI("HomeApJudgeProcessTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentConnectedTime = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime = 39000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight = 36000;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend = 0;
 
    // already homeAp
    long recordMarkedAsHomeApTime1 = 1736405214;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = recordMarkedAsHomeApTime1;
    WifiHistoryRecordManager::GetInstance().HomeApJudgeProcess();
    long testMarkedAsHomeApTime1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime;
    EXPECT_TRUE(recordMarkedAsHomeApTime1 == testMarkedAsHomeApTime1);
 
    // set homeAp flag
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = INVALID_TIME_POINT;
    WifiHistoryRecordManager::GetInstance().HomeApJudgeProcess();
    long testMarkedAsHomeApTime2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime;
    EXPECT_TRUE(testMarkedAsHomeApTime2 != INVALID_TIME_POINT);
 
    // not homeAp
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight = 0;
    WifiHistoryRecordManager::GetInstance().HomeApJudgeProcess();
    long testMarkedAsHomeApTime3 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime;
    EXPECT_TRUE(testMarkedAsHomeApTime3 == INVALID_TIME_POINT);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, UpdateConnectionTimeTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateConnectionTimeTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    // The statistical time does not meet the requirements
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = 1736232414;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek = 2;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour = 14;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute = 45;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond = 54;
    WifiHistoryRecordManager::GetInstance().UpdateConnectionTime(true);
 
    long testTotalUseTimeAtNight1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    EXPECT_TRUE(testTotalUseTimeAtNight1 == 0);
 
    // Count time across 0 o'clock
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::time_t currentTime = std::time(nullptr) - 84600;  // - 23:30
    std::tm* localTime = std::localtime(&currentTime);
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = currentTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek = localTime->tm_wday;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour = localTime->tm_hour;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute = localTime->tm_min;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond = localTime->tm_sec;
    WifiHistoryRecordManager::GetInstance().UpdateConnectionTime(false);
 
    long testTotalUseTimeAtNight2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    EXPECT_TRUE(testTotalUseTimeAtNight2 != 0);
 
    // The statistical time does not cross 0 o'clock
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::time_t currentTime3 = std::time(nullptr) - 3600;  // Reduce by one hour
    std::tm* localTime3 = std::localtime(&currentTime3);
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = currentTime3;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek = localTime3->tm_wday;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour = localTime3->tm_hour;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute = localTime3->tm_min;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond = localTime3->tm_sec;
    WifiHistoryRecordManager::GetInstance().UpdateConnectionTime(true);
 
    long testTotalUseTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime;
    EXPECT_TRUE(testTotalUseTime != 0);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, IsAbnormalTimeRecordsTest, TestSize.Level1)
{
    WIFI_LOGI("IsAbnormalTimeRecordsTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = INVALID_TIME_POINT;
    bool ret1 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    EXPECT_TRUE(ret1);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime = 32503689365;  // 3000-01-01
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = std::time(nullptr);
    bool ret2 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    EXPECT_TRUE(ret2);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime = 315559083;  // 1980-01-01
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = 315559083;  // 1980-01-01
    bool ret3 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    EXPECT_TRUE(ret3);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime
        = std::time(nullptr) - 5000;  // 5000:test time
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint
        = std::time(nullptr) - 2000;  // 2000:test time
    bool ret4 = WifiHistoryRecordManager::GetInstance().IsAbnormalTimeRecords();
    EXPECT_FALSE(ret4);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, UpdateStaticTimePointTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateStaticTimePointTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    std::time_t testTime = 315559083;  // 1980-01-01
    std::tm* localTime = std::localtime(&testTime);
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint = testTime;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordDayInWeek = localTime->tm_wday;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordHour = localTime->tm_hour;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordMinute = localTime->tm_min;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentRecordSecond = localTime->tm_sec;
    WifiHistoryRecordManager::GetInstance().UpdateStaticTimePoint(std::time(nullptr));
 
    long current = WifiHistoryRecordManager::GetInstance().connectedApInfo_.currenttStaticTimePoint;
    EXPECT_TRUE(current != testTime);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, StaticDurationInNightAndWeekendTest, TestSize.Level1)
{
    WIFI_LOGI("StaticDurationInNightAndWeekendTest enter");
 
    // weekend
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day = 6;
    int startTime = 192;
    int endTime = 235;
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day, startTime, endTime);
    long nightTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime == 0);
    EXPECT_TRUE(weekendTime != 0);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day1 = 0;
    int startTime1 = 531;
    int endTime1 = 5547;
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day1, startTime1, endTime1);
    long nightTime1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime1 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime1 == 0);
    EXPECT_TRUE(weekendTime1 != 0);
 
    // workday
    // startTime < 7:00, endTime < 7:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day2 = 1;  // Monday
    int startTime2 = 18000;  // 5:00
    int endTime2 = 21600;  // 6:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day2, startTime2, endTime2);
    long nightTime2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime2 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime2 != 0);
    EXPECT_TRUE(weekendTime2 == 0);
 
    // startTime < 7:00, 7:00 <= endTime < 20:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day3 = 2;  // Tuesday
    int startTime3 = 18000;  // 5:00
    int endTime3 = 36000;  // 10:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day3, startTime3, endTime3);
    long nightTime3 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime3 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime3 != 0);
    EXPECT_TRUE(weekendTime3 == 0);
 
    // startTime < 7:00, 24:00 > endTime > 20:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day4 = 3;  // Wednesday
    int startTime4 = 18000;  // 5:00
    int endTime4 = 79200;  // 22:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day4, startTime4, endTime4);
    long nightTime4 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime4 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime4 != 0);
    EXPECT_TRUE(weekendTime4 == 0);
 
    // 7:00 =< startTime < 20:00, endTime >= 20:00
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day5 = 4;  // Thursday
    int startTime5 = 36000;  // 10:00
    int endTime5 = 79200;  // 22:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day5, startTime5, endTime5);
    long nightTime5 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime5 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime5 != 0);
    EXPECT_TRUE(weekendTime5 == 0);
 
    // startTime >= 20:00, 24:00 > endTime
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day6 = 5;  // Friday
    int startTime6 = 75600;  // 21:00
    int endTime6 = 79200;  // 22:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day6, startTime6, endTime6);
    long nightTime6 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime6 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime6 != 0);
    EXPECT_TRUE(weekendTime6 == 0);
 
    // startTime > 7:00, 20:00 > endTime
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    int day7 = 1;  // Monday
    int startTime7 = 36000;  // 10:00
    int endTime7 = 50400;  // 14:00
    WifiHistoryRecordManager::GetInstance().StaticDurationInNightAndWeekend(day7, startTime7, endTime7);
    long nightTime7 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight;
    long weekendTime7 = WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend;
    EXPECT_TRUE(nightTime7 == 0);
    EXPECT_TRUE(weekendTime7 == 0);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, AddOrUpdateApInfoRecordTest, TestSize.Level1)
{
    WIFI_LOGI("AddOrUpdateApInfoRecordTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid = "11:22:ff:3a:11:43";
 
    // insert
    long markedAsHomeApTime = 1736225374;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = 8;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid = "AddOrUpdateApInfoRecordTest";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.firstConnectedTime = 1736225372;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.currentConnectedTime = 1736225373;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTime = 100;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtNight = 100;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.totalUseTimeAtWeekend = 100;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = markedAsHomeApTime;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
 
    ConnectedApInfo dbApInfo;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);
    EXPECT_TRUE(dbApInfo.bssid == testBssid);
    EXPECT_TRUE(dbApInfo.markedAsHomeApTime == markedAsHomeApTime);
 
    // update
    long markedAsHomeApTime2 = 1736225899;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = markedAsHomeApTime2;
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
 
    ConnectedApInfo dbApInfo2;
    int ret2 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo2);
    EXPECT_TRUE(ret2 == QUERY_HAS_RECORD);
    EXPECT_TRUE(dbApInfo2.bssid == testBssid);
    EXPECT_TRUE(dbApInfo2.markedAsHomeApTime == markedAsHomeApTime2);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, RemoveApInfoRecordTest, TestSize.Level1)
{
    WIFI_LOGI("RemoveApInfoRecordTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    std::string testBssid = "dd:aa:55:55:0c:ff";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = 66;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid = "RemoveApInfoRecordTest";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    ConnectedApInfo dbApInfo;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);
 
    WifiHistoryRecordManager::GetInstance().RemoveApInfoRecord(testBssid);
    ConnectedApInfo dbApInfo2;
    int ret2 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo2);
    EXPECT_TRUE(ret2 != QUERY_HAS_RECORD);
 
}
 
HWTEST_F(WifiHistoryRecordManagerTest, QueryApInfoRecordByBssidTest, TestSize.Level1)
{
    WIFI_LOGI("QueryApInfoRecordByBssidTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    std::string testBssid = "44:aa:12:55:0c:ff";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = 90;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid = "QueryApInfoRecordByBssidTest";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
    ConnectedApInfo dbApInfo;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);
 
    std::string testBssid2 = "44:37:a5:55:aa:ff";
    ConnectedApInfo dbApInfo2;
    int ret2 = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid2, dbApInfo2);
    EXPECT_TRUE(ret2 != QUERY_HAS_RECORD);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, QueryAllApInfoRecordTest, TestSize.Level1)
{
    WIFI_LOGI("QueryAllApInfoRecordTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    std::string testBssid = "23:aa:6c:55:0c:cc";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = 52;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid = "QueryAllApInfoRecordTest";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
 
    std::vector<ConnectedApInfo> dbApInfoVector;
    int queryRet = WifiHistoryRecordManager::GetInstance().QueryAllApInfoRecord(dbApInfoVector);
    EXPECT_TRUE(queryRet == QUERY_HAS_RECORD);
 
    bool addRet = false;
    for (const ConnectedApInfo &info : dbApInfoVector) {
        if (info.bssid == testBssid) {
            addRet = true;
            break;
        }
    }
    EXPECT_TRUE(addRet);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, CreateApInfoBucketTest, TestSize.Level1)
{
    WIFI_LOGI("CreateApInfoBucketTest enter");
    ConnectedApInfo apInfo;
    WifiHistoryRecordManager::GetInstance().CreateApInfoBucket(apInfo);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, IsHomeApTest, TestSize.Level1)
{
    WIFI_LOGI("IsHomeApTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid1 = "11:3a:ff:22:ac:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = std::time(nullptr);
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid1;
    bool ret1 = WifiHistoryRecordManager::GetInstance().IsHomeAp(testBssid1);
    EXPECT_TRUE(ret1);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid2 = "11:3a:ff:22:ac:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = std::time(nullptr);
    bool ret2 = WifiHistoryRecordManager::GetInstance().IsHomeAp(testBssid2);
    EXPECT_FALSE(ret2);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    std::string testBssid3 = "11:3a:ff:22:ac:66";
    std::string testBssid4 = "31:5b:ff:55:ac:66";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid4;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = std::time(nullptr);
    bool ret3 = WifiHistoryRecordManager::GetInstance().IsHomeAp(testBssid3);
    EXPECT_FALSE(ret3);
 
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.markedAsHomeApTime = std::time(nullptr);
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
}
 
HWTEST_F(WifiHistoryRecordManagerTest, ClearConnectedApInfoTest, TestSize.Level1)
{
    WIFI_LOGI("ClearConnectedApInfoTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
}
 
HWTEST_F(WifiHistoryRecordManagerTest, DelectAllApInfoTest, TestSize.Level1)
{
    WIFI_LOGI("DelectAllApInfoTest enter");
    WifiHistoryRecordManager::GetInstance().DelectAllApInfo();
 
    std::vector<ConnectedApInfo> dbApInfoVector;
    int ret = WifiHistoryRecordManager::GetInstance().QueryAllApInfoRecord(dbApInfoVector);
    EXPECT_TRUE(ret == QUERY_NO_RECORD);
}
 
HWTEST_F(WifiHistoryRecordManagerTest, DelectApInfoTest, TestSize.Level1)
{
    WIFI_LOGI("DelectApInfoTest enter");
    WifiHistoryRecordManager::GetInstance().ClearConnectedApInfo();
 
    std::string testSsid = "DelectApInfoTest";
    std::string testBssid = "23:bb:9c:55:aa:cc";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.networkId = 33;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.ssid = "DelectApInfoTest";
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.bssid = testBssid;
    WifiHistoryRecordManager::GetInstance().connectedApInfo_.keyMgmt = "SAE";
    WifiHistoryRecordManager::GetInstance().AddOrUpdateApInfoRecord();
 
    ConnectedApInfo dbApInfo;
    int ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo);
    EXPECT_TRUE(ret == QUERY_HAS_RECORD);
 
    WifiHistoryRecordManager::GetInstance().DelectApInfo(testSsid, testBssid);
 
    ret = WifiHistoryRecordManager::GetInstance().QueryApInfoRecordByBssid(testBssid, dbApInfo);
    EXPECT_TRUE(ret != QUERY_HAS_RECORD);
}
}
}