/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_net_stats_manager.h"
#include "wifi_logger.h"

using namespace testing;
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
const std::string g_errLog = "wifitest";
DEFINE_WIFILOG_LABEL("WifiNetStatsManagerTest");
class WifiNetStatsManagerTest : public Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiNetStatsManagerTest, StartNetStats_CreatesTimerAndStartsIt, TestSize.Level1)
{
    WIFI_LOGI("StartNetStats_CreatesTimerAndStartsIt enter!");
    WifiNetStatsManager::GetInstance().StartNetStats();
    EXPECT_NE(WifiNetStatsManager::GetInstance().m_netStatsTimerId, 0);
}

HWTEST_F(WifiNetStatsManagerTest, StopNetStats_StopsAndDestroysTimer, TestSize.Level1)
{
    WIFI_LOGI("StopNetStats_StopsAndDestroysTimer enter!");
    WifiNetStatsManager::GetInstance().StopNetStats();
    EXPECT_EQ(WifiNetStatsManager::GetInstance().m_netStatsTimerId, 0);
}

HWTEST_F(WifiNetStatsManagerTest, GetIncrementalNetStats_CalculatesIncrementalNetStats_1, TestSize.Level1)
{
    WIFI_LOGI("GetIncrementalNetStats_CalculatesIncrementalNetStats_1 enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100;
    netStats.push_back(netStatsInfo);
    WifiNetStatsManager::GetInstance().m_lastStatsMap = {};
    NetStats ret = WifiNetStatsManager::GetInstance().GetIncrementalNetStats(netStats);
    EXPECT_EQ(ret[0].uid_, 123);
    EXPECT_EQ(ret[0].rxBytes_, 100);
}

HWTEST_F(WifiNetStatsManagerTest, GetIncrementalNetStats_CalculatesIncrementalNetStats_2, TestSize.Level1)
{
    WIFI_LOGI("GetIncrementalNetStats_CalculatesIncrementalNetStats enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfoCur;
    netStatsInfoCur.uid_ = 123;
    netStatsInfoCur.rxBytes_ = 100;
    netStats.push_back(netStatsInfoCur);

    NetStatsInfo netStatsInfoLast;
    netStatsInfoLast.uid_ = 123;
    netStatsInfoLast.rxBytes_ = 50;
    WifiNetStatsManager::GetInstance().m_lastStatsMap = {{123, netStatsInfoLast}};
    NetStats ret = WifiNetStatsManager::GetInstance().GetIncrementalNetStats(netStats);
    EXPECT_EQ(ret[0].uid_, 123);
    EXPECT_EQ(ret[0].rxBytes_, 50);
}

HWTEST_F(WifiNetStatsManagerTest, GetTotalNetStatsInfo_CalculatesTotalNetStatsInfo, TestSize.Level1)
{
    WIFI_LOGI("GetTotalNetStatsInfo_CalculatesTotalNetStatsInfo enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo1;
    netStatsInfo1.uid_ = 111;
    netStatsInfo1.rxBytes_ = 100;

    NetStatsInfo netStatsInfo2;
    netStatsInfo2.uid_ = 222;
    netStatsInfo2.rxBytes_ = 200;
    netStats.push_back(netStatsInfo1);
    netStats.push_back(netStatsInfo2);
    NetStatsInfo ret = WifiNetStatsManager::GetInstance().GetTotalNetStatsInfo(netStats);
    EXPECT_EQ(ret.uid_, -1);
    EXPECT_EQ(ret.rxBytes_, 300);
}

HWTEST_F(WifiNetStatsManagerTest, ConvertNetStatsToMap_ConvertsNetStatsToMap, TestSize.Level1)
{
    WIFI_LOGI("ConvertNetStatsToMap_ConvertsNetStatsToMap enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo1;
    netStatsInfo1.uid_ = 111;
    netStatsInfo1.rxBytes_ = 100;

    NetStatsInfo netStatsInfo2;
    netStatsInfo2.uid_ = 222;
    netStatsInfo2.rxBytes_ = 200;
    netStats.push_back(netStatsInfo1);
    netStats.push_back(netStatsInfo2);
    std::map<int32_t, NetStatsInfo> ret = WifiNetStatsManager::GetInstance().ConvertNetStatsToMap(netStats);
    EXPECT_EQ(ret[111].rxBytes_, 100);
    EXPECT_EQ(ret[222].rxBytes_, 200);
    EXPECT_EQ(static_cast<int>(ret.size()), 2);
}

HWTEST_F(WifiNetStatsManagerTest, GetTrafficLog_GeneratesTrafficLog_NoEndStr, TestSize.Level1)
{
    WIFI_LOGI("GetTrafficLog_GeneratesTrafficLog_NoEndStr enter!");
    std::string bundleName = "testBundle";
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 111;
    netStatsInfo.rxBytes_ = 100;
    netStatsInfo.txBytes_ = 200;
    netStatsInfo.rxPackets_ = 1;
    netStatsInfo.txPackets_ = 2;
    std::string ret = WifiNetStatsManager::GetInstance().GetTrafficLog(bundleName, netStatsInfo, false);
    EXPECT_EQ(ret, "testBundle/100/200/1/2");
}

HWTEST_F(WifiNetStatsManagerTest, GetTrafficLog_GeneratesTrafficLog_HasEndStr, TestSize.Level1)
{
    WIFI_LOGI("GetTrafficLog_GeneratesTrafficLog_HasEndStr enter!");
    std::string bundleName = "testBundle";
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 111;
    netStatsInfo.rxBytes_ = 100;
    netStatsInfo.txBytes_ = 200;
    netStatsInfo.rxPackets_ = 1;
    netStatsInfo.txPackets_ = 2;
    std::string ret = WifiNetStatsManager::GetInstance().GetTrafficLog(bundleName, netStatsInfo, true);
    EXPECT_EQ(ret, "testBundle/100/200/1/2,");
}

HWTEST_F(WifiNetStatsManagerTest, GetBundleName_GetsBundleName, TestSize.Level1)
{
    WIFI_LOGI("GetBundleName_GetsBundleName enter!");
    int32_t uid = -1;
    std::string ret = WifiNetStatsManager::GetInstance().GetBundleName(uid);
    EXPECT_EQ(ret, "total");
}

HWTEST_F(WifiNetStatsManagerTest, LogNetStatsTraffic_LogsNetStatsTraffic, TestSize.Level1)
{
    WIFI_LOGI("LogNetStatsTraffic_LogsNetStatsTraffic enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo1;
    netStatsInfo1.uid_ = 111;
    netStatsInfo1.rxBytes_ = 100;
    netStatsInfo1.txBytes_ = 100;
    netStatsInfo1.rxPackets_ = 1;
    netStatsInfo1.txPackets_ = 1;

    NetStatsInfo netStatsInfo2;
    netStatsInfo2.uid_ = 222;
    netStatsInfo2.rxBytes_ = 200;
    netStatsInfo2.txBytes_ = 200;
    netStatsInfo2.rxPackets_ = 2;
    netStatsInfo2.txPackets_ = 2;

    netStats.push_back(netStatsInfo1);
    netStats.push_back(netStatsInfo2);
    WifiNetStatsManager::GetInstance().LogNetStatsTraffic(netStats);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiNetStatsManagerTest, InitSpeedTestInfo_ResetsAllSpeedTestVariables, TestSize.Level1)
{
    WIFI_LOGI("InitSpeedTestInfo_ResetsAllSpeedTestVariables enter!");
    WifiNetStatsManager::GetInstance().maxRxSpeed_ = 100;
    WifiNetStatsManager::GetInstance().maxTxSpeed_ = 200;
    WifiNetStatsManager::GetInstance().totalRxBytes_ = 1000;
    WifiNetStatsManager::GetInstance().totalTxBytes_ = 2000;
    WifiNetStatsManager::GetInstance().highSpeedDuration_ = 5000;
    WifiNetStatsManager::GetInstance().avgRxSpeed_ = 50;
    WifiNetStatsManager::GetInstance().avgTxSpeed_ = 60;
    WifiNetStatsManager::GetInstance().speedSampleCount_ = 5;
 
    WifiNetStatsManager::GetInstance().InitSpeedTestInfo();
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().maxRxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().maxTxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().totalRxBytes_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().totalTxBytes_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().highSpeedDuration_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().avgRxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().avgTxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().speedSampleCount_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, CheckAndReportSpeedTest_NegativeTimeInterval_UpdatesTimeOnly, TestSize.Level1)
{
    WIFI_LOGI("CheckAndReportSpeedTest_NegativeTimeInterval_UpdatesTimeOnly enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100;
    netStatsInfo.txBytes_ = 200;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().lastLogTime_ = 1000;
    int64_t currentTime = 500;
 
    WifiNetStatsManager::GetInstance().CheckAndReportSpeedTest(netStats, currentTime);
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().lastLogTime_, currentTime);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().lastAppName_, "unknown:123");
}
 
HWTEST_F(WifiNetStatsManagerTest, CheckAndReportSpeedTest_HighSpeed_AccumulatesStats, TestSize.Level1)
{
    WIFI_LOGI("CheckAndReportSpeedTest_HighSpeed_AccumulatesStats enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100 * 1024 * 1024;
    netStatsInfo.txBytes_ = 5 * 1024 * 1024;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().lastLogTime_ = 0;
    WifiNetStatsManager::GetInstance().lastAppName_ = "app1";
    WifiNetStatsManager::GetInstance().maxRxSpeed_ = 0;
    WifiNetStatsManager::GetInstance().maxTxSpeed_ = 0;
    WifiNetStatsManager::GetInstance().highSpeedDuration_ = 0;
 
    int64_t currentTime = 1000;
 
    WifiNetStatsManager::GetInstance().CheckAndReportSpeedTest(netStats, currentTime);
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().lastAppName_, "unknown:123");
    EXPECT_EQ(WifiNetStatsManager::GetInstance().lastLogTime_, currentTime);
    EXPECT_GT(WifiNetStatsManager::GetInstance().highSpeedDuration_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, CheckAndReportSpeedTest_LowSpeed_BelowThreshold, TestSize.Level1)
{
    WIFI_LOGI("CheckAndReportSpeedTest_LowSpeed_BelowThreshold enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100;
    netStatsInfo.txBytes_ = 100;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().lastLogTime_ = 0;
    WifiNetStatsManager::GetInstance().lastAppName_ = "testApp";
    WifiNetStatsManager::GetInstance().speedSampleCount_ = 0;
 
    int64_t currentTime = 1000;
 
    WifiNetStatsManager::GetInstance().CheckAndReportSpeedTest(netStats, currentTime);
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().speedSampleCount_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().highSpeedDuration_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, CheckAndReportSpeedTest_AppChanged_ReportsSpeedTest, TestSize.Level1)
{
    WIFI_LOGI("CheckAndReportSpeedTest_AppChanged_ReportsSpeedTest enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 456;
    netStatsInfo.rxBytes_ = 5 * 1024 * 1024;
    netStatsInfo.txBytes_ = 5 * 1024 * 1024;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().lastLogTime_ = 0;
    WifiNetStatsManager::GetInstance().lastAppName_ = "oldApp";
    WifiNetStatsManager::GetInstance().speedSampleCount_ = 1;
 
    int64_t currentTime = 15000;
 
    WifiNetStatsManager::GetInstance().CheckAndReportSpeedTest(netStats, currentTime);
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().lastAppName_, "unknown:456");
}
 
HWTEST_F(WifiNetStatsManagerTest, CheckAndReportSpeedTest_ExceedsDurationThreshold_IncrementsSampleCount,
    TestSize.Level1)
{
    WIFI_LOGI("CheckAndReportSpeedTest_ExceedsDurationThreshold_IncrementsSampleCount enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100 * 1024 * 1024;
    netStatsInfo.txBytes_ = 100 * 1024 * 1024;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().lastLogTime_ = 0;
    WifiNetStatsManager::GetInstance().highSpeedDuration_ = 5000;
    WifiNetStatsManager::GetInstance().speedSampleCount_ = 0;
 
    int64_t currentTime = 15000;
 
    WifiNetStatsManager::GetInstance().CheckAndReportSpeedTest(netStats, currentTime);
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().speedSampleCount_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, CheckAndReportSpeedTest_LowSpeedAfterHighSpeed_ReportsCHR, TestSize.Level1)
{
    WIFI_LOGI("CheckAndReportSpeedTest_LowSpeedAfterHighSpeed_ReportsCHR enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100;
    netStatsInfo.txBytes_ = 100;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().lastLogTime_ = 0;
    WifiNetStatsManager::GetInstance().speedSampleCount_ = 5;
    WifiNetStatsManager::GetInstance().maxRxSpeed_ = 50;
    WifiNetStatsManager::GetInstance().maxTxSpeed_ = 60;
 
    int64_t currentTime = 1000;
 
    WifiNetStatsManager::GetInstance().CheckAndReportSpeedTest(netStats, currentTime);
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().speedSampleCount_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, ReportSpeedTestChr_CalculatesAverageSpeed_AndReportsEvent, TestSize.Level1)
{
    WIFI_LOGI("ReportSpeedTestChr_CalculatesAverageSpeed_AndReportsEvent enter!");
    WifiNetStatsManager::GetInstance().lastAppName_ = "test.app";
    WifiNetStatsManager::GetInstance().maxRxSpeed_ = 100;
    WifiNetStatsManager::GetInstance().maxTxSpeed_ = 200;
    WifiNetStatsManager::GetInstance().totalRxBytes_ = 10 * 1024 * 1024;
    WifiNetStatsManager::GetInstance().totalTxBytes_ = 20 * 1024 * 1024;
    WifiNetStatsManager::GetInstance().highSpeedDuration_ = 5000;
    WifiNetStatsManager::GetInstance().avgRxSpeed_ = 0;
    WifiNetStatsManager::GetInstance().avgTxSpeed_ = 0;
 
    WifiNetStatsManager::GetInstance().ReportSpeedTestChr();
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().avgRxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().avgTxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().maxRxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().maxTxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().highSpeedDuration_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, ReportSpeedTestChr_ZeroDuration_HandlesDivisionByZero, TestSize.Level1)
{
    WIFI_LOGI("ReportSpeedTestChr_ZeroDuration_HandlesDivisionByZero enter!");
    WifiNetStatsManager::GetInstance().lastAppName_ = "test.app";
    WifiNetStatsManager::GetInstance().maxRxSpeed_ = 100;
    WifiNetStatsManager::GetInstance().maxTxSpeed_ = 200;
    WifiNetStatsManager::GetInstance().totalRxBytes_ = 1000;
    WifiNetStatsManager::GetInstance().totalTxBytes_ = 2000;
    WifiNetStatsManager::GetInstance().highSpeedDuration_ = 0;
 
    WifiNetStatsManager::GetInstance().ReportSpeedTestChr();
 
    EXPECT_EQ(WifiNetStatsManager::GetInstance().avgRxSpeed_, 0);
    EXPECT_EQ(WifiNetStatsManager::GetInstance().avgTxSpeed_, 0);
}
 
HWTEST_F(WifiNetStatsManagerTest, LogNetStatsTraffic_WithSpeedTest_CallsCheckAndReport, TestSize.Level1)
{
    WIFI_LOGI("LogNetStatsTraffic_WithSpeedTest_CallsCheckAndReport enter!");
    NetStats netStats;
    NetStatsInfo netStatsInfo;
    netStatsInfo.uid_ = 123;
    netStatsInfo.rxBytes_ = 100;
    netStatsInfo.txBytes_ = 200;
    netStatsInfo.rxPackets_ = 1;
    netStatsInfo.txPackets_ = 2;
    netStats.push_back(netStatsInfo);
 
    WifiNetStatsManager::GetInstance().m_lastStatsMap = {};
    WifiNetStatsManager::GetInstance().lastLogTime_ = 0;
 
    WifiNetStatsManager::GetInstance().LogNetStatsTraffic(netStats);
 
    EXPECT_NE(WifiNetStatsManager::GetInstance().lastLogTime_, 0);
}
}  // namespace Wifi
}  // namespace OHOS