/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "wifi_exception_record_utils.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <unistd.h>
#include <fstream>
#include "wifi_logger.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiExceptionRecordUtilsTest");

static constexpr const char* TEST_FILE_PATH =
    "/data/service/el1/public/wifi/wifi_exception.json";

static constexpr int MAX_FAULTS_PER_GROUP = 10;
static constexpr int MAX_TOTAL_RECORDS = 50;
static constexpr int DHCP_REASON_BASE = 101;

class WifiExceptionRecordUtilsTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp()
    {
        unlink(TEST_FILE_PATH);
    }
    void TearDown()
    {
        unlink(TEST_FILE_PATH);
    }

    WifiExceptionRecord MakeRecord(const std::string& ssid, ExceptionReason reason,
                                    int64_t ts, int dhcpStatus, const std::string& extra)
    {
        WifiExceptionRecord rec;
        rec.ssid = ssid;
        rec.timestamp = ts;
        rec.reason = reason;
        rec.detail = DhcpFaultDetail{dhcpStatus, extra};
        return rec;
    }
};
HWTEST_F(WifiExceptionRecordUtilsTest, AddException_SingleDhcpFault, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    auto rec = MakeRecord("TestAP", ExceptionReason::DHCP_CONNECTION_FAIL, 1000, -1, "fail");
    EXPECT_EQ(utils.AddException(rec), 0);
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].ssid, "TestAP");
    EXPECT_EQ(groups[0].faults.size(), 1u);
    EXPECT_EQ(groups[0].faults[0].reason, ExceptionReason::DHCP_CONNECTION_FAIL);
}
HWTEST_F(WifiExceptionRecordUtilsTest, AddException_MergeSameReasonDetail, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    auto rec1 = MakeRecord("AP1", ExceptionReason::DHCP_GET_IP_TIMEOUT, 1000, -1, "timeout");
    auto rec2 = MakeRecord("AP1", ExceptionReason::DHCP_GET_IP_TIMEOUT, 2000, -1, "timeout");
    EXPECT_EQ(utils.AddException(rec1), 0);
    EXPECT_EQ(utils.AddException(rec2), 0);
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].faults.size(), 1u);
    EXPECT_EQ(groups[0].faults[0].timestamp, 2000);
}

HWTEST_F(WifiExceptionRecordUtilsTest, AddException_DifferentReasonsNotMerged, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    auto rec1 = MakeRecord("AP1", ExceptionReason::DHCP_CONNECTION_FAIL, 1000, -1, "a");
    auto rec2 = MakeRecord("AP1", ExceptionReason::DHCP_GET_IP_TIMEOUT, 2000, -1, "b");
    utils.AddException(rec1);
    utils.AddException(rec2);
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].faults.size(), 2u);
}

HWTEST_F(WifiExceptionRecordUtilsTest, AddException_PerGroupLimit10, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    for (int i = 0; i < 15; i++)
    {
        auto rec = MakeRecord("AP1", static_cast<ExceptionReason>(DHCP_REASON_BASE + i), 1000 + i, i, "x");
        utils.AddException(rec);
    }
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_LE(groups[0].faults.size(), static_cast<size_t>(MAX_FAULTS_PER_GROUP));
}

HWTEST_F(WifiExceptionRecordUtilsTest, AddException_GlobalLimit50, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    for (int g = 0; g < 6; g++)
    {
        for (int i = 0; i < MAX_FAULTS_PER_GROUP; i++)
        {
            std::string ssid = "AP" + std::to_string(g);
            auto rec = MakeRecord(ssid, static_cast<ExceptionReason>(DHCP_REASON_BASE + i),
                                  1000 + g * MAX_FAULTS_PER_GROUP + i, i, "x");
            utils.AddException(rec);
        }
    }
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    int total = 0;
    for (const auto& g : groups) total += static_cast<int>(g.faults.size());
    EXPECT_LE(total, MAX_TOTAL_RECORDS);
}
HWTEST_F(WifiExceptionRecordUtilsTest, GetAllExceptions_EmptyFile, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    std::vector<ApGroup> groups;
    EXPECT_EQ(utils.GetAllExceptions(groups), 0);
    EXPECT_TRUE(groups.empty());
}

HWTEST_F(WifiExceptionRecordUtilsTest, GetAllExceptions_MultipleGroups, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    utils.AddException(MakeRecord("AP_A", ExceptionReason::DHCP_CONNECTION_FAIL, 1000, -1, "a"));
    utils.AddException(MakeRecord("AP_B", ExceptionReason::DHCP_GET_IP_TIMEOUT, 2000, -1, "b"));
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    EXPECT_EQ(groups.size(), 2u);
}

HWTEST_F(WifiExceptionRecordUtilsTest, ClearExceptions_ClearsAll, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    utils.AddException(MakeRecord("AP1", ExceptionReason::DHCP_CONNECTION_FAIL, 1000, -1, "x"));
    EXPECT_EQ(utils.ClearExceptions(), 0);
    std::vector<ApGroup> groups;
    utils.GetAllExceptions(groups);
    EXPECT_TRUE(groups.empty());
}

HWTEST_F(WifiExceptionRecordUtilsTest, ReasonToString_AllReasons, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    EXPECT_EQ(utils.ReasonToString(ExceptionReason::DHCP_CONNECTION_FAIL), "DHCP_CONNECTION_FAIL");
    EXPECT_EQ(utils.ReasonToString(ExceptionReason::DHCP_GET_IP_TIMEOUT), "DHCP_GET_IP_TIMEOUT");
    EXPECT_EQ(utils.ReasonToString(ExceptionReason::DHCP_IPV4_RESULT_FAIL), "DHCP_IPV4_RESULT_FAIL");
    EXPECT_EQ(utils.ReasonToString(ExceptionReason::DHCP_IP_EXPIRED), "DHCP_IP_EXPIRED");
}

HWTEST_F(WifiExceptionRecordUtilsTest, CategoryToString_AllCategories, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    EXPECT_EQ(utils.CategoryToString(ExceptionReason::DHCP_CONNECTION_FAIL), "DHCP");
}

HWTEST_F(WifiExceptionRecordUtilsTest, FormatTime_BasicFormat, TestSize.Level0)
{
    WifiExceptionRecordUtils utils;
    std::string result = utils.FormatTime(0);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.length(), 19u);
}

}
}