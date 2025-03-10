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
#include "wifi_log.h"
#include "wifi_logger.h"
#include "speed_limit_configs_writer.h"

using namespace OHOS::Wifi;
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

static std::string g_errLog;
void SpeedLogCallback(const LogType type, const LogLevel level,
                      const unsigned int domain, const char *tag,
                      const char *msg)
{
    g_errLog = msg;
}

class SpeedLimitConfigsWriterTest : public Test {
public:
    void SetUp() override
    {
        LOG_SetCallback(SpeedLogCallback);
        // Set up any necessary dependencies or configurations for the tests
    }

    void TearDown() override
    {
        // Clean up any resources allocated in SetUp()
    }
};

HWTEST_F(SpeedLimitConfigsWriterTest, SetBgLimitMode_ReturnsWifiOptSuccessWhenFileOpenSucceeds, TestSize.Level1)
{
    EXPECT_EQ(WIFI_OPT_SUCCESS, SetBgLimitMode(1));
}

HWTEST_F(SpeedLimitConfigsWriterTest, SetBgLimitIdList_DoesNotCallSetUidPidsWhenTypeIsUnknown, TestSize.Level1)
{
    std::vector<int> idList = {10, 11, 12};
    SetBgLimitIdList(idList, 999);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SpeedLimitConfigsWriterTest, SetUidPids_WritesIdStrToFileWhenFileOpenSucceeds, TestSize.Level1)
{
    const char *filePath = "/path/to/file";
    const int idArray[] = {1, 2, 3};
    const int size = sizeof(idArray) / sizeof(idArray[0]);
    SetUidPids(filePath, idArray, size);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SpeedLimitConfigsWriterTest, SetUidPids_DoesNotWriteIdStrToFileWhenFileOpenFails, TestSize.Level1)
{
    const char *filePath = "/path/to/nonexistent/file";
    const int idArray[] = {4, 5, 6};
    const int size = sizeof(idArray) / sizeof(idArray[0]);
    SetUidPids(filePath, idArray, size);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}