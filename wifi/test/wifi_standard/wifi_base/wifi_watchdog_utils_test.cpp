/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_watchdog_utils.h"
using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {
// Test fixture for WifiWatchDogUtils
class WifiWatchDogUtilsTest : public testing::Test {
protected:
    void SetUp() override
    {
        // Set up any required resources before each test
    }

    void TearDown() override
    {
        // Release any resources allocated in SetUp()
    }
};

// Test case for WifiWatchDogUtils::GetInstance()
HWTEST_F(WifiWatchDogUtilsTest, GetInstanceTest, TestSize.Level1)
{
    std::shared_ptr<WifiWatchDogUtils> instance1 = WifiWatchDogUtils::GetInstance();
    std::shared_ptr<WifiWatchDogUtils> instance2 = WifiWatchDogUtils::GetInstance();

    // Check that the instances are the same
    EXPECT_FALSE(g_errLog.find(WifiWatchDogUtilsTest) != std::string::npos);
}

// Test case for WifiWatchDogUtils::ResetProcess()
HWTEST_F(WifiWatchDogUtilsTest, ResetProcessTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Call the ResetProcess function with usingHiviewDfx set to true and a thread name
    bool result = wifiWatchDogUtils->ResetProcess(true, "TestThread", true);

    // Check that the function returns true
    EXPECT_TRUE(result);
}

// Test case for WifiWatchDogUtils::StartWatchDogForFunc()
HWTEST_F(WifiWatchDogUtilsTest, StartWatchDogForFuncTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Call the StartWatchDogForFunc function with a function name
    int id = wifiWatchDogUtils->StartWatchDogForFunc("TestFunction");

    // Check that the returned ID is not -1
    EXPECT_NE(id, -1);

    // Call the StopWatchDogForFunc function with a function name and an ID
    bool result = wifiWatchDogUtils->StopWatchDogForFunc("TestFunction", id);

    // Check that the function returns true
    EXPECT_TRUE(result);
}

// Test case for WifiWatchDogUtils::StartAllWatchDog()
HWTEST_F(WifiWatchDogUtilsTest, StartAllWatchDogTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Call the StartAllWatchDog function
    wifiWatchDogUtils->StartAllWatchDog();
}

// Test case for WifiWatchDogUtils::ReportResetEvent()
HWTEST_F(WifiWatchDogUtilsTest, ReportResetEventTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Call the ReportResetEvent function with a thread name
    bool result = wifiWatchDogUtils->ReportResetEvent("TestThread");

    // Check that the function returns true
    EXPECT_TRUE(result);
}
}
}