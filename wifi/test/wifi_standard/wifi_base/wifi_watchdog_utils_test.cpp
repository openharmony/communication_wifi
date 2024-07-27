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
namespace OHOS {
namespace Wifi {
// Mock class for HiviewDFX
class MockHiviewDFX {
public:
    MOCK_METHOD5(SetTimer, void(const std::string &, int, void *, void *, int));
    MOCK_METHOD1(CancelTimer, void(int));
    MOCK_METHOD0(InitFfrtWatchdog, void());
};
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
    EXPECT_EQ(instance1, instance2);
}

// Test case for WifiWatchDogUtils::ResetProcess()
HWTEST_F(WifiWatchDogUtilsTest, ResetProcessTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Create a mock of HiviewDFX
    MockHiviewDFX mockHiviewDFX;

    // Set expectations on the mock object
    EXPECT_CALL(mockHiviewDFX,
        SetTimer("WifiResetTimer", 0, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY))
        .Times(1);

    // Set the mock object as the instance of HiviewDFX
    HiviewDFX::XCollie::GetInstance = [&mockHiviewDFX]() -> MockHiviewDFX & { return mockHiviewDFX; };

    // Call the ResetProcess function with usingHiviewDfx set to true and a thread name
    bool result = wifiWatchDogUtils->ResetProcess(true, "TestThread");

    // Check that the function returns true
    EXPECT_TRUE(result);
}

// Test case for WifiWatchDogUtils::StartWatchDogForFunc()
HWTEST_F(WifiWatchDogUtilsTest, StartWatchDogForFuncTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Create a mock of HiviewDFX
    MockHiviewDFX mockHiviewDFX;

    // Set expectations on the mock object
    EXPECT_CALL(mockHiviewDFX, SetTimer("TestFunction", 10, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG))
        .Times(1)
        .WillOnce(testing::Return(123));

    // Set the mock object as the instance of HiviewDFX
    HiviewDFX::XCollie::GetInstance = [&mockHiviewDFX]() -> MockHiviewDFX & { return mockHiviewDFX; };

    // Call the StartWatchDogForFunc function with a function name
    int id = wifiWatchDogUtils->StartWatchDogForFunc("TestFunction");

    // Check that the returned ID is not -1
    EXPECT_NE(id, -1);
}

// Test case for WifiWatchDogUtils::StopWatchDogForFunc()
HWTEST_F(WifiWatchDogUtilsTest, StopWatchDogForFuncTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Create a mock of HiviewDFX
    MockHiviewDFX mockHiviewDFX;

    // Set expectations on the mock object
    EXPECT_CALL(mockHiviewDFX, CancelTimer(123)).Times(1);

    // Set the mock object as the instance of HiviewDFX
    HiviewDFX::XCollie::GetInstance = [&mockHiviewDFX]() -> MockHiviewDFX & { return mockHiviewDFX; };

    // Call the StopWatchDogForFunc function with a function name and an ID
    bool result = wifiWatchDogUtils->StopWatchDogForFunc("TestFunction", 123);

    // Check that the function returns true
    EXPECT_TRUE(result);
}

// Test case for WifiWatchDogUtils::StartAllWatchDog()
HWTEST_F(WifiWatchDogUtilsTest, StartAllWatchDogTest, TestSize.Level1)
{
    // Create an instance of WifiWatchDogUtils
    std::shared_ptr<WifiWatchDogUtils> wifiWatchDogUtils = WifiWatchDogUtils::GetInstance();

    // Create a mock of HiviewDFX
    MockHiviewDFX mockHiviewDFX;

    // Set expectations on the mock object
    EXPECT_CALL(mockHiviewDFX, InitFfrtWatchdog()).Times(1);

    // Set the mock object as the instance of HiviewDFX
    HiviewDFX::Watchdog::GetInstance = [&mockHiviewDFX]() -> MockHiviewDFX & { return mockHiviewDFX; };

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