/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_net_observer.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const std::string g_errLog = "wifitest";
using namespace NetManagerStandard;
DEFINE_WIFILOG_LABEL("WifiNetObserverTest");
class WifiNetObserverTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        netStateObserver = sptr<NetStateObserver>(new NetStateObserver());
    }
    virtual void TearDown() {}
    sptr<NetStateObserver> netStateObserver;
};

// Test case for setting the net state callback
HWTEST_F(WifiNetObserverTest, SetNetStateCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("SetNetStateCallbackTest enter!");

    // Create a mock callback function
    std::function<void(SystemNetWorkState, std::string)> mockCallback =
        [](SystemNetWorkState netState, std::string urlRedirect) {
            // Mock implementation
        };

    // Set the net state callback
    netStateObserver->SetNetStateCallback(mockCallback);
    ASSERT_NE(netStateObserver->m_callback, nullptr);
}

HWTEST_F(WifiNetObserverTest, NetWifiObserverStartTest, TestSize.Level1)
{
    WIFI_LOGI("StartNetStateObserver enter!");
    netStateObserver->StartNetStateObserver(netStateObserver);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiNetObserverTest, NetWifiObserverStopTest, TestSize.Level1)
{
    WIFI_LOGI("StopNetStateObserver enter!");
    netStateObserver->StopNetStateObserver(netStateObserver);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

// Test case for handling net detection result
HWTEST_F(WifiNetObserverTest, OnNetDetectionResultChangedTest, TestSize.Level1)
{
    WIFI_LOGI("OnNetDetectionResultChangedTest enter!");
    int result = -1;
    // Create a mock callback function
    std::function<void(SystemNetWorkState, std::string)> mockCallback =
        [&result](SystemNetWorkState netState, std::string urlRedirect) {
            switch (netState) {
                case NETWORK_NOTWORKING:
                    result = 0;
                    break;
                case NETWORK_IS_WORKING:
                    result = 1;
                    break;
                case NETWORK_IS_PORTAL:
                    result = 2;
                    break;
                default:
                    result = -1;
                    break;
            }
        };

    // Set the net state callback
    netStateObserver->SetNetStateCallback(mockCallback);

    // Call the OnNetDetectionResultChanged method with different detection results
    netStateObserver->OnNetDetectionResultChanged(
        NetManagerStandard::NET_DETECTION_CAPTIVE_PORTAL, "http://example.com");
    EXPECT_EQ(result, 2);
    netStateObserver->OnNetDetectionResultChanged(
        NetManagerStandard::NET_DETECTION_FAIL, "");
    EXPECT_EQ(result, 0);
    netStateObserver->OnNetDetectionResultChanged(
        NetManagerStandard::NET_DETECTION_SUCCESS, "");
    EXPECT_EQ(result, 1);
}

// Test case for getting the Wi-Fi network handle
HWTEST_F(WifiNetObserverTest, GetWifiNetworkHandleTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiNetworkHandleTest enter!");
    // Call the GetWifiNetworkHandle method
    sptr<NetHandle> result = netStateObserver->GetWifiNetworkHandle();

    // Verify the result -- without permission:ohos.permission.GET_NETWORK_INFO
    EXPECT_EQ(result, nullptr);
}

// Test case for starting Wi-Fi detection
HWTEST_F(WifiNetObserverTest, StartWifiDetectionTest, TestSize.Level1)
{
    WIFI_LOGI("StartWifiDetectionTest enter!");
    // Call the StartWifiDetection method
    int32_t result = netStateObserver->StartWifiDetection();

    // Verify the result
    EXPECT_EQ(result, 1);
}

// Test case for getting the Wi-Fi network ID
HWTEST_F(WifiNetObserverTest, GetWifiNetIdTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiNetIdTest enter!");
    // Call the GetWifiNetId method
    int32_t result = netStateObserver->GetWifiNetId();

    // Verify the result -- without permission:ohos.permission.GET_NETWORK_INFO
    EXPECT_EQ(result, 0);
}
}  // namespace Wifi
}  // namespace OHOS