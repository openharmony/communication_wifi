/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "scan_interface.h"
#include <gtest/gtest.h>
#include "mock_wifi_manager.h"
#include "mock_scan_service.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_supplicant_hal_interface.h"
#include "mock_wifi_sta_hal_interface.h"

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
class WifiEventTest : public testing::Test{
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    static void SetUp(){};
    static void TearDown(){};

    void AddEventCallbackTest()
    {
        WifiEvent *cb = nullptr;
        AddEventCallback(cb);
    }

    void OnWifiStateChangedTest()
    {
        int state = 1;s
		OnWifiStateChanged(state);
    }

    void  OnWifiRssiChangedTest()
    {
        int rssi = 1;
		OnWifiRssiChanged(rssi);
    }
    void OnWifiConnectionChangedTest()
    {
        int state = 1;
        WifiLinkedInfo linkInfo = ERROR_WIFI_INVALID_ARGS;
        OnWifiConnectionChanged(linkInfo);
    }
    void RegisterWifiEventsTest()
    {
        RegisterWifiEvents();
    }
    void IsEventRegisteredTest()
    {
        IsEventRegistered();
    }
    void SetIsEventRegistratedTest()
    {
        bool isEventRegistered = true;
        SetIsEventRegistrated(isEventRegistered);
    }

}

HWTEST_F(StaMonitorTest, AddEventCallbackTest, TestSize.Level1)
{
    AddEventCallbackTest();
}
HWTEST_F(StaMonitorTest, OnWifiStateChangedTest, TestSize.Level1)
{
    OnWifiStateChangedTest();
}
HWTEST_F(StaMonitorTest, OnWifiRssiChangedTest, TestSize.Level1)
{
    OnWifiRssiChangedTest();
}
HWTEST_F(StaMonitorTest, OnWifiConnectionChangedTest, TestSize.Level1)
{
    OnWifiConnectionChangedTest();
}
HWTEST_F(StaMonitorTest, RegisterWifiEventsTest, TestSize.Level1)
{
    RegisterWifiEventsTest();
}
HWTEST_F(StaMonitorTest, IsEventRegisteredTest, TestSize.Level1)
{
    IsEventRegisteredTest();
}
HWTEST_F(StaMonitorTest, SetIsEventRegistratedTest, TestSize.Level1)
{
    SetIsEventRegistratedTest();
}

}  // namespace Wifi
}  // namespace OHOS
