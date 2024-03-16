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
DEFINE_WIFILOG_LABEL("WifiNetObserverTest");
class WifiNetObserverTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

static void NetObserverCallbackTest(SystemNetWorkState netState)
{
    WIFI_LOGI("NetObserverCallbackTest is %{public}d\n", netState);
}


HWTEST_F(WifiNetObserverTest, NetWifiObserverStartTest, TestSize.Level1)
{
    WIFI_LOGI("StartNetStateObserver enter!");
    NetStateObserver::GetInstance().StartNetStateObserver();
}

HWTEST_F(WifiNetObserverTest, NetWifiObserverStopTest, TestSize.Level1)
{
    WIFI_LOGI("StopNetStateObserver enter!");
    NetStateObserver::GetInstance().StopNetStateObserver();
}

HWTEST_F(WifiNetObserverTest, SetNetStateCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("OnAppForegroudChangedTest enter!");
    NetStateObserver::GetInstance().SetNetStateCallback(NetObserverCallbackTest);
}

HWTEST_F(WifiNetObserverTest, GetCellNetStateTest, TestSize.Level1)
{
    WIFI_LOGI("GetCellNetState enter!");
    SystemNetWorkState netState = NetStateObserver::GetInstance().GetCellNetState();
    EXPECT_EQ(true, netState <= NETWORK_IS_PORTAL);
}


}  // namespace Wifi
}  // namespace OHOS