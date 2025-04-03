/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include "wifi_power_state_listener_test.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"

using namespace testing::ext;
DEFINE_WIFILOG_LABEL("WifiPowerStateListenerTest");

namespace OHOS {
namespace Wifi {
static std::string g_errLog;
void WifiPowerStateListenerCallBack(const LogType type, const LogLevel level,
                                  const unsigned int domain,
                                  const char *tag, const char *msg)
{
    g_errLog = msg;
}
HWTEST_F(WifiPowerStateListenerTest, OnSyncSleepTest, TestSize.Level1)
{
    WIFI_LOGE("OnSyncSleepTest enter!");
    bool onForceSleep = true;
    WifiPowerStateListener::GetInstance().OnSyncSleep(onForceSleep);
    onForceSleep = false;
    WifiPowerStateListener::GetInstance().OnSyncSleep(onForceSleep);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiPowerStateListenerTest, OnSyncWakeupTest, TestSize.Level1)
{
    WIFI_LOGE("OnSyncWakeupTest enter!");
    bool onForceSleep = true;
    WifiPowerStateListener::GetInstance().OnSyncWakeup(onForceSleep);
    onForceSleep = false;
    WifiPowerStateListener::GetInstance().OnSyncWakeup(onForceSleep);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiPowerStateListenerTest, DealPowerEnterSleepEventTest, TestSize.Level1)
{
    WIFI_LOGE("DealPowerEnterSleepEventTest enter!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::RUNNING);
    WifiPowerStateListener::GetInstance().DealPowerEnterSleepEvent();
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
    WifiPowerStateListener::GetInstance().DealPowerEnterSleepEvent();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiPowerStateListenerTest, DealPowerExitSleepEventTest, TestSize.Level1)
{
    WIFI_LOGE("DealPowerExitSleepEventTest enter!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::RUNNING);
    WifiPowerStateListener::GetInstance().DealPowerEnterSleepEvent();
    WifiPowerStateListener::GetInstance().DealPowerExitSleepEvent();
    WifiPowerStateListener::GetInstance().DealPowerExitSleepEvent();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
}  // namespace Wifi
}  // namespace OHOS