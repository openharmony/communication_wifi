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
#include "wifi_event_subscriber_manager_test.h"
#include "wifi_logger.h"

using namespace testing::ext;
DEFINE_WIFILOG_LABEL("WifiEventSubscriberManagerTest");


namespace OHOS {
namespace Wifi {

constexpr int32_t COMMON_EVENT_SERVICE_ID = 3299;

HWTEST_F(WifiEventSubscriberManagerTest, HandleCesServiceChange_Add_True, TestSize.Level1)
{
    WIFI_LOGE("HandleCesServiceChange_Add_True enter!");
    WifiEventSubscriberManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.HandleCesServiceChange(true));
}

HWTEST_F(WifiEventSubscriberManagerTest, HandleCesServiceChange_Add_False, TestSize.Level1)
{
    WIFI_LOGE("HandleCesServiceChange_Add_False enter!");
    WifiEventSubscriberManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.HandleCesServiceChange(false));
}

HWTEST_F(WifiEventSubscriberManagerTest, OnSystemAbilityChanged_CesSa_Add, TestSize.Level1)
{
    WIFI_LOGE("OnSystemAbilityChanged_CesSa_Add enter!");
    WifiEventSubscriberManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.OnSystemAbilityChanged(COMMON_EVENT_SERVICE_ID, true));
}

HWTEST_F(WifiEventSubscriberManagerTest, OnSystemAbilityChanged_CesSa_Remove, TestSize.Level1)
{
    WIFI_LOGE("OnSystemAbilityChanged_CesSa_Remove enter!");
    WifiEventSubscriberManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.OnSystemAbilityChanged(COMMON_EVENT_SERVICE_ID, false));
}

HWTEST_F(WifiEventSubscriberManagerTest, OnSystemAbilityChanged_OtherSa, TestSize.Level1)
{
    WIFI_LOGE("OnSystemAbilityChanged_OtherSa enter!");
    WifiEventSubscriberManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.OnSystemAbilityChanged(1234, true));
    EXPECT_NO_FATAL_FAILURE(manager.OnSystemAbilityChanged(1234, false));
}
}  // namespace Wifi
}  // namespace OHOS
