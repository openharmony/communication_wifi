/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "kits/c/wifi_event.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "kits/c/wifi_device.h"
#include "kits/c/wifi_scan_info.h"
#include "wifi_logger.h"

using ::testing::Return;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiCEventStubTest");

namespace OHOS {
namespace Wifi {
class WifiEventTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    virtual void SetUp() {};
    virtual void TearDown() {};

    /* Connection state change */
    static void OnWifiConnectionChanged(int state, WifiLinkedInfo *info)
    {
        WIFI_LOGE("OnWifiConnectionChanged enter!");
    }
    /* Scan state change */
    static void OnWifiScanStateChanged(int state, int size)
    {
        WIFI_LOGE("OnWifiScanStateChanged enter!");
    }
    /* Hotspot state change */
    static void OnHotspotStateChanged(int state)
    {
        WIFI_LOGE("OnHotspotStateChanged enter!");
    }
    /* Station connected */
    static void OnHotspotStaJoin(StationInfo *info)
    {
        WIFI_LOGE("OnHotspotStaJoin enter!");
    }
    /* Station disconnected */
    static void OnHotspotStaLeave(StationInfo *info)
    {
        WIFI_LOGE("OnHotspotStaLeave enter!");
    }
    /* Device config change */
    static void OnDeviceConfigChange(ConfigChange state)
    {
        WIFI_LOGE("OnDeviceConfigChange enter!");
    }

    void RegisterWifiEventErrorTest()
    {
        WIFI_LOGE("RegisterWifiEventErrorTest enter!");
        WifiEvent *event = nullptr;
        RegisterWifiEvent(event);
        EXPECT_EQ(RegisterWifiEvent(event), ERROR_WIFI_UNKNOWN);
    }
    void UnRegisterWifiEventTest()
    {
        WIFI_LOGE("UnRegisterWifiEventTest enter!");
        WifiEvent *event = nullptr;
        EXPECT_EQ(UnRegisterWifiEvent(event), WIFI_SUCCESS);
    }
    void RegisterWifiEventSuccessTest()
    {
        WIFI_LOGE("RegisterWifiEventSuccessTest enter!");
        WifiEvent event;
        event.OnWifiConnectionChanged = OnWifiConnectionChanged;
        event.OnWifiScanStateChanged = OnWifiScanStateChanged;
        event.OnHotspotStateChanged = OnHotspotStateChanged;
        event.OnHotspotStaJoin = OnHotspotStaJoin;
        event.OnHotspotStaLeave = OnHotspotStaLeave;
        event.OnDeviceConfigChange = OnDeviceConfigChange;
        EXPECT_EQ(RegisterWifiEvent(&event), WIFI_SUCCESS);
        EXPECT_EQ(UnRegisterWifiEvent(&event), WIFI_SUCCESS);
    }
};

HWTEST_F(WifiEventTest, RegisterWifiEventErrorTest, TestSize.Level1)
{
    RegisterWifiEventErrorTest();
}

HWTEST_F(WifiEventTest, UnRegisterWifiEventTest, TestSize.Level1)
{
    UnRegisterWifiEventTest();
}

HWTEST_F(WifiEventTest, RegisterWifiEventSuccessTest, TestSize.Level1)
{
    RegisterWifiEventSuccessTest();
}
}  // namespace Wifi
}  // namespace OHOS
