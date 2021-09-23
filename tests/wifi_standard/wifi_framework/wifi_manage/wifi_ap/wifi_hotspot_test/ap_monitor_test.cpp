/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ap_monitor.h"
#include "operator_overload.h"
#include "mock_wifi_ap_hal_interface.h"

using namespace OHOS;
using ::testing::_;
using ::testing::An;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::TypedEq;

namespace OHOS {
namespace Wifi {
const std::string Mac = "AA:BB:CC:DD:EE:FF";
StationInfo staInfo = {
    "test_deviceName",
    Mac.c_str(),
    "127.0.0.1",
};
const int AP_ENABLE = 109;
const int AP_DISABLE = 110;
const int AP_FAILED = 111;
class ApMonitor_Test : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pApMonitor = new ApMonitor();
    }
    virtual void TearDown()
    {
        EXPECT_CALL(WifiApHalInterface::GetInstance(), RegisterApEvent(_))
            .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
        delete pApMonitor;
    }

public:
    void WraUnregisterHandler(const std::string &iface)
    {
        pApMonitor->UnregisterHandler(iface);
        return;
    }

public:
    ApMonitor *pApMonitor;
};

/* StationChangeEvent */

TEST_F(ApMonitor_Test, StationChangeEvent_JOIN)
{
    const int type = 105;
    EXPECT_CALL(WifiApHalInterface::GetInstance(), RegisterApEvent(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    pApMonitor->StartMonitor();
    WifiApConnectionNofify cInfo;
    cInfo.type = type;
    cInfo.mac = "AA:BB:CC:DD:EE:FF";
    pApMonitor->OnStaJoinOrLeave(cInfo);
}
TEST_F(ApMonitor_Test, StationChangeEvent_LEAVE)
{
    const int type = 106;
    WifiApConnectionNofify cInfo;
    cInfo.type = type;
    cInfo.mac = "AA:BB:CC:DD:EE:FF";
    pApMonitor->OnStaJoinOrLeave(cInfo);
}
TEST_F(ApMonitor_Test, StationChangeEvent_NULL)
{
    WifiApConnectionNofify cInfo;
    pApMonitor->OnStaJoinOrLeave(cInfo);
}
/* OnHotspotStateEvent */
TEST_F(ApMonitor_Test, OnHotspotStateEvent_ENABLE)
{
    pApMonitor->OnHotspotStateEvent(AP_ENABLE);
}

TEST_F(ApMonitor_Test, OnHotspotStateEvent_DISABLE)
{
    pApMonitor->OnHotspotStateEvent(AP_DISABLE);
}
TEST_F(ApMonitor_Test, OnHotspotStateEvent_FAILED)
{
    pApMonitor->OnHotspotStateEvent(AP_FAILED);
}

/* StartMonitor */
TEST_F(ApMonitor_Test, StartMonitor_SUCCESS)
{
    EXPECT_CALL(WifiApHalInterface::GetInstance(), RegisterApEvent(_)).WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    pApMonitor->StartMonitor();
}

/* StopMonitor */
TEST_F(ApMonitor_Test, StopMonitor_SUCCESS)
{
    EXPECT_CALL(WifiApHalInterface::GetInstance(), RegisterApEvent(An<IWifiApMonitorEventCallback>()))
        .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    pApMonitor->StopMonitor();
}
/* UnregisterHandler */
TEST_F(ApMonitor_Test, UnregisterHandler_SUCCESS)
{
    WraUnregisterHandler("wlan1");
}
} // namespace Wifi
} // namespace OHOS