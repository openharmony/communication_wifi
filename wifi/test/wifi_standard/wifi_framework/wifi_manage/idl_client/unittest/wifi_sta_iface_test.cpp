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
#include "i_wifi_sta_iface.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiStaIfaceTest : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    virtual void SetUp(){};
    virtual void TearDown(){};
	
    void StartScanTest()
    {
        ScanSettings *settings = nullptr;
        StartScan(settings);
    }

    void StartPnoScanTest()
    {
        PnoScanSettings *settings = nullptr;
        StartPnoScan(settings);
    }

    void StartWpsPbcModeTest()
    {
        WifiWpsParam *param = nullptr;
        StartWpsPbcMode(param);
    }

    void StartWpsPinModeTest()
    {
        WifiWpsParam *param = nullptr;
        int *pinCode = nullptr;
        StartWpsPinMode(param, pinCode);
    }

    void GetRoamingCapabilitiesTest()
    {
        WifiRoamCapability *capability = nullptr;
        GetRoamingCapabilities(capability);
    }
};
HWTEST_F(WifiStaIfaceTest, StartScanTest, TestSize.Level1)
{
    StartScanTest();
}
HWTEST_F(WifiStaIfaceTest, StartPnoScanTest, TestSize.Level1)
{
    StartPnoScanTest();
}
HWTEST_F(WifiStaIfaceTest, StartWpsPbcModeTest, TestSize.Level1)
{
    StartWpsPbcModeTest();
}
HWTEST_F(WifiStaIfaceTest, StartWpsPinModeTest, TestSize.Level1)
{
    StartWpsPinModeTest();
}
HWTEST_F(WifiStaIfaceTest, GetRoamingCapabilitiesTest, TestSize.Level1)
{
    GetRoamingCapabilitiesTest();
}
}  // namespace Wifi
}  // namespace OHOS
