/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../../../interfaces/kits/c/wifi_hotspot.h"
#include "../../../interfaces/kits/c/wifi_hotspot_config.h"
#include "../../../interfaces/kits/c/wifi_device_config.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
unsigned int g_status = 17;
unsigned char g_result = 5;
int g_mode = 1;
class WifiHotspotTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

public:
    void EnableHotspotTest()
    {
        EnableHotspot();
    }

    void DisableHotspotTest()
    {
        DisableHotspot();
    }

    void IsHotspotActiveTest()
    {
        IsHotspotActive();
    }

    void SetHotspotConfigTests()
    {
        HotspotConfig config;
        config.band = g_mode;
        SetHotspotConfig(&config);
    }

    void GetHotspotConfigTests()
    {
        HotspotConfig result;
        result.band = g_mode;
        GetHotspotConfig(&result);
    }

    void GetStationListTest()
    {
        StationInfo result;
        result.ipAddress = g_status;
        unsigned int *size = &g_status;
        GetStationList(&result, size);
    }

    void DisassociateStaTests()
    {
        unsigned char *mac = &g_result;
        int macLen = 0;
        DisassociateSta(mac, macLen);
    }

    void AddTxPowerInfoTests()
    {
        int power = 0;
        AddTxPowerInfo(power);
    }
};
HWTEST_F(WifiHotspotTest, EnableHotspotTest, TestSize.Level1)
{
    EnableHotspotTest();
}

HWTEST_F(WifiHotspotTest, DisableHotspotTest, TestSize.Level1)
{
    DisableHotspotTest();
}

HWTEST_F(WifiHotspotTest, IsHotspotActiveTest, TestSize.Level1)
{
    IsHotspotActiveTest();
}

HWTEST_F(WifiHotspotTest, SetHotspotConfigTests, TestSize.Level1)
{
    SetHotspotConfigTests();
}

HWTEST_F(WifiHotspotTest, GetHotspotConfigTests, TestSize.Level1)
{
    GetHotspotConfigTests();
}

HWTEST_F(WifiHotspotTest, DisassociateStaTests, TestSize.Level1)
{
    DisassociateStaTests();
}

HWTEST_F(WifiHotspotTest, AddTxPowerInfoTests, TestSize.Level1)
{
    AddTxPowerInfoTests();
}
}
}

