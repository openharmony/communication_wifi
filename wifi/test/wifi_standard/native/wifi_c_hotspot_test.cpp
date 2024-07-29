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

#include "kits/c/wifi_hotspot.h"
#include "kits/c/wifi_hotspot_config.h"
#include "kits/c/wifi_device_config.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
unsigned int g_status = 17;
unsigned char g_result = 5;
int g_mode = 1;
const char* g_testDataLen60 = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
const char* g_testDataLen65 = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345";
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

/**
 * @tc.name: SetHotspotConfigTestsNormal
 * @tc.desc:  GetKeyMgmtFromSecurityType 函数不能直接写测试用例 没有对外暴露接口并且有static
    限制，直接通过SetHotspotConfig测试
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotTest, SetHotspotConfigTestsNormal, TestSize.Level1)
{
    HotspotConfig config;
    config.band = g_mode;
    memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, g_testDataLen60, WIFI_MAX_KEY_LEN-5);
    memcpy_s(config.ipAddress, WIFI_MAX_IPV4_LEN, "192.168.1.12", 12);
    config.securityType = WifiSecurityType::WIFI_SEC_TYPE_PSK;
    SetHotspotConfig(&config);
}

/**
 * @tc.name: SetHotspotConfigTestsException01
 * @tc.desc:  GetKeyMgmtFromSecurityType 函数不能直接写测试用例 没有对外暴露接口并且有static
    限制，直接通过SetHotspotConfig测试
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotTest, SetHotspotConfigTestsException01, TestSize.Level1)
{
    HotspotConfig *config = nullptr;
    WifiErrorCode ret = SetHotspotConfig(config);
    EXPECT_TRUE(ret == ERROR_WIFI_INVALID_ARGS);
}

/**
 * @tc.name: SetHotspotConfigTestsException02
 * @tc.desc:  GetKeyMgmtFromSecurityType 函数不能直接写测试用例 没有对外暴露接口并且有static
    限制，直接通过SetHotspotConfig测试
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotTest, SetHotspotConfigTestsException02, TestSize.Level1)
{
    HotspotConfig config;
    config.band = g_mode;
    config.securityType = WifiSecurityType::WIFI_SEC_TYPE_EAP;
    WifiErrorCode ret = SetHotspotConfig(&config);
    EXPECT_TRUE(ret == ERROR_WIFI_NOT_SUPPORTED);
}

/**
 * @tc.name: SetHotspotConfigTestsException03
 * @tc.desc:  GetKeyMgmtFromSecurityType 函数不能直接写测试用例 没有对外暴露接口并且有static
    限制，直接通过SetHotspotConfig测试
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotTest, SetHotspotConfigTestsException03, TestSize.Level1)
{
    HotspotConfig config;
    config.band = g_mode;
    config.securityType = WifiSecurityType::WIFI_SEC_TYPE_PSK;
    memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, g_testDataLen65, WIFI_MAX_KEY_LEN);
    SetHotspotConfig(&config);
}

/**
 * @tc.name: SetHotspotConfigTestsException04
 * @tc.desc:  GetKeyMgmtFromSecurityType 函数不能直接写测试用例 没有对外暴露接口并且有static
    限制，直接通过SetHotspotConfig测试
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiHotspotTest, SetHotspotConfigTestsException04, TestSize.Level1)
{
    HotspotConfig config;
    config.band = g_mode;
    config.securityType = WifiSecurityType::WIFI_SEC_TYPE_PSK;
    memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, g_testDataLen60, 60);
    memcpy_s(config.ipAddress, WIFI_MAX_IPV4_LEN, "192.168.1.1222555454545", WIFI_MAX_IPV4_LEN);
    SetHotspotConfig(&config);
}

HWTEST_F(WifiHotspotTest, GetHotspotConfigTests, TestSize.Level1)
{
    GetHotspotConfigTests();
}

HWTEST_F(WifiHotspotTest, GetStationListTests, TestSize.Level1)
{
    GetStationListTest();
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

