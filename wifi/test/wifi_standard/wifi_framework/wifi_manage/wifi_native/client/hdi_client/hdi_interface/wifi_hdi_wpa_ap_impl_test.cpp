/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include "wifi_hdi_wpa_ap_impl.h"
1
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiHdiWpaApImplTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaApImplTest, HdiStartApTest, TestSize.Level1)
{
    char ifaceName[8] = "Wlan1";
    int id = 1;
    WifiErrorNo result = HdiStartAp(nullptr, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    result = HdiStartAp(ifaceName, 0);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiRegisterApEventCallbackTest, TestSize.Level1)
{
    struct IHostapdCallback *callback = nullptr;
    WifiErrorNo result = HdiRegisterApEventCallback(callback);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiReloadApConfigInfoTest, TestSize.Level1)
{
    int id = 1;
    WifiErrorNo result = HdiReloadApConfigInfo(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiEnableApTest, TestSize.Level1)
{
    int id = 1;
    WifiErrorNo result = HdiEnableAp(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiDisableApTest, TestSize.Level1)
{
    int id = 1;
    WifiErrorNo result = HdiDisableAp(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApPasswdTest, TestSize.Level1)
{
    const char pass[23] = "123456789";
    int id = 1;
    WifiErrorNo result = HdiSetApPasswd(pass, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApNamewdTest, TestSize.Level1)
{
    const char name[23] = "danzhapi";
    int id = 1;
    WifiErrorNo result = HdiSetApName(name, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApWpaValueTest, TestSize.Level1)
{
    int securityType = 1;
    int id = 1;
    WifiErrorNo result = HdiSetApWpaValue(securityType, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApBandTest, TestSize.Level1)
{
    int band = 1;
    int id = 1;
    WifiErrorNo result = HdiSetApBand(band, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetAp80211nTest, TestSize.Level1)
{
    int value = 10;
    int id = 1;
    WifiErrorNo result = HdiSetAp80211n(value, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApWmmTest, TestSize.Level1)
{
    int value = 10;
    int id = 1;
    WifiErrorNo result = HdiSetApWmm(value, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApChannelTest, TestSize.Level1)
{
    int channel = 125;
    int id = 1;
    WifiErrorNo result = HdiSetApChannel(channel, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetApMaxConnTest, TestSize.Level1)
{
    int maxConn = 125;
    int id = 1;
    WifiErrorNo result = HdiSetApMaxConn(maxConn, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiSetMacFilterTest, TestSize.Level1)
{
    const char mac[18] = "01:02:03:04:05:06";
    int id = 1;
    WifiErrorNo result = HdiSetMacFilter(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiDelMacFilterTest, TestSize.Level1)
{
    const char mac[18] = "01:02:03:04:05:06";
    int id = 1;
    WifiErrorNo result = HdiDelMacFilter(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiGetStaInfosTest, TestSize.Level1)
{
    char buf[32] = "asdfg";
    int size = 10;
    int id = 1;
    WifiErrorNo result = HdiGetStaInfos(buf, size, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaApImplTest, HdiDisassociateStaTest, TestSize.Level1)
{
    const char mac[18] = "01:02:03:04:05:06";
    int id = 1;
    WifiErrorNo result = HdiDisassociateSta(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}
}
}