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
#include "wifi_hdi_wpa_proxy.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiHdiWpaProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaProxyTest, HdiWpaStartTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStart();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaProxyTest, HdiWpaStopTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStop();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaProxyTest, HdiAddWpaIfaceTest, TestSize.Level1)
{
    const char ifName[10] = "Wlan1";
    const char confName[10] = "";
    WifiErrorNo result = HdiAddWpaIface(ifName, confName);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    result = HdiAddWpaIface(nullptr, confName);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    result = HdiAddWpaIface(ifName, nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaProxyTest, HdiRemoveWpaIfaceTest, TestSize.Level1)
{
    const char ifName[10] = "Wlan1";
    WifiErrorNo result = HdiRemoveWpaIface(nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    result = HdiRemoveWpaIface(ifName);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaProxyTest, CopyUserFileTest, TestSize.Level1)
{
    const char *srcFilePath;
    const char *destFilePath;
    WifiErrorNo result = CopyUserFile(srcFilePath, destFilePath);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    result = CopyUserFile(nullptr, destFilePath);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    result = CopyUserFile(srcFilePath, nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaProxyTest, CopyConfigFileTest, TestSize.Level1)
{
    const char *configName = nullptr;
    WifiErrorNo result = CopyConfigFile(configName);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaProxyTest, HdiApStartTest, TestSize.Level1)
{
    int id = 0;
    char ifaceName[10] = "Wlan0";
    WifiErrorNo result = HdiApStart(id, ifaceName);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}
}
}