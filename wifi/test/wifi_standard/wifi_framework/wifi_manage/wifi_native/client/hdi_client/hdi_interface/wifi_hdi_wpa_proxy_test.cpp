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
#include "hdf_remote_service.h"
#include "log.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
static std::string g_errLog;
void WifiHdiProLogCallback(const LogType type, const LogLevel level,
                           const unsigned int domain, const char *tag,
                           const char *msg)
{
    g_errLog = msg;
}
class WifiHdiWpaProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        LOG_SetCallback(WifiHdiProLogCallback);
    }
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaProxyTest, HdiWpaStartTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStart();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaProxyTest, HdiWpaStopTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStop();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
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
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
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
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

extern "C" void ProxyOnApRemoteDied(struct HdfDeathRecipient* recipient, struct HdfRemoteService* service);
HWTEST_F(WifiHdiWpaProxyTest, ProxyOnApRemoteDiedTest, TestSize.Level1)
{
    struct HdfDeathRecipient recipient;
    struct HdfRemoteService service;
    ProxyOnApRemoteDied(nullptr, &service);
    ProxyOnApRemoteDied(&recipient, nullptr);
    ProxyOnApRemoteDied(nullptr, nullptr);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

extern "C" WifiErrorNo RegistHdfApDeathCallBack();
HWTEST_F(WifiHdiWpaProxyTest, RegistHdfApDeathCallBackTest, TestSize.Level1)
{
    WifiErrorNo result = RegistHdfApDeathCallBack();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

extern "C" WifiErrorNo UnRegistHdfDeathCallBack();
HWTEST_F(WifiHdiWpaProxyTest, RegistHdfDeathCallBackTest, TestSize.Level1)
{
    WifiErrorNo result = UnRegistHdfDeathCallBack();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

extern "C" void RemoveIfaceName(const char* ifName);
HWTEST_F(WifiHdiWpaProxyTest, RemoveIfaceNameTest, TestSize.Level1)
{
    RemoveIfaceName(nullptr);
    RemoveIfaceName("");
    RemoveIfaceName("wlan");
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

extern "C" void AddIfaceName(const char* ifName);
HWTEST_F(WifiHdiWpaProxyTest, AddIfaceNameTest, TestSize.Level1)
{
    AddIfaceName(nullptr);
    AddIfaceName("");
    AddIfaceName("wlan");
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

extern "C" void HdiApResetGlobalObj();
HWTEST_F(WifiHdiWpaProxyTest, HdiApResetGlobalObjTest, TestSize.Level1)
{
    HdiApResetGlobalObj();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

extern "C" bool FindifaceName(const char* ifName);
HWTEST_F(WifiHdiWpaProxyTest, FindifaceNameTest, TestSize.Level1)
{
    bool result = FindifaceName(nullptr);
    EXPECT_EQ(result, true);
    result = FindifaceName("");
    EXPECT_EQ(result, true);
    result = FindifaceName("wlan0");
    EXPECT_EQ(result, false);
}

extern "C" void ProxyOnRemoteDied(struct HdfDeathRecipient* recipient, struct HdfRemoteService* service);
HWTEST_F(WifiHdiWpaProxyTest, ProxyOnRemoteDiedTest, TestSize.Level1)
{
    struct HdfDeathRecipient recipient;
    struct HdfRemoteService service;
    ProxyOnRemoteDied(nullptr, &service);
    ProxyOnRemoteDied(&recipient, nullptr);
    ProxyOnRemoteDied(nullptr, nullptr);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
}
}