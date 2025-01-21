/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include "wifi_asset_manager.h"
#include "log.h"
 
using namespace testing::ext;
namespace OHOS {
namespace Wifi {
static std::string g_errLog;
void WifiAssetLogCallback(const LogType type, const LogLevel level, 
const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}
#ifdef SUPPORT_ClOUD_WIFI_ASSET
class WifiAssetManagerTest : public testing::Test {
protected:
    void SetUp() override {
        LOG_SetCallback(WifiAssetLogCallback);
        // Set up code here
    }
 
    void TearDown() override {
        // Tear down code here
    }
};
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetUpdate, testing::ext::TestSize.Level1)
{
    WifiDeviceConfig config;
    int32_t userId = USER_ID_DEFAULT;
    WifiAssetManager::GetInstance().WifiAssetUpdate(config, userId);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetAdd, testing::ext::TestSize.Level1)
{
    WifiDeviceConfig config;
    int32_t userId = USER_ID_DEFAULT;
    bool flagSync = true;
    WifiAssetManager::GetInstance().WifiAssetAdd(config, userId, flagSync);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetQuery, testing::ext::TestSize.Level1)
{
    int32_t userId = USER_ID_DEFAULT;
    WifiAssetManager::GetInstance().WifiAssetQuery(userId);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetRemove, testing::ext::TestSize.Level1)
{
    WifiDeviceConfig config;
    int32_t userId = USER_ID_DEFAULT;
    bool flagSync = true;
    WifiAssetManager::GetInstance().WifiAssetRemove(config, userId, flagSync);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetAddPack, testing::ext::TestSize.Level1)
{
    std::vector<WifiDeviceConfig> mWifiDeviceConfig;
    int32_t userId = USER_ID_DEFAULT;
    bool flagSync = true;
    WifiAssetManager::GetInstance().WifiAssetAddPack(mWifiDeviceConfig, userId, flagSync);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetRemovePack, testing::ext::TestSize.Level1)
{
    std::vector<WifiDeviceConfig> mWifiDeviceConfig;
    int32_t userId = USER_ID_DEFAULT;
    bool flagSync = true;
    WifiAssetManager::GetInstance().WifiAssetRemovePack(mWifiDeviceConfig, userId, flagSync);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetRemoveAll, testing::ext::TestSize.Level1)
{
    int32_t userId = USER_ID_DEFAULT;
    bool flagSync = true;
    WifiAssetManager::GetInstance().WifiAssetRemoveAll(userId, flagSync);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(WifiAssetManagerTest, TestWifiAssetUpdatePack, testing::ext::TestSize.Level1)
{
    std::vector<WifiDeviceConfig> mWifiDeviceConfig;
    int32_t userId = USER_ID_DEFAULT;
    WifiAssetManager::GetInstance().WifiAssetUpdatePack(mWifiDeviceConfig, userId);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiAssetManagerTest, InitUpLoadLocalDeviceSyncTest01, testing::ext::TestSize.Level1)
{
    WifiAssetManager::GetInstance().InitUpLoadLocalDeviceSync();
    EXPECT_NE(WifiAssetManager::GetInstance().assetServiceThread_, nullptr);
}

HWTEST_F(WifiAssetManagerTest, CloudAssetSyncTest01, testing::ext::TestSize.Level1)
{
    WifiAssetManager::GetInstance().CloudAssetSync();
    EXPECT_NE(WifiAssetManager::GetInstance().assetServiceThread_, nullptr);
}

HWTEST_F(WifiAssetManagerTest, WifiAssetRemovePackTest01, testing::ext::TestSize.Level1)
{
    std::vector<WifiDeviceConfig> mWifiDeviceConfig;
    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.bssidType = 1;
    mWifiDeviceConfig.push_back(wifiDeviceConfig);

    int32_t userId = USER_ID_DEFAULT;
    bool flagSync = true;
    WifiAssetManager::GetInstance().WifiAssetRemovePack(mWifiDeviceConfig, userId, flagSync);
    EXPECT_NE(WifiAssetManager::GetInstance().assetServiceThread_, nullptr);
}

HWTEST_F(WifiAssetManagerTest, IsWifiConfigUpdatedTest01, testing::ext::TestSize.Level1)
{
    std::vector<WifiDeviceConfig> newWifiDeviceConfigs;
    WifiDeviceConfig config;
    config.uid = 1;
    config.keyMgmt = KEY_MGMT_WAPI;
    config.ssid = "TEST";

    WifiDeviceConfig config1;
    config1.ssid = "TEST";
    newWifiDeviceConfigs.push_back(config1);

    WifiAssetManager::GetInstance().IsWifiConfigUpdated(newWifiDeviceConfigs, config);
    EXPECT_NE(WifiAssetManager::GetInstance().assetServiceThread_, nullptr);
}
#endif
}  // namespace Wifi
}  // namespace OHOS