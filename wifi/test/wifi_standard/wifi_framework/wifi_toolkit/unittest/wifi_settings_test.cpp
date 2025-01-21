/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include "securec.h"
#include "wifi_settings.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiSettingsTest");
constexpr int NETWORK_ID = 15;
constexpr int TYPE = 3;
constexpr int SCORE = 0;
constexpr int STATE = 0;
constexpr int UID = 0;
constexpr int ZERO = 0;
constexpr int WIFI_OPT_RETURN = -1;
constexpr int MIN_RSSI_2DOT_4GHZ = -80;
constexpr int MIN_RSSI_5GZ = -77;
constexpr char BACKUP_CONFIG_FILE_PATH_TEST[] = CONFIG_ROOR_DIR"/backup_config_test.conf";
static std::string g_errLog;
void WifiSetLogCallback(const LogType type, const LogLevel level,
                        const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}
class WifiSettingsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() 
    {
        LOG_SetCallback(WifiSetLogCallback);
    }
    virtual void TearDown() {}
};

HWTEST_F(WifiSettingsTest, ClearDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGE("ClearDeviceConfigTest enter!");
    WifiSettings::GetInstance().ClearDeviceConfig();
}

HWTEST_F(WifiSettingsTest, GetDeviceConfig2Test, TestSize.Level1)
{
    WIFI_LOGE("GetDeviceConfig2Test enter!");
    int networkId = ZERO;
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    WIFI_LOGE("GetDeviceConfig2Test result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetDeviceConfig3Test, TestSize.Level1)
{
    WIFI_LOGE("GetDeviceConfig3Test enter!");
    std::string ssid;
    std::string keymgmt;
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetDeviceConfig(ssid, keymgmt, config);
    WIFI_LOGE("GetDeviceConfig3Test result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetDeviceEphemeralTest, TestSize.Level1)
{
    WIFI_LOGE("SetDeviceEphemeralTest enter!");
    int result = WifiSettings::GetInstance().SetDeviceEphemeral(NETWORK_ID, false);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
    result = WifiSettings::GetInstance().SetDeviceEphemeral(NETWORK_ID, true);
    WIFI_LOGE("SetDeviceEphemeralTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetDeviceAfterConnectTest, TestSize.Level1)
{
    WIFI_LOGE("SetDeviceAfterConnectTest enter!");
    int result = WifiSettings::GetInstance().SetDeviceAfterConnect(NETWORK_ID);
    WIFI_LOGE("SetDeviceAfterConnectTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetCandidateConfigTest, TestSize.Level1)
{
    WIFI_LOGE("GetCandidateConfigTest enter!");
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetCandidateConfig(UID, NETWORK_ID, config);
    WIFI_LOGE("GetCandidateConfigTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetAllCandidateConfigTest, TestSize.Level1)
{
    WIFI_LOGE("GetAllCandidateConfigTest enter!");
    std::vector<WifiDeviceConfig> configs;
    int result = WifiSettings::GetInstance().GetAllCandidateConfig(UID, configs);
    WIFI_LOGE("GetAllCandidateConfigTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, IncreaseDeviceConnFailedCountTest, TestSize.Level1)
{
    WIFI_LOGE("IncreaseDeviceConnFailedCountTest enter!");
    std::string index;
    int indexType = ZERO;
    int count = ZERO;
    WifiSettings::GetInstance().SetDeviceConnFailedCount(index, TYPE, count);
    int result = WifiSettings::GetInstance().IncreaseDeviceConnFailedCount(index, indexType, count);
    WIFI_LOGE("IncreaseDeviceConnFailedCountTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, GetCandidateConfigWithoutUidTest, TestSize.Level1)
{
    WIFI_LOGI("GetCandidateConfigWithoutUidTest enter!");
    WifiDeviceConfig config1;
    config1.ssid = "test";
    config1.keyMgmt = "SAE";
    config1.uid  = 1;
    config1.isShared = false;
    WifiSettings::GetInstance().AddDeviceConfig(config1);
 
    WifiDeviceConfig config2;
    int result = WifiSettings::GetInstance().GetCandidateConfigWithoutUid("test", "SAE", config2);
    WIFI_LOGI("GetCandidateConfigWithoutUidTest result(%{public}d)", result);
    EXPECT_NE(result, MIN_RSSI_2DOT_4GHZ);
}
 
HWTEST_F(WifiSettingsTest, GetAllCandidateConfigWithoutUidTest, TestSize.Level1)
{
    WIFI_LOGI("GetAllCandidateConfigWithoutUidTest enter!");
    WifiDeviceConfig config1;
    config1.ssid = "test";
    config1.keyMgmt = "SAE";
    config1.uid  = 1;
    config1.isShared = false;
    WifiSettings::GetInstance().AddDeviceConfig(config1);
 
    std::vector<WifiDeviceConfig> config2;
    int result = WifiSettings::GetInstance().GetAllCandidateConfigWithoutUid(config2);
    WIFI_LOGI("GetAllCandidateConfigWithoutUidTest result(%{public}d)", result);
    EXPECT_NE(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, SetDeviceConnFailedCountTest, TestSize.Level1)
{
    WIFI_LOGE("SetDeviceConnFailedCountTest enter!");
    std::string index;
    int indexType = ZERO;
    int count = ZERO;
    WifiSettings::GetInstance().SetDeviceConnFailedCount(index, TYPE, count);
    int result = WifiSettings::GetInstance().SetDeviceConnFailedCount(index, indexType, count);
    WIFI_LOGE("SetDeviceConnFailedCountTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, AddRandomMacTest, TestSize.Level1)
{
    WIFI_LOGE("AddRandomMacTest enter!");
    WifiStoreRandomMac randomMacInfo;
    bool result = WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
    WIFI_LOGE("AddRandomMacTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, AddRandomMacTest2, TestSize.Level1)
{
    WIFI_LOGE("AddRandomMacTest2 enter!");
    WifiStoreRandomMac randomMacInfo;
    randomMacInfo.ssid = "wifitest1";
    randomMacInfo.keyMgmt = "keyMgmt";
    randomMacInfo.randomMac = "00:11:22:33:44:55";
    WifiSettings::GetInstance().mWifiStoreRandomMac.push_back(randomMacInfo);
    bool result = WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
    WIFI_LOGE("AddRandomMacTest result(%{public}d)", result);
    EXPECT_TRUE(result);
    randomMacInfo.ssid = "wifitest221";
    randomMacInfo.keyMgmt = "keyM3gmt";
    result = WifiSettings::GetInstance().AddRandomMac(randomMacInfo);
    WIFI_LOGE("AddRandomMacTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiSettingsTest, GetRandomMacTest, TestSize.Level1)
{
    WIFI_LOGE("GetRandomMacTest enter!");
    WifiStoreRandomMac randomMacInfo;
    bool result = WifiSettings::GetInstance().GetRandomMac(randomMacInfo);
    WIFI_LOGE("GetRandomMacTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, SetOperatorWifiTypeTest, TestSize.Level1)
{
    WIFI_LOGE("SetOperatorWifiTypeTest enter!");
    int result = WifiSettings::GetInstance().SetOperatorWifiType(SCORE);
    WIFI_LOGE("SetOperatorWifiTypeTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetWhetherToAllowNetworkSwitchoverTest, TestSize.Level1)
{
    WIFI_LOGE("GetWhetherToAllowNetworkSwitchoverTest enter!");
    WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover(NETWORK_ID);
    bool result = WifiSettings::GetInstance().GetWhetherToAllowNetworkSwitchover();
    WIFI_LOGE("GetWhetherToAllowNetworkSwitchoverTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, GetScoretacticsInitScoreTest, TestSize.Level1)
{
    WIFI_LOGE("GetScoretacticsInitScoreTest enter!");
    WifiSettings::GetInstance().GetScoretacticsInitScore(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetScoretacticsInitScore();
    WIFI_LOGE("GetScoretacticsInitScoreTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiSettingsTest, GetScoretacticsNormalScoreTest, TestSize.Level1)
{
    WIFI_LOGE("GetScoretacticsNormalScoreTest enter!");
    WifiSettings::GetInstance().GetScoretacticsNormalScore(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetScoretacticsNormalScore();
    WIFI_LOGE("GetScoretacticsNormalScoreTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiSettingsTest, IsModulePreLoadTest, TestSize.Level1)
{
    WIFI_LOGE("IsModulePreLoadTest enter!");
    bool state = WifiSettings::GetInstance().IsModulePreLoad("wifitest");
    EXPECT_FALSE(state);
    bool result = WifiSettings::GetInstance().IsModulePreLoad("StaService");
    WIFI_LOGE("IsModulePreLoadTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, GetSupportHwPnoFlagTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportHwPnoFlagTest enter!");
    bool state = WifiSettings::GetInstance().GetSupportHwPnoFlag(NETWORK_ID);
    EXPECT_TRUE(state);
    bool result = WifiSettings::GetInstance().GetSupportHwPnoFlag();
    WIFI_LOGE("GetSupportHwPnoFlagTest result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiSettingsTest, GetMinRssi2Dot4GhzTest, TestSize.Level1)
{
    WIFI_LOGE("GetMinRssi2Dot4GhzTest enter!");
    WifiSettings::GetInstance().GetMinRssi2Dot4Ghz(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetMinRssi2Dot4Ghz();
    WIFI_LOGE("GetMinRssi2Dot4GhzTest result(%{public}d)", result);
    EXPECT_EQ(result, MIN_RSSI_2DOT_4GHZ);
}

HWTEST_F(WifiSettingsTest, GetMinRssi5GhzTest, TestSize.Level1)
{
    WIFI_LOGE("GetMinRssi5GhzTest enter!");
    WifiSettings::GetInstance().GetMinRssi5Ghz(NETWORK_ID);
    int result = WifiSettings::GetInstance().GetMinRssi5Ghz();
    WIFI_LOGE("GetMinRssi5GhzTest result(%{public}d)", result);
    EXPECT_EQ(result, MIN_RSSI_5GZ);
}

HWTEST_F(WifiSettingsTest, SetRealMacAddressTest, TestSize.Level1)
{
    WIFI_LOGE("SetRealMacAddressTest enter!");
    std::string macAddress;
    int result = WifiSettings::GetInstance().SetRealMacAddress(macAddress);
    WIFI_LOGE("SetRealMacAddressTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, GetRealMacAddressTest, TestSize.Level1)
{
    WIFI_LOGE("GetRealMacAddressTest enter!");
    std::string macAddress;
    int state = WifiSettings::GetInstance().GetRealMacAddress(macAddress, NETWORK_ID);
    EXPECT_EQ(state, WIFI_OPT_SUCCESS);
    int result = WifiSettings::GetInstance().GetRealMacAddress(macAddress);
    WIFI_LOGE("GetRealMacAddressTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, SetDefaultFrequenciesByCountryBandTest, TestSize.Level1)
{
    WIFI_LOGE("SetDefaultFrequenciesByCountryBandTest enter!");
    std::vector<int> frequencies;
    WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, frequencies);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, SetScanOnlySwitchStateTest, TestSize.Level1)
{
    WIFI_LOGE("SetScanOnlySwitchStateTest enter!");
    WifiSettings::GetInstance().SetScanOnlySwitchState(STATE);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, GetScanOnlySwitchStateTest, TestSize.Level1)
{
    WIFI_LOGE("GetScanOnlySwitchStateTest enter!");
    int result = WifiSettings::GetInstance().GetScanOnlySwitchState(NETWORK_ID);
    result = WifiSettings::GetInstance().GetScanOnlySwitchState();
    WIFI_LOGE("GetScanOnlySwitchStateTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiSettingsTest, MergeWifiConfigTest, TestSize.Level1)
{
    WIFI_LOGI("MergeWifiConfigTest enter");
    WifiSettings::GetInstance().MergeWifiConfig();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, MergeSoftapConfigTest, TestSize.Level1)
{
    WIFI_LOGI("MergeSoftapConfigTest enter");
    WifiSettings::GetInstance().MergeSoftapConfig();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, ConfigsDeduplicateAndSaveTest, TestSize.Level1)
{
    WIFI_LOGI("ConfigsDeduplicateAndSaveTest enter");
    WifiDeviceConfig config;
    config.ssid = "test";
    config.keyMgmt = "WPA-PSK";
    std::vector<WifiDeviceConfig> configs;
    configs.push_back(config);
    WifiSettings::GetInstance().ConfigsDeduplicateAndSave(configs);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, OnBackupTest1, TestSize.Level1)
{
    WIFI_LOGI("OnBackupTest1 enter");
    UniqueFd fd(-1);
    EXPECT_EQ(WifiSettings::GetInstance().OnBackup(fd, ""), -1);
    close(fd.Release());
    WifiSettings::GetInstance().RemoveBackupFile();
}

HWTEST_F(WifiSettingsTest, OnBackupTest2, TestSize.Level1)
{
    WIFI_LOGI("OnBackupTest2 enter");
    UniqueFd fd(-1);
    std::string backupInfo = R"(
        [{
            "detail": [{
                "encryption_symkey": "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0",
                "gcmParams_iv": "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1"
            }]
        }]
    )";
    EXPECT_EQ(WifiSettings::GetInstance().OnBackup(fd, backupInfo), 0);
    close(fd.Release());
    WifiSettings::GetInstance().RemoveBackupFile();
}

HWTEST_F(WifiSettingsTest, OnRestoreTest1, TestSize.Level1)
{
    WIFI_LOGI("OnRestoreTest1 enter");
    UniqueFd fd(-1);
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, ""), -1);
    close(fd.Release());
}

HWTEST_F(WifiSettingsTest, OnRestoreTest2, TestSize.Level1)
{
    WIFI_LOGI("OnRestoreTest2 enter");
    std::vector<WifiBackupConfig> configs;
    WifiBackupConfig config;
    config.ssid = "onrestretest";
    config.keyMgmt = "WPA-PSK";
    config.preSharedKey = "12345678";
    configs.push_back(config);

    WifiConfigFileImpl<WifiBackupConfig> wifiBackupConfig;
    wifiBackupConfig.SetConfigFilePath(BACKUP_CONFIG_FILE_PATH_TEST);
    wifiBackupConfig.SetValue(configs);
    wifiBackupConfig.SaveConfig();

    UniqueFd fd(-1);
    std::string restoreInfo = R"(
        [{
            "detail": [{
                "encryption_symkey": "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0",
                "gcmParams_iv": "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1"
            }]
        }]
    )";
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, restoreInfo), -1);

    fd = UniqueFd(open(BACKUP_CONFIG_FILE_PATH_TEST, O_RDONLY));
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, restoreInfo), 0);
    close(fd.Release());
    remove(BACKUP_CONFIG_FILE_PATH_TEST);
    WifiSettings::GetInstance().RemoveBackupFile();
}

HWTEST_F(WifiSettingsTest, OnRestoreTest3, TestSize.Level1)
{
    WIFI_LOGI("OnRestoreTest3 enter");
    UniqueFd fd(-1);
    std::string restoreInfo = R"(
        [{
            "detail": [{
                "api_version": 9
            }]
        }]
    )";
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, restoreInfo), -1);

    fd = UniqueFd(open(BACKUP_CONFIG_FILE_PATH_TEST, O_CREAT | O_EXCL | O_RDWR));
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, restoreInfo), -1);

    std::string xml = R"(
        <WifiBackupData>
        <float name="Version" value="1.3" />
        <NetworkList>
        <Network>
        <WifiConfiguration>
        <string name="SSID">&quot;test&quot;</string>
        <null name="PreSharedKey" />
        <byte-array name="AllowedKeyMgmt" num="1">01</byte-array>
        </WifiConfiguration>
        </Network>
        </NetworkList>
        </WifiBackupData>
    )";
    write(fd.Get(), xml.c_str(), xml.size());
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, restoreInfo), -1);

    lseek(fd.Get(), 0, SEEK_SET);
    EXPECT_EQ(WifiSettings::GetInstance().OnRestore(fd, restoreInfo), 0);
    close(fd.Release());
    remove(BACKUP_CONFIG_FILE_PATH_TEST);
}

HWTEST_F(WifiSettingsTest, SetBackupReplyCodeTest, TestSize.Level1)
{
    WIFI_LOGI("SetBackupReplyCodeTest enter");
    std::string replyCode = WifiSettings::GetInstance().SetBackupReplyCode(0);
    std::string checkReplyCode = R"({"resultInfo":[{"errorCode":"0","errorInfo":"","type":"ErrorInfo"}]})";
    checkReplyCode += "\n";
    EXPECT_EQ(replyCode, checkReplyCode);
}

HWTEST_F(WifiSettingsTest, ConvertBackupCfgToDeviceCfgTest, TestSize.Level1)
{
    WIFI_LOGI("ConvertBackupCfgToDeviceCfgTest enter");
    WifiBackupConfig backupCfg;
    WifiDeviceConfig config;
    ConvertBackupCfgToDeviceCfg(backupCfg, config);
    EXPECT_EQ(backupCfg.instanceId, config.instanceId);
}

HWTEST_F(WifiSettingsTest, ConvertDeviceCfgToBackupCfgTest, TestSize.Level1)
{
    WIFI_LOGI("ConvertDeviceCfgToBackupCfgTest enter");
    WifiBackupConfig backupCfg;
    WifiDeviceConfig config;
    ConvertDeviceCfgToBackupCfg(config, backupCfg);
    EXPECT_EQ(backupCfg.instanceId, config.instanceId);
}

HWTEST_F(WifiSettingsTest, GetOperatorWifiTypeTest, TestSize.Level1)
{
    WIFI_LOGI("GetOperatorWifiTypeTest enter");
    WifiSettings::GetInstance().GetOperatorWifiType();
    WifiSettings::GetInstance().GetOperatorWifiType(NETWORK_ID);
    EXPECT_FALSE(WifiSettings::GetInstance().GetOperatorWifiType(NETWORK_ID));
}

HWTEST_F(WifiSettingsTest, GetCanOpenStaWhenAirplaneModeTest, TestSize.Level1)
{
    WIFI_LOGI("GetCanOpenStaWhenAirplaneModeTest enter");
    WifiSettings::GetInstance().GetCanOpenStaWhenAirplaneMode(NETWORK_ID);
    EXPECT_EQ(WifiSettings::GetInstance().GetCanOpenStaWhenAirplaneMode(NETWORK_ID), true);
}

HWTEST_F(WifiSettingsTest, AddWpsDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("AddWpsDeviceConfigTest enter");
    WifiDeviceConfig config;
    int result =  WifiSettings::GetInstance().AddWpsDeviceConfig(config);
    EXPECT_EQ(result, -1);
    WifiSettings::GetInstance().AddWpsDeviceConfig(config);
}

HWTEST_F(WifiSettingsTest, GetDeviceConfig5Test, TestSize.Level1)
{
    WIFI_LOGE("GetDeviceConfig5Test enter!");
    std::string ProcessName = "wifitest";
    int indexType = STATE;
    WifiDeviceConfig config;
    int result = WifiSettings::GetInstance().GetDeviceConfig(ProcessName, indexType, config);
    WIFI_LOGE("GetDeviceConfig5Test result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_RETURN);
}

HWTEST_F(WifiSettingsTest, ClearHotspotConfigTest, TestSize.Level1)
{
    WIFI_LOGI("ClearHotspotConfigTest enter");
    WifiSettings::GetInstance().ClearHotspotConfig();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, GetDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("GetDeviceConfigTest enter");
    std::string ancoCallProcessName = "wifitest";
    std::string ssid = "0123//45";
    std::string keymgmt = "WPA";
    WifiDeviceConfig config;
    WifiDeviceConfig configs;
    config.ssid = "0123//45";
    config.keyMgmt = "WPA";
    config.ancoCallProcessName = "wifitest";
    config.wifiEapConfig.clientCert = "//twifitest";
    WifiSettings::GetInstance().mWifiDeviceConfig.emplace(SCORE, config);
    WifiSettings::GetInstance().mWifiDeviceConfig.emplace(SCORE, configs);
    int result = WifiSettings::GetInstance().GetDeviceConfig(ssid, keymgmt, config);
    EXPECT_EQ(result, -1);
    WifiSettings::GetInstance().ClearDeviceConfig();
}

HWTEST_F(WifiSettingsTest, RemoveWifiP2pSupplicantGroupInfoTets, TestSize.Level1)
{
    WifiSettings::GetInstance().RemoveWifiP2pSupplicantGroupInfo();
    EXPECT_NE(WifiSettings::GetInstance().RemoveWifiP2pSupplicantGroupInfo(), 0);
}

HWTEST_F(WifiSettingsTest, EncryptionWifiDeviceConfigOnBootTest, TestSize.Level1)
{
    WIFI_LOGI("EncryptionWifiDeviceConfigOnBootTest enter");
    WifiSettings::GetInstance().EncryptionWifiDeviceConfigOnBoot();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiSettingsTest, EncryptionDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("EncryptionDeviceConfigTest enter");
    WifiDeviceConfig config;
    config.preSharedKey = "12345678";
    WifiSettings::GetInstance().EncryptionDeviceConfig(config);
    EXPECT_NE(WifiSettings::GetInstance().EncryptionDeviceConfig(config), false);
}

HWTEST_F(WifiSettingsTest, DecryptionDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("DecryptionDeviceConfigTest enter");
    WifiDeviceConfig config;
    config.preSharedKey = "12345678";
    WifiSettings::GetInstance().DecryptionDeviceConfig(config);
    EXPECT_NE(WifiSettings::GetInstance().DecryptionDeviceConfig(config), -1);
}

HWTEST_F(WifiSettingsTest, IsWifiDeviceConfigDecipheredTest, TestSize.Level1)
{
    WIFI_LOGI("IsWifiDeviceConfigDecipheredTest enter");
    WifiDeviceConfig config;
    config.preSharedKey = "12345678";
    WifiSettings::GetInstance().IsWifiDeviceConfigDeciphered(config);
    EXPECT_EQ(WifiSettings::GetInstance().IsWifiDeviceConfigDeciphered(config), true);
}

HWTEST_F(WifiSettingsTest, EncryptionWapiConfigTest, TestSize.Level1)
{
    WIFI_LOGI("EncryptionWapiConfigTest enter");
    WifiDeviceConfig config;
    config.keyMgmt = KEY_MGMT_WAPI_CERT;
    config.wifiWapiConfig.wapiUserCertData = "12345678";
    WifiSettings::GetInstance().EncryptionDeviceConfig(config);
    EXPECT_EQ(WifiSettings::GetInstance().EncryptionDeviceConfig(config), false);
}

HWTEST_F(WifiSettingsTest, EncryptionWapiConfigTest_001, TestSize.Level1)
{
    WIFI_LOGI("DecryptionWapiConfigTest_001 enter");
    WifiDeviceConfig config;
    WifiEncryptionInfo wifiEncryptionInfo;
    config.keyMgmt = KEY_MGMT_WAPI_CERT;
    config.wifiWapiConfig.wapiUserCertData = "12345678";
    config.wifiWapiConfig.wapiAsCertData = "abcdefg";
    WifiSettings::GetInstance().EncryptionWapiConfig(wifiEncryptionInfo, config);
    EXPECT_NE(WifiSettings::GetInstance().EncryptionWapiConfig(wifiEncryptionInfo, config), true);
}

HWTEST_F(WifiSettingsTest, DecryptionWapiConfigTest, TestSize.Level1)
{
    WIFI_LOGI("DecryptionWapiConfigTest enter");
    WifiDeviceConfig config;
    config.keyMgmt = KEY_MGMT_WAPI_CERT;
    config.wifiWapiConfig.wapiUserCertData = "12345678";
    WifiSettings::GetInstance().DecryptionDeviceConfig(config);
    EXPECT_NE(WifiSettings::GetInstance().DecryptionDeviceConfig(config),-1);
}
#ifdef SUPPORT_ClOUD_WIFI_ASSET
HWTEST_F(WifiSettingsTest, UpdateWifiConfigFormCloudTest, TestSize.Level1)
{
    WIFI_LOGE("UpdateWifiConfigFormCloudTest enter!");
    WifiDeviceConfig config;
    config.networkId = 0;
    config.ssid = "test1";
    config.keyMgmt = "WPA-PSK";
    config.preSharedKey = "123456789";
    WifiSettings::GetInstance().AddDeviceConfig(config);
    std::vector<WifiDeviceConfig> newWifiDeviceConfigs;
    // Add new WifiDeviceConfig objects to newWifiDeviceConfigs vector
    WifiDeviceConfig config1;
    config1.ssid = "test1";
    config1.keyMgmt = "WPA-PSK";
    config1.preSharedKey = "12345678";
    newWifiDeviceConfigs.push_back(config1);
    std::set<int> wifiLinkedNetworkIds;
    wifiLinkedNetworkIds.insert(0);
    wifiLinkedNetworkIds.insert(1);
    WifiSettings::GetInstance().UpdateWifiConfigFromCloud(newWifiDeviceConfigs, wifiLinkedNetworkIds);
    // Assert the updated WifiDeviceConfig objects in mWifiDeviceConfig map
    // based on the newWifiDeviceConfigs vector
    WifiDeviceConfig updatedConfig;
    WifiSettings::GetInstance().GetDeviceConfig(0, updatedConfig);
    EXPECT_EQ(updatedConfig.ssid, "test1");
    EXPECT_EQ(updatedConfig.keyMgmt, "WPA-PSK");
    EXPECT_EQ(updatedConfig.preSharedKey, "123456789");
}
#endif
}  // namespace Wifi
}  // namespace OHO
