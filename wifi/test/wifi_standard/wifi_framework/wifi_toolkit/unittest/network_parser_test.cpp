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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <iostream>
#include <map>
#include <memory>
#include "wifi_log.h"
#include "wifi_logger.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"
#include "wifi_settings.h"
#include "network_parser.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
  
namespace OHOS {
namespace Wifi {
static std::string g_errLog;
void NetworkPLogCallback(const LogType type, const LogLevel level,
                         const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}
DEFINE_WIFILOG_LABEL("NetworkParserTest");
constexpr int TEN = 10;

class NetworkParserTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_networkXmlParser = std::make_unique<NetworkXmlParser>();
        LOG_SetCallback(NetworkPLogCallback);
    }
    virtual void TearDown() {}
private:
    std::unique_ptr<NetworkXmlParser> m_networkXmlParser;
};

HWTEST_F(NetworkParserTest, GetIpConfigTest, TestSize.Level1)
{
    WIFI_LOGI("GetIpConfigTest enter");
    EXPECT_EQ(AssignIpMethod::UNASSIGNED, m_networkXmlParser->GetIpConfig(nullptr));
}

HWTEST_F(NetworkParserTest, GotoNetworkListTest, TestSize.Level1)
{
    WIFI_LOGI("GetIpConfigTest enter");
    EXPECT_EQ(nullptr, m_networkXmlParser->GotoNetworkList(nullptr));
}

HWTEST_F(NetworkParserTest, GetConfigNameAsIntTest, TestSize.Level1)
{
    WIFI_LOGI("GetConfigNameAsIntTest enter");
    EXPECT_EQ(WifiConfigType::UNVALID, m_networkXmlParser->GetConfigNameAsInt(nullptr));
}

HWTEST_F(NetworkParserTest, GetNodeNameAsIntTest, TestSize.Level1)
{
    WIFI_LOGI("GetNodeNameAsIntTest enter");
    EXPECT_EQ(NetworkSection::UNVALID, m_networkXmlParser->GetNodeNameAsInt(nullptr));
}

HWTEST_F(NetworkParserTest, ParseIpConfigTest, TestSize.Level1)
{
    WIFI_LOGI("ParseIpConfigTest enter");
    m_networkXmlParser->ParseIpConfig(nullptr);
}

HWTEST_F(NetworkParserTest, GetProxyMethodTest, TestSize.Level1)
{
    WIFI_LOGI("GetProxyMethodTest enter");
    EXPECT_EQ(ConfigureProxyMethod::CLOSED, m_networkXmlParser->GetProxyMethod(nullptr));
}

HWTEST_F(NetworkParserTest, ParseProxyConfigTest, TestSize.Level1)
{
    WIFI_LOGI("ParseProxyConfigTest enter");
    m_networkXmlParser->ParseProxyConfig(nullptr);
}

HWTEST_F(NetworkParserTest, HasWepKeysFalseTest, TestSize.Level1)
{
    WIFI_LOGI("HasWepKeysFalseTest enter");
    WifiDeviceConfig wifiConfig;
    EXPECT_FALSE(m_networkXmlParser->HasWepKeys(wifiConfig));
}

HWTEST_F(NetworkParserTest, HasWepKeysTrueTest, TestSize.Level1)
{
    WIFI_LOGI("HasWepKeysTrueTest enter");
    WifiDeviceConfig wifiConfig;
    wifiConfig.wepKeys[0] = "test";
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, GetKeyMgmtTest, TestSize.Level1)
{
    WIFI_LOGI("GetKeyMgmtTest enter");
    WifiDeviceConfig wifiConfig;
    m_networkXmlParser->GetKeyMgmt(nullptr, wifiConfig);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, GetRandMacSettingTest, TestSize.Level1)
{
    WIFI_LOGI("GetRandMacSettingTest enter");
    EXPECT_EQ(OHOS::Wifi::WifiPrivacyConfig::RANDOMMAC, m_networkXmlParser->GetRandMacSetting(nullptr));
}

HWTEST_F(NetworkParserTest, ParseWifiConfigTest, TestSize.Level1)
{
    WIFI_LOGI("ParseWifiConfigTest enter");
    m_networkXmlParser->ParseWifiConfig(nullptr);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, ParseWepKeysTest, TestSize.Level1)
{
    WIFI_LOGI("ParseWepKeysTest enter");
    WifiDeviceConfig wifiConfig;
    m_networkXmlParser->ParseWepKeys(nullptr, wifiConfig);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, ParseNetworkTest, TestSize.Level1)
{
    WIFI_LOGI("ParseNetworkTest enter");
    m_networkXmlParser->ParseNetwork(nullptr);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, ParseNetworkListTest, TestSize.Level1)
{
    WIFI_LOGI("ParseNetworkListTest enter");
    m_networkXmlParser->ParseNetworkList(nullptr);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, GetParseTypeTest, TestSize.Level1)
{
    WIFI_LOGI("GetParseTypeTest enter");
    EXPECT_TRUE(m_networkXmlParser->GetParseType(nullptr) == NetworkParseType::UNKNOWN);
}

HWTEST_F(NetworkParserTest, EnableNetworksTest, TestSize.Level1)
{
    WIFI_LOGI("EnableNetworksTest enter");
    m_networkXmlParser->EnableNetworks();
    EXPECT_NE(m_networkXmlParser->wifiConfigs.size(), TEN);
}

HWTEST_F(NetworkParserTest, ParseInternalTest, TestSize.Level1)
{
    WIFI_LOGI("ParseInternalTest enter");
    EXPECT_FALSE(m_networkXmlParser->ParseInternal(nullptr));
}

HWTEST_F(NetworkParserTest, IsWifiConfigValidTrueTest, TestSize.Level1)
{
    WIFI_LOGI("IsWifiConfigValidTrueTest enter");
    WifiDeviceConfig wifiConfig;
    wifiConfig.keyMgmt = OHOS::Wifi::KEY_MGMT_SAE;
    EXPECT_TRUE(m_networkXmlParser->IsWifiConfigValid(wifiConfig));
}

HWTEST_F(NetworkParserTest, IsWifiConfigValidFalseTest, TestSize.Level1)
{
    WIFI_LOGI("IsWifiConfigValidFalseTest enter");
    WifiDeviceConfig wifiConfig;
    EXPECT_FALSE(m_networkXmlParser->IsWifiConfigValid(wifiConfig));
}

HWTEST_F(NetworkParserTest, GetNetworksTest, TestSize.Level1)
{
    WIFI_LOGI("GetNetworksTest enter");
    EXPECT_EQ(m_networkXmlParser->GetNetworks().size(), 0);
}

HWTEST_F(NetworkParserTest, GetRandomMacmapTest, TestSize.Level1)
{
    WIFI_LOGI("GetRandomMacmapTest enter");
    EXPECT_EQ(m_networkXmlParser->GetRandomMacmap().size(), 0);
}

HWTEST_F(NetworkParserTest, IsRandomMacValidTest, TestSize.Level1)
{
    WIFI_LOGI("IsRandomMacValidTest enter");
    std::string macAddress;
    EXPECT_FALSE(m_networkXmlParser->IsRandomMacValid(macAddress));

    macAddress = "02:00:00:00:00:00";
    EXPECT_FALSE(m_networkXmlParser->IsRandomMacValid(macAddress));

    macAddress = "02:00:00:00:00";
    EXPECT_FALSE(m_networkXmlParser->IsRandomMacValid(macAddress));

    macAddress = "01:02:03:04:05:06";
    EXPECT_TRUE(m_networkXmlParser->IsRandomMacValid(macAddress));
}

HWTEST_F(NetworkParserTest, ParseSsidTest, TestSize.Level1)
{
    WIFI_LOGI("ParseSsidTest enter");
    xmlNodePtr root = nullptr;
    WifiDeviceConfig config;
    m_networkXmlParser->ParseSsid(root, config);

    root = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr target = xmlNewChild(root, nullptr, BAD_CAST "target", nullptr);
    m_networkXmlParser->ParseSsid(target, config);

    xmlNodePtr textNode = xmlNewText(BAD_CAST "0test0");
    xmlAddChild(target, textNode);
    m_networkXmlParser->ParseSsid(target, config);
    EXPECT_TRUE(config.ssid == "test");
    xmlFreeNode(root);
}

HWTEST_F(NetworkParserTest, ParsePreSharedKeyTest, TestSize.Level1)
{
    WIFI_LOGI("ParsePreSharedKeyTest enter");
    xmlNodePtr root = nullptr;
    WifiDeviceConfig config;
    m_networkXmlParser->ParsePreSharedKey(root, config);

    root = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr target = xmlNewChild(root, nullptr, BAD_CAST "target", nullptr);
    m_networkXmlParser->ParsePreSharedKey(target, config);

    xmlNodePtr textNode = xmlNewText(BAD_CAST "0test0");
    xmlAddChild(target, textNode);
    m_networkXmlParser->ParsePreSharedKey(target, config);
    EXPECT_TRUE(config.preSharedKey == "test");
    xmlFreeNode(root);
}

HWTEST_F(NetworkParserTest, ParseInternetHistoryTest, TestSize.Level1)
{
    WIFI_LOGI("ParseInternetHistoryTest enter");
    xmlNodePtr root = nullptr;
    WifiDeviceConfig config;
    m_networkXmlParser->ParseInternetHistory(root, config);

    root = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr target = xmlNewChild(root, nullptr, BAD_CAST "target", nullptr);
    m_networkXmlParser->ParseInternetHistory(target, config);

    xmlNodePtr textNode = xmlNewText(BAD_CAST "-1/0/1/2/0/0/0/0/0/0");
    xmlAddChild(target, textNode);
    m_networkXmlParser->ParseInternetHistory(target, config);
    // -1/0/1/2/0/0/0/0/0/0 -> 11111111111110011100 -> 262119
    EXPECT_TRUE(config.networkStatusHistory == 262119);
    xmlFreeNode(root);
}

HWTEST_F(NetworkParserTest, ParseStatusTest, TestSize.Level1)
{
    WIFI_LOGI("ParseStatusTest enter");
    xmlNodePtr root = nullptr;
    WifiDeviceConfig config;
    m_networkXmlParser->ParseStatus(root, config);

    root = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr target = xmlNewChild(root, nullptr, BAD_CAST "target", nullptr);
    m_networkXmlParser->ParseStatus(target, config);

    xmlNodePtr textNode = xmlNewText(BAD_CAST "NETWORK_SELECTION_ENABLED");
    xmlAddChild(target, textNode);
    m_networkXmlParser->ParseStatus(target, config);
    xmlFreeNode(root);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(NetworkParserTest, ParseMacMapPlusTest, TestSize.Level1)
{
    WIFI_LOGI("ParseMacMapPlusTest enter");
    xmlNodePtr root = nullptr;
    m_networkXmlParser->ParseMacMapPlus(root);

    root = xmlNewNode(nullptr, BAD_CAST "root");
    xmlNodePtr macAddressMap = xmlNewChild(root, nullptr, BAD_CAST "MacAddressMap", nullptr);
    m_networkXmlParser->ParseMacMapPlus(root);

    xmlNodePtr macMapEntryPlus = xmlNewChild(macAddressMap, nullptr, BAD_CAST "map", nullptr);
    xmlNewProp(macMapEntryPlus, BAD_CAST "name", BAD_CAST "MacMapEntryPlus");
    m_networkXmlParser->ParseMacMapPlus(root);

    xmlNodePtr bssidAndMac = xmlNewChild(macMapEntryPlus, nullptr, BAD_CAST "string", BAD_CAST "00:11:22:33:44:55");
    xmlNewProp(bssidAndMac, BAD_CAST "name", BAD_CAST "xx:00:11:22:33:44:xx");
    m_networkXmlParser->ParseMacMapPlus(root);
    EXPECT_TRUE(m_networkXmlParser->wifiStoreRandomMacs[0].randomMac == "00:11:22:33:44:55");
    xmlFreeNode(root);
}

HWTEST_F(NetworkParserTest, GotoMacAddressMapTest, TestSize.Level1)
{
    WIFI_LOGI("GotoMacAddressMapTest enter");
    xmlNodePtr root = nullptr;
    EXPECT_TRUE(m_networkXmlParser->GotoMacAddressMap(root) == nullptr);
}

HWTEST_F(NetworkParserTest, SetMacByMacMapPlusTest, TestSize.Level1)
{
    WIFI_LOGI("SetMacByMacMapPlusTest enter");
    std::map<std::string, std::string> macMap;
    macMap["xx:00:11:22:33:44:xx"] = "00:11:22:33:44:55";
    macMap["xx:00:11:22:33:66:xx"] = "00:11:22:33:44:55";
    m_networkXmlParser->SetMacByMacMapPlus(macMap);
    EXPECT_TRUE(m_networkXmlParser->wifiStoreRandomMacs.size() == 1);
}

HWTEST_F(NetworkParserTest, FillupMacByConfigTest, TestSize.Level1)
{
    WIFI_LOGI("FillupMacByConfigTest enter");
    WifiDeviceConfig config;
    config.macAddress = "00:11:22:33:44:55";
    m_networkXmlParser->wifiConfigs.push_back(config);
    config.macAddress = "00:11:22:33:44:66";
    m_networkXmlParser->wifiConfigs.push_back(config);

    WifiStoreRandomMac wifiStoreRandomMac;
    wifiStoreRandomMac.randomMac = "00:11:22:33:44:55";
    m_networkXmlParser->wifiStoreRandomMacs.push_back(wifiStoreRandomMac);
    m_networkXmlParser->FillupMacByConfig();
    EXPECT_TRUE(m_networkXmlParser->wifiStoreRandomMacs.size() == 2);
}
}
}