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
DEFINE_WIFILOG_LABEL("NetworkParserTest");

class NetworkParserTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_networkXmlParser = std::make_unique<NetworkXmlParser>();
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
    EXPECT_TRUE(m_networkXmlParser->HasWepKeys(wifiConfig));
}

HWTEST_F(NetworkParserTest, GetKeyMgmtTest, TestSize.Level1)
{
    WIFI_LOGI("GetKeyMgmtTest enter");
    WifiDeviceConfig wifiConfig;
    m_networkXmlParser->GetKeyMgmt(nullptr, wifiConfig);
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
}

HWTEST_F(NetworkParserTest, ParseWepKeysTest, TestSize.Level1)
{
    WIFI_LOGI("ParseWepKeysTest enter");
    WifiDeviceConfig wifiConfig;
    m_networkXmlParser->ParseWepKeys(nullptr, wifiConfig);
}

HWTEST_F(NetworkParserTest, ParseStatusTest, TestSize.Level1)
{
    WIFI_LOGI("ParseStatusTest enter");
    WifiDeviceConfig wifiConfig;
    m_networkXmlParser->ParseStatus(nullptr, wifiConfig);
}

HWTEST_F(NetworkParserTest, ParseNetworkTest, TestSize.Level1)
{
    WIFI_LOGI("ParseNetworkTest enter");
    m_networkXmlParser->ParseNetwork(nullptr);
}

HWTEST_F(NetworkParserTest, ParseNetworkListTest, TestSize.Level1)
{
    WIFI_LOGI("ParseNetworkListTest enter");
    m_networkXmlParser->ParseNetworkList(nullptr);
}

HWTEST_F(NetworkParserTest, ParseMacMapTest, TestSize.Level1)
{
    WIFI_LOGI("ParseMacMapTest enter");
    m_networkXmlParser->ParseMacMap();
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

HWTEST_F(NetworkParserTest, IsRandomMacValidFalseTest, TestSize.Level1)
{
    WIFI_LOGI("IsRandomMacValidFalseTest enter");
    WifiDeviceConfig wifiConfig;
    wifiConfig.macAddress = "02:00:00:00:00:00";
    EXPECT_FALSE(m_networkXmlParser->IsRandomMacValid(wifiConfig));
}

HWTEST_F(NetworkParserTest, GetNetworksTest, TestSize.Level1)
{
    WIFI_LOGI("GetNetworksTest enter");
    m_networkXmlParser->GetNetworks();
}

HWTEST_F(NetworkParserTest, GetRandomMacmapTest, TestSize.Level1)
{
    WIFI_LOGI("GetRandomMacmapTest enter");
    m_networkXmlParser->GetRandomMacmap();
}
}
}