/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "wifi_app_parser.h"
#include <gtest/gtest.h>
#include <memory>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "wifi_logger.h"

using ::testing::Eq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiAppParserTest");


class AppParserTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_appXmlParser = std::make_unique<AppParser>();
        InitAppParserTest();
        m_appXmlParser->ParseAppList(root_node);
    }
    virtual void TearDown() {}

private:
    void InitAppParserTest()
    {
        root_node = xmlNewNode(NULL, BAD_CAST("MonitorAPP"));

        xmlNodePtr gameAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("GameInfo"), NULL);
        xmlNewProp(gameAppNode, BAD_CAST("gameName"), BAD_CAST "gameApp");

        xmlNodePtr whileListAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("AppWhiteList"), NULL);
        xmlNewProp(whileListAppNode, BAD_CAST("packageName"), BAD_CAST "whiteListApp");

        xmlNodePtr blackListAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("AppBlackList"), NULL);
        xmlNewProp(blackListAppNode, BAD_CAST("packageName"), BAD_CAST "blackListApp");

        xmlNodePtr chariotAppNode = xmlNewTextChild(root_node, NULL, BAD_CAST("ChariotApp"), NULL);
        xmlNewProp(chariotAppNode, BAD_CAST("packageName"), BAD_CAST "chariotApp");
    }

private:
    std::unique_ptr<AppParser> m_appXmlParser;
    xmlNodePtr root_node;
};

HWTEST_F(AppParserTest, InitAppParser, TestSize.Level1)
{
    WIFI_LOGI("InitAppParser enter");
    EXPECT_FALSE(m_appXmlParser->InitAppParser("nothing.xml"));
}

HWTEST_F(AppParserTest, ParseInternal_Fail, TestSize.Level1)
{
    WIFI_LOGI("ParseInternal_Fail enter");
    EXPECT_FALSE(m_appXmlParser->ParseInternal(nullptr));
}

HWTEST_F(AppParserTest, ParseInternal_Success, TestSize.Level1)
{
    WIFI_LOGI("ParseInternal_Success enter");
    EXPECT_TRUE(m_appXmlParser->ParseInternal(root_node));
}

HWTEST_F(AppParserTest, ParseAppList_fail, TestSize.Level1)
{
    WIFI_LOGI("ParseAppList_fail enter");
    xmlNodePtr otherNode = xmlNewNode(NULL, BAD_CAST "otherNode");
    m_appXmlParser->ParseAppList(otherNode);
    EXPECT_EQ(1, m_appXmlParser->m_lowLatencyAppVec.size());
    EXPECT_EQ(1, m_appXmlParser->m_whiteAppVec.size());
    EXPECT_EQ(1, m_appXmlParser->m_blackAppVec.size());
    EXPECT_EQ(1, m_appXmlParser->m_chariotAppVec.size());
}

HWTEST_F(AppParserTest, ParseAppList_Success, TestSize.Level1)
{
    WIFI_LOGI("ParseAppList_Success enter");
    m_appXmlParser->ParseAppList(root_node);
    EXPECT_EQ(1, m_appXmlParser->m_lowLatencyAppVec.size());
    EXPECT_EQ(1, m_appXmlParser->m_whiteAppVec.size());
    EXPECT_EQ(1, m_appXmlParser->m_blackAppVec.size());
    EXPECT_EQ(1, m_appXmlParser->m_chariotAppVec.size());
}

HWTEST_F(AppParserTest, IsLowLatencyApp_True, TestSize.Level1)
{
    WIFI_LOGI("IsLowLatencyApp_True enter");
    std::string appName = "gameApp";
    EXPECT_TRUE(m_appXmlParser->IsLowLatencyApp(appName));
}

HWTEST_F(AppParserTest, IsLowLatencyApp_False, TestSize.Level1)
{
    WIFI_LOGI("IsLowLatencyApp_False enter");
    std::string appName = "other";
    EXPECT_FALSE(m_appXmlParser->IsLowLatencyApp(appName));
}

HWTEST_F(AppParserTest, IsWhiteListApp_True, TestSize.Level1)
{
    WIFI_LOGI("IsWhiteListApp_True enter");
    std::string appName = "whiteListApp";
    EXPECT_TRUE(m_appXmlParser->IsWhiteListApp(appName));
}

HWTEST_F(AppParserTest, IsWhiteListApp_False, TestSize.Level1)
{
    WIFI_LOGI("IsWhiteListApp_False enter");
    std::string appName = "other";
    EXPECT_FALSE(m_appXmlParser->IsWhiteListApp(appName));
}

HWTEST_F(AppParserTest, IsBlackListApp_True, TestSize.Level1)
{
    WIFI_LOGI("IsBlackListApp_True enter");
    std::string appName = "blackListApp";
    EXPECT_TRUE(m_appXmlParser->IsBlackListApp(appName));
}

HWTEST_F(AppParserTest, IsBlackListApp_False, TestSize.Level1)
{
    WIFI_LOGI("IsBlackListApp_False enter");
    std::string appName = "other";
    EXPECT_FALSE(m_appXmlParser->IsBlackListApp(appName));
}

HWTEST_F(AppParserTest, IsChariotApp_True, TestSize.Level1)
{
    WIFI_LOGI("IsChariotApp_True enter");
    std::string appName = "chariotApp";
    EXPECT_TRUE(m_appXmlParser->IsChariotApp(appName));
}

HWTEST_F(AppParserTest, IsChariotApp_False, TestSize.Level1)
{
    WIFI_LOGI("IsChariotApp_False enter");
    std::string appName = "other";
    EXPECT_FALSE(m_appXmlParser->IsChariotApp(appName));
}
} // namespace Wifi
} // namespace OHOS
