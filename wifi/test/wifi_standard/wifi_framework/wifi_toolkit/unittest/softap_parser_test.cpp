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
#include "softap_parser.h"

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
DEFINE_WIFILOG_LABEL("SoftapParserTest");

class SoftapParserTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_softapXmlParser  = std::make_unique<SoftapXmlParser>();
    }
    virtual void TearDown() {}
private:
    std::unique_ptr<SoftapXmlParser> m_softapXmlParser;
};

HWTEST_F(SoftapParserTest, ParseInternalTest, TestSize.Level1)
{
    WIFI_LOGI("ParseInternalTest enter");
    EXPECT_FALSE(m_softapXmlParser->ParseInternal(nullptr));
}

HWTEST_F(SoftapParserTest, GotoSoftApNodeTest, TestSize.Level1)
{
    WIFI_LOGI("GotoSoftApNodeTest enter");
    EXPECT_EQ(nullptr, m_softapXmlParser->GotoSoftApNode(nullptr));
}

HWTEST_F(SoftapParserTest, ParseSoftapTest, TestSize.Level1)
{
    WIFI_LOGI("ParseSoftapTest enter");
    m_softapXmlParser->ParseSoftap(nullptr);
}

HWTEST_F(SoftapParserTest, GetConfigNameAsIntTest, TestSize.Level1)
{
    WIFI_LOGI("GetConfigNameAsIntTest enter");
    EXPECT_EQ(HotspotConfigType::UNUSED, m_softapXmlParser->GetConfigNameAsInt(nullptr));
}

HWTEST_F(SoftapParserTest, GetBandInfoTest, TestSize.Level1)
{
    WIFI_LOGI("GetBandInfoTest enter");
    m_softapXmlParser->GetBandInfo(nullptr);
}

HWTEST_F(SoftapParserTest, TransBandinfoTest, TestSize.Level1)
{
    WIFI_LOGI("TransBandinfoTest enter");
    m_softapXmlParser->TransBandinfo(nullptr);
}

HWTEST_F(SoftapParserTest, GetSoftapConfigsTest, TestSize.Level1)
{
    WIFI_LOGI("GetSoftapConfigsTest enter");
    m_softapXmlParser->GetSoftapConfigs();
}
}
}