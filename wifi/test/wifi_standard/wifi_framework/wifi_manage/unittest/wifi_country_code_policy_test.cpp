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
#include <memory>
#include "wifi_config_center.h"
#include "wifi_country_code_policy.h"
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_log.h"
#include "wifi_logger.h"
#include "wifi_scan_msg.h"
#include "wifi_settings.h"
 
using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

DEFINE_WIFILOG_LABEL("WifiCountryCodePolicyTest");

namespace OHOS {
namespace Wifi {
class WifiCountryCodePolicyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_wifiCountryCodePolicy = std::make_unique<WifiCountryCodePolicy>();
    }
    virtual void TearDown()
    {}

    std::unique_ptr<WifiCountryCodePolicy> m_wifiCountryCodePolicy;
};

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodePolicyTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodePolicyTest enter");
    m_wifiCountryCodePolicy->GetWifiCountryCodePolicy();
}

HWTEST_F(WifiCountryCodePolicyTest, CreatePolicyTest, TestSize.Level1)
{
    WIFI_LOGI("CreatePolicyTest enter");
    m_wifiCountryCodePolicy->CreatePolicy();
}

HWTEST_F(WifiCountryCodePolicyTest, CalculateWifiCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGI("CalculateWifiCountryCodeTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->CalculateWifiCountryCode(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByFactoryTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByFactoryTest enter");
    std::string code;

    // Factory mode is disabled by default
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByFactory(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByMccTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByMccTest enter");
    std::string code;

    // The current OH_hone cannot reside in the cellular network without card insertion
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByMcc(code));
}

HWTEST_F(WifiCountryCodePolicyTest, HandleScanResultActionTest, TestSize.Level1)
{
    WIFI_LOGI("HandleScanResultActionTest enter");
    m_wifiCountryCodePolicy->HandleScanResultAction();
}

HWTEST_F(WifiCountryCodePolicyTest, IsContainBssidTrueTest, TestSize.Level1)
{
    WIFI_LOGI("IsContainBssidTest enter");
    std::string bssid = "11:22:33:44:55:66";
    std::vector<std::string> bssidList;
    bssidList.push_back("11:22:33:44:55:66");
    bssidList.push_back("22:22:33:44:55:66");
    EXPECT_TRUE(m_wifiCountryCodePolicy->IsContainBssid(bssidList, bssid));
}

HWTEST_F(WifiCountryCodePolicyTest, IsContainBssidFalseTest, TestSize.Level1)
{
    WIFI_LOGI("IsContainBssidTest enter");
    std::string bssid = "11:22:33:44:55:66";
    std::vector<std::string> bssidList;
    bssidList.push_back("33:22:33:44:55:66");
    bssidList.push_back("22:22:33:44:55:66");
    EXPECT_FALSE(m_wifiCountryCodePolicy->IsContainBssid(bssidList, bssid));
}

HWTEST_F(WifiCountryCodePolicyTest, StatisticCountryCodeFromScanResultTest, TestSize.Level1)
{
    WIFI_LOGI("StatisticCountryCodeFromScanResultTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->StatisticCountryCodeFromScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, FindLargestCountCountryCodeFailTest, TestSize.Level1)
{
    WIFI_LOGI("FindLargestCountCountryCodeFailTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));
}

HWTEST_F(WifiCountryCodePolicyTest, ParseCountryCodeElementTest, TestSize.Level1)
{
    WIFI_LOGI("ParseCountryCodeElementTest enter");
    WifiInfoElem info;
    info.id = 7;
    info.content = {'C', 'N'};
    std::vector<WifiInfoElem> infoElems;
    infoElems.push_back(info);
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->ParseCountryCodeElement(infoElems, code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByAPTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByAPTest enter");
    WifiLinkedInfo info;
    WifiSettings::GetInstance().GetLinkedInfo(info);
    if (info.connState == ConnState::CONNECTED) {
        std::string code;
        EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByAP(code));
    }
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByScanResultTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByScanResultTest enter");
    int state = WifiSettings::GetInstance().GetWifiState(0);
    if (state == static_cast<int>(WifiState::ENABLED)) {
        std::string code;
        EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByScanResult(code));
    }
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByRegionTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByRegionTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByRegion(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDefaultZZTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDefaultZZTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByDefaultZZ(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDbTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDbTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByDb(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDefaultRegionTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDefaultRegionTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByDefaultRegion(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDefaultTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDefaultTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByDefault(code));
}
}
}