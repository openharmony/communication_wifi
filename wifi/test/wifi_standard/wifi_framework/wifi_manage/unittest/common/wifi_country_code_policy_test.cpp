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

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCountryCodePolicyTest");

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
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByMcc(code));
}

HWTEST_F(WifiCountryCodePolicyTest, HandleScanResultActionTest, TestSize.Level1)
{
    WIFI_LOGI("HandleScanResultActionTest enter");
    std::vector<WifiScanInfo> list;

    // Add simulated scan results
    WifiScanInfo info1;
    info1.bssid = "11:22:33:44:55:66";
    std::vector<WifiInfoElem> infoElems1;
    WifiInfoElem elem1;
    elem1.id = 7;
    elem1.content = {'C', 'N'};
    infoElems1.push_back(elem1);
    info1.infoElems = std::move(infoElems1);
    list.push_back(info1);

    WifiScanInfo info2;
    info2.bssid = "aa:22:33:44:55:66";
    std::vector<WifiInfoElem> infoElems2;
    WifiInfoElem elem2;
    elem2.id = 7;
    elem2.content = {'C', 'N'};
    infoElems2.push_back(elem2);
    info2.infoElems = std::move(infoElems2);
    list.push_back(info2);

    WifiSettings::GetInstance().SaveScanInfoList(list);
    m_wifiCountryCodePolicy->HandleScanResultAction();
}

HWTEST_F(WifiCountryCodePolicyTest, IsContainBssidTrueTest, TestSize.Level1)
{
    WIFI_LOGI("IsContainBssidTrueTest enter");
    std::string bssid = "11:22:33:44:55:66";
    std::vector<std::string> bssidList;
    bssidList.push_back("11:22:33:44:55:66");
    bssidList.push_back("22:22:33:44:55:66");
    EXPECT_TRUE(m_wifiCountryCodePolicy->IsContainBssid(bssidList, bssid));
}

HWTEST_F(WifiCountryCodePolicyTest, IsContainBssidFalseTest, TestSize.Level1)
{
    WIFI_LOGI("IsContainBssidFalseTest enter");
    std::string bssid = "11:22:33:44:55:66";
    std::vector<std::string> bssidList;
    bssidList.push_back("33:22:33:44:55:66");
    bssidList.push_back("22:22:33:44:55:66");
    EXPECT_FALSE(m_wifiCountryCodePolicy->IsContainBssid(bssidList, bssid));
}

HWTEST_F(WifiCountryCodePolicyTest, StatisticCountryCodeFromScanResultFailTest, TestSize.Level1)
{
    WIFI_LOGI("StatisticCountryCodeFromScanResultFailTest enter");
    std::vector<WifiScanInfo> list;
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->StatisticCountryCodeFromScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, StatisticCountryCodeFromScanResultSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("StatisticCountryCodeFromScanResultSuccessTest enter");
    std::vector<WifiScanInfo> wifiScanInfoList;

    // Add simulated scan results
    WifiScanInfo info1;
    info1.bssid = "11:22:33:44:55:66";
    std::vector<WifiInfoElem> infoElems1;
    WifiInfoElem elem1;
    elem1.id = 7;
    elem1.content = {'C', 'N'};
    infoElems1.push_back(elem1);
    info1.infoElems = std::move(infoElems1);
    wifiScanInfoList.push_back(info1);

    WifiScanInfo info2;
    info2.bssid = "aa:22:33:44:55:66";
    std::vector<WifiInfoElem> infoElems2;
    WifiInfoElem elem2;
    elem2.id = 7;
    elem2.content = {'C', 'N'};
    infoElems2.push_back(elem2);
    info2.infoElems = std::move(infoElems2);
    wifiScanInfoList.push_back(info2);

    WifiSettings::GetInstance().SaveScanInfoList(wifiScanInfoList);

    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->StatisticCountryCodeFromScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, FindLargestCountCountryCodeFailTest, TestSize.Level1)
{
    WIFI_LOGI("FindLargestCountCountryCodeFailTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));

    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:66", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:77", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:88", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:99", "JP");
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));
    EXPECT_TRUE(code == "CN");
}

HWTEST_F(WifiCountryCodePolicyTest, ParseCountryCodeElementTest, TestSize.Level1)
{
    WIFI_LOGI("ParseCountryCodeElementTest enter");
    std::vector<WifiInfoElem> infoElems;

    WifiInfoElem info;
    info.id = 7;
    info.content = {'C', 'N'};
    infoElems.push_back(info);

    WifiInfoElem info2;
    info2.id = 7;
    info2.content = {'J', 'P'};
    infoElems.push_back(info2);

    WifiInfoElem info3;
    info3.id = 3;
    info3.content = {'C', 'M'};
    infoElems.push_back(info3);

    WifiInfoElem info4;
    info4.id = 3;
    infoElems.push_back(info4);

    WifiInfoElem info5;
    info5.content = {'A', 'S'};
    infoElems.push_back(info5);

    WifiInfoElem info6;
    info6.id = 7;
    info6.content = {'C'};
    infoElems.push_back(info6);

    WifiInfoElem info8;
    info8.id = 7;
    info8.content = {'A', 'S', 'A', 'S'};
    infoElems.push_back(info8);

    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->ParseCountryCodeElement(infoElems, code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByAPTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByAPTest enter");
    // Add simulated scan results
    std::vector<WifiScanInfo> wifiScanInfoList;
    WifiScanInfo info1;
    info1.bssid = "11:22:33:44:55:66";
    std::vector<WifiInfoElem> infoElems1;
    WifiInfoElem elem1;
    elem1.id = 7;
    elem1.content = {'C', 'N'};
    infoElems1.push_back(elem1);
    info1.infoElems = std::move(infoElems1);
    wifiScanInfoList.push_back(info1);
    WifiSettings::GetInstance().SaveScanInfoList(wifiScanInfoList);

    // Add simulated wifi connection results
    WifiLinkedInfo info;
    info.connState = OHOS::Wifi::ConnState::CONNECTED;
    info.bssid = "11:22:33:44:55:66";
    WifiSettings::GetInstance().SaveLinkedInfo(info, 0);

    std::string code;
    m_wifiCountryCodePolicy->GetWifiCountryCodeByAP(code);
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByScanResultTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByScanResultTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByScanResult(code));

    m_wifiCountryCodePolicy->m_wifiCountryCodeFromScanResults = "CN";
    int wifiState = 3;
    int instId = 0;
    WifiSettings::GetInstance().SetWifiState(wifiState, instId);
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByScanResult(code));
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

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByCacheTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByCacheTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByCache(code));
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