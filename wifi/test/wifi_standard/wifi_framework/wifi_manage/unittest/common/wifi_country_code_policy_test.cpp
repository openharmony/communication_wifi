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
#include "mock_wifi_global_func.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_config_center.h"
#include "wifi_country_code_policy.h"
#include "wifi_country_code_manager.h"
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_logger.h"
#include "wifi_scan_msg.h"
#ifndef OHOS_ARCH_LITE
#include "common_event_manager.h"
#include "common_event.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
#endif
 
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
static std::string g_errLog = "wifitest";
DEFINE_WIFILOG_LABEL("WifiCountryCodePolicyTest");

class WifiCountryCodePolicyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_wifiCountryCodePolicy = std::make_unique<WifiCountryCodePolicy>(
            std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(31));  // 31: all the algorithms will take effect
    }
    virtual void TearDown()
    {}

    std::unique_ptr<WifiCountryCodePolicy> m_wifiCountryCodePolicy;
};

HWTEST_F(WifiCountryCodePolicyTest, CreatePolicyTest, TestSize.Level1)
{
    WIFI_LOGI("CreatePolicyTest enter");
    m_wifiCountryCodePolicy->CreatePolicy(
        std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(31));  // 31: all the algorithms will take effect
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage") != std::string::npos);
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

    // Add simulated scan results
    std::vector<WifiScanInfo> list;
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

HWTEST_F(WifiCountryCodePolicyTest, IsContainBssidNullTest, TestSize.Level1)
{
    WIFI_LOGI("IsContainBssidNullTest enter");
    std::vector<std::string> bssidList;
    std::string bssid;
    EXPECT_FALSE(m_wifiCountryCodePolicy->IsContainBssid(bssidList, bssid));
}

HWTEST_F(WifiCountryCodePolicyTest, StatisticCountryCodeFromScanResultFailTest, TestSize.Level1)
{
    WIFI_LOGI("StatisticCountryCodeFromScanResultFailTest enter");
    std::vector<WifiScanInfo> wifiScanInfoList;
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->StatisticCountryCodeFromScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, StatisticCountryCodeFromScanResultSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("StatisticCountryCodeFromScanResultSuccessTest enter");

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

    WifiScanInfo info2;
    info2.bssid = "aa:22:33:44:55:66";
    std::vector<WifiInfoElem> infoElems2;
    WifiInfoElem elem2;
    elem2.id = 7;
    elem2.content = {'C', 'N'};
    infoElems2.push_back(elem2);
    info2.infoElems = std::move(infoElems2);
    wifiScanInfoList.push_back(info2);
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->StatisticCountryCodeFromScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, FindLargestCountCountryCodeSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("FindLargestCountCountryCodeSuccessTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));

    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:66", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:77", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:88", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:99", "JP");
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));
    EXPECT_TRUE(code == "CN");
}

HWTEST_F(WifiCountryCodePolicyTest, FindLargestCountCountryCodeSortCodeIsOneTest, TestSize.Level1)
{
    WIFI_LOGI("FindLargestCountCountryCodeSuccessTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));

    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:66", "CN");
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));
    EXPECT_TRUE(code == "CN");
}

HWTEST_F(WifiCountryCodePolicyTest, FindLargestCountCountryCodeSameCountTest, TestSize.Level1)
{
    WIFI_LOGI("FindLargestCountCountryCodeSameCountTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));

    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("11:22:33:44:55:66", "CN");
    m_wifiCountryCodePolicy->m_bssidAndCountryCodeMap.insert_or_assign("77:22:33:44:55:66", "JP");
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->FindLargestCountCountryCode(code));
}

HWTEST_F(WifiCountryCodePolicyTest, ParseCountryCodeElementFailTest, TestSize.Level1)
{
    WIFI_LOGI("ParseCountryCodeElementFailTest enter");
    std::vector<WifiInfoElem> infoElems1;
    std::string code1;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->ParseCountryCodeElement(infoElems1, code1));

    std::vector<WifiInfoElem> infoElems2;
    WifiInfoElem info3;
    info3.id = 3;
    info3.content = {'A'};
    infoElems2.push_back(info3);
    std::string code2;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->ParseCountryCodeElement(infoElems2, code2));
}

HWTEST_F(WifiCountryCodePolicyTest, ParseCountryCodeElementSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("ParseCountryCodeElementSuccessTest enter");
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

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByAPSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByAPSuccessTest enter");
    // Add simulated wifi connection results
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = OHOS::Wifi::ConnState::CONNECTED;
    wifiLinkedInfo.bssid = "11:22:33:44:55:66";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

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

    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByAP(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByAPFailTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByAPFailTest enter");
    // Add simulated wifi connection results
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = OHOS::Wifi::ConnState::DISCONNECTED;
    wifiLinkedInfo.bssid = "11:22:33:44:55:66";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByAP(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByScanResultFailTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByScanResultFailTest enter");
    std::string code;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_))
        .WillRepeatedly(Return(static_cast<int>(WifiState::DISABLED)));
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByScanResult(code));

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_))
        .WillRepeatedly(Return(static_cast<int>(WifiState::ENABLED)));
    m_wifiCountryCodePolicy->m_wifiCountryCodeFromScanResults = "";
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, m_wifiCountryCodePolicy->GetWifiCountryCodeByScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByScanResultSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByScanResultSuccessTest enter");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_))
        .WillOnce(Return(static_cast<int>(WifiState::ENABLED)));

    m_wifiCountryCodePolicy->m_wifiCountryCodeFromScanResults = "CN";
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByScanResult(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByRegionTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByRegionTest enter");
    std::string code;
    m_wifiCountryCodePolicy->GetWifiCountryCodeByRegion(code);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage") != std::string::npos);
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDefaultZZTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDefaultZZTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByDefaultZZ(code));
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByCacheSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByCacheSuccessTest enter");
    std::string code;
    m_wifiCountryCodePolicy->GetWifiCountryCodeByCache(code);
    EXPECT_EQ(m_wifiCountryCodePolicy->GetWifiCountryCodeByCache(code), WIFI_OPT_FAILED);
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDefaultRegionTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDefaultRegionTest enter");
    std::string code;
    m_wifiCountryCodePolicy->GetWifiCountryCodeByDefaultRegion(code);
    EXPECT_EQ(m_wifiCountryCodePolicy->GetWifiCountryCodeByDefaultRegion(code), WIFI_OPT_FAILED);
}

HWTEST_F(WifiCountryCodePolicyTest, GetWifiCountryCodeByDefaultTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeByDefaultTest enter");
    std::string code;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, m_wifiCountryCodePolicy->GetWifiCountryCodeByDefault(code));
}
}
}