/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "wifi_country_code_policy_no_mobile.h"
#include "locale_config.h"
#include "wifi_country_code_manager.h"
#include "wifi_errcode.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
constexpr int MAX_SCAN_SAVED_SIZE = 3;
constexpr int COUNTRY_CODE_INDEX_IN_REGION = 2;
constexpr int FEATURE_RCV_AP_CONNECTED = 0;
constexpr int FEATURE_RCV_SCAN_RESLUT = 1;
constexpr int FEATURE_RCV_REGION_CHANGE = 2;
constexpr int REGION_LEN = 3;
constexpr unsigned int COUNTRY_CODE_EID = 7;
constexpr unsigned long COUNTRY_CODE_LENGTH = 2;

WifiCountryCodePolicyNoMobile::WifiCountryCodePolicyNoMobile(
    const std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> &wifiCountryCodePolicy)
{
    m_wifiCountryCodePolicy = wifiCountryCodePolicy;
    Init();
}

WifiCountryCodePolicyNoMobile::~WifiCountryCodePolicyNoMobile()
{}

void WifiCountryCodePolicyNoMobile::Init()
{}

ErrCode WifiCountryCodePolicyNoMobile::CalculateWifiCountryCode(std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}

WifiCountryCodePolicyNoMobile::WifiCcpCommonEventListener::WifiCcpCommonEventListener(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo,
    WifiCountryCodePolicyNoMobile *wifiCountryCodePolicyNoMobile)
    : CommonEventSubscriber(subscriberInfo), m_wifiCountryCodePolicyNoMobile(wifiCountryCodePolicyNoMobile)
{}

void WifiCountryCodePolicyNoMobile::WifiCcpCommonEventListener::OnReceiveEvent(
    const OHOS::EventFwk::CommonEventData &eventData)
{}

/*
 * If two hotspots with the same number exist in the environment (with different country codes),
 * a hotspot may not be scanned in a single scan. When the country code is selected by comparing
 * the number of hotspots, the selection changes.
 * Therefore, the latest three scanning results are collected, and the scanning results are superimposed.
 * The country code that appears most frequently is selected to reduce the risk of change.
 */
void WifiCountryCodePolicyNoMobile::HandleScanResultAction(int scanStatus)
{}

ErrCode WifiCountryCodePolicyNoMobile::StatisticCountryCodeFromScanResult(
    std::vector<BssidAndCountryCode> &scanInfoList)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::ParseCountryCodeElement(
    std::vector<WifiInfoElem> &infoElems, std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByAP(std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByScanResult(std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByRegion(std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}
}
}