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

DEFINE_WIFILOG_LABEL("WifiCountryCodePolicyNoMobile");

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
{
    if (m_wifiCcpCommonEventListener != nullptr) {
        OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(m_wifiCcpCommonEventListener);
    }
}

void WifiCountryCodePolicyNoMobile::Init()
{
    if (m_wifiCountryCodePolicy[FEATURE_RCV_SCAN_RESLUT]) {
        OHOS::EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED);
        OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
        std::shared_ptr<WifiCcpCommonEventListener> m_wifiCcpCommonEventListener
            = std::make_shared<WifiCcpCommonEventListener>(subscriberInfo, this);
        OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(m_wifiCcpCommonEventListener);
    }
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyBase::GetWifiCountryCodeByFactory, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByAP, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByScanResult, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByRegion, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyBase::GetWifiCountryCodeByCache, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyBase::GetWifiCountryCodeByDefault, this, std::placeholders::_1));
}

ErrCode WifiCountryCodePolicyNoMobile::CalculateWifiCountryCode(std::string &wifiCountryCode)
{
    for (const auto &policy : m_policyList) {
        if (policy(wifiCountryCode) == WIFI_OPT_SUCCESS) {
            return WIFI_OPT_SUCCESS;
        }
    }
    return WIFI_OPT_FAILED;
}

WifiCountryCodePolicyNoMobile::WifiCcpCommonEventListener::WifiCcpCommonEventListener(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo,
    WifiCountryCodePolicyNoMobile *wifiCountryCodePolicyNoMobile)
    : CommonEventSubscriber(subscriberInfo), m_wifiCountryCodePolicyNoMobile(wifiCountryCodePolicyNoMobile)
{}

void WifiCountryCodePolicyNoMobile::WifiCcpCommonEventListener::OnReceiveEvent(
    const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("receive wifi scan finish common event, action = %{public}s", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED) {
        m_wifiCountryCodePolicyNoMobile->HandleScanResultAction(eventData.GetCode());
    }
}

/*
 * If two hotspots with the same number exist in the environment (with different country codes),
 * a hotspot may not be scanned in a single scan. When the country code is selected by comparing
 * the number of hotspots, the selection changes.
 * Therefore, the latest three scanning results are collected, and the scanning results are superimposed.
 * The country code that appears most frequently is selected to reduce the risk of change.
 */
void WifiCountryCodePolicyNoMobile::HandleScanResultAction(int scanStatus)
{
    if (static_cast<int>(ScanHandleNotify::SCAN_OK) != scanStatus) {
        return;
    }
    std::vector<BssidAndCountryCode> scanInfoList;
    if (StatisticCountryCodeFromScanResult(scanInfoList) != WIFI_OPT_SUCCESS) {
        return;
    }
    m_allScanInfoList.push_back(scanInfoList);
    if (m_allScanInfoList.size() > MAX_SCAN_SAVED_SIZE) {
        m_allScanInfoList.pop_front();
    }
    std::string wifiCountryCode;
    std::map<std::string, int> codeCount;
    for (const auto &oneScanInfos : m_allScanInfoList) {
        for (const auto &info : oneScanInfos) {
            codeCount.insert_or_assign(info.wifiCountryCode, codeCount[info.wifiCountryCode] + 1);
        }
    }
    std::vector<std::pair<std::string, int>> vec(codeCount.begin(), codeCount.end());
    sort(vec.begin(), vec.end(), [](std::pair<std::string, int> a, std::pair<std::string, int> b) {
        return a.second > b.second;
    });
    std::pair<std::string, int> firstCode = vec.front();
    WIFI_LOGI("the country code with the highest quantity is %{public}s, count is %{public}d",
        firstCode.first.c_str(), firstCode.second);

    if (!IsValidCountryCode(firstCode.first)) {
        WIFI_LOGE("the country code obtained from the scann result is invalid");
        m_wifiCountryCodeFromScanResults = "";
        return;
    }
    m_wifiCountryCodeFromScanResults = firstCode.first;
    WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal();
}

ErrCode WifiCountryCodePolicyNoMobile::StatisticCountryCodeFromScanResult(
    std::vector<BssidAndCountryCode> &scanInfoList)
{
    std::vector<BssidAndCountryCode> tempScanInfoList;
    std::vector<WifiScanInfo> results;
    WifiSettings::GetInstance().GetScanInfoList(results);
    if (results.size() == 0) {
        WIFI_LOGI("get scanResult size is 0");
        return WIFI_OPT_FAILED;
    }
    for (auto &scanInfo : results) {
        std::string tempWifiCountryCode;
        ErrCode errorCode = ParseCountryCodeElement(scanInfo.infoElems, tempWifiCountryCode);
        if (errorCode == WIFI_OPT_FAILED || scanInfo.bssid.empty() || tempWifiCountryCode.empty()) {
            continue;
        }
        StrToUpper(tempWifiCountryCode);
        tempScanInfoList.push_back({scanInfo.bssid, tempWifiCountryCode});
    }
    if (tempScanInfoList.size() == 0) {
        WIFI_LOGI("get country code from scanResult size is 0");
        return WIFI_OPT_FAILED;
    }
    scanInfoList = tempScanInfoList;
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::ParseCountryCodeElement(
    std::vector<WifiInfoElem> &infoElems, std::string &wifiCountryCode)
{
    if (infoElems.size()) {
        return WIFI_OPT_FAILED;
    }
    for (const auto &ie : infoElems) {
        if (ie.id != COUNTRY_CODE_EID) {
            continue;
        }
        if (ie.content.size() < COUNTRY_CODE_LENGTH) {
            continue;
        }
        std::string tempWifiCountryCode;
        for (char c : ie.content) {
            tempWifiCountryCode.push_back(c);
        }
        wifiCountryCode = tempWifiCountryCode;
        return WIFI_OPT_SUCCESS;
    }
    return WIFI_OPT_FAILED;
}

ErrCode WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByAP(std::string &wifiCountryCode)
{
    if (!m_wifiCountryCodePolicy[FEATURE_RCV_AP_CONNECTED]) {
        return WIFI_OPT_FAILED;
    }
    WifiLinkedInfo result;
    WifiSettings::GetInstance().GetLinkedInfo(result);
    if (static_cast<int>(OHOS::Wifi::ConnState::CONNECTED) != result.connState) {
        return WIFI_OPT_FAILED;
    }
    std::vector<WifiScanInfo> scanResults;
    WifiSettings::GetInstance().GetScanInfoList(scanResults);
    if (scanResults.empty()) {
        return WIFI_OPT_FAILED;
    }
    for (auto &info : scanResults) {
        if (strcasecmp(info.bssid.c_str(), result.bssid.c_str()) == 0) {
            ParseCountryCodeElement(info.infoElems, wifiCountryCode);
            break;
        }
    }
    WIFI_LOGI("get wifi country code by ap is success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByScanResult(std::string &wifiCountryCode)
{
    if (!m_wifiCountryCodePolicy[FEATURE_RCV_SCAN_RESLUT] || m_wifiCountryCodeFromScanResults.empty()) {
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = m_wifiCountryCodeFromScanResults;
    WIFI_LOGI("get country code by scan result is success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyNoMobile::GetWifiCountryCodeByRegion(std::string &wifiCountryCode)
{
    if (!m_wifiCountryCodePolicy[FEATURE_RCV_REGION_CHANGE]) {
        return WIFI_OPT_FAILED;
    }
    std::string wifiCountryCodeStr = Global::I18n::LocaleConfig::GetSystemRegion();  // eg: zh-Hans-CN
    if (wifiCountryCodeStr.empty()) {
        WIFI_LOGE("get country code by region is fail, GetSystemRegion is empty");
        return WIFI_OPT_FAILED;
    }
    std::vector<std::string> result;
    SplitString(wifiCountryCodeStr, "-", result);
    if (result.size() != REGION_LEN || !IsValidCountryCode(result[COUNTRY_CODE_INDEX_IN_REGION])) {
        WIFI_LOGE("get country code by region is fail, the format is incorrect");
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = result[COUNTRY_CODE_INDEX_IN_REGION];
    WIFI_LOGI("get country code by region is success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}
}
}