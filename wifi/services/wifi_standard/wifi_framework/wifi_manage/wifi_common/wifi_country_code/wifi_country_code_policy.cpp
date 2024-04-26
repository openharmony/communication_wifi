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

#include "wifi_country_code_policy.h"
#include <memory>
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
#include "core_service_client.h"
#endif
#ifdef I18N_INTL_UTIL_ENABLE
#include "locale_config.h"
#endif
#include "uri.h"
#include "wifi_country_code_manager.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCountryCodePolicy");

WifiCountryCodePolicy::WifiCountryCodePolicy()
{
    CreatePolicy();
}

WifiCountryCodePolicy::~WifiCountryCodePolicy()
{
    if (m_telephoneNetworkSearchStateChangeListener != nullptr) {
        OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(m_telephoneNetworkSearchStateChangeListener);
    }
    if (m_wifiScanFinishCommonEventListener != nullptr) {
        OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(m_wifiScanFinishCommonEventListener);
    }
}

void WifiCountryCodePolicy::GetWifiCountryCodePolicy()
{
    char preValue[WIFI_COUNTRY_CODE_SIZE] = {0};
    int errorCode = GetParamValue(WIFI_COUNTRY_CODE_CONFIG,
        WIFI_COUNTRY_CODE_CONFIG_DEFAULT, preValue, WIFI_COUNTRY_CODE_SIZE);
    int policyConf = 0;
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGI("get wifi country code policy config fail, use policyConf=0");
        m_wifiCountryCodePolicyConf = std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(policyConf);
        return;
    }
    policyConf = ConvertStringToInt(preValue);
    m_wifiCountryCodePolicyConf = std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(policyConf);
    WIFI_LOGI("get wifi country code policy config is %{public}d", policyConf);
}

void WifiCountryCodePolicy::CreatePolicy()
{
    WIFI_LOGI("create wifi country code policy");
    GetWifiCountryCodePolicy();
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByFactory, this, std::placeholders::_1));
    if (m_wifiCountryCodePolicyConf[FEATURE_MCC]) {
        OHOS::EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED);
        OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
        m_telephoneNetworkSearchStateChangeListener
            = std::make_shared<TelephoneNetworkSearchStateChangeListener>(subscriberInfo);
        OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(m_telephoneNetworkSearchStateChangeListener);

        m_policyList.emplace_back(
            std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByMcc, this, std::placeholders::_1));
    }
    if (m_wifiCountryCodePolicyConf[FEATURE_RCV_AP_CONNECTED]) {
        m_policyList.emplace_back(
            std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByAP, this, std::placeholders::_1));
    }
    if (m_wifiCountryCodePolicyConf[FEATURE_RCV_SCAN_RESLUT]) {
        OHOS::EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED);
        OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
        m_wifiScanFinishCommonEventListener
            = std::make_shared<WifiScanEventListener>(subscriberInfo, this);
        OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(m_wifiScanFinishCommonEventListener);

        m_policyList.emplace_back(
            std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByScanResult, this, std::placeholders::_1));
    }
    if (m_wifiCountryCodePolicyConf[FEATURE_USE_REGION]) {
        m_policyList.emplace_back(
            std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByRegion, this, std::placeholders::_1));
    }
    if (m_wifiCountryCodePolicyConf[FEATURE_USE_ZZ]) {
        m_policyList.emplace_back(
            std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByDefaultZZ, this, std::placeholders::_1));
    }
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByCache, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByDefaultRegion, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicy::GetWifiCountryCodeByDefault, this, std::placeholders::_1));
}

ErrCode WifiCountryCodePolicy::CalculateWifiCountryCode(std::string &wifiCountryCode)
{
    for (const auto &policy : m_policyList) {
        if (policy(wifiCountryCode) == WIFI_OPT_SUCCESS) {
            return WIFI_OPT_SUCCESS;
        }
    }
    return WIFI_OPT_FAILED;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByFactory(std::string &wifiCountryCode)
{
    char roRunModeValue[WIFI_COUNTRY_CODE_RUN_MODE_SIZE] = {0};
    int errorCode = GetParamValue(WIFI_COUNTRY_CODE_RUN_MODE, DEFAULT_RO_RUN_MODE, roRunModeValue,
        WIFI_COUNTRY_CODE_RUN_MODE_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE || strcasecmp(FACTORY_RO_RUN_MODE, roRunModeValue) != 0) {
        WIFI_LOGI("wifi country code factory mode does not take effect or fail, ret=%{public}d, "
            "runMode=%{public}s", errorCode, roRunModeValue);
        return WIFI_OPT_FAILED;
    }
    char factoryWifiCountryCodeValue[FACTORY_WIFI_COUNTRY_CODE_SIZE] = {0};
    errorCode = GetParamValue(FACTORY_WIFI_COUNTRY_CODE, DEFAULT_WIFI_COUNTRY_CODE,
        factoryWifiCountryCodeValue, FACTORY_WIFI_COUNTRY_CODE_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGI("get wifi country code by factory fail, errorCode=%{public}d", errorCode);
        return WIFI_OPT_FAILED;
    }
    if (!IsValidCountryCode(factoryWifiCountryCodeValue)) {
        WIFI_LOGI("get wifi country code by factory fail, code invalid, code=%{public}s",
            factoryWifiCountryCodeValue);
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = factoryWifiCountryCodeValue;
    WIFI_LOGI("get wifi country code by factory success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByMcc(std::string &wifiCountryCode)
{
    // get cached plmn
    char cachedPlmn[OPERATOR_NUMERIC_SIZE] = {0};
    int errorCode = GetParamValue(OPERATOR_NUMERIC_KEY, DEFAULT_OPERATOR_NUMERIC, cachedPlmn, OPERATOR_NUMERIC_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE || strcasecmp(DEFAULT_OPERATOR_NUMERIC, cachedPlmn) == 0) {
        WIFI_LOGE("get wifi country code by cached mcc fail, ret=%{public}d, cachedPlmn=%{public}s",
            errorCode, cachedPlmn);
        return WIFI_OPT_FAILED;
    }
    std::string cachedPlmnStr(cachedPlmn);
    int integerCachedMcc = ConvertStringToInt(cachedPlmnStr.substr(PLMN_SUBSTR_LEFT, PLMN_SUBSTR_RIGHT));
    if (ConvertMncToIso(integerCachedMcc, wifiCountryCode) != true) {
        WIFI_LOGE("get wifi country code by cached mcc fail, cached plmn invalid, mcc=%{public}d", integerCachedMcc);
        return WIFI_OPT_FAILED;
    }
 
    // get dynamic plmn
    std::string dynamicPlmn;
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    dynamicPlmn = Str16ToStr8(Telephony::CoreServiceClient::GetInstance().GetOperatorNumeric(SLOT_ID));
#endif
    if (dynamicPlmn.empty() || dynamicPlmn.length() < PLMN_LEN) {
        WIFI_LOGI("get wifi country code by dynamic mcc fail, plmn invalid, plmn=%{public}s, use cached plmn, "
            "cache code=%{public}s", dynamicPlmn.c_str(), wifiCountryCode.c_str());
        return WIFI_OPT_SUCCESS;
    }
    int integerMcc = ConvertStringToInt(dynamicPlmn.substr(PLMN_SUBSTR_LEFT, PLMN_SUBSTR_RIGHT));
    if (ConvertMncToIso(integerMcc, wifiCountryCode) != true) {
        WIFI_LOGI("get wifi country code by dynamic mcc fail, convert fail, mcc=%{public}d, use cached plmn, "
            "cache code=%{public}s", integerMcc, wifiCountryCode.c_str());
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGI("get wifi country code by dynamic mcc success, mcc=%{public}d, code=%{public}s",
        integerMcc, wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

void WifiCountryCodePolicy::HandleScanResultAction()
{
    std::string tempWifiCountryCode;
    if (StatisticCountryCodeFromScanResult(tempWifiCountryCode) != WIFI_OPT_SUCCESS) {
        m_wifiCountryCodeFromScanResults = "";
        return;
    }
    if (!IsValidCountryCode(tempWifiCountryCode)) {
        WIFI_LOGE("the country code obtained from the scann result is invalid, code=%{public}s",
            tempWifiCountryCode.c_str());
        m_wifiCountryCodeFromScanResults = "";
        return;
    }
    m_wifiCountryCodeFromScanResults = tempWifiCountryCode;
}

bool WifiCountryCodePolicy::IsContainBssid(const std::vector<std::string> &bssidList, const std::string &bssid)
{
    if (bssidList.size() == 0 || bssid.empty()) {
        return false;
    }
    return std::find(bssidList.begin(), bssidList.end(), bssid) != bssidList.end();
}

ErrCode WifiCountryCodePolicy::StatisticCountryCodeFromScanResult(std::string &wifiCountryCode)
{
    std::vector<WifiScanInfo> results;
    WifiSettings::GetInstance().GetScanInfoList(results);
    if (results.size() == 0) {
        WIFI_LOGI("get scanResult size is 0");
        return WIFI_OPT_FAILED;
    }
    std::vector<std::string> bssidVector;
    for (auto &scanInfo : results) {
        std::string tempWifiCountryCode;
        ErrCode errorCode = ParseCountryCodeElement(scanInfo.infoElems, tempWifiCountryCode);
        if (errorCode == WIFI_OPT_FAILED || scanInfo.bssid.empty() || tempWifiCountryCode.empty()) {
            continue;
        }
        StrToUpper(tempWifiCountryCode);
        m_bssidAndCountryCodeMap.insert_or_assign(scanInfo.bssid, tempWifiCountryCode);
        bssidVector.push_back(scanInfo.bssid);
    }
    m_allBssidVector.push_back(bssidVector);
    if (m_allBssidVector.size() > MAX_SCAN_SAVED_SIZE) {
        for (const std::string &bssid : m_allBssidVector[BSSID_VECTOR_INDEX_ZERO]) {
            if (!IsContainBssid(m_allBssidVector[BSSID_VECTOR_INDEX_ONE], bssid) &&
                !IsContainBssid(m_allBssidVector[BSSID_VECTOR_INDEX_TWO], bssid) &&
                !IsContainBssid(m_allBssidVector[BSSID_VECTOR_INDEX_THREE], bssid)) {
                m_bssidAndCountryCodeMap.erase(bssid);  // remove the ap that have not been scanned recently
            }
        }
        m_allBssidVector.erase(m_allBssidVector.begin());
    }
    return FindLargestCountCountryCode(wifiCountryCode);
}

ErrCode WifiCountryCodePolicy::FindLargestCountCountryCode(std::string &wifiCountryCode)
{
    std::map<std::string, int> codeCount;  // counting the number of different country codes
    for (const auto &info : m_bssidAndCountryCodeMap) {
        codeCount.insert_or_assign(info.second, codeCount[info.second] + 1);
    }
    std::vector<std::pair<std::string, int>> sortCode(codeCount.begin(), codeCount.end());
    sort(sortCode.begin(), sortCode.end(), [](const std::pair<std::string, int> &a,
        const std::pair<std::string, int> &b) {
        return a.second > b.second;
    });
    if (sortCode.size() == 0) {
        WIFI_LOGI("country code count is zero");
        return WIFI_OPT_FAILED;
    }
    if (sortCode.size() == 1) {
        std::pair<std::string, int> oneCode = sortCode[0];
        wifiCountryCode = oneCode.first;
        WIFI_LOGI("only one country, code=%{public}s", wifiCountryCode.c_str());
        return WIFI_OPT_SUCCESS;
    }
    std::pair<std::string, int> firstCode = sortCode[0];
    std::pair<std::string, int> secondCode = sortCode[1];
    if (firstCode.second == secondCode.second) {
        WIFI_LOGI("contains two country codes with the same count and the largest count, unable to make decisions,"
            " code=%{public}s|%{public}s, count=%{public}d",
            firstCode.first.c_str(), secondCode.first.c_str(), firstCode.second);
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = firstCode.first;
    WIFI_LOGI("largest num of country code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::ParseCountryCodeElement(
    const std::vector<WifiInfoElem> &infoElems, std::string &wifiCountryCode)
{
    if (infoElems.empty()) {
        return WIFI_OPT_FAILED;
    }
    for (const auto &ie : infoElems) {
        if (ie.id != COUNTRY_CODE_EID || ie.content.size() < WIFI_COUNTRY_CODE_LEN) {
            continue;
        }
        std::string tempWifiCountryCode;
        for (int i = 0 ; i < WIFI_COUNTRY_CODE_LEN; i++) {
            tempWifiCountryCode.push_back(ie.content[i]);
        }
        if (!IsValidCountryCode(tempWifiCountryCode)) {
            continue;
        }
        wifiCountryCode = tempWifiCountryCode;
        return WIFI_OPT_SUCCESS;
    }
    return WIFI_OPT_FAILED;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByAP(std::string &wifiCountryCode)
{
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
        if (strcasecmp(info.bssid.c_str(), result.bssid.c_str()) == 0 &&
            ParseCountryCodeElement(info.infoElems, wifiCountryCode) == WIFI_OPT_SUCCESS) {
            WIFI_LOGI("get wifi country code by ap success, code=%{public}s", wifiCountryCode.c_str());
            return WIFI_OPT_SUCCESS;
        }
    }
    WIFI_LOGI("get wifi country code by ap fail, the country code of the AP is incorrect or empty");
    return WIFI_OPT_FAILED;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByScanResult(std::string &wifiCountryCode)
{
    // if wifi state is not ENABLED, do not obtain the country code from the scan results
    if (WifiSettings::GetInstance().GetWifiState(SLOT_ID) != static_cast<int>(WifiState::ENABLED) ||
        m_wifiCountryCodeFromScanResults.empty()) {
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = m_wifiCountryCodeFromScanResults;
    WIFI_LOGI("get wifi country code by scan result success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByRegion(std::string &wifiCountryCode)
{
    // the user selects an area in settings
    std::string tempWifiCountryCode;
#ifdef I18N_INTL_UTIL_ENABLE
    tempWifiCountryCode = Global::I18n::LocaleConfig::GetSystemRegion();
#endif
    if (tempWifiCountryCode.empty() || !IsValidCountryCode(tempWifiCountryCode)) {
        WIFI_LOGE("get wifi country code by region fail, code=%{public}s", tempWifiCountryCode.c_str());
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = tempWifiCountryCode;
    WIFI_LOGI("get wifi country code by region success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByDefaultZZ(std::string &wifiCountryCode)
{
    wifiCountryCode = DEFAULT_WIFI_COUNTRY_CODE_ZZ;
    WIFI_LOGI("get wifi country code by default ZZ success, code=%{public}s",
        DEFAULT_WIFI_COUNTRY_CODE_ZZ);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByCache(std::string &wifiCountryCode)
{
    char tempWifiCountryCode[WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_SIZE] = {0};
    int ret = GetParamValue(WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY, DEFAULT_WIFI_COUNTRY_CODE,
        tempWifiCountryCode, WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_SIZE);
    if (ret <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGE("get wifi country code by cache fail, ret=%{public}d", ret);
        return WIFI_OPT_FAILED;
    }
    if (!IsValidCountryCode(tempWifiCountryCode)) {
        WIFI_LOGE("get wifi country code by cache fail, code invalid, code=%{public}s", tempWifiCountryCode);
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = tempWifiCountryCode;
    WIFI_LOGI("get wifi country code by cache success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByDefaultRegion(std::string &wifiCountryCode)
{
    char defaultRegion[DEFAULT_REGION_SIZE] = {0};
    int errorCode = GetParamValue(DEFAULT_REGION_KEY,
        DEFAULT_REGION, defaultRegion, DEFAULT_REGION_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGI("get wifi country code by default region fail, errorCode=%{public}d", errorCode);
        return WIFI_OPT_FAILED;
    }
    if (!IsValidCountryCode(defaultRegion)) {
        WIFI_LOGI("get wifi country code by default region fail, code invalid, code=%{public}s", defaultRegion);
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = defaultRegion;
    WIFI_LOGI("get wifi country code by default region success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicy::GetWifiCountryCodeByDefault(std::string &wifiCountryCode)
{
    wifiCountryCode = DEFAULT_WIFI_COUNTRY_CODE;
    WIFI_LOGI("get wifi country code by default success, use default code=%{public}s",
        DEFAULT_WIFI_COUNTRY_CODE);
    return WIFI_OPT_SUCCESS;
}

WifiCountryCodePolicy::TelephoneNetworkSearchStateChangeListener::TelephoneNetworkSearchStateChangeListener(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{}

void WifiCountryCodePolicy::TelephoneNetworkSearchStateChangeListener::OnReceiveEvent(
    const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    WIFI_LOGI("receive common event: %{public}s", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED) {
        WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal();
    }
}

WifiCountryCodePolicy::WifiScanEventListener::WifiScanEventListener(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo, WifiCountryCodePolicy *wifiCountryCodePolicy)
    : CommonEventSubscriber(subscriberInfo), m_wifiCountryCodePolicyPtr(wifiCountryCodePolicy)
{}

void WifiCountryCodePolicy::WifiScanEventListener::OnReceiveEvent(
    const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("receive wifi scan finish common event, action = %{public}s, status = %{public}d",
        action.c_str(), eventData.GetCode());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED &&
        static_cast<int>(ScanHandleNotify::SCAN_OK) == eventData.GetCode() &&
        m_wifiCountryCodePolicyPtr != nullptr) {
        m_wifiCountryCodePolicyPtr->HandleScanResultAction();
        WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal();
    }
}
}
}