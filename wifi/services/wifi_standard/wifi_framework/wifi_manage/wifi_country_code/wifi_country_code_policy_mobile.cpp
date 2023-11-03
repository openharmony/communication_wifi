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

#include "wifi_country_code_policy_mobile.h"
#include <sstream>
#include "core_service_client.h"
#include "wifi_country_code_manager.h"
#include "wifi_logger.h"
#include "wifi_global_func.h"

DEFINE_WIFILOG_LABEL("WifiCountryCodePolicyMobile");

namespace OHOS {
namespace Wifi {
constexpr int PLMN_LEN = 3;
constexpr int PLMN_SUBSTR_LEFT = 0;
constexpr int PLMN_SUBSTR_RIGHT = 3;
constexpr int32_t SLOT_ID = 0;

WifiCountryCodePolicyMobile::WifiCountryCodePolicyMobile()
{
    InitPolicy();
}

WifiCountryCodePolicyMobile::~WifiCountryCodePolicyMobile()
{
    if (m_telephoneNetworkSearchStateChangeListener != nullptr) {
        OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(m_telephoneNetworkSearchStateChangeListener);
    }
}

void WifiCountryCodePolicyMobile::InitPolicy()
{
    // Subscribe to public events of network camping status change.
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    m_telephoneNetworkSearchStateChangeListener
        = std::make_shared<TelephoneNetworkSearchStateChangeListener>(subscriberInfo);
    OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(m_telephoneNetworkSearchStateChangeListener);

    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyBase::GetWifiCountryCodeByFactory, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyMobile::GetWifiCountryCodeByMcc, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyBase::GetWifiCountryCodeByCache, this, std::placeholders::_1));
    m_policyList.emplace_back(
        std::bind(&WifiCountryCodePolicyBase::GetWifiCountryCodeByDefault, this, std::placeholders::_1));
}

ErrCode WifiCountryCodePolicyMobile::CalculateWifiCountryCode(std::string &wifiCountryCode)
{
    for (const auto &policy : m_policyList) {
        if (policy(wifiCountryCode) == WIFI_OPT_SUCCESS) {
            return WIFI_OPT_SUCCESS;
        }
    }
    return WIFI_OPT_FAILED;
}

ErrCode WifiCountryCodePolicyMobile::GetWifiCountryCodeByMcc(std::string &wifiCountryCode)
{
    std::string regPlmn1;
#ifdef TELEPHONE_CORE_SERVICE_ENABLE
    regPlmn1 = Str16ToStr8(Telephony::CoreServiceClient::GetInstance().GetOperatorNumeric(SLOT_ID));
#endif
    if (regPlmn1.empty() || regPlmn1.length() < PLMN_LEN) {
        WIFI_LOGE("get wifi country code by mcc fail, plmn invalid, plmn=%{public}s", regPlmn1.c_str());
        return WIFI_OPT_FAILED;
    }
    int integerMcc = ConvertStringToInt(regPlmn1.substr(PLMN_SUBSTR_LEFT, PLMN_SUBSTR_RIGHT));
    if (ConvertMncToIso(integerMcc, wifiCountryCode) != true) {
        WIFI_LOGE("get wifi country code by mcc fail, mcc=%{public}d", integerMcc);
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("get wifi country code by mcc success, mcc=%{public}d, code=%{public}s",
        integerMcc, wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

WifiCountryCodePolicyMobile::TelephoneNetworkSearchStateChangeListener::TelephoneNetworkSearchStateChangeListener(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{}

void WifiCountryCodePolicyMobile::TelephoneNetworkSearchStateChangeListener::OnReceiveEvent(
    const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    WIFI_LOGI("receive telephone network state change common event: %{public}s", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED) {
        WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal();
    }
}
}
}