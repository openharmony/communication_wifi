/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "wifi_country_code_manager.h"
#include <cstdint>
#include <sstream>
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "i_ap_service.h"
#include "parameter.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_common_event_helper.h"
#include "wifi_country_code_policy_factory.h"
#include "wifi_datashare_utils.h"
#include "wifi_errcode.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_settings.h"

DEFINE_WIFILOG_LABEL("WifiCountryCodeManager");

namespace OHOS {
namespace Wifi {
constexpr const char* WIFI_COUNTRY_CODE_CONFIG = "const.wifi.country_code_no_mcc";
constexpr const char* WIFI_COUNTRY_CODE_CONFIG_DEFAULT = "0";
constexpr int32_t SYSTEM_PARAMETER_ERROR_CODE = 0;
constexpr int32_t WIFI_COUNTRY_CODE_SIZE = 16;
const std::string CLASS_NAME = "WifiCountryCodeManager";

WifiCountryCodeManager::~WifiCountryCodeManager()
{
    if (m_telephoneNetworkSearchStateChangeListener != nullptr) {
        OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(m_telephoneNetworkSearchStateChangeListener);
    }
}

WifiCountryCodeManager &WifiCountryCodeManager::GetInstance()
{
    static WifiCountryCodeManager instance;
    return instance;
}

ErrCode WifiCountryCodeManager::Init()
{
    WIFI_LOGI("init");
    char preValue[WIFI_COUNTRY_CODE_SIZE] = {0};
    int errorCode = GetParameter(WIFI_COUNTRY_CODE_CONFIG,
        WIFI_COUNTRY_CODE_CONFIG_DEFAULT, preValue, WIFI_COUNTRY_CODE_SIZE);
    int policyConf = 0;
    if (errorCode > SYSTEM_PARAMETER_ERROR_CODE) {
        policyConf = ConvertCharToInt(preValue[0]);
    }
    WIFI_LOGI("get wifi country code policy config is %{public}d", policyConf);

    std::unique_ptr<WifiCountryCodePolicyFactory> policyFactory = std::make_unique<WifiCountryCodePolicyFactory>();
    m_wifiCountryCodePolicy = policyFactory->CreatePolicy(std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(policyConf));

    // Subscribe to public events of network camping status change.
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<TelephoneNetworkSearchStateChangeListener> m_telephoneNetworkSearchStateChangeListener
        = std::make_shared<TelephoneNetworkSearchStateChangeListener>(subscriberInfo);
    OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(m_telephoneNetworkSearchStateChangeListener);

    m_staCallback.callbackModuleName = CLASS_NAME;
    m_staCallback.OnStaOpenRes = DealStaOpenRes;
    m_staCallback.OnStaConnChanged = DealStaConnChanged;
    m_apCallback.callbackModuleName = CLASS_NAME;
    m_apCallback.OnApStateChangedEvent = DealApStateChanged;
    UpdateWifiCountryCode();
    return WIFI_OPT_SUCCESS;
}

StaServiceCallback WifiCountryCodeManager::GetStaCallback()
{
    return m_staCallback;
}

IApServiceCallbacks WifiCountryCodeManager::GetApCallback()
{
    return m_apCallback;
}

void WifiCountryCodeManager::GetWifiCountryCode(std::string &wifiCountryCode)
{
    wifiCountryCode = m_wifiCountryCode;
}

ErrCode WifiCountryCodeManager::SetWifiCountryCodeFromExternal(const std::string &wifiCountryCode)
{
    WIFI_LOGI("set wifi country code from external, code=%{public}s", m_wifiCountryCode.c_str());
    return UpdateWifiCountryCode(wifiCountryCode);
}

/*
 * Scenario for updating wifi country code:
 * 1 Received a telephone network search state change notify;
 * 2 Wifi open success;
 * 4 Wifi connected or disconnected;
 * 5 Softap started;
 * 6 Update the country code by calling the SetWifiCountryCode interface externally;
 * 5 Report the scanning result.
 */
ErrCode WifiCountryCodeManager::UpdateWifiCountryCode(const std::string &externalCode)
{
    std::string wifiCountryCode;
    if (!externalCode.empty() && IsValidCountryCode(externalCode) == WIFI_OPT_SUCCESS) {
        WIFI_LOGI("external set wifi country code, code=%{public}s", externalCode.c_str());
        wifiCountryCode = externalCode;
        StrToUpper(wifiCountryCode);
    } else if (m_wifiCountryCodePolicy->CalculateWifiCountryCode(wifiCountryCode) == WIFI_OPT_FAILED) {
        WIFI_LOGE("calculate wifi country code failed");
        return WIFI_OPT_FAILED;
    }
    StrToUpper(wifiCountryCode);
    WIFI_LOGI("calculate wifi country code result:%{public}s", wifiCountryCode.c_str());
    WifiSettings::GetInstance().SetCountryCode(wifiCountryCode);
    UpdateWifiCountryCodeCache(wifiCountryCode);
    m_wifiCountryCode = wifiCountryCode;
    NotifyWifiCountryCodeChangeListeners(wifiCountryCode);
    return WIFI_OPT_SUCCESS;
}

void WifiCountryCodeManager::NotifyWifiCountryCodeChangeListeners(const std::string &wifiCountryCode)
{
    if (!m_wifiCountryCodeChangeListeners.empty()) {
        for (auto &callBackItem : m_wifiCountryCodeChangeListeners) {
            callBackItem->OnWifiCountryCodeChanged(wifiCountryCode);
        }
    }
}

ErrCode WifiCountryCodeManager::RegisterWifiCountryCodeChangeListener(
    const std::shared_ptr<IWifiCountryCodeChangeListener> &listener)
{
    m_wifiCountryCodeChangeListeners.insert(listener);
    WIFI_LOGI("register success, listener module name: %{public}s", listener->GetListenerModuleName().c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodeManager::UnregisterWifiCountryCodeChangeListener(
    const std::shared_ptr<IWifiCountryCodeChangeListener> &listener)
{
    for (auto it = m_wifiCountryCodeChangeListeners.begin(); it != m_wifiCountryCodeChangeListeners.end(); ++it) {
        if (strcasecmp(listener->GetListenerModuleName().c_str(), (*it)->GetListenerModuleName().c_str()) == 0) {
            m_wifiCountryCodeChangeListeners.erase(it);
            WIFI_LOGI("unregister success, listener module name: %{public}s",
                listener->GetListenerModuleName().c_str());
            return WIFI_OPT_SUCCESS;
        }
    }
    WIFI_LOGE("unregister fail, listener module name: %{public}s", listener->GetListenerModuleName().c_str());
    return WIFI_OPT_FAILED;
}

void WifiCountryCodeManager::DealStaOpenRes(OperateResState state, int instId)
{
    WIFI_LOGI("wifi open, state=%{public}d", state);
    if (state == OperateResState::OPEN_WIFI_SUCCEED) {
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
    }
}

void WifiCountryCodeManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    WIFI_LOGI("wifi connection state change, state=%{public}d", state);
    if (state == OperateResState::CONNECT_AP_CONNECTED || state == OperateResState::DISCONNECT_DISCONNECTING) {
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
    }
}

void WifiCountryCodeManager::DealApStateChanged(ApState state, int id)
{
    WIFI_LOGI("ap state change, state=%{public}d, id=%{public}d", state, id);
    if (state == ApState::AP_STATE_STARTED) {
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
    }
}

WifiCountryCodeManager::TelephoneNetworkSearchStateChangeListener::TelephoneNetworkSearchStateChangeListener(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{}

void WifiCountryCodeManager::TelephoneNetworkSearchStateChangeListener::OnReceiveEvent(
    const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    WIFI_LOGI("receive telephone network state change common event: %{public}s", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED) {
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
    }
}

ErrCode WifiCountryCodeManager::UpdateWifiCountryCodeCache(const std::string &wifiCountryCode)
{
    WIFI_LOGI("update wifi country code cache");
    auto wifiDataShareHelperUtils = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (wifiDataShareHelperUtils == nullptr) {
        WIFI_LOGE("database is null");
        return WIFI_OPT_FAILED;
    }
    Uri uri(SETTINGS_DATASHARE_URI_WIFI_COUNTRY_CODE);
    std::string tempWifiCountryCode;
    ErrCode ret = wifiDataShareHelperUtils->Query(uri, SETTINGS_DATASHARE_KEY_WIFI_COUNTRY_CODE, tempWifiCountryCode);
    if (ret == WIFI_OPT_FAILED) {
        WIFI_LOGI("database to insert wifi country code");
        ret = wifiDataShareHelperUtils->Insert(uri, SETTINGS_DATASHARE_KEY_WIFI_COUNTRY_CODE, wifiCountryCode);
    } else if (strcasecmp(tempWifiCountryCode.c_str(), wifiCountryCode.c_str()) != 0) {
        ret = wifiDataShareHelperUtils->Update(uri, SETTINGS_DATASHARE_KEY_WIFI_COUNTRY_CODE, wifiCountryCode);
    }
    WIFI_LOGI("database to insert or update wifi country code, ret=%{public}d", ret);
    return WIFI_OPT_SUCCESS;
}
}
}