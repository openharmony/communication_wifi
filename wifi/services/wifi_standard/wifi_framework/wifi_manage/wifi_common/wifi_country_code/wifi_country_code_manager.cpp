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
#include "i_ap_service.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_common_event_helper.h"
#include "wifi_datashare_utils.h"
#include "wifi_errcode.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_config_center.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCountryCodeManager");
const std::string CLASS_NAME = "WifiCountryCodeManager";

WifiCountryCodeManager::~WifiCountryCodeManager()
{
    std::lock_guard<std::mutex> lock(m_countryCodeMutex);
    m_codeChangeListeners.clear();
}

WifiCountryCodeManager &WifiCountryCodeManager::GetInstance()
{
    static WifiCountryCodeManager instance;
    return instance;
}

ErrCode WifiCountryCodeManager::Init()
{
    WIFI_LOGI("init");
    wifiCountryCodePolicyConf_ = GetWifiCountryCodePolicy();
    m_wifiCountryCodePolicy = std::make_shared<WifiCountryCodePolicy>(wifiCountryCodePolicyConf_);
#ifdef FEATURE_STA_SUPPORT
    m_staCallback.callbackModuleName = CLASS_NAME;
    m_staCallback.OnStaConnChanged = DealStaConnChanged;
#endif

#ifdef FEATURE_AP_SUPPORT
    m_apCallback.callbackModuleName = CLASS_NAME;
    m_apCallback.OnApStateChangedEvent = DealApStateChanged;
#endif
    return WIFI_OPT_SUCCESS;
}

#ifdef FEATURE_STA_SUPPORT
StaServiceCallback WifiCountryCodeManager::GetStaCallback() const
{
    return m_staCallback;
}
#endif

#ifdef FEATURE_AP_SUPPORT
IApServiceCallbacks WifiCountryCodeManager::GetApCallback() const
{
    return m_apCallback;
}
#endif

void WifiCountryCodeManager::GetWifiCountryCode(std::string &wifiCountryCode) const
{
    wifiCountryCode = m_wifiCountryCode;
}

ErrCode WifiCountryCodeManager::SetWifiCountryCodeFromExternal(const std::string &wifiCountryCode)
{
    WIFI_LOGD("set wifi country code from external, externalCode=%{public}s", wifiCountryCode.c_str());
    return UpdateWifiCountryCode(wifiCountryCode);
}

void WifiCountryCodeManager::TriggerUpdateWifiCountryCode(int triggerReason)
{
    if (triggerReason == TRIGGER_UPDATE_REASON_TEL_NET_CHANGE && wifiCountryCodePolicyConf_[FEATURE_MCC]) {
        WIFI_LOGI("TEL_NET_CHANGE trigger update country code change");
        UpdateWifiCountryCode();
    } else if (triggerReason == TRIGGER_UPDATE_REASON_SCAN_CHANGE &&
        wifiCountryCodePolicyConf_[FEATURE_RCV_SCAN_RESLUT] && m_wifiCountryCodePolicy != nullptr) {
        m_wifiCountryCodePolicy->HandleScanResultAction();
        UpdateWifiCountryCode();
    }
}

bool WifiCountryCodeManager::IsAllowUpdateWifiCountryCode()
{
    bool ret = true;

    // The Wi-Fi connection has just succeeded. Updating the country code is allowed.
    if (m_isFirstConnected) {
        WIFI_LOGI("wifi first connected, allow update wifi country code");
        m_isFirstConnected = false;
        return ret;
    }

    std::map <int, WifiLinkedInfo> allLinkedInfo = WifiConfigCenter::GetInstance().GetAllWifiLinkedInfo();
    for (auto item : allLinkedInfo) {
        if (item.second.connState == ConnState::CONNECTED) {
            WIFI_LOGI("wifi connected, not allow update wifi country code, instId=%{public}d", item.first);
            ret = false;
            break;
        }
    }
    return ret;
}

/*
 * Scenarios that trigger country code update, with configuration files controlling the effectiveness of the scenario:
 * 1 Received a telephone network search state change notify;
 * 2 Wifi open success;
 * 3 Softap started;
 * 4 Update the country code by calling the SetWifiCountryCode interface externally;
 * 5 Report the scanning result.
 */
ErrCode WifiCountryCodeManager::UpdateWifiCountryCode(const std::string &externalCode)
{
    if (!IsAllowUpdateWifiCountryCode()) {
        return WIFI_OPT_FAILED;
    }
    std::string wifiCountryCode;
    if (!externalCode.empty() && !IsValidCountryCode(externalCode)) {
        WIFI_LOGI("external set wifi country code, code=%{public}s", externalCode.c_str());
        wifiCountryCode = externalCode;
    } else if (m_wifiCountryCodePolicy == nullptr ||
        m_wifiCountryCodePolicy->CalculateWifiCountryCode(wifiCountryCode) == WIFI_OPT_FAILED) {
        WIFI_LOGE("calculate wifi country code failed");
        return WIFI_OPT_FAILED;
    }
    StrToUpper(wifiCountryCode);
    WIFI_LOGI("calculate wifi country code result:%{public}s", wifiCountryCode.c_str());
    UpdateWifiCountryCodeCache(wifiCountryCode);
    m_wifiCountryCode = wifiCountryCode;
    NotifyWifiCountryCodeChangeListeners(wifiCountryCode);
    return WIFI_OPT_SUCCESS;
}

void WifiCountryCodeManager::NotifyWifiCountryCodeChangeListeners(const std::string &wifiCountryCode)
{
    std::lock_guard<std::mutex> lock(m_countryCodeMutex);
    for (auto &callBackItem : m_codeChangeListeners) {
        WIFI_LOGI("notify wifi country code change, module name=%{public}s", callBackItem.first.c_str());
        callBackItem.second->OnWifiCountryCodeChanged(wifiCountryCode);
    }
}

ErrCode WifiCountryCodeManager::RegisterWifiCountryCodeChangeListener(
    const std::shared_ptr<IWifiCountryCodeChangeListener> &listener)
{
    std::lock_guard<std::mutex> lock(m_countryCodeMutex);
    if (listener->GetListenerModuleName().empty()) {
        WIFI_LOGE("register fail, listener module name is null");
        return WIFI_OPT_FAILED;
    }
    m_codeChangeListeners.insert_or_assign(listener->GetListenerModuleName(), listener);
    WIFI_LOGI("register success, listener module name: %{public}s", listener->GetListenerModuleName().c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodeManager::UnregisterWifiCountryCodeChangeListener(
    const std::shared_ptr<IWifiCountryCodeChangeListener> &listener)
{
    return UnregisterWifiCountryCodeChangeListener(listener->GetListenerModuleName());
}

ErrCode WifiCountryCodeManager::UnregisterWifiCountryCodeChangeListener(const std::string &moduleName)
{
    std::lock_guard<std::mutex> lock(m_countryCodeMutex);
    if (moduleName.empty()) {
        WIFI_LOGE("unregister fail, listener module name is null");
        return WIFI_OPT_FAILED;
    }
    int ret = static_cast<int>(m_codeChangeListeners.erase(moduleName));
    WIFI_LOGI("unregister ret=%{public}d, listener module name: %{public}s", ret, moduleName.c_str());
    return ret > 0 ? WIFI_OPT_SUCCESS : WIFI_OPT_FAILED;
}

#ifdef FEATURE_STA_SUPPORT
void WifiCountryCodeManager::DealStaOpened(int instId)
{
    WIFI_LOGI("wifi opened, id=%{public}d", instId);
    WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
}

void WifiCountryCodeManager::DealStaStopped(int instId)
{
    WIFI_LOGI("wifi close, id=%{public}d", instId);
    std::string moduleName = "StaService_" + std::to_string(instId);
    WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(moduleName);
}
#endif

#ifdef FEATURE_STA_SUPPORT
void WifiCountryCodeManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    WIFI_LOGD("wifi connection state change, state=%{public}d, id=%{public}d", state, instId);
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        WifiCountryCodeManager::GetInstance().m_isFirstConnected = true;
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
    }
}
#endif

#ifdef FEATURE_AP_SUPPORT
void WifiCountryCodeManager::DealApStateChanged(ApState state, int id)
{
    WIFI_LOGI("ap state change, state=%{public}d, id=%{public}d", state, id);
    if (state == ApState::AP_STATE_STARTED) {
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode();
    } else if (state != ApState::AP_STATE_STARTING && state != ApState::AP_STATE_STARTED) {
        std::string moduleName = "ApService_" + std::to_string(id);
        WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(moduleName);
    }
}
#endif

ErrCode WifiCountryCodeManager::UpdateWifiCountryCodeCache(const std::string &wifiCountryCode)
{
    if (wifiCountryCode.empty() || !IsValidCountryCode(wifiCountryCode)) {
        WIFI_LOGE("wifi country code is empty or invalid");
        return WIFI_OPT_FAILED;
    }
    int ret = SetParamValue(WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY, wifiCountryCode.c_str());
    std::string retStr = ret == 0 ? "success" : "fail, ret=" + std::to_string(ret);
    WIFI_LOGI("update wifi country code cache %{public}s", retStr.c_str());
    return ret == 0 ? WIFI_OPT_SUCCESS : WIFI_OPT_FAILED;
}

std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> WifiCountryCodeManager::GetWifiCountryCodePolicy()
{
    char preValue[WIFI_COUNTRY_CODE_SIZE] = {0};
    int errorCode = GetParamValue(WIFI_COUNTRY_CODE_CONFIG,
        WIFI_COUNTRY_CODE_CONFIG_DEFAULT, preValue, WIFI_COUNTRY_CODE_SIZE);
    int policyConf = 0;
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGI("get wifi country code policy config fail, use policyConf=0");
        return std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(policyConf);
    }
    policyConf = ConvertStringToInt(preValue);
    WIFI_LOGI("get wifi country code policy config is %{public}d", policyConf);
    return std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(policyConf);
}
}
}