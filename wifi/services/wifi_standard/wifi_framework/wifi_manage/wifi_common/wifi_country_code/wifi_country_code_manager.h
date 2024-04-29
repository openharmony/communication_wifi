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

#ifndef WIFI_COUNTRY_CODE_MANAGER
#define WIFI_COUNTRY_CODE_MANAGER

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "i_wifi_country_code_change_listener.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service_callbacks.h"
#endif
#ifdef FEATURE_STA_SUPPORT
#include "sta_service_callback.h"
#endif
#include "wifi_country_code_define.h"
#include "wifi_country_code_policy.h"

namespace OHOS {
namespace Wifi {
class WifiCountryCodeManager {
public:
    /**
     * @Description get WifiCountryCodeManager instance
     *
     * @return WifiCountryCodeManager
     */
    static WifiCountryCodeManager &GetInstance();

    /**
     * @Description wifiCountryCodeManager init
     *
     * @return init result
     */
    ErrCode Init();
#ifdef FEATURE_STA_SUPPORT
    /**
     * @Description get sta change Callback
     *
     * @return callBack obj
     */
    StaServiceCallback GetStaCallback() const;
#endif
#ifdef FEATURE_AP_SUPPORT
    /**
     * @Description get ap change Callback
     *
     * @return callBack obj
     */
    IApServiceCallbacks GetApCallback() const;
#endif

    /**
     * @Description get wifi country code
     *
     * @param wifiCountryCode - wifi country code
     */
    void GetWifiCountryCode(std::string &wifiCountryCode) const;

    /**
     * @Description provides the set wifiCountryCode interface for external systems
     *
     * @param wifiCountryCode - wifi country code
     * @return error code
     */
    ErrCode SetWifiCountryCodeFromExternal(const std::string &wifiCountryCode = "");

    /**
     * @Description register wifi country code change listener
     *
     * @param listener - listener obj
     * @return error code
     */
    ErrCode RegisterWifiCountryCodeChangeListener(const std::shared_ptr<IWifiCountryCodeChangeListener> &listener);

    /**
     * @Description unregister wifi country code change listener
     *
     * @param listener - listener obj
     * @return error code
     */
    ErrCode UnregisterWifiCountryCodeChangeListener(const std::shared_ptr<IWifiCountryCodeChangeListener> &listener);

    /**
     * @Description disable WifiCountryCodeManager construct
     *
     * @param WifiCountryCodeManager - WifiCountryCodeManager obj
     */
    WifiCountryCodeManager(const WifiCountryCodeManager&) = delete;

    /**
     * @Description WifiCountryCodeManager deconstruct
     */
    ~WifiCountryCodeManager();

    /**
     * @Description disable WifiCountryCodeManager equals sign opertaor
     */
    WifiCountryCodeManager &operator=(const WifiCountryCodeManager &) = delete;
private:
#ifdef FEATURE_STA_SUPPORT
    StaServiceCallback m_staCallback;
#endif
#ifdef FEATURE_AP_SUPPORT
    IApServiceCallbacks m_apCallback;
#endif
    std::map<std::string, std::shared_ptr<IWifiCountryCodeChangeListener>> m_codeChangeListeners;
    std::string m_wifiCountryCode = DEFAULT_WIFI_COUNTRY_CODE;
    std::shared_ptr<WifiCountryCodePolicy> m_wifiCountryCodePolicy;
    std::mutex m_countryCodeMutex;

    WifiCountryCodeManager() = default;
    void SendCountryCodeChangeCommonEvent(const std::string &wifiCountryCode);
    ErrCode UpdateWifiCountryCode(const std::string &externalCode = "");
#ifdef FEATURE_STA_SUPPORT
    static void DealStaOpenRes(OperateResState state, int instId = 0);
    static void DealStaCloseRes(OperateResState state, int instId = 0);
#endif
#ifdef FEATURE_AP_SUPPORT
    static void DealApStateChanged(ApState state, int id = 0);
#endif
    ErrCode UpdateWifiCountryCodeCache(const std::string &wifiCountryCode);
    void NotifyWifiCountryCodeChangeListeners(const std::string &wifiCountryCode);
    ErrCode UnregisterWifiCountryCodeChangeListener(const std::string &moduleName);
};
}
}
#endif