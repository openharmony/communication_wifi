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

#include <memory>
#include <string>
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "i_wifi_country_code_change_listener.h"
#include "i_wifi_country_code_policy.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service_callbacks.h"
#endif
#ifdef FEATURE_STA_SUPPORT
#include "sta_service_callback.h"
#endif
#include "wifi_country_code_define.h"

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
    StaServiceCallback GetStaCallback();
#endif
#ifdef FEATURE_AP_SUPPORT
    /**
     * @Description get ap change Callback
     *
     * @return callBack obj
     */
    IApServiceCallbacks GetApCallback();
#endif

    /**
     * @Description get wifi country code
     *
     * @param wifiCountryCode - wifi country code
     */
    void GetWifiCountryCode(std::string &wifiCountryCode);

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
    class TelephoneNetworkSearchStateChangeListener : public OHOS::EventFwk::CommonEventSubscriber {
    public:
        /**
         * @Description TelephoneNetworkSearchStateChangeListener constructor
         */
        explicit TelephoneNetworkSearchStateChangeListener(
            const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);

        /**
         * @Description TelephoneNetworkSearchStateChangeListener destructor
         */
        ~TelephoneNetworkSearchStateChangeListener() = default;

        /**
        * @Description on receive telephone network search state change event
        *
        * @param direction - event data
        */
        void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
    };
#ifdef FEATURE_STA_SUPPORT
    StaServiceCallback m_staCallback;
#endif
#ifdef FEATURE_AP_SUPPORT
    IApServiceCallbacks m_apCallback;
#endif
    struct ListenerNameCmp {
        bool operator() (const std::shared_ptr<IWifiCountryCodeChangeListener> &listener1,
            const std::shared_ptr<IWifiCountryCodeChangeListener> &listener2) const
        {
            return strcasecmp(listener1->GetListenerModuleName().c_str(),
                listener2->GetListenerModuleName().c_str()) < 0;
        }
    };
    std::set<std::shared_ptr<IWifiCountryCodeChangeListener>, ListenerNameCmp> m_wifiCountryCodeChangeListeners;
    std::string m_wifiCountryCode = DEFAULT_WIFI_COUNTRY_CODE;
    std::shared_ptr<TelephoneNetworkSearchStateChangeListener> m_telephoneNetworkSearchStateChangeListener;
    std::shared_ptr<IWifiCountryCodePolicy> m_wifiCountryCodePolicy;

    WifiCountryCodeManager() = default;
    void SendCountryCodeChangeCommonEvent(const std::string &wifiCountryCode);
    ErrCode UpdateWifiCountryCode(const std::string &externalCode = "");
#ifdef FEATURE_STA_SUPPORT
    static void DealStaOpenRes(OperateResState state);
    static void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info);
#endif
#ifdef FEATURE_AP_SUPPORT
    static void DealApStateChanged(ApState state, int id = 0);
#endif
    ErrCode UpdateWifiCountryCodeCache(const std::string &wifiCountryCode);
    void NotifyWifiCountryCodeChangeListeners(const std::string &wifiCountryCode);
};
}
}
#endif