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

#ifndef WIFI_COUNTRY_CODE_POLICY_FACTORY_H
#define WIFI_COUNTRY_CODE_POLICY_FACTORY_H

#include <bitset>
#include <list>
#include <string>
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "wifi_errcode.h"
#include "wifi_scan_msg.h"
#include "wifi_country_code_define.h"
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {
class WifiCountryCodePolicy {
public:
    /**
     * @Description WifiCountryCodePolicy constructor
     */
    WifiCountryCodePolicy();

    /**
     * @Description WifiCountryCodePolicy destructor
     */
    ~WifiCountryCodePolicy();

    /**
     * @Description calculate wifi countryCode
     *
     * @return wifiCountryCode - country code
     */
    ErrCode CalculateWifiCountryCode(std::string &wifiCountryCode);
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

    class WifiScanEventListener : public OHOS::EventFwk::CommonEventSubscriber {
    public:
        /**
         * @Description WifiScanEventListener constructor
         */
        WifiScanEventListener(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo,
            WifiCountryCodePolicy *wifiCountryCodePolicy);

        /**
         * @Description WifiScanEventListener destructor
         */
        ~WifiScanEventListener() = default;

        /**
         * @Description on receive change event
         *
         * @param direction - event data
         */
        void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
    private:
        WifiCountryCodePolicy *m_wifiCountryCodePolicyPtr;
    };

    void CreatePolicy();
    void GetWifiCountryCodePolicy();
    ErrCode GetWifiCountryCodeByFactory(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByMcc(std::string &wifiCountryCode);
    void HandleScanResultAction();
    ErrCode StatisticCountryCodeFromScanResult(std::string &wifiCountryCode);
    ErrCode FindLargestCountCountryCode(std::string &wifiCountryCode);
    ErrCode ParseCountryCodeElement(const std::vector<WifiInfoElem> &infoElems, std::string &wifiCountryCode);
    ErrCode HandleWifiNetworkStateChangeAction(int connectionStatus);
    ErrCode GetWifiCountryCodeByRegion(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByAP(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByScanResult(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByDefaultZZ(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByCache(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByDefaultRegion(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByDefault(std::string &wifiCountryCode);
    bool IsContainBssid(const std::vector<std::string> &bssidList, const std::string &bssid);

    std::shared_ptr<TelephoneNetworkSearchStateChangeListener> m_telephoneNetworkSearchStateChangeListener;
    std::shared_ptr<WifiScanEventListener> m_wifiScanFinishCommonEventListener;
    std::vector<std::vector<std::string>> m_allBssidVector;
    std::map<std::string, std::string> m_bssidAndCountryCodeMap;
    std::string m_wifiCountryCodeFromScanResults;
    std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> m_wifiCountryCodePolicyConf;
    std::list<std::function<ErrCode(std::string&)>> m_policyList;
};
}
}
#endif