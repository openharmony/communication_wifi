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

#ifndef WIFI_COUNTRY_CODE_POLICY_NO_MOBILE_H
#define WIFI_COUNTRY_CODE_POLICY_NO_MOBILE_H

#include <string>
#include <vector>
#include <list>
#include <map>
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "wifi_country_code_policy_base.h"
#include "wifi_errcode.h"
#include "wifi_scan_msg.h"
#include "wifi_country_code_define.h"

namespace OHOS {
namespace Wifi {
struct BssidAndCountryCode {
    std::string bssid;
    std::string wifiCountryCode;
};

class WifiCountryCodePolicyNoMobile : public WifiCountryCodePolicyBase {
public:
    /**
     * @Description WifiCountryCodePolicyNoMobile constructor
     *
     * @param wifiCountryCodePolicy - Monitoring effectiveness strategy
     */
    explicit WifiCountryCodePolicyNoMobile(
        const std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> &wifiCountryCodePolicy);

    /**
     * @Description WifiCountryCodePolicyNoMobile destructor
     */
    ~WifiCountryCodePolicyNoMobile() override;

    /**
     * @Description calculate wifi country code
     *
     * @param wifiCountryCode - result of wifiCountryCode
     * @return error code
     */
    ErrCode CalculateWifiCountryCode(std::string &wifiCountryCode) override;
private:
    class WifiCcpCommonEventListener : public OHOS::EventFwk::CommonEventSubscriber {
    public:
        /**
         * @Description WifiCcpCommonEventListener constructor
         */
        WifiCcpCommonEventListener(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo,
            WifiCountryCodePolicyNoMobile *wifiCountryCodePolicyNoMobile);

        /**
         * @Description WifiCcpCommonEventListener destructor
         */
        ~WifiCcpCommonEventListener() = default;

        /**
         * @Description on receive change event
         *
         * @param direction - event data
         */
        void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
    private:
        WifiCountryCodePolicyNoMobile *m_wifiCountryCodePolicyNoMobile;
    };
    std::shared_ptr<WifiCcpCommonEventListener> m_wifiScanFinishCommonEventListener;
    std::list<std::vector<BssidAndCountryCode>> m_allScanInfoList;
    std::string m_wifiCountryCodeFromScanResults;
    std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> m_wifiCountryCodePolicy;

    void InitPolicy();
    void HandleScanResultAction(int scanStatus);
    ErrCode StatisticCountryCodeFromScanResult(std::vector<BssidAndCountryCode> &scanInfoList);
    ErrCode ParseCountryCodeElement(std::vector<WifiInfoElem> &infoElems, std::string &wifiCountryCode);
    ErrCode HandleWifiNetworkStateChangeAction(int connectionStatus);
    ErrCode GetWifiCountryCodeByRegion(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByAP(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByScanResult(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByDefaultZZ(std::string &wifiCountryCode);
};
}
}
#endif