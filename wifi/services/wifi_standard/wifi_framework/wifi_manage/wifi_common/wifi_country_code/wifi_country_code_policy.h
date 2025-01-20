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
#include <mutex>
#include "wifi_errcode.h"
#include "wifi_scan_msg.h"
#include "wifi_country_code_define.h"
#include "wifi_scan_msg.h"
#include "wifi_library_utils.h"

namespace OHOS {
namespace Wifi {
class WifiCountryCodePolicy {
public:
    /**
     * @Description WifiCountryCodePolicy constructor
     *
     * @param wifiCountryCodePolicyConf wifi country code policy config
     */
    explicit WifiCountryCodePolicy(std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> wifiCountryCodePolicyConf);
    /**
     * @Description WifiCountryCodePolicy destructor
     */
    ~WifiCountryCodePolicy() = default;

    /**
     * @Description calculate wifi countryCode
     *
     * @return wifiCountryCode - country code
     */
    ErrCode CalculateWifiCountryCode(std::string &wifiCountryCode);

    /**
     * @Description handle scan result action
     */
    void HandleScanResultAction();
private:
    void CreatePolicy(std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> wifiCountryCodePolicyConf);
    ErrCode GetWifiCountryCodeByFactory(std::string &wifiCountryCode);
    ErrCode GetWifiCountryCodeByMcc(std::string &wifiCountryCode);
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

    std::mutex countryCodeFromScanResult;
    std::vector<std::vector<std::string>> m_allBssidVector;
    std::map<std::string, std::string> m_bssidAndCountryCodeMap;
    std::string m_wifiCountryCodeFromScanResults;
    std::list<std::function<ErrCode(std::string&)>> m_policyList;
};

class WifiCountryCodeIntlUtils {
public:
    WifiCountryCodeIntlUtils() : wifiLibraryUtils_("libwifi_ext_lib.z.so", libHandle_, false) {}
    ~WifiCountryCodeIntlUtils() = default;
    std::string GetSystemRegion();
private:
    static void* libHandle_;
    WifiLibraryUtils wifiLibraryUtils_;
};
}
}
#endif