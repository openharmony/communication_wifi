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

#ifndef WIFI_COUNTRY_CODE_POLICY_BASE_H
#define WIFI_COUNTRY_CODE_POLICY_BASE_H

#include <string>
#include <bitset>
#include <list>
#include <functional>
#include "i_wifi_country_code_policy.h"
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class WifiCountryCodePolicyBase : public IWifiCountryCodePolicy {
public:
    /**
     * @Description WifiCountryCodePolicyBase constructor
     */
    WifiCountryCodePolicyBase() = default;

    /**
     * @Description WifiCountryCodePolicyBase constructor
     */
    ~WifiCountryCodePolicyBase() override = default;

    /**
     * @Description calculate wifi country code
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - operation result
     */
    ErrCode CalculateWifiCountryCode(std::string &wifiCountryCode) override;

    /**
     * @Description get wifi country code by factory
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - operation result
     */
    ErrCode GetWifiCountryCodeByFactory(std::string &wifiCountryCode) override;

    /**
     * @Description get wifi country code from settings database
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - operation result
     */
    ErrCode GetWifiCountryCodeByCache(std::string &wifiCountryCode) override;

    /**
     * @Description updating the wifi country code cache in the settings database
     *
     * @param wifiCountryCode - New wifi country code
     * @return ErrCode - Operation result
     */
    ErrCode UpdateWifiCountryCodeCache(const std::string &wifiCountryCode) override;

    /**
     * @Description get wifi country code by default
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - Operation result
     */
    ErrCode GetWifiCountryCodeByDefault(std::string &wifiCountryCode) override;

    /**
     * @Description place country code selection strategy list
     */
    std::list<std::function<ErrCode(std::string&)>> m_policyList;
};
}
}
#endif