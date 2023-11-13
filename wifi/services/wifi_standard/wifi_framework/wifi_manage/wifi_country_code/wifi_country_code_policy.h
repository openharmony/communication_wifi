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
#include <string>
#include "wifi_errcode.h"
#include "i_wifi_country_code_policy.h"
#include "wifi_country_code_define.h"

namespace OHOS {
namespace Wifi {
class WifiCountryCodePolicyFactory {
public:
    /**
     * @Description WifiCountryCodePolicyFactory constructor
     */
    WifiCountryCodePolicyFactory() = default;

    /**
     * @Description WifiCountryCodePolicyFactory destructor
     */
    ~WifiCountryCodePolicyFactory() = default;

    /**
     * @Description create wifi country code algorithm obj
     * @param policyConf - indicates the prop value for the policy to take effect.
     * @return IWifiCountryCodePolicy - actual country code algorithm
     */
    std::shared_ptr<IWifiCountryCodePolicy> CreatePolicy(
        const std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN> &policyConf);
};
}
}
#endif