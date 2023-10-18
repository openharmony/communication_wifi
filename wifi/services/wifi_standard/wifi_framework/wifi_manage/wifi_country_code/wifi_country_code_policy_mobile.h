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

#ifndef WIFI_COUNTRY_CODE_POLICY_MOBILE_H
#define WIFI_COUNTRY_CODE_POLICY_MOBILE_H

#include <cstdint>
#include <string>
#include "wifi_country_code_policy_base.h"
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class WifiCountryCodePolicyMobile : public WifiCountryCodePolicyBase {
public:
    /**
     * @Description WifiCountryCodePolicyMobile constructor
     */
    WifiCountryCodePolicyMobile();

    /**
     * @Description WifiCountryCodePolicyMobile destructor
     */
    ~WifiCountryCodePolicyMobile() override = default;

    /**
     * @Description calculate and get wifi country code
     *
     * @return std::string - calculate result
     */
    ErrCode CalculateWifiCountryCode(std::string &wifiCountryCode) override;
private:
    void InitPolicy();
    ErrCode GetWifiCountryCodeByMcc(std::string &wifiCountryCode);
};
}
}
#endif