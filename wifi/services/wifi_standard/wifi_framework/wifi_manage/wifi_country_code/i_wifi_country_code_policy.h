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

#ifndef I_WIFI_COUNTRY_CODE_POLICY_H
#define I_WIFI_COUNTRY_CODE_POLICY_H

#include <string>
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class IWifiCountryCodePolicy {
public:
    /**
     * @Description IWifiCountryCodePolicy donstructor
     */

    virtual ~IWifiCountryCodePolicy() = default;

    /**
     * @Description calculate and get wifi country code
     *
     * @return std::string - calculate result
     */
    virtual ErrCode CalculateWifiCountryCode(std::string &wifiCountryCode) = 0;

    /**
     * @Description get wifi country code by factory
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - operation result
     */
    virtual ErrCode GetWifiCountryCodeByFactory(std::string &wifiCountryCode) = 0;

    /**
     * @Description get wifi country code from settings database
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - operation result
     */
    virtual ErrCode GetWifiCountryCodeByCache(std::string &wifiCountryCode) = 0;

    /**
     * @Description updating the wifi country code cache in the settings database
     *
     * @param wifiCountryCode - New wifi country code
     * @return ErrCode - Operation result
     */
    virtual ErrCode UpdateWifiCountryCodeCache(const std::string &wifiCountryCode) = 0;

    /**
     * @Description get wifi country code by default
     *
     * @param wifiCountryCode - Obtained wifi country code
     * @return ErrCode - Operation result
     */
    virtual ErrCode GetWifiCountryCodeByDefault(std::string &wifiCountryCode) = 0;
};
}
}
#endif