/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "wifi_country_code_policy_base.h"
#include <memory>
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "parameter.h"
#include "uri.h"
#include "wifi_country_code_define.h"
#include "wifi_datashare_utils.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiCountryCodePolicyBase");

namespace OHOS {
namespace Wifi {
constexpr const char* DEFAULT_RO_RUN_MODE = "normal";
constexpr const char* FACTORY_RO_RUN_MODE = "factory";
constexpr const char* FACTORY_WIFI_COUNTRY_CODE = "const.factory.wifi_country_code";
constexpr const char* IS_RO_RUN_MODE = "const.wifi.ro.runmode";
constexpr int32_t FACTORY_WIFI_COUNTRY_CODE_SIZE = 16;
constexpr int32_t RO_RUN_MODE_SIZE = 16;
constexpr int32_t SYSTEM_PARAMETER_ERROR_CODE = 0;

ErrCode WifiCountryCodePolicyBase::CalculateWifiCountryCode(std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyBase::GetWifiCountryCodeByFactory(std::string &wifiCountryCode)
{
    char roRunModeValue[RO_RUN_MODE_SIZE] = {0};
    int errorCode = GetParameter(IS_RO_RUN_MODE, DEFAULT_RO_RUN_MODE, roRunModeValue, RO_RUN_MODE_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE || strcasecmp(FACTORY_RO_RUN_MODE, &roRunModeValue[0]) != 0) {
        WIFI_LOGI("the country code factory mode does not take effect");
        return WIFI_OPT_FAILED;
    }
    char factoryWifiCountryCodeValue[FACTORY_WIFI_COUNTRY_CODE_SIZE] = {0};
    errorCode = GetParameter(FACTORY_WIFI_COUNTRY_CODE, DEFAULT_WIFI_COUNTRY_CODE,
        factoryWifiCountryCodeValue, FACTORY_WIFI_COUNTRY_CODE_SIZE);
    if (errorCode <= SYSTEM_PARAMETER_ERROR_CODE) {
        WIFI_LOGI("get wifi country code by factory fail, errorCode=%{public}d", errorCode);
        return WIFI_OPT_FAILED;
    }
    if (!IsValidCountryCode(&factoryWifiCountryCodeValue[0])) {
        WIFI_LOGI("get wifi country code by factory fail, code invalid");
        return WIFI_OPT_FAILED;
    }
    wifiCountryCode = &factoryWifiCountryCodeValue[0];
    WIFI_LOGI("get wifi country code by factory success, code=%{public}s", wifiCountryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiCountryCodePolicyBase::GetWifiCountryCodeByCache(std::string &wifiCountryCode)
{
    auto wifiDataShareHelperUtils = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (wifiDataShareHelperUtils == nullptr) {
        return WIFI_OPT_FAILED;
    }
    std::string wifiCountryCodeCache;
    Uri uri(SETTINGS_DATASHARE_URI_WIFI_COUNTRY_CODE);
    int ret = wifiDataShareHelperUtils->Query(uri, SETTINGS_DATASHARE_KEY_WIFI_COUNTRY_CODE, wifiCountryCodeCache);
    if (ret == WIFI_OPT_SUCCESS) {
        WIFI_LOGI("get wifi country code by cache success, code=%{public}s", wifiCountryCodeCache.c_str());
        wifiCountryCode = wifiCountryCodeCache;
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGE("get wifi country code by cache fail, ret=%{public}d", ret);
    return WIFI_OPT_FAILED;
}

ErrCode WifiCountryCodePolicyBase::GetWifiCountryCodeByDefault(std::string &wifiCountryCode)
{
    wifiCountryCode = DEFAULT_WIFI_COUNTRY_CODE;
    WIFI_LOGI("get wifi country code by default success, use default code=HK");
    return WIFI_OPT_SUCCESS;
}
ErrCode WifiCountryCodePolicyBase::UpdateWifiCountryCodeCache(const std::string &wifiCountryCode)
{
    return WIFI_OPT_FAILED;
}
}
}