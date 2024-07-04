/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "mock_wifi_global_func.h"
#include <cstring>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("MockWifiGlobalFunc");
constexpr const char* WIFI_COUNTRY_CODE_CONFIG = "const.wifi.country_code.conf";
constexpr const char* WIFI_COUNTRY_CODE_RUN_MODE = "const.wifi.country_code.runmode";
constexpr const char* FACTORY_WIFI_COUNTRY_CODE = "const.wifi.country_code.factory";
constexpr const char* OPERATOR_NUMERIC_KEY = "ril.operator.numeric";  // plmn cached
constexpr const char* WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY = "persist.wifi.country_code.dynamic_update";
constexpr const char* DEFAULT_REGION_KEY = "const.global.region";
const int INDEX_ZERO = 0;
const int INDEX_ONE = 1;
const int INDEX_TWO = 2;
const int INDEX_THREE = 3;
const int INDEX_FOUR = 4;
const int INDEX_FIVE = 5;
const int INDEX_SIX = 6;

int GetParamValue(const char *key, const char *def, char *value, uint32_t len)
{
    if (strcasecmp(key, WIFI_COUNTRY_CODE_CONFIG) == 0) {
        WIFI_LOGI("GetParamValue WIFI_COUNTRY_CODE_CONFIG");
        value[INDEX_ZERO] = '3';
        value[INDEX_ONE] = '1';
        return 1;  // success
    } else if (strcasecmp(key, WIFI_COUNTRY_CODE_RUN_MODE) == 0) {
        WIFI_LOGI("GetParamValue WIFI_COUNTRY_CODE_RUN_MODE");
        value[INDEX_ZERO] = 'f';
        value[INDEX_ONE] = 'a';
        value[INDEX_TWO] = 'c';
        value[INDEX_THREE] = 't';
        value[INDEX_FOUR] = 'o';
        value[INDEX_FIVE] = 'r';
        value[INDEX_SIX] = 'y';
        return 1;  // success
    } else if (strcasecmp(key, FACTORY_WIFI_COUNTRY_CODE)) {
        WIFI_LOGI("GetParamValue FACTORY_WIFI_COUNTRY_CODE");
        value[INDEX_ZERO] = 'U';
        value[INDEX_ONE] = 'S';
        return 1;  // success
    } else if (strcasecmp(key, OPERATOR_NUMERIC_KEY)) {
        WIFI_LOGI("GetParamValue OPERATOR_NUMERIC_KEY");
        value[INDEX_ZERO] = '4';
        value[INDEX_ONE] = '6';
        value[INDEX_TWO] = '0';
        value[INDEX_THREE] = '0';
        value[INDEX_FOUR] = '0';
        value[INDEX_FIVE] = '0';
        value[INDEX_SIX] = '0';
        return 1;  // success
    } else if (strcasecmp(key, WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY)) {
        WIFI_LOGI("GetParamValue WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY");
        value[INDEX_ZERO] = 'C';
        value[INDEX_ONE] = 'N';
        return 1;  // success
    } else if (strcasecmp(key, DEFAULT_REGION_KEY)) {
        WIFI_LOGI("GetParamValue DEFAULT_REGION_KEY");
        value[INDEX_ZERO] = 'J';
        value[INDEX_ONE] = 'P';
        return 1;  // success
    } else {
        // nothing
    }
    return 0;
}
}
}