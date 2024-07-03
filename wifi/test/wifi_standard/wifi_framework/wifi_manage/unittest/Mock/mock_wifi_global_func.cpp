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

int GetParamValue(const char *key, const char *def, char *value, uint32_t len)
{
    if (strcasecmp(key, WIFI_COUNTRY_CODE_CONFIG) == 0) {
        WIFI_LOGI("GetParamValue WIFI_COUNTRY_CODE_CONFIG");
        value[0] = '3';
        value[1] = '1';
        return 1;  // success
    } else if (strcasecmp(key, WIFI_COUNTRY_CODE_RUN_MODE) == 0) {
        WIFI_LOGI("GetParamValue WIFI_COUNTRY_CODE_RUN_MODE");
        value[0] = 'f';
        value[1] = 'a';
        value[2] = 'c';
        value[3] = 't';
        value[4] = 'o';
        value[5] = 'r';
        value[6] = 'y';
        return 1;  // success
    } else if (strcasecmp(key, FACTORY_WIFI_COUNTRY_CODE)) {
        WIFI_LOGI("GetParamValue FACTORY_WIFI_COUNTRY_CODE");
        value[0] = 'U';
        value[1] = 'S';
        return 1;  // success
    } else if (strcasecmp(key, OPERATOR_NUMERIC_KEY)) {
        WIFI_LOGI("GetParamValue OPERATOR_NUMERIC_KEY");
        value[0] = '4';
        value[1] = '6';
        value[2] = '0';
        value[3] = '0';
        value[4] = '0';
        value[5] = '0';
        value[6] = '0';
        return 1;  // success
    } else if (strcasecmp(key, WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY)) {
        WIFI_LOGI("GetParamValue WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY");
        value[0] = 'C';
        value[1] = 'N';
        return 1;  // success
    } else if (strcasecmp(key, DEFAULT_REGION_KEY)) {
        WIFI_LOGI("GetParamValue DEFAULT_REGION_KEY");
        value[0] = 'J';
        value[1] = 'P';
        return 1;  // success
    } else {
        // nothing
    }
    return 0;
}
}
}