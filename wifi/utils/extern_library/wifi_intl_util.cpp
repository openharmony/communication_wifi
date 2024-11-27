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
#ifdef I18N_INTL_UTIL_ENABLE
#include <string>
#include "securec.h"
#include "wifi_intl_util.h"
#include "locale_config.h"
#include "wifi_logger.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiIntlUtil");
extern "C" void GetSystemRegion(char *region, int size)
{
    std::string regionStr = Global::I18n::LocaleConfig::GetSystemRegion();
    if (regionStr.empty()) {
        WIFI_LOGE("Get system region failed");
        return;
    }
    if (static_cast<int>(regionStr.size()) > size) {
        WIFI_LOGE("Region size is too small");
        return;
    }
    if (strncpy_s(region, regionStr.size() + 1, regionStr.c_str(), regionStr.size()) != 0) {
        WIFI_LOGE("Copy system region failed");
        return;
    }
    return;
}
} // namespace Wifi
} // namespace OHOS
#endif // I18N_INTL_UTIL_ENABLE
