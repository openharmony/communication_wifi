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

#ifndef OHOS_WIFI_DATASHARE_UTILS_H
#define OHOS_WIFI_DATASHARE_UTILS_H

#include <memory>
#include <utility>
#include <singleton.h>

#include "iremote_object.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
namespace {
constexpr const char *SETTINGS_DATASHARE_URL_AIRPLANE_MODE =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=airplane_mode";
constexpr const char *SETTINGS_DATASHARE_KEY_AIRPLANE_MODE = "settings.telephony.airplanemode";
constexpr const char *SETTINGS_DATASHARE_URI_LOCATION_MODE =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=location_enable";
constexpr const char *SETTINGS_DATASHARE_KEY_LOCATION_MODE = "location_switch_enable";
}

class WifiDataShareHelperUtils : DelayedSingleton<WifiDataShareHelperUtils> {
public:
    WifiDataShareHelperUtils();
    ~WifiDataShareHelperUtils() = default;
    ErrCode Query(Uri &uri, const std::string &key, std::string &value);

    ErrCode RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer);

    ErrCode UnRegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer);

private:
    std::shared_ptr<DataShare::DataShareHelper> WifiCreateDataShareHelper();
private:
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_ = nullptr;
};

class IWifiDataShareRemoteBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IWifiScan");
};

}   // namespace Wifi
}   // namespace OHOS
#endif
