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

#include <vector>
#include "wifi_logger.h"
#include "wifi_datashare_utils.h"
DEFINE_WIFILOG_LABEL("WifiDataShareHelperUtils");

namespace OHOS {
namespace Wifi {
namespace {
constexpr const char *SETTINGS_DATASHARE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
constexpr const char *SETTINGS_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *SETTINGS_DATA_COLUMN_VALUE = "VALUE";
}

WifiDataShareHelperUtils::WifiDataShareHelperUtils(int systemAbilityId)
{
    dataShareHelper_ = WifiCreateDataShareHelper(systemAbilityId);
}

std::shared_ptr<DataShare::DataShareHelper> WifiDataShareHelperUtils::WifiCreateDataShareHelper(int systemAbilityId)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        WIFI_LOGE("WifiCreateDataShareHelper GetSystemAbilityManager failed.");
        return nullptr;
    }

    sptr<IRemoteObject> remote = saManager->GetSystemAbility(systemAbilityId);
    if (remote == nullptr) {
        WIFI_LOGE("WifiCreateDataShareHelper GetSystemAbility Service failed.");
        return nullptr;
    }

    WIFI_LOGI("WifiCreateDataShareHelper creator. systemAbilityId:%{public}d", systemAbilityId);
    return DataShare::DataShareHelper::Creator(remote, SETTINGS_DATASHARE_URI, SETTINGS_DATA_EXT_URI);
}

ErrCode WifiDataShareHelperUtils::Query(Uri &uri, const std::string &key, std::string &value)
{
    if (dataShareHelper_ == nullptr) {
        WIFI_LOGE("WifiDataShareHelper query error, dataShareHelper_ is nullptr");
        return WIFI_OPT_FAILED;
    }

    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, key);
    auto result = dataShareHelper_->Query(uri, predicates, columns);
    if (result == nullptr) {
        WIFI_LOGE("WifiDataShareHelper query error, result is null");
        return WIFI_OPT_FAILED;
    }

    if (result->GoToFirstRow() != DataShare::E_OK) {
        WIFI_LOGE("WifiDataShareHelper query failed,go to first row error");
        result->Close();
        return WIFI_OPT_FAILED;
    }

    int columnIndex;
    result->GetColumnIndex(SETTINGS_DATA_COLUMN_VALUE, columnIndex);
    result->GetString(columnIndex, value);
    result->Close();
    WIFI_LOGI("WifiDataShareHelper query success,value[%{public}s]", value.c_str());
    return WIFI_OPT_SUCCESS;
}

}   // namespace Wifi
}   // namespace OHOS