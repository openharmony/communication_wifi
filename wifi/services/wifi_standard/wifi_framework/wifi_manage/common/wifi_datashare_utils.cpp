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
#include "iremote_stub.h"
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

WifiDataShareHelperUtils::WifiDataShareHelperUtils()
{
    dataShareHelper_ = WifiCreateDataShareHelper();
}

std::shared_ptr<DataShare::DataShareHelper> WifiDataShareHelperUtils::WifiCreateDataShareHelper()
{
    auto remote = sptr<IWifiDataShareRemoteBroker>(new (std::nothrow) IRemoteStub<IWifiDataShareRemoteBroker>());
    if (remote == nullptr) {
        WIFI_LOGE("%{public}s remote is nullptr", __func__);
        return nullptr;
    }
    auto remoteObj = remote->AsObject();
    if (remoteObj == nullptr) {
        WIFI_LOGE("%{public}s remoteObj_ is nullptr", __func__);
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATASHARE_URI, SETTINGS_DATA_EXT_URI);
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

ErrCode WifiDataShareHelperUtils::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    if (dataShareHelper_ == nullptr) {
        WIFI_LOGE("WifiDataShareHelper %{public}s error, dataShareHelper_ is nullptr", __func__);
        return WIFI_OPT_FAILED;
    }

    if (observer == nullptr) {
        WIFI_LOGE("WifiDataShareHelper %{public}s error, observer is nullptr", __func__);
        return WIFI_OPT_FAILED;
    }
    dataShareHelper_->RegisterObserver(uri, observer);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::UnRegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    if (dataShareHelper_ == nullptr) {
        WIFI_LOGE("WifiDataShareHelper %{public}s error, dataShareHelper_ is nullptr", __func__);
        return WIFI_OPT_FAILED;
    }

    if (observer == nullptr) {
        WIFI_LOGE("WifiDataShareHelper %{public}s error, observer is nullptr", __func__);
        return WIFI_OPT_FAILED;
    }

    dataShareHelper_->UnregisterObserver(uri, observer);
    return WIFI_OPT_SUCCESS;
}

}   // namespace Wifi
}   // namespace OHOS