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
#include "wifi_datashare_utils.h"
#ifdef HAS_ACCOUNT_PART
#include "os_account_manager.h"
#endif
#include "wifi_log.h"
#include "wifi_logger.h"

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

std::shared_ptr<DataShare::DataShareHelper> WifiDataShareHelperUtils::WifiCreateDataShareHelper(bool onlySettingsData)
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
    if (onlySettingsData) {
        return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATA_EXT_URI);
    }
    return DataShare::DataShareHelper::Creator(remoteObj, SETTINGS_DATASHARE_URI, SETTINGS_DATA_EXT_URI);
}

ErrCode WifiDataShareHelperUtils::Query(Uri &uri, const std::string &key, std::string &value, bool onlySettingsData)
{
    std::shared_ptr<DataShare::DataShareHelper> queryHelper = WifiCreateDataShareHelper(onlySettingsData);
    CHECK_NULL_AND_RETURN(queryHelper, WIFI_OPT_FAILED);

    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, key);
    auto result = queryHelper->Query(uri, predicates, columns);
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
    queryHelper->Release();
    WIFI_LOGI("WifiDataShareHelper query success,value[%{public}s]", value.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::Insert(Uri &uri, const std::string &key, const std::string &value)
{
    std::shared_ptr<DataShare::DataShareHelper> insertHelper = WifiCreateDataShareHelper();
    CHECK_NULL_AND_RETURN(insertHelper, WIFI_OPT_FAILED);

    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject keyObj(key);
    DataShare::DataShareValueObject valueObj(value);
    valuesBucket.Put(SETTINGS_DATA_COLUMN_KEYWORD, keyObj);
    valuesBucket.Put(SETTINGS_DATA_COLUMN_VALUE, valueObj);
    int result = insertHelper->Insert(uri, valuesBucket);
    if (result <= 0) {
        WIFI_LOGE("WifiDataShareHelper insert failed, resultCode=%{public}d", result);
        return WIFI_OPT_FAILED;
    }
    insertHelper->NotifyChange(uri);
    insertHelper->Release();
    WIFI_LOGE("DataShareHelper insert success");
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::Update(Uri &uri, const std::string &key, const std::string &value)
{
    std::shared_ptr<DataShare::DataShareHelper> updateHelper = WifiCreateDataShareHelper();
    CHECK_NULL_AND_RETURN(updateHelper, WIFI_OPT_FAILED);

    DataShare::DataShareValuesBucket valuesBucket;
    DataShare::DataShareValueObject valueObj(value);
    valuesBucket.Put(SETTINGS_DATA_COLUMN_VALUE, valueObj);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_COLUMN_KEYWORD, key);
    int result = updateHelper->Update(uri, predicates, valuesBucket);
    if (result <= 0) {
        WIFI_LOGE("WifiDataShareHelper update failed, resultCode=%{public}d", result);
        return WIFI_OPT_FAILED;
    }
    updateHelper->NotifyChange(uri);
    updateHelper->Release();
    WIFI_LOGE("DataShareHelper update success");
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    std::shared_ptr<DataShare::DataShareHelper> registerHelper = WifiCreateDataShareHelper();
    CHECK_NULL_AND_RETURN(registerHelper, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(observer, WIFI_OPT_FAILED);
    registerHelper->RegisterObserver(uri, observer);
    registerHelper->Release();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::UnRegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    std::shared_ptr<DataShare::DataShareHelper> unregisterHelper = WifiCreateDataShareHelper();
    CHECK_NULL_AND_RETURN(unregisterHelper, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(observer, WIFI_OPT_FAILED);
    unregisterHelper->UnregisterObserver(uri, observer);
    unregisterHelper->Release();
    return WIFI_OPT_SUCCESS;
}

std::string WifiDataShareHelperUtils::GetLoactionDataShareUri()
{
    std::vector<int> accountIds;
#ifdef HAS_ACCOUNT_PART
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountIds);
#endif
    std::string userId = "100";
    if (!accountIds.empty()) {
        userId = std::to_string(accountIds[0]);
    }

    std::string uri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_"
        + userId + "?Proxy=true&key=location_enable";
    return uri;
}

}   // namespace Wifi
}   // namespace OHOS