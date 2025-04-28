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
#include "system_ability_definition.h"

DEFINE_WIFILOG_LABEL("WifiDataShareHelperUtils");

namespace OHOS {
namespace Wifi {
namespace {
constexpr const char *SETTINGS_DATASHARE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
constexpr const char *SETTINGS_DATA_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *SETTINGS_DATA_COLUMN_VALUE = "VALUE";
constexpr const char *DEFAULT_USERID = "100";

// E_OK and E_DATA_SHARE_NOT_READY used to check datashare ready
constexpr const int32_t E_OK = 0;
constexpr const int32_t E_DATA_SHARE_NOT_READY = 1055;
}

WifiDataShareHelperUtils& WifiDataShareHelperUtils::GetInstance()
{
    static WifiDataShareHelperUtils instance;
    return instance;
}

bool WifiDataShareHelperUtils::IsDataMgrServiceActive()
{
    sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        WIFI_LOGE("Failed to get SystemAbilityManager!");
        return false;
    }
    sptr<IRemoteObject> object = saMgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (object == nullptr) {
        WIFI_LOGE("Failed to get DataMgrService!");
        return false;
    }
    return true;
}

bool WifiDataShareHelperUtils::CheckIfSettingsDataReady()
{
    if (isDataShareReady_) {
        return true;
    }

    if (!IsDataMgrServiceActive()) {
        return false;
    }

    auto remote = sptr<IWifiDataShareRemoteBroker>(new (std::nothrow) IRemoteStub<IWifiDataShareRemoteBroker>());
    if (remote == nullptr) {
        WIFI_LOGE("%{public}s remote is nullptr", __func__);
        return false;
    }
    auto remoteObj = remote->AsObject();
    if (remoteObj == nullptr) {
        WIFI_LOGE("%{public}s remoteObj_ is nullptr", __func__);
        return false;
    }

    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> ret =
        DataShare::DataShareHelper::Create(remoteObj, SETTINGS_DATASHARE_URI, SETTINGS_DATA_EXT_URI);
    WIFI_LOGI("%{public}s create datashare helper, ret = %{public}d", __func__, ret.first);

    if (ret.first == E_DATA_SHARE_NOT_READY) {
        return false;
    }

    if (ret.first == E_OK) {
        if (ret.second) {
            ret.second->Release();
        }
        isDataShareReady_ = true;
    }
    return true;
}

std::shared_ptr<DataShare::DataShareHelper> WifiDataShareHelperUtils::WifiCreateDataShareHelper(bool onlySettingsData)
{
    if (!CheckIfSettingsDataReady()) {
        WIFI_LOGE("%{public}s datashare not ready.", __func__);
        return nullptr;
    }

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
        ClearResources(queryHelper, result);
        return WIFI_OPT_FAILED;
    }

    if (result->GoToFirstRow() != DataShare::E_OK) {
        WIFI_LOGE("WifiDataShareHelper query failed,go to first row error");
        ClearResources(queryHelper, result);
        return WIFI_OPT_FAILED;
    }

    int columnIndex;
    result->GetColumnIndex(SETTINGS_DATA_COLUMN_VALUE, columnIndex);
    result->GetString(columnIndex, value);
    ClearResources(queryHelper, result);
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
        ClearResources(insertHelper, nullptr);
        return WIFI_OPT_FAILED;
    }
    insertHelper->NotifyChange(uri);
    ClearResources(insertHelper, nullptr);
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
        ClearResources(updateHelper, nullptr);
        return WIFI_OPT_FAILED;
    }
    updateHelper->NotifyChange(uri);
    ClearResources(updateHelper, nullptr);
    WIFI_LOGE("DataShareHelper update success");
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    std::shared_ptr<DataShare::DataShareHelper> registerHelper = WifiCreateDataShareHelper();
    CHECK_NULL_AND_RETURN(registerHelper, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(observer, WIFI_OPT_FAILED);
    registerHelper->RegisterObserver(uri, observer);
    ClearResources(registerHelper, nullptr);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDataShareHelperUtils::UnRegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    std::shared_ptr<DataShare::DataShareHelper> unregisterHelper = WifiCreateDataShareHelper();
    CHECK_NULL_AND_RETURN(unregisterHelper, WIFI_OPT_FAILED);
    CHECK_NULL_AND_RETURN(observer, WIFI_OPT_FAILED);
    unregisterHelper->UnregisterObserver(uri, observer);
    ClearResources(unregisterHelper, nullptr);
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

void WifiDataShareHelperUtils::ClearResources(std::shared_ptr<DataShare::DataShareHelper> operatrPtr,
    std::shared_ptr<DataShare::DataShareResultSet> result)
{
    if (result != nullptr) {
        result->Close();
        result = nullptr;
    }
    if (operatrPtr != nullptr) {
        operatrPtr->Release();
        operatrPtr = nullptr;
    }
}

std::string WifiDataShareHelperUtils::GetScanMacInfoWhiteListDataShareUri()
{
    std::vector<int> accountIds;
#ifdef HAS_ACCOUNT_PART
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(accountIds);
#endif
    std::string userId = DEFAULT_USERID;
    if (!accountIds.empty()) {
        userId = std::to_string(accountIds[0]);
    }

    std::string uri = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_" + userId +
        "?Proxy=true&key=" + SETTINGS_DATASHARE_KEY_SCANMACINFO_WHITELIST;
    return uri;
}
}   // namespace Wifi
}   // namespace OHOS