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
#ifdef SUPPORT_ClOUD_WIFI_ASSET
#include "wifi_asset_manager.h"
#include "wifi_settings.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"
#include "parameters.h"
#include "wifi_global_func.h"

#ifdef HAS_ACCOUNT_PART
#include "os_account_manager.h"
#endif
 
namespace OHOS {
namespace Wifi {
static AssetValue g_userIdValue = {.u32 = USER_ID_DEFAULT};
static AssetValue g_trustAccountValue = {.u32 = SEC_ASSET_SYNC_TYPE_TRUSTED_ACCOUNT};
const std::string WIFI_ASSET_NETWORK_ON_SYNC = "WifiAssetNetworkOnSync";
bool IsExistInAsset(const WifiDeviceConfig &config, std::string key)
{
    std::string aliasId = config.ssid + config.keyMgmt;
    AssetBlob alias = {
        static_cast<uint32_t>(aliasId.length()), reinterpret_cast<uint8_t *>(const_cast<char *>(aliasId.c_str()))};
    AssetAttr attr[] = {
        {.tag = SEC_ASSET_TAG_ALIAS, {.blob = alias}},
        {.tag = SEC_ASSET_TAG_RETURN_TYPE, {.u32 = SEC_ASSET_RETURN_ALL}},
        {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
    };
    AssetResultSet resultSet = {0};
    int32_t ret = AssetQuery(attr, sizeof(attr) / sizeof(attr[0]), &resultSet);
    if (ret == SEC_ASSET_SUCCESS && resultSet.count > 0) {
        AssetAttr *result = AssetParseAttr(&resultSet.results[0], SEC_ASSET_TAG_SECRET);
        if (result) {
            std::string val = std::string(reinterpret_cast<char *>(result->value.blob.data), result->value.blob.size);
            AssetFreeResultSet(&resultSet);
            return val == key;
        } else {
            LOGE("IsExistInAsset result is nullptr ");
        }
    } else {
        LOGI("IsExistInAsset ret:%{public}d, count:%{public}d", ret, static_cast<int32_t>(resultSet.count));
    }
    AssetFreeResultSet(&resultSet);
    return false;
}

void SplitString(const std::string &input, const char spChar, std::vector<std::string> &outArray)
{
    std::stringstream sstr(input);
    std::string token;
    while (getline(sstr, token, spChar)) {
        outArray.push_back(token);
    }
}

bool CheckEap(const WifiDeviceConfig &config)
{
    if (config.keyMgmt != KEY_MGMT_EAP && config.keyMgmt != KEY_MGMT_SUITE_B_192) {
        return false;
    }
    if (config.wifiEapConfig.eap == EAP_METHOD_TLS) {
        if (config.wifiEapConfig.identity.empty() ||
            (config.wifiEapConfig.certEntry.size() == 0 &&
                (config.wifiEapConfig.clientCert.empty() || config.wifiEapConfig.privateKey.empty()))) {
            return false;
        }
        return true;
    }
    if ((config.wifiEapConfig.eap == EAP_METHOD_PEAP) || (config.wifiEapConfig.eap == EAP_METHOD_PWD) ||
               (config.wifiEapConfig.eap == EAP_METHOD_TTLS)) {
        if (config.wifiEapConfig.identity.empty() || config.wifiEapConfig.password.empty()) {
            return false;
        }
        return true;
    }
    return true;
}
 
bool CheckWapi(const WifiDeviceConfig &config)
{
    if (config.keyMgmt == KEY_MGMT_WAPI_PSK) {
        if (config.wifiWapiConfig.wapiPskType < static_cast<int>(WapiPskType::WAPI_PSK_ASCII) ||
            config.wifiWapiConfig.wapiPskType > static_cast<int>(WapiPskType::WAPI_PSK_HEX)) {
            return false;
        }
        return true;
    }
    if (config.wifiWapiConfig.wapiAsCertData.empty() || config.wifiWapiConfig.wapiUserCertData.empty()) {
        return false;
    }
    return true;
}
 
bool IsWapiOrEap(const WifiDeviceConfig &config)
{
    if (config.keyMgmt == KEY_MGMT_WAPI_CERT || config.keyMgmt == KEY_MGMT_WAPI_PSK) {
        return CheckWapi(config);
    }
    if (config.keyMgmt == KEY_MGMT_EAP || config.keyMgmt == KEY_MGMT_SUITE_B_192) {
        return CheckEap(config);
    }
    return false;
}
 
bool WifiAssetValid(const WifiDeviceConfig &config)
{
    if (config.uid != -1) {
        LOGD("WifiAssetValid WifiDeviceConfig ssid: %{public}s is not created by user, uid : %{public}d",
            SsidAnonymize(config.ssid).c_str(), config.uid);
        return false;
    }
    if (IsWapiOrEap(config)) {
        LOGD("WifiAssetValid WifiDeviceConfig ssid: %{public}s is %{public}s",
            SsidAnonymize(config.ssid).c_str(), config.keyMgmt.c_str());
        return false;
    }
    return true;
}
 
bool ArrayToWifiDeviceConfig(WifiDeviceConfig &config, std::vector<std::string> &outArray)
{
    if (outArray.size() != SIZE_OF_ITEM) {
        LOGE("WifiAsset ArrayToWifiDeviceConfig, Error Number Tag Saved In Asset");
        return false;
    }
    size_t index = 0;
    while (index < outArray.size()) {
        config.ssid = HexToString(outArray[index++]);
        config.keyMgmt = HexToString(outArray[index++]);
        config.preSharedKey = HexToString(outArray[index++]);
        for (int u = 0; u < WEPKEYS_SIZE; u++) {
            config.wepKeys[u] = HexToString(outArray[index++]);
        }
        config.wepTxKeyIndex = CheckDataLegal(outArray[index++]);
        config.hiddenSSID = CheckDataLegal(outArray[index++]);
        config.wifiProxyconfig.manualProxyConfig.serverHostName = HexToString(outArray[index++]);
        config.wifiProxyconfig.manualProxyConfig.serverPort = CheckDataLegal(outArray[index++]);
        config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = HexToString(outArray[index++]);
        config.version = CheckDataLegal(outArray[index++]);
    }
    if (config.keyMgmt != KEY_MGMT_NONE && (config.preSharedKey).length() == 0) {
        LOGE("WifiAsset ArrayToWifiDeviceConfig, ssid : %{public}s psk empty!", SsidAnonymize(config.ssid).c_str());
        return false;
    }
    return true;
}
 
void WifiAssetManager::WifiAssetTriggerSync()
{
    AssetValue syncValue = {.u32 = SEC_ASSET_NEED_SYNC};
    AssetAttr attrMove[] = {
        {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
        {.tag = SEC_ASSET_TAG_OPERATION_TYPE, .value = syncValue},
        {.tag = SEC_ASSET_TAG_SYNC_TYPE, .value = g_trustAccountValue},
    };
    int32_t ret = 0;
    AssetResultSet resultSetSingel = {0};
    /* The AssetQuery function is only used as a synchronous operation */
    ret = AssetQuery(attrMove, sizeof(attrMove) / sizeof(attrMove[0]), &resultSetSingel);
    LOGI("WifiAssetTriggerSync ret = %{public}d", ret);
    AssetFreeResultSet(&resultSetSingel);
}
 
static int32_t WifiAssetAttrAdd(const WifiDeviceConfig &config, bool flagSync = true)
{
    int32_t ret = SEC_ASSET_INVALID_ARGUMENT;
    if (config.keyMgmt != KEY_MGMT_NONE && (config.preSharedKey).length() == 0) {
        LOGE("WifiAssetAttrAdd, ssid : %{public}s psk empty!", SsidAnonymize(config.ssid).c_str());
        return ret;
    }
    std::string aliasId = config.ssid + config.keyMgmt;
    /* secret */
    std::string secretWifiDevice = "";
    secretWifiDevice += StringToHex(config.ssid) + ";";
    secretWifiDevice += StringToHex(config.keyMgmt) + ";";
    secretWifiDevice += StringToHex(config.preSharedKey) + ";";
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        secretWifiDevice += StringToHex(config.wepKeys[i]) +";";
    }
    secretWifiDevice += std::to_string(config.wepTxKeyIndex) + ";";
    secretWifiDevice += std::to_string(config.hiddenSSID) + ";";
    secretWifiDevice += StringToHex(config.wifiProxyconfig.manualProxyConfig.serverHostName) + ";";
    secretWifiDevice += std::to_string(config.wifiProxyconfig.manualProxyConfig.serverPort) + ";";
    secretWifiDevice += StringToHex(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList) + ";";
    secretWifiDevice += std::to_string(config.version);
    if (IsExistInAsset(config, secretWifiDevice)) {
        LOGE("WifiAssetAttrAdd, ExistInAsset");
        return SEC_ASSET_SUCCESS;
    }

    AssetValue secret = {.blob = {static_cast<uint32_t>(secretWifiDevice.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(secretWifiDevice.c_str()))}};
    AssetValue aliasValue = {.blob = {static_cast<uint32_t>(aliasId.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(aliasId.c_str()))}};
    AssetValue authTypeValue = {.u32 = SEC_ASSET_AUTH_TYPE_NONE};
    AssetAttr attr[] = {
        {.tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue},
        {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
        {.tag = SEC_ASSET_TAG_AUTH_TYPE, .value = authTypeValue},
        {.tag = SEC_ASSET_TAG_SECRET, .value = secret},
        {.tag = SEC_ASSET_TAG_SYNC_TYPE, .value = g_trustAccountValue},
    };
    ret = AssetAdd(attr, sizeof(attr) / sizeof(attr[0]));
    if (flagSync && ret == SEC_ASSET_SUCCESS) {
        WifiAssetManager::GetInstance().WifiAssetTriggerSync();
    }
    return ret;
}
 
static void WifiAssetAttrQuery(const AssetResultSet &resultSet, int32_t userId,
    std::vector<WifiDeviceConfig> &assetWifiConfig)
{
    for (uint32_t i = 0; i < resultSet.count; i++) {
        AssetAttr *checkItem = AssetParseAttr(resultSet.results + i, SEC_ASSET_TAG_ALIAS);
        if (checkItem == nullptr) {
            LOGE("WifiAssetAttrQuery ASSET_TAG_ALIAS is nullptr");
            continue;
        }
        std::string strAlias =
            std::string(reinterpret_cast<const char *>(checkItem->value.blob.data), checkItem->value.blob.size);
        AssetValue returnValue = {.u32 = SEC_ASSET_RETURN_ALL};
        AssetValue aliasValue = {.blob = checkItem->value.blob};
        AssetAttr attrSingle[] = {
            {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
            {.tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue},
            {.tag = SEC_ASSET_TAG_RETURN_TYPE, .value = returnValue},
        };
        AssetResultSet resultSetSingel = {0};
        int ret = AssetQuery(attrSingle, sizeof(attrSingle) / sizeof(attrSingle[0]), &resultSetSingel);
        if (ret != SEC_ASSET_SUCCESS) {
            LOGE("WifiAssetQuery Failed, ret %{public}d, %{public}s", ret, SsidAnonymize(strAlias).c_str());
            AssetFreeResultSet(&resultSetSingel);
            continue;
        };
        AssetAttr *checkItemSingle = AssetParseAttr(resultSetSingel.results, SEC_ASSET_TAG_SECRET);
        if (checkItemSingle == nullptr) {
            LOGE("WifiAssetParseAttr Failed, ret %{public}d, %{public}s", ret, SsidAnonymize(strAlias).c_str());
            AssetFreeResultSet(&resultSetSingel);
            continue;
        }
        std::string strSecret = std::string(
            reinterpret_cast<const char *>(checkItemSingle->value.blob.data), checkItemSingle->value.blob.size);
        WifiDeviceConfig AssetWifiDeviceConfig;
        std::vector<std::string> outArray;
        SplitString(strSecret, ';', outArray);
        if (ArrayToWifiDeviceConfig(AssetWifiDeviceConfig, outArray)) {
            assetWifiConfig.push_back(AssetWifiDeviceConfig);
        }
        AssetFreeResultSet(&resultSetSingel);
    }
}
 
WifiAssetManager &WifiAssetManager::GetInstance()
{
    static WifiAssetManager gWifiAsset;
    return gWifiAsset;
}
 
WifiAssetManager::WifiAssetManager()
{
    if (assetServiceThread_ == nullptr) {
        assetServiceThread_ = std::make_unique<WifiEventHandler>("WifiEventAddAsset");
    }
#ifdef HAS_ACCOUNT_PART
    if (GetDeviceType() == ProductDeviceType::PC) {
        int userId = static_cast<int>(USER_ID_DEFAULT);
        OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
        g_userIdValue = {.u32 = static_cast<uint32_t>(userId)};
    }
#endif
    staCallback_.callbackModuleName = WIFI_ASSET_NETWORK_ON_SYNC;
    staCallback_.OnStaConnChanged = [&](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
    firstSync_.store(false);
}

WifiAssetManager::~WifiAssetManager()
{
    if (assetServiceThread_ != nullptr) {
        assetServiceThread_.reset();
    }
}

void WifiAssetManager::InitUpLoadLocalDeviceSync()
{
    if (firstSync_.load()) {
        LOGE("WifiAssetManager, local data is sync");
        return;
    }
    WifiSettings::GetInstance().UpLoadLocalDeviceConfigToCloud();
}

void WifiAssetManager::CloudAssetSync()
{
    if (!(firstSync_.load())) {
        LOGE("WifiAssetManager, local data not sync");
        return;
    }
    WifiAssetQuery(USER_ID_DEFAULT);
}
 
void WifiAssetManager::WifiAssetAdd(const WifiDeviceConfig &config, int32_t userId, bool flagSync)
{
    if (!WifiAssetValid(config) || !assetServiceThread_) {
        return;
    }
    assetServiceThread_->PostAsyncTask([=]() {
        int32_t ret = WifiAssetAttrAdd(config, flagSync);
        if (ret != SEC_ASSET_SUCCESS && ret != SEC_ASSET_DUPLICATED) {
            LOGE("WifiAssetAdd Failed, ret: %{public}d, ssid: %{public}s", ret, SsidAnonymize(config.ssid).c_str());
        } else {
            LOGI("WifiAssetAdd Success, ssid : %{public}s", SsidAnonymize(config.ssid).c_str());
        }
    });
}
 
void WifiAssetManager::WifiAssetQuery(int32_t userId)
{
    if (!assetServiceThread_) {
        LOGE("WifiAssetQuery, assetServiceThread_ is null");
        return;
    }
    assetServiceThread_->PostAsyncTask([=]() {
        int32_t ret = 0;
        AssetValue returnValue = {.u32 = SEC_ASSET_RETURN_ATTRIBUTES};
        AssetAttr attrQu[] = {
            {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
            {.tag = SEC_ASSET_TAG_RETURN_TYPE, .value = returnValue},
        };
        AssetResultSet resultSet = {0};
        LOGI("WifiAssetQuery start");
        ret = AssetQuery(attrQu, sizeof(attrQu) / sizeof(attrQu[0]), &resultSet);
        if (ret != SEC_ASSET_SUCCESS) {
            LOGE("WifiAssetQuery Failed, Error Code is %{public}d", ret);
            AssetFreeResultSet(&resultSet);
            return;
        };
        std::vector<WifiDeviceConfig> assetWifiConfig;
        if (resultSet.count != 0) {
            WifiAssetAttrQuery(resultSet, userId, assetWifiConfig);
        } else {
            LOGE("WifiAssetQuery empty!");
        }
        AssetFreeResultSet(&resultSet);
        std::set<int> wifiLinkedNetworkIds = WifiConfigCenter::GetInstance().GetAllWifiLinkedNetworkId();
        WifiSettings::GetInstance().UpdateWifiConfigFromCloud(assetWifiConfig, wifiLinkedNetworkIds);
        WifiSettings::GetInstance().SyncDeviceConfig();
    });
}
 
void WifiAssetManager::WifiAssetUpdate(const WifiDeviceConfig &config, int32_t userId)
{
    WifiAssetRemove(config, userId, false);
    WifiAssetAdd(config, userId, true);
}
 
void WifiAssetManager::WifiAssetRemove(const WifiDeviceConfig &config, int32_t userId, bool flagSync)
{
    if (!(WifiAssetValid(config)) || !assetServiceThread_) {
        return;
    }
    assetServiceThread_->PostAsyncTask([=]() {
        std::string aliasId = config.ssid + config.keyMgmt;
        AssetValue aliasValue = {.blob = {static_cast<uint32_t>(aliasId.size()),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(aliasId.c_str()))}};
        int32_t ret = 0;
        AssetAttr attrMove[] = {
            {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
            {.tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue},
        };
        ret = AssetRemove(attrMove, sizeof(attrMove) / sizeof(attrMove[0]));
        if (ret != SEC_ASSET_SUCCESS) {
            LOGE("WifiAssetRemove Failed, ret: %{public}d, %{public}s", ret, SsidAnonymize(config.ssid).c_str());
        } else {
            LOGI("WifiAssetRemove Success, ssid : %{public}s", SsidAnonymize(config.ssid).c_str());
        }
        if (flagSync) {
            WifiAssetTriggerSync();
        }
    });
}
 
void WifiAssetManager::WifiAssetAddPack(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
    int32_t userId, bool flagSync, bool firstSync)
{
    if (!assetServiceThread_) {
        LOGE("WifiAssetAddPack, assetServiceThread_ is null");
        return;
    }
    if (wifiDeviceConfigs.size() == 0) {
        LOGI("WifiAssetAddPack, pack is null");
        if (firstSync) {
            firstSync_.store(true);
        }
        return;
    }
    assetServiceThread_->PostAsyncTask([=]() {
        for (auto mapConfig : wifiDeviceConfigs) {
            if (!WifiAssetValid(mapConfig)) {
                continue;
            }
            int32_t ret = WifiAssetAttrAdd(mapConfig, false);
            if (ret != SEC_ASSET_SUCCESS && ret != SEC_ASSET_DUPLICATED) {
                LOGE("WifiAssetAddPack Failed, ret: %{public}d, ssid : %{public}s", ret,
                    SsidAnonymize(mapConfig.ssid).c_str());
            } else {
                LOGI("WifiAssetAddPack Success, ssid : %{public}s", SsidAnonymize(mapConfig.ssid).c_str());
            }
        }
        if (flagSync) {
            WifiAssetTriggerSync();
        }
        if (firstSync) {
            firstSync_.store(true);
        }
    });
}
 
static void WifiAssetRemovePackInner(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
    int32_t userId, bool flagSync)
{
    for (auto mapConfig: wifiDeviceConfigs) {
        if (!WifiAssetValid(mapConfig)) {
            continue;
        }
        std::string aliasId = mapConfig.ssid + mapConfig.keyMgmt;
        AssetValue aliasValue = {.blob = {static_cast<uint32_t>(aliasId.size()),
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(aliasId.c_str()))}};
        AssetAttr attrMove[] = {
            {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
            {.tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue},
        };
        int32_t ret = AssetRemove(attrMove, sizeof(attrMove) / sizeof(attrMove[0]));
        if (ret != SEC_ASSET_SUCCESS) {
            LOGE("WifiAssetRemovePackInner Failed, ret: %{public}d, ssid : %{public}s", ret,
                SsidAnonymize(mapConfig.ssid).c_str());
        } else {
            LOGI("WifiAssetRemovePackInner Success, ssid : %{public}s", SsidAnonymize(mapConfig.ssid).c_str());
        }
    }
    if (flagSync) {
        WifiAssetManager::GetInstance().WifiAssetTriggerSync();
    }
}
 
void WifiAssetManager::WifiAssetUpdatePack(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs, int32_t userId)
{
    WifiAssetRemovePack(wifiDeviceConfigs, userId, false);
    WifiAssetAddPack(wifiDeviceConfigs, userId, true);
}
 
void WifiAssetManager::WifiAssetRemovePack(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
    int32_t userId, bool flagSync)
{
    if (!assetServiceThread_ || wifiDeviceConfigs.size() == 0) {
        return;
    }
    assetServiceThread_->PostAsyncTask([=]() { WifiAssetRemovePackInner(wifiDeviceConfigs, userId, flagSync); });
}
 
void WifiAssetManager::WifiAssetRemoveAll(int32_t userId, bool flagSync)
{
    if (!assetServiceThread_) {
        return;
    }
    assetServiceThread_->PostAsyncTask([=]() {
        int32_t ret = 0;
        AssetAttr attrMove[] = {
            {.tag = SEC_ASSET_TAG_USER_ID, .value = g_userIdValue},
        };
        ret = AssetRemove(attrMove, sizeof(attrMove) / sizeof(attrMove[0]));
        if (ret != SEC_ASSET_SUCCESS) {
            LOGE("WifiAssetRemoveAll Failed, Error Code is %{public}d", ret);
        } else {
            LOGI("WifiAssetRemoveAll Success");
        }
        if (flagSync) {
            WifiAssetTriggerSync();
        }
    });
}
bool WifiAssetManager::IsWifiConfigUpdated(const std::vector<WifiDeviceConfig> newWifiDeviceConfigs,
    WifiDeviceConfig &config)
{
    if (!WifiAssetValid(config)) {
        return true;
    }
    for (auto iter : newWifiDeviceConfigs) {
        if (config.ssid != iter.ssid || config.keyMgmt != iter.keyMgmt) {
            continue;
        }
        if (IsWifiConfigChanged(iter, config)) {
            config.preSharedKey = iter.preSharedKey;
            config.hiddenSSID = iter.hiddenSSID;
            config.wepTxKeyIndex = iter.wepTxKeyIndex;
            for (int u = 0; u < WEPKEYS_SIZE; u++) {
                config.wepKeys[u] = iter.wepKeys[u];
            }
            config.wifiProxyconfig.manualProxyConfig.serverHostName =
                iter.wifiProxyconfig.manualProxyConfig.serverHostName;
 
            config.wifiProxyconfig.manualProxyConfig.serverPort =
                iter.wifiProxyconfig.manualProxyConfig.serverPort;
 
            config.wifiProxyconfig.manualProxyConfig.exclusionObjectList =
                iter.wifiProxyconfig.manualProxyConfig.exclusionObjectList;
            config.version = 0;
            LOGI("WifiAsset IsWifiConfigUpdated, ssid : %{public}s, psksize : %{public}d",
                SsidAnonymize(config.ssid).c_str(), static_cast<int>((config.preSharedKey).length()));
        }
        return true;
    }
    return false;
}
 
bool WifiAssetManager::IsWifiConfigChanged(const WifiDeviceConfig &config, const WifiDeviceConfig &oriConfig)
{
    if (!WifiAssetValid(config)) {
        return false;
    }
    if (config.ssid != oriConfig.ssid || config.keyMgmt != oriConfig.keyMgmt) {
        return true;
    }
    if (config.preSharedKey != oriConfig.preSharedKey || config.hiddenSSID != oriConfig.hiddenSSID) {
        return true;
    }
    if (config.wepTxKeyIndex != oriConfig.wepTxKeyIndex) {
        return true;
    }
 
    for (int u = 0; u < WEPKEYS_SIZE; u++) {
        if (config.wepKeys[u] != oriConfig.wepKeys[u]) {
            return true;
        }
    }
 
    if (config.wifiProxyconfig.manualProxyConfig.serverHostName !=
            oriConfig.wifiProxyconfig.manualProxyConfig.serverHostName) {
        return true;
    }
 
    if (config.wifiProxyconfig.manualProxyConfig.serverPort !=
            oriConfig.wifiProxyconfig.manualProxyConfig.serverPort) {
        return true;
    }
 
    if (config.wifiProxyconfig.manualProxyConfig.exclusionObjectList !=
            oriConfig.wifiProxyconfig.manualProxyConfig.exclusionObjectList) {
        return true;
    }
    return false;
}

StaServiceCallback WifiAssetManager::GetStaCallback() const
{
    return staCallback_;
}

void WifiAssetManager::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        LOGI("WifiAsset network connected");
        if (info.networkId != currentConnectedNetworkId_ &&
            system::GetParameter("persist.wifi.is_connect_from_user", "") == "1") {
            WifiAssetTriggerSync();
        }
        currentConnectedNetworkId_ = info.networkId;
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        currentConnectedNetworkId_ = -1;
    }
}
}  // namespace Wifi
}  // namespace OHOS
#endif