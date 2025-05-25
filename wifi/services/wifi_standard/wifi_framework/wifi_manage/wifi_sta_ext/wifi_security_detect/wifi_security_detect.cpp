/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#include <chrono>
#include "json/json.h"
#include <nlohmann/json.hpp>

#include "wifi_security_detect.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_settings.h"
#include "wifi_config_center.h"
#include "datashare_helper.h"
#include "wifi_notification_util.h"
#include "sg_classify_client.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiSecurityDetect");
namespace OHOS {
namespace Wifi {

const std::string WIFI_SECURITY_NETWORK_ON_SYNC = "WifiSecurityNetworkOnSync";
constexpr int32_t SUCCESS = 0;
constexpr int32_t FAIL = 1;
const std::string SETTINGS_DATASHARE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string SETTINGS_DATA_KEYWORD = "KEYWORD";
const std::string SETTINGS_DATA_VALUE = "VALUE";
const uint32_t securityGuardModelID = 3001000011;
const int wirelessType_802_11A = 1;
const int wirelessType_802_11B = 2;
const int wirelessType_802_11G = 3;
const int wirelessType_802_11N = 4;
const int wirelessType_802_11AC = 5;
const int wirelessType_802_11AX = 6;
const int NUM24 = 24;

WifiSecurityDetect::WifiSecurityDetect()
{
    if (securityDetectThread_ == nullptr) {
        securityDetectThread_ = std::make_unique<WifiEventHandler>("WifiEventAddAsset");
    }
    staCallback_.callbackModuleName = WIFI_SECURITY_NETWORK_ON_SYNC;
    staCallback_.OnStaConnChanged = [&](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
}

bool WifiSecurityDetect::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    WIFI_LOGI("WifiSecurityDetect network connected");
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        currentConnectedNetworkId_ = info.networkId;
        SecurityDetect(info);
        return true;
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        currentConnectedNetworkId_ = -1;
        return false;
    } else {
        return false;
    }
}

StaServiceCallback WifiSecurityDetect::GetStaCallback() const
{
    return staCallback_;
}

std::shared_ptr<DataShare::DataShareHelper> WifiSecurityDetect::CreateDataShareHelper()
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

Uri WifiSecurityDetect::AssembleUri(const std::string &key)
{
    Uri uri(SETTINGS_DATASHARE_URI + "&key=" + key);
    return uri;
}

bool WifiSecurityDetect::SettingDataOnOff()
{
    auto operatePtr = CreateDataShareHelper();
    if (operatePtr == nullptr) {
        WIFI_LOGE("wifioperatePtr is null");
        return false;
    }

    auto uri = AssembleUri("wifi_cloud_security_check");
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_KEYWORD, "wifi_cloud_security_check");
    std::vector<std::string> columns = {SETTINGS_DATA_VALUE};
    auto resultSet = operatePtr->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        WIFI_LOGE("DataShareHelper query result is nullptr, key = %{public}s", "wifi_cloud_security_check");
        operatePtr->Release();
        return false;
    }
    std::string valueResult;
    resultSet->GoToFirstRow();
    int32_t value = resultSet->GetString(0, valueResult);
    WIFI_LOGI("SettingDataOnOff %{public}d", value);
    if (valueResult == "1") {
        WIFI_LOGI("SettingDataOn");
        return true;
    } else {
        WIFI_LOGI("SettingDataOff");
        return false;
    }
    return true;
}

bool WifiSecurityDetect::SecurityDetectTime(const int &networkId)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        WIFI_LOGE("%{public}s, not find networkId:%{public}d", __FUNCTION__, networkId);
        return false;
    }

    if (config.lastConnectTime == -1) {
        return true;
    }
    auto DetectTime = std::chrono::system_clock::now();
    auto hours = std::chrono::duration_cast<std::chrono::hours>(
        DetectTime - std::chrono::system_clock::from_time_t(config.lastConnectTime));
    if (hours.count() > NUM24) {
        WIFI_LOGI("WifiDetect less than 24");
        return true;
    } else {
        WIFI_LOGI("WifiDetect more than 24");
        return false;
    }
}

WifiSecurityDetect &WifiSecurityDetect::GetInstance()
{
    static WifiSecurityDetect securitywifi;
    return securitywifi;
}

bool WifiSecurityDetect::SecurityDetectResult(const std::string &devId, uint32_t modelId, const std::string &param)
{
    auto promise = std::make_shared<std::promise<SecurityModelResult>>();
    auto future = promise->get_future();
    auto func = [promise](const OHOS::Security::SecurityGuard::SecurityModelResult &result) mutable -> int32_t {
        SecurityModelResult model = {.devId = result.devId, .modelId = result.modelId, .result = result.result};
        promise->set_value(model);
        return SUCCESS;
    };
    auto ret = OHOS::Security::SecurityGuard::RequestSecurityModelResultAsync(devId, modelId, param, func);
    if (ret != SUCCESS) {
        WIFI_LOGE("RequestSecurityModelResultSync error, ret=%{public}d", ret);
        return false;
    }

    SecurityModelResult model = future.get();
    std::string result = "0";
    nlohmann::json root = nlohmann::json::parse(model.result.c_str());
    if (root["status"] != 0) {
        WIFI_LOGE("RequestSecurityModelResultSync status error= %{public}d", root["status"].get<int>());
        return false;
    }

    if (root["result"] == result) {
        WIFI_LOGI("SG wifi result is security");
        return true;
    } else {
        WIFI_LOGI("SG wifi result is not security");
        return false;
    }
}

void WifiSecurityDetect::WifiConnectConfigParma(const WifiLinkedInfo &info, Json::Value &root)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(info.networkId, config) != 0) {
        WIFI_LOGE("%{public}s, not find networkId:%{public}d", __FUNCTION__, info.networkId);
        return;
    }

    IpInfo wifiIpInfo;
    int32_t m_instId = 0;
    WifiConfigCenter::GetInstance().GetIpInfo(wifiIpInfo, m_instId);
    switch (info.wifiStandard) {
        case wirelessType_802_11A:
            root["wirelessType"] = "802.11a";
            break;
        case wirelessType_802_11B:
            root["wirelessType"] = "802.11b";
            break;
        case wirelessType_802_11G:
            root["wirelessType"] = "802.11g";
            break;
        case wirelessType_802_11N:
            root["wirelessType"] = "802.11n";
            break;
        case wirelessType_802_11AC:
            root["wirelessType"] = "802.11ac";
            break;
        case wirelessType_802_11AX:
            root["wirelessType"] = "802.11ax";
            break;
        default:
            WIFI_LOGE("wifi wirelessType is unknown");
            return;
    }

    root["ssid"] = config.ssid;
    root["bssid"] = config.bssid;
    root["signalStrength"] = config.rssi;
    root["authentication"] = config.keyMgmt;
    root["frequencyBand"] = config.frequency;
    root["gatewayIp"] = wifiIpInfo.ipAddress;
    root["gatewayMac"] = config.macAddress;
    root["primaryDns"] = wifiIpInfo.primaryDns;
    root["secondDns"] = wifiIpInfo.secondDns;
}

void WifiSecurityDetect::SecurityDetect(const WifiLinkedInfo &info)
{
    SecurityModelResult model;
    model.devId = "";
    model.modelId = securityGuardModelID;
    model.result = "";
    if (!SecurityDetectTime(info.networkId)) {
        WIFI_LOGI("networkId:%{public}d detect less than 24 hours", info.networkId);
        return;
    }

    Json::Value root;
    Json::FastWriter writer;
    WifiConnectConfigParma(info, root);
    model.param = writer.write(root);
    WIFI_LOGI("%{public}s", model.param.c_str());
    securityDetectThread_->PostAsyncTask([=]() mutable -> int32_t {
        if (!SettingDataOnOff()) {
            return FAIL;
        }
        bool result = SecurityDetectResult(model.devId, model.modelId, model.param);
        WIFI_LOGI("PopupNotification   result %{public}d", result);
        if (result == true) {
            WIFI_LOGI("PopupNotification  open");
            PopupNotification(1, info.networkId);
        } else {
            WIFI_LOGI("PopupNotification  close");
            PopupNotification(2, info.networkId);
        }
        return SUCCESS;
    });
}

void WifiSecurityDetect::PopupNotification(int status, int networkid)
{
    WIFI_LOGI("wifi security pop-up notification start");
    OHOS::AAFwk::Want want;
    want.SetElementName("com.huawei.hmos.security.privacycenter", "WlanNotificationAbility");
    if (status == 1) {
        want.SetParam("notificationType", 1);
    } else {
        want.SetParam("notificationType", 2);
    }
    want.SetParam("networkId", networkid);
    WifiNotificationUtil &NotificationUtil = WifiNotificationUtil::GetInstance();

    auto result = NotificationUtil.StartAbility(want);
    WIFI_LOGI("wifi security pop-up notification End, result = %{public}d", result);
}

WifiSecurityDetect::~WifiSecurityDetect()
{
    WIFI_LOGI("enter ~WifiSecurityDetect");
}

}  // namespace Wifi
}  // namespace OHOS