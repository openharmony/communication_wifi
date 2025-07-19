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

#ifdef WIFI_SECURITY_DETECT_ENABLE
#include <chrono>
#include "json/json.h"
#include "ip_tools.h"
#include "wifi_security_detect.h"
#include "wifi_security_detect_observer.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_settings.h"
#include "wifi_config_center.h"
#include "wifi_common_util.h"
#include "datashare_helper.h"
#include "wifi_notification_util.h"
#include "sg_classify_client.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiSecurityDetect");
namespace OHOS {
namespace Wifi {

const std::string WIFI_SECURITY_NETWORK_ON_SYNC = "WifiSecurityNetworkOnSync";
const std::string SETTINGS_DATASHARE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string SETTINGS_DATA_KEYWORD = "KEYWORD";
const std::string SETTINGS_DATA_VALUE = "VALUE";
const int MIN_5G_FREQUENCY = 5160;
const int MAX_5G_FREQUENCY = 5865;
const uint32_t securityGuardModelID = 3001000011;
const int NUM24 = 24;
static sptr<SecurityDetectObserver> SecurityDetectObserver_ = nullptr;
#define SECURITY_WAITING_TIME 500

WifiSecurityDetect::WifiSecurityDetect()
{
    if (securityDetectThread_ == nullptr) {
        securityDetectThread_ = std::make_unique<WifiEventHandler>("WifiSecurityDetect");
    }
    staCallback_.callbackModuleName = WIFI_SECURITY_NETWORK_ON_SYNC;
    staCallback_.OnStaConnChanged = [&](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
}

void WifiSecurityDetect::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    std::unique_lock<std::mutex> lock(shareDetectMutex_);
    if (state == OperateResState::CONNECT_NETWORK_ENABLED) {
        currentConnectedNetworkId_ = info.networkId;
        if (!networkDetecting_.load()) {
            networkDetecting_.store(true);
            SecurityDetect(info);
        }
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        PopupNotification(WifiNotification::CLOSE, info.networkId);
        currentConnectedNetworkId_.store(-1);
        networkDetecting_.store(false);
    } else {
        return;
    }
}

StaServiceCallback WifiSecurityDetect::GetStaCallback() const
{
    return staCallback_;
}

void WifiSecurityDetect::SetDatashareReady()
{
    datashareReady_.store(true);
}

void WifiSecurityDetect::SetChangeNetworkid(int networkId)
{
    currentConnectedNetworkId_.store(networkId);
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

bool WifiSecurityDetect::IsSettingSecurityDetectOn()
{
    if (datashareReady_ == false) {
        return false;
    }
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
    resultSet->GetString(0, valueResult);
    if (valueResult == "1") {
        WIFI_LOGI("SecurityDetectOn");
        operatePtr->Release();
        return true;
    } else {
        WIFI_LOGI("SecurityDetectOff");
        operatePtr->Release();
        return false;
    }
}

bool WifiSecurityDetect::IsSecurityDetectTimeout(const int &networkId)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, config) != 0) {
        WIFI_LOGE("%{public}s, not find networkId:%{public}d", __FUNCTION__, networkId);
        return false;
    }

    if (config.lastDetectTime == -1) {
        return true;
    }
    auto hours = std::chrono::duration_cast<std::chrono::hours>(
        std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(config.lastDetectTime));
    if (hours.count() >= NUM24) {
        WIFI_LOGI("WifiDetect more than 24");
        return true;
    } else {
        WIFI_LOGI("WifiDetect less than 24");
        return false;
    }
}

WifiSecurityDetect &WifiSecurityDetect::GetInstance()
{
    static WifiSecurityDetect securitywifi;
    return securitywifi;
}

ErrCode WifiSecurityDetect::SecurityDetectResult(
    const std::string &devId, uint32_t modelId, const std::string &param, bool &result)
{
    auto promise = std::make_shared<std::promise<SecurityModelResult>>();
    auto future = promise->get_future();
    auto func = [promise](const OHOS::Security::SecurityGuard::SecurityModelResult &result) mutable -> int32_t {
        SecurityModelResult model = {.devId = result.devId, .modelId = result.modelId, .result = result.result};
        promise->set_value(model);
        return WIFI_OPT_SUCCESS;
    };
    auto ret = OHOS::Security::SecurityGuard::RequestSecurityModelResultAsync(devId, modelId, param, func);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("RequestSecurityModelResultSync error, ret=%{public}d", ret);
        return WIFI_OPT_FAILED;
    }

    if (future.wait_for(std::chrono::milliseconds(SECURITY_WAITING_TIME)) == std::future_status::ready) {
        SecurityModelResult model = future.get();
        return SecurityModelJsonResult(model, result);
    } else {
        WIFI_LOGE("RequestSecurityModelResultSync timeout");
        return WIFI_OPT_FAILED;
    }
}

void WifiSecurityDetect::RegisterSecurityDetectObserver()
{
    std::unique_lock<std::mutex> lock(shareSecurityObserverMutex_);
    if (isSecurityDetectObservered_) {
        return;
    }

    auto datashareHelper = CreateDataShareHelper();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("SecurityDetectObserver operatePtr is nullptr");
        return;
    }
    SecurityDetectObserver_ = sptr<SecurityDetectObserver>::MakeSptr();
    if (SecurityDetectObserver_ == nullptr) {
        WIFI_LOGI("%{public}s SecurityDetectObserver_ is null", __func__);
        return;
    }
    auto uri = AssembleUri("wifi_cloud_security_check");
    datashareHelper->RegisterObserver(uri, SecurityDetectObserver_);
    isSecurityDetectObservered_ = true;
    WIFI_LOGI("registerSecurityDetectObserver success");
}

void WifiSecurityDetect::UnRegisterSecurityDetectObserver()
{
    std::unique_lock<std::mutex> lock(shareSecurityObserverMutex_);
    if (!isSecurityDetectObservered_) {
        return;
    }

    auto datashareHelper = CreateDataShareHelper();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("SecurityDetectObserver operatePtr is nullptr");
        return;
    }
    SecurityDetectObserver_ = sptr<SecurityDetectObserver>::MakeSptr();
    if (SecurityDetectObserver_ == nullptr) {
        WIFI_LOGI("%{public}s SecurityDetectObserver_ is null", __func__);
        return;
    }
    auto uri = AssembleUri("wifi_cloud_security_check");
    datashareHelper->UnregisterObserver(uri, SecurityDetectObserver_);
    isSecurityDetectObservered_ = false;
    WIFI_LOGI("unregisterSecurityDetectObserver success");
}

ErrCode WifiSecurityDetect::SecurityModelJsonResult(SecurityModelResult model, bool &result)
{
    Json::Value root;
    Json::Reader reader;
    bool parsingSuccess = reader.parse(model.result, root);
    if (!parsingSuccess) {
        WIFI_LOGE("model.result is null");
        return WIFI_OPT_FAILED;
    }

    if (root["status"].isInt() && root["status"].asInt() != 0) {
        WIFI_LOGE("RequestSecurityModelResultSync status error= %{public}d", root["status"].asInt());
        return WIFI_OPT_FAILED;
    }
    std::string SecurityResult;
    if (root["result"].isString()) {
        SecurityResult = root["result"].asString();
    } else {
        WIFI_LOGE("The result is not string");
        return WIFI_OPT_FAILED;
    }
    if (CheckDataLegal(SecurityResult) == 0) {
        WIFI_LOGI("SG wifi result is secure");
        result = true;
        return WIFI_OPT_SUCCESS;
    } else if (CheckDataLegal(SecurityResult) == 1) {
        WIFI_LOGI("SG wifi result is not secure");
        result = false;
        return WIFI_OPT_SUCCESS;
    } else {
        return WIFI_OPT_FAILED;
    }
}

int32_t WifiSecurityDetect::AuthenticationConvert(std::string key)
{
    if (key == KEY_MGMT_NONE) {
        return SecurityType::SECURITY_TYPE_OPEN;
    } else if (key == KEY_MGMT_WEP) {
        return SecurityType::SECURITY_TYPE_WEP;
    } else if (key == KEY_MGMT_WPA_PSK) {
        return SecurityType::SECURITY_TYPE_PSK;
    } else if (key == KEY_MGMT_SAE) {
        return SecurityType::SECURITY_TYPE_SAE;
    } else if (key == KEY_MGMT_EAP) {
        return SecurityType::SECURITY_TYPE_EAP;
    } else if (key == KEY_MGMT_SUITE_B_192) {
        return SecurityType::SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT;
    } else if (key == KEY_MGMT_WAPI_CERT) {
        return SecurityType::SECURITY_TYPE_WAPI_CERT;
    } else if (key == KEY_MGMT_WAPI_PSK) {
        return SecurityType::SECURITY_TYPE_WAPI_PSK;
    } else {
        WIFI_LOGE("wifi authentication is unknown");
        return -1;
    }
}

void WifiSecurityDetect::ConverWifiLinkInfoToJson(const WifiLinkedInfo &info, Json::Value &root)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(info.networkId, config) != 0) {
        WIFI_LOGE("%{public}s, not find networkId:%{public}d", __FUNCTION__, info.networkId);
        return;
    }
    IpInfo wifiIpInfo;
    int32_t instId = 0;
    WifiConfigCenter::GetInstance().GetIpInfo(wifiIpInfo, instId);
    switch (info.wifiStandard) {
        case WireType::WIRE_802_11A:
            root["wirelessType"] = "802.11a";
            break;
        case WireType::WIRE_802_11B:
            root["wirelessType"] = "802.11b";
            break;
        case WireType::WIRE_802_11G:
            root["wirelessType"] = "802.11g";
            break;
        case WireType::WIRE_802_11N:
            root["wirelessType"] = "802.11n";
            break;
        case WireType::WIRE_802_11AC:
            root["wirelessType"] = "802.11ac";
            break;
        case WireType::WIRE_802_11AX:
            root["wirelessType"] = "802.11ax";
            break;
        default:
            WIFI_LOGE("wifi wirelessType is unknown");
            root["wirelessType"] = "";
    }
    root["ssid"] = config.ssid;
    root["bssid"] = config.bssid;
    root["signalStrength"] = config.rssi;
    root["authentication"] = AuthenticationConvert(config.keyMgmt);
    if (config.frequency >= MIN_5G_FREQUENCY && config.frequency <= MAX_5G_FREQUENCY) {
        root["frequencyBand"] = "5GHz";
    } else {
        root["frequencyBand"] = "2.4GHz";
    }
    root["gatewayIp"] = IpTools::ConvertIpv4Address(wifiIpInfo.ipAddress);
    root["gatewayMac"] = config.macAddress;
    root["primaryDns"] = IpTools::ConvertIpv4Address(wifiIpInfo.primaryDns);
    if (wifiIpInfo.secondDns == 0) {
        root["secondDns"] = "0.0.0.0";
    } else {
        root["secondDns"] = IpTools::ConvertIpv4Address(wifiIpInfo.secondDns);
    }
}

void WifiSecurityDetect::SecurityDetect(const WifiLinkedInfo &info)
{
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(info.networkId, config) != 0) {
        WIFI_LOGE("%{public}s, not find networkId:%{public}d", __FUNCTION__, info.networkId);
        return;
    }
    SecurityModelResult model;
    model.devId = "";
    model.modelId = securityGuardModelID;
    model.result = "";
    if (!IsSecurityDetectTimeout(info.networkId)) {
        WIFI_LOGI("networkId:%{public}d detect less than 24 hours", info.networkId);
        return;
    }

    Json::Value root;
    Json::FastWriter writer;
    ConverWifiLinkInfoToJson(info, root);
    model.param = writer.write(root);
    WIFI_LOGI(
        "ssid:%{public}s bssid:%{public}s", SsidAnonymize(config.ssid).c_str(), MacAnonymize(config.bssid).c_str());
    securityDetectThread_->PostAsyncTask([=]() mutable -> int32_t {
        if (!IsSettingSecurityDetectOn()) {
            return WIFI_OPT_FAILED;
        }
        bool result = true;
        ErrCode ret = SecurityDetectResult(model.devId, model.modelId, model.param, result);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("SecurityDetectResult result is fail");
            return WIFI_OPT_FAILED;
        }
        WIFI_LOGI("PopupNotification result is %{public}d", result);
        config.isSecureWifi = result;
        config.lastDetectTime = time(0);
        PopupNotification(config.isSecureWifi ? WifiNotification::CLOSE : WifiNotification::OPEN, info.networkId);
        WifiSettings::GetInstance().AddDeviceConfig(config);
        WifiSettings::GetInstance().SyncDeviceConfig();
        return WIFI_OPT_SUCCESS;
    });
}

void WifiSecurityDetect::PopupNotification(int status, int networkid)
{
    WIFI_LOGI("wifi security pop-up notification start");
    OHOS::AAFwk::Want want;
    std::string bundleName = WifiSettings::GetInstance().GetPackageName("SECURITY_BUNDLE");
    want.SetElementName(bundleName, "WlanNotificationAbility");
    if (status == 1) {
        if (!IsSettingSecurityDetectOn()) {
            WIFI_LOGI("The SecurityDetect is off");
            return;
        }
        if (networkid == -1) {
            WIFI_LOGI("The networkid is off");
            return;
        }
        if (currentConnectedNetworkId_.load() != networkid) {
            WIFI_LOGI("The networkid is changed current networkid:%{public}d detect networkid:%{public}d",
                currentConnectedNetworkId_.load(),
                networkid);
            return;
        }
        want.SetParam("notificationType", WifiNotification::OPEN);
    } else {
        want.SetParam("notificationType", WifiNotification::CLOSE);
    }
    want.SetParam("networkId", networkid);

    auto result = WifiNotificationUtil::GetInstance().StartAbility(want);
    WIFI_LOGI("wifi security pop-up notification End, result = %{public}d", result);
}

WifiSecurityDetect::~WifiSecurityDetect()
{
    UnRegisterSecurityDetectObserver();
    WIFI_LOGI("enter ~WifiSecurityDetect");
}

}  // namespace Wifi
}  // namespace OHOS
#endif