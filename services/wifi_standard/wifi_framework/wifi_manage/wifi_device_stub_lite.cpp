/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "wifi_device_stub_lite.h"
#include "define.h"
#include "liteipc_adapter.h"
#include "wifi_device_callback_proxy.h"
#include "wifi_errcode.h"
#include "wifi_logger.h"
#include "wifi_msg.h"

DEFINE_WIFILOG_LABEL("WifiDeviceStubLite");

namespace OHOS {
namespace Wifi {
WifiDeviceStub::WifiDeviceStub()
{
    InitHandleMap();
}

WifiDeviceStub::~WifiDeviceStub()
{}

void WifiDeviceStub::ReadIpAddress(IpcIo *req, WifiIpAddress &address)
{
    constexpr int MAX_LIMIT_SIZE = 1024;
    address.family = IpcIoPopInt32(req);
    address.addressIpv4 = IpcIoPopInt32(req);
    int size = IpcIoPopInt32(req);
    if (size > MAX_LIMIT_SIZE) {
        WIFI_LOGE("Read ip address parameter error: %{public}d", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        address.addressIpv6.push_back(IpcIoPopInt8(req));
    }
}

void WifiDeviceStub::ReadWifiDeviceConfig(IpcIo *req, WifiDeviceConfig &config)
{
    size_t size;
    config.networkId = IpcIoPopInt32(req);
    config.status = IpcIoPopInt32(req);
    config.bssid = (char *)IpcIoPopString(req, &size);
    config.ssid = (char *)IpcIoPopString(req, &size);
    config.band = IpcIoPopInt32(req);
    config.channel = IpcIoPopInt32(req);
    config.frequency = IpcIoPopInt32(req);
    config.level = IpcIoPopInt32(req);
    config.isPasspoint = IpcIoPopBool(req);
    config.isEphemeral = IpcIoPopBool(req);
    config.preSharedKey = (char *)IpcIoPopString(req, &size);
    config.keyMgmt = (char *)IpcIoPopString(req, &size);
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        config.wepKeys[i] = (char *)IpcIoPopString(req, &size);
    }
    config.wepTxKeyIndex = IpcIoPopInt32(req);
    config.priority = IpcIoPopInt32(req);
    config.hiddenSSID = IpcIoPopBool(req);
    config.wifiIpConfig.assignMethod = AssignIpMethod(IpcIoPopInt32(req));
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = IpcIoPopInt32(req);
    config.wifiIpConfig.staticIpAddress.ipAddress.flags = IpcIoPopInt32(req);
    config.wifiIpConfig.staticIpAddress.ipAddress.scope = IpcIoPopInt32(req);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.gateway);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer1);
    ReadIpAddress(req, config.wifiIpConfig.staticIpAddress.dnsServer2);
    config.wifiIpConfig.staticIpAddress.domains = (char *)IpcIoPopString(req, &size);
    config.wifiEapConfig.eap = (char *)IpcIoPopString(req, &size);
    config.wifiEapConfig.identity = (char *)IpcIoPopString(req, &size);
    config.wifiEapConfig.password = (char *)IpcIoPopString(req, &size);
    config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(IpcIoPopInt32(req));
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = (char *)IpcIoPopString(req, &size);
    config.wifiProxyconfig.manualProxyConfig.serverHostName = (char *)IpcIoPopString(req, &size);
    config.wifiProxyconfig.manualProxyConfig.serverPort = IpcIoPopInt32(req);
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = (char *)IpcIoPopString(req, &size);
    config.wifiPrivacySetting = WifiPrivacyConfig(IpcIoPopInt32(req));
}

void WifiDeviceStub::WriteIpAddress(IpcIo *reply, const WifiIpAddress &address)
{
    IpcIoPushInt32(reply, address.family);
    IpcIoPushInt32(reply, address.addressIpv4);
    int size = address.addressIpv6.size();
    IpcIoPushInt32(reply, size);
    for (int i = 0; i < size; i++) {
        IpcIoPushInt8(reply, address.addressIpv6[i]);
    }
}

void WifiDeviceStub::WriteWifiDeviceConfig(IpcIo *reply, const WifiDeviceConfig &config)
{
    IpcIoPushInt32(reply, config.networkId);
    IpcIoPushInt32(reply, config.status);
    IpcIoPushString(reply, config.bssid.c_str());
    IpcIoPushString(reply, config.ssid.c_str());
    IpcIoPushInt32(reply, config.band);
    IpcIoPushInt32(reply, config.channel);
    IpcIoPushInt32(reply, config.frequency);
    IpcIoPushInt32(reply, config.level);
    IpcIoPushBool(reply, config.isPasspoint);
    IpcIoPushBool(reply, config.isEphemeral);
    IpcIoPushString(reply, config.preSharedKey.c_str());
    IpcIoPushString(reply, config.keyMgmt.c_str());
    for (int j = 0; j < WEPKEYS_SIZE; j++) {
        IpcIoPushString(reply, config.wepKeys[j].c_str());
    }
    IpcIoPushInt32(reply, config.wepTxKeyIndex);
    IpcIoPushInt32(reply, config.priority);
    IpcIoPushBool(reply, config.hiddenSSID);
    IpcIoPushInt32(reply, (int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    IpcIoPushInt32(reply, config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    IpcIoPushInt32(reply, config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    IpcIoPushInt32(reply, config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
    IpcIoPushString(reply, config.wifiIpConfig.staticIpAddress.domains.c_str());
    IpcIoPushString(reply, config.wifiEapConfig.eap.c_str());
    IpcIoPushString(reply, config.wifiEapConfig.identity.c_str());
    IpcIoPushString(reply, config.wifiEapConfig.password.c_str());
    IpcIoPushInt32(reply, (int)config.wifiProxyconfig.configureMethod);
    IpcIoPushString(reply, config.wifiProxyconfig.autoProxyConfig.pacWebAddress.c_str());
    IpcIoPushString(reply, config.wifiProxyconfig.manualProxyConfig.serverHostName.c_str());
    IpcIoPushInt32(reply, config.wifiProxyconfig.manualProxyConfig.serverPort);
    IpcIoPushString(reply, config.wifiProxyconfig.manualProxyConfig.exclusionObjectList.c_str());
    IpcIoPushInt32(reply, (int)config.wifiPrivacySetting);
}

void WifiDeviceStub::OnEnableWifi(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = EnableWifi();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnDisableWifi(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DisableWifi();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnAddDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(req, config);

    int result = INVALID_NETWORK_ID;
    ErrCode ret = AddDeviceConfig(config, result);

    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt32(reply, result);
    }
}

void WifiDeviceStub::OnRemoveDevice(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = IpcIoPopInt32(req);
    ErrCode ret = RemoveDevice(networkId);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnRemoveAllDevice(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = RemoveAllDevice();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnGetDeviceConfigs(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    std::vector<WifiDeviceConfig> result;
    ErrCode ret = GetDeviceConfigs(result);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        unsigned int size = result.size();
        IpcIoPushInt32(reply, size);
        for (unsigned int i = 0; i < size; ++i) {
            WriteWifiDeviceConfig(reply, result[i]);
        }
    }
}

void WifiDeviceStub::OnEnableDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = IpcIoPopInt32(req);
    bool attemptEnable = IpcIoPopBool(req);
    ErrCode ret = EnableDeviceConfig(networkId, attemptEnable);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnDisableDeviceConfig(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = IpcIoPopInt32(req);
    ErrCode ret = DisableDeviceConfig(networkId);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnConnectTo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int networkId = IpcIoPopInt32(req);
    ErrCode ret = ConnectToNetwork(networkId);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnConnect2To(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    WifiDeviceConfig config;
    ReadWifiDeviceConfig(req, config);
    ErrCode ret = ConnectToDevice(config);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnReConnect(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = ReConnect();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnReAssociate(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = ReAssociate();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnDisconnect(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = Disconnect();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnStartWps(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    WpsConfig config;
    config.setup = SetupMethod(IpcIoPopInt32(req));
    config.pin = (char *)IpcIoPopString(req, &size);
    config.bssid = (char *)IpcIoPopString(req, &size);

    ErrCode ret = StartWps(config);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnCancelWps(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = CancelWps();
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnIsWifiActive(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    bool bActive = false;
    ErrCode ret = IsWifiActive(bActive);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushBool(reply, bActive);
    }
}

void WifiDeviceStub::OnGetWifiState(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int state = 0;
    ErrCode ret = GetWifiState(state);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt32(reply, state);
    }
}

void WifiDeviceStub::OnGetLinkedInfo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    WifiLinkedInfo wifiInfo;
    ErrCode ret = GetLinkedInfo(wifiInfo);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt32(reply, wifiInfo.networkId);
        IpcIoPushString(reply, wifiInfo.ssid.c_str());
        IpcIoPushString(reply, wifiInfo.bssid.c_str());
        IpcIoPushInt32(reply, wifiInfo.rssi);
        IpcIoPushInt32(reply, wifiInfo.band);
        IpcIoPushInt32(reply, wifiInfo.frequency);
        IpcIoPushInt32(reply, wifiInfo.linkSpeed);
        IpcIoPushString(reply, wifiInfo.macAddress.c_str());
        IpcIoPushInt32(reply, wifiInfo.ipAddress);
        IpcIoPushInt32(reply, (int)wifiInfo.connState);
        IpcIoPushBool(reply, wifiInfo.ifHiddenSSID);
        IpcIoPushString(reply, wifiInfo.rxLinkSpeed.c_str());
        IpcIoPushString(reply, wifiInfo.txLinkSpeed.c_str());
        IpcIoPushInt32(reply, wifiInfo.chload);
        IpcIoPushInt32(reply, wifiInfo.snr);
        IpcIoPushInt32(reply, (int)wifiInfo.supplicantState);
        IpcIoPushInt32(reply, (int)wifiInfo.detailedState);
    }
}

void WifiDeviceStub::OnGetIpInfo(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    IpInfo info;
    ErrCode ret = GetIpInfo(info);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt32(reply, info.ipAddress);
        IpcIoPushInt32(reply, info.gateway);
        IpcIoPushInt32(reply, info.netmask);
        IpcIoPushInt32(reply, info.primaryDns);
        IpcIoPushInt32(reply, info.secondDns);
        IpcIoPushInt32(reply, info.serverIp);
        IpcIoPushInt32(reply, info.leaseDuration);
    }
}

void WifiDeviceStub::OnSetCountryCode(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t size;
    std::string countrycode = (char *)IpcIoPopString(req, &size);
    ErrCode ret = SetCountryCode(countrycode);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnGetCountryCode(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    std::string countryCode;
    ErrCode ret = GetCountryCode(countryCode);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushString(reply, countryCode.c_str());
    }
}

void WifiDeviceStub::OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = WIFI_OPT_FAILED;
    SvcIdentity *sid = IpcIoPopSvc(req);
    if (sid == nullptr) {
        WIFI_LOGE("sid is null");
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, ret);
        return;
    }
#ifdef __LINUX__
    BinderAcquire(sid->ipcContext, sid->handle);
#endif

    callback_ = std::make_shared<WifiDeviceCallBackProxy>(sid);
    WIFI_LOGD("create new WifiDeviceCallbackProxy!");
    ret = RegisterCallBack(callback_);

    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
}

void WifiDeviceStub::OnGetSignalLevel(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int rssi = IpcIoPopInt32(req);
    int band = IpcIoPopInt32(req);
    int level = 0;
    ErrCode ret = GetSignalLevel(rssi, band, level);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt32(reply, level);
    }
}

void WifiDeviceStub::OnGetSupportedFeatures(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    long features = 0;
    int ret = GetSupportedFeatures(features);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);

    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushInt64(reply, features);
    }
}

void WifiDeviceStub::OnGetDeviceMacAdd(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    std::string strMacAddr;
    ErrCode ret = GetDeviceMacAddress(strMacAddr);
    IpcIoPushInt32(reply, 0);
    IpcIoPushInt32(reply, ret);
    if (ret == WIFI_OPT_SUCCESS) {
        IpcIoPushString(reply, strMacAddr.c_str());
    }
}

void WifiDeviceStub::InitHandleMap()
{
    handleFuncMap_[WIFI_SVR_CMD_ENABLE_WIFI] = &WifiDeviceStub::OnEnableWifi;
    handleFuncMap_[WIFI_SVR_CMD_DISABLE_WIFI] = &WifiDeviceStub::OnDisableWifi;
    handleFuncMap_[WIFI_SVR_CMD_ADD_DEVICE_CONFIG] = &WifiDeviceStub::OnAddDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveDevice;
    handleFuncMap_[WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG] = &WifiDeviceStub::OnRemoveAllDevice;
    handleFuncMap_[WIFI_SVR_CMD_GET_DEVICE_CONFIGS] = &WifiDeviceStub::OnGetDeviceConfigs;
    handleFuncMap_[WIFI_SVR_CMD_ENABLE_DEVICE] = &WifiDeviceStub::OnEnableDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_DISABLE_DEVICE] = &WifiDeviceStub::OnDisableDeviceConfig;
    handleFuncMap_[WIFI_SVR_CMD_CONNECT_TO] = &WifiDeviceStub::OnConnectTo;
    handleFuncMap_[WIFI_SVR_CMD_CONNECT2_TO] = &WifiDeviceStub::OnConnect2To;
    handleFuncMap_[WIFI_SVR_CMD_RECONNECT] = &WifiDeviceStub::OnReConnect;
    handleFuncMap_[WIFI_SVR_CMD_REASSOCIATE] = &WifiDeviceStub::OnReAssociate;
    handleFuncMap_[WIFI_SVR_CMD_DISCONNECT] = &WifiDeviceStub::OnDisconnect;
    handleFuncMap_[WIFI_SVR_CMD_START_WPS] = &WifiDeviceStub::OnStartWps;
    handleFuncMap_[WIFI_SVR_CMD_CANCEL_WPS] = &WifiDeviceStub::OnCancelWps;
    handleFuncMap_[WIFI_SVR_CMD_IS_WIFI_ACTIVE] = &WifiDeviceStub::OnIsWifiActive;
    handleFuncMap_[WIFI_SVR_CMD_GET_WIFI_STATE] = &WifiDeviceStub::OnGetWifiState;
    handleFuncMap_[WIFI_SVR_CMD_GET_LINKED_INFO] = &WifiDeviceStub::OnGetLinkedInfo;
    handleFuncMap_[WIFI_SVR_CMD_GET_DHCP_INFO] = &WifiDeviceStub::OnGetIpInfo;
    handleFuncMap_[WIFI_SVR_CMD_SET_COUNTRY_CODE] = &WifiDeviceStub::OnSetCountryCode;
    handleFuncMap_[WIFI_SVR_CMD_GET_COUNTRY_CODE] = &WifiDeviceStub::OnGetCountryCode;
    handleFuncMap_[WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT] = &WifiDeviceStub::OnRegisterCallBack;
    handleFuncMap_[WIFI_SVR_CMD_GET_SIGNAL_LEVEL] = &WifiDeviceStub::OnGetSignalLevel;
    handleFuncMap_[WIFI_SVR_CMD_GET_SUPPORTED_FEATURES] = &WifiDeviceStub::OnGetSupportedFeatures;
    handleFuncMap_[WIFI_SVR_CMD_GET_DERVICE_MAC_ADD] = &WifiDeviceStub::OnGetDeviceMacAdd;
}

int WifiDeviceStub::OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply)
{
    WIFI_LOGD("run: %{public}s code: %{public}u", __func__, code);
    if (req == nullptr || reply == nullptr) {
        WIFI_LOGD("req:%{public}d, reply:%{public}d", req == nullptr, reply == nullptr);
        return LITEIPC_EINVAL;
    }
    int exception = IpcIoPopInt32(req);
    if (exception) {
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, WIFI_OPT_NOT_SUPPORTED);
        return WIFI_OPT_FAILED;
    }

    HandleFuncMap::iterator iter = handleFuncMap_.find(code);
    if (iter == handleFuncMap_.end()) {
        WIFI_LOGI("not find function to deal, code %{public}u", code);
        IpcIoPushInt32(reply, 0);
        IpcIoPushInt32(reply, WIFI_OPT_NOT_SUPPORTED);
    } else {
        (this->*(iter->second))(code, req, reply);
    }

    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
